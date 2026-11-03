// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::Arc;

use axum::{
	Json, Router,
	extract::{Query, Request, State, rejection::QueryRejection},
	http::{HeaderMap, HeaderValue, StatusCode, header},
	middleware::{self, Next},
	response::{IntoResponse, Response},
	routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
	policy::PermissionResolver,
	verify::{DomainVerifier, VerifyError, parse_claims},
	zitadel::{Credential, CredentialType, ZitadelClient},
};

/// Where this server's source lives, as served to clients.
///
/// The commit hash makes the pointer exact, satisfying the AGPL source offer
/// for binaries handed out to the network: the build (`build.rs` locally, the
/// flake in releases) pins it to the tree the binary was built from.
pub const SOURCE_OFFER: &str = concat!(
	"source available at ",
	env!("CARGO_PKG_REPOSITORY"),
	"/commit/",
	env!("GIT_COMMIT_HASH"),
);

/// The `Server` header sent with every response, including errors, so that
/// even unauthenticated clients get pointed at the source.
const SERVER_ID: &str = concat!(
	"zapp/",
	env!("CARGO_PKG_VERSION"),
	" (source available at ",
	env!("CARGO_PKG_REPOSITORY"),
	"/commit/",
	env!("GIT_COMMIT_HASH"),
	")",
);

pub struct AppState {
	pub verifier: DomainVerifier,
	pub resolver: Box<dyn PermissionResolver>,
	pub zitadel: Arc<ZitadelClient>,
	/// Service account name prefix for https issuers.
	pub account_prefix_https: String,
	/// Service account name prefix for plain-http issuers; None rejects them.
	pub account_prefix_http: Option<String>,
}

pub fn router(state: Arc<AppState>) -> Router {
	Router::new()
		.route("/", get(|| async { SOURCE_OFFER }))
		.route("/healthz", get(|| async { "ok" }))
		.route("/v1/credentials", post(issue_credentials))
		.layer(middleware::from_fn(source_offer_header))
		.with_state(state)
}

async fn source_offer_header(request: Request, next: Next) -> Response {
	let mut response = next.run(request).await;
	response.headers_mut().insert(header::SERVER, HeaderValue::from_static(SERVER_ID));
	response
}

#[derive(Deserialize)]
struct CredentialsQuery {
	/// Which kind of credential to issue; defaults to a personal access
	/// token.
	#[serde(rename = "type", default)]
	credential_type: CredentialType,
}

#[derive(Serialize)]
struct CredentialsResponse {
	issuer: String,
	/// Base URL of the Zitadel instance the credential is valid for, with
	/// a trailing slash.
	zitadel_url: String,
	username: String,
	user_id: String,
	project_id: String,
	#[serde(rename = "type")]
	credential_type: CredentialType,
	/// The personal access token (`type` = `pat`).
	#[serde(skip_serializing_if = "Option::is_none")]
	secret: Option<String>,
	/// The private key in Zitadel's JSON key file format (`type` = `key`).
	#[serde(skip_serializing_if = "Option::is_none")]
	key: Option<serde_json::Value>,
	/// RFC 3339 timestamp.
	expires_at: String,
}

#[derive(Serialize)]
struct ErrorResponse {
	error: String,
	message: String,
}

enum ApiError {
	BadQuery(QueryRejection),
	MissingBearer,
	Verify(VerifyError),
	NotEntitled(String),
	SubjectNotUsable(String),
	Zitadel(anyhow::Error),
}

impl IntoResponse for ApiError {
	fn into_response(self) -> Response {
		let (status, error, message) = match self {
			ApiError::BadQuery(e) => (
				StatusCode::BAD_REQUEST,
				"invalid_query",
				format!("{}; `type` must be `pat` (default) or `key`", e.body_text()),
			),
			ApiError::MissingBearer => (
				StatusCode::UNAUTHORIZED,
				"missing_token",
				"Authorization: Bearer <self-issued JWT> header required".to_string(),
			),
			ApiError::Verify(e) => {
				let error = match &e {
					VerifyError::MalformedToken(_)
					| VerifyError::MissingIssuer
					| VerifyError::InvalidIssuerDomain(_)
					| VerifyError::InvalidIssuerPath(_)
					| VerifyError::AudienceMismatch { .. }
					| VerifyError::Jwt(_)
					| VerifyError::NoMatchingKey => "invalid_token",
					VerifyError::TokenInactive(_) => "token_inactive",
					_ => "verification_failed",
				};
				let message = match error {
					//= docs/requirements/zapp.md#verify-1
					//# zapp MUST NOT return to the client what went wrong in a
					//# request to the issuer.
					"verification_failed" => {
						"the token could not be verified with its issuer".to_string()
					}
					_ => e.to_string(),
				};
				(StatusCode::UNAUTHORIZED, error, message)
			}
			ApiError::NotEntitled(issuer) => (
				StatusCode::FORBIDDEN,
				"issuer_not_entitled",
				format!("issuer {issuer} does not match any configured pattern"),
			),
			ApiError::SubjectNotUsable(subject) => (
				StatusCode::FORBIDDEN,
				"subject_not_usable",
				format!(
					"subject {subject:?} gives a service account name longer than 200 characters"
				),
			),
			ApiError::Zitadel(e) => {
				warn!("zitadel error: {e:#}");
				(
					StatusCode::BAD_GATEWAY,
					"zitadel_error",
					"failed to provision service account and project in Zitadel".to_string(),
				)
			}
		};
		(status, Json(ErrorResponse { error: error.to_string(), message })).into_response()
	}
}

/// Exchanges a self-issued JWT (proving domain ownership via introspection
/// or JWKS on the issuer's domain) for a Zitadel service account owning a
/// project of the same name, returned as a personal access token or a
/// machine key, as requested.
async fn issue_credentials(
	State(state): State<Arc<AppState>>,
	query: Result<Query<CredentialsQuery>, QueryRejection>,
	headers: HeaderMap,
) -> Result<Json<CredentialsResponse>, ApiError> {
	let Query(query) = query.map_err(ApiError::BadQuery)?;
	let token = bearer_token(&headers).ok_or(ApiError::MissingBearer)?;

	// Unverified, so it only decides whether the issuer is worth asking.
	let claimed = parse_claims(token).map_err(ApiError::Verify)?;
	//= docs/requirements/zapp.md#verify-1
	//# zapp MUST NOT send any request to the issuer of a token unless the
	//# issuer claimed by the token matches the issuer pattern of some grant.
	if !state.resolver.matches_issuer(&claimed.scheme, &claimed.domain, claimed.port, &claimed.path)
	{
		return Err(ApiError::NotEntitled(claimed.issuer_url()));
	}

	let claims = state.verifier.verify(token).await.map_err(|e| {
		info!("issuer verification failed: {e}");
		ApiError::Verify(e)
	})?;
	let issuer = claims.issuer_url();

	//= docs/requirements/zapp.md#subject-4
	//# zapp MUST pass the verified subject to the permission resolver.
	let entitlement = state
		.resolver
		.resolve(
			&claims.scheme,
			&claims.domain,
			claims.port,
			&claims.path,
			claims.subject.as_deref(),
		)
		.ok_or_else(|| ApiError::NotEntitled(issuer.clone()))?;

	// The verifier already rejects http issuers when no http prefix is
	// configured; this match merely picks the prefix.
	let prefix = match claims.scheme.as_str() {
		"http" => state
			.account_prefix_http
			.as_deref()
			.ok_or_else(|| ApiError::Verify(VerifyError::HttpIssuerDisallowed(issuer.clone())))?,
		_ => state.account_prefix_https.as_str(),
	};

	let name = match &entitlement.subject {
		//= docs/requirements/zapp.md#subject-3
		//# If the matching grant has a subject pattern, the names of the
		//# service account and the project MUST contain the subject, so that
		//# every pair of issuer and subject gets its own service account and
		//# project.
		Some(subject) => claims
			.subject_account_name(prefix, subject)
			.ok_or_else(|| ApiError::SubjectNotUsable(subject.clone()))?,
		//= docs/requirements/zapp.md#subject-3
		//# If the matching grant has no subject pattern, the names MUST stay
		//# the same as without subject support.
		None => claims.account_name(prefix),
	};

	let provisioned = state
		.zitadel
		.provision(&name, &issuer, &entitlement, query.credential_type)
		.await
		.map_err(ApiError::Zitadel)?;

	info!(
		"issued {:?} for service account {} ({}) owning project {} in org {} with instance roles {:?} and org roles {:?} for issuer {issuer} subject {:?} (expires_at {})",
		query.credential_type,
		provisioned.username,
		provisioned.user_id,
		provisioned.project_id,
		entitlement.org_id,
		entitlement.instance_roles,
		entitlement.org_roles,
		entitlement.subject,
		provisioned.expires_at
	);
	let (secret, key) = match provisioned.credential {
		Credential::Pat(token) => (Some(token), None),
		Credential::Key(key_file) => {
			let key = serde_json::from_str(&key_file)
				.map_err(|e| ApiError::Zitadel(anyhow::anyhow!("machine key is not JSON: {e}")))?;
			(None, Some(key))
		}
	};
	Ok(Json(CredentialsResponse {
		issuer,
		zitadel_url: state.zitadel.url().to_string(),
		username: provisioned.username,
		user_id: provisioned.user_id,
		project_id: provisioned.project_id,
		credential_type: query.credential_type,
		secret,
		key,
		expires_at: provisioned.expires_at,
	}))
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
	headers
		.get(header::AUTHORIZATION)?
		.to_str()
		.ok()?
		.strip_prefix("Bearer ")
		.map(str::trim)
		.filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
	use std::{collections::BTreeMap, sync::Mutex};

	use axum::body::Body;
	use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
	use serde_json::json;
	use tower::ServiceExt as _;
	use wiremock::{
		Mock, MockServer, ResponseTemplate,
		matchers::{body_partial_json, method, path},
	};

	use super::*;
	use crate::{
		config::VerificationConfig,
		policy::{Entitlement, PermissionResolver},
		zitadel::tests::test_client,
	};

	/// Entitles every caller (unless `refuse_issuers`) to org 1 with
	/// per-subject accounts and records the subject it was asked about.
	#[derive(Default)]
	struct RecordingResolver {
		subjects: Arc<Mutex<Vec<Option<String>>>>,
		refuse_issuers: bool,
	}

	impl PermissionResolver for RecordingResolver {
		fn matches_issuer(&self, _: &str, _: &str, _: Option<u16>, _: &str) -> bool {
			!self.refuse_issuers
		}

		fn resolve(
			&self,
			_scheme: &str,
			_domain: &str,
			_port: Option<u16>,
			_path: &str,
			subject: Option<&str>,
		) -> Option<Entitlement> {
			self.subjects.lock().unwrap().push(subject.map(str::to_string));
			Some(Entitlement {
				org_id: "1".to_string(),
				duration: std::time::Duration::from_secs(3600),
				instance_roles: Vec::new(),
				org_roles: vec!["ORG_USER_MANAGER".to_string()],
				subject: subject.map(str::to_string),
			})
		}
	}

	/// The decoded metadata of a `metadata/_bulk` request.
	fn metadata_of(request: &wiremock::Request) -> BTreeMap<String, String> {
		let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
		body["metadata"]
			.as_array()
			.into_iter()
			.flatten()
			.map(|entry| {
				let value = base64::prelude::BASE64_STANDARD
					.decode(entry["value"].as_str().unwrap_or_default())
					.unwrap_or_default();
				(
					entry["key"].as_str().unwrap_or_default().to_string(),
					String::from_utf8(value).unwrap_or_default(),
				)
			})
			.collect()
	}

	#[tokio::test]
	async fn issues_per_subject_credentials() {
		let subject = "system:serviceaccount:tenant-a:admin-api";

		// The workload's issuer, verifying tokens by introspection.
		let issuer = MockServer::start().await;
		let iss = issuer.uri();
		Mock::given(method("GET"))
			.and(path("/.well-known/openid-configuration"))
			.respond_with(ResponseTemplate::new(200).set_body_json(json!({
				"issuer": iss,
				"introspection_endpoint": format!("{iss}/introspect"),
			})))
			.mount(&issuer)
			.await;
		Mock::given(method("POST"))
			.and(path("/introspect"))
			.respond_with(
				ResponseTemplate::new(200).set_body_json(json!({ "active": true, "sub": subject })),
			)
			.mount(&issuer)
			.await;

		// Zitadel, on the happy path where nothing exists yet.
		let zitadel = MockServer::start().await;
		let client = test_client(&zitadel).await;
		let name = format!("zapp-insecure/{}#{subject}", iss.trim_start_matches("http://"));
		Mock::given(method("POST"))
			.and(path("/management/v1/projects"))
			.and(body_partial_json(json!({ "name": name })))
			.respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "10" })))
			.expect(1)
			.mount(&zitadel)
			.await;
		Mock::given(method("POST"))
			.and(path("/management/v1/users/machine"))
			.and(body_partial_json(json!({ "userName": name })))
			.respond_with(ResponseTemplate::new(200).set_body_json(json!({ "userId": "20" })))
			.expect(1)
			.mount(&zitadel)
			.await;
		Mock::given(method("POST"))
			.and(path("/management/v1/projects/10/members"))
			.respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
			.mount(&zitadel)
			.await;
		//= docs/requirements/zapp.md#audit-1
		//= type=test
		//# zapp MUST record the verified issuer in the metadata of the service
		//# account, and for a subject-scoped grant also the verified subject.
		let expected_metadata = BTreeMap::from([
			("origin".to_string(), iss.clone()),
			("creator.10".to_string(), "1".to_string()),
			("subject".to_string(), subject.to_string()),
		]);
		Mock::given(method("POST"))
			.and(path("/management/v1/users/20/metadata/_bulk"))
			.and(move |request: &wiremock::Request| metadata_of(request) == expected_metadata)
			.respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
			.expect(1)
			.mount(&zitadel)
			.await;
		Mock::given(method("POST"))
			.and(path("/management/v1/orgs/me/members"))
			.and(body_partial_json(json!({ "userId": "20", "roles": ["ORG_USER_MANAGER"] })))
			.respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
			.expect(1)
			.mount(&zitadel)
			.await;
		Mock::given(method("POST"))
			.and(path("/management/v1/users/20/pats"))
			.respond_with(ResponseTemplate::new(200).set_body_json(json!({ "token": "pat" })))
			.mount(&zitadel)
			.await;

		let resolver = RecordingResolver::default();
		let subjects = resolver.subjects.clone();
		let state = Arc::new(AppState {
			verifier: DomainVerifier::new(&VerificationConfig::default(), true).unwrap(),
			resolver: Box::new(resolver),
			zitadel: Arc::new(client),
			account_prefix_https: "zapp/".to_string(),
			account_prefix_http: Some("zapp-insecure/".to_string()),
		});
		// Unsigned: introspection vouches for it. The payload's own sub is
		// ignored.
		let payload = json!({ "iss": iss, "aud": "zapp", "sub": "from-payload" });
		let token = format!(
			"{}.{}.signature",
			URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#),
			URL_SAFE_NO_PAD.encode(payload.to_string())
		);
		let request = axum::http::Request::post("/v1/credentials")
			.header(header::AUTHORIZATION, format!("Bearer {token}"))
			.body(Body::empty())
			.unwrap();

		let response = router(state).oneshot(request).await.unwrap();
		let status = response.status();
		let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
		assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
		let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
		assert_eq!(body["username"], name);

		//= docs/requirements/zapp.md#subject-4
		//= type=test
		//# zapp MUST pass the verified subject to the permission resolver.
		assert_eq!(*subjects.lock().unwrap(), [Some(subject.to_string())]);
	}

	/// Sends an unsigned token for issuer `iss` to a zapp whose Zitadel is
	/// a bare mock, and returns the status and the JSON body.
	async fn request_credentials(
		iss: &str,
		resolver: RecordingResolver,
	) -> (StatusCode, serde_json::Value) {
		let zitadel = MockServer::start().await;
		let state = Arc::new(AppState {
			verifier: DomainVerifier::new(&VerificationConfig::default(), true).unwrap(),
			resolver: Box::new(resolver),
			zitadel: Arc::new(test_client(&zitadel).await),
			account_prefix_https: "zapp/".to_string(),
			account_prefix_http: Some("zapp-insecure/".to_string()),
		});
		let payload = json!({ "iss": iss, "aud": "zapp" });
		let token = format!(
			"{}.{}.signature",
			URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#),
			URL_SAFE_NO_PAD.encode(payload.to_string())
		);
		let request = axum::http::Request::post("/v1/credentials")
			.header(header::AUTHORIZATION, format!("Bearer {token}"))
			.body(Body::empty())
			.unwrap();
		let response = router(state).oneshot(request).await.unwrap();
		let status = response.status();
		let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
		(status, serde_json::from_slice(&body).unwrap())
	}

	#[tokio::test]
	async fn does_not_contact_issuers_without_a_grant() {
		let issuer = MockServer::start().await;
		Mock::given(wiremock::matchers::any())
			.respond_with(ResponseTemplate::new(500))
			.expect(0)
			.mount(&issuer)
			.await;
		let resolver = RecordingResolver { refuse_issuers: true, ..RecordingResolver::default() };
		let subjects = resolver.subjects.clone();

		//= docs/requirements/zapp.md#verify-1
		//= type=test
		//# zapp MUST NOT send any request to the issuer of a token unless the
		//# issuer claimed by the token matches the issuer pattern of some
		//# grant.
		let (status, body) = request_credentials(&issuer.uri(), resolver).await;
		assert_eq!(status, StatusCode::FORBIDDEN);
		assert_eq!(body["error"], "issuer_not_entitled");
		assert!(subjects.lock().unwrap().is_empty());
	}

	#[tokio::test]
	async fn hides_issuer_errors_from_clients() {
		let issuer = MockServer::start().await;
		Mock::given(method("GET"))
			.and(path("/.well-known/openid-configuration"))
			.respond_with(ResponseTemplate::new(503))
			.expect(1)
			.mount(&issuer)
			.await;

		//= docs/requirements/zapp.md#verify-1
		//= type=test
		//# zapp MUST NOT return to the client what went wrong in a request to
		//# the issuer.
		let (status, body) = request_credentials(&issuer.uri(), RecordingResolver::default()).await;
		assert_eq!(status, StatusCode::UNAUTHORIZED);
		assert_eq!(body["error"], "verification_failed");
		assert_eq!(body["message"], "the token could not be verified with its issuer");
	}
}
