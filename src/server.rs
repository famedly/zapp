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
	verify::{DomainVerifier, VerifyError},
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
				(StatusCode::UNAUTHORIZED, error, e.to_string())
			}
			ApiError::NotEntitled(issuer) => (
				StatusCode::FORBIDDEN,
				"issuer_not_entitled",
				format!("issuer {issuer} does not match any configured pattern"),
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

	let claims = state.verifier.verify(token).await.map_err(|e| {
		info!("issuer verification failed: {e}");
		ApiError::Verify(e)
	})?;
	let issuer = claims.issuer_url();

	let entitlement = state
		.resolver
		.resolve(&claims.scheme, &claims.domain, claims.port, &claims.path)
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

	let provisioned = state
		.zitadel
		.provision(
			&claims.account_name(prefix),
			&issuer,
			&entitlement.org_id,
			entitlement.duration,
			query.credential_type,
		)
		.await
		.map_err(ApiError::Zitadel)?;

	info!(
		"issued {:?} for service account {} ({}) owning project {} in org {} for issuer {issuer} (expires_at {})",
		query.credential_type,
		provisioned.username,
		provisioned.user_id,
		provisioned.project_id,
		entitlement.org_id,
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
