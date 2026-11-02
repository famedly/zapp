// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::time::Duration;

use anyhow::Context as _;
use jsonwebtoken::{AlgorithmFamily, DecodingKey, Validation, jwk::JwkSet};
use serde::Deserialize;

use crate::{
	config::VerificationConfig,
	policy::{is_valid_domain, is_valid_path},
};

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
	#[error("malformed bearer token: {0}")]
	MalformedToken(String),
	#[error("token has no usable issuer claim")]
	MissingIssuer,
	#[error("issuer {0:?} is not an https:// or http:// URL with a valid domain")]
	InvalidIssuerDomain(String),
	#[error(
		"issuer {0:?} has an invalid path (segments must be lowercase alphanumerics, '-', '_' or '.'; no credentials/query/fragment)"
	)]
	InvalidIssuerPath(String),
	#[error("plain-http issuer {0:?} is not accepted (no account_prefix_http configured)")]
	HttpIssuerDisallowed(String),
	#[error("discovery on {domain} failed: {reason}")]
	Discovery { domain: String, reason: String },
	#[error("{0} metadata has neither introspection_endpoint nor jwks_uri")]
	NoDiscoveredMethod(String),
	#[error("introspection endpoint {0:?} is not a URL on the issuer's origin")]
	UntrustedIntrospectionEndpoint(String),
	#[error("introspection request to {domain} failed: {reason}")]
	Introspection { domain: String, reason: String },
	#[error("token was rejected by the introspection endpoint of {0}")]
	TokenInactive(String),
	#[error("discovery document issuer {found:?} does not match token issuer {expected:?}")]
	IssuerMismatch { expected: String, found: String },
	#[error("jwks_uri {0:?} is not a URL on the issuer's origin")]
	UntrustedJwksUri(String),
	#[error("token audience {found:?} does not include the required audience {expected:?}")]
	AudienceMismatch { expected: String, found: Vec<String> },
	#[error("JWKS contains no key matching the token")]
	NoMatchingKey,
	#[error("token failed JWKS validation: {0}")]
	Jwt(String),
}

/// Claims parsed from an unverified token payload: the raw `iss` value,
/// the origin (scheme, domain, port) and normalized path extracted from
/// it, and the audiences (`aud`).
#[derive(Debug, Clone)]
pub struct TokenClaims {
	pub raw: String,
	/// "https" or "http". Plain http is accepted here; keeping grant
	/// patterns on https:// is the operator's responsibility.
	pub scheme: String,
	pub domain: String,
	/// Non-default port, if any.
	pub port: Option<u16>,
	/// Normalized path: "" for root, otherwise "/a/b" (validated, see
	/// `policy::is_valid_path`).
	pub path: String,
	pub audiences: Vec<String>,
	/// The token's subject (`sub`), set only once the token has been
	/// verified: from the validated JWT claims, or from the introspection
	/// response. Never taken from the unverified payload.
	pub subject: Option<String>,
}

impl TokenClaims {
	/// The normalized issuer URL.
	pub fn issuer_url(&self) -> String {
		format!("{}://{}{}", self.scheme, self.host_port(), self.path)
	}

	/// Host with the non-default port appended, if any ("localhost:39231").
	pub fn host_port(&self) -> String {
		match self.port {
			Some(port) => format!("{}:{port}", self.domain),
			None => self.domain.clone(),
		}
	}

	/// Names the service account (and project) for this issuer:
	/// `<prefix><host>[:<port>][/<path>]`, i.e. the issuer URL with the
	/// `<scheme>://` replaced verbatim by the configured per-scheme prefix
	/// (no separator is inserted; include one in the prefix if wanted).
	/// https and http use distinct prefixes, which keeps the namespaces
	/// disjoint.
	pub fn account_name(&self, prefix: &str) -> String {
		format!("{prefix}{}{}", self.host_port(), self.path)
	}

	/// Names the service account (and project) for this issuer and a
	/// subject: `<account_name>#<subject>`, the subject percent-encoded
	/// outside `[a-z0-9:._-]` (so `#` never appears in it), or `None` if the
	/// name would exceed Zitadel's 200 characters. Neither the prefix nor
	/// the issuer part can contain `#`, so the name is unambiguous.
	pub fn subject_account_name(&self, prefix: &str, subject: &str) -> Option<String> {
		//= docs/requirements/zapp.md#subject-3
		//# The name for a pair of issuer and subject MUST differ from the name
		//# for every other issuer and from the name for every other pair of
		//# issuer and subject.
		let mut name = format!("{}#", self.account_name(prefix));
		//= docs/requirements/zapp.md#subject-3
		//# In names, zapp MUST percent-encode every character of the subject
		//# other than lower-case letters, digits, colons, dots, underscores and
		//# hyphens, so that the subjects of any issuer give valid and distinct
		//# names.
		for byte in subject.bytes() {
			match byte {
				b'a'..=b'z' | b'0'..=b'9' | b':' | b'.' | b'_' | b'-' => name.push(byte as char),
				_ => name.push_str(&format!("%{byte:02x}")),
			}
		}
		//= docs/requirements/zapp.md#subject-3
		//# zapp MUST reject a subject if the resulting name would be longer
		//# than 200 characters.
		(name.chars().count() <= MAX_NAME_LENGTH).then_some(name)
	}

	/// URL of the OpenID Connect discovery document for this issuer.
	fn discovery_url(&self) -> String {
		format!("{}/.well-known/openid-configuration", self.issuer_url())
	}
}

/// Longest service account (user) and project name Zitadel accepts.
const MAX_NAME_LENGTH: usize = 200;

/// Verifies domain ownership.
///
/// The issuer domain is taken from the token's `iss` claim, and
/// `{issuer}/.well-known/openid-configuration` is fetched from it. If the
/// metadata advertises an `introspection_endpoint`, the token is verified
/// via OAuth 2.0 token introspection (RFC 7662); otherwise its signature
/// is verified against the advertised `jwks_uri` (suited for Kubernetes
/// service account tokens whose issuer is served publicly).
///
/// The trust anchor is the discovery fetch, which is pinned to the claimed
/// origin. Both advertised endpoints must additionally be URLs on that
/// same origin: this rejects transitive trust in third-party
/// infrastructure and keeps outbound requests pinned to the claimed origin.
///
/// Plain-http issuers are only verified when an http account prefix is
/// configured; beyond that, it is the operator's responsibility to only
/// configure `https://` grant patterns unless plain http is really wanted.
pub struct DomainVerifier {
	http: reqwest::Client,
	/// Audience every token must carry, regardless of verification path.
	audience: String,
	/// Whether plain-http issuers are verified at all (true iff an http
	/// account prefix is configured). Checked before any outbound request,
	/// so with http disabled zapp never talks to arbitrary host:port
	/// origins named in unauthenticated tokens.
	allow_http: bool,
}

#[derive(Deserialize)]
struct DiscoveryMetadata {
	issuer: Option<String>,
	introspection_endpoint: Option<String>,
	jwks_uri: Option<String>,
}

impl DomainVerifier {
	pub fn new(config: &VerificationConfig, allow_http: bool) -> anyhow::Result<Self> {
		let mut builder = reqwest::Client::builder()
			.timeout(Duration::from_secs(config.timeout_secs))
			.redirect(reqwest::redirect::Policy::none());
		if let Some(ca_file) = &config.ca_file {
			//= docs/requirements/zapp.md#ca-1
			//# zapp MUST refuse to start if the configured CA bundle cannot be
			//# read or contains no certificate.
			let pem = std::fs::read(ca_file)
				.with_context(|| format!("reading verification.ca_file {}", ca_file.display()))?;
			let certs = reqwest::Certificate::from_pem_bundle(&pem)
				.with_context(|| format!("parsing verification.ca_file {}", ca_file.display()))?;
			anyhow::ensure!(
				!certs.is_empty(),
				"verification.ca_file {} contains no certificate",
				ca_file.display()
			);
			//= docs/requirements/zapp.md#ca-1
			//# If a CA bundle is configured, zapp MUST trust its certificates
			//# for discovery, introspection and JWKS requests, in addition to
			//# the system's trusted roots.
			builder = builder.tls_certs_merge(certs);
		}
		let http = builder.build()?;
		Ok(Self { http, audience: config.audience.clone(), allow_http })
	}

	/// Verifies the token and returns the proven issuer claims.
	pub async fn verify(&self, token: &str) -> Result<TokenClaims, VerifyError> {
		let mut issuer = parse_claims(token)?;

		if issuer.scheme == "http" && !self.allow_http {
			return Err(VerifyError::HttpIssuerDisallowed(issuer.raw));
		}

		// Audience binding applies to every token, no matter how it is
		// verified: it prevents tokens minted for other services from
		// being replayed against zapp.
		if !issuer.audiences.iter().any(|a| a == &self.audience) {
			return Err(VerifyError::AudienceMismatch {
				expected: self.audience.clone(),
				found: issuer.audiences,
			});
		}

		let metadata = self.fetch_discovery(&issuer).await.map_err(|e| VerifyError::Discovery {
			domain: issuer.domain.clone(),
			reason: e.to_string(),
		})?;

		issuer.subject = if let Some(endpoint) = metadata.introspection_endpoint {
			self.introspect(&issuer, &endpoint, token).await?
		} else if let Some(jwks_uri) = metadata.jwks_uri {
			self.verify_jwks(&issuer, metadata.issuer.as_deref(), &jwks_uri, token).await?
		} else {
			return Err(VerifyError::NoDiscoveredMethod(issuer.domain));
		};
		Ok(issuer)
	}

	async fn fetch_discovery(&self, issuer: &TokenClaims) -> reqwest::Result<DiscoveryMetadata> {
		let url = issuer.discovery_url();
		let response = self.http.get(&url).send().await?.error_for_status()?;
		response.json().await
	}

	async fn introspect(
		&self,
		issuer: &TokenClaims,
		endpoint: &str,
		token: &str,
	) -> Result<Option<String>, VerifyError> {
		let domain = issuer.domain.as_str();
		// Not strictly required for the core proof: the discovery document
		// itself was fetched from the claimed origin, so the origin
		// endorsed this endpoint. We still reject delegation to other hosts
		// (defense in depth): off-origin verifiers can be compromised, lapse
		// or change hands independently of the domain, and pinning outbound
		// requests to the claimed origin contains SSRF. Ownership here means
		// the origin itself answers for the token, not that it once pointed
		// at some third party that does.
		let parsed: reqwest::Url = endpoint
			.parse()
			.map_err(|_| VerifyError::UntrustedIntrospectionEndpoint(endpoint.to_string()))?;
		if parsed.scheme() != issuer.scheme
			|| parsed.host_str() != Some(domain)
			|| parsed.port() != issuer.port
		{
			return Err(VerifyError::UntrustedIntrospectionEndpoint(endpoint.to_string()));
		}

		#[derive(Deserialize)]
		struct IntrospectionResponse {
			active: bool,
			sub: Option<String>,
		}

		let response = self
			.http
			.post(endpoint)
			.form(&[("token", token)])
			.send()
			.await
			.map_err(|e| VerifyError::Introspection {
				domain: domain.to_string(),
				reason: e.to_string(),
			})?
			.error_for_status()
			.map_err(|e| VerifyError::Introspection {
				domain: domain.to_string(),
				reason: e.to_string(),
			})?;
		let body: IntrospectionResponse =
			response.json().await.map_err(|e| VerifyError::Introspection {
				domain: domain.to_string(),
				reason: format!("invalid introspection response: {e}"),
			})?;
		if !body.active {
			return Err(VerifyError::TokenInactive(domain.to_string()));
		}
		//= docs/requirements/zapp.md#subject-2
		//# When zapp verifies a token by introspection, it MUST take the
		//# subject only from the introspection response and MUST NOT take it
		//# from the token payload.
		Ok(body.sub)
	}

	async fn verify_jwks(
		&self,
		issuer: &TokenClaims,
		metadata_issuer: Option<&str>,
		jwks_uri: &str,
		token: &str,
	) -> Result<Option<String>, VerifyError> {
		// The discovery document must name the issuer we asked for; this
		// binds the key set to the token's iss claim.
		let found = metadata_issuer.unwrap_or_default();
		let matches_raw = found.trim_end_matches('/') == issuer.raw.trim_end_matches('/');
		// The discovery document may also name the normalized form of the
		// token's iss (e.g. without an explicitly spelled-out default port).
		let matches_normalized = found.trim_end_matches('/') == issuer.issuer_url();
		if !matches_raw && !matches_normalized {
			return Err(VerifyError::IssuerMismatch {
				expected: issuer.raw.clone(),
				found: found.to_string(),
			});
		}

		// Same-origin pin as for the introspection endpoint (see there):
		// the discovery document already endorses this jwks_uri, but we
		// reject off-origin delegation so the key material vouching for
		// the token is served by the claimed origin itself.
		let jwks_url: reqwest::Url =
			jwks_uri.parse().map_err(|_| VerifyError::UntrustedJwksUri(jwks_uri.to_string()))?;
		if jwks_url.scheme() != issuer.scheme
			|| jwks_url.host_str() != Some(issuer.domain.as_str())
			|| jwks_url.port() != issuer.port
		{
			return Err(VerifyError::UntrustedJwksUri(jwks_uri.to_string()));
		}

		let discovery =
			|reason: String| VerifyError::Discovery { domain: issuer.domain.clone(), reason };
		let response = self
			.http
			.get(jwks_url)
			.send()
			.await
			.map_err(|e| discovery(format!("fetching JWKS: {e}")))?
			.error_for_status()
			.map_err(|e| discovery(format!("JWKS fetch returned {e}")))?;
		let jwks: JwkSet =
			response.json().await.map_err(|e| discovery(format!("invalid JWKS document: {e}")))?;

		validate_with_jwks(&jwks, token, &self.audience, &issuer.raw)
	}
}

/// Validates signature, expiry, audience and issuer of a token against a
/// JWK set and returns its subject (`sub`), if any. Pure so it can be tested
/// without network access.
fn validate_with_jwks(
	jwks: &JwkSet,
	token: &str,
	audience: &str,
	issuer: &str,
) -> Result<Option<String>, VerifyError> {
	let header = jsonwebtoken::decode_header(token)
		.map_err(|e| VerifyError::MalformedToken(e.to_string()))?;

	// Asymmetric algorithms only; never HS* (the JWKS is public) or none.
	let algorithm = match header.alg.family() {
		AlgorithmFamily::Rsa | AlgorithmFamily::Ec | AlgorithmFamily::Ed => header.alg,
		other => {
			return Err(VerifyError::Jwt(format!("disallowed algorithm {other:?}")));
		}
	};

	let jwk = match &header.kid {
		Some(kid) => jwks.find(kid).ok_or(VerifyError::NoMatchingKey)?,
		// Without a kid we can only proceed unambiguously with a single key.
		None if jwks.keys.len() == 1 => &jwks.keys[0],
		None => return Err(VerifyError::NoMatchingKey),
	};
	let key =
		DecodingKey::from_jwk(jwk).map_err(|e| VerifyError::Jwt(format!("unusable JWK: {e}")))?;

	let mut validation = Validation::new(algorithm);
	validation.set_audience(&[audience]);
	validation.set_issuer(&[issuer]);
	validation.set_required_spec_claims(&["exp", "aud", "iss"]);

	#[derive(Deserialize)]
	struct Validated {
		sub: Option<String>,
	}
	let validated = jsonwebtoken::decode::<Validated>(token, &key, &validation)
		.map_err(|e| VerifyError::Jwt(e.to_string()))?;
	//= docs/requirements/zapp.md#subject-2
	//# When zapp verifies a token by its signature, it MUST take the subject
	//# only from the claims of the validated token.
	Ok(validated.claims.sub)
}

/// Extracts issuer and audiences from an (unverified) JWT payload. The
/// issuer is only used to decide *which* domain to ask for verification;
/// trust is established by the introspection or JWKS check against that
/// domain.
pub fn parse_claims(token: &str) -> Result<TokenClaims, VerifyError> {
	#[derive(Deserialize)]
	struct RawClaims {
		iss: Option<String>,
		aud: Option<RawAudience>,
	}

	/// RFC 7519: aud is either a single string or an array of strings.
	#[derive(Deserialize)]
	#[serde(untagged)]
	enum RawAudience {
		One(String),
		Many(Vec<String>),
	}

	// Decode without verifying: the claims only determine *which* domain
	// to ask for verification. All checks (signature or introspection,
	// exp, aud) happen afterwards against that domain.
	let raw = jsonwebtoken::dangerous::insecure_decode::<RawClaims>(token)
		.map_err(|e| VerifyError::MalformedToken(e.to_string()))?
		.claims;

	let issuer = raw.iss.as_deref().ok_or(VerifyError::MissingIssuer)?;
	let audiences = match raw.aud {
		Some(RawAudience::One(aud)) => vec![aud],
		Some(RawAudience::Many(auds)) => auds,
		None => Vec::new(),
	};

	// The issuer must be a full https or plain-http URL; bare domains
	// are rejected (matching OpenID Connect, where iss is always a URL).
	// http is not rejected here: whether it is trusted is decided by the
	// http opt-in and the configured grant patterns.
	let url: reqwest::Url =
		issuer.parse().map_err(|_| VerifyError::InvalidIssuerDomain(issuer.to_string()))?;
	if url.scheme() != "https" && url.scheme() != "http" {
		return Err(VerifyError::InvalidIssuerDomain(issuer.to_string()));
	}
	// Credentials, queries and fragments have no place in an issuer.
	if !url.username().is_empty()
		|| url.password().is_some()
		|| url.query().is_some()
		|| url.fragment().is_some()
	{
		return Err(VerifyError::InvalidIssuerPath(issuer.to_string()));
	}
	let domain = url
		.host_str()
		.ok_or_else(|| VerifyError::InvalidIssuerDomain(issuer.to_string()))?
		.to_string();
	let path = url.path().trim_end_matches('/').to_string();
	if !is_valid_path(&path) {
		return Err(VerifyError::InvalidIssuerPath(issuer.to_string()));
	}
	let (scheme, port) = (url.scheme().to_string(), url.port());

	if !is_valid_domain(&domain) {
		return Err(VerifyError::InvalidIssuerDomain(issuer.to_string()));
	}
	// The subject is only filled in after verification.
	Ok(TokenClaims {
		raw: issuer.to_string(),
		scheme,
		domain,
		port,
		path,
		audiences,
		subject: None,
	})
}

#[cfg(test)]
mod tests {
	use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
	use jsonwebtoken::{Algorithm, EncodingKey, Header};
	use p256::{elliptic_curve::sec1::ToEncodedPoint, pkcs8::EncodePrivateKey};
	use serde_json::json;

	use super::*;

	fn jwt_with_payload(payload: &str) -> String {
		let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
		let body = URL_SAFE_NO_PAD.encode(payload);
		format!("{header}.{body}.signature")
	}

	/// Serves `{iss}/.well-known/openid-configuration` and an introspection
	/// endpoint over TLS on `localhost`, with a certificate issued by a
	/// freshly generated CA. Returns the issuer URL and the CA certificate
	/// (PEM).
	async fn tls_issuer() -> (String, String) {
		use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
		use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
		use tokio_rustls::{
			TlsAcceptor,
			rustls::{
				ServerConfig,
				pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
			},
		};

		let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
		ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
		let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
		let server_key = KeyPair::generate().unwrap();
		let server_cert = CertificateParams::new(vec!["localhost".to_string()])
			.unwrap()
			.signed_by(&server_key, &ca)
			.unwrap();
		let config = ServerConfig::builder()
			.with_no_client_auth()
			.with_single_cert(
				vec![server_cert.der().clone()],
				PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
			)
			.unwrap();
		let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));

		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let iss = format!("https://localhost:{}", listener.local_addr().unwrap().port());
		let discovery =
			json!({ "issuer": iss, "introspection_endpoint": format!("{iss}/introspect") })
				.to_string();
		tokio::spawn(async move {
			while let Ok((tcp, _)) = listener.accept().await {
				let (acceptor, discovery) = (acceptor.clone(), discovery.clone());
				tokio::spawn(async move {
					let Ok(mut tls) = acceptor.accept(tcp).await else { return };
					// Read the head and the body announced in it, then answer
					// by request line and close.
					let mut request = Vec::new();
					let mut buf = [0u8; 4096];
					loop {
						let n = tls.read(&mut buf).await.unwrap_or(0);
						if n == 0 {
							return;
						}
						request.extend_from_slice(&buf[..n]);
						let text = String::from_utf8_lossy(&request).to_ascii_lowercase();
						if let Some(end) = text.find("\r\n\r\n") {
							let length = text
								.lines()
								.find_map(|line| line.strip_prefix("content-length:"))
								.and_then(|value| value.trim().parse::<usize>().ok())
								.unwrap_or(0);
							if request.len() >= end + 4 + length {
								break;
							}
						}
					}
					let body = if request.starts_with(b"GET /.well-known/openid-configuration") {
						discovery
					} else {
						json!({ "active": true, "sub": "tls-subject" }).to_string()
					};
					let response = format!(
						"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
						body.len()
					);
					tls.write_all(response.as_bytes()).await.ok();
					tls.shutdown().await.ok();
				});
			}
		});
		(iss, ca.pem())
	}

	fn write_temp(contents: &str) -> std::path::PathBuf {
		let path = std::env::temp_dir().join(format!(
			"zapp-test-ca-{}-{}.pem",
			std::process::id(),
			std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
		));
		std::fs::write(&path, contents).unwrap();
		path
	}

	fn verification(ca_file: Option<std::path::PathBuf>) -> VerificationConfig {
		VerificationConfig { audience: "zapp".to_string(), timeout_secs: 5, ca_file }
	}

	#[tokio::test]
	async fn trusts_a_configured_ca_bundle() {
		let (iss, ca_pem) = tls_issuer().await;
		let token = jwt_with_payload(&json!({ "iss": iss, "aud": "zapp", "sub": "x" }).to_string());

		let untrusting = DomainVerifier::new(&verification(None), false).unwrap();
		assert!(
			matches!(untrusting.verify(&token).await, Err(VerifyError::Discovery { .. })),
			"the test CA must not be trusted by default"
		);

		//= docs/requirements/zapp.md#ca-1
		//= type=test
		//# If a CA bundle is configured, zapp MUST trust its certificates for
		//# discovery, introspection and JWKS requests, in addition to the
		//# system's trusted roots.
		let ca_file = write_temp(&ca_pem);
		let trusting = DomainVerifier::new(&verification(Some(ca_file.clone())), false).unwrap();
		std::fs::remove_file(ca_file).ok();
		let claims = trusting.verify(&token).await.expect("verified over TLS");
		assert_eq!(claims.subject.as_deref(), Some("tls-subject"));
	}

	#[test]
	fn rejects_unusable_ca_bundles() {
		//= docs/requirements/zapp.md#ca-1
		//= type=test
		//# zapp MUST refuse to start if the configured CA bundle cannot be read
		//# or contains no certificate.
		let missing = std::env::temp_dir().join("zapp-test-ca-does-not-exist.pem");
		assert!(DomainVerifier::new(&verification(Some(missing)), false).is_err());
		let empty = write_temp("not a certificate\n");
		assert!(DomainVerifier::new(&verification(Some(empty.clone())), false).is_err());
		std::fs::remove_file(empty).ok();
	}

	#[test]
	fn rejects_bare_domain_issuer() {
		// The issuer must be a full URL, as in OpenID Connect.
		let token = jwt_with_payload(r#"{"iss":"app.famedly.dev"}"#);
		assert!(matches!(parse_claims(&token), Err(VerifyError::InvalidIssuerDomain(_))));
	}

	#[test]
	fn extracts_url_issuer() {
		let claims =
			parse_claims(&jwt_with_payload(r#"{"iss":"https://app.famedly.dev/auth"}"#)).unwrap();
		assert_eq!(claims.domain, "app.famedly.dev");
		assert_eq!(claims.path, "/auth");
		assert_eq!(claims.issuer_url(), "https://app.famedly.dev/auth");
	}

	#[test]
	fn rejects_invalid_issuer_paths() {
		for iss in [
			"https://app.famedly.dev/K8S",
			"https://app.famedly.dev/k8s?x=1",
			"https://app.famedly.dev/k8s#frag",
			"https://user@app.famedly.dev/k8s",
		] {
			let token = jwt_with_payload(&format!(r#"{{"iss":"{iss}"}}"#));
			assert!(
				matches!(parse_claims(&token), Err(VerifyError::InvalidIssuerPath(_))),
				"expected rejection of {iss}"
			);
		}
	}

	fn named(iss: &str, prefix: &str) -> String {
		parse_claims(&jwt_with_payload(&format!(r#"{{"iss":"{iss}"}}"#)))
			.unwrap()
			.account_name(prefix)
	}

	#[test]
	fn names_account_after_issuer() {
		//= docs/requirements/zapp.md#subject-3
		//= type=test
		//# If the matching grant has no subject pattern, the names MUST stay
		//# the same as without subject support.
		assert_eq!(
			named("https://my-app.famedly.dev/k8s/c1", "zapp/"),
			"zapp/my-app.famedly.dev/k8s/c1"
		);
		assert_eq!(named("https://app.famedly.dev", "zapp/"), "zapp/app.famedly.dev");
		assert_eq!(named("https://app.famedly.dev/k8s/", "zapp/"), "zapp/app.famedly.dev/k8s");
		// The prefix is used verbatim: no separator is inserted.
		assert_eq!(named("https://app.famedly.dev/k8s", "zapp-"), "zapp-app.famedly.dev/k8s");
		// Non-default ports are kept; default ports are omitted even when
		// spelled out (the url crate normalizes them away at parse time).
		assert_eq!(
			named("http://localhost:39231/", "zapp-insecure/"),
			"zapp-insecure/localhost:39231"
		);
		assert_eq!(named("https://app.famedly.dev:443/k8s", "zapp/"), "zapp/app.famedly.dev/k8s");
		assert_eq!(
			named("https://app.famedly.dev:8443/k8s", "zapp/"),
			"zapp/app.famedly.dev:8443/k8s"
		);
	}

	#[test]
	fn names_account_after_issuer_and_subject() {
		let claims =
			|iss: &str| parse_claims(&jwt_with_payload(&format!(r#"{{"iss":"{iss}"}}"#))).unwrap();
		let k8s = claims("https://k8s.example.com");
		//= docs/requirements/zapp.md#subject-3
		//= type=test
		//# If the matching grant has a subject pattern, the names of the
		//# service account and the project MUST contain the subject, so that
		//# every pair of issuer and subject gets its own service account and
		//# project.
		assert_eq!(
			k8s.subject_account_name("zapp/", "system:serviceaccount:tenant-a:admin-api")
				.as_deref(),
			Some("zapp/k8s.example.com#system:serviceaccount:tenant-a:admin-api")
		);
		//= docs/requirements/zapp.md#subject-3
		//= type=test
		//# In names, zapp MUST percent-encode every character of the subject
		//# other than lower-case letters, digits, colons, dots, underscores and
		//# hyphens, so that the subjects of any issuer give valid and distinct
		//# names.
		assert_eq!(
			k8s.subject_account_name("zapp/", "Auth0|a b@c#%").as_deref(),
			Some("zapp/k8s.example.com#%41uth0%7ca%20b%40c%23%25")
		);
		// Upper-case letters are encoded, so subjects differing in case do
		// not collide in Zitadel's case-insensitive user names.
		assert_ne!(k8s.subject_account_name("zapp/", "A"), k8s.subject_account_name("zapp/", "a"));
		// Non-ASCII subjects are encoded byte by byte.
		assert_eq!(
			k8s.subject_account_name("zapp/", "ü").as_deref(),
			Some("zapp/k8s.example.com#%c3%bc")
		);

		//= docs/requirements/zapp.md#subject-3
		//= type=test
		//# The name for a pair of issuer and subject MUST differ from the name
		//# for every other issuer and from the name for every other pair of
		//# issuer and subject.
		let with_port = claims("https://k8s.example.com:8443");
		let with_path = claims("https://k8s.example.com/x");
		let names = [
			k8s.account_name("zapp/"),
			with_port.account_name("zapp/"),
			with_path.account_name("zapp/"),
			k8s.subject_account_name("zapp/", "8443").unwrap(),
			k8s.subject_account_name("zapp/", "x").unwrap(),
			k8s.subject_account_name("zapp/", "/x").unwrap(),
			with_path.subject_account_name("zapp/", "y").unwrap(),
			k8s.subject_account_name("zapp/", "x#y").unwrap(),
			k8s.subject_account_name("zapp/", "x%23y").unwrap(),
		];
		let distinct: std::collections::BTreeSet<_> = names.iter().collect();
		assert_eq!(distinct.len(), names.len(), "{names:?}");

		//= docs/requirements/zapp.md#subject-3
		//= type=test
		//# zapp MUST reject a subject if the resulting name would be longer
		//# than 200 characters.
		let base = k8s.account_name("zapp/").len() + 1;
		assert!(k8s.subject_account_name("zapp/", &"a".repeat(200 - base)).is_some());
		assert!(k8s.subject_account_name("zapp/", &"a".repeat(201 - base)).is_none());
		assert!(k8s.subject_account_name("zapp/", &"A".repeat(60)).is_none());
	}

	#[test]
	fn extracts_http_url_issuer_with_port() {
		// Plain http is not rejected here; whether it is trusted is up to
		// the configured grant patterns.
		let claims =
			parse_claims(&jwt_with_payload(r#"{"iss":"http://localhost:39231/"}"#)).unwrap();
		assert_eq!(claims.scheme, "http");
		assert_eq!(claims.domain, "localhost");
		assert_eq!(claims.port, Some(39231));
		assert_eq!(claims.path, "");
		assert_eq!(claims.issuer_url(), "http://localhost:39231");
		assert_eq!(
			claims.discovery_url(),
			"http://localhost:39231/.well-known/openid-configuration"
		);
	}

	#[test]
	fn rejects_non_http_scheme_issuer() {
		let token = jwt_with_payload(r#"{"iss":"ftp://app.famedly.dev"}"#);
		assert!(matches!(parse_claims(&token), Err(VerifyError::InvalidIssuerDomain(_))));
	}

	#[test]
	fn rejects_missing_issuer() {
		let token = jwt_with_payload(r#"{"sub":"x"}"#);
		assert!(matches!(parse_claims(&token), Err(VerifyError::MissingIssuer)));
	}

	#[test]
	fn rejects_garbage() {
		assert!(matches!(parse_claims("not-a-jwt"), Err(VerifyError::MalformedToken(_))));
	}

	#[test]
	fn discovery_url_strips_trailing_slash() {
		let url_issuer =
			parse_claims(&jwt_with_payload(r#"{"iss":"https://app.famedly.dev/k8s/"}"#)).unwrap();
		assert_eq!(
			url_issuer.discovery_url(),
			"https://app.famedly.dev/k8s/.well-known/openid-configuration"
		);
		let root_issuer =
			parse_claims(&jwt_with_payload(r#"{"iss":"https://app.famedly.dev"}"#)).unwrap();
		assert_eq!(
			root_issuer.discovery_url(),
			"https://app.famedly.dev/.well-known/openid-configuration"
		);
	}

	#[test]
	fn parses_string_and_array_audiences() {
		let single =
			parse_claims(&jwt_with_payload(r#"{"iss":"https://app.famedly.dev","aud":"zapp"}"#))
				.unwrap();
		assert_eq!(single.audiences, vec!["zapp"]);

		let multiple = parse_claims(&jwt_with_payload(
			r#"{"iss":"https://app.famedly.dev","aud":["zapp","other"]}"#,
		))
		.unwrap();
		assert_eq!(multiple.audiences, vec!["zapp", "other"]);

		let missing =
			parse_claims(&jwt_with_payload(r#"{"iss":"https://app.famedly.dev"}"#)).unwrap();
		assert!(missing.audiences.is_empty());
	}

	// --- JWKS validation, with a keypair generated on demand ---

	const ISSUER: &str = "https://app.famedly.dev/k8s";
	const AUDIENCE: &str = "zapp";

	/// Generates a fresh P-256 keypair: (signing key, JWKS with the public
	/// key under kid "test").
	fn test_keypair() -> (EncodingKey, JwkSet) {
		let secret = p256::SecretKey::random(&mut rand_core::OsRng);
		let der = secret.to_pkcs8_der().expect("encode private key");
		let encoding_key = EncodingKey::from_ec_der(der.as_bytes());

		let point = secret.public_key().to_encoded_point(false);
		let jwks = serde_json::from_value(json!({
			"keys": [{
				"kty": "EC",
				"crv": "P-256",
				"alg": "ES256",
				"use": "sig",
				"kid": "test",
				"x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
				"y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
			}]
		}))
		.expect("valid JWKS");
		(encoding_key, jwks)
	}

	fn sign(key: &EncodingKey, kid: &str, claims: serde_json::Value) -> String {
		let mut header = Header::new(Algorithm::ES256);
		header.kid = Some(kid.to_string());
		jsonwebtoken::encode(&header, &claims, key).expect("signing")
	}

	fn now() -> i64 {
		std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
	}

	#[test]
	fn jwks_accepts_valid_token() {
		let (key, jwks) = test_keypair();
		let token = sign(
			&key,
			"test",
			json!({
				"iss": ISSUER,
				"aud": [AUDIENCE],
				"sub": "system:serviceaccount:default:zapp-client",
				"exp": now() + 300,
			}),
		);
		//= docs/requirements/zapp.md#subject-2
		//= type=test
		//# When zapp verifies a token by its signature, it MUST take the
		//# subject only from the claims of the validated token.
		assert_eq!(
			validate_with_jwks(&jwks, &token, AUDIENCE, ISSUER).expect("valid token").as_deref(),
			Some("system:serviceaccount:default:zapp-client")
		);
	}

	#[tokio::test]
	async fn introspection_subject_comes_from_the_response() {
		use wiremock::{
			Mock, MockServer, ResponseTemplate,
			matchers::{method, path},
		};

		let server = MockServer::start().await;
		let iss = server.uri();
		Mock::given(method("GET"))
			.and(path("/.well-known/openid-configuration"))
			.respond_with(ResponseTemplate::new(200).set_body_json(json!({
				"issuer": iss,
				"introspection_endpoint": format!("{iss}/introspect"),
			})))
			.mount(&server)
			.await;
		let introspected = |body: serde_json::Value| {
			Mock::given(method("POST"))
				.and(path("/introspect"))
				.respond_with(ResponseTemplate::new(200).set_body_json(body))
		};
		// The unverified payload names a different subject than the
		// introspection endpoint.
		let token = jwt_with_payload(
			&json!({ "iss": iss, "aud": AUDIENCE, "sub": "from-payload" }).to_string(),
		);
		let verifier = DomainVerifier::new(
			&VerificationConfig { audience: AUDIENCE.to_string(), timeout_secs: 5, ca_file: None },
			true,
		)
		.unwrap();

		//= docs/requirements/zapp.md#subject-2
		//= type=test
		//# When zapp verifies a token by introspection, it MUST take the
		//# subject only from the introspection response and MUST NOT take it
		//# from the token payload.
		let mock = introspected(json!({ "active": true, "sub": "from-introspection" }))
			.mount_as_scoped(&server)
			.await;
		let claims = verifier.verify(&token).await.expect("active token");
		assert_eq!(claims.subject.as_deref(), Some("from-introspection"));
		drop(mock);

		introspected(json!({ "active": true })).mount(&server).await;
		let claims = verifier.verify(&token).await.expect("active token");
		assert_eq!(claims.subject, None, "the unverified payload must not be used");
	}

	#[test]
	fn jwks_rejects_wrong_audience() {
		let (key, jwks) = test_keypair();
		let token = sign(
			&key,
			"test",
			json!({"iss": ISSUER, "aud": ["something-else"], "exp": now() + 300}),
		);
		assert!(matches!(
			validate_with_jwks(&jwks, &token, AUDIENCE, ISSUER),
			Err(VerifyError::Jwt(_))
		));
	}

	#[test]
	fn jwks_rejects_missing_audience() {
		let (key, jwks) = test_keypair();
		let token = sign(&key, "test", json!({"iss": ISSUER, "exp": now() + 300}));
		assert!(matches!(
			validate_with_jwks(&jwks, &token, AUDIENCE, ISSUER),
			Err(VerifyError::Jwt(_))
		));
	}

	#[test]
	fn jwks_rejects_expired_token() {
		let (key, jwks) = test_keypair();
		let token =
			sign(&key, "test", json!({"iss": ISSUER, "aud": [AUDIENCE], "exp": now() - 300}));
		assert!(matches!(
			validate_with_jwks(&jwks, &token, AUDIENCE, ISSUER),
			Err(VerifyError::Jwt(_))
		));
	}

	#[test]
	fn jwks_rejects_wrong_key() {
		let (key, _) = test_keypair();
		let (_, other_jwks) = test_keypair();
		let token =
			sign(&key, "test", json!({"iss": ISSUER, "aud": [AUDIENCE], "exp": now() + 300}));
		assert!(matches!(
			validate_with_jwks(&other_jwks, &token, AUDIENCE, ISSUER),
			Err(VerifyError::Jwt(_))
		));
	}

	#[test]
	fn jwks_rejects_unknown_kid() {
		let (key, mut jwks) = test_keypair();
		// A second key in the set forces kid-based selection.
		let (_, other) = test_keypair();
		jwks.keys.extend(other.keys);
		let token =
			sign(&key, "unknown", json!({"iss": ISSUER, "aud": [AUDIENCE], "exp": now() + 300}));
		assert!(matches!(
			validate_with_jwks(&jwks, &token, AUDIENCE, ISSUER),
			Err(VerifyError::NoMatchingKey)
		));
	}

	#[test]
	fn jwks_rejects_symmetric_algorithm() {
		let (_, jwks) = test_keypair();
		let mut header = Header::new(Algorithm::HS256);
		header.kid = Some("test".to_string());
		let token = jsonwebtoken::encode(
			&header,
			&json!({"iss": ISSUER, "aud": [AUDIENCE], "exp": now() + 300}),
			&EncodingKey::from_secret(b"guessable"),
		)
		.unwrap();
		assert!(matches!(
			validate_with_jwks(&jwks, &token, AUDIENCE, ISSUER),
			Err(VerifyError::Jwt(_))
		));
	}
}
