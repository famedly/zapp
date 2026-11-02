// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{path::PathBuf, time::Duration};

use anyhow::Context;
use serde::Deserialize;
use url::Url;

#[derive(Debug, Deserialize)]
pub struct Config {
	/// Address to listen on, e.g. "0.0.0.0:8080".
	#[serde(default = "default_listen")]
	pub listen: String,
	pub zitadel: ZitadelConfig,
	#[serde(default)]
	pub verification: VerificationConfig,
	/// Garbage collection of service accounts whose issuer stopped
	/// renewing. Disabled when absent.
	#[serde(default)]
	pub gc: Option<GcConfig>,
	/// Statically configured issuer grants, matched in order.
	#[serde(default)]
	pub grants: Vec<GrantConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ZitadelConfig {
	/// Base URL of the Zitadel instance, e.g. "https://auth.example.com".
	pub url: Url,
	/// Path to the private key JSON of the Zitadel service user zapp acts
	/// as (Zitadel console: service user → Keys → New → JSON). The service
	/// user must be allowed to manage users, projects and project members
	/// in every organisation named by a grant (IAM_OWNER, or ORG_OWNER on
	/// each of them).
	pub key_file: PathBuf,
	/// Prefix for service account (and project) names of https issuers:
	/// "<prefix><host>[:<port>][/<path>]". Used verbatim, so include a
	/// trailing separator (e.g. "zapp/") if one is wanted.
	#[serde(default = "default_account_prefix")]
	pub account_prefix_https: String,
	/// Prefix for service account names of plain-http issuers. Optional: if
	/// unset, http issuers are rejected outright. Must differ from
	/// account_prefix_https, since the prefix is the only place the scheme
	/// is encoded in the service account name.
	#[serde(default)]
	pub account_prefix_http: Option<String>,
	/// Default lifetime of the personal access token issued for a service
	/// account, e.g. "24h" or "30m".
	#[serde(default = "default_duration", with = "humantime_serde")]
	pub default_duration: Duration,
}

/// How self-issued tokens are verified. zapp always fetches
/// `{issuer}/.well-known/openid-configuration` and then uses the advertised
/// `introspection_endpoint` (preferred) or `jwks_uri`.
#[derive(Debug, Deserialize)]
pub struct VerificationConfig {
	/// Audience every token must carry, regardless of how it is verified.
	/// Kubernetes: `kubectl create token <sa> --audience=<this>`.
	#[serde(default = "default_audience")]
	pub audience: String,
	/// Timeout in seconds for verification HTTP requests (discovery,
	/// introspection and JWKS fetches).
	#[serde(default = "default_timeout_secs")]
	pub timeout_secs: u64,
}

impl Default for VerificationConfig {
	fn default() -> Self {
		Self { audience: default_audience(), timeout_secs: default_timeout_secs() }
	}
}

/// Garbage collection thresholds. An account's age is the time since its
/// newest personal access token or machine key was created (or since the
/// account was created, if it has none).
#[derive(Debug, Clone, Deserialize)]
pub struct GcConfig {
	/// How often to run a collection pass, e.g. "10m".
	#[serde(default = "default_gc_interval", with = "humantime_serde")]
	pub interval: Duration,
	/// Age after which a service account and its projects are deactivated,
	/// e.g. "24h". A renewal reactivates them.
	#[serde(with = "humantime_serde")]
	pub soft: Duration,
	/// Age after which a service account's projects and then the account
	/// itself are deleted, e.g. "36h". Must not be shorter than `soft`.
	#[serde(with = "humantime_serde")]
	pub hard: Duration,
}

/// A statically configured grant: issuers matching `pattern` are entitled to
/// a service account and project in the given Zitadel organisation.
#[derive(Debug, Clone, Deserialize)]
pub struct GrantConfig {
	/// Full issuer pattern, e.g. "https://*.famedly.dev/**" or
	/// "https://trusted.example.com/k8s". The scheme may be "*" for any
	/// scheme; the host part matches label by label ('*' once per label,
	/// "**" once per hostname as its own label for any number of labels)
	/// with an optional ":port" (or ":*" for any port); the path part
	/// matches segment by segment ('*' once per segment, "/**/" once per
	/// path for any number of segments).
	///
	/// Patterns should normally use https://. An "http://" (or "*://")
	/// pattern is accepted but entitles plain-http issuers, whose
	/// ownership proof can be spoofed on the network; only use it for
	/// local testing (e.g. "http://localhost:*/**" with the mock issuer).
	pub pattern: String,
	/// ID of the Zitadel organisation in which the service account and
	/// project for matching issuers are created.
	pub org_id: String,
	/// Personal access token lifetime, e.g. "12h"; falls back to
	/// `zitadel.default_duration` when unset.
	#[serde(default, with = "humantime_serde::option")]
	pub duration: Option<Duration>,
	/// Roles the service account additionally holds on the whole Zitadel
	/// instance, e.g. `["IAM_OWNER_VIEWER"]` for a client that must read
	/// users across all organisations. Empty by default: the account only
	/// owns its project. Since these reach across every organisation, they
	/// are only allowed for an exact issuer (a pattern without wildcards),
	/// and zapp's own service user then needs `IAM_OWNER`.
	#[serde(default)]
	pub instance_roles: Vec<String>,
	/// Roles the service account holds on the grant's organisation
	/// (`org_id`), e.g. `["ORG_USER_MANAGER"]` for a client that manages the
	/// users of its organisation. Empty by default. Only allowed for an exact
	/// issuer, like `instance_roles`.
	#[serde(default)]
	pub org_roles: Vec<String>,
}

impl Config {
	pub fn load(path: &str) -> anyhow::Result<Self> {
		let raw =
			std::fs::read_to_string(path).with_context(|| format!("reading config {path}"))?;
		let config: Config = toml::from_str(&raw).with_context(|| format!("parsing {path}"))?;
		config.validated()
	}

	fn validated(mut self) -> anyhow::Result<Self> {
		// The Zitadel client resolves API paths relative to the base URL,
		// so it must denote a directory.
		if !self.zitadel.url.path().ends_with('/') {
			let path = format!("{}/", self.zitadel.url.path());
			self.zitadel.url.set_path(&path);
		}
		if self.zitadel.default_duration.is_zero() {
			anyhow::bail!("zitadel.default_duration must be positive");
		}
		if let Some(gc) = &self.gc {
			if gc.interval.is_zero() || gc.soft.is_zero() || gc.hard.is_zero() {
				anyhow::bail!("gc.interval, gc.soft and gc.hard must be positive");
			}
			if gc.hard < gc.soft {
				anyhow::bail!("gc.hard must not be shorter than gc.soft");
			}
			let longest_credential = self
				.grants
				.iter()
				.filter_map(|grant| grant.duration)
				.chain([self.zitadel.default_duration])
				.max()
				.unwrap_or_default();
			if gc.soft < longest_credential {
				anyhow::bail!(
					"gc.soft ({}) is shorter than the longest credential lifetime ({}): accounts would be deactivated while their credentials are still valid",
					humantime::format_duration(gc.soft),
					humantime::format_duration(longest_credential)
				);
			}
		}
		for grant in &self.grants {
			if !grant.pattern.starts_with("https://")
				&& !grant.pattern.starts_with("http://")
				&& !grant.pattern.starts_with("*://")
			{
				anyhow::bail!(
					"grant pattern {:?} must be a full issuer pattern starting with https:// (or http:// for local testing, or *:// for any scheme)",
					grant.pattern
				);
			}
			if let Err(reason) = crate::pattern::validate_pattern(&grant.pattern) {
				anyhow::bail!("invalid grant pattern {:?}: {reason}", grant.pattern);
			}
			// A "*://" scheme wildcard also matches plain-http issuers,
			// so it needs the same opt-in as an explicit http:// pattern.
			let allows_http =
				grant.pattern.starts_with("http://") || grant.pattern.starts_with("*://");
			if allows_http && self.zitadel.account_prefix_http.is_none() {
				anyhow::bail!(
					"grant pattern {:?} allows plain-http issuers, but zitadel.account_prefix_http is not set",
					grant.pattern
				);
			}
			if grant.org_id.is_empty() || !grant.org_id.chars().all(|c| c.is_ascii_digit()) {
				anyhow::bail!(
					"grant pattern {:?} has invalid org_id {:?}: Zitadel organisation IDs are numeric",
					grant.pattern,
					grant.org_id
				);
			}
			if grant.duration.is_some_and(|duration| duration.is_zero()) {
				anyhow::bail!("grant pattern {:?}: duration must be positive", grant.pattern);
			}
			if !grant.instance_roles.is_empty() && grant.pattern.contains('*') {
				anyhow::bail!(
					"grant pattern {:?} has instance_roles, which are only allowed for an exact issuer without wildcards",
					grant.pattern
				);
			}
			if let Some(role) = grant.instance_roles.iter().find(|role| {
				role.is_empty() || !role.chars().all(|c| c.is_ascii_uppercase() || c == '_')
			}) {
				anyhow::bail!(
					"grant pattern {:?} has invalid instance role {role:?}: Zitadel roles look like IAM_OWNER_VIEWER",
					grant.pattern
				);
			}
			if !grant.org_roles.is_empty() && grant.pattern.contains('*') {
				//= docs/requirements/zapp.md#org-roles-2
				//# zapp MUST refuse to start if a grant names organisation
				//# roles and its issuer pattern contains a wildcard.
				anyhow::bail!(
					"grant pattern {:?} has org_roles, which are only allowed for an exact issuer without wildcards",
					grant.pattern
				);
			}
			if let Some(role) = grant.org_roles.iter().find(|role| {
				role.len() <= "ORG_".len()
					|| !role.starts_with("ORG_")
					|| !role.chars().all(|c| c.is_ascii_uppercase() || c == '_')
			}) {
				//= docs/requirements/zapp.md#org-roles-2
				//# zapp MUST refuse to start if an organisation role of a grant
				//# does not start with ORG_ or contains characters other than
				//# upper-case letters and underscores.
				anyhow::bail!(
					"grant pattern {:?} has invalid org role {role:?}: Zitadel organisation roles look like ORG_USER_MANAGER",
					grant.pattern
				);
			}
		}
		validate_account_prefix(
			"zitadel.account_prefix_https",
			&self.zitadel.account_prefix_https,
		)?;
		if let Some(http_prefix) = &self.zitadel.account_prefix_http {
			validate_account_prefix("zitadel.account_prefix_http", http_prefix)?;
			if *http_prefix == self.zitadel.account_prefix_https {
				anyhow::bail!(
					"zitadel.account_prefix_http must differ from zitadel.account_prefix_https: the prefix is the only place the issuer scheme is encoded in service account names"
				);
			}
		}
		Ok(self)
	}
}

/// Service account names are "<prefix><host>[:<port>][/<path>]". The
/// prefix must not contain '@' (Zitadel treats it as the login name
/// separator) or whitespace.
fn validate_account_prefix(key: &str, prefix: &str) -> anyhow::Result<()> {
	if prefix.is_empty() || prefix.contains('@') || prefix.chars().any(char::is_whitespace) {
		anyhow::bail!("{key} {prefix:?} must be non-empty and contain no '@' or whitespace");
	}
	Ok(())
}

fn default_listen() -> String {
	"127.0.0.1:8080".to_string()
}

fn default_account_prefix() -> String {
	"zapp/".to_string()
}

fn default_duration() -> Duration {
	Duration::from_secs(24 * 60 * 60)
}

fn default_gc_interval() -> Duration {
	Duration::from_secs(10 * 60)
}

fn default_audience() -> String {
	"zapp".to_string()
}

fn default_timeout_secs() -> u64 {
	10
}

#[cfg(test)]
mod tests {
	use super::*;

	fn parse(toml: &str) -> anyhow::Result<Config> {
		toml::from_str::<Config>(toml).map_err(anyhow::Error::from)?.validated()
	}

	const MINIMAL: &str = r#"
[zitadel]
url = "https://auth.example.com"
key_file = "/run/secrets/zapp-key.json"

[[grants]]
pattern = "https://trusted.example.com/k8s"
org_id = "123456789012345678"
"#;

	#[test]
	fn accepts_minimal_config() {
		let config = parse(MINIMAL).expect("valid config");
		assert_eq!(config.listen, "127.0.0.1:8080");
		assert_eq!(config.zitadel.url.as_str(), "https://auth.example.com/");
		assert_eq!(config.zitadel.account_prefix_https, "zapp/");
		assert_eq!(config.zitadel.default_duration, Duration::from_secs(86_400));
		assert_eq!(config.verification.audience, "zapp");
		assert_eq!(config.grants[0].org_id, "123456789012345678");
		assert_eq!(config.grants[0].duration, None);
	}

	#[test]
	fn parses_humantime_durations() {
		let toml = MINIMAL.replace(
			"key_file = \"/run/secrets/zapp-key.json\"",
			"key_file = \"/run/secrets/zapp-key.json\"\ndefault_duration = \"30m\"",
		) + "duration = \"12h\"\n";
		let config = parse(&toml).expect("valid config");
		assert_eq!(config.zitadel.default_duration, Duration::from_secs(30 * 60));
		assert_eq!(config.grants[0].duration, Some(Duration::from_secs(12 * 60 * 60)));

		assert!(parse(&(MINIMAL.to_string() + "duration = \"0s\"\n")).is_err());
	}

	#[test]
	fn normalizes_url_to_directory() {
		let toml = MINIMAL.replace("https://auth.example.com", "https://example.com/zitadel");
		let config = parse(&toml).expect("valid config");
		assert_eq!(config.zitadel.url.as_str(), "https://example.com/zitadel/");
	}

	#[test]
	fn rejects_non_numeric_org_id() {
		let toml = MINIMAL.replace("123456789012345678", "my-org");
		assert!(parse(&toml).is_err());
	}

	#[test]
	fn http_grants_require_http_prefix() {
		let without_prefix = MINIMAL.replace("https://trusted", "http://trusted");
		assert!(parse(&without_prefix).is_err());
		let with_prefix = without_prefix.replace(
			"key_file = \"/run/secrets/zapp-key.json\"",
			"key_file = \"/run/secrets/zapp-key.json\"\naccount_prefix_http = \"zapp-insecure/\"",
		);
		assert!(parse(&with_prefix).is_ok());
	}

	#[test]
	fn http_prefix_must_differ() {
		let toml = MINIMAL.replace(
			"key_file = \"/run/secrets/zapp-key.json\"",
			"key_file = \"/run/secrets/zapp-key.json\"\naccount_prefix_http = \"zapp/\"",
		);
		assert!(parse(&toml).is_err());
	}

	#[test]
	fn rejects_bad_prefixes() {
		for prefix in ["", "za pp", "za@pp"] {
			let toml = MINIMAL.replace(
				"key_file = \"/run/secrets/zapp-key.json\"",
				&format!(
					"key_file = \"/run/secrets/zapp-key.json\"\naccount_prefix_https = \"{prefix}\""
				),
			);
			assert!(parse(&toml).is_err(), "prefix {prefix:?} should be rejected");
		}
	}

	#[test]
	fn gc_thresholds() {
		let gc = |soft: &str, hard: &str| {
			parse(&format!("{MINIMAL}\n[gc]\nsoft = \"{soft}\"\nhard = \"{hard}\"\n"))
		};
		let config = gc("24h", "36h").expect("valid config");
		let gc_config = config.gc.expect("gc configured");
		assert_eq!(gc_config.interval, Duration::from_secs(600));
		assert_eq!(gc_config.soft, Duration::from_secs(24 * 3600));
		assert_eq!(gc_config.hard, Duration::from_secs(36 * 3600));

		assert!(gc("36h", "24h").is_err(), "hard shorter than soft");
		assert!(gc("12h", "36h").is_err(), "soft shorter than default_duration");
		assert!(gc("0s", "36h").is_err());
		assert!(parse(MINIMAL).expect("valid config").gc.is_none());
	}

	#[test]
	fn instance_roles_require_an_exact_issuer() {
		let config = parse(&(MINIMAL.to_string() + "instance_roles = [\"IAM_OWNER_VIEWER\"]\n"))
			.expect("valid config");
		assert_eq!(config.grants[0].instance_roles, ["IAM_OWNER_VIEWER"]);
		assert!(parse(MINIMAL).expect("valid config").grants[0].instance_roles.is_empty());

		let wildcard = MINIMAL
			.replace("https://trusted.example.com/k8s", "https://*.example.com/k8s")
			+ "instance_roles = [\"IAM_OWNER_VIEWER\"]\n";
		assert!(parse(&wildcard).is_err(), "wildcard pattern with instance roles");
		for role in ["", "iam_owner", "IAM OWNER"] {
			let toml = MINIMAL.to_string() + &format!("instance_roles = [\"{role}\"]\n");
			assert!(parse(&toml).is_err(), "role {role:?} should be rejected");
		}
	}

	#[test]
	fn org_roles_require_an_exact_issuer() {
		let config = parse(&(MINIMAL.to_string() + "org_roles = [\"ORG_USER_MANAGER\"]\n"))
			.expect("valid config");
		assert_eq!(config.grants[0].org_roles, ["ORG_USER_MANAGER"]);
		assert!(parse(MINIMAL).expect("valid config").grants[0].org_roles.is_empty());

		//= docs/requirements/zapp.md#org-roles-2
		//= type=test
		//# zapp MUST refuse to start if a grant names organisation roles and
		//# its issuer pattern contains a wildcard.
		let wildcard = MINIMAL
			.replace("https://trusted.example.com/k8s", "https://*.example.com/k8s")
			+ "org_roles = [\"ORG_USER_MANAGER\"]\n";
		assert!(parse(&wildcard).is_err(), "wildcard pattern with org roles");
	}

	#[test]
	fn rejects_invalid_org_roles() {
		//= docs/requirements/zapp.md#org-roles-2
		//= type=test
		//# zapp MUST refuse to start if an organisation role of a grant does
		//# not start with ORG_ or contains characters other than upper-case
		//# letters and underscores.
		for role in ["", "ORG_", "org_user_manager", "ORG USER", "IAM_OWNER", "PROJECT_OWNER"] {
			let toml = MINIMAL.to_string() + &format!("org_roles = [\"{role}\"]\n");
			assert!(parse(&toml).is_err(), "role {role:?} should be rejected");
		}
	}

	#[test]
	fn rejects_partial_or_invalid_patterns() {
		let bare = MINIMAL.replace("https://trusted.example.com/k8s", "trusted.example.com");
		assert!(parse(&bare).is_err());
		let invalid = MINIMAL.replace("https://trusted.example.com/k8s", "https://a**.example.com");
		assert!(parse(&invalid).is_err());
	}
}
