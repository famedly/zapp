// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::time::Duration;

use crate::{
	config::GrantConfig,
	pattern::{pattern_matches, subject_matches},
};

/// The entitlement resolved for a verified issuer: the Zitadel organisation
/// in which its service account and project live, and how long the issued
/// personal access token is valid.
#[derive(Debug, Clone)]
pub struct Entitlement {
	pub org_id: String,
	pub duration: Duration,
	/// Roles on the whole Zitadel instance, on top of owning the project.
	pub instance_roles: Vec<String>,
	/// Roles on the organisation `org_id`, on top of owning the project.
	pub org_roles: Vec<String>,
	/// The verified subject, if the entitlement is per subject: then the
	/// service account and project names include it, so each issuer and
	/// subject pair gets its own.
	pub subject: Option<String>,
}

/// Resolves a verified issuer origin (scheme + domain + port) and path, plus
/// the verified token subject (`sub`, if any), to an entitlement.
///
/// Today this is backed by statically configured patterns. In the future,
/// implementations may query a third-party server for dynamic issuer
/// details and translate them to an organisation.
pub trait PermissionResolver: Send + Sync {
	fn resolve(
		&self,
		scheme: &str,
		domain: &str,
		port: Option<u16>,
		path: &str,
		subject: Option<&str>,
	) -> Option<Entitlement>;
}

/// Static resolver matching issuers against configured patterns, in order.
pub struct StaticResolver {
	grants: Vec<GrantConfig>,
	default_duration: Duration,
}

impl StaticResolver {
	pub fn new(grants: Vec<GrantConfig>, default_duration: Duration) -> Self {
		Self { grants, default_duration }
	}
}

impl PermissionResolver for StaticResolver {
	fn resolve(
		&self,
		scheme: &str,
		domain: &str,
		port: Option<u16>,
		path: &str,
		subject: Option<&str>,
	) -> Option<Entitlement> {
		// An empty subject identifies nobody.
		let subject = subject.filter(|subject| !subject.is_empty());
		let grant = self.grants.iter().find(|grant| {
			pattern_matches(&grant.pattern, scheme, domain, port, path)
				&& match (&grant.subject, subject) {
					//= docs/requirements/zapp.md#subject-1
					//# A grant without a subject pattern MUST match
					//# independently of the token's subject.
					(None, _) => true,
					//= docs/requirements/zapp.md#subject-1
					//# A grant with a subject pattern MUST match a token only
					//# if the verified subject of the token matches the subject
					//# pattern.
					(Some(pattern), Some(subject)) => subject_matches(pattern, subject),
					//= docs/requirements/zapp.md#subject-1
					//# A grant with a subject pattern MUST NOT match a token
					//# without a verified subject or with an empty one.
					(Some(_), None) => false,
				}
		})?;
		Some(Entitlement {
			org_id: grant.org_id.clone(),
			duration: grant.duration.unwrap_or(self.default_duration),
			instance_roles: grant.instance_roles.clone(),
			org_roles: grant.org_roles.clone(),
			subject: grant.subject.as_ref().and(subject).map(str::to_string),
		})
	}
}

/// Validates a DNS hostname: lowercase letters, digits and hyphens in
/// labels of at most 63 characters that neither start nor end with a
/// hyphen, at most 253 characters in total.
pub fn is_valid_domain(domain: &str) -> bool {
	if domain.is_empty() || domain.len() > 253 {
		return false;
	}
	domain.split('.').all(|label| {
		!label.is_empty()
			&& label.len() <= 63
			&& !label.starts_with('-')
			&& !label.ends_with('-')
			&& label.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
	})
}

/// Validates a normalized issuer path ("" for root, otherwise "/a/b").
/// Segments are non-empty and consist of lowercase alphanumerics, '-', '_'
/// and '.', but are not the relative segments "." or "..".
pub fn is_valid_path(path: &str) -> bool {
	if path.is_empty() {
		return true;
	}
	let Some(rest) = path.strip_prefix('/') else {
		return false;
	};
	rest.split('/').all(|segment| {
		!segment.is_empty()
			&& segment != "."
			&& segment != ".."
			&& segment.chars().all(|c| {
				c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '.'
			})
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	fn grant(pattern: &str, org_id: &str, subject: Option<&str>) -> GrantConfig {
		GrantConfig {
			pattern: pattern.to_string(),
			org_id: org_id.to_string(),
			duration: None,
			instance_roles: Vec::new(),
			org_roles: Vec::new(),
			subject: subject.map(str::to_string),
		}
	}

	fn resolver() -> StaticResolver {
		StaticResolver::new(
			vec![
				grant("https://k8s.example.com", "1", Some("system:serviceaccount:tenant-a:*")),
				grant("https://k8s.example.com", "2", Some("system:serviceaccount:tenant-b:*")),
				grant("https://k8s.example.com", "3", None),
			],
			Duration::from_secs(3600),
		)
	}

	fn resolve(subject: Option<&str>) -> Option<Entitlement> {
		resolver().resolve("https", "k8s.example.com", None, "", subject)
	}

	#[test]
	fn subject_grants_match_only_their_subjects() {
		//= docs/requirements/zapp.md#subject-1
		//= type=test
		//# A grant with a subject pattern MUST match a token only if the
		//# verified subject of the token matches the subject pattern.
		let a = resolve(Some("system:serviceaccount:tenant-a:admin-api")).unwrap();
		assert_eq!(a.org_id, "1");
		assert_eq!(a.subject.as_deref(), Some("system:serviceaccount:tenant-a:admin-api"));
		let b = resolve(Some("system:serviceaccount:tenant-b:admin-api")).unwrap();
		assert_eq!(b.org_id, "2");

		//= docs/requirements/zapp.md#subject-1
		//= type=test
		//# A grant without a subject pattern MUST match independently of the
		//# token's subject.
		let other = resolve(Some("system:serviceaccount:tenant-c:admin-api")).unwrap();
		assert_eq!(other.org_id, "3");
		assert_eq!(other.subject, None, "grants without a subject are per issuer");
		assert_eq!(resolve(None).unwrap().org_id, "3");
	}

	#[test]
	fn subject_grants_need_a_subject() {
		//= docs/requirements/zapp.md#subject-1
		//= type=test
		//# A grant with a subject pattern MUST NOT match a token without a
		//# verified subject or with an empty one.
		let only_subject_grants = StaticResolver::new(
			vec![grant("https://k8s.example.com", "1", Some("**"))],
			Duration::from_secs(3600),
		);
		let resolve =
			|subject| only_subject_grants.resolve("https", "k8s.example.com", None, "", subject);
		assert!(resolve(None).is_none());
		assert!(resolve(Some("")).is_none());
		assert!(resolve(Some("anything")).is_some());
	}

	#[test]
	fn domain_validation() {
		assert!(is_valid_domain("a.famedly.dev"));
		assert!(is_valid_domain("a-b.famedly.dev"));
		assert!(is_valid_domain("localhost"));
		assert!(is_valid_domain("xn--mnchen-3ya.example.com"));
		assert!(is_valid_domain("127.0.0.1"));
		assert!(!is_valid_domain(""));
		assert!(!is_valid_domain("a..famedly.dev"));
		assert!(!is_valid_domain("-a.famedly.dev"));
		assert!(!is_valid_domain("a.famedly.dev/path"));
		assert!(!is_valid_domain("A.Famedly.Dev"));
		assert!(!is_valid_domain("a famedly.dev"));
	}

	#[test]
	fn path_validation() {
		assert!(is_valid_path(""));
		assert!(is_valid_path("/k8s"));
		assert!(is_valid_path("/k8s/c1"));
		assert!(is_valid_path("/k8s/cluster-1"));
		assert!(is_valid_path("/k8s_v1/v1.2"));
		assert!(!is_valid_path("k8s"));
		assert!(!is_valid_path("/k8s/"));
		assert!(!is_valid_path("//k8s"));
		assert!(!is_valid_path("/K8S"));
		assert!(!is_valid_path("/k8s/../c1"));
		assert!(!is_valid_path("/./c1"));
		assert!(!is_valid_path("/k8s c1"));
	}
}
