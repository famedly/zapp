// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Matching of issuer URLs against wildcard patterns such as
//! "https://*.famedly.dev/**" or "http://localhost:*/".

/// Matches a verified issuer origin (scheme, domain, optional non-default
/// port) plus normalized path ("" for root) against a full issuer pattern
/// such as "https://*.famedly.dev/**" or "http://localhost:*/".
///
/// Wildcards (structurally enforced by [`validate_pattern`]):
/// - The scheme matches exactly, or "*" matches any scheme. Since a "*"
///   scheme also entitles plain-http issuers, it is the same deliberate
///   opt-in as an "http://" pattern.
/// - The host matches label by label: a '*' inside a label matches any run of
///   characters, and a "**" label matches any number of whole labels, including
///   none ("**.famedly.dev" also matches the apex "famedly.dev").
/// - No ":port" in the pattern means only the scheme's default port matches;
///   ":<number>" is an exact port and ":*" matches any port.
/// - The path matches segment by segment like the host: '*' within a segment,
///   "/**/" for any number of segments ("/k8s/**" matches "/k8s" itself and
///   everything below it). A pattern without a path matches only the root path.
pub fn pattern_matches(
	pattern: &str,
	scheme: &str,
	domain: &str,
	port: Option<u16>,
	path: &str,
) -> bool {
	let Some((scheme_pattern, rest)) = pattern.split_once("://") else {
		return false;
	};
	if scheme_pattern != "*" && scheme_pattern != scheme {
		return false;
	}
	let (host_pattern, path_pattern) = match rest.find('/') {
		Some(i) => (&rest[..i], &rest[i..]),
		None => (rest, "/"),
	};
	let (host_pattern, port_pattern) = match host_pattern.rsplit_once(':') {
		Some((host, port)) => (host, Some(port)),
		None => (host_pattern, None),
	};
	let port_ok = match port_pattern {
		// No port in the pattern: only the scheme's default port matches.
		None => port.is_none(),
		Some("*") => true,
		Some(expected) => port.is_some() && expected.parse::<u16>().ok() == port,
	};
	port_ok && host_matches(host_pattern, domain) && path_matches(path_pattern, path)
}

/// Matches a token subject against a subject pattern such as
/// "system:serviceaccount:tenant-a:*". Subjects are compared segment by
/// segment, split at ':', with the same wildcards as issuer paths: '*' once
/// per segment (never crossing a ':'), "**" as its own segment for any number
/// of segments. A subject without ':' is a single segment, so any issuer's
/// subjects work.
pub fn subject_matches(pattern: &str, subject: &str) -> bool {
	let patterns: Vec<&str> = pattern.split(':').collect();
	let values: Vec<&str> = subject.split(':').collect();
	segments_match(&patterns, &values)
}

/// Validates the wildcard structure of a subject pattern, see
/// [`subject_matches`].
pub fn validate_subject_pattern(pattern: &str) -> Result<(), String> {
	validate_wildcard_segments(pattern.split(':'), "subject segment", "subject")
}

fn host_matches(pattern: &str, domain: &str) -> bool {
	let pattern = pattern.to_ascii_lowercase();
	let domain = domain.to_ascii_lowercase();
	let pattern_labels: Vec<&str> = pattern.split('.').collect();
	let domain_labels: Vec<&str> = domain.split('.').collect();
	segments_match(&pattern_labels, &domain_labels)
}

fn path_matches(pattern: &str, path: &str) -> bool {
	let pattern_segments: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
	let path_segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
	segments_match(&pattern_segments, &path_segments)
}

/// Matches a sequence of host labels or path segments against a pattern
/// sequence in which at most one "**" absorbs any number of values
/// (including none) and every other element must match exactly one value.
fn segments_match(patterns: &[&str], values: &[&str]) -> bool {
	match patterns.iter().position(|p| *p == "**") {
		None => {
			patterns.len() == values.len()
				&& std::iter::zip(patterns, values).all(|(p, v)| segment_matches(p, v))
		}
		Some(i) => {
			let (head, tail) = (&patterns[..i], &patterns[i + 1..]);
			// validate_pattern rejects a second "**"; never match one.
			!tail.contains(&"**")
				&& values.len() >= head.len() + tail.len()
				&& std::iter::zip(head, values).all(|(p, v)| segment_matches(p, v))
				&& std::iter::zip(tail.iter().rev(), values.iter().rev())
					.all(|(p, v)| segment_matches(p, v))
		}
	}
}

/// Matches a single host label or path segment. A '*' matches any run of
/// characters (possibly empty); validate_pattern rejects more than one
/// '*' per label/segment, so a second one never matches.
fn segment_matches(pattern: &str, value: &str) -> bool {
	match pattern.split_once('*') {
		None => pattern == value,
		Some((prefix, suffix)) => {
			!suffix.contains('*')
				&& value.len() >= prefix.len() + suffix.len()
				&& value.starts_with(prefix)
				&& value.ends_with(suffix)
		}
	}
}

/// Validates the wildcard structure of a grant pattern:
/// - the scheme and the port may each be exactly "*" (matching any scheme / any
///   port), but '*' may not combine with other characters there (no "http*", no
///   ":1*") and "**" is disallowed;
/// - "**" in the host must be its own label (as in "a.**.dev") and may appear
///   at most once per hostname;
/// - "**" in the path must be its own segment (as in "/a/**/b") and may appear
///   at most once per path;
/// - any other host label or path segment may contain at most one '*'.
pub fn validate_pattern(pattern: &str) -> Result<(), String> {
	let Some((scheme, rest)) = pattern.split_once("://") else {
		return Err("missing \"://\" after the scheme".to_string());
	};
	if scheme.contains('*') && scheme != "*" {
		return Err(format!("a scheme wildcard must be exactly \"*\", got {scheme:?}"));
	}
	let (host_port, path) = match rest.find('/') {
		Some(i) => (&rest[..i], &rest[i..]),
		None => (rest, "/"),
	};
	let (host, port) = match host_port.rsplit_once(':') {
		Some((host, port)) => (host, Some(port)),
		None => (host_port, None),
	};
	if let Some(port) = port
		&& port != "*"
		&& port.parse::<u16>().is_err()
	{
		return Err(format!("port {port:?} must be a port number or exactly \"*\""));
	}
	if host.is_empty() {
		return Err("missing host".to_string());
	}
	validate_wildcard_segments(host.split('.'), "host label", "hostname")?;
	validate_wildcard_segments(path.split('/').filter(|s| !s.is_empty()), "path segment", "path")
}

fn validate_wildcard_segments<'a>(
	segments: impl Iterator<Item = &'a str>,
	kind: &str,
	whole: &str,
) -> Result<(), String> {
	let mut seen_multi = false;
	for segment in segments {
		if segment == "**" {
			if seen_multi {
				return Err(format!("\"**\" may appear at most once per {whole}"));
			}
			seen_multi = true;
		} else if segment.contains("**") {
			return Err(format!("\"**\" must be its own {kind}, got {segment:?}"));
		} else if segment.matches('*').count() > 1 {
			return Err(format!("at most one '*' per {kind}, got {segment:?}"));
		} else if segment.is_empty() {
			return Err(format!("empty {kind}"));
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	/// pattern_matches for an https issuer without a port.
	fn https_matches(pattern: &str, domain: &str, path: &str) -> bool {
		pattern_matches(pattern, "https", domain, None, path)
	}

	#[test]
	fn single_star_host_matches_one_label() {
		let p = "https://*.famedly.dev/**";
		assert!(https_matches(p, "a.famedly.dev", ""));
		assert!(https_matches(p, "a.famedly.dev", "/k8s"));
		assert!(!https_matches(p, "a.b.famedly.dev", ""));
		assert!(!https_matches(p, "famedly.dev", "/k8s"));
		assert!(!https_matches(p, "famedly.dev.evil.com", ""));
	}

	#[test]
	fn double_star_host_matches_any_depth_and_apex() {
		let p = "https://**.famedly.dev/**";
		assert!(https_matches(p, "famedly.dev", ""));
		assert!(https_matches(p, "a.famedly.dev", "/k8s"));
		assert!(https_matches(p, "a.b.famedly.dev", "/k8s/c1"));
		assert!(!https_matches(p, "xfamedly.dev", ""));
		assert!(!https_matches(p, "famedly.dev.evil.com", ""));
		assert!(!https_matches(p, "famedly.devx", ""));
	}

	#[test]
	fn partial_label_wildcard() {
		let p = "https://app-*.famedly.dev";
		assert!(https_matches(p, "app-1.famedly.dev", ""));
		assert!(https_matches(p, "app-staging.famedly.dev", ""));
		assert!(!https_matches(p, "app.famedly.dev", ""));
		assert!(!https_matches(p, "app-1.b.famedly.dev", ""));
	}

	#[test]
	fn exact_host_and_path() {
		let p = "https://trusted.example.com/k8s";
		assert!(https_matches(p, "trusted.example.com", "/k8s"));
		assert!(!https_matches(p, "trusted.example.com", "/k8s/c1"));
		assert!(!https_matches(p, "trusted.example.com", ""));
		assert!(!https_matches(p, "other.example.com", "/k8s"));
	}

	#[test]
	fn path_double_star_matches_parent_and_below() {
		let p = "https://a.famedly.dev/k8s/**";
		assert!(https_matches(p, "a.famedly.dev", "/k8s"));
		assert!(https_matches(p, "a.famedly.dev", "/k8s/c1"));
		assert!(https_matches(p, "a.famedly.dev", "/k8s/c1/prod"));
		assert!(!https_matches(p, "a.famedly.dev", "/k8sx"));
		assert!(!https_matches(p, "a.famedly.dev", ""));
	}

	#[test]
	fn path_single_star_matches_exactly_one_segment() {
		let p = "https://a.famedly.dev/k8s/*";
		assert!(https_matches(p, "a.famedly.dev", "/k8s/c1"));
		assert!(!https_matches(p, "a.famedly.dev", "/k8s"));
		assert!(!https_matches(p, "a.famedly.dev", "/k8s/c1/prod"));
	}

	#[test]
	fn path_infix_double_star_and_partial_segments() {
		let p = "https://a.famedly.dev/k8s/**/prod";
		assert!(https_matches(p, "a.famedly.dev", "/k8s/prod"));
		assert!(https_matches(p, "a.famedly.dev", "/k8s/c1/prod"));
		assert!(https_matches(p, "a.famedly.dev", "/k8s/c1/x/prod"));
		assert!(!https_matches(p, "a.famedly.dev", "/k8s/c1"));
		assert!(!https_matches(p, "a.famedly.dev", "/prod"));

		let p = "https://a.famedly.dev/k8s/c-*";
		assert!(https_matches(p, "a.famedly.dev", "/k8s/c-1"));
		assert!(!https_matches(p, "a.famedly.dev", "/k8s/d-1"));
	}

	#[test]
	fn host_only_pattern_matches_root_only() {
		let p = "https://a.famedly.dev";
		assert!(https_matches(p, "a.famedly.dev", ""));
		assert!(!https_matches(p, "a.famedly.dev", "/k8s"));
	}

	#[test]
	fn scheme_must_match_exactly() {
		// An https pattern never entitles a plain-http issuer...
		assert!(!pattern_matches("https://a.famedly.dev/**", "http", "a.famedly.dev", None, ""));
		// ...and vice versa; http entitlement requires an explicit
		// http:// pattern.
		assert!(!pattern_matches("http://a.famedly.dev/**", "https", "a.famedly.dev", None, ""));
		assert!(pattern_matches("http://a.famedly.dev/**", "http", "a.famedly.dev", None, ""));
	}

	#[test]
	fn scheme_wildcard_matches_any_scheme() {
		let p = "*://a.famedly.dev";
		assert!(pattern_matches(p, "https", "a.famedly.dev", None, ""));
		assert!(pattern_matches(p, "http", "a.famedly.dev", None, ""));
		assert!(!pattern_matches(p, "https", "b.famedly.dev", None, ""));
	}

	#[test]
	fn schemeless_pattern_never_matches() {
		assert!(!https_matches("*.famedly.dev", "a.famedly.dev", ""));
	}

	#[test]
	fn port_patterns() {
		// No port in the pattern: only the default port matches.
		assert!(!pattern_matches("http://localhost/*", "http", "localhost", Some(8080), ""));
		// Exact port.
		let exact = "http://localhost:8080/**";
		assert!(pattern_matches(exact, "http", "localhost", Some(8080), ""));
		assert!(!pattern_matches(exact, "http", "localhost", Some(9090), ""));
		assert!(!pattern_matches(exact, "http", "localhost", None, ""));
		// Port wildcard, e.g. for mock issuers bound to port 0.
		let any = "http://localhost:*/**";
		assert!(pattern_matches(any, "http", "localhost", Some(39231), ""));
		assert!(pattern_matches(any, "http", "localhost", None, "/k8s"));
		assert!(!pattern_matches(any, "http", "remotehost", Some(39231), ""));
	}

	#[test]
	fn subject_patterns() {
		let tenant = "system:serviceaccount:tenant-a:*";
		assert!(subject_matches(tenant, "system:serviceaccount:tenant-a:admin-api"));
		assert!(!subject_matches(tenant, "system:serviceaccount:tenant-b:admin-api"));
		assert!(!subject_matches(tenant, "system:serviceaccount:tenant-a"));

		let service = "system:serviceaccount:tenant-*:admin-api";
		assert!(subject_matches(service, "system:serviceaccount:tenant-a:admin-api"));
		assert!(!subject_matches(service, "system:serviceaccount:tenant-a:other"));
		// '*' never crosses a ':'.
		assert!(!subject_matches(service, "system:serviceaccount:tenant-a:x:admin-api"));

		assert!(subject_matches("system:**", "system:serviceaccount:a:b"));
		// Subjects of other issuers are a single segment.
		assert!(subject_matches("312909075212345678", "312909075212345678"));
		assert!(subject_matches("auth0|*", "auth0|abc"));
		assert!(!subject_matches("auth0|*", "google|abc"));
		assert!(!subject_matches("exact", "exact:more"));
	}

	#[test]
	fn subject_pattern_validation() {
		assert!(validate_subject_pattern("system:serviceaccount:tenant-a:*").is_ok());
		assert!(validate_subject_pattern("system:**").is_ok());
		assert!(validate_subject_pattern("").is_err());
		assert!(validate_subject_pattern("a::b").is_err());
		assert!(validate_subject_pattern("a**b").is_err());
		assert!(validate_subject_pattern("**:a:**").is_err());
		assert!(validate_subject_pattern("*a*").is_err());
	}

	#[test]
	fn pattern_validation() {
		assert!(validate_pattern("https://*.famedly.dev/**").is_ok());
		assert!(validate_pattern("https://**.famedly.dev").is_ok());
		assert!(validate_pattern("*://localhost:*/**").is_ok());
		assert!(validate_pattern("https://a.famedly.dev:8443/k8s/**/prod").is_ok());
		assert!(validate_pattern("https://app-*.famedly.dev/a*b/c").is_ok());

		// Missing scheme separator.
		assert!(validate_pattern("*.famedly.dev").is_err());
		// '*' in the scheme and the port must be the whole value; "**"
		// is disallowed there entirely.
		assert!(validate_pattern("http*://a.dev/").is_err());
		assert!(validate_pattern("**://a.dev/").is_err());
		assert!(validate_pattern("https://a.dev:1*/").is_err());
		assert!(validate_pattern("https://a.dev:**/").is_err());
		// "**" must be its own label/segment...
		assert!(validate_pattern("https://a**.dev/").is_err());
		assert!(validate_pattern("https://a.dev/k8s**").is_err());
		// ...and may appear only once per hostname/path.
		assert!(validate_pattern("https://**.a.**.dev/").is_err());
		assert!(validate_pattern("https://a.dev/**/x/**").is_err());
		// At most one '*' per label/segment.
		assert!(validate_pattern("https://a*b*c.dev/").is_err());
		assert!(validate_pattern("https://a.dev/a*b*c").is_err());
		// Empty host labels are malformed.
		assert!(validate_pattern("https://a..dev/").is_err());
		assert!(validate_pattern("https:///k8s").is_err());
	}
}
