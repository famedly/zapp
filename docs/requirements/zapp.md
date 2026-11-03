<!--
SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# zapp requirements

Requirements on zapp, written with the key words of RFC 2119 so that
[Duvet](https://github.com/awslabs/duvet) can trace them to code and tests
(`duvet report --ci`). Each sentence with a key word is its own paragraph.

Terms: a _workload_ presents a token from its _issuer_; the token's `sub` claim
is its _subject_ (for Kubernetes service account tokens
`system:serviceaccount:<namespace>:<service account>`). A _grant_ is a
configured rule that entitles matching workloads to a _service account_ and a
project in an _organisation_ of Zitadel.

## Organisation roles

### ORG-ROLES-1

A grant can name organisation roles.

If the matching grant names organisation roles, zapp MUST make the service account a member of the grant's organisation with exactly these roles.

If the service account already is a member of that organisation, zapp MUST replace its roles there with the grant's organisation roles.

### ORG-ROLES-2

zapp MUST refuse to start if an organisation role of a grant does not start with `ORG_` or contains characters other than upper-case letters and underscores.

zapp MUST refuse to start if a grant names organisation roles and its issuer pattern contains a wildcard.

## Tenant identity

### SUBJECT-1

A grant can name a subject pattern.

A grant with a subject pattern MUST match a token only if the verified subject of the token matches the subject pattern.

A grant with a subject pattern MUST NOT match a token without a verified subject or with an empty one.

A grant without a subject pattern MUST match independently of the token's subject.

zapp MUST refuse to start if a subject pattern is empty or contains an invalid wildcard.

### SUBJECT-2

When zapp verifies a token by its signature, it MUST take the subject only from the claims of the validated token.

When zapp verifies a token by introspection, it MUST take the subject only from the introspection response and MUST NOT take it from the token payload.

### SUBJECT-3

If the matching grant has a subject pattern, the names of the service account and the project MUST contain the subject, so that every pair of issuer and subject gets its own service account and project.

If the matching grant has no subject pattern, the names MUST stay the same as without subject support.

The name for a pair of issuer and subject MUST differ from the name for every other issuer and from the name for every other pair of issuer and subject.

In names, zapp MUST percent-encode every character of the subject other than lower-case letters, digits, colons, dots, underscores and hyphens, so that the subjects of any issuer give valid and distinct names.

zapp MUST reject a subject if the resulting name would be longer than 200 characters.

### SUBJECT-4

zapp MUST pass the verified subject to the permission resolver.

## Verification

### CA-1

A CA bundle can be limited to a list of CA hosts.

If a CA bundle is configured without CA hosts, zapp MUST trust its certificates for discovery, introspection and JWKS requests to every issuer, in addition to the system's trusted roots.

If CA hosts are configured, zapp MUST trust the CA bundle only for requests to issuers on these hosts and MUST use only the system's trusted roots for every other issuer.

zapp SHOULD warn at startup if a CA bundle is configured without CA hosts.

zapp MUST refuse to start if the configured CA bundle cannot be read or contains no certificate.

zapp MUST refuse to start if CA hosts are configured without a CA bundle or a CA host is not a valid hostname.

### VERIFY-1

zapp MUST NOT send any request to the issuer of a token unless the issuer claimed by the token matches the issuer pattern of some grant.

zapp MUST NOT return to the client what went wrong in a request to the issuer.

## Accounts

### AUDIT-1

zapp MUST record the verified issuer in the metadata of the service account, and for a subject-scoped grant also the verified subject.

zapp MUST NOT use the recorded subject to recognise or garbage collect service accounts.

### ADOPT-1

A service account of the requested name can already exist, and an account can rename itself, so the name alone does not identify it.

zapp MUST adopt an existing service account of the requested name only if its recorded issuer equals the verified issuer and its recorded subject equals the subject of a subject-scoped grant, or is absent for a grant without subject pattern.

Otherwise zapp MUST refuse the request without changing or granting anything to that account.

### HOME-ORG-1

If no home organisation is configured, zapp MUST create the service account and the project in the grant's organisation.

If a home organisation is configured, zapp MUST create the service account and the project in the home organisation instead of the grant's organisation.

If a home organisation is configured, zapp MUST give the service account its organisation roles on the grant's organisation.

If a home organisation is configured, garbage collection MUST include the home organisation.

zapp MUST refuse to start if the home organisation ID is not numeric.

zapp MUST refuse to start if a grant names organisation roles and its organisation is the home organisation.

zapp MUST refuse to start if a home organisation is configured and a grant names an instance role that can write users.
