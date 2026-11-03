<!--
SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# zapp — Zitadel Automatic Project Provisioner

Issuer-based self-service provisioning of [Zitadel](https://zitadel.com/)
projects.

A client proves ownership of an issuer URL using a **JWT** bearer token. zapp
extracts the issuer from the token's `iss` claim and fetches
`{issuer}/.well-known/openid-configuration`. The metadata decides how the token
is verified:

- If it advertises an **`introspection_endpoint`** (RFC 7662), the token is
  posted there and must be reported `active`.
- Otherwise, the token's signature is validated against the advertised
  **`jwks_uri`**. The token must carry the configured audience (`aud`), a valid
  `exp`, and be signed with an asymmetric algorithm. This fits **Kubernetes
  service account tokens**: point `--service-account-issuer` at an https URL you
  own, serve the discovery documents publicly, and mint tokens with
  `kubectl create token <sa> --audience=zapp` (or a projected volume).

The issuer (and, optionally, the token's subject) is matched against a
configurable ruleset; each rule names the Zitadel organisation it entitles to.
Keep production patterns on `https://` (an http ownership proof can be spoofed
on the network) and reserve `http://` for local testing.

In exchange, zapp creates in that organisation (or in a configured home
organisation) a **service account** named after the issuer (and subject, for
subject-scoped grants), a **project** of the same name, makes the service
account **project owner**, and returns a credential for it: a personal access
token or, on request, a machine key. With that the client can manage its project
(applications, roles, grants, ...) through the Zitadel API on its own.

```
client                         zapp                        client's issuer       Zitadel
  |  POST /v1/credentials        |                                |                |
  |  Bearer <self-issued JWT> -> |                                |                |
  |                              | GET {iss}/.well-known/         |                |
  |                              |   openid-configuration ------> |                |
  |                              | introspection_endpoint set?    |                |
  |                              |   POST token=<JWT> ----------> |                |
  |                              |     { "active": true } <------ |                |
  |                              | else: GET <jwks_uri> --------> |                |
  |                              |   check signature, aud, exp    |                |
  |                              | match issuer against patterns  |                |
  |                              | create project (409: adopt, reactivate) ------> |
  |                              | create service account (409: adopt) ----------> |
  |                              | set origin / creator.<project> metadata -----> |
  |                              | add PROJECT_OWNER member (409: restore role) -> |
  |                              | create personal access token or key ----------> |
  |  { username, project_id,     |                                |                |
  |    secret | key,             |                                |                |
  |    expires_at } <----------- |                                |                |
```

## Usage

```sh
zapp [path/to/zapp.toml]    # defaults to ./zapp.toml
```

zapp authenticates against Zitadel as a service user with a private key JSON
file (`zitadel.key_file`). That service user must be able to manage users,
projects and project members in every organisation named by a grant:
`IAM_OWNER`, or `ORG_OWNER` on each of those organisations (which also covers
granting `org_roles`), and in the home organisation `zitadel.account_org_id` if
set. If any grant sets `instance_roles`, it needs `IAM_OWNER`. See
[`zapp.example.toml`](zapp.example.toml) for all options.

## API

### `POST /v1/credentials[?type=pat|key]`

Header: `Authorization: Bearer <self-issued JWT>`

Query `type` selects the credential:

- `pat` (default): a **personal access token**, an opaque bearer token that is
  used as-is (`Authorization: Bearer <secret>`) until it expires. Zero client
  complexity, but whoever holds it is the service account until expiry.
- `key`: a **machine key**, an RSA private key in Zitadel's JSON key file
  format. The client signs short-lived JWTs with it and exchanges them at
  Zitadel's token endpoint (`urn:ietf:params:oauth:grant-type:jwt-bearer`) for
  access tokens, choosing scopes per request. Only the public key is stored in
  Zitadel, and leaked access tokens die quickly.

The JWT must carry an `iss` claim containing a full `https://` (or `http://` for
testing) URL — bare domains are rejected, matching OpenID Connect, where `iss`
is always a URL. The issuer must serve OpenID Connect discovery metadata with
`introspection_endpoint` (preferred) or `jwks_uri`.

Response `200`:

```json
{
	"issuer": "https://app.famedly.dev/k8s",
	"zitadel_url": "https://auth.example.com/",
	"username": "zapp/app.famedly.dev/k8s",
	"user_id": "312909075212345678",
	"project_id": "312909075287654321",
	"type": "pat",
	"secret": "...",
	"expires_at": "2026-09-18T18:55:00Z"
}
```

With `type=key`, `secret` is replaced by `key`, the JSON key file as an object
(`{"type": "serviceaccount", "keyId": ..., "key": "<PEM-encoded RSA private key>", "userId": ...}`),
ready to be written to disk for Zitadel client libraries.

Either credential acts as the service account `username`, which owns the project
`project_id` (named `username` as well) in the grant's organisation, on the
Zitadel instance at `zitadel_url`.

Errors: `400` (`invalid_query`: unknown `type`), `401` (token
missing/invalid/inactive, verification failure), `403` (`issuer_not_entitled`:
no configured pattern matches; `subject_not_usable`: subject too long for a
name), `502` (Zitadel unreachable or rejected the request).

Renewal: simply call the endpoint again. zapp adopts the existing service
account and project (reactivating them if garbage collection has deactivated
them) and issues a fresh credential; earlier credentials keep working until they
expire. Everything set up in the project survives.

### Provisioning

Every step is optimistic and converges under concurrent requests:

1. **Create the project** named after the issuer. On `409 Conflict` the existing
   project of that name is looked up and reactivated if needed.
1. **Create the service account** of the same name and set metadata on it:
   `origin = <issuer>` marks it as zapp-managed, `subject = <subject>` (only for
   subject-scoped grants),
   `creator.<project id> = 1` records the project it was provisioned for (the ID
   is in the key, so several can coexist). On `409 Conflict` the existing
   account is adopted, but only if its `origin` and `subject` metadata match the
   request (an account can rename itself, so another issuer's or subject's
   account could have claimed the name); otherwise the request is refused and
   nothing is granted. On adoption the metadata is added, it is reactivated or
   unlocked, and
   any _other_ project recorded in its `creator.*` keys is deleted, so an
   account owns exactly one project. zapp refuses to adopt a human user of that
   name.
1. **Make it `PROJECT_OWNER`**. On `409 Conflict` (already a member) the role is
   restored if the account had dropped it.
1. **Grant instance roles**, only if the grant sets `instance_roles`: the
   account becomes an instance member with exactly those roles (on
   `409 Conflict` its roles are overwritten).
1. **Grant organisation roles**, only if the grant sets `org_roles`: the account
   becomes a member of the grant's organisation with exactly those roles (on
   `409 Conflict` its roles there are overwritten).
1. **Issue the credential** with the grant's expiry.

#### Trust model

The issued credential acts as the service account, which holds only
`PROJECT_OWNER` on its project, plus any `instance_roles` and `org_roles` its
grant names. Instance roles reach across every organisation (`IAM_OWNER_VIEWER`,
for example, reads all users), so they are only accepted on grants for an exact
issuer, never on a wildcard pattern. The same holds for organisation roles: they
reach every user (or project) of the grant's organisation, so a wildcard issuer
pattern, which can match issuers run by unrelated parties, may not carry them; a
wildcard _subject_ pattern can (all subjects come from the one exact issuer).
Removing either from a grant does not revoke memberships already granted; they
go when garbage collection deletes the account, or by hand. Tested against
Zitadel, `PROJECT_OWNER` alone lets the account rename itself
(`UpdateMyUserName`), remove its own project membership and delete its project,
but _not_ write its own metadata (`SetUserMetadata` needs `user.write`; the auth
API has no metadata write at all). zapp therefore relies on nothing the account
can change:

- Accounts are recognised by `origin` metadata, not by name. An existing
  account is adopted by name only if its `origin` and `subject` match.
- Projects are tracked by `creator.*` metadata, not by membership. A
  `PROJECT_OWNER` that removes its own membership does not exempt its project
  from cleanup; a project deleted by the account is simply found gone.

This no longer holds for an account whose `org_roles` include writing users
(`ORG_USER_MANAGER`, `ORG_OWNER`): it can write the metadata of every user in
its organisation, its own included, and thereby make zapp remove any project of
that organisation (by recording it as `creator.*`) or adopt other accounts into
garbage collection. Two ways out:

- Set `zitadel.account_org_id` to a **home organisation**: every service account
  and project is then created there, and `org_roles` are granted on the grant's
  organisation to a member from the home organisation (Zitadel accepts org
  members from other organisations). An account can write the users of the
  organisation it acts on, but not those of the home organisation, so zapp's
  metadata stays out of its reach. zapp therefore refuses to start if a grant
  with `org_roles` names the home organisation as its `org_id`. Accounts created
  before a home organisation was configured stay in their grant's organisation
  until garbage collection removes them; the next request creates a new pair in
  the home organisation.
- Without a home organisation, only grant such roles in an organisation whose
  users and projects all belong to the party the account acts for (e.g. one
  tenant).

### Garbage collection

An issuer that stops renewing is presumed gone. With a `[gc]` section, zapp
periodically scans every organisation named by a grant for machine users
carrying `origin` metadata and judges their age by the creation time of their
newest personal access token or machine key (or of the account itself, if it has
none):

- **soft** (`gc.soft`, e.g. `24h`): the service account is deactivated, then
  every project recorded in its `creator.*` metadata. Deactivated resources are
  dormant but intact; the next credential request from the issuer reactivates
  them.
- **hard** (`gc.hard`, e.g. `36h`): deactivation as above, then the projects are
  deleted, then the account.

With `soft = "24h"` and `hard = "36h"`, an issuer that last got a credential at
T is deactivated at T+24h and deleted at T+36h (both thresholds are measured
from the last credential). `gc.soft` must be at least the longest configured
credential lifetime, so an account is never deactivated while a credential is
still valid. zapp's service user additionally needs to read user metadata,
tokens and keys, and delete users and projects in those organisations
(`ORG_OWNER` covers this).

## Configuration

Issuer patterns are statically configured as ordered `[[grants]]`; the first
matching pattern wins. A pattern is a full issuer pattern such as
`https://*.famedly.dev/**`: the scheme must match the issuer exactly (`*` for
any scheme), the host part is matched label by label (`*` once per label, `**`
as its own label for any number of labels) with an optional `:port` (or `:*` for
any port), and the path part is matched segment by segment (`*` once per
segment, `/**/` once per path for any number of segments). Each grant names the
Zitadel organisation (`org_id`) to provision in and may set a token `duration`
(humantime syntax such as `"12h"`), falling back to `zitadel.default_duration`.
A grant for an exact issuer may also set `instance_roles` (e.g.
`["IAM_OWNER_VIEWER"]`) and `org_roles` (e.g. `["ORG_USER_MANAGER"]`, roles
starting with `ORG_`), see the trust model above.

### Subject-scoped grants

All workloads of one issuer share it: on a Kubernetes cluster every pod's token
has the cluster's issuer. A grant may therefore set `subject`, a pattern over
the token's `sub` claim. It then only matches tokens whose subject matches, and
every pair of issuer and subject gets its own service account and project. With
one grant per tenant, each tenant's workloads land in its own organisation:

```toml
[[grants]]
pattern = "https://k8s.example.com"
subject = "system:serviceaccount:tenant-a:*"
org_id = "111111111111111111"
org_roles = ["ORG_USER_MANAGER"]
```

The subject is split at `:` and matched segment by segment like an issuer path:
`*` once per segment (never across a `:`), `**` as its own segment for any
number of segments; e.g. `system:serviceaccount:tenant-*:admin-api`. Subjects
without `:` (other issuers use numeric IDs, UUIDs, `provider|id`, ...) are a
single segment, so this works for any issuer, not only Kubernetes.

When zapp runs inside a Kubernetes cluster and the issuer is the API server
itself (e.g. `https://kubernetes.default.svc`), set `verification.ca_file` to
the cluster CA (`/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`): its
certificates are trusted for discovery, introspection and JWKS requests on top
of the system roots. zapp fetches discovery and JWKS without credentials, so the
API server must allow anonymous requests to them, e.g. by binding the
`system:service-account-issuer-discovery` ClusterRole to
`system:unauthenticated` (by default it is bound to service accounts only).

Only a verified subject is used: from the claims of a token whose signature was
validated against the JWKS, or from the `sub` of the introspection response —
never from the payload of an introspected token. A token without a (non-empty)
verified subject never matches a subject-scoped grant. Grants without `subject`
ignore the subject entirely and behave as before; order grants from specific to
general, since the first match wins. The `PermissionResolver` receives the
verified subject too.

Because the scheme is part of the pattern, allowing plain-http issuers is an
explicit opt-in per grant (on top of the `account_prefix_http` opt-in). Only use
`http://` patterns for local testing.

### Service account and project names

A verified issuer maps to the name `<prefix><host>[:<port>][/<path>]` — the
issuer URL with `<scheme>://` replaced verbatim by a prefix — used for both the
service account and its project:

- The prefix is `zitadel.account_prefix_https` for https issuers (default
  `zapp/`) and `zitadel.account_prefix_http` for http issuers. They must differ
  (the prefix is the only place the scheme is encoded), and the http prefix is
  optional — leaving it unset rejects http issuers entirely.
- No separator is inserted between prefix and host: include a trailing `/` (or
  whatever separator is wanted) in the prefix itself.
- Non-default ports are kept; default ports are omitted even when the issuer URL
  spells them out. Trailing slashes are stripped.

Examples (with prefixes `zapp/` and `zapp-insecure/`):
`https://app.famedly.dev/k8s/c1` → `zapp/app.famedly.dev/k8s/c1`,
`http://localhost:39231/` → `zapp-insecure/localhost:39231`.

For a subject-scoped grant, `#<subject>` is appended:
`zapp/k8s.example.com#system:serviceaccount:tenant-a:admin-api`. Every byte of
the subject outside `a-z`, `0-9`, `:`, `.`, `_`, `-` is percent-encoded
(`Auth0|x` → `%41uth0%7cx`), so names stay unambiguous and subjects differing
only in case get distinct accounts. Prefixes may not contain `#`. A subject
whose name would exceed 200 characters (Zitadel's limit) is rejected with
`403 subject_not_usable`. Garbage collection handles these accounts like any
other: each is collected on its own.

## Mock client

`examples/mock_client.rs` spins up a local plain-http issuer with an
introspection endpoint on `127.0.0.1` port 0 (a random free port), mints a JWT
with `iss = http://localhost:<port>/`, and optionally exchanges it against a
running zapp:

```sh
cargo run --example mock_client                          # print token, keep serving
cargo run --example mock_client http://127.0.0.1:8080    # full exchange against zapp
```

For zapp to accept it, set `zitadel.account_prefix_http` and configure a grant
with the pattern `http://localhost:*` (see `zapp.example.toml`).

## Future work

Dynamic entitlements: the `PermissionResolver` trait (`src/policy.rs`) is the
extension point for querying a third-party server about an issuer and verified
subject and translating the response to an organisation, complementing the
static patterns.

## Requirements

[`docs/requirements/zapp.md`](docs/requirements/zapp.md) states the requirements
on organisation roles and subject-scoped grants. They are traced to code and
tests with [Duvet](https://github.com/awslabs/duvet): `duvet report --ci` fails
if the committed `.duvet/snapshot.txt` is out of date.
