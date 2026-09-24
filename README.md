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

The issuer is matched against a configurable ruleset; each rule names the
Zitadel organisation it entitles to. Keep production patterns on `https://` (an
http ownership proof can be spoofed on the network) and reserve `http://` for
local testing.

In exchange, zapp creates in that organisation a **service account** named after
the issuer, a **project** of the same name, makes the service account **project
owner**, and returns a credential for it: a personal access token or, on
request, a machine key. With that the client can manage its project
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
`IAM_OWNER`, or `ORG_OWNER` on each of those organisations. If any grant sets
`instance_roles`, it needs `IAM_OWNER`. See
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
no configured pattern matches), `502` (Zitadel unreachable or rejected the
request).

Renewal: simply call the endpoint again. zapp adopts the existing service
account and project (reactivating them if garbage collection has deactivated
them) and issues a fresh credential; earlier credentials keep working until they
expire. Everything set up in the project survives.

### Provisioning

Every step is optimistic and converges under concurrent requests:

1. **Create the project** named after the issuer. On `409 Conflict` the existing
   project of that name is looked up and reactivated if needed.
1. **Create the service account** of the same name and set metadata on it:
   `origin = <issuer>` marks it as zapp-managed, `creator.<project id> = 1`
   records the project it was provisioned for (the ID is in the key, so several
   can coexist). On `409 Conflict` the existing account is adopted: the metadata
   is added, it is reactivated or unlocked, and any _other_ project recorded in
   its `creator.*` keys is deleted, so an account owns exactly one project. zapp
   refuses to adopt a human user of that name.
1. **Make it `PROJECT_OWNER`**. On `409 Conflict` (already a member) the role is
   restored if the account had dropped it.
1. **Grant instance roles**, only if the grant sets `instance_roles`: the
   account becomes an instance member with exactly those roles (on
   `409 Conflict` its roles are overwritten).
1. **Issue the credential** with the grant's expiry.

#### Trust model

The issued credential acts as the service account, which holds only
`PROJECT_OWNER` on its project, plus any `instance_roles` its grant names.
Instance roles reach across every organisation (`IAM_OWNER_VIEWER`, for example,
reads all users), so they are only accepted on grants for an exact issuer, never
on a wildcard pattern. Removing them from a grant does not revoke memberships
already granted; they go when garbage collection deletes the account, or by
hand. Tested against Zitadel, that lets it rename itself (`UpdateMyUserName`),
remove its own project membership and delete its project, but _not_ write its
own metadata (`SetUserMetadata` needs `user.write`; the auth API has no metadata
write at all). zapp therefore relies on nothing the account can change:

- Accounts are recognised by `origin` metadata, not by name.
- Projects are tracked by `creator.*` metadata, not by membership. A
  `PROJECT_OWNER` that removes its own membership does not exempt its project
  from cleanup; a project deleted by the account is simply found gone.

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
`["IAM_OWNER_VIEWER"]`), see the trust model above.

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
extension point for querying a third-party server about an issuer and
translating the response to an organisation, complementing the static patterns.
