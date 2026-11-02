// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use anyhow::Context as _;
use base64::{Engine as _, prelude::BASE64_STANDARD};
use famedly_zitadel_rust_client::v2::{
	HEADER_ZITADEL_ORGANIZATION_ID, Zitadel,
	authentication::Token,
	management::{
		V1GetProjectByIdResponse, V1Project, V1ProjectNameQuery, V1ProjectQuery, V1ProjectState,
		V1TextQueryMethod,
	},
	users::{
		OrganizationIdQuery, SearchQuery, TextQueryMethod, TypeQuery, User, UserNameQuery,
		UserState, Userv2Type,
	},
};
use futures::TryStreamExt as _;
use reqwest::{Method, StatusCode};
use reqwest_middleware::ClientWithMiddleware;
use serde::{
	Deserialize, Serialize,
	de::{DeserializeOwned, IgnoredAny},
};
use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tracing::info;
use url::Url;

use crate::{config::ZitadelConfig, policy::Entitlement};

/// Administrator role of a user on a project.
const PROJECT_OWNER: &str = "PROJECT_OWNER";

/// Metadata key on a zapp-managed service account holding the issuer URL it
/// was provisioned for. Its presence marks the account as zapp-managed.
pub const METADATA_ORIGIN: &str = "origin";

/// Metadata key prefix `creator.<project id>` (value `1`) recording that the
/// service account was provisioned as creator of that project.
pub const METADATA_CREATOR_PREFIX: &str = "creator.";

/// Page size for management API list calls.
const PAGE_SIZE: usize = 100;

/// Which kind of credential to issue for a service account.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
	/// A personal access token: an opaque bearer token, used as-is.
	#[default]
	Pat,
	/// A machine key: an RSA private key (Zitadel's JSON key file) with
	/// which the client signs JWTs to obtain short-lived access tokens.
	Key,
}

/// A credential issued for a service account.
#[derive(Debug)]
pub enum Credential {
	Pat(String),
	/// Zitadel's JSON key file, verbatim.
	Key(String),
}

/// What zapp provisioned for an issuer.
#[derive(Debug)]
pub struct Provisioned {
	/// Username of the service account, e.g. "zapp/app.famedly.dev/k8s".
	pub username: String,
	pub user_id: String,
	/// ID of the project (of the same name) the service account owns.
	pub project_id: String,
	pub credential: Credential,
	/// Expiry of the credential, RFC 3339.
	pub expires_at: String,
}

/// A zapp-managed service account, as seen by garbage collection.
#[derive(Debug)]
pub struct ManagedAccount {
	pub user_id: String,
	pub username: String,
	/// Whether the account is active (as opposed to deactivated/locked).
	pub active: bool,
	pub created_at: Option<OffsetDateTime>,
	/// Issuer the account was provisioned for (`origin` metadata).
	pub origin: String,
	/// Projects zapp recorded the account as creator of (`creator.<id>`
	/// metadata). Authoritative: user metadata needs `user.write`, which the
	/// account does not hold, so only zapp writes these keys.
	pub project_ids: Vec<String>,
}

/// State of a project.
#[derive(Debug, Clone, Copy)]
pub struct ProjectStatus {
	pub active: bool,
}

/// A non-success answer from Zitadel, kept typed so callers can react to
/// specific statuses (409: name already taken, 404: gone).
#[derive(Debug, thiserror::Error)]
#[error("Zitadel answered {status}: {body}")]
pub struct HttpError {
	pub status: StatusCode,
	pub body: String,
}

fn has_status(err: &anyhow::Error, status: StatusCode) -> bool {
	err.downcast_ref::<HttpError>().is_some_and(|e| e.status == status)
}

#[derive(Deserialize)]
struct IdResponse {
	id: String,
}

#[derive(Deserialize)]
struct UserIdResponse {
	#[serde(rename = "userId")]
	user_id: String,
}

#[derive(Deserialize)]
#[serde(bound = "T: DeserializeOwned")]
struct Listing<T> {
	#[serde(default = "Vec::new")]
	result: Vec<T>,
}

#[derive(Deserialize)]
struct ObjectDetails {
	#[serde(rename = "creationDate")]
	creation_date: Option<String>,
}

#[derive(Deserialize)]
struct Dated {
	details: Option<ObjectDetails>,
}

#[derive(Deserialize)]
struct MetadataEntry {
	key: String,
	/// Base64-encoded.
	#[serde(default)]
	value: String,
}

#[derive(Deserialize)]
struct Member {
	#[serde(rename = "userId")]
	user_id: Option<String>,
	#[serde(default)]
	roles: Vec<String>,
}

fn parse_time(rfc3339: &str) -> Option<OffsetDateTime> {
	OffsetDateTime::parse(rfc3339, &Rfc3339).ok()
}

/// Project IDs recorded in `creator.<id>` metadata keys. Only numeric IDs
/// are accepted, since they end up in request paths.
fn creator_project_ids(metadata: &BTreeMap<String, String>) -> Vec<String> {
	metadata
		.keys()
		.filter_map(|key| key.strip_prefix(METADATA_CREATOR_PREFIX))
		.filter(|id| !id.is_empty() && id.chars().all(|c| c.is_ascii_digit()))
		.map(str::to_string)
		.collect()
}

/// Zitadel client provisioning service accounts and the projects they own.
pub struct ZitadelClient {
	zitadel: Zitadel,
	/// Separate token holder for the requests made without the client
	/// library (which hides HTTP status codes zapp needs to react to); it
	/// authenticates with the same service user key.
	token: Arc<Token>,
	http: ClientWithMiddleware,
	url: Url,
}

impl ZitadelClient {
	/// Connects to Zitadel, authenticating as the configured service user.
	/// Fails fast if the key file is unusable or Zitadel is unreachable.
	pub async fn new(config: &ZitadelConfig) -> anyhow::Result<Self> {
		let http = reqwest_middleware::ClientBuilder::new(
			reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?,
		)
		.build();
		let zitadel = Zitadel::new(http.clone(), config.url.clone(), config.key_file.clone(), None)
			.await
			.with_context(|| format!("authenticating against Zitadel at {}", config.url))?;
		let token = Token::new(config.url.clone(), &config.key_file, http.clone(), None, None)
			.await
			.with_context(|| format!("authenticating against Zitadel at {}", config.url))?;
		Ok(Self { zitadel, token: Arc::new(token), http, url: config.url.clone() })
	}

	/// Base URL of the Zitadel instance the credentials are valid for.
	pub fn url(&self) -> &Url {
		&self.url
	}

	/// Ensures that in the entitlement's organisation `org_id` an active
	/// project `name` and an active service account `name` exist, that the
	/// service account records itself as creator of the project (metadata),
	/// owns it and holds exactly `instance_roles` on the instance and
	/// `org_roles` on organisation `org_id` (each if any), and issues a
	/// credential of the requested kind valid for `duration`.
	///
	/// Both are created optimistically and adopted (reactivated if needed)
	/// on a name conflict, so renewals and concurrent requests converge on
	/// the same pair. An adopted service account keeps its earlier
	/// credentials until they expire; any other project it recorded itself
	/// as creator of is removed, so an account owns exactly one project.
	pub async fn provision(
		&self,
		name: &str,
		issuer: &str,
		entitlement: &Entitlement,
		credential_type: CredentialType,
	) -> anyhow::Result<Provisioned> {
		let Entitlement { org_id, duration, instance_roles, org_roles, .. } = entitlement;
		let org_id = org_id.as_str();
		let project_id = self.ensure_project(name, org_id).await?;
		let user_id = self.ensure_service_account(name, issuer, org_id, &project_id).await?;
		self.ensure_project_owner(org_id, &project_id, &user_id).await?;
		// ponytail: a grant whose instance_roles were removed leaves existing
		// memberships in place until GC deletes the account. Revoking them
		// here would need IAM_OWNER for every zapp, even without such grants.
		if !instance_roles.is_empty() {
			self.ensure_instance_member(&user_id, instance_roles).await?;
		}
		// shortcut: like instance_roles, removed org_roles stay until GC
		// deletes the account.
		if !org_roles.is_empty() {
			self.ensure_org_member(org_id, &user_id, org_roles).await?;
		}

		let expires_at = (OffsetDateTime::now_utc() + *duration)
			.format(&Rfc3339)
			.context("formatting credential expiry")?;
		let credential = match credential_type {
			CredentialType::Pat => {
				Credential::Pat(self.create_pat(&user_id, org_id, &expires_at).await?)
			}
			CredentialType::Key => {
				Credential::Key(self.create_machine_key(&user_id, org_id, &expires_at).await?)
			}
		};

		Ok(Provisioned { username: name.to_string(), user_id, project_id, credential, expires_at })
	}

	/// Creates project `name`, or adopts and reactivates the existing one.
	async fn ensure_project(&self, name: &str, org_id: &str) -> anyhow::Result<String> {
		match self
			.call::<IdResponse>(Method::POST, "projects", org_id, Some(json!({ "name": name })))
			.await
		{
			Ok(created) => return Ok(created.id),
			Err(e) if has_status(&e, StatusCode::CONFLICT) => {}
			Err(e) => return Err(e.context("creating project")),
		}

		let project = self.find_project_named(name, org_id).await?.with_context(|| {
			format!("project {name} exists according to Zitadel but cannot be found")
		})?;
		let project_id = project.id().cloned().context("Zitadel returned a project without id")?;
		if !matches!(project.state(), Some(V1ProjectState::Active)) {
			self.call::<IgnoredAny>(
				Method::POST,
				&format!("projects/{project_id}/_reactivate"),
				org_id,
				None,
			)
			.await
			.context("reactivating project")?;
			info!("reactivated project {name} ({project_id})");
		}
		Ok(project_id)
	}

	/// Creates service account `name` with zapp's metadata, or adopts the
	/// existing one: stamps the metadata, reactivates it and removes any
	/// other project it recorded itself as creator of.
	async fn ensure_service_account(
		&self,
		name: &str,
		issuer: &str,
		org_id: &str,
		project_id: &str,
	) -> anyhow::Result<String> {
		let creator_key = format!("{METADATA_CREATOR_PREFIX}{project_id}");
		let metadata = [(METADATA_ORIGIN, issuer), (creator_key.as_str(), "1")];

		let body = json!({
			"userName": name,
			"name": name,
			"description": format!("zapp-managed service account for issuer {issuer}"),
		});
		match self.call::<UserIdResponse>(Method::POST, "users/machine", org_id, Some(body)).await {
			Ok(created) => {
				self.set_user_metadata(&created.user_id, org_id, &metadata).await?;
				return Ok(created.user_id);
			}
			Err(e) if has_status(&e, StatusCode::CONFLICT) => {}
			Err(e) => return Err(e.context("creating service account")),
		}

		let user = self.find_user_named(name, org_id).await?.with_context(|| {
			format!("service account {name} exists according to Zitadel but cannot be found")
		})?;
		anyhow::ensure!(
			user.machine().is_some(),
			"user {name} exists but is not a service account; refusing to take it over"
		);
		let user_id = user.user_id().cloned().context("Zitadel returned a user without id")?;

		self.set_user_metadata(&user_id, org_id, &metadata).await?;
		match user.state() {
			Some(UserState::Inactive) => {
				self.zitadel
					.reactivate_user(&user_id)
					.await
					.context("reactivating service account")?;
				info!("reactivated service account {name} ({user_id})");
			}
			Some(UserState::Locked) => {
				self.zitadel.unlock_user(&user_id).await.context("unlocking service account")?;
				info!("unlocked service account {name} ({user_id})");
			}
			_ => {}
		}
		self.release_stale_projects(org_id, &user_id, project_id).await?;
		Ok(user_id)
	}

	/// Removes every project zapp recorded the service account as creator
	/// of except `keep`, and forgets them in its metadata.
	///
	/// Deliberately not gated on the account still being `PROJECT_OWNER`:
	/// that role includes `project.member.delete`, so the account could
	/// drop its own membership and thereby exempt a project from cleanup.
	/// The `creator.*` metadata is zapp's own record and is trusted as such.
	async fn release_stale_projects(
		&self,
		org_id: &str,
		user_id: &str,
		keep: &str,
	) -> anyhow::Result<()> {
		let metadata = self.user_metadata(user_id, org_id).await?;
		let stale: Vec<String> =
			creator_project_ids(&metadata).into_iter().filter(|id| id != keep).collect();
		if stale.is_empty() {
			return Ok(());
		}
		for project_id in &stale {
			self.remove_project(org_id, project_id).await?;
			info!("removed stale project {project_id} of service account {user_id}");
		}
		let keys: Vec<String> =
			stale.iter().map(|id| format!("{METADATA_CREATOR_PREFIX}{id}")).collect();
		self.delete_user_metadata(user_id, org_id, &keys).await
	}

	/// Makes the service account `PROJECT_OWNER` of the project, restoring
	/// the role if it is already a member without it.
	async fn ensure_project_owner(
		&self,
		org_id: &str,
		project_id: &str,
		user_id: &str,
	) -> anyhow::Result<()> {
		match self
			.call::<IgnoredAny>(
				Method::POST,
				&format!("projects/{project_id}/members"),
				org_id,
				Some(json!({ "userId": user_id, "roles": [PROJECT_OWNER] })),
			)
			.await
		{
			Ok(_) => return Ok(()),
			Err(e) if has_status(&e, StatusCode::CONFLICT) => {}
			Err(e) => return Err(e.context("making service account project owner")),
		}

		if !self.is_project_owner(org_id, project_id, user_id).await? {
			self.call::<IgnoredAny>(
				Method::PUT,
				&format!("projects/{project_id}/members/{user_id}"),
				org_id,
				Some(json!({ "roles": [PROJECT_OWNER] })),
			)
			.await
			.context("restoring project owner role")?;
			info!("restored project owner role of service account {user_id} on {project_id}");
		}
		Ok(())
	}

	/// Makes the service account an instance member with exactly `roles`,
	/// overwriting whatever roles it held before.
	async fn ensure_instance_member(&self, user_id: &str, roles: &[String]) -> anyhow::Result<()> {
		match self
			.request::<IgnoredAny>(
				Method::POST,
				"admin/v1/members",
				None,
				Some(json!({ "userId": user_id, "roles": roles })),
			)
			.await
		{
			Ok(_) => return Ok(()),
			Err(e) if has_status(&e, StatusCode::CONFLICT) => {}
			Err(e) => return Err(e.context("making service account an instance member")),
		}
		match self
			.request::<IgnoredAny>(
				Method::PUT,
				&format!("admin/v1/members/{user_id}"),
				None,
				Some(json!({ "roles": roles })),
			)
			.await
		{
			Ok(_) => Ok(()),
			// Zitadel rejects an update that changes nothing.
			Err(e) if has_status(&e, StatusCode::PRECONDITION_FAILED) => Ok(()),
			Err(e) => Err(e.context("updating instance roles of service account")),
		}
	}

	/// Makes the service account a member of organisation `org_id` with
	/// exactly `roles`, overwriting whatever roles it held there before.
	async fn ensure_org_member(
		&self,
		org_id: &str,
		user_id: &str,
		roles: &[String],
	) -> anyhow::Result<()> {
		//= docs/requirements/zapp.md#org-roles-1
		//# If the matching grant names organisation roles, zapp MUST make the
		//# service account a member of the grant's organisation with exactly
		//# these roles.
		match self
			.call::<IgnoredAny>(
				Method::POST,
				"orgs/me/members",
				org_id,
				Some(json!({ "userId": user_id, "roles": roles })),
			)
			.await
		{
			Ok(_) => return Ok(()),
			Err(e) if has_status(&e, StatusCode::CONFLICT) => {}
			Err(e) => return Err(e.context("making service account an organisation member")),
		}
		//= docs/requirements/zapp.md#org-roles-1
		//# If the service account already is a member of that organisation,
		//# zapp MUST replace its roles there with the grant's organisation
		//# roles.
		match self
			.call::<IgnoredAny>(
				Method::PUT,
				&format!("orgs/me/members/{user_id}"),
				org_id,
				Some(json!({ "roles": roles })),
			)
			.await
		{
			Ok(_) => Ok(()),
			// Zitadel rejects an update that changes nothing.
			Err(e) if has_status(&e, StatusCode::PRECONDITION_FAILED) => Ok(()),
			Err(e) => Err(e.context("updating organisation roles of service account")),
		}
	}

	async fn find_project_named(
		&self,
		name: &str,
		org_id: &str,
	) -> anyhow::Result<Option<V1Project>> {
		let query = V1ProjectQuery::new().with_name_query(
			V1ProjectNameQuery::new()
				.with_name(name.to_string())
				.with_method(V1TextQueryMethod::Equals),
		);
		let projects: Vec<V1Project> = self
			.zitadel
			.list_projects(Some(org_id.to_string()), None, Some(vec![query]))
			.context("searching existing projects")?
			.try_collect()
			.await
			.context("searching existing projects")?;
		// Exact-match query, but never adopt anything we did not ask for.
		Ok(projects.into_iter().find(|project| project.name().map(String::as_str) == Some(name)))
	}

	async fn find_user_named(&self, name: &str, org_id: &str) -> anyhow::Result<Option<User>> {
		let queries = vec![
			SearchQuery::new().with_user_name_query(
				UserNameQuery::new(name.to_string()).with_method(TextQueryMethod::Equals),
			),
			SearchQuery::new()
				.with_organization_id_query(OrganizationIdQuery::new(org_id.to_string())),
		];
		let users: Vec<User> = self
			.zitadel
			.list_users(Some(org_id.to_string()), None, None, Some(queries))
			.context("searching existing service accounts")?
			.try_collect()
			.await
			.context("searching existing service accounts")?;
		Ok(users.into_iter().find(|user| user.username().map(String::as_str) == Some(name)))
	}

	/// Issues a personal access token for `user_id`, expiring at
	/// `expires_at` (RFC 3339).
	async fn create_pat(
		&self,
		user_id: &str,
		org_id: &str,
		expires_at: &str,
	) -> anyhow::Result<String> {
		#[derive(Deserialize)]
		struct Created {
			token: String,
		}
		let created: Created = self
			.call(
				Method::POST,
				&format!("users/{user_id}/pats"),
				org_id,
				Some(json!({ "expirationDate": expires_at })),
			)
			.await
			.context("creating personal access token")?;
		Ok(created.token)
	}

	/// Issues a machine key for `user_id`, expiring at `expires_at` (RFC
	/// 3339). Zitadel generates the keypair and returns the private key as
	/// its JSON key file, which is passed on verbatim.
	async fn create_machine_key(
		&self,
		user_id: &str,
		org_id: &str,
		expires_at: &str,
	) -> anyhow::Result<String> {
		#[derive(Deserialize)]
		struct Created {
			#[serde(rename = "keyDetails")]
			key_details: String,
		}
		let created: Created = self
			.call(
				Method::POST,
				&format!("users/{user_id}/keys"),
				org_id,
				Some(json!({ "type": "KEY_TYPE_JSON", "expirationDate": expires_at })),
			)
			.await
			.context("creating machine key")?;
		let key_file =
			BASE64_STANDARD.decode(created.key_details).context("decoding machine key")?;
		String::from_utf8(key_file).context("decoding machine key")
	}

	// --- Garbage collection primitives -----------------------------------

	/// Lists the zapp-managed service accounts (machine users carrying
	/// `origin` metadata) of organisation `org_id`, including deactivated
	/// ones. Every machine user's metadata is inspected rather than
	/// filtering by name: an account can rename itself (`UpdateMyUserName`
	/// needs only `authenticated`), but not touch its metadata.
	pub async fn list_managed_accounts(&self, org_id: &str) -> anyhow::Result<Vec<ManagedAccount>> {
		let queries = vec![
			SearchQuery::new().with_type_query(TypeQuery::new(Userv2Type::Machine)),
			SearchQuery::new()
				.with_organization_id_query(OrganizationIdQuery::new(org_id.to_string())),
		];
		let users: Vec<User> = self
			.zitadel
			.list_users(Some(org_id.to_string()), None, None, Some(queries))
			.context("listing service accounts")?
			.try_collect()
			.await
			.context("listing service accounts")?;

		let mut accounts = Vec::new();
		for user in users {
			let Some(user_id) = user.user_id() else { continue };
			if user.machine().is_none() {
				continue;
			}
			let metadata = self.user_metadata(user_id, org_id).await?;
			let Some(origin) = metadata.get(METADATA_ORIGIN) else { continue };
			accounts.push(ManagedAccount {
				user_id: user_id.clone(),
				username: user.username().cloned().unwrap_or_default(),
				active: matches!(user.state(), Some(UserState::Active)),
				created_at: user
					.details()
					.and_then(|details| details.creation_date())
					.and_then(|date| parse_time(date)),
				origin: origin.clone(),
				project_ids: creator_project_ids(&metadata),
			});
		}
		Ok(accounts)
	}

	/// When the newest personal access token or machine key of `user_id`
	/// was created, if any.
	pub async fn last_credential_issued(
		&self,
		org_id: &str,
		user_id: &str,
	) -> anyhow::Result<Option<OffsetDateTime>> {
		let pats: Vec<Dated> = self
			.list_paged(&format!("users/{user_id}/pats/_search"), org_id)
			.await
			.context("listing personal access tokens")?;
		let keys: Vec<Dated> = self
			.list_paged(&format!("users/{user_id}/keys/_search"), org_id)
			.await
			.context("listing machine keys")?;
		Ok(pats
			.iter()
			.chain(&keys)
			.filter_map(|dated| dated.details.as_ref()?.creation_date.as_deref())
			.filter_map(parse_time)
			.max())
	}

	/// Whether `user_id` holds `PROJECT_OWNER` on the project.
	async fn is_project_owner(
		&self,
		org_id: &str,
		project_id: &str,
		user_id: &str,
	) -> anyhow::Result<bool> {
		let members: Listing<Member> = self
			.call(
				Method::POST,
				&format!("projects/{project_id}/members/_search"),
				org_id,
				Some(json!({ "queries": [{ "userIdQuery": { "userId": user_id } }] })),
			)
			.await
			.with_context(|| format!("listing members of project {project_id}"))?;
		Ok(members.result.iter().any(|member| {
			member.user_id.as_deref() == Some(user_id)
				&& member.roles.iter().any(|role| role == PROJECT_OWNER)
		}))
	}

	/// Looks up project `project_id`: `None` if it no longer exists,
	/// otherwise whether it is active.
	pub async fn project_status(
		&self,
		org_id: &str,
		project_id: &str,
	) -> anyhow::Result<Option<ProjectStatus>> {
		let project = match self
			.call::<V1GetProjectByIdResponse>(
				Method::GET,
				&format!("projects/{project_id}"),
				org_id,
				None,
			)
			.await
		{
			Ok(response) => response,
			Err(e) if has_status(&e, StatusCode::NOT_FOUND) => return Ok(None),
			Err(e) => return Err(e.context(format!("looking up project {project_id}"))),
		};
		let active =
			matches!(project.project().and_then(V1Project::state), Some(V1ProjectState::Active));
		Ok(Some(ProjectStatus { active }))
	}

	pub async fn deactivate_project(&self, org_id: &str, project_id: &str) -> anyhow::Result<()> {
		self.call::<IgnoredAny>(
			Method::POST,
			&format!("projects/{project_id}/_deactivate"),
			org_id,
			None,
		)
		.await
		.with_context(|| format!("deactivating project {project_id}"))?;
		Ok(())
	}

	/// Removes the project; a project that is already gone is fine.
	pub async fn remove_project(&self, org_id: &str, project_id: &str) -> anyhow::Result<()> {
		match self
			.call::<IgnoredAny>(Method::DELETE, &format!("projects/{project_id}"), org_id, None)
			.await
		{
			Ok(_) => Ok(()),
			Err(e) if has_status(&e, StatusCode::NOT_FOUND) => Ok(()),
			Err(e) => Err(e.context(format!("removing project {project_id}"))),
		}
	}

	pub async fn deactivate_user(&self, user_id: &str) -> anyhow::Result<()> {
		self.zitadel
			.deactivate_user(user_id)
			.await
			.with_context(|| format!("deactivating service account {user_id}"))?;
		Ok(())
	}

	pub async fn delete_user(&self, user_id: &str) -> anyhow::Result<()> {
		self.zitadel
			.delete_user(user_id)
			.await
			.with_context(|| format!("deleting service account {user_id}"))?;
		Ok(())
	}

	// --- Metadata ----------------------------------------------------------

	/// All metadata of the user, values decoded (non-UTF-8 values are
	/// skipped).
	async fn user_metadata(
		&self,
		user_id: &str,
		org_id: &str,
	) -> anyhow::Result<BTreeMap<String, String>> {
		let entries: Vec<MetadataEntry> = self
			.list_paged(&format!("users/{user_id}/metadata/_search"), org_id)
			.await
			.with_context(|| format!("listing metadata of service account {user_id}"))?;
		Ok(entries
			.into_iter()
			.filter_map(|entry| {
				let value = BASE64_STANDARD.decode(entry.value).ok()?;
				Some((entry.key, String::from_utf8(value).ok()?))
			})
			.collect())
	}

	async fn set_user_metadata(
		&self,
		user_id: &str,
		org_id: &str,
		entries: &[(&str, &str)],
	) -> anyhow::Result<()> {
		let metadata: Vec<_> = entries
			.iter()
			.map(|(key, value)| json!({ "key": key, "value": BASE64_STANDARD.encode(value) }))
			.collect();
		self.call::<IgnoredAny>(
			Method::POST,
			&format!("users/{user_id}/metadata/_bulk"),
			org_id,
			Some(json!({ "metadata": metadata })),
		)
		.await
		.with_context(|| format!("setting metadata of service account {user_id}"))?;
		Ok(())
	}

	async fn delete_user_metadata(
		&self,
		user_id: &str,
		org_id: &str,
		keys: &[String],
	) -> anyhow::Result<()> {
		self.call::<IgnoredAny>(
			Method::DELETE,
			&format!("users/{user_id}/metadata/_bulk"),
			org_id,
			Some(json!({ "keys": keys })),
		)
		.await
		.with_context(|| format!("deleting metadata of service account {user_id}"))?;
		Ok(())
	}

	// --- Transport -----------------------------------------------------------

	/// Collects every page of a management API `_search` endpoint.
	async fn list_paged<T: DeserializeOwned>(
		&self,
		path: &str,
		org_id: &str,
	) -> anyhow::Result<Vec<T>> {
		let mut all = Vec::new();
		let mut offset = 0usize;
		loop {
			let page: Listing<T> = self
				.call(
					Method::POST,
					path,
					org_id,
					Some(json!({
						"query": { "offset": offset.to_string(), "limit": PAGE_SIZE, "asc": true },
					})),
				)
				.await?;
			let count = page.result.len();
			all.extend(page.result);
			if count < PAGE_SIZE {
				return Ok(all);
			}
			offset += count;
		}
	}

	/// Sends a management API v1 request to `path` (relative to
	/// `management/v1/`), acting in organisation `org_id`, and parses the
	/// response. Non-success answers surface as [`HttpError`].
	async fn call<T: DeserializeOwned>(
		&self,
		method: Method,
		path: &str,
		org_id: &str,
		body: Option<serde_json::Value>,
	) -> anyhow::Result<T> {
		self.request(method, &format!("management/v1/{path}"), Some(org_id), body).await
	}

	/// Sends a request to `path` (relative to the Zitadel base URL), acting
	/// in organisation `org_id` if given, and parses the response.
	/// Non-success answers surface as [`HttpError`].
	async fn request<T: DeserializeOwned>(
		&self,
		method: Method,
		path: &str,
		org_id: Option<&str>,
		body: Option<serde_json::Value>,
	) -> anyhow::Result<T> {
		let url = self.url.join(path)?;
		let mut request = self
			.http
			.request(method, url)
			.bearer_auth(self.token.token().await.context("refreshing Zitadel access token")?);
		if let Some(org_id) = org_id {
			request = request.header(HEADER_ZITADEL_ORGANIZATION_ID, org_id);
		}
		if let Some(body) = &body {
			request = request.json(body);
		}
		let response = request.send().await?;
		let status = response.status();
		let text = response.text().await?;
		if !status.is_success() {
			return Err(HttpError { status, body: text }.into());
		}
		let text = if text.trim().is_empty() { "null" } else { text.as_str() };
		serde_json::from_str(text).context("parsing Zitadel response")
	}
}

#[cfg(test)]
pub(crate) mod tests {
	use aws_lc_rs::{
		encoding::{AsDer, Pkcs8V1Der},
		rsa::{KeyPair, KeySize},
	};
	use wiremock::{
		Mock, MockServer, ResponseTemplate,
		matchers::{body_json, header, method, path},
	};

	use super::*;

	const ORG_ID: &str = "123456789012345678";
	const USER_ID: &str = "312909075212345678";

	/// A client talking to `server`, authenticated with a freshly generated
	/// service user key against a mocked token endpoint.
	pub(crate) async fn test_client(server: &MockServer) -> ZitadelClient {
		Mock::given(method("POST"))
			.and(path("/oauth/v2/token"))
			.respond_with(ResponseTemplate::new(200).set_body_json(json!({
				"access_token": "test-token",
				"token_type": "Bearer",
				"expires_in": 3600,
			})))
			.mount(server)
			.await;

		let key = KeyPair::generate(KeySize::Rsa2048).expect("generating RSA key");
		let der = AsDer::<Pkcs8V1Der>::as_der(&key).expect("encoding key");
		let pem = format!(
			"-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
			BASE64_STANDARD.encode(der.as_ref())
		);
		let key_file = std::env::temp_dir().join(format!(
			"zapp-test-key-{}-{}.json",
			std::process::id(),
			OffsetDateTime::now_utc().unix_timestamp_nanos()
		));
		let key_json = json!({ "type": "serviceaccount", "keyId": "1", "key": pem, "userId": "1" });
		std::fs::write(&key_file, key_json.to_string()).expect("writing key file");

		let config = ZitadelConfig {
			url: format!("{}/", server.uri()).parse().expect("mock server URL"),
			key_file: key_file.clone(),
			account_prefix_https: "zapp/".to_string(),
			account_prefix_http: None,
			default_duration: Duration::from_secs(3600),
		};
		let client = ZitadelClient::new(&config).await.expect("connecting to mock Zitadel");
		std::fs::remove_file(key_file).ok();
		client
	}

	fn roles() -> Vec<String> {
		vec!["ORG_USER_MANAGER".to_string()]
	}

	#[tokio::test]
	async fn adds_org_member_with_exactly_the_roles() {
		let server = MockServer::start().await;
		let client = test_client(&server).await;
		Mock::given(method("POST"))
			.and(path("/management/v1/orgs/me/members"))
			.and(header(HEADER_ZITADEL_ORGANIZATION_ID, ORG_ID))
			.and(body_json(json!({ "userId": USER_ID, "roles": ["ORG_USER_MANAGER"] })))
			.respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
			.expect(1)
			.mount(&server)
			.await;

		//= docs/requirements/zapp.md#org-roles-1
		//= type=test
		//# If the matching grant names organisation roles, zapp MUST make the
		//# service account a member of the grant's organisation with exactly
		//# these roles.
		client.ensure_org_member(ORG_ID, USER_ID, &roles()).await.expect("org member added");
	}

	#[tokio::test]
	async fn overwrites_roles_of_an_existing_org_member() {
		let server = MockServer::start().await;
		let client = test_client(&server).await;
		Mock::given(method("POST"))
			.and(path("/management/v1/orgs/me/members"))
			.respond_with(ResponseTemplate::new(409).set_body_json(json!({ "code": 6 })))
			.expect(1)
			.mount(&server)
			.await;
		Mock::given(method("PUT"))
			.and(path(format!("/management/v1/orgs/me/members/{USER_ID}")))
			.and(header(HEADER_ZITADEL_ORGANIZATION_ID, ORG_ID))
			.and(body_json(json!({ "roles": ["ORG_USER_MANAGER"] })))
			.respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
			.expect(1)
			.mount(&server)
			.await;

		//= docs/requirements/zapp.md#org-roles-1
		//= type=test
		//# If the service account already is a member of that organisation,
		//# zapp MUST replace its roles there with the grant's organisation
		//# roles.
		client.ensure_org_member(ORG_ID, USER_ID, &roles()).await.expect("org roles replaced");
	}

	#[tokio::test]
	async fn unchanged_org_member_is_fine() {
		let server = MockServer::start().await;
		let client = test_client(&server).await;
		Mock::given(method("POST"))
			.and(path("/management/v1/orgs/me/members"))
			.respond_with(ResponseTemplate::new(409))
			.mount(&server)
			.await;
		// Zitadel rejects an update that changes nothing.
		Mock::given(method("PUT"))
			.and(path(format!("/management/v1/orgs/me/members/{USER_ID}")))
			.respond_with(ResponseTemplate::new(412))
			.expect(1)
			.mount(&server)
			.await;
		client.ensure_org_member(ORG_ID, USER_ID, &roles()).await.expect("nothing to change");
	}

	#[tokio::test]
	async fn org_member_errors_surface() {
		let server = MockServer::start().await;
		let client = test_client(&server).await;
		Mock::given(method("POST"))
			.and(path("/management/v1/orgs/me/members"))
			.respond_with(ResponseTemplate::new(403))
			.mount(&server)
			.await;
		assert!(client.ensure_org_member(ORG_ID, USER_ID, &roles()).await.is_err());
	}

	#[test]
	fn creator_ids_are_numeric_only() {
		let metadata: BTreeMap<String, String> = [
			("origin", "https://a.example"),
			("creator.123", "1"),
			("creator.", "1"),
			("creator.../users/1", "1"),
			("creator.42x", "1"),
			("creator.7", "1"),
		]
		.into_iter()
		.map(|(k, v)| (k.to_string(), v.to_string()))
		.collect();
		assert_eq!(creator_project_ids(&metadata), vec!["123", "7"]);
	}

	#[test]
	fn parses_zitadel_timestamps() {
		assert!(parse_time("2026-09-22T10:00:00.123456Z").is_some());
		assert!(parse_time("2026-09-22T10:00:00Z").is_some());
		assert!(parse_time("yesterday").is_none());
	}
}
