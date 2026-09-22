// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Garbage collection of zapp-managed service accounts and their projects.
//!
//! An issuer that stops renewing is presumed gone. Its service account is
//! recognised by the `origin` metadata zapp stamps on it, its projects by the
//! `creator.<project id>` metadata keys. The age of an account is the time
//! since its newest personal access token or machine key was created (or
//! since the account itself was created, if it has none):
//!
//! - **soft**: once older than `gc.soft`, the account is deactivated, then
//!   every project it created. Deactivated resources are dormant but intact;
//!   the next credential request from the issuer reactivates them.
//! - **hard**: once older than `gc.hard`, the account is deactivated as above,
//!   then its projects are deleted, then the account itself.
//!
//! The `creator.*` metadata is authoritative: writing user metadata needs
//! `user.write`, which the account does not hold, so only zapp writes it. It
//! is deliberately *not* cross-checked against project membership: a
//! `PROJECT_OWNER` can remove its own membership, and gating on it would let
//! an account exempt its project from collection.

use std::{collections::BTreeSet, sync::Arc};

use time::OffsetDateTime;
use tracing::{info, warn};

use crate::{
	config::GcConfig,
	zitadel::{ManagedAccount, ZitadelClient},
};

/// Which stage garbage collection reached for an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
	/// Younger than the soft threshold: nothing to do.
	Fresh,
	/// Older than the soft threshold: deactivate.
	Soft,
	/// Older than the hard threshold: deactivate and delete.
	Hard,
}

/// Picks the stage for an account whose last activity was at `last_active`.
pub fn stage(config: &GcConfig, now: OffsetDateTime, last_active: OffsetDateTime) -> Stage {
	let age = now - last_active;
	if age >= config.hard {
		Stage::Hard
	} else if age >= config.soft {
		Stage::Soft
	} else {
		Stage::Fresh
	}
}

/// Runs garbage collection every `config.interval` until the process ends.
pub async fn run(config: GcConfig, org_ids: BTreeSet<String>, zitadel: Arc<ZitadelClient>) {
	let mut ticker = tokio::time::interval(config.interval);
	ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
	loop {
		ticker.tick().await;
		for org_id in &org_ids {
			if let Err(e) = collect(&config, &zitadel, org_id).await {
				warn!("garbage collection in org {org_id} failed: {e:#}");
			}
		}
	}
}

/// One garbage collection pass over organisation `org_id`. Failures on a
/// single account are logged and do not stop the pass.
pub async fn collect(
	config: &GcConfig,
	zitadel: &ZitadelClient,
	org_id: &str,
) -> anyhow::Result<()> {
	let now = OffsetDateTime::now_utc();
	let accounts = zitadel.list_managed_accounts(org_id).await?;
	for account in accounts {
		if let Err(e) = collect_account(config, zitadel, org_id, &account, now).await {
			warn!(
				"garbage collecting service account {} ({}) failed: {e:#}",
				account.username, account.user_id
			);
		}
	}
	Ok(())
}

async fn collect_account(
	config: &GcConfig,
	zitadel: &ZitadelClient,
	org_id: &str,
	account: &ManagedAccount,
	now: OffsetDateTime,
) -> anyhow::Result<()> {
	let last_credential = zitadel.last_credential_issued(org_id, &account.user_id).await?;
	let Some(last_active) = last_credential.max(account.created_at) else {
		// Zitadel always reports creation dates; without one there is no
		// safe way to judge age.
		warn!(
			"service account {} ({}) has no creation date; skipping",
			account.username, account.user_id
		);
		return Ok(());
	};

	let stage = stage(config, now, last_active);
	if stage == Stage::Fresh {
		return Ok(());
	}
	info!(
		"service account {} ({}) for issuer {} last active {last_active}: {stage:?} collection",
		account.username, account.user_id, account.origin
	);

	// Deactivate the account first: it is the thing holding credentials.
	if account.active {
		zitadel.deactivate_user(&account.user_id).await?;
		info!("deactivated service account {} ({})", account.username, account.user_id);
	}

	let mut projects = Vec::new();
	for project_id in &account.project_ids {
		let Some(status) = zitadel.project_status(org_id, project_id).await? else {
			continue;
		};
		if status.active {
			zitadel.deactivate_project(org_id, project_id).await?;
			info!("deactivated project {project_id} of {}", account.username);
		}
		projects.push(project_id.as_str());
	}

	if stage == Stage::Hard {
		for project_id in projects {
			zitadel.remove_project(org_id, project_id).await?;
			info!("deleted project {project_id} of {}", account.username);
		}
		zitadel.delete_user(&account.user_id).await?;
		info!("deleted service account {} ({})", account.username, account.user_id);
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use super::*;

	fn config() -> GcConfig {
		GcConfig {
			interval: Duration::from_secs(600),
			soft: Duration::from_secs(24 * 3600),
			hard: Duration::from_secs(36 * 3600),
		}
	}

	#[test]
	fn stages_by_age() {
		let now = OffsetDateTime::UNIX_EPOCH + Duration::from_secs(100 * 3600);
		let at = |hours_ago: u64| now - Duration::from_secs(hours_ago * 3600);
		assert_eq!(stage(&config(), now, at(0)), Stage::Fresh);
		assert_eq!(stage(&config(), now, at(23)), Stage::Fresh);
		assert_eq!(stage(&config(), now, at(24)), Stage::Soft);
		assert_eq!(stage(&config(), now, at(35)), Stage::Soft);
		assert_eq!(stage(&config(), now, at(36)), Stage::Hard);
		assert_eq!(stage(&config(), now, at(1000)), Stage::Hard);
	}

	#[test]
	fn future_activity_is_fresh() {
		let now = OffsetDateTime::UNIX_EPOCH + Duration::from_secs(100 * 3600);
		assert_eq!(stage(&config(), now, now + Duration::from_secs(3600)), Stage::Fresh);
	}
}
