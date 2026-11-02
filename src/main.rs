// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

mod config;
mod gc;
mod pattern;
mod policy;
mod server;
mod verify;
mod zitadel;

use std::sync::Arc;

use anyhow::Context;
use tracing::info;

use crate::{
	config::Config, policy::StaticResolver, server::AppState, verify::DomainVerifier,
	zitadel::ZitadelClient,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	tracing_subscriber::fmt()
		.with_env_filter(
			tracing_subscriber::EnvFilter::try_from_default_env()
				.unwrap_or_else(|_| "zapp=info".into()),
		)
		.init();

	let config_path = std::env::args().nth(1).unwrap_or_else(|| "zapp.toml".to_string());
	let config = Config::load(&config_path)?;

	if config.grants.is_empty() {
		anyhow::bail!("no [[grants]] configured; nothing could ever be issued");
	}

	let zitadel = Arc::new(ZitadelClient::new(&config.zitadel).await?);

	if let Some(gc) = config.gc.clone() {
		let org_ids = config.gc_org_ids();
		info!(
			"garbage collection every {}: deactivate after {}, delete after {}",
			humantime::format_duration(gc.interval),
			humantime::format_duration(gc.soft),
			humantime::format_duration(gc.hard)
		);
		tokio::spawn(gc::run(gc, org_ids, zitadel.clone()));
	}

	let state = Arc::new(AppState {
		// Plain-http issuers are only verified (and thus talked to) at
		// all when an http account prefix is configured.
		verifier: DomainVerifier::new(
			&config.verification,
			config.zitadel.account_prefix_http.is_some(),
		)?,
		resolver: Box::new(StaticResolver::new(config.grants, config.zitadel.default_duration)),
		zitadel,
		account_prefix_https: config.zitadel.account_prefix_https.clone(),
		account_prefix_http: config.zitadel.account_prefix_http.clone(),
	});

	let listener = tokio::net::TcpListener::bind(&config.listen)
		.await
		.with_context(|| format!("binding to {}", config.listen))?;
	info!(
		"zapp {} listening on {} ({})",
		env!("CARGO_PKG_VERSION"),
		config.listen,
		server::SOURCE_OFFER
	);
	axum::serve(listener, server::router(state)).await?;
	Ok(())
}
