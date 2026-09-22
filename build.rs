// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::process::Command;

fn main() {
	println!("cargo:rerun-if-env-changed=GIT_COMMIT_HASH");
	if std::env::var("GIT_COMMIT_HASH").is_ok() {
		return;
	}

	let git_dir = git(&["rev-parse", "--absolute-git-dir"]).expect("git should output git-dir");
	let head_ref = git(&["symbolic-ref", "--quiet", "HEAD"]);
	let hash =
		git(&["rev-parse", head_ref.as_deref().unwrap_or("HEAD")]).expect("git should output rev");
	println!("cargo:rustc-env=GIT_COMMIT_HASH={hash}");
	println!("cargo:rerun-if-changed={git_dir}/HEAD");
	if let Some(head_ref) = head_ref {
		println!("cargo:rerun-if-changed={git_dir}/{head_ref}");
	}
}

fn git(args: &[&str]) -> Option<String> {
	let mut output = Command::new("git").args(args).output().expect("git command should run");
	output.status.success().then(|| {
		output.stdout.pop_if(|&mut b| b == b'\n');
		String::from_utf8(output.stdout).expect("git output should be UTF-8")
	})
}
