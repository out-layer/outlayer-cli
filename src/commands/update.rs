//! `outlayer update` — self-update the CLI to the latest GitHub release.
//!
//! Uses the `self_update` GitHub backend, which matches the release asset for
//! the current platform (target triple, e.g. `aarch64-apple-darwin`) built by
//! `.github/workflows/release.yml`, downloads it, and atomically replaces the
//! running binary. Releases are cut on git tags, so `update` only sees a new
//! version once a tagged release has been published.

use anyhow::{Context, Result};

/// Repo hosting the release artifacts (see `.github/workflows/release.yml`).
const REPO_OWNER: &str = "out-layer";
const REPO_NAME: &str = "outlayer-cli";
/// Binary name inside the release tarball (`BINARY_NAME` in release.yml).
const BIN_NAME: &str = "outlayer";

/// Check GitHub releases for a newer version and replace the running binary.
///
/// **Blocking** — `self_update` uses `reqwest::blocking`, which spins up its
/// own runtime and panics if called from within an async context. The
/// dispatcher MUST run this via `tokio::task::spawn_blocking`.
pub fn run() -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    println!("outlayer v{current} — checking {REPO_OWNER}/{REPO_NAME} for updates…");

    let status = self_update::backends::github::Update::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .bin_name(BIN_NAME)
        .current_version(current)
        .show_download_progress(true)
        .build()
        .context("failed to configure self-update")?
        .update()
        .context(
            "self-update failed — check your network, or that a release asset exists \
             for this platform. You can always reinstall with: \
             cargo install --git https://github.com/out-layer/outlayer-cli --force",
        )?;

    if status.updated() {
        println!("✓ Updated outlayer to v{}", status.version());
    } else {
        println!("✓ Already up to date (v{current})");
    }
    Ok(())
}
