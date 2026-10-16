use anyhow::{Context, Result};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::config::{self, NetworkConfig};
use crate::near::{ContractCaller, NearClient};

/// `outlayer deploy <name> <wasm_url>` — deploy agent to OutLayer
///
/// A version is a prebuilt wasm named by its sha256: what a caller pays to run
/// is exactly the file that was published, and it cannot change under the same
/// version later.
pub async fn deploy(
    network: &NetworkConfig,
    project_name: &str,
    wasm_url: &str,
    wasm_hash: Option<String>,
    build_target: &str,
    no_activate: bool,
) -> Result<()> {
    let creds = config::load_credentials(network)?;
    let owner = &creds.account_id;

    let hash = match wasm_hash {
        Some(h) => h,
        None => {
            eprintln!("Downloading WASM to compute hash...");
            compute_wasm_hash(wasm_url).await?
        }
    };
    let source = json!({
        "WasmUrl": {
            "url": wasm_url,
            "hash": hash,
            "build_target": build_target
        }
    });
    let short_hash = if hash.len() > 12 { &hash[..12] } else { &hash };
    let version_label = format!("{short_hash}...");

    eprintln!("Deploying {owner}/{project_name}...");
    eprintln!("  Source: WasmUrl ({wasm_url})");

    let near = NearClient::new(network);
    let caller = ContractCaller::from_credentials(&creds, network)?;

    let project_id = format!("{owner}/{project_name}");
    let deposit = 100_000_000_000_000_000_000_000u128; // 0.1 NEAR
    let gas = 100_000_000_000_000u64; // 100 TGas

    // Check if project exists
    let existing = near.get_project(&project_id).await?;

    if existing.is_some() {
        eprintln!("  Adding version {version_label}...");
        caller
            .call_contract(
                "add_version",
                json!({
                    "project_name": project_name,
                    "source": source,
                    "set_active": !no_activate
                }),
                gas,
                deposit,
            )
            .await
            .context("Failed to add version")?;
    } else {
        eprintln!("  Creating new project...");
        caller
            .call_contract(
                "create_project",
                json!({
                    "name": project_name,
                    "source": source
                }),
                gas,
                deposit,
            )
            .await
            .context("Failed to create project")?;
    }

    if no_activate {
        eprintln!("  Version {version_label} deployed (not activated)");
    } else {
        eprintln!("  Project deployed");
    }

    eprintln!("\nRun with: outlayer run {owner}/{project_name} '{{\"command\": \"hello\"}}'");
    Ok(())
}

async fn compute_wasm_hash(url: &str) -> Result<String> {
    let response = reqwest::get(url)
        .await
        .with_context(|| format!("Failed to download WASM from {url}"))?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to download WASM: HTTP {}", response.status());
    }

    let bytes = response
        .bytes()
        .await
        .context("Failed to read WASM response body")?;

    Ok(hex::encode(Sha256::digest(&bytes)))
}
