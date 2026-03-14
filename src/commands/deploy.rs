use anyhow::{Context, Result};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::config::{self, NetworkConfig};
use crate::near::{ContractCaller, NearClient};

/// `outlayer deploy <name>` — deploy agent to OutLayer
pub async fn deploy(
    network: &NetworkConfig,
    project_name: &str,
    wasm_url: Option<String>,
    wasm_hash: Option<String>,
    build_target: &str,
    no_activate: bool,
) -> Result<()> {
    let creds = config::load_credentials(network)?;
    let owner = &creds.account_id;

    let (source, version_label) = if let Some(url) = &wasm_url {
        // WASM URL source (FastFS or any URL)
        let hash = match &wasm_hash {
            Some(h) => h.clone(),
            None => {
                eprintln!("Downloading WASM to compute hash...");
                compute_wasm_hash(url).await?
            }
        };
        let source = json!({
            "WasmUrl": {
                "url": url,
                "hash": hash,
                "build_target": build_target
            }
        });
        let short_hash = if hash.len() > 12 { &hash[..12] } else { &hash };
        (source, format!("{short_hash}..."))
    } else {
        // GitHub source (default)
        let commit = get_git_commit()?;
        let repo_url = get_git_remote()?;
        let source = json!({
            "GitHub": {
                "repo": repo_url,
                "commit": commit,
                "build_target": build_target
            }
        });
        (source, commit)
    };

    eprintln!("Deploying {owner}/{project_name}...");
    if wasm_url.is_some() {
        eprintln!("  Source: WasmUrl ({})", wasm_url.as_ref().unwrap());
    } else {
        eprintln!("  Source: GitHub ({version_label})");
    }

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

fn get_git_commit() -> Result<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .context("Failed to run git rev-parse HEAD")?;

    if !output.status.success() {
        anyhow::bail!("Not a git repository. Initialize git first: git init && git commit");
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn get_git_remote() -> Result<String> {
    let output = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .context("Failed to get git remote URL")?;

    if !output.status.success() {
        anyhow::bail!("No git remote found. Add one: git remote add origin <url>");
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
