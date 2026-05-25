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
        // Explicit WASM URL source
        let hash = match &wasm_hash {
            Some(h) => h.clone(),
            None => {
                eprintln!("  Computing WASM hash...");
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
        // Try local build first, fall back to GitHub
        match build_and_upload(network, build_target).await {
            Ok((url, hash)) => {
                let source = json!({
                    "WasmUrl": {
                        "url": url,
                        "hash": hash,
                        "build_target": build_target
                    }
                });
                let short = if hash.len() > 12 { &hash[..12] } else { &hash };
                (source, format!("fastfs:{short}..."))
            }
            Err(_) => {
                // No local WASM — try GitHub
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
            }
        }
    };

    eprintln!("\n  Deploying \x1b[1m{owner}/{project_name}\x1b[0m...");
    eprintln!("  Source: {version_label}");

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
        eprintln!("  \x1b[32m✓\x1b[0m Deployed");
    }

    eprintln!("\n  Run: \x1b[33moutlayer run {owner}/{project_name} '{{\"command\": \"hello\"}}'\x1b[0m");
    Ok(())
}

/// Build WASM locally and upload to FastFS.
/// Returns (fastfs_url, sha256_hex) on success.
async fn build_and_upload(
    network: &NetworkConfig,
    build_target: &str,
) -> Result<(String, String)> {
    // 1. Find WASM — either already built, or build it
    let wasm_path = find_or_build_wasm(build_target)?;

    // 2. Read and hash
    let content = std::fs::read(&wasm_path)
        .with_context(|| format!("Failed to read WASM: {}", wasm_path.display()))?;
    let hash = hex::encode(Sha256::digest(&content));

    eprintln!("  Built: {} ({} bytes)", wasm_path.display(), content.len());
    eprintln!("  SHA256: {hash}");

    // 3. Upload to FastFS
    let creds = config::load_credentials(network)?;
    let receiver_id = network.contract_id.clone();
    let relative_path = format!("{hash}.wasm");

    let payloads = crate::commands::upload::prepare_fastfs_payloads(
        &relative_path, "application/wasm", &content,
    );
    let num_chunks = payloads.len();

    eprintln!("  Uploading to FastFS...");
    if num_chunks > 1 {
        eprintln!("  Chunks: {num_chunks}");
    }

    let mut last_tx_hash = None;
    let mut upload_end_nonce = 0u64;

    if creds.is_wallet_key() {
        crate::commands::upload::upload_via_wallet(
            network, &creds, &receiver_id, &payloads,
        ).await?;
    } else {
        // Upload chunks and track last tx hash
        let private_key = config::load_private_key(&network.network_id, &creds.account_id, &creds)?;
        let signer = crate::near::NearSigner::new(network, &creds.account_id, &private_key)?;
        let (current_nonce, block_hash) = signer.get_tx_context().await?;
        upload_end_nonce = current_nonce + num_chunks as u64;

        for (i, payload) in payloads.iter().enumerate() {
            if num_chunks > 1 {
                eprint!("  Uploading chunk {}/{}... ", i + 1, num_chunks);
            } else {
                eprint!("  Uploading... ");
            }

            let tx_hash = signer
                .send_function_call_async(
                    &receiver_id.parse()?,
                    "__fastdata_fastfs",
                    payload.clone(),
                    1,
                    0,
                    current_nonce + 1 + i as u64,
                    block_hash,
                )
                .await
                .with_context(|| format!("Failed to upload chunk {}/{}", i + 1, num_chunks))?;

            eprintln!("tx: {tx_hash}");
            last_tx_hash = Some(tx_hash);
        }
    }

    // Wait for last upload tx to finalize so nonce is updated before deploy
    if last_tx_hash.is_some() && upload_end_nonce > 0 {
        eprint!("  Waiting for finalization... ");
        let private_key = config::load_private_key(&network.network_id, &creds.account_id, &creds)?;
        let signer = crate::near::NearSigner::new(network, &creds.account_id, &private_key)?;
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if let Ok((current, _)) = signer.get_tx_context().await {
                if current >= upload_end_nonce {
                    break;
                }
            }
        }
        eprintln!("ok");
    }

    let fastfs_host = match network.network_id.as_str() {
        "mainnet" => "main.fastfs.io",
        "testnet" => "test.fastfs.io",
        other => anyhow::bail!("unknown network '{other}'"),
    };
    let url = format!(
        "https://{}/{}/{}/{}",
        fastfs_host, creds.account_id, receiver_id, relative_path
    );

    eprintln!("  FastFS: {url}");
    Ok((url, hash))
}

/// Find a pre-built WASM or build one with cargo.
fn find_or_build_wasm(build_target: &str) -> Result<std::path::PathBuf> {
    // Check common output locations for pre-built WASM
    let search_dirs = vec![
        format!("target/{build_target}/release/"),
        "pkg/".to_string(),
        "out/".to_string(),
    ];

    for dir in &search_dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map_or(false, |e| e == "wasm") {
                    return Ok(path);
                }
            }
        }
    }

    // No pre-built WASM found — try to build
    eprintln!("  Building WASM (\x1b[36mcargo build --target {build_target} --release\x1b[0m)...");

    let output = std::process::Command::new("cargo")
        .args(["build", "--target", build_target, "--release"])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .output()
        .context("Failed to run cargo build")?;

    if !output.status.success() {
        anyhow::bail!("cargo build failed — fix errors and try again");
    }

    // Find the built WASM
    let dir = format!("target/{build_target}/release/");
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "wasm") {
                return Ok(path);
            }
        }
    }

    anyhow::bail!("Build succeeded but no .wasm file found in {dir}")
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
