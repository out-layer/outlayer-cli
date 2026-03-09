use anyhow::Result;
use serde_json::json;

use crate::config::{self, NetworkConfig, ProjectConfig};
use crate::near::{NearClient, NearSigner};

/// `outlayer versions` — list project versions
pub async fn list(network: &NetworkConfig, project_config: &ProjectConfig) -> Result<()> {
    let near = NearClient::new(network);

    let project_id = format!(
        "{}/{}",
        project_config.project.owner, project_config.project.name
    );

    let versions = near.list_versions(&project_id, None, Some(50)).await?;

    if versions.is_empty() {
        eprintln!("No versions found for {project_id}");
        return Ok(());
    }

    println!(
        "{:<12} {:<50} {:<8}",
        "VERSION", "SOURCE", "STATUS"
    );

    for v in &versions {
        let version_key = &v.wasm_hash;
        let short_key = if version_key.len() > 10 {
            &version_key[..10]
        } else {
            version_key
        };

        let source_str = format_source(&v.source);
        let status = if v.is_active { "active" } else { "---" };

        println!("{:<12} {:<50} {:<8}", short_key, source_str, status);
    }

    Ok(())
}

/// `outlayer versions activate <version_key>` — switch active version
pub async fn activate(
    network: &NetworkConfig,
    project_config: &ProjectConfig,
    version_key: &str,
) -> Result<()> {
    let creds = config::load_credentials(network)?;
    let private_key = config::load_private_key(&network.network_id, &creds.account_id, &creds)?;

    let signer = NearSigner::new(network, &creds.account_id, &private_key)?;
    let gas = 30_000_000_000_000u64; // 30 TGas

    signer
        .call_contract(
            "set_active_version",
            json!({
                "project_name": project_config.project.name,
                "version_key": version_key,
            }),
            gas,
            0,
        )
        .await?;

    eprintln!("Activated version: {version_key}");
    Ok(())
}

/// `outlayer versions remove <version_key>` — remove a version
pub async fn remove(
    network: &NetworkConfig,
    project_config: &ProjectConfig,
    version_key: &str,
) -> Result<()> {
    let creds = config::load_credentials(network)?;
    let private_key = config::load_private_key(&network.network_id, &creds.account_id, &creds)?;

    let signer = NearSigner::new(network, &creds.account_id, &private_key)?;
    let gas = 30_000_000_000_000u64; // 30 TGas

    signer
        .call_contract(
            "remove_version",
            json!({
                "project_name": project_config.project.name,
                "version_key": version_key,
            }),
            gas,
            0,
        )
        .await?;

    eprintln!("Removed version: {version_key}");
    Ok(())
}

fn format_source(source: &serde_json::Value) -> String {
    if let Some(obj) = source.as_object() {
        if let Some(github) = obj.get("GitHub") {
            let repo = github
                .get("repo")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let commit = github
                .get("commit")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let short_commit = if commit.len() > 7 {
                &commit[..7]
            } else {
                commit
            };
            return format!("github:{repo}@{short_commit}");
        }
        if let Some(wasm) = obj.get("WasmUrl") {
            let url = wasm.get("url").and_then(|v| v.as_str()).unwrap_or("?");
            return format!("wasm:{url}");
        }
    }
    source.to_string()
}
