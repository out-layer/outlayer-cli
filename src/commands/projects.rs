use anyhow::Result;

use crate::config::{self, NetworkConfig};
use crate::near::NearClient;

/// `outlayer projects [account]` — list projects for a user
pub async fn list(network: &NetworkConfig, account: Option<String>) -> Result<()> {
    let account_id = match account {
        Some(id) => id,
        None => {
            let creds = config::load_credentials(network)?;
            creds.account_id
        }
    };

    let near = NearClient::new(network);

    let projects: Vec<crate::near::ProjectView> = near
        .view_call(
            "list_user_projects",
            serde_json::json!({ "account_id": account_id }),
        )
        .await?;

    if projects.is_empty() {
        eprintln!("No projects for {account_id}.");
        return Ok(());
    }

    println!(
        "{:<35} {:<12} {:<30} {:<10}",
        "PROJECT", "VERSION", "SOURCE", "UUID"
    );

    for p in &projects {
        let short_version = if p.active_version.len() > 10 {
            &p.active_version[..10]
        } else {
            &p.active_version
        };

        // Fetch active version to get source type
        let source_str = match near.get_version(&p.project_id, &p.active_version).await {
            Ok(Some(v)) => format_source(&v.source),
            _ => "---".to_string(),
        };

        println!(
            "{:<35} {:<12} {:<30} {:<10}",
            p.project_id, short_version, source_str, p.uuid
        );
    }

    Ok(())
}

fn format_source(source: &serde_json::Value) -> String {
    if let Some(obj) = source.as_object() {
        if let Some(github) = obj.get("GitHub") {
            let repo = github
                .get("repo")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            // Shorten repo URL
            let short_repo = repo
                .strip_prefix("https://github.com/")
                .unwrap_or(repo);
            let commit = github
                .get("commit")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let short_commit = if commit.len() > 7 {
                &commit[..7]
            } else {
                commit
            };
            return format!("github:{short_repo}@{short_commit}");
        }
        if let Some(wasm) = obj.get("WasmUrl") {
            let url = wasm.get("url").and_then(|v| v.as_str()).unwrap_or("?");
            let short = if url.len() > 25 {
                &url[..25]
            } else {
                url
            };
            return format!("wasm:{short}...");
        }
    }
    "unknown".to_string()
}
