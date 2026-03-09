use anyhow::Result;

use crate::api::ApiClient;
use crate::config::{self, NetworkConfig, ProjectConfig};
use crate::near::NearClient;

/// `outlayer status [call_id]` — project info or poll async call
pub async fn status(
    network: &NetworkConfig,
    project_config: &ProjectConfig,
    call_id: Option<String>,
) -> Result<()> {
    if let Some(call_id) = call_id {
        poll_call(network, project_config, &call_id).await
    } else {
        project_info(network, project_config).await
    }
}

async fn project_info(network: &NetworkConfig, project_config: &ProjectConfig) -> Result<()> {
    let near = NearClient::new(network);

    let project_id = format!(
        "{}/{}",
        project_config.project.owner, project_config.project.name
    );

    let project = near.get_project(&project_id).await?;

    match project {
        Some(p) => {
            println!("Project:  {}", p.project_id);
            println!("UUID:     {}", p.uuid);
            println!("Version:  {} (active)", p.active_version);
            if let Some(deposit) = &p.storage_deposit {
                let near_amount = deposit.parse::<u128>().unwrap_or(0) as f64 / 1e24;
                println!("Storage:  {:.4} NEAR", near_amount);
            }
        }
        None => {
            eprintln!("Project not found: {project_id}");
            eprintln!("Run 'outlayer deploy' to create it.");
        }
    }

    Ok(())
}

async fn poll_call(
    network: &NetworkConfig,
    project_config: &ProjectConfig,
    call_id: &str,
) -> Result<()> {
    let creds = config::load_credentials(network)?;
    let api = ApiClient::new(network);

    // Build payment key for auth
    let payment_key = load_payment_key(&creds.account_id, project_config)?;

    let response = api.get_call_result(call_id, &payment_key).await?;

    println!("Call ID:  {}", response.call_id);
    println!("Status:   {}", response.status);

    if let Some(output) = &response.output {
        println!(
            "Output:   {}",
            serde_json::to_string_pretty(output).unwrap_or_else(|_| output.to_string())
        );
    }
    if let Some(error) = &response.error {
        println!("Error:    {error}");
    }
    if let Some(cost) = &response.compute_cost {
        println!("Cost:     {cost}");
    }
    if let Some(time_ms) = response.time_ms {
        println!("Time:     {time_ms}ms");
    }

    Ok(())
}

fn load_payment_key(account_id: &str, config: &ProjectConfig) -> Result<String> {
    if let Ok(key) = std::env::var("PAYMENT_KEY") {
        return Ok(key);
    }

    let cwd = std::env::current_dir()?;
    let env_path = cwd.join(".env");
    if env_path.exists() {
        let content = std::fs::read_to_string(&env_path)?;
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("PAYMENT_KEY=") {
                return Ok(val.to_string());
            }
        }
    }

    if let Some(ref run) = config.run {
        if let Some(nonce) = run.payment_key_nonce {
            anyhow::bail!(
                "Payment key secret not found. Set PAYMENT_KEY env var.\n\
                 Expected format: {account_id}:{nonce}:<secret>"
            );
        }
    }

    anyhow::bail!("No payment key configured. Set PAYMENT_KEY env var.");
}
