use anyhow::Result;
use serde_json::json;

use crate::api::ApiClient;
use crate::config::{self, NetworkConfig};
use crate::near::{ContractCaller, NearClient};

/// `outlayer earnings` — show developer earnings
pub async fn show(network: &NetworkConfig) -> Result<()> {
    let creds = config::load_credentials(network)?;
    let api = ApiClient::new(network);
    let near = NearClient::new(network);

    // Get HTTPS earnings from coordinator
    let https_earnings = api
        .get_project_owner_earnings(&creds.account_id)
        .await
        .ok();

    // Get blockchain earnings from contract
    let blockchain_earnings = near.get_developer_earnings(&creds.account_id).await.ok();

    let https_balance = https_earnings
        .as_ref()
        .map(|e| format_usd(&e.balance))
        .unwrap_or_else(|| "$0.00".to_string());

    let https_total = https_earnings
        .as_ref()
        .map(|e| format_usd(&e.total_earned))
        .unwrap_or_else(|| "$0.00".to_string());

    let blockchain_balance = blockchain_earnings
        .as_ref()
        .map(|e| format_usd(e))
        .unwrap_or_else(|| "$0.00".to_string());

    println!("Blockchain earnings:  {blockchain_balance}");
    println!("HTTPS API earnings:   {https_balance} (total: {https_total})");

    Ok(())
}

/// `outlayer earnings withdraw` — withdraw blockchain earnings
pub async fn withdraw(network: &NetworkConfig) -> Result<()> {
    let creds = config::load_credentials(network)?;

    let caller = ContractCaller::from_credentials(&creds, network)?;
    let gas = 100_000_000_000_000u64; // 100 TGas

    caller
        .call_contract("withdraw_developer_earnings", json!({}), gas, 1) // 1 yoctoNEAR
        .await?;

    eprintln!("Earnings withdrawn to {}", creds.account_id);
    Ok(())
}

/// `outlayer earnings history` — view earnings history
pub async fn history(
    network: &NetworkConfig,
    source: Option<String>,
    limit: i64,
) -> Result<()> {
    let creds = config::load_credentials(network)?;
    let api = ApiClient::new(network);

    let resp = api
        .get_earnings_history(&creds.account_id, source.as_deref(), limit, 0)
        .await?;

    if resp.earnings.is_empty() {
        eprintln!("No earnings history.");
        return Ok(());
    }

    println!(
        "{:<12} {:<10} {:<25} {:>10}",
        "DATE", "SOURCE", "PROJECT", "AMOUNT"
    );

    for e in &resp.earnings {
        let date = format_timestamp(e.created_at);
        let amount = format_usd(&e.amount);
        println!(
            "{:<12} {:<10} {:<25} {:>10}",
            date, e.source, e.project_id, amount
        );
    }

    if resp.total_count > limit {
        eprintln!(
            "\nShowing {}/{} entries. Use --limit to see more.",
            resp.earnings.len(),
            resp.total_count
        );
    }

    Ok(())
}

/// Format minimal USD units (6 decimals) to human-readable
fn format_usd(minimal_units: &str) -> String {
    let units: u64 = minimal_units.parse().unwrap_or(0);
    let dollars = units as f64 / 1_000_000.0;
    format!("${:.2}", dollars)
}

fn format_timestamp(ts: i64) -> String {
    // ts is unix seconds or milliseconds — normalize
    let secs = if ts > 1_000_000_000_000 {
        ts / 1000
    } else {
        ts
    };
    // Simple date format without chrono
    let days_since_epoch = secs / 86400;
    // Approximate: good enough for display
    let year = 1970 + (days_since_epoch / 365);
    let day_in_year = days_since_epoch % 365;
    let month = day_in_year / 30 + 1;
    let day = day_in_year % 30 + 1;
    format!("{:04}-{:02}-{:02}", year, month, day)
}
