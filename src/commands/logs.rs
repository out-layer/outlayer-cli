use anyhow::{Context, Result};

use crate::api::ApiClient;
use crate::config::{self, NetworkConfig, ProjectConfig};

/// `outlayer logs` — view execution history (payment key usage)
pub async fn logs(
    network: &NetworkConfig,
    project_config: Option<&ProjectConfig>,
    nonce: Option<u32>,
    limit: i64,
) -> Result<()> {
    let creds = config::load_credentials(network)?;
    let api = ApiClient::new(network);

    // Determine nonce from flag, config, or bail
    let nonce = nonce
        .or_else(|| {
            project_config
                .and_then(|c| c.run.as_ref())
                .and_then(|r| r.payment_key_nonce)
        })
        .context("No payment key nonce. Use --nonce or set payment_key_nonce in outlayer.toml.")?;

    let resp = api
        .get_payment_key_usage(&creds.account_id, nonce, limit, 0)
        .await?;

    if resp.usage.is_empty() {
        eprintln!("No execution history for key nonce {nonce}.");
        return Ok(());
    }

    println!(
        "{:<38} {:<10} {:>10} {:<25}",
        "CALL_ID", "STATUS", "COST", "PROJECT"
    );

    for u in &resp.usage {
        let cost = format_usd(&u.compute_cost);
        println!(
            "{:<38} {:<10} {:>10} {:<25}",
            u.call_id, u.status, cost, u.project_id
        );
    }

    if resp.total > limit {
        eprintln!(
            "\nShowing {}/{} entries. Use --limit to see more.",
            resp.usage.len(),
            resp.total
        );
    }

    Ok(())
}

fn format_usd(minimal_units: &str) -> String {
    let units: u64 = minimal_units.parse().unwrap_or(0);
    let dollars = units as f64 / 1_000_000.0;
    format!("${:.4}", dollars)
}
