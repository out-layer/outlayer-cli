//! `outlayer redeem <code>` — redeem a sponsor code for a custody wallet, and
//! `outlayer keys trial-key` — read that wallet's nonce-0 key again.
//!
//! A sponsor code (`spn_…`) puts a subscription on the wallet's nonce-0 key,
//! paid by the sponsor; the key is created if the wallet has none. The wallet
//! is named by its API key (`wk_…`), resolved as `outlayer checks` resolves it:
//! `--api-key`, then `OUTLAYER_WALLET_KEY`.
//!
//! The nonce-0 key is derived by the keystore, so it is never written to disk
//! here: `outlayer keys trial-key` reads it again on request.

use anyhow::{Context, Result};

use crate::api::ApiClient;
use super::checks::resolve_wallet_key;
use crate::config::NetworkConfig;

/// What the coordinator said, as one line. Two body shapes: the refusals with
/// `{error: <sentence>, reason: <code>}`, and the wallet API's
/// `{error: <code>, message: <sentence>}`.
fn refusal(status: reqwest::StatusCode, body: &serde_json::Value) -> String {
    let (reason, error) = match body["reason"].as_str() {
        Some(reason) => (reason, body["error"].as_str().unwrap_or("")),
        None => (body["error"].as_str().unwrap_or(""), body["message"].as_str().unwrap_or("")),
    };
    match (reason.is_empty(), error.is_empty()) {
        (false, false) => format!("{error} ({reason}, HTTP {})", status.as_u16()),
        (true, false) => format!("{error} (HTTP {})", status.as_u16()),
        _ => format!("HTTP {}", status.as_u16()),
    }
}

/// Stablecoin minimal units (6 decimals) as dollars.
fn usd(minimal: &str) -> String {
    match minimal.parse::<u128>() {
        Ok(n) => format!("${}.{:02}", n / 1_000_000, (n % 1_000_000) / 10_000),
        Err(_) => minimal.to_string(),
    }
}

/// `outlayer redeem <code>`
pub async fn redeem(network: &NetworkConfig, api_key: Option<&str>, code: &str) -> Result<()> {
    let key = resolve_wallet_key(api_key)?;
    let api = ApiClient::new(network);

    eprintln!("Redeeming the sponsor code...");
    let (status, body) = api.redeem_sponsor_code(&key, code.trim()).await?;
    if !status.is_success() {
        anyhow::bail!("The code was not redeemed: {}", refusal(status, &body));
    }

    let sponsor = body["sponsor"].as_str().unwrap_or("?");
    let allowance = body["allowance_usd"].as_str().unwrap_or("0");
    let expires_at = body["expires_at"].as_str().unwrap_or("?");
    eprintln!();
    eprintln!("  Sponsor:    {sponsor}");
    eprintln!("  Allowance:  {}", usd(allowance));
    eprintln!("  Until:      {expires_at}");
    eprintln!("  Owner:      {}", body["owner"].as_str().unwrap_or("?"));
    if let Some(note) = body["note"].as_str() {
        eprintln!();
        eprintln!("  {note}");
    }
    match body["payment_key"].as_str() {
        Some(payment_key) => {
            eprintln!();
            eprintln!("Payment key (send as X-Payment-Key; `outlayer keys trial-key` reads it again):");
            // Alone on stdout, so `$(outlayer redeem …)` captures just the key.
            println!("{payment_key}");
        }
        None => {
            eprintln!();
            eprintln!(
                "The grant is on this wallet's nonce-0 key, but this credential cannot read the \
                 key: it was claimed with another of the wallet's credentials, or drawn at \
                 random. That credential, or the copy you kept, carries the subscription."
            );
        }
    }
    Ok(())
}

/// `outlayer keys trial-key`
pub async fn show_nonce0(network: &NetworkConfig, api_key: Option<&str>) -> Result<()> {
    let key = resolve_wallet_key(api_key)?;
    let api = ApiClient::new(network);
    let (status, body) = api.get_nonce0_payment_key(&key).await?;
    if !status.is_success() {
        anyhow::bail!("No key: {}", refusal(status, &body));
    }
    let payment_key = body["payment_key"]
        .as_str()
        .context("The coordinator answered without a payment_key")?;
    let kind = if body["subscription"].as_bool().unwrap_or(false) {
        "subscription"
    } else {
        "trial"
    };
    eprintln!(
        "Nonce-0 key ({kind}), until {}:",
        body["expires_at"].as_str().unwrap_or("—")
    );
    println!("{payment_key}");
    Ok(())
}
