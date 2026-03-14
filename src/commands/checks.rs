use anyhow::{Context, Result};

use crate::api::ApiClient;
use crate::config::NetworkConfig;

/// Resolve wallet API key from --api-key flag or OUTLAYER_WALLET_KEY env var
pub fn resolve_wallet_key(api_key: Option<&str>) -> Result<String> {
    if let Some(key) = api_key {
        return Ok(key.to_string());
    }
    std::env::var("OUTLAYER_WALLET_KEY")
        .context("Wallet API key required. Use --api-key or set OUTLAYER_WALLET_KEY env var")
}

/// `outlayer checks create <token> <amount>`
pub async fn create(
    network: &NetworkConfig,
    api_key: Option<&str>,
    token: &str,
    amount: &str,
    memo: Option<&str>,
    expires_in: Option<u64>,
) -> Result<()> {
    let key = resolve_wallet_key(api_key)?;
    let api = ApiClient::new(network);

    eprintln!("Creating payment check...");

    let resp = api
        .create_payment_check(&key, token, amount, memo, expires_in)
        .await?;

    println!("check_id:  {}", resp.check_id);
    println!("check_key: {}", resp.check_key);
    println!("token:     {}", resp.token);
    println!("amount:    {}", resp.amount);
    if let Some(memo) = &resp.memo {
        println!("memo:      {}", memo);
    }
    println!("created:   {}", resp.created_at);
    if let Some(expires) = &resp.expires_at {
        println!("expires:   {}", expires);
    }

    eprintln!("\nSave the check_key — it is shown only once. Send it to the recipient.");

    Ok(())
}

/// `outlayer checks batch-create --file checks.json`
pub async fn batch_create(
    network: &NetworkConfig,
    api_key: Option<&str>,
    file: &str,
) -> Result<()> {
    let key = resolve_wallet_key(api_key)?;
    let api = ApiClient::new(network);

    let data = std::fs::read_to_string(file)
        .with_context(|| format!("Failed to read file: {}", file))?;
    let checks: Vec<serde_json::Value> =
        serde_json::from_str(&data).context("Invalid JSON in checks file. Expected array of {token, amount, memo?, expires_in?}")?;

    if checks.is_empty() {
        anyhow::bail!("Empty checks array");
    }
    if checks.len() > 10 {
        anyhow::bail!("Maximum 10 checks per batch");
    }

    eprintln!("Creating {} payment checks...", checks.len());

    let resp = api.batch_create_payment_checks(&key, &checks).await?;

    for (i, check) in resp.checks.iter().enumerate() {
        println!("--- Check {} ---", i + 1);
        println!("check_id:  {}", check.check_id);
        println!("check_key: {}", check.check_key);
        println!("amount:    {}", check.amount);
        if let Some(memo) = &check.memo {
            println!("memo:      {}", memo);
        }
    }

    eprintln!("\nSave all check_keys — they are shown only once.");

    Ok(())
}

/// `outlayer checks claim <check_key>`
pub async fn claim(
    network: &NetworkConfig,
    api_key: Option<&str>,
    check_key: &str,
    amount: Option<&str>,
) -> Result<()> {
    let key = resolve_wallet_key(api_key)?;
    let api = ApiClient::new(network);

    if let Some(amt) = amount {
        eprintln!("Claiming {} from payment check...", amt);
    } else {
        eprintln!("Claiming payment check (full)...");
    }

    let resp = api.claim_payment_check(&key, check_key, amount).await?;

    println!("token:     {}", resp.token);
    println!("claimed:   {}", resp.amount_claimed);
    println!("remaining: {}", resp.remaining);
    if let Some(memo) = &resp.memo {
        println!("memo:      {}", memo);
    }
    println!("time:      {}", resp.claimed_at);

    eprintln!("\nFunds landed in your intents balance.");

    Ok(())
}

/// `outlayer checks reclaim <check_id>`
pub async fn reclaim(
    network: &NetworkConfig,
    api_key: Option<&str>,
    check_id: &str,
    amount: Option<&str>,
) -> Result<()> {
    let key = resolve_wallet_key(api_key)?;
    let api = ApiClient::new(network);

    if let Some(amt) = amount {
        eprintln!("Reclaiming {} from check {}...", amt, check_id);
    } else {
        eprintln!("Reclaiming check {} (full remaining)...", check_id);
    }

    let resp = api.reclaim_payment_check(&key, check_id, amount).await?;

    println!("token:     {}", resp.token);
    println!("reclaimed: {}", resp.amount_reclaimed);
    println!("remaining: {}", resp.remaining);
    println!("time:      {}", resp.reclaimed_at);

    eprintln!("\nFunds returned to your intents balance.");

    Ok(())
}

/// `outlayer checks status <check_id>`
pub async fn status(
    network: &NetworkConfig,
    api_key: Option<&str>,
    check_id: &str,
) -> Result<()> {
    let key = resolve_wallet_key(api_key)?;
    let api = ApiClient::new(network);

    let resp = api.get_payment_check_status(&key, check_id).await?;

    println!("check_id:  {}", resp.check_id);
    println!("status:    {}", resp.status);
    println!("token:     {}", resp.token);
    println!("amount:    {}", resp.amount);
    println!("claimed:   {}", resp.claimed_amount);
    println!("reclaimed: {}", resp.reclaimed_amount);
    if let Some(memo) = &resp.memo {
        println!("memo:      {}", memo);
    }
    println!("created:   {}", resp.created_at);
    if let Some(expires) = &resp.expires_at {
        println!("expires:   {}", expires);
    }
    if let Some(claimed_at) = &resp.claimed_at {
        println!("claimed_at: {}", claimed_at);
    }
    if let Some(claimed_by) = &resp.claimed_by {
        println!("claimed_by: {}", claimed_by);
    }

    Ok(())
}

/// `outlayer checks list`
pub async fn list(
    network: &NetworkConfig,
    api_key: Option<&str>,
    status_filter: Option<&str>,
    limit: i64,
) -> Result<()> {
    let key = resolve_wallet_key(api_key)?;
    let api = ApiClient::new(network);

    let resp = api
        .list_payment_checks(&key, status_filter, limit)
        .await?;

    if resp.checks.is_empty() {
        eprintln!("No payment checks found.");
        return Ok(());
    }

    println!(
        "{:<20} {:<18} {:>12} {:>12} {:<10}",
        "CHECK_ID", "TOKEN", "AMOUNT", "CLAIMED", "STATUS"
    );

    for check in &resp.checks {
        let token_short = if check.token.len() > 16 {
            format!("{}...", &check.token[..14])
        } else {
            check.token.clone()
        };
        println!(
            "{:<20} {:<18} {:>12} {:>12} {:<10}",
            check.check_id, token_short, check.amount, check.claimed_amount, check.status
        );
    }

    Ok(())
}

/// `outlayer checks sign-message <message> <recipient>`
pub async fn sign_message(
    network: &NetworkConfig,
    api_key: Option<&str>,
    message: &str,
    recipient: &str,
    nonce: Option<&str>,
) -> Result<()> {
    let key = resolve_wallet_key(api_key)?;
    let api = ApiClient::new(network);

    eprintln!("Signing message for {}...", recipient);

    let resp = api.sign_message(&key, message, recipient, nonce).await?;

    println!("account_id: {}", resp.account_id);
    println!("public_key: {}", resp.public_key);
    println!("signature:  {}", resp.signature);
    println!("nonce:      {}", resp.nonce);

    Ok(())
}

/// `outlayer checks peek <check_key>`
pub async fn peek(
    network: &NetworkConfig,
    api_key: Option<&str>,
    check_key: &str,
) -> Result<()> {
    let key = resolve_wallet_key(api_key)?;
    let api = ApiClient::new(network);

    let resp = api.peek_payment_check(&key, check_key).await?;

    println!("token:   {}", resp.token);
    println!("balance: {}", resp.balance);
    println!("status:  {}", resp.status);
    if let Some(memo) = &resp.memo {
        println!("memo:    {}", memo);
    }
    if let Some(expires) = &resp.expires_at {
        println!("expires: {}", expires);
    }

    Ok(())
}
