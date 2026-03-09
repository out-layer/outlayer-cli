use anyhow::{Context, Result};
use serde_json::json;

use crate::api::{ApiClient, GetPubkeyRequest};
use crate::config::{self, NetworkConfig};
use crate::crypto;
use crate::near::{NearClient, NearSigner};

/// `outlayer keys create` — create a new payment key
pub async fn create(network: &NetworkConfig) -> Result<()> {
    let creds = config::load_credentials(network)?;
    let private_key = config::load_private_key(&network.network_id, &creds.account_id, &creds)?;

    let near = NearClient::new(network);
    let signer = NearSigner::new(network, &creds.account_id, &private_key)?;
    let api = ApiClient::new(network);

    // Get next nonce
    let nonce = near
        .get_next_payment_key_nonce(&creds.account_id)
        .await
        .context("Failed to get next payment key nonce")?;

    eprintln!("Creating payment key (nonce: {nonce})...");

    // Generate secret
    let secret = crypto::generate_payment_key_secret();

    // Build secrets JSON
    let secrets_json = json!({
        "key": secret,
        "project_ids": [],
        "max_per_call": null,
        "initial_balance": null
    })
    .to_string();

    // Get pubkey for encryption
    let pubkey = api
        .get_secrets_pubkey(&GetPubkeyRequest {
            accessor: json!({ "type": "System", "PaymentKey": {} }),
            owner: creds.account_id.clone(),
            profile: Some(nonce.to_string()),
            secrets_json: secrets_json.clone(),
        })
        .await
        .context("Failed to get keystore pubkey")?;

    // Encrypt
    let encrypted = crypto::encrypt_secrets(&pubkey, &secrets_json)?;

    // Store on contract
    let deposit = 100_000_000_000_000_000_000_000u128; // 0.1 NEAR
    let gas = 100_000_000_000_000u64; // 100 TGas

    signer
        .call_contract(
            "store_secrets",
            json!({
                "accessor": { "System": "PaymentKey" },
                "profile": nonce.to_string(),
                "encrypted_secrets_base64": encrypted,
                "access": "AllowAll"
            }),
            gas,
            deposit,
        )
        .await
        .context("Failed to store payment key")?;

    let api_key = format!("{}:{}:{}", creds.account_id, nonce, secret);

    eprintln!("Payment key created (nonce: {nonce})");
    println!("{api_key}");
    eprintln!("\nSave this key — it cannot be recovered.");
    eprintln!("Top up: outlayer keys topup --nonce {nonce} --amount 1");

    Ok(())
}

/// `outlayer keys list` — list payment keys with balances
pub async fn list(network: &NetworkConfig) -> Result<()> {
    let creds = config::load_credentials(network)?;
    let near = NearClient::new(network);
    let api = ApiClient::new(network);

    // Get all user secrets, filter for System(PaymentKey) entries
    let secrets = near.list_user_secrets(&creds.account_id).await?;

    let payment_keys: Vec<_> = secrets
        .iter()
        .filter(|s| s.accessor.to_string().contains("System"))
        .collect();

    if payment_keys.is_empty() {
        eprintln!("No payment keys. Create one: outlayer keys create");
        return Ok(());
    }

    println!(
        "{:<8} {:>12} {:>12} {:>12}",
        "NONCE", "AVAILABLE", "SPENT", "INITIAL"
    );

    for pk in &payment_keys {
        let nonce: u32 = pk.profile.parse().unwrap_or(0);

        // Try to get balance from coordinator
        match api
            .get_payment_key_balance(&creds.account_id, nonce)
            .await
        {
            Ok(balance) => {
                println!(
                    "{:<8} {:>12} {:>12} {:>12}",
                    nonce,
                    format_usd(&balance.available),
                    format_usd(&balance.spent),
                    format_usd(&balance.initial_balance),
                );
            }
            Err(_) => {
                // Key exists on contract but not yet initialized in coordinator
                println!(
                    "{:<8} {:>12} {:>12} {:>12}",
                    nonce, "---", "---", "---"
                );
            }
        }
    }

    Ok(())
}

/// `outlayer keys balance --nonce N` — check specific key balance
pub async fn balance(network: &NetworkConfig, nonce: u32) -> Result<()> {
    let creds = config::load_credentials(network)?;
    let api = ApiClient::new(network);

    let balance = api
        .get_payment_key_balance(&creds.account_id, nonce)
        .await?;

    println!("Balance:    {}", format_usd(&balance.available));
    println!("Spent:      {}", format_usd(&balance.spent));
    println!("Reserved:   {}", format_usd(&balance.reserved));
    println!("Initial:    {}", format_usd(&balance.initial_balance));
    if let Some(last_used) = &balance.last_used_at {
        println!("Last used:  {last_used}");
    }

    Ok(())
}

/// `outlayer keys topup --nonce N --amount X` — top up with NEAR
pub async fn topup(network: &NetworkConfig, nonce: u32, amount_near: f64) -> Result<()> {
    let creds = config::load_credentials(network)?;
    let private_key = config::load_private_key(&network.network_id, &creds.account_id, &creds)?;

    if network.network_id != "mainnet" {
        anyhow::bail!("Top-up with NEAR is only available on mainnet.");
    }

    // Convert NEAR to yoctoNEAR
    let deposit = (amount_near * 1e24) as u128;
    let min_deposit = 35_000_000_000_000_000_000_000u128; // 0.035 NEAR minimum
    if deposit < min_deposit {
        anyhow::bail!("Minimum top-up is 0.035 NEAR (0.01 deposit + 0.025 execution fees).");
    }

    let signer = NearSigner::new(network, &creds.account_id, &private_key)?;
    let gas = 200_000_000_000_000u64; // 200 TGas (cross-contract calls)

    eprintln!("Topping up key nonce {nonce} with {amount_near} NEAR...");

    signer
        .call_contract(
            "top_up_payment_key_with_near",
            json!({
                "nonce": nonce,
                "swap_contract_id": "intents.near"
            }),
            gas,
            deposit,
        )
        .await
        .context("Top-up failed")?;

    eprintln!("Top-up successful. NEAR will be swapped to USDC via Intents.");
    eprintln!("Check balance: outlayer keys balance --nonce {nonce}");

    Ok(())
}

/// `outlayer keys delete --nonce N` — delete payment key
pub async fn delete(network: &NetworkConfig, nonce: u32) -> Result<()> {
    let creds = config::load_credentials(network)?;
    let private_key = config::load_private_key(&network.network_id, &creds.account_id, &creds)?;

    let signer = NearSigner::new(network, &creds.account_id, &private_key)?;
    let gas = 100_000_000_000_000u64; // 100 TGas

    eprintln!("Deleting payment key nonce {nonce}...");

    signer
        .call_contract(
            "delete_payment_key",
            json!({ "nonce": nonce }),
            gas,
            1, // 1 yoctoNEAR
        )
        .await
        .context("Failed to delete payment key")?;

    eprintln!("Payment key deleted. Storage deposit refunded.");
    Ok(())
}

fn format_usd(minimal_units: &str) -> String {
    let units: u64 = minimal_units.parse().unwrap_or(0);
    let dollars = units as f64 / 1_000_000.0;
    format!("${:.2}", dollars)
}
