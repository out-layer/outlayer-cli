use anyhow::{Context, Result};
use serde_json::json;

use crate::api::{ApiClient, GetPubkeyRequest};
use crate::config::{self, NetworkConfig};
use crate::crypto;
use crate::near::{ContractCaller, NearClient};

/// `outlayer keys create` — create a new payment key
pub async fn create(network: &NetworkConfig) -> Result<()> {
    let creds = config::load_credentials(network)?;

    let near = NearClient::new(network);
    let caller = ContractCaller::from_credentials(&creds, network)?;
    let api = ApiClient::new(network);

    // Get next nonce
    let nonce = near
        .get_next_payment_key_nonce(&creds.account_id)
        .await
        .context("Failed to get next payment key nonce")?;

    eprintln!("Creating payment key (nonce: {nonce})...");

    // Generate secret
    let secret = crypto::generate_payment_key_secret();

    // Build secrets JSON.
    //
    // Every field is a STRING, and `initial_balance` especially. The worker
    // reads this blob when the contract announces the key and requires
    // `initial_balance` to be a string it can parse as a number; a JSON null
    // fails that read, the key is never registered with the coordinator, and
    // what the caller is left holding is a key that exists on chain, is
    // refused by the API, and cannot be topped up — because the top-up reads
    // the same blob. The dashboard writes the same shape, and it must stay the
    // same shape: there is one reader.
    //
    // `max_per_call` of "0" means no limit, which is what an unset limit is.
    let secrets_json = json!({
        "key": secret,
        "project_ids": [],
        "max_per_call": "0",
        "initial_balance": "0"
    })
    .to_string();

    // Get pubkey for encryption
    let pubkey = api
        .get_secrets_pubkey(
            &GetPubkeyRequest {
                accessor: json!({ "type": "System", "PaymentKey": {} }),
                owner: creds.account_id.clone(),
                profile: Some(nonce.to_string()),
                secrets_json: secrets_json.clone(),
            },
            // Payment keys are owner-scoped, never vault-bound — the
            // System(PaymentKey) accessor doesn't take a vault_id.
            None,
        )
        .await
        .context("Failed to get keystore pubkey")?;

    // Encrypt
    let encrypted = crypto::encrypt_secrets(&pubkey, &secrets_json)?;

    let api_key = format!("{}:{}:{}", creds.account_id, nonce, secret);

    // Written down BEFORE the transaction that creates the key.
    //
    // `secret` was generated in this process and exists nowhere else. On chain
    // it goes only as ciphertext the keystore alone can open, and nothing is
    // allowed to hand it back — that is what makes a payment key a credential
    // rather than a stored secret. So the order matters: once `store_secrets`
    // is broadcast the key exists, holds its storage deposit and can be topped
    // up, and a process that dies before it prints anything leaves a key nobody
    // can ever spend. Storing first makes the crash survivable; storing after
    // would only narrow the window.
    let stored_at = config::save_payment_key(&network.network_id, &creds.account_id, nonce, &api_key)
        .context("Refusing to create a payment key that cannot be written down")?;

    // Store on contract
    let deposit = 100_000_000_000_000_000_000_000u128; // 0.1 NEAR
    let gas = 100_000_000_000_000u64; // 100 TGas

    caller
        .call_contract(
            "store_secrets",
            json!({
                "accessor": { "System": "PaymentKey" },
                "profile": nonce.to_string(),
                "encrypted_secrets_base64": encrypted,
                "access": "AllowAll",
                // Payment keys stay on the OutLayer default master
                // (operational data, not custody).
                "vault_id": null,
            }),
            gas,
            deposit,
        )
        .await
        .context("Failed to store payment key")?;

    eprintln!("Payment key created (nonce: {nonce})");
    println!("{api_key}");
    eprintln!(
        "\nSaved to {} (owner-only). Read it back with: outlayer keys show {nonce}",
        stored_at.display()
    );
    // A key with no balance is not yet usable: the API refuses a call it cannot
    // charge. Naming the next step here rather than leaving it to be discovered.
    eprintln!("Add a balance before using it: outlayer keys topup {nonce} --usd 1");

    Ok(())
}

/// `outlayer keys show` — print a payment key this machine created.
///
/// Reads what `create` wrote before it sent the transaction. Only this machine
/// has it: the chain holds ciphertext, and there is no route by which the
/// keystore hands a payment key back — a "recover my key" endpoint would let
/// anyone who can impersonate an owner walk off with a working credential.
///
/// So a key created elsewhere, or created before this stored anything, is gone
/// rather than merely absent, and the message says which of the two it is.
pub fn show(network: &NetworkConfig, nonce: u32) -> Result<()> {
    let creds = config::load_credentials(network)?;

    match config::load_payment_key(&network.network_id, &creds.account_id, nonce) {
        Some(key) => {
            println!("{key}");
            Ok(())
        }
        None => anyhow::bail!(
            "No payment key {}:{} on this machine. It is not recoverable from the chain — \
             the contract holds it encrypted for the keystore and nothing gives it back. \
             If the key still has a balance, withdraw it and create a new key.",
            creds.account_id,
            nonce
        ),
    }
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

/// `outlayer keys balance N` — check specific key balance
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

/// The stablecoin the contract itself settles in.
///
/// Asked of the contract rather than configured here: the two must agree, and
/// only one of them is authoritative. A key topped up in the wrong token would
/// be a transfer the contract never credits.
async fn stablecoin_contract(near: &NearClient) -> Result<String> {
    let token: Option<String> = near
        .view_call("get_payment_token_contract", json!({}))
        .await
        .context("Failed to ask the contract which token it settles in")?;
    token.ok_or_else(|| {
        anyhow::anyhow!("This contract has no payment token set, so a key cannot hold a balance")
    })
}

/// `outlayer keys topup N --usd X` — top up with the stablecoin.
///
/// The second half of creating a usable key, and the only half that works off
/// mainnet: the NEAR route swaps through Intents, which exists on mainnet
/// alone. The transfer carries `top_up_payment_key` in its `msg`, the contract
/// credits the key, and the worker re-encrypts the blob with the new balance —
/// so the balance appears a moment later, not instantly.
pub async fn topup_usd(network: &NetworkConfig, nonce: u32, amount_usd: f64) -> Result<()> {
    let creds = config::load_credentials(network)?;

    if !(amount_usd > 0.0) {
        anyhow::bail!("Top-up amount must be greater than zero");
    }
    // 6 decimals, the stablecoin's own unit. Rounded rather than truncated so
    // "1.23" is not quietly 1.229999.
    let minimal = (amount_usd * 1_000_000.0).round() as u128;

    let near = NearClient::new(network);
    let token = stablecoin_contract(&near).await?;

    let caller = ContractCaller::from_credentials(&creds, network)?;
    eprintln!("Topping up key nonce {nonce} with ${amount_usd} ({token})...");

    caller
        .call_contract_at(
            &token,
            "ft_transfer_call",
            json!({
                "receiver_id": network.contract_id,
                "amount": minimal.to_string(),
                "msg": json!({ "action": "top_up_payment_key", "nonce": nonce }).to_string(),
            }),
            100_000_000_000_000u64, // 100 TGas
            1,                      // 1 yoctoNEAR, as NEP-141 requires
        )
        .await
        .context("Top-up failed")?;

    eprintln!("Top-up sent. The balance appears once the worker has re-encrypted the key.");
    eprintln!("Check balance: outlayer keys balance {nonce}");

    Ok(())
}

/// `outlayer keys topup N X` — top up with NEAR
pub async fn topup(network: &NetworkConfig, nonce: u32, amount_near: f64) -> Result<()> {
    let creds = config::load_credentials(network)?;

    if network.network_id != "mainnet" {
        anyhow::bail!(
            "Top-up with NEAR is only available on mainnet — it swaps through Intents, \
             which has no testnet deployment. Use --usd to send the stablecoin directly."
        );
    }

    // Convert NEAR to yoctoNEAR
    let deposit = (amount_near * 1e24) as u128;
    let min_deposit = 35_000_000_000_000_000_000_000u128; // 0.035 NEAR minimum
    if deposit < min_deposit {
        anyhow::bail!("Minimum top-up is 0.035 NEAR (0.01 deposit + 0.025 execution fees).");
    }

    let caller = ContractCaller::from_credentials(&creds, network)?;
    let gas = 200_000_000_000_000u64; // 200 TGas (cross-contract calls)

    eprintln!("Topping up key nonce {nonce} with {amount_near} NEAR...");

    caller
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
    eprintln!("Check balance: outlayer keys balance {nonce}");

    Ok(())
}

/// `outlayer keys delete N` — delete payment key
pub async fn delete(network: &NetworkConfig, nonce: u32) -> Result<()> {
    let creds = config::load_credentials(network)?;

    let caller = ContractCaller::from_credentials(&creds, network)?;
    let gas = 100_000_000_000_000u64; // 100 TGas

    eprintln!("Deleting payment key nonce {nonce}...");

    caller
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
