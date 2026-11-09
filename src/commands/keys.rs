use anyhow::{Context, Result};
use serde_json::json;

use crate::api::{ApiClient, GetPubkeyRequest};
use crate::config::{self, NetworkConfig};
use crate::crypto;
use crate::near::{ContractCaller, NearClient};

/// `outlayer keys create [--project owner/name]…` — create a new payment key,
/// optionally restricted to the projects named.
pub async fn create(network: &NetworkConfig, projects: &[String]) -> Result<()> {
    for project in projects {
        check_project_scope(project)?;
    }
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
        "project_ids": projects,
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

    // Encrypt. A payment key is a `System` accessor — nothing to normalise, so
    // only the key itself is taken from the answer.
    let encrypted = crypto::encrypt_secrets(&pubkey.pubkey, &secrets_json)?;

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
    if projects.is_empty() {
        eprintln!("It pays for any project.");
    } else {
        eprintln!("It pays only for: {}", projects.join(", "));
    }
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
/// The second half of creating a usable key. The transfer carries
/// `top_up_payment_key` in its `msg`, the contract credits the key, and the
/// worker re-encrypts the blob with the new balance — so the balance appears a
/// moment later, not instantly.
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

    eprintln!("Payment key deleted. Storage deposit refunded; the remaining balance is forfeited (`outlayer keys close` would have refunded it).");
    Ok(())
}

/// The chain's ledger of one key's refund, as `get_payment_key_refund_ledger`
/// answers it. `None` for a key created before the ledger that was never
/// topped up or closed since.
#[derive(Debug, serde::Deserialize)]
struct RefundLedgerView {
    user_funded: String,
    refunded: String,
    refundable_cap: String,
    closing_since: Option<u64>,
    claimable_at: Option<u64>,
}

async fn refund_ledger(near: &NearClient, owner: &str, nonce: u32) -> Result<Option<RefundLedgerView>> {
    near.view_call(
        "get_payment_key_refund_ledger",
        json!({ "owner": owner, "nonce": nonce }),
    )
    .await
    .context("Failed to read the key's refund ledger from the contract")
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// "in 23h 59m" / "now", for a block timestamp in nanoseconds.
fn until(ns: u64) -> String {
    let now = now_ns();
    if ns <= now {
        return "now".to_string();
    }
    let secs = (ns - now) / 1_000_000_000;
    format!("in {}h {:02}m", secs / 3600, (secs % 3600) / 60)
}

/// `outlayer keys close N` — stop a key and start its refund.
///
/// The key takes no more calls or top-ups from here; what it has left is
/// claimed a day later with `keys claim`, once every call in flight on it has
/// settled. The chain pays at most what THIS account deposited on the key
/// after the refund ledger was released, less what it already refunded — the
/// figure printed before the transaction is sent.
pub async fn close(network: &NetworkConfig, nonce: u32) -> Result<()> {
    let creds = config::load_credentials(network)?;
    let near = NearClient::new(network);
    let caller = ContractCaller::from_credentials(&creds, network)?;

    let ledger = refund_ledger(&near, &creds.account_id, nonce).await?;
    if let Some(l) = &ledger {
        if let (Some(_), Some(at)) = (l.closing_since, l.claimable_at) {
            anyhow::bail!(
                "Payment key {nonce} is already closing. Claim its refund with \
                 `outlayer keys claim {nonce}` ({}).",
                until(at)
            );
        }
    }
    let cap = ledger.as_ref().map(|l| l.refundable_cap.as_str()).unwrap_or("0");

    eprintln!("Closing payment key {nonce}.");
    eprintln!("  From now: no new calls, no top-ups. Calls already running settle normally.");
    if cap == "0" {
        eprintln!("  Nothing on this key is refundable on chain: it was funded before refunds existed, or");
        eprintln!("  by a grant. Closing it deletes it; whatever it can still spend is spent through the key.");
    } else {
        eprintln!("  Refundable on chain: {} — what this account deposited on the key since refunds exist, less refunds.", format_usd(cap));
    }
    eprintln!("  Grants, sponsor credit and trial allowance are never refunded.");
    eprintln!("  Do not close while a NEAR top-up of this key is in progress: the swapped stablecoin");
    eprintln!("  would go back to the swap account, not to you.");
    eprintln!("  In 24 hours: `outlayer keys claim {nonce}` pays it out and deletes the key (one claim a day).");

    caller
        .call_contract(
            "close_payment_key",
            json!({ "nonce": nonce }),
            100_000_000_000_000u64, // 100 TGas: the call yields for the coordinator
            1,                      // 1 yoctoNEAR
        )
        .await
        .context("Failed to close the payment key")?;

    match refund_ledger(&near, &creds.account_id, nonce).await? {
        Some(l) if l.closing_since.is_some() => {
            eprintln!(
                "Payment key {nonce} is closing. Claim its refund {}: outlayer keys claim {nonce}",
                l.claimable_at.map(until).unwrap_or_else(|| "in 24 hours".to_string())
            );
        }
        _ => {
            eprintln!(
                "The transaction went through but the key is not marked closing: the coordinator \
                 did not confirm the close in time. The key is still live; run this again."
            );
        }
    }
    Ok(())
}

/// `outlayer keys claim N` — claim a closed key's refund.
///
/// Accepted a day after the close. The worker asks the coordinator what the
/// key has left; the chain pays at most its own cap of it, deletes the key
/// and returns its storage deposit. A coordinator that still has a call of
/// the key in flight refuses, and the key stays closing: claim again later.
pub async fn claim(network: &NetworkConfig, nonce: u32) -> Result<()> {
    let creds = config::load_credentials(network)?;
    let near = NearClient::new(network);
    let caller = ContractCaller::from_credentials(&creds, network)?;

    let before = refund_ledger(&near, &creds.account_id, nonce).await?;
    let Some(ledger) = before.as_ref().filter(|l| l.closing_since.is_some()) else {
        anyhow::bail!(
            "Payment key {nonce} is not closing. Close it first: outlayer keys close {nonce}"
        );
    };
    if let Some(at) = ledger.claimable_at {
        if at > now_ns() {
            anyhow::bail!(
                "Payment key {nonce} closed too recently: its refund can be claimed {}.",
                until(at)
            );
        }
    }

    eprintln!("Claiming the refund of payment key {nonce}.");
    eprintln!(
        "  Refundable on chain: at most {} (deposited {}, refunded {}).",
        format_usd(&ledger.refundable_cap),
        format_usd(&ledger.user_funded),
        format_usd(&ledger.refunded)
    );
    eprintln!("  The key is deleted and its storage deposit returned; its nonce is not reused.");

    let result = caller
        .call_contract(
            "claim_payment_key_refund",
            json!({ "nonce": nonce }),
            100_000_000_000_000u64, // 100 TGas: the call yields for the coordinator
            1,                      // 1 yoctoNEAR
        )
        .await
        .context("Failed to claim the refund")?;

    let paid = result
        .value
        .as_ref()
        .and_then(|v| v.as_str())
        .unwrap_or("0")
        .to_string();

    if paid != "0" {
        eprintln!("Refunded {} to {}. Payment key {nonce} is deleted.", format_usd(&paid), creds.account_id);
        return Ok(());
    }
    match refund_ledger(&near, &creds.account_id, nonce).await? {
        Some(l) if l.closing_since.is_some() => {
            eprintln!(
                "Nothing was paid and the key stays closing: the coordinator still has money of this \
                 key in flight, or did not answer in time. Claim again tomorrow: outlayer keys claim {nonce}"
            );
        }
        _ => {
            eprintln!(
                "Payment key {nonce} is deleted; nothing was refundable on chain (deposits made before \
                 refunds existed, grants and trial credit are spent through the key, not returned)."
            );
        }
    }
    Ok(())
}

fn format_usd(minimal_units: &str) -> String {
    let units: u64 = minimal_units.parse().unwrap_or(0);
    let dollars = units as f64 / 1_000_000.0;
    format!("${:.2}", dollars)
}

/// A scope the coordinator matches: `owner/name` exactly, or `owner/*` for
/// every project of one owner. Anything else would be stored and then match
/// nothing, leaving a key that pays for no project at all.
fn check_project_scope(project: &str) -> Result<()> {
    let (owner, name) = project
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("--project {project:?}: expected owner/name, for example alice.near/my-app"))?;
    if owner.is_empty() || name.is_empty() || name.contains('/') || owner.contains(char::is_whitespace) || name.contains(char::is_whitespace) {
        anyhow::bail!("--project {project:?}: expected owner/name, or owner/* for every project of one owner");
    }
    if name.contains('*') && name != "*" {
        anyhow::bail!("--project {project:?}: `*` stands for a whole project name only (owner/*), not a prefix");
    }
    Ok(())
}

#[cfg(test)]
mod project_scope_tests {
    use super::check_project_scope;

    #[test]
    fn a_scope_is_owner_slash_name_or_owner_slash_star() {
        assert!(check_project_scope("zavodil2.testnet/compliance-gateway").is_ok());
        assert!(check_project_scope("alice.near/*").is_ok());
        for bad in ["compliance-gateway", "/app", "alice.near/", "a/b/c", "alice.near/app*", "alice near/app"] {
            assert!(check_project_scope(bad).is_err(), "{bad} must be refused");
        }
    }
}
