//! `outlayer vault` — per-customer sovereign vault management.
//!
//! Subcommands:
//!   * `init`                          — atomic deploy + verify + customer/register
//!   * `status <account>`              — display vault state
//!   * `verify <account>`              — end-user verification (`is_vault_verified` + checks)
//!   * `initiate-recovery <account>`   — cessation-triggered (DAO must be ceased)
//!   * `initiate-unilateral-recovery <account>`
//!   * `finalize-recovery <account>`
//!   * `set-exit-window <account> <window>`
//!   * `unlocked-add-key <account> <pubkey> [--full-access]`
//!
//! Plan reference: partitioned-dreaming-patterson.md lines 642-677.

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::json;

use crate::config::{self, NetworkConfig};
use crate::near::{AccessKeyPerm, ContractCaller, NearClient};

// ─── Wire types (mirror vault-contract DTOs) ──────────────────────────────
//
// `near_primitives::types::AccountId` and `near_crypto::PublicKey` JSON-
// serialize as strings, so plain `String` round-trips fine here. The CLI
// crate is published independently of `near-offshore` so we cannot pull
// the real `VaultState` types in.

#[derive(Debug, Deserialize)]
pub struct VaultStateView {
    pub parent: String,
    pub keystore_dao: String,
    pub mpc_contract: String,
    /// Initial TEE function-call key pinned at deploy. `None` only
    /// for vaults deployed against the pre-key-swap WASM hash.
    #[serde(default)]
    pub initial_tee_key: Option<String>,
    pub registered_tee_keys: Vec<String>,
    pub recovery: Option<RecoveryStateView>,
    pub unlocked: bool,
    pub unilateral_exit_window_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct RecoveryStateView {
    pub initiated_at: u64,
    pub finalize_after: u64,
    pub finalize_before: u64,
    pub trigger: RecoveryTriggerView,
}

#[derive(Debug, Deserialize)]
pub enum RecoveryTriggerView {
    Cessation,
    Unilateral,
}

// ─── init ──────────────────────────────────────────────────────────────────

/// Initial balance transferred to the new vault account at deploy time.
/// Sized to cover (a) the WASM storage stake and (b) a gas reserve for
/// the vault's outbound MPC `request_app_private_key` calls.
///
/// With NEP-591 `UseGlobalContract` the WASM bytes (~150 KB) live in
/// the global registry, not on this account. Measured on a fresh
/// testnet deploy: `storage_usage = 391 bytes` → ~0.004 NEAR storage
/// stake. Each outbound `request_master → mpc.request_app_private_key`
/// burns ~0.001 NEAR gas (the deposit is 1 yocto), and the master is
/// cached in keystore-worker enclave memory after the first call, so
/// most vaults trigger MPC only a handful of times in their lifetime.
///
/// 0.1 NEAR ≈ 0.004 storage + ~100 MPC-calls headroom with 10× safety
/// margin on storage growth (registered_tee_keys, recovery state).
/// High-frequency derivers can top up; the parent-budget check below
/// prevents getting stuck mid-flow.
///
/// Must match `dashboard/lib/vault.ts::VAULT_INITIAL_YOCTO`.
const VAULT_INITIAL_NEAR: u128 = 100_000_000_000_000_000_000_000; // 0.1 NEAR (yocto)

/// Conservative budget for the parent's signing key — must cover the
/// transfer (`VAULT_INITIAL_NEAR`) plus the deploy tx's gas (~0.05 NEAR
/// at typical mainnet gas prices for a 5-action atomic, ~150KB WASM).
/// Used by the pre-flight balance check.
const VAULT_PARENT_BUDGET_NEAR: u128 = VAULT_INITIAL_NEAR + 100_000_000_000_000_000_000_000; // +0.1 NEAR gas headroom

/// Gas for the inline `new()` call inside the atomic deploy. `new` is
/// pure constructor-style logic (writes 4 fields, no cross-contract
/// calls), so 30 TGas is generous; we leave room for future code-hash
/// whitelist checks if the contract grows.
const VAULT_NEW_GAS: u64 = 30_000_000_000_000;

pub async fn init(
    network: &NetworkConfig,
    name: &str,
    parent: Option<String>,
    exit_window: &str,
    webhook_url: Option<&str>,
) -> Result<()> {
    // ─── 0. Parse + validate inputs up front ────────────────────────────
    let exit_window_secs = parse_exit_window(exit_window)?;
    if name.is_empty() || name.contains('.') {
        anyhow::bail!(
            "--name must be a single sub-account label (got '{name}'). \
             E.g. 'vault' produces 'vault.<your-account>.near'"
        );
    }

    let creds = config::load_credentials(network)
        .with_context(|| "`outlayer vault init` requires a logged-in NEAR account")?;
    if creds.is_wallet_key() {
        anyhow::bail!(
            "`outlayer vault init` requires a NEAR full-access key \
             (custody-wallet auth not supported — the parent NEAR account itself signs \
             the atomic deploy). Re-login with `outlayer login {}`.",
            network.network_id
        );
    }

    // The `parent` field on the vault is immutable post-deploy and is
    // the ONLY account that can call `unilateral_initiate_recovery`,
    // `set_exit_window`, or `unlocked_add_key`. A typo here silently
    // bricks recovery for the vault's lifetime. Refuse a parent that
    // doesn't match the logged-in signer unless the user explicitly
    // sets it (`--parent` was passed at all).
    let parent_account = match parent {
        Some(p) if p != creds.account_id => {
            anyhow::bail!(
                "--parent {} does not match the logged-in account {}. \
                 The parent is immutable post-deploy and is the ONLY account that \
                 can recover this vault — a typo here is unrecoverable. \
                 If you really mean to deploy with a different parent, log in as \
                 that account first (so its private key signs the deploy and \
                 controls recovery).",
                p, creds.account_id
            );
        }
        Some(p) => p,
        None => creds.account_id.clone(),
    };
    let vault_account_id = format!("{name}.{parent_account}");

    eprintln!("Vault deploy plan:");
    eprintln!("  parent:        {parent_account}");
    eprintln!("  vault account: {vault_account_id}");
    eprintln!("  exit window:   {} ({}s)", format_seconds_human(exit_window_secs), exit_window_secs);
    eprintln!(
        "  initial:       {} yoctoNEAR (~{:.2} NEAR)",
        VAULT_INITIAL_NEAR,
        VAULT_INITIAL_NEAR as f64 / 1e24,
    );
    eprintln!();

    let near = NearClient::new(network);
    let api = crate::api::ApiClient::new(network);

    // ─── 0a. Vault sub-account must NOT already exist ───────────────────
    //
    // CreateAccount inside the atomic tx fails if the account exists,
    // which reverts the whole 5-action sequence. We surface this as a
    // clean error pre-flight; if an init crashed mid-flow on a previous
    // run leaving the vault deployed but unregistered, the recovery is
    // `outlayer vault resume <account>`, not a fresh init.
    let existing = near
        .view_account_info(&vault_account_id)
        .await
        .with_context(|| format!("failed to probe {vault_account_id}"))?;
    if existing.exists {
        anyhow::bail!(
            "Account {vault_account_id} already exists (balance {} yoctoNEAR). \
             If a previous init crashed before /customer/register completed, \
             use `outlayer vault resume {vault_account_id}` to finish registration. \
             Otherwise pick a different --name.",
            existing.amount_yocto
        );
    }

    // ─── 0b. Parent must have enough NEAR for the atomic deploy ─────────
    //
    // The atomic tx transfers `VAULT_INITIAL_NEAR` and burns ~0.05 NEAR
    // gas; if the parent's balance is short, the tx reverts after
    // signing — at which point the customer has paid block-inclusion
    // gas for nothing. Cheap to RPC-probe up front.
    let parent_info = near
        .view_account_info(&parent_account)
        .await
        .with_context(|| format!("failed to probe parent account {parent_account}"))?;
    if !parent_info.exists {
        anyhow::bail!(
            "Parent account {parent_account} does not exist on {} — \
             cannot deploy a sub-account from a non-existent parent.",
            network.network_id
        );
    }
    if parent_info.amount_yocto < VAULT_PARENT_BUDGET_NEAR {
        anyhow::bail!(
            "Parent account {parent_account} has only {} yoctoNEAR (~{:.3} NEAR); \
             vault deploy needs at least {} yoctoNEAR (~{:.3} NEAR) — \
             {} for vault.transfer + ~0.1 NEAR gas headroom. \
             Top up the parent and retry.",
            parent_info.amount_yocto,
            parent_info.amount_yocto as f64 / 1e24,
            VAULT_PARENT_BUDGET_NEAR,
            VAULT_PARENT_BUDGET_NEAR as f64 / 1e24,
            VAULT_INITIAL_NEAR,
        );
    }

    // ─── 1. Resolve the vault WASM hash from keystore-DAO ────────────────
    //
    // CLI doesn't ship the WASM bytes — UseGlobalContract by hash
    // means the bytes already live in NEAR's global-contract
    // registry; we just need a 32-byte hash to reference them.
    //
    // Authoritative source for which hash to use = keystore-DAO's
    // `list_approved_vault_versions` view-call. We pick the most
    // recently approved non-deprecated entry. This eliminates the
    // need to bake the hash into the CLI binary or sync it from
    // configs — when the DAO whitelists a new version (and
    // optionally deprecates the old one), every CLI user picks it up
    // on their next deploy without an upgrade. No env override exists
    // by design: every deploy MUST go through the DAO whitelist.
    eprintln!("[1/6] Resolving vault code hash from {}...", network.keystore_dao_id);
    let code_hash_b58 = resolve_vault_code_hash(&near, &network.keystore_dao_id).await?;
    eprintln!("      Using approved vault code hash: {code_hash_b58}");

    // ─── 2. Get the deterministic TEE pubkey BEFORE deploy ──────────────
    //
    // The vault's only initial access key is the TEE function-call key.
    // We need the public key to drop into the AddKey action of the same
    // atomic transaction; the keystore derives it deterministically from
    // (master_secret, vault_id) so we can call this any time.
    eprintln!("[2/6] Fetching TEE function-call pubkey for {vault_account_id}...");
    let tee_pubkey_str = api
        .derive_vault_tee_key(&vault_account_id)
        .await
        .context("Failed to derive TEE pubkey from coordinator")?;
    eprintln!("      TEE pubkey: {tee_pubkey_str}");
    let tee_pubkey: near_crypto::PublicKey = tee_pubkey_str
        .parse()
        .with_context(|| format!("coordinator returned malformed TEE pubkey '{tee_pubkey_str}'"))?;

    // ─── 3. Atomic deploy — single signed tx, all-or-nothing ────────────
    //
    // The deploy uses NEP-591 `UseGlobalContract`: the WASM lives in
    // NEAR's global-contract registry under sha256(WASM). We send the
    // hash, not the bytes — tx payload drops from ~150 KB to a couple
    // hundred bytes. The hash MUST already be deployed via
    // `near contract deploy-as-global ... as-global-hash` (operator
    // step, once per WASM version).
    eprintln!("[3/6] Building atomic-deploy tx (5 actions, UseGlobalContract by hash)...");
    let signer = match ContractCaller::from_credentials(&creds, network)? {
        ContractCaller::Local(s) => s,
        ContractCaller::Wallet { .. } => unreachable!("wallet auth refused above"),
    };
    let vault_account: near_primitives::types::AccountId = vault_account_id
        .parse()
        .with_context(|| format!("'{vault_account_id}' is not a valid NEAR account id"))?;
    let mpc_contract: near_primitives::types::AccountId = network
        .mpc_contract_id
        .parse()
        .with_context(|| format!("invalid mpc_contract_id '{}'", network.mpc_contract_id))?;
    // Stash the TEE pubkey inside the contract state via `new()` so
    // a future `finalize_recovery` can atomically delete it as part
    // of the sovereign key-swap. The same pubkey is also installed
    // by the AddKey action below in the same atomic tx — they MUST
    // match. JSON-encoded as `ed25519:<base58>` which is what
    // near-sdk's `PublicKey` deserialiser expects.
    let new_args = json!({
        "parent": parent_account,
        "keystore_dao": network.keystore_dao_id,
        "mpc_contract": network.mpc_contract_id,
        "initial_tee_pubkey": tee_pubkey.to_string(),
        "initial_exit_window": exit_window_secs,
    });
    // Decode the b58 hash we already validated in step 1 into raw
    // 32 bytes for the UseGlobalContract action.
    let vault_code_hash = base58_decode_32(&code_hash_b58)?;

    eprintln!("      Broadcasting (CreateAccount + Transfer + UseGlobalContract + new() + AddKey atomically)...");
    let outcome = signer
        .atomic_deploy_vault(
            &vault_account,
            VAULT_INITIAL_NEAR,
            vault_code_hash,
            new_args,
            VAULT_NEW_GAS,
            tee_pubkey,
            &mpc_contract,
        )
        .await
        .context("atomic-deploy transaction failed")?;
    let tx_id = outcome.transaction_outcome.id.to_string();
    eprintln!("      Tx hash: {tx_id}");
    if let near_primitives::views::FinalExecutionStatus::Failure(err) = &outcome.status {
        anyhow::bail!(
            "atomic deploy reverted (tx: {tx_id}): {:?} — vault account state is rolled back, retry safely.",
            err
        );
    }

    // The CLI's broadcast_tx_commit waits for the *parent's* RPC node to
    // confirm finality, but the coordinator's keystore-worker queries a
    // different node — usually one or two blocks behind. Without this
    // poll, step 4 reliably races finality and surfaces a scary
    // "UNKNOWN_ACCOUNT, vault does not exist" error, even though resume
    // works. Wait until the keystore-worker's RPC can also see the new
    // vault account before triggering verification.
    await_vault_visible(&near, &vault_account_id, &code_hash_b58).await?;

    // ─── 4. Drive vault-checker → mark_vault_verified on chain ──────────
    eprintln!("[4/5] Triggering keystore re-verification (mark_vault_verified)...");
    let verify_resp = match api.sign_vault_verification(&vault_account_id).await {
        Ok(v) => v,
        Err(e) => {
            anyhow::bail!(
                "verification call failed — the vault account is deployed but \
                 NOT yet verified on chain. Retry with:\n\n    \
                 outlayer vault resume {}\n\n\
                 (it picks up at step 4 idempotently). Underlying error: {:#}",
                vault_account_id, e
            );
        }
    };
    if verify_resp.already_verified {
        eprintln!("      Vault was already verified on chain (idempotent re-run).");
    } else if let Some(h) = &verify_resp.tx_hash {
        eprintln!("      mark_vault_verified tx: {h}");
    }

    // ─── 5. Done. API keys are minted separately on demand ──────────────
    //
    // Vault deploy stops here: the vault contract is on chain, the
    // keystore-DAO has flipped `is_vault_verified == true`, and the
    // per-customer master is reachable via MPC CKD. Custody API keys
    // (`wk_...`) are NOT issued by `vault init` — they're minted on
    // demand via `POST /register {"vault_id": ...}`, which can be
    // called any number of times (N wallets per vault are supported).
    // This keeps `vault init` honest about what a vault actually is:
    // a master-secret root, not a wallet.
    if webhook_url.is_some() {
        eprintln!();
        eprintln!("Note: --webhook-url is ignored without a custody wallet bound to the vault.");
        eprintln!("      Pass it when minting an API key instead (POST /register).");
    }
    eprintln!("[5/5] Done.");
    eprintln!();
    eprintln!("Vault deployed and verified:");
    eprintln!("  vault: {vault_account_id}");
    eprintln!();
    eprintln!("To mint a custody API key for this vault (run any number of times \
        for separate wallets, e.g. one per agent):");
    eprintln!();
    eprintln!(
        "  curl -s -X POST {}/register \\\n    -H 'Content-Type: application/json' \\\n    -d '{{\"vault_id\":\"{vault_account_id}\"}}'",
        network.api_base_url,
    );
    eprintln!();
    eprintln!("Inspect:  outlayer vault status {vault_account_id}");
    eprintln!("Verify:   outlayer vault verify  {vault_account_id}");

    Ok(())
}

/// `outlayer vault resume <account>` — re-run sign-verification on a
/// vault whose atomic deploy landed but whose `mark_vault_verified`
/// keystore call never did (e.g. the customer ^C'd between steps 3
/// and 4, or the keystore was briefly unreachable).
///
/// Idempotent end-to-end: keystore returns `already_verified = true`
/// when the on-chain flag is already set, so re-running this against
/// an already-verified vault is a cheap no-op confirmation.
///
/// Does NOT mint a custody API key. After `vault init` was decoupled
/// from `/customer/register`, the key-minting step is an entirely
/// separate user action (`POST /register {"vault_id": ...}`, N keys
/// per vault allowed). Resume's only job is to nudge the on-chain
/// `is_vault_verified` flag if for some reason it didn't land.
pub async fn resume(network: &NetworkConfig, account: &str) -> Result<()> {
    let near = NearClient::new(network);
    let api = crate::api::ApiClient::new(network);

    eprintln!("Resuming vault init for: {account}");

    // Pre-flight: the vault must actually exist.
    let info = near
        .view_account_info(account)
        .await
        .with_context(|| format!("failed to probe {account}"))?;
    if !info.exists {
        anyhow::bail!(
            "Cannot resume — vault account {account} does NOT exist. \
             A `vault init` whose atomic-deploy tx never landed leaves no on-chain \
             state, so just re-run `outlayer vault init` from scratch."
        );
    }

    eprintln!("[1/1] Triggering keystore re-verification (mark_vault_verified)...");
    let verify_resp = api
        .sign_vault_verification(account)
        .await
        .with_context(|| "verification call failed during resume")?;
    if verify_resp.already_verified {
        eprintln!("      Vault was already verified on chain (idempotent re-run).");
    } else if let Some(h) = &verify_resp.tx_hash {
        eprintln!("      mark_vault_verified tx: {h}");
    }

    eprintln!();
    eprintln!("Vault: {account}");
    eprintln!();
    eprintln!("To mint a custody API key for this vault:");
    eprintln!();
    eprintln!(
        "  curl -s -X POST {}/register \\\n    -H 'Content-Type: application/json' \\\n    -d '{{\"vault_id\":\"{account}\"}}'",
        network.api_base_url,
    );
    Ok(())
}

/// Approval metadata returned by `keystore-dao.list_approved_vault_versions`.
/// Mirrors `keystore-dao-contract::VaultVersionInfo`; only the fields
/// CLI actually reads are deserialised.
#[derive(Debug, Deserialize)]
struct VaultVersionInfo {
    label: String,
    deprecated: bool,
    approved_at: u64,
}

/// Resolve which vault code hash to deploy against. Reads from
/// `keystore-DAO.list_approved_vault_versions()` and picks the most
/// recently approved non-deprecated entry. No env-var override, no
/// config bake-in — the DAO is the single source of truth.
async fn resolve_vault_code_hash(near: &NearClient, dao_id: &str) -> Result<String> {
    let versions: Vec<(String, VaultVersionInfo)> = near
        .view_call_on(dao_id, "list_approved_vault_versions", json!({}))
        .await
        .with_context(|| {
            format!("list_approved_vault_versions view-call failed on {dao_id}")
        })?;

    let mut candidate: Option<(String, VaultVersionInfo)> = None;
    for (hash, info) in versions {
        if info.deprecated {
            continue;
        }
        // Pick the most recently approved non-deprecated entry.
        if candidate
            .as_ref()
            .map_or(true, |(_, prev)| info.approved_at > prev.approved_at)
        {
            candidate = Some((hash, info));
        }
    }
    let (hash, info) = candidate.ok_or_else(|| {
        anyhow::anyhow!(
            "{dao_id} has no non-deprecated approved vault code hash. \
             Operator must publish a vault WASM as a global contract \
             (`near contract deploy-as-global ... as-global-hash`) and \
             approve the resulting hash via `approve_vault_version`."
        )
    })?;
    eprintln!(
        "      → label=\"{}\", approved_at_ns={}",
        info.label, info.approved_at
    );
    Ok(hash)
}

/// Decode a `Base58CryptoHash`-form WASM hash (as stored on the
/// keystore-DAO whitelist) into the raw 32 bytes required by the
/// `UseGlobalContract` action's `CodeHash` variant. Returns an error
/// if the input doesn't decode to exactly 32 bytes — protects against
/// a typo'd or wrong-length value reaching the network.
fn base58_decode_32(b58: &str) -> Result<[u8; 32]> {
    let raw = bs58::decode(b58)
        .into_vec()
        .with_context(|| format!("vault code hash '{b58}' is not valid base58"))?;
    if raw.len() != 32 {
        anyhow::bail!(
            "vault code hash '{b58}' decoded to {} bytes; expected 32 (sha256)",
            raw.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Poll the RPC until the freshly-deployed vault account is visible at
/// final finality with a contract attached (local or NEP-591 global).
///
/// `broadcast_tx_commit` returns once the parent's RPC node sees the tx
/// at final finality, but the coordinator's keystore-worker uses a
/// different node which is sometimes one or two blocks behind. Without
/// this poll, step 4's `/customer/sign-verification` reliably races and
/// returns `UNKNOWN_ACCOUNT`, even though the resume path works.
///
/// Times out after ~30 s — well beyond any normal finality propagation
/// window. On timeout we surface a clear resume hint so the customer
/// isn't stuck guessing whether the tx itself failed.
///
/// `expected_global_hash`: the base58 code hash we passed to the
/// `UseGlobalContract` action in step 3. The poll only returns success
/// once the RPC sees this exact hash bound to the account — guards
/// against the (extremely unlikely) failure mode where the global
/// registry's pointer drifted or the account was already running a
/// different global contract from a stale CreateAccount-then-deploy
/// flow (caller's pre-flight rejects existing accounts, but the
/// equality check costs nothing and surfaces the mismatch loudly).
async fn await_vault_visible(
    near: &NearClient,
    vault_account_id: &str,
    expected_global_hash: &str,
) -> Result<()> {
    use std::time::{Duration, Instant};
    let started = Instant::now();
    let timeout = Duration::from_secs(30);
    let interval = Duration::from_secs(1);
    // Rustc thinks the initial assignment is dead because the first
    // iteration always overwrites before the timeout branch can read it
    // — true but harmless; we want a meaningful value if Instant::now()
    // somehow already exceeds the timeout on entry.
    #[allow(unused_assignments)]
    let mut last_err: String = "no probe ran".into();
    eprintln!("      Waiting for vault to be visible at final finality...");
    loop {
        match near.view_account_info(vault_account_id).await {
            Ok(info) if info.exists => {
                match info.effective_code_hash() {
                    Some(h) if h == expected_global_hash => return Ok(()),
                    Some(h) => {
                        // Authoritative mismatch — bail immediately;
                        // retrying won't fix a globally-different
                        // contract code on a fresh account.
                        anyhow::bail!(
                            "vault account {vault_account_id} is on chain but its \
                             code hash {h} ≠ requested {expected_global_hash}. \
                             This shouldn't happen with a clean atomic deploy; \
                             inspect the tx receipts before continuing."
                        );
                    }
                    None => {
                        last_err = "account exists but no contract attached yet".into();
                    }
                }
            }
            Ok(_) => {
                last_err = "account not yet visible".into();
            }
            Err(e) => {
                last_err = format!("{e:#}");
            }
        }
        if started.elapsed() >= timeout {
            anyhow::bail!(
                "vault account {vault_account_id} did not reach final finality \
                 within {}s; the atomic deploy may still be propagating. \
                 Resume idempotently with:\n\n    \
                 outlayer vault resume {vault_account_id}\n\n\
                 (last probe: {last_err})",
                timeout.as_secs(),
            );
        }
        tokio::time::sleep(interval).await;
    }
}

// ─── status / verify (read-only) ──────────────────────────────────────────

/// `outlayer vault status <account>` — display current vault state.
///
/// Single view-call to `<vault>.get_state()`; no DAO trust check. For
/// the verification check use `outlayer vault verify` instead.
pub async fn status(network: &NetworkConfig, account: &str) -> Result<()> {
    let near = NearClient::new(network);
    let state = fetch_vault_state(&near, account).await?;
    println!("Vault:           {account}");
    println!("Parent:          {}", state.parent);
    println!("Keystore-DAO:    {}", state.keystore_dao);
    println!("MPC contract:    {}", state.mpc_contract);
    println!(
        "Status:          {}",
        if state.unlocked { "UNLOCKED (recovered)" } else { "locked (TEE-controlled)" },
    );
    println!(
        "Exit window:     {}",
        format_seconds_human(state.unilateral_exit_window_secs),
    );
    match &state.initial_tee_key {
        Some(k) => println!("Initial TEE key: {k}"),
        None => println!("Initial TEE key: (none — pre-launch test vault)"),
    }
    println!(
        "Registered TEE keys (DAO-rotated): {}",
        state.registered_tee_keys.len()
    );
    for k in &state.registered_tee_keys {
        println!("  • {k}");
    }
    if let Some(rec) = &state.recovery {
        let trigger = match rec.trigger {
            RecoveryTriggerView::Cessation => "cessation",
            RecoveryTriggerView::Unilateral => "unilateral",
        };
        println!();
        println!("Recovery in progress ({trigger}):");
        println!("  initiated_at    {} (ns)", rec.initiated_at);
        println!("  finalize_after  {} (ns)", rec.finalize_after);
        println!("  finalize_before {} (ns)", rec.finalize_before);
    } else {
        println!("Recovery:        none in progress");
    }
    Ok(())
}

/// `outlayer vault verify <account>` — end-user verification.
///
/// Trust signal #1: `keystore-dao.is_vault_verified(account)` — the
/// canonical "this vault was checked by an attested TEE" flag. Vaults
/// failing this should not be trusted regardless of the other checks.
///
/// Defense-in-depth checks (informational; failures are flagged but do
/// not flip the trust signal): code hash matches an approved
/// vault-contract WASM, vault has registered TEE keys, vault is not
/// unlocked, and the on-chain access keys are bounded and TEE-only.
pub async fn verify(network: &NetworkConfig, account: &str) -> Result<()> {
    let near = NearClient::new(network);

    println!("Verifying vault: {account}");
    println!("(network: {})", network.network_id);
    println!();

    let mut warnings: Vec<String> = Vec::new();

    // 0. Existence check. Without this the chain of view-calls below
    //    surfaces UnknownAccount as opaque RPC errors deep in step 2.
    let info = near
        .view_account_info(account)
        .await
        .with_context(|| format!("failed to probe {account}"))?;
    if !info.exists {
        println!("Vault account {account} does NOT exist on {}.", network.network_id);
        println!();
        println!("Result: NOT VERIFIED — no contract deployed.");
        return Ok(());
    }

    // 1. Primary trust signal — keystore-DAO `is_vault_verified`.
    let is_verified: bool = near
        .view_call_on(
            &network.keystore_dao_id,
            "is_vault_verified",
            json!({ "vault_id": account }),
        )
        .await
        .with_context(|| {
            format!(
                "is_vault_verified view-call failed on {} — vault may not exist",
                network.keystore_dao_id
            )
        })?;
    println!(
        "[1/5] keystore-dao.is_vault_verified : {}",
        if is_verified { "TRUE  (verified)" } else { "FALSE (not verified — do NOT trust)" },
    );
    if !is_verified {
        warnings.push("vault is NOT in keystore-dao.verified_vaults".into());
    }

    // 2. Code hash must match an approved vault-contract WASM.
    //    The "effective" hash is `global_contract_hash` when the vault
    //    was deployed via NEP-591 `UseGlobalContract` (which is the
    //    flow `outlayer vault init` uses), else the LOCAL `code_hash`.
    let acct = near
        .view_account_info(account)
        .await
        .with_context(|| format!("failed to fetch account info for {account}"))?;
    match acct.effective_code_hash() {
        None => {
            warnings.push(format!("no contract deployed at {account}"));
            println!("[2/5] code hash                       : NONE (no contract deployed)");
        }
        Some(hash) => {
            let kind = if acct.global_contract_hash.is_some() {
                "global"
            } else {
                "local"
            };
            let approved: bool = near
                .view_call_on(
                    &network.keystore_dao_id,
                    "is_vault_code_approved",
                    json!({ "hash": hash }),
                )
                .await
                .with_context(|| "is_vault_code_approved view-call failed".to_string())?;
            println!(
                "[2/5] vault code hash ({kind})  : {hash}  {}",
                if approved { "APPROVED" } else { "NOT APPROVED" }
            );
            if !approved {
                warnings.push(format!(
                    "vault code hash {hash} is not in keystore-dao approved set"
                ));
            }
        }
    }

    // 3. Vault contract get_state — pulls parent, MPC, exit window,
    //    registered TEE keys, recovery state.
    let state = match fetch_vault_state(&near, account).await {
        Ok(s) => s,
        Err(e) => {
            println!("[3/5] vault.get_state()               : FAILED ({e})");
            warnings.push(format!("get_state failed: {e}"));
            // Failed get_state means we cannot reason about the vault
            // — force the unsafe headline regardless of DAO flag.
            print_warnings(&warnings, is_verified, false);
            return Ok(());
        }
    };
    println!(
        "[3/5] vault.get_state()               : OK (parent={}, keystore_dao={}, mpc={})",
        state.parent, state.keystore_dao, state.mpc_contract
    );
    if state.keystore_dao != network.keystore_dao_id {
        warnings.push(format!(
            "vault.keystore_dao = {} ≠ network.keystore_dao_id = {}",
            state.keystore_dao, network.keystore_dao_id
        ));
    }
    if state.mpc_contract != network.mpc_contract_id {
        warnings.push(format!(
            "vault.mpc_contract = {} ≠ network.mpc_contract_id = {}",
            state.mpc_contract, network.mpc_contract_id
        ));
    }
    if state.unlocked {
        warnings
            .push("vault is UNLOCKED — parent has post-recovery key authority".into());
    }
    // `registered_tee_keys` is the explicit allow-list of TEE keys added
    // by `propose_tee_key` (keystore-DAO-gated). The INITIAL TEE
    // function-call key installed by `atomic_deploy_vault`'s AddKey
    // action lives only on the access-key list (verified in check #4
    // below), not in this vec, so an empty vec right after `init` is
    // expected. Only flag it once the parent has unlocked the vault
    // — at that point we expect at least one registered key, otherwise
    // there's no path back into the TEE.
    if state.registered_tee_keys.is_empty() && state.unlocked {
        warnings.push("vault is unlocked but has no registered TEE keys".into());
    }
    if let Some(rec) = &state.recovery {
        warnings.push(format!(
            "recovery in progress ({:?}, finalize_after={} ns)",
            rec.trigger, rec.finalize_after
        ));
    }
    println!(
        "      exit window                    : {}",
        format_seconds_human(state.unilateral_exit_window_secs)
    );
    println!(
        "      initial_tee_key                : {}",
        state.initial_tee_key.as_deref().unwrap_or("(none — legacy vault)")
    );
    println!("      registered_tee_keys (rotated)  : {}", state.registered_tee_keys.len());
    println!(
        "      unlocked / recovery            : {} / {}",
        state.unlocked,
        state.recovery.is_some()
    );

    // 4. Access keys must all be function-call keys scoped to MPC's
    //    `request_app_private_key`. Anything else is a red flag —
    //    vault-checker would have rejected the verification.
    let keys = near
        .view_access_key_list(account)
        .await
        .with_context(|| format!("failed to view_access_key_list({account})"))?;
    let mut bad_keys = 0usize;
    for k in &keys {
        match &k.permission {
            AccessKeyPerm::FullAccess => {
                bad_keys += 1;
                warnings
                    .push(format!("vault has a FULL-ACCESS key {} — must not exist", k.public_key));
            }
            AccessKeyPerm::FunctionCall {
                receiver_id,
                method_names,
                allowance,
            } => {
                // The vault has three valid FCAK scopes:
                //
                //   (a) initial TEE key installed by `atomic_deploy_vault`:
                //       receiver = the vault itself,
                //       methods  = ["request_master"].
                //       The keystore-worker calls this proxy because MPC
                //       requires a 1 yocto deposit which a function-call
                //       access key cannot attach directly.
                //
                //   (b) TEE key added via DAO-gated `propose_tee_key`:
                //       receiver = state.mpc_contract,
                //       methods  = ["request_app_private_key"].
                //
                //   (c) post-recovery key the parent installs via
                //       `unlocked_add_key` once `state.unlocked == true`:
                //       receiver = the vault itself, any methods.
                let initial_tee_scope = receiver_id == account
                    && method_names.len() == 1
                    && method_names[0] == "request_master";
                let propose_tee_scope = receiver_id == &state.mpc_contract
                    && method_names.len() == 1
                    && method_names[0] == "request_app_private_key";
                let unlocked_self_call = state.unlocked && receiver_id == account;
                let tee_scope_ok = initial_tee_scope || propose_tee_scope;
                if !tee_scope_ok && !unlocked_self_call {
                    bad_keys += 1;
                    warnings.push(format!(
                        "access key {} has unexpected scope: receiver={}, methods={:?}",
                        k.public_key, receiver_id, method_names
                    ));
                }
                // Defense in depth: TEE function-call keys (both initial
                // and `propose_tee_key`-installed) are added with
                // `Allowance::Unlimited` (None). A limited or zero
                // allowance would silently break the vault's ability
                // to make MPC calls.
                if tee_scope_ok && allowance.is_some() {
                    warnings.push(format!(
                        "TEE access key {} has limited allowance ({:?}); \
                         expected Unlimited (None)",
                        k.public_key, allowance
                    ));
                }
            }
        }
    }
    println!(
        "[4/5] access keys ({})                : {}",
        keys.len(),
        if bad_keys == 0 { "OK".to_string() } else { format!("{bad_keys} unexpected key(s)") }
    );

    // 5. Cross-check: every key in `registered_tee_keys` must also be
    //    present on the account's access-key list. (Reverse direction
    //    would be too strict — propose_tee_key only updates the list
    //    after the AddKey promise resolves; `unlocked_add_key` adds keys
    //    not tracked in `registered_tee_keys` at all.)
    let on_chain: std::collections::HashSet<&str> =
        keys.iter().map(|k| k.public_key.as_str()).collect();
    let missing: Vec<&String> = state
        .registered_tee_keys
        .iter()
        .filter(|k| !on_chain.contains(k.as_str()))
        .collect();
    if missing.is_empty() {
        println!("[5/5] registered_tee_keys ⊆ access keys: OK");
    } else {
        println!(
            "[5/5] registered_tee_keys ⊆ access keys: {} missing",
            missing.len()
        );
        for k in &missing {
            warnings.push(format!(
                "registered TEE key {k} not present on account access-key list"
            ));
        }
    }

    // Track the worst-case shape so the headline reflects user-visible
    // danger, not just the DAO flag (which lags ban events).
    let safe = is_verified && bad_keys == 0 && !state.unlocked;
    print_warnings(&warnings, is_verified, safe);
    Ok(())
}

async fn fetch_vault_state(near: &NearClient, account: &str) -> Result<VaultStateView> {
    near.view_call_on(account, "get_state", json!({}))
        .await
        .with_context(|| format!("failed to call {account}.get_state()"))
}

fn print_warnings(warnings: &[String], is_verified: bool, safe: bool) {
    println!();
    if warnings.is_empty() && safe {
        println!("Result: PASS — vault verified, all defense-in-depth checks OK");
        return;
    }
    // `safe` flips the headline to a hard NOT-SAFE even when the DAO
    // still says verified, to cover the race window where a vault has
    // been tampered (full-access key added, unlocked) but the
    // automated ban hasn't fired yet.
    let headline = if !safe {
        "NOT SAFE — defense-in-depth checks failed (do not deposit funds)"
    } else if !is_verified {
        "NOT VERIFIED — do not deposit funds"
    } else {
        "VERIFIED (with warnings — review below)"
    };
    println!("Result: {headline}");
    for w in warnings {
        println!("  ⚠ {w}");
    }
}

fn format_seconds_human(secs: u64) -> String {
    if secs % 86_400 == 0 && secs >= 86_400 {
        format!("{} day(s) ({secs}s)", secs / 86_400)
    } else if secs % 3600 == 0 && secs >= 3600 {
        format!("{} hour(s) ({secs}s)", secs / 3600)
    } else {
        format!("{secs}s")
    }
}

// ─── recovery flow ────────────────────────────────────────────────────────

// Gas budgets — vault recovery callbacks have an inner cross-contract
// view-call to keystore-DAO (`is_ceased`/`is_keystore_approved`) plus
// the callback itself, so we err on the side of generous static gas.
const GAS_VAULT_RECOVERY: u64 = 100_000_000_000_000; // 100 TGas
/// Higher because `unlocked_add_key` issues a NEAR `AddKey` action via
/// `Promise::new(...).add_access_key_allowance(...)` — promise emission
/// + execution should stay well under this.
const GAS_VAULT_ADD_KEY: u64 = 100_000_000_000_000; // 100 TGas

/// `outlayer vault initiate-recovery <account>` — cessation-triggered
/// recovery. The vault contract itself accepts a permissionless call
/// here (the DAO `is_ceased()` callback is the real authority), but
/// this CLI is the customer-facing entry point and we restrict the
/// signer to the vault's `parent` to keep the UX consistent with the
/// other vault subcommands and to fail fast on the most common user
/// mistake (logged in as the wrong account). A third party who
/// genuinely needs to drive a stalled cessation timer can still call
/// the contract directly with `near-cli`.
pub async fn initiate_recovery(network: &NetworkConfig, account: &str) -> Result<()> {
    let caller = parent_caller(network, account, "initiate-recovery").await?;
    eprintln!("Calling {account}.initiate_recovery() — DAO cessation gate is checked in the callback...");
    let result = caller
        .call_contract_at(account, "initiate_recovery", json!({}), GAS_VAULT_RECOVERY, 0)
        .await
        .context("initiate_recovery failed")?;
    print_tx_hash(&result.tx_hash);
    eprintln!(
        "If the DAO has declared cessation, the 7-day timer is now running. \
         Track progress with `outlayer vault status {account}`."
    );
    Ok(())
}

/// `outlayer vault initiate-unilateral-recovery <account>` — parent-only
/// voluntary recovery. The vault contract checks
/// `env::predecessor_account_id() == self.parent`, so the CLI signer
/// must be the same NEAR account that's set as the vault's `parent`.
pub async fn initiate_unilateral_recovery(network: &NetworkConfig, account: &str) -> Result<()> {
    let caller = parent_caller(network, account, "initiate-unilateral-recovery").await?;
    eprintln!(
        "Calling {account}.unilateral_initiate_recovery() — exit window is captured at this call."
    );
    let result = caller
        .call_contract_at(
            account,
            "unilateral_initiate_recovery",
            json!({}),
            GAS_VAULT_RECOVERY,
            0,
        )
        .await
        .context("unilateral_initiate_recovery failed")?;
    print_tx_hash(&result.tx_hash);
    eprintln!(
        "Unilateral recovery initiated. Run `outlayer vault status {account}` to see \
         finalize_after / finalize_before timestamps."
    );
    Ok(())
}

/// `outlayer vault finalize-recovery <account> <new_parent_pubkey>` —
/// finalizes either Cessation or Unilateral recovery and atomically
/// hands on-chain authority to `new_parent_pubkey`.
///
/// On success the single transaction:
///   1. Sets `unlocked = true` and clears `recovery`.
///   2. Deletes every TEE access key the contract tracks (initial +
///      DAO-registered) so the keystore-worker can no longer sign
///      `vault.request_master`.
///   3. Adds `new_parent_pubkey` as a full-access key — the customer
///      can immediately use it to call `vault.request_master` and
///      recover the per-vault master via MPC (see
///      `scripts/customer-recovery/`).
///
/// The pubkey MUST be controlled by the customer — anyone holding
/// the corresponding private key owns the vault after this call.
/// Generate it locally on a machine the customer trusts; the CLI
/// never exfiltrates it.
///
/// Cessation routes through `keystore_dao.is_ceased()` and resolves
/// asynchronously inside the contract; Unilateral resolves inline.
pub async fn finalize_recovery(
    network: &NetworkConfig,
    account: &str,
    new_parent_pubkey: &str,
) -> Result<()> {
    let parsed_pubkey: near_crypto::PublicKey = new_parent_pubkey
        .parse()
        .with_context(|| format!(
            "invalid new_parent_pubkey '{}' — expected ed25519:<base58> or secp256k1:<base58>",
            new_parent_pubkey
        ))?;
    let pubkey_str = parsed_pubkey.to_string();

    // Pre-flight: the contract's atomic swap inside finalize_recovery
    // first deletes every TEE access key (initial + DAO-registered)
    // then adds `new_parent_pubkey` as FullAccess. NEAR receipts
    // execute actions in order, but if the pubkey we're adding
    // ALREADY exists on the account (e.g. customer pasted the
    // initial TEE pubkey, or accidentally pasted a key the account
    // had from before via `unlocked_add_key`) the AddKey action
    // panics with `AccessKeyAlreadyExists`. State mutation
    // (unlocked=true) is gated behind a post-swap callback now, so
    // a failed swap just leaves the vault in its previous state and
    // the customer can re-try — but catching the collision client-
    // side gives a clearer error than waiting for the chain panic.
    let near = NearClient::new(network);
    let state = fetch_vault_state(&near, account).await?;
    if let Some(ref initial) = state.initial_tee_key {
        if initial == &pubkey_str {
            anyhow::bail!(
                "new_parent_pubkey {pubkey_str} is the same as this vault's initial TEE key. \
                 The contract would try to delete and re-add the same key, which fails on chain. \
                 Generate a FRESH keypair (e.g. `customer-recovery generate-key`)."
            );
        }
    }
    if state.registered_tee_keys.iter().any(|k| k == &pubkey_str) {
        anyhow::bail!(
            "new_parent_pubkey {pubkey_str} is already a registered TEE key on this vault. \
             The contract would delete it during the swap and fail to add it back. \
             Generate a FRESH keypair."
        );
    }
    let existing_keys = near
        .view_access_key_list(account)
        .await
        .with_context(|| format!("failed to read access keys for {account}"))?;
    if existing_keys.iter().any(|k| k.public_key == pubkey_str) {
        anyhow::bail!(
            "new_parent_pubkey {pubkey_str} is already an access key on {account} \
             (probably from a prior `unlocked_add_key` or rotation). The atomic swap \
             would AddKey it again and panic with AccessKeyAlreadyExists. Generate a \
             FRESH keypair."
        );
    }

    let caller = parent_caller(network, account, "finalize-recovery").await?;
    eprintln!(
        "Calling {account}.finalize_recovery({}) — routes by recovery.trigger.",
        parsed_pubkey
    );
    eprintln!(
        "      On success the vault will atomically:\n  \
         - delete all TEE access keys (no more OutLayer signing)\n  \
         - add your pubkey as FullAccess (you own the vault)"
    );
    let result = caller
        .call_contract_at(
            account,
            "finalize_recovery",
            json!({ "new_parent_pubkey": parsed_pubkey.to_string() }),
            GAS_VAULT_RECOVERY,
            0,
        )
        .await
        .context("finalize_recovery failed")?;
    print_tx_hash(&result.tx_hash);
    // Success path returns PromiseOrValue::Promise (key-swap actions
    // carry no return value) — the only synchronous boolean is
    // `false` from the window-expired / DAO-revoked branches. Treat
    // anything that isn't `Some(false)` as success.
    if result.value.as_ref().and_then(|v| v.as_bool()) == Some(false) {
        eprintln!(
            "Result: finalize did NOT unlock (DAO revoked cessation or window expired)"
        );
    } else {
        eprintln!(
            "Result: vault is now UNLOCKED and your key is installed.\n         \
             Recover the per-vault master locally with `customer-recovery` \
             (see scripts/customer-recovery/README.md)."
        );
    }
    eprintln!("Run `outlayer vault status {account}` to confirm.");
    Ok(())
}

/// `outlayer vault set-exit-window <account> <window>` — parent-only.
/// Updates `unilateral_exit_window_secs`. In-flight recoveries are not
/// affected (their finalize timestamps are frozen at initiate time).
pub async fn set_exit_window(
    network: &NetworkConfig,
    account: &str,
    window: &str,
) -> Result<()> {
    let secs = parse_exit_window(window)?;
    let caller = parent_caller(network, account, "set-exit-window").await?;
    eprintln!(
        "Calling {account}.set_exit_window({secs}) (= {})...",
        format_seconds_human(secs)
    );
    let result = caller
        .call_contract_at(
            account,
            "set_exit_window",
            json!({ "new_window_secs": secs }),
            GAS_VAULT_RECOVERY,
            0,
        )
        .await
        .context("set_exit_window failed")?;
    print_tx_hash(&result.tx_hash);
    eprintln!(
        "Exit window updated. Future `unilateral-initiate-recovery` calls will use {}.",
        format_seconds_human(secs)
    );
    Ok(())
}

/// `outlayer vault unlocked-add-key <account> <pubkey> [--full-access]` —
/// parent-only, vault must be unlocked (post-recovery). Default
/// `full_access = false` adds a function-call key with the contract's
/// 1-NEAR allowance default; `--full-access` adds a full-access key.
pub async fn unlocked_add_key(
    network: &NetworkConfig,
    account: &str,
    pubkey: &str,
    full_access: bool,
) -> Result<()> {
    // Reject malformed pubkeys client-side — otherwise the contract
    // panics inside its `PublicKey` deserialise and we lose the gas.
    pubkey.parse::<near_crypto::PublicKey>().with_context(|| {
        format!("'{pubkey}' is not a valid NEAR public key (expected 'ed25519:...' or 'secp256k1:...')")
    })?;
    let caller = parent_caller(network, account, "unlocked-add-key").await?;
    eprintln!(
        "Calling {account}.unlocked_add_key({pubkey}, full_access={full_access})..."
    );
    let result = caller
        .call_contract_at(
            account,
            "unlocked_add_key",
            json!({
                "public_key": pubkey,
                "full_access": full_access,
                // `null` selects the contract's 1-NEAR default allowance.
                "allowance": null,
            }),
            GAS_VAULT_ADD_KEY,
            0,
        )
        .await
        .context("unlocked_add_key failed")?;
    print_tx_hash(&result.tx_hash);
    eprintln!(
        "Key added. Type: {}",
        if full_access { "FULL ACCESS" } else { "function-call (1 NEAR allowance, all vault methods)" }
    );
    Ok(())
}

// ─── shared helpers for recovery commands ────────────────────────────────

/// Build a `ContractCaller` from the logged-in user's credentials.
/// Vault `initiate-unilateral-recovery` / `finalize-recovery` /
/// `set-exit-window` / `unlocked-add-key` all require
/// `predecessor == vault.parent`; this helper enforces it at the CLI
/// layer so the user gets a clear local error instead of a contract
/// panic. We pay one extra RPC view-call to read the vault's
/// `parent` field — cheap (~100ms) given these are once-per-customer
/// operations.
///
/// Refuses wallet-key creds outright (those don't have a NEAR
/// signing key) and refuses when `creds.account_id` doesn't match
/// the vault's parent.
async fn parent_caller(
    network: &NetworkConfig,
    account: &str,
    cmd: &str,
) -> Result<ContractCaller> {
    let creds = config::load_credentials(network)
        .with_context(|| format!("`outlayer vault {cmd}` requires a logged-in NEAR account"))?;
    if creds.is_wallet_key() {
        anyhow::bail!(
            "`outlayer vault {cmd}` requires a NEAR full-access key (custody-wallet auth not supported). \
             Vault recovery must be signed by the parent account directly. \
             Re-login with `outlayer login {}`.",
            network.network_id,
        );
    }
    // Read the vault's parent from chain and reject early if it
    // doesn't match the logged-in account.
    let near = NearClient::new(network);
    let state = fetch_vault_state(&near, account).await.with_context(|| {
        format!(
            "could not read vault state for {account} — does it exist on {}?",
            network.network_id
        )
    })?;
    if state.parent != creds.account_id {
        anyhow::bail!(
            "`outlayer vault {cmd}` must be signed by the vault's parent account.\n  \
             logged-in: {}\n  vault.parent: {}\n\
             Re-login as {} or pass a different vault id.",
            creds.account_id,
            state.parent,
            state.parent,
        );
    }
    eprintln!(
        "Acting as: {} → {}",
        creds.account_id, account,
    );
    ContractCaller::from_credentials(&creds, network)
        .with_context(|| "Failed to load NEAR signer".to_string())
}

fn print_tx_hash(tx_hash: &Option<String>) {
    if let Some(h) = tx_hash {
        eprintln!("Tx hash: {h}");
    }
}

// ─── helpers ──────────────────────────────────────────────────────────────

/// Parse a window string like "24h" / "7d" / "30d" into seconds.
/// Used by both `vault init --exit-window` and `vault set-exit-window`.
/// Bounds (`MIN`/`MAX_UNILATERAL_EXIT_WINDOW_SECS`) are enforced
/// contract-side; this function only handles the textual form.
pub fn parse_exit_window(input: &str) -> Result<u64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        anyhow::bail!("exit window cannot be empty (use '24h', '7d', or '30d')");
    }
    let (num_part, unit) = trimmed.split_at(
        trimmed
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(trimmed.len()),
    );
    if num_part.is_empty() {
        anyhow::bail!(
            "exit window must start with a number (e.g. '24h', '7d', '30d'); got '{}'",
            input
        );
    }
    let n: u64 = num_part
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid number in exit window '{}': {}", input, e))?;
    let secs = match unit {
        "s" | "S" => Some(n),
        "m" | "M" => n.checked_mul(60),
        "h" | "H" => n.checked_mul(3600),
        "d" | "D" => n.checked_mul(86400),
        "" => anyhow::bail!(
            "exit window missing unit suffix; use 's', 'm', 'h', or 'd', e.g. '180s', '3m', '24h', '7d'"
        ),
        other => anyhow::bail!(
            "unknown exit window unit '{}'; use 's', 'm', 'h', or 'd', e.g. '180s', '3m', '24h', '7d'",
            other
        ),
    }
    .ok_or_else(|| anyhow::anyhow!("exit window '{}' overflows u64 seconds", input))?;
    Ok(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_exit_window_basic() {
        assert_eq!(parse_exit_window("24h").unwrap(), 86_400);
        assert_eq!(parse_exit_window("7d").unwrap(), 604_800);
        assert_eq!(parse_exit_window("30d").unwrap(), 2_592_000);
        assert_eq!(parse_exit_window("1H").unwrap(), 3600);
    }

    #[test]
    fn parse_exit_window_rejects_bad() {
        assert!(parse_exit_window("").is_err());
        assert!(parse_exit_window("h").is_err());
        assert!(parse_exit_window("24").is_err());
        assert!(parse_exit_window("24x").is_err());
        assert!(parse_exit_window("abc").is_err());
    }
}
