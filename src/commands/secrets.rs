use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::api::{ApiClient, GetPubkeyRequest};
use crate::config::{self, NetworkConfig, ProjectConfig};
use crate::crypto;
use crate::near::{ContractCaller, NearClient};

// ── Accessor Resolution ──────────────────────────────────────────────

struct ResolvedAccessor {
    /// Internally tagged ({"type":"Project", ...}) — for coordinator API
    coordinator: Value,
    /// Externally tagged ({"Project": {...}}) — for contract
    contract: Value,
}

fn resolve_accessor(
    project: Option<String>,
    repo: Option<String>,
    branch: Option<String>,
    wasm_hash: Option<String>,
    project_config: Option<&ProjectConfig>,
) -> Result<ResolvedAccessor> {
    if let Some(hash) = wasm_hash {
        return Ok(ResolvedAccessor {
            coordinator: json!({"type": "WasmHash", "hash": hash}),
            contract: json!({"WasmHash": {"hash": hash}}),
        });
    }

    if let Some(repo) = repo {
        return Ok(ResolvedAccessor {
            coordinator: json!({"type": "Repo", "repo": repo, "branch": branch}),
            contract: json!({"Repo": {"repo": repo, "branch": branch}}),
        });
    }

    if let Some(project_id) = project {
        return Ok(ResolvedAccessor {
            coordinator: json!({"type": "Project", "project_id": project_id}),
            contract: json!({"Project": {"project_id": project_id}}),
        });
    }

    // Fallback to outlayer.toml
    let config = project_config.context(
        "No accessor specified. Use --project, --repo, or --wasm-hash \
         (or run from a directory with outlayer.toml)",
    )?;
    let project_id = format!("{}/{}", config.project.owner, config.project.name);
    Ok(ResolvedAccessor {
        coordinator: json!({"type": "Project", "project_id": project_id}),
        contract: json!({"Project": {"project_id": project_id}}),
    })
}

// ── Access Control Parsing ───────────────────────────────────────────

fn parse_access(access_str: &str) -> Result<Value> {
    match access_str {
        "allow-all" | "AllowAll" => Ok(json!("AllowAll")),
        s if s.starts_with("whitelist:") => {
            let accounts: Vec<&str> = s["whitelist:".len()..].split(',').collect();
            if accounts.is_empty() || accounts.iter().any(|a| a.is_empty()) {
                anyhow::bail!(
                    "Whitelist requires at least one account. \
                     Use: --access whitelist:alice.near,bob.near"
                );
            }
            Ok(json!({ "Whitelist": accounts }))
        }
        other => anyhow::bail!(
            "Unknown access type: '{other}'. Use: allow-all, whitelist:acc1,acc2"
        ),
    }
}

// ── Generate Spec Parsing ────────────────────────────────────────────

struct GenerateSpec {
    name: String,
    generation_type: String,
}

fn parse_generate_specs(generate: Vec<String>) -> Result<Vec<GenerateSpec>> {
    let mut specs = Vec::new();
    for g in generate {
        let (name, gen_type) = g.split_once(':').with_context(|| {
            format!(
                "Invalid --generate format: '{g}'. \
                 Use PROTECTED_NAME:type (e.g. PROTECTED_KEY:hex32)"
            )
        })?;
        if !name.starts_with("PROTECTED_") {
            anyhow::bail!(
                "Generated secret names must start with PROTECTED_. Got: '{name}'"
            );
        }
        specs.push(GenerateSpec {
            name: name.to_string(),
            generation_type: gen_type.to_string(),
        });
    }
    Ok(specs)
}

// ── Parse JSON secrets ───────────────────────────────────────────────

fn parse_secrets_json(json_str: &str) -> Result<serde_json::Map<String, Value>> {
    let val: Value =
        serde_json::from_str(json_str).context("Invalid JSON. Use: '{\"KEY\":\"value\"}'")?;
    let map = val
        .as_object()
        .context("Secrets must be a JSON object: '{\"KEY\":\"value\"}'")?
        .clone();
    if map.is_empty() {
        anyhow::bail!("Empty secrets object");
    }
    Ok(map)
}

// ── Set ──────────────────────────────────────────────────────────────

/// `outlayer secrets set '{"KEY":"val"}' [--generate PROTECTED_X:type] [--access ...] [--vault-id ...]`
#[allow(clippy::too_many_arguments)]
pub async fn set(
    network: &NetworkConfig,
    project_config: Option<&ProjectConfig>,
    secrets_json: Option<String>,
    profile: &str,
    project: Option<String>,
    repo: Option<String>,
    branch: Option<String>,
    wasm_hash: Option<String>,
    generate: Vec<String>,
    access_str: &str,
    vault_id: Option<String>,
) -> Result<()> {
    let creds = config::load_credentials(network)?;

    let accessor = resolve_accessor(project, repo, branch, wasm_hash, project_config)?;
    let access = parse_access(access_str)?;
    let generate_specs = parse_generate_specs(generate)?;

    let secrets_map = match &secrets_json {
        Some(s) => Some(parse_secrets_json(s)?),
        None => None,
    };

    if secrets_map.is_none() && generate_specs.is_empty() {
        anyhow::bail!("Provide secrets JSON and/or --generate flags");
    }

    let api = ApiClient::new(network);

    let encrypted_data = if generate_specs.is_empty() {
        // Simple flow: encrypt manually, no TEE generation
        let secrets_str = Value::Object(secrets_map.clone().unwrap()).to_string();

        eprintln!("Encrypting secrets...");
        let pubkey = api
            .get_secrets_pubkey(
                &GetPubkeyRequest {
                    accessor: accessor.coordinator.clone(),
                    owner: creds.account_id.clone(),
                    profile: Some(profile.to_string()),
                    secrets_json: secrets_str.clone(),
                },
                vault_id.as_deref(),
            )
            .await
            .context("Failed to get keystore pubkey")?;

        crypto::encrypt_secrets(&pubkey, &secrets_str)?
    } else {
        // Generate flow: call add_generated_secret (TEE merges manual + generated)
        let encrypted_base64 = if let Some(map) = &secrets_map {
            let secrets_str = Value::Object(map.clone()).to_string();

            eprintln!("Encrypting manual secrets...");
            let pubkey = api
                .get_secrets_pubkey(
                    &GetPubkeyRequest {
                        accessor: accessor.coordinator.clone(),
                        owner: creds.account_id.clone(),
                        profile: Some(profile.to_string()),
                        secrets_json: secrets_str.clone(),
                    },
                    vault_id.as_deref(),
                )
                .await?;

            Some(crypto::encrypt_secrets(&pubkey, &secrets_str)?)
        } else {
            None
        };

        eprintln!("Generating protected secrets in TEE...");
        let new_secrets: Vec<Value> = generate_specs
            .iter()
            .map(|s| json!({"name": s.name, "generation_type": s.generation_type}))
            .collect();

        let response = api
            .add_generated_secret(&json!({
                "accessor": accessor.coordinator,
                "owner": creds.account_id,
                "profile": profile,
                "encrypted_secrets_base64": encrypted_base64,
                "new_secrets": new_secrets,
            }))
            .await
            .context("Failed to generate protected secrets")?;

        response.encrypted_data_base64
    };

    // Store on contract
    let caller = ContractCaller::from_credentials(&creds, network)?;
    let deposit = 100_000_000_000_000_000_000_000u128; // 0.1 NEAR
    let gas = 50_000_000_000_000u64; // 50 TGas

    caller
        .call_contract(
            "store_secrets",
            json!({
                "accessor": accessor.contract,
                "profile": profile,
                "encrypted_secrets_base64": encrypted_data,
                "access": access,
                // `--vault-id <vault.account>` binds the secret to a
                // per-customer vault: the keystore decrypts it via
                // the per-vault master derived from MPC CKD using
                // that vault's predecessor. Without --vault-id,
                // legacy default-master decryption applies.
                "vault_id": vault_id,
            }),
            gas,
            deposit,
        )
        .await
        .context("Failed to store secrets")?;

    // Summary
    let mut parts = Vec::new();
    if let Some(map) = &secrets_map {
        let mut keys: Vec<&String> = map.keys().collect();
        keys.sort();
        parts.push(format!("keys: {}", keys.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(", ")));
    }
    if !generate_specs.is_empty() {
        let names: Vec<&str> = generate_specs.iter().map(|s| s.name.as_str()).collect();
        parts.push(format!("protected (TEE): {}", names.join(", ")));
    }
    eprintln!("Secrets stored (profile: {profile}, {})", parts.join("; "));

    Ok(())
}

// ── Update ───────────────────────────────────────────────────────────

/// `outlayer secrets update '{"KEY":"val"}' [--generate PROTECTED_X:type]`
///
/// Merges with existing secrets, preserving all PROTECTED_* variables.
/// Uses NEP-413 signature for authentication.
#[allow(clippy::too_many_arguments)]
pub async fn update(
    network: &NetworkConfig,
    project_config: Option<&ProjectConfig>,
    secrets_json: Option<String>,
    profile: &str,
    project: Option<String>,
    repo: Option<String>,
    branch: Option<String>,
    wasm_hash: Option<String>,
    generate: Vec<String>,
) -> Result<()> {
    let creds = config::load_credentials(network)?;

    let accessor = resolve_accessor(project, repo, branch, wasm_hash, project_config)?;
    let generate_specs = parse_generate_specs(generate)?;

    let secrets_map = match &secrets_json {
        Some(s) => Some(parse_secrets_json(s)?),
        None => None,
    };

    if secrets_map.is_none() && generate_specs.is_empty() {
        anyhow::bail!("Provide secrets JSON and/or --generate flags");
    }

    // Build sorted key lists for NEP-413 message
    let mut sorted_keys: Vec<String> = secrets_map
        .as_ref()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    sorted_keys.sort();

    let mut sorted_protected: Vec<String> = generate_specs
        .iter()
        .map(|s| s.name.clone())
        .collect();
    sorted_protected.sort();

    // NEP-413 message
    let message = format!(
        "Update Outlayer secrets for {}:{}\nkeys:{}\nprotected:{}",
        creds.account_id,
        profile,
        sorted_keys.join(","),
        sorted_protected.join(","),
    );

    let recipient = &network.contract_id;

    eprintln!("Signing update request...");

    // Sign: local key or wallet API
    // Both verifiers (keystore, coordinator) expect signature in base64 format.
    let (signature, public_key, nonce_base64) = if creds.is_wallet_key() {
        let wk = creds
            .wallet_key
            .as_ref()
            .context("wallet_key missing from credentials")?;
        let api = ApiClient::new(network);
        let resp = api.sign_message(wk, &message, recipient, None).await?;
        (resp.signature_base64, resp.public_key, resp.nonce)
    } else {
        let private_key = config::load_private_key(&network.network_id, &creds.account_id, &creds)?;
        let (sig_near, pk, nonce) = crypto::sign_nep413(&private_key, &message, recipient)?;
        // Convert ed25519:base58 → raw bytes → base64
        let sig_b58 = sig_near.strip_prefix("ed25519:").unwrap_or(&sig_near);
        let sig_bytes = bs58::decode(sig_b58).into_vec().context("Failed to decode signature base58")?;
        let sig_base64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &sig_bytes,
        );
        (sig_base64, pk, nonce)
    };

    // Build secrets to send (plaintext — coordinator encrypts inside TEE)
    let secrets_value = secrets_map
        .as_ref()
        .map(|m| Value::Object(m.clone()))
        .unwrap_or(json!({}));

    let generate_protected: Vec<Value> = generate_specs
        .iter()
        .map(|s| json!({"name": s.name, "generation_type": s.generation_type}))
        .collect();

    let api = ApiClient::new(network);

    eprintln!("Updating secrets...");
    let response = api
        .update_user_secrets(&json!({
            "accessor": accessor.coordinator,
            "profile": profile,
            "owner": creds.account_id,
            "mode": "append",
            "secrets": secrets_value,
            "generate_protected": generate_protected,
            "signed_message": message,
            "signature": signature,
            "public_key": public_key,
            "nonce": nonce_base64,
            "recipient": recipient,
        }))
        .await
        .context("Failed to update secrets")?;

    // Store merged result on contract
    let caller = ContractCaller::from_credentials(&creds, network)?;
    let deposit = 100_000_000_000_000_000_000_000u128; // 0.1 NEAR
    let gas = 50_000_000_000_000u64;

    caller
        .call_contract(
            "store_secrets",
            json!({
                "accessor": accessor.contract,
                "profile": profile,
                "encrypted_secrets_base64": response.encrypted_secrets_base64,
                "access": "AllowAll",
                // Re-store flow preserves the existing vault binding
                // (`null` = no-op on the side-table per
                // the contract's documented semantics, see
                // contract/src/secrets.rs `store_secrets`).
                "vault_id": null,
            }),
            gas,
            deposit,
        )
        .await
        .context("Failed to store updated secrets")?;

    // Summary
    let mut parts = Vec::new();
    if !sorted_keys.is_empty() {
        parts.push(format!("updated: {}", sorted_keys.join(", ")));
    }
    if !sorted_protected.is_empty() {
        parts.push(format!("protected (TEE): {}", sorted_protected.join(", ")));
    }
    eprintln!("Secrets updated (profile: {profile}, {})", parts.join("; "));

    Ok(())
}

// ── List ─────────────────────────────────────────────────────────────

/// `outlayer secrets list` — list stored secrets metadata
pub async fn list(network: &NetworkConfig) -> Result<()> {
    let creds = config::load_credentials(network)?;
    let near = NearClient::new(network);

    let secrets = near.list_user_secrets(&creds.account_id).await?;

    // Filter out System (PaymentKey) entries
    let user_secrets: Vec<_> = secrets
        .iter()
        .filter(|s| !s.accessor.to_string().contains("System"))
        .collect();

    if user_secrets.is_empty() {
        eprintln!("No secrets stored.");
        return Ok(());
    }

    println!(
        "{:<15} {:<30} {:<15}",
        "PROFILE", "ACCESSOR", "ACCESS"
    );

    for s in user_secrets {
        let accessor_str = format_accessor(&s.accessor);
        let access_str = format_access(&s.access);
        println!("{:<15} {:<30} {:<15}", s.profile, accessor_str, access_str);
    }

    Ok(())
}

// ── Delete ───────────────────────────────────────────────────────────

/// `outlayer secrets delete [--project|--repo|--wasm-hash]`
#[allow(clippy::too_many_arguments)]
pub async fn delete(
    network: &NetworkConfig,
    project_config: Option<&ProjectConfig>,
    profile: &str,
    project: Option<String>,
    repo: Option<String>,
    branch: Option<String>,
    wasm_hash: Option<String>,
) -> Result<()> {
    let creds = config::load_credentials(network)?;

    let accessor = resolve_accessor(project, repo, branch, wasm_hash, project_config)?;

    let caller = ContractCaller::from_credentials(&creds, network)?;
    let gas = 30_000_000_000_000u64; // 30 TGas

    caller
        .call_contract(
            "delete_secrets",
            json!({
                "accessor": accessor.contract,
                "profile": profile,
            }),
            gas,
            0, // no deposit, storage refunded
        )
        .await
        .context("Failed to delete secrets")?;

    eprintln!("Secrets deleted (profile: {profile})");
    Ok(())
}

// ── Set for an agent ─────────────────────────────────────────────────

/// The most a `store_agent_secret` call may ask this account to attach.
///
/// The deposit is storage, and the contract charges 0.00001 NEAR per
/// byte against a 10 KB ceiling — so a whole secret cannot cost more
/// than 0.1 NEAR, and the endpoint asks for exactly that. One NEAR
/// leaves room for the price to move without an upgrade, and is far
/// too little to matter if an answer we did not expect ever reaches
/// this check.
const MAX_AGENT_SECRET_DEPOSIT_YOCTO: u128 = 1_000_000_000_000_000_000_000_000;

/// NEAR's per-transaction gas ceiling. A call asking for more is not a
/// call, so the number is wrong before it is dangerous.
const MAX_GAS: u64 = 300_000_000_000_000;

/// Refuse a pubkey that is not the one this request asked for.
///
/// The answer carries the seed it belongs to, and the seed is derivable
/// from what we sent: `project:{project_id}:{agent_account}`. Rebuilding
/// it and comparing turns "the key came back for a different agent" from
/// something invisible into a refusal. It cannot prove the key belongs
/// to the seed — only the holder of the master can — but it does catch
/// the answer being for another agent entirely, which is the shape a
/// mix-up takes.
fn check_agent_secret_pubkey(
    pubkey: &crate::api::AgentSecretPubkey,
    project_id: &str,
) -> Result<()> {
    if pubkey.agent_account.trim().is_empty() {
        anyhow::bail!("The coordinator returned no agent account to store the secret under");
    }

    let expected_seed = format!("project:{}:{}", project_id, pubkey.agent_account);
    if pubkey.seed != expected_seed {
        anyhow::bail!(
            "The encryption key came back for a different secret than the one asked for.\n  \
             asked for: {expected_seed}\n  \
             answered:  {}\n\
             Nothing was encrypted. Sealing a credential to this key would hand it to \
             whoever the other seed belongs to.",
            pubkey.seed,
        );
    }

    Ok(())
}

/// Refuse to sign a prepared call that is not the one we asked for.
///
/// The call comes back from the coordinator and would be sent by a full
/// access key, so every field of it is attacker-controlled input until
/// checked. Signing it unread would make this command a way to get an
/// arbitrary transaction signed by anyone who runs it — the receiver,
/// the method and the deposit all arrive over the same wire as the
/// signature.
///
/// The ciphertext is checked too, and for a different reason: it is the
/// one field whose substitution would still produce a valid, working
/// secret — an older credential replayed into place, which for a
/// rotation is the whole attack.
fn check_prepared_agent_secret(
    prepared: &crate::api::PreparedAgentSecret,
    contract_id: &str,
    project_id: &str,
    encrypted_secrets_base64: &str,
    expected_vault_id: Option<&str>,
) -> Result<()> {
    if prepared.contract_id != contract_id {
        anyhow::bail!(
            "The prepared call is addressed to '{}', not to the OutLayer contract '{contract_id}'. \
             Nothing was signed.",
            prepared.contract_id,
        );
    }
    if prepared.method_name != "store_agent_secret" {
        anyhow::bail!(
            "The prepared call invokes '{}', not 'store_agent_secret'. Nothing was signed.",
            prepared.method_name,
        );
    }

    let args = prepared
        .args
        .as_object()
        .context("The prepared call carries no arguments object")?;

    let str_arg = |name: &str| -> Result<&str> {
        args.get(name)
            .and_then(|v| v.as_str())
            .with_context(|| format!("The prepared call is missing a string '{name}' argument"))
    };

    let expected_accessor = json!({ "Project": { "project_id": project_id } });
    let accessor = args
        .get("accessor")
        .context("The prepared call is missing its 'accessor' argument")?;
    if accessor != &expected_accessor {
        anyhow::bail!(
            "The prepared call stores the secret against {}, not against project '{project_id}'. \
             Nothing was signed.",
            format_accessor(accessor),
        );
    }

    if str_arg("encrypted_secrets_base64")? != encrypted_secrets_base64 {
        anyhow::bail!(
            "The prepared call carries different ciphertext than the one just encrypted. \
             Nothing was signed — sending it would store a secret this machine did not produce."
        );
    }

    if str_arg("profile")? != prepared.agent_account {
        anyhow::bail!(
            "The prepared call names the secret '{}' while reporting the agent as '{}'. \
             Nothing was signed.",
            str_arg("profile")?,
            prepared.agent_account,
        );
    }

    let access = args
        .get("access")
        .context("The prepared call is missing its 'access' argument")?;
    if access != &json!("AllowAll") {
        anyhow::bail!(
            "The prepared call grants {} rather than naming the agent as the sole reader. \
             Nothing was signed.",
            format_access(access),
        );
    }

    // The vault is decided by the wallet key's own binding, not by this
    // request, so there is no value to require — only one to report. A
    // caller who knows which vault they expect says so, and gets a
    // refusal instead of a surprise.
    let vault_id = args.get("vault_id").and_then(|v| v.as_str());
    if let Some(expected) = expected_vault_id {
        if vault_id != Some(expected) {
            anyhow::bail!(
                "The prepared call binds the secret to {} rather than to the expected vault \
                 '{expected}'. Nothing was signed — a secret sealed under one vault's master \
                 cannot be read under another's.",
                vault_id
                    .map(|v| format!("vault '{v}'"))
                    .unwrap_or_else(|| "the default master".to_string()),
            );
        }
    }

    if str_arg("agent_pubkey")?.is_empty() || str_arg("wallet_signature")?.is_empty() {
        anyhow::bail!(
            "The prepared call carries no wallet signature. The contract would reject it; \
             nothing was signed."
        );
    }

    let deposit: u128 = prepared
        .deposit
        .parse()
        .with_context(|| format!("Deposit '{}' is not a number", prepared.deposit))?;
    if deposit > MAX_AGENT_SECRET_DEPOSIT_YOCTO {
        anyhow::bail!(
            "The prepared call asks this account to attach {} yoctoNEAR, more than the {} \
             a secret's storage can cost. Nothing was signed.",
            deposit,
            MAX_AGENT_SECRET_DEPOSIT_YOCTO,
        );
    }

    let gas: u64 = prepared
        .gas
        .parse()
        .with_context(|| format!("Gas '{}' is not a number", prepared.gas))?;
    if gas == 0 || gas > MAX_GAS {
        anyhow::bail!(
            "The prepared call asks for {gas} gas, which is outside what a transaction may \
             attach. Nothing was signed."
        );
    }

    Ok(())
}

/// `outlayer secrets set-for-agent '{"KEY":"val"}' --project <owner>/<name>`
///
/// Leaves a credential for an agent to use with one connector: sealed to
/// the agent's own key, stored on chain under the agent's name, readable
/// by the agent and by nobody else.
///
/// The plaintext never leaves this machine. What goes out is ciphertext
/// the coordinator cannot read, sealed to a key fetched under the
/// agent's own authentication.
pub async fn set_for_agent(
    network: &NetworkConfig,
    secrets_json: String,
    project_id: String,
    api_key: Option<&str>,
    vault_id: Option<String>,
    agent_pays: bool,
) -> Result<()> {
    let secrets_map = parse_secrets_json(&secrets_json)?;
    let secrets_str = Value::Object(secrets_map.clone()).to_string();

    let wallet_key = super::checks::resolve_wallet_key(api_key)?;
    let api = ApiClient::new(network);

    let pubkey = api
        .agent_secret_pubkey(&wallet_key, &project_id)
        .await
        .context("Failed to get the agent's encryption key")?;
    check_agent_secret_pubkey(&pubkey, &project_id)?;

    let encrypted = crypto::encrypt_secrets(&pubkey.pubkey, &secrets_str)?;

    let agent_account = if agent_pays {
        let stored = api
            .store_agent_secret(&wallet_key, &project_id, &encrypted)
            .await?;
        eprintln!("Stored by the agent's own wallet, tx {}", stored.tx_hash);
        stored.agent_account
    } else {
        let creds = config::load_credentials(network)?;
        let prepared = api
            .prepare_agent_secret(&wallet_key, &project_id, &encrypted, &creds.account_id)
            .await?;
        check_prepared_agent_secret(
            &prepared,
            &network.contract_id,
            &project_id,
            &encrypted,
            vault_id.as_deref(),
        )?;

        // The receiver is this network's contract id, not the one the
        // answer named — they were just compared, and taking ours keeps
        // the destination of a signed transaction decided here.
        let caller = ContractCaller::from_credentials(&creds, network)?;
        let outcome = caller
            .call_contract(
                &prepared.method_name,
                prepared.args.clone(),
                prepared.gas.parse()?,
                prepared.deposit.parse()?,
            )
            .await
            .context("Failed to store the agent's secret")?;

        eprintln!(
            "Stored, paid by {}, tx {}",
            creds.account_id,
            outcome.tx_hash.as_deref().unwrap_or("-"),
        );
        prepared.agent_account
    };

    let mut keys: Vec<&String> = secrets_map.keys().collect();
    keys.sort();
    eprintln!(
        "Secret for {agent_account} on {project_id} (keys: {})",
        keys.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(", "),
    );

    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────

fn format_accessor(accessor: &Value) -> String {
    if let Some(obj) = accessor.as_object() {
        if let Some(project) = obj.get("Project") {
            if let Some(id) = project.get("project_id").and_then(|v| v.as_str()) {
                return format!("Project({id})");
            }
        }
        if let Some(repo) = obj.get("Repo") {
            if let Some(r) = repo.get("repo").and_then(|v| v.as_str()) {
                let branch = repo
                    .get("branch")
                    .and_then(|v| v.as_str())
                    .map(|b| format!("@{b}"))
                    .unwrap_or_default();
                return format!("Repo({r}{branch})");
            }
        }
        if let Some(wasm) = obj.get("WasmHash") {
            if let Some(h) = wasm.get("hash").and_then(|v| v.as_str()) {
                let short = if h.len() > 8 { &h[..8] } else { h };
                return format!("WasmHash({short}...)");
            }
        }
    }
    accessor.to_string()
}

fn format_access(access: &Value) -> String {
    if access.is_string() && access.as_str() == Some("AllowAll") {
        return "AllowAll".to_string();
    }
    if let Some(obj) = access.as_object() {
        if let Some(wl) = obj.get("Whitelist") {
            if let Some(arr) = wl.as_array() {
                return format!("Whitelist({})", arr.len());
            }
        }
    }
    access.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{AgentSecretPubkey, PreparedAgentSecret};

    const PROJECT: &str = "connectors.outlayer.testnet/connector-probe";
    const AGENT: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    const CIPHERTEXT: &str = "AQIDBAUGBwgJCgsMDQ4PEA==";
    const CONTRACT: &str = "outlayer.testnet";

    fn pubkey_answer() -> AgentSecretPubkey {
        AgentSecretPubkey {
            pubkey: "aa".repeat(32),
            seed: format!("project:{PROJECT}:{AGENT}"),
            agent_account: AGENT.to_string(),
        }
    }

    fn prepared_call() -> PreparedAgentSecret {
        PreparedAgentSecret {
            contract_id: CONTRACT.to_string(),
            method_name: "store_agent_secret".to_string(),
            args: json!({
                "agent_pubkey": "ed25519:11111111111111111111111111111111",
                "accessor": { "Project": { "project_id": PROJECT } },
                "profile": AGENT,
                "encrypted_secrets_base64": CIPHERTEXT,
                "access": "AllowAll",
                "vault_id": "vault.alice.testnet",
                "wallet_signature": "ab".repeat(64),
            }),
            deposit: "100000000000000000000000".to_string(),
            gas: "100000000000000".to_string(),
            agent_account: AGENT.to_string(),
        }
    }

    #[test]
    fn the_answer_this_request_asked_for_is_accepted() {
        check_agent_secret_pubkey(&pubkey_answer(), PROJECT).unwrap();
        check_prepared_agent_secret(
            &prepared_call(),
            CONTRACT,
            PROJECT,
            CIPHERTEXT,
            Some("vault.alice.testnet"),
        )
        .unwrap();
    }

    #[test]
    fn a_key_for_another_agent_is_refused() {
        let mut answer = pubkey_answer();
        answer.seed = format!("project:{PROJECT}:someone-else.testnet");
        let err = check_agent_secret_pubkey(&answer, PROJECT).unwrap_err().to_string();
        assert!(err.contains("different secret"), "{err}");
    }

    #[test]
    fn a_key_for_another_project_is_refused() {
        // Same agent, same shape, another connector: the seed names the
        // project, so encrypting to this key would seal the credential
        // where a different connector's code can ask for it.
        let answer = pubkey_answer();
        assert!(check_agent_secret_pubkey(&answer, "connectors.outlayer.testnet/other").is_err());
    }

    #[test]
    fn a_nameless_agent_is_refused() {
        let mut answer = pubkey_answer();
        answer.agent_account = "  ".to_string();
        assert!(check_agent_secret_pubkey(&answer, PROJECT).is_err());
    }

    /// Every field of a prepared call is attacker-controlled input until
    /// checked, and this is the list of what checking it means. A field
    /// that stops being checked fails here rather than in someone's
    /// account.
    #[test]
    fn a_prepared_call_that_is_not_the_one_asked_for_is_refused() {
        let cases: Vec<(&str, Box<dyn Fn(&mut PreparedAgentSecret)>)> = vec![
            (
                "another receiver",
                Box::new(|p| p.contract_id = "attacker.testnet".to_string()),
            ),
            (
                "another method",
                Box::new(|p| p.method_name = "ft_transfer".to_string()),
            ),
            (
                "another project",
                Box::new(|p| {
                    p.args["accessor"] = json!({ "Project": { "project_id": "x.testnet/y" } })
                }),
            ),
            (
                "substituted ciphertext",
                Box::new(|p| p.args["encrypted_secrets_base64"] = json!("b3RoZXI=")),
            ),
            (
                "another name",
                Box::new(|p| p.args["profile"] = json!("other.testnet")),
            ),
            (
                "a wider audience",
                Box::new(|p| p.args["access"] = json!({ "Whitelist": ["attacker.testnet"] })),
            ),
            (
                "another vault",
                Box::new(|p| p.args["vault_id"] = json!("vault.attacker.testnet")),
            ),
            (
                "the default master instead of the vault",
                Box::new(|p| p.args["vault_id"] = json!(null)),
            ),
            (
                "no signature",
                Box::new(|p| p.args["wallet_signature"] = json!("")),
            ),
            (
                "a draining deposit",
                Box::new(|p| p.deposit = "5000000000000000000000000".to_string()),
            ),
            (
                "impossible gas",
                Box::new(|p| p.gas = "500000000000000".to_string()),
            ),
            (
                "no arguments at all",
                Box::new(|p| p.args = json!("nothing")),
            ),
        ];

        for (name, tamper) in cases {
            let mut prepared = prepared_call();
            tamper(&mut prepared);
            assert!(
                check_prepared_agent_secret(
                    &prepared,
                    CONTRACT,
                    PROJECT,
                    CIPHERTEXT,
                    Some("vault.alice.testnet"),
                )
                .is_err(),
                "a prepared call with {name} was accepted",
            );
        }
    }

    /// Without `--vault-id` there is nothing to compare against, so the
    /// binding the coordinator chose is reported rather than enforced.
    /// Everything else is still checked.
    #[test]
    fn an_unstated_vault_expectation_checks_everything_else() {
        let mut prepared = prepared_call();
        prepared.args["vault_id"] = json!("vault.someone.testnet");
        check_prepared_agent_secret(&prepared, CONTRACT, PROJECT, CIPHERTEXT, None).unwrap();

        prepared.args["access"] = json!({ "Whitelist": ["attacker.testnet"] });
        assert!(check_prepared_agent_secret(&prepared, CONTRACT, PROJECT, CIPHERTEXT, None).is_err());
    }
}
