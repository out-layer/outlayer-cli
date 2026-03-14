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

/// `outlayer secrets set '{"KEY":"val"}' [--generate PROTECTED_X:type] [--access ...]`
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
            .get_secrets_pubkey(&GetPubkeyRequest {
                accessor: accessor.coordinator.clone(),
                owner: creds.account_id.clone(),
                profile: Some(profile.to_string()),
                secrets_json: secrets_str.clone(),
            })
            .await
            .context("Failed to get keystore pubkey")?;

        crypto::encrypt_secrets(&pubkey, &secrets_str)?
    } else {
        // Generate flow: call add_generated_secret (TEE merges manual + generated)
        let encrypted_base64 = if let Some(map) = &secrets_map {
            let secrets_str = Value::Object(map.clone()).to_string();

            eprintln!("Encrypting manual secrets...");
            let pubkey = api
                .get_secrets_pubkey(&GetPubkeyRequest {
                    accessor: accessor.coordinator.clone(),
                    owner: creds.account_id.clone(),
                    profile: Some(profile.to_string()),
                    secrets_json: secrets_str.clone(),
                })
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
    let (signature, public_key, nonce_base64) = if creds.is_wallet_key() {
        let wk = creds
            .wallet_key
            .as_ref()
            .context("wallet_key missing from credentials")?;
        let api = ApiClient::new(network);
        let resp = api.sign_message(wk, &message, recipient, None).await?;
        (resp.signature, resp.public_key, resp.nonce)
    } else {
        let private_key = config::load_private_key(&network.network_id, &creds.account_id, &creds)?;
        crypto::sign_nep413(&private_key, &message, recipient)?
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
