use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::api::{AgentSecretScope, ApiClient, GetPubkeyRequest};
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

/// Re-spell the repository in the CONTRACT accessor the way the keystore does.
///
/// The keystore normalises a repo URL before it asks the contract for a secret
/// (`accessor_to_contract_json`), so what a person typed —
/// `https://github.com/a/b`, `git@github.com:a/b`, a trailing `.git` — is not
/// what the reader will ask for. Storing the typed form produces a secret that
/// encrypts to the right key, lands on chain, and is never found at run time.
/// Measured against the deployed contract: written as
/// `https://github.com/x/y`, read as `github.com/x/y`, answer `null`.
///
/// The spelling is TAKEN FROM THE ANSWER rather than recomputed here. The rule
/// lives in the keystore; a second copy in this binary would be the one that
/// drifts. This is what the dashboard has always done, which is why secrets
/// stored through it have always been readable.
fn apply_repo_normalization(accessor: &mut ResolvedAccessor, repo_normalized: Option<&str>) {
    let Some(normalized) = repo_normalized else { return };
    if let Some(repo) = accessor
        .contract
        .get_mut("Repo")
        .and_then(|r| r.get_mut("repo"))
    {
        *repo = json!(normalized);
    }
}

/// The NEP-413 message an update is signed over.
///
/// **Each section is present only when it has content**, because that is how
/// the verifier builds it: `keystore-worker/src/api.rs` appends `\nkeys:` only
/// for a non-empty key list and `\nprotected:` only for a non-empty generated
/// list. This wrote both unconditionally, so `secrets update` without
/// `--generate` signed a message ending in an empty `protected:` line and the
/// keystore refused it — every plain update failed with
/// `Invalid message format. Expected payload to match request data.` The
/// dashboard builds it conditionally, which is why the same operation has
/// always worked there.
///
/// Three parties have to write the same string and none of them can see the
/// others, so the shapes are pinned by the tests below.
fn update_message(owner: &str, profile: &str, keys: &[String], protected: &[String]) -> String {
    let mut message = format!("Update Outlayer secrets for {owner}:{profile}");
    if !keys.is_empty() {
        message.push_str(&format!("\nkeys:{}", keys.join(",")));
    }
    if !protected.is_empty() {
        message.push_str(&format!("\nprotected:{}", protected.join(",")));
    }
    message
}

/// Ask what the repository is called, and re-spell the accessor with the
/// answer.
///
/// For the commands that do not encrypt anything — `delete`, and the store half
/// of `update` — there is no pubkey call to take the spelling from, and taking
/// it from nowhere is what left them addressing a slot the store no longer
/// writes to. One extra request, only when there is a repository to re-spell:
/// `Project` and `WasmHash` have nothing to normalise and are left untouched
/// without asking anybody.
///
/// `/secrets/pubkey` derives a key and stores nothing, so calling it to learn a
/// name costs a round trip and no state.
async fn canonicalize_repo(
    api: &ApiClient,
    accessor: &mut ResolvedAccessor,
    owner: &str,
    profile: &str,
    vault_id: Option<&str>,
) -> Result<()> {
    if accessor.contract.get("Repo").is_none() {
        return Ok(());
    }

    let answer = api
        .get_secrets_pubkey(
            &GetPubkeyRequest {
                accessor: accessor.coordinator.clone(),
                owner: owner.to_string(),
                profile: Some(profile.to_string()),
                // Nothing is being encrypted here; this call is only asked for
                // the name it gives the repository.
                secrets_json: "{}".to_string(),
            },
            vault_id,
        )
        .await
        .context("Failed to ask the coordinator how this repository is spelled")?;

    apply_repo_normalization(accessor, answer.repo_normalized.as_deref());
    Ok(())
}

fn resolve_accessor(
    project: Option<String>,
    repo: Option<String>,
    branch: Option<String>,
    wasm_hash: Option<String>,
    project_config: Option<&ProjectConfig>,
) -> Result<ResolvedAccessor> {
    if let Some(hash) = wasm_hash {
        // The contract stores a hash lowercased and echoes that spelling in
        // the row it answers; `set` and `update` compare the echoed accessor
        // with this one byte for byte to tell "the row" from "another row".
        // Spelled any other way, the same hash would read as a different row
        // — NEW for `set` (the default condition over the stored one),
        // "no secret at this accessor" for `update`.
        let hash = hash.trim().to_lowercase();
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
        s if s.starts_with("whitelist:") => parse_whitelist(&s["whitelist:".len()..]),
        other => anyhow::bail!(
            "Unknown access type: '{other}'. Use: allow-all, whitelist:acc1,acc2 — an entry may \
             carry a deadline, acc@2026-10-01T00:00:00Z, after which it no longer admits"
        ),
    }
}

/// `a.near,b.near@2026-10-01T00:00:00Z` → the contract's
/// condition. Entries without a deadline form one `Whitelist`; each entry with
/// one becomes `And[Whitelist[entry], ValidUntil(deadline)]`, and the groups are
/// joined with `Or`. A single group is written bare.
fn parse_whitelist(list: &str) -> Result<Value> {
    let entries: Vec<&str> = list.split(',').collect();
    if entries.is_empty() || entries.iter().any(|e| e.trim().is_empty()) {
        anyhow::bail!(
            "Whitelist requires at least one account. Use: --access whitelist:alice.near,bob.near"
        );
    }
    let mut open: Vec<&str> = Vec::new();
    let mut groups: Vec<Value> = Vec::new();
    for entry in entries {
        match entry.split_once('@') {
            None => open.push(entry.trim()),
            Some((account, deadline)) => {
                let account = account.trim();
                if account.is_empty() {
                    anyhow::bail!("'{entry}': the account before '@' is empty");
                }
                let until_ns = parse_deadline(deadline.trim())
                    .with_context(|| format!("'{entry}': the deadline after '@' is not a date"))?;
                groups.push(json!({ "Logic": { "operator": "And", "conditions": [
                    whitelist_of(&[account]),
                    { "ValidUntil": { "until_ns": until_ns.to_string() } }
                ]}}));
            }
        }
    }
    if !open.is_empty() {
        groups.insert(0, whitelist_of(&open));
    }
    Ok(if groups.len() == 1 {
        groups.remove(0)
    } else {
        json!({ "Logic": { "operator": "Or", "conditions": groups } })
    })
}

fn whitelist_of(accounts: &[&str]) -> Value {
    json!({ "Whitelist": { "accounts": accounts } })
}

/// A deadline as nanoseconds since the epoch. Exactly two spellings, both UTC:
/// `YYYY-MM-DD` and `YYYY-MM-DDTHH:MM:SSZ`. A local time is refused because it
/// would mean a different instant on every machine.
///
/// A bare number is refused rather than read as epoch seconds. `20261001` parses
/// as a number, and taking it that way would silently mean August 1970 to
/// somebody who meant 2026-10-01: the grant would be born expired, and the
/// refusal would blame a limit in 1970.
fn parse_deadline(text: &str) -> Result<u64> {
    if text.is_empty() || text.chars().all(|c| c.is_ascii_digit()) {
        anyhow::bail!(
            "'{text}' is not a date: write it as 2026-10-01 or 2026-10-01T00:00:00Z (UTC). \
             A bare number is not read as epoch seconds, because 20261001 would silently \
             mean August 1970 to somebody who meant 2026-10-01"
        );
    }
    let (date, time) = match text.split_once('T') {
        Some((d, t)) => (d, t.strip_suffix('Z').context("the time must end in 'Z' (UTC)")?),
        None => (text, "00:00:00"),
    };
    let mut ymd = date.split('-').map(|p| p.parse::<i64>());
    let (y, m, d) = match (ymd.next(), ymd.next(), ymd.next(), ymd.next()) {
        (Some(Ok(y)), Some(Ok(m)), Some(Ok(d)), None) => (y, m, d),
        _ => anyhow::bail!("expected YYYY-MM-DD, got '{date}'"),
    };
    let mut hms = time.split(':').map(|p| p.parse::<i64>());
    let (h, mi, sec) = match (hms.next(), hms.next(), hms.next(), hms.next()) {
        (Some(Ok(h)), Some(Ok(mi)), Some(Ok(s)), None) => (h, mi, s),
        _ => anyhow::bail!("expected HH:MM:SS, got '{time}'"),
    };
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || !(0..24).contains(&h) || !(0..60).contains(&mi) || !(0..60).contains(&sec) {
        anyhow::bail!("'{text}' is not a calendar date and time");
    }
    let days = days_from_civil(y, m, d);
    // `1..=31` admits 2026-02-30; the round trip does not. A deadline that rolls
    // into the next month would lapse later than the owner wrote.
    if civil_from_days(days) != (y, m, d) {
        anyhow::bail!("'{text}' is not a calendar date");
    }
    let secs = days * 86_400 + h * 3_600 + mi * 60 + sec;
    if secs < 0 {
        anyhow::bail!("'{text}' is before 1970");
    }
    (secs as u64)
        .checked_mul(1_000_000_000)
        .context("the deadline is too far in the future")
}

/// Days since 1970-01-01 for a proleptic Gregorian date, after Howard Hinnant.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`]: `(year, month, day)`.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// The condition a row is stored under right now, or `None` when there is no
/// such row. Read from the chain, since that is where it lives.
async fn stored_row(
    near: &NearClient,
    accessor_contract: &Value,
    profile: &str,
    owner: &str,
) -> Result<Option<Value>> {
    near.view_call(
        "get_secrets",
        json!({ "accessor": accessor_contract, "profile": profile, "owner": owner }),
    )
    .await
    .context("Failed to read the stored secret")
}

/// What `set` stores a row under when the caller gave no `--access`: the
/// condition it already has, so a rotation never changes who may read; for a
/// new row under a project, the signer alone — a personal secret is readable
/// by whoever names it only if its owner says so; for a new repository- or
/// hash-bound row, everyone, as those rows are an app's own.
fn default_access(existing: Option<Value>, accessor_contract: &Value, owner: &str) -> (Value, &'static str) {
    match existing {
        Some(access) => (access, "kept the stored condition"),
        None if accessor_contract.get("Project").is_some() => (whitelist_of(&[owner]), "new project row: only you"),
        None => (json!("AllowAll"), "new row: everyone"),
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
    access_str: Option<&str>,
    vault_id: Option<String>,
) -> Result<()> {
    let creds = config::load_credentials(network)?;

    let mut accessor = resolve_accessor(project, repo, branch, wasm_hash, project_config)?;
    let explicit_access = access_str.map(parse_access).transpose()?;
    let generate_specs = parse_generate_specs(generate)?;

    let secrets_map = match &secrets_json {
        Some(s) => Some(parse_secrets_json(s)?),
        None => None,
    };

    if secrets_map.is_none() && generate_specs.is_empty() {
        anyhow::bail!("Provide secrets JSON and/or --generate flags");
    }

    let api = ApiClient::new(network);

    // The condition: what was asked for, else what the row already has, else
    // the default for a row of this kind. Decided before anything is encrypted
    // or generated in the TEE — a chain that cannot be read then costs the
    // caller nothing and no generated key is made to be thrown away. The
    // accessor takes its canonical spelling first, so the row read here is the
    // row written below.
    let access = match explicit_access {
        Some(access) => access,
        None => {
            canonicalize_repo(&api, &mut accessor, &creds.account_id, profile, vault_id.as_deref()).await?;
            // `get_secrets` answers a branch-specific read with the WILDCARD row
            // when no branch row exists, and echoes the accessor it actually
            // found. Copying that condition onto a new branch row and calling it
            // "kept" would be a lie: the wildcard row is a different row, and it
            // keeps its own condition. Only a row at the very accessor about to
            // be written counts as existing.
            let row = stored_row(&NearClient::new(network), &accessor.contract, profile, &creds.account_id).await?;
            let existing = match row {
                None => None,
                Some(r) => {
                    // An answer that names no accessor cannot say which row it
                    // is; storing "a new row" over it with the default would
                    // be exactly the silent reset this read exists to prevent.
                    let Some(found) = r.get("accessor") else {
                        anyhow::bail!("the chain's answer names no accessor, so which row it is cannot be told — pass --access to store anyway");
                    };
                    if found == &accessor.contract {
                        r.get("access").cloned()
                    } else {
                        eprintln!(
                            "Note: {profile} is stored under a different accessor ({}); this writes a NEW row.",
                            format_accessor(found)
                        );
                        None
                    }
                }
            };
            let (access, why) = default_access(existing, &accessor.contract, &creds.account_id);
            eprintln!("Access: {} ({why}; pass --access to choose)", format_access(&access));
            access
        }
    };

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

        apply_repo_normalization(&mut accessor, pubkey.repo_normalized.as_deref());
        crypto::encrypt_secrets(&pubkey.pubkey, &secrets_str)?
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

            apply_repo_normalization(&mut accessor, pubkey.repo_normalized.as_deref());
            Some(crypto::encrypt_secrets(&pubkey.pubkey, &secrets_str)?)
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

        // The generate-only path never calls the pubkey endpoint, so this
        // answer is the only place the normalised spelling comes from.
        apply_repo_normalization(
            &mut accessor,
            response
                .accessor
                .as_ref()
                .and_then(|a| a.pointer("/Repo/repo_normalized"))
                .and_then(|v| v.as_str()),
        );

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

    let mut accessor = resolve_accessor(project, repo, branch, wasm_hash, project_config)?;
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

    let api = ApiClient::new(network);

    // The merged result is stored on chain below, and `set` writes the
    // normalised spelling — so this has to write the same one, or an update
    // lands in a second slot instead of replacing the first.
    //
    // `update_user_secrets` answers with the ciphertext and nothing else, so
    // unlike `set` there is no accessor in the reply to take it from.
    canonicalize_repo(&api, &mut accessor, &creds.account_id, profile, None).await?;

    // The merged row keeps the condition it had. An update changes values, not
    // who may read them — re-storing under a default would silently widen a
    // whitelisted row or narrow an app's AllowAll credential. Read before
    // anything is signed or merged: a row that is not there, or a chain that
    // cannot be read, stops here at no cost — not even a signature.
    let row = stored_row(&NearClient::new(network), &accessor.contract, profile, &creds.account_id)
        .await?
        .context("no such secret to update — store it with `outlayer secrets set` first")?;
    // `get_secrets` answers a branch-specific read with the WILDCARD row when
    // no branch row exists. An update merges into the row it was asked about;
    // it does not mint a branch row carrying another row's condition.
    let Some(found) = row.get("accessor") else {
        anyhow::bail!("the chain's answer names no accessor, so which row it is cannot be told — nothing changed");
    };
    if found != &accessor.contract {
        anyhow::bail!(
            "no secret at this accessor (profile: {profile}); {} holds one — \
             `update` merges into an existing row, `set` creates one",
            format_accessor(found)
        );
    }
    let access = row
        .get("access")
        .cloned()
        .context("the stored row carries no access condition")?;

    // NEP-413 message
    let message = update_message(&creds.account_id, profile, &sorted_keys, &sorted_protected);

    let recipient = &network.contract_id;

    eprintln!("Signing update request...");

    // Sign: local key or wallet API
    // Both verifiers (keystore, coordinator) expect signature in base64 format.
    let (signature, public_key, nonce_base64) = if creds.is_wallet_key() {
        let wk = creds
            .wallet_key
            .as_ref()
            .context("wallet_key missing from credentials")?;
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
                "access": access,
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

// ── Access ───────────────────────────────────────────────────────────

/// `outlayer secrets access --access ... [--project|--repo|--wasm-hash]` —
/// change who may read a stored secret. The ciphertext stays; only the
/// condition moves, through the contract's `update_access`. This is how an
/// owner grants an agent (`whitelist:me.near,<agent>@<deadline>`) and how they
/// take it back.
#[allow(clippy::too_many_arguments)]
pub async fn access(
    network: &NetworkConfig,
    project_config: Option<&ProjectConfig>,
    profile: &str,
    project: Option<String>,
    repo: Option<String>,
    branch: Option<String>,
    wasm_hash: Option<String>,
    access_str: &str,
) -> Result<()> {
    let creds = config::load_credentials(network)?;
    let new_access = parse_access(access_str)?;

    let mut accessor = resolve_accessor(project, repo, branch, wasm_hash, project_config)?;
    canonicalize_repo(&ApiClient::new(network), &mut accessor, &creds.account_id, profile, None).await?;

    let near = NearClient::new(network);
    let Some(row) = stored_row(&near, &accessor.contract, profile, &creds.account_id).await? else {
        anyhow::bail!("no such secret (profile: {profile}) — nothing to change the access of");
    };
    // The read may have been answered by the wildcard row. `update_access` keys
    // on the exact accessor, so pricing one row and editing another ends in
    // `Secrets not found` after the user has already paid for a view.
    let Some(found) = row.get("accessor") else {
        anyhow::bail!("the chain's answer names no accessor, so which row it is cannot be told — nothing changed");
    };
    if found != &accessor.contract {
        anyhow::bail!(
            "no secret at this accessor (profile: {profile}); {} holds one, \
             and update_access edits the exact accessor it is given",
            format_accessor(found)
        );
    }

    // A condition is stored bytes, and the contract re-prices the row on every
    // edit. Attaching the whole estimate is always enough: the deposit already
    // held is credited towards it and the excess comes back in the same
    // transaction, so widening asks only for the growth and narrowing refunds.
    let ciphertext = row
        .get("encrypted_secrets")
        .and_then(Value::as_str)
        .unwrap_or_default();
    // `U128` reaches JSON as a decimal string, which is all this needs.
    // A price that cannot be fetched must not block the edit. Narrowing a
    // condition and swapping a name for one of equal length need no deposit at
    // all, and those are exactly the edits an owner makes in a hurry — a revoke
    // should not wait on a flaky view call. Sending nothing lets the contract
    // decide: it refuses only genuine growth, and says how much it wanted.
    let estimate: u128 = match near
        .view_call::<String>(
            "estimate_storage_cost",
            json!({
                "accessor": accessor.contract,
                "profile": profile,
                "owner": creds.account_id,
                "encrypted_secrets_base64": ciphertext,
                "access": new_access,
                "vault_id": Value::Null,
            }),
        )
        .await
    {
        Ok(quote) => quote.parse().unwrap_or(0),
        Err(e) => {
            eprintln!("Could not price this condition ({e}); sending without a deposit. \
                       A condition that grows the row will be refused, saying what it costs.");
            0
        }
    };

    let caller = ContractCaller::from_credentials(&creds, network)?;
    caller
        .call_contract(
            "update_access",
            json!({
                "accessor": accessor.contract,
                "profile": profile,
                "new_access": new_access,
            }),
            30_000_000_000_000u64,
            estimate,
        )
        .await
        .context("Failed to update the access condition")?;

    eprintln!("Access updated (profile: {profile}): {}", format_access(&new_access));
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

    let mut accessor = resolve_accessor(project, repo, branch, wasm_hash, project_config)?;
    // The store writes the normalised spelling, so the delete has to ask for
    // the same one — otherwise a secret cannot be removed with the flags that
    // created it, and its deposit stays staked.
    canonicalize_repo(
        &ApiClient::new(network),
        &mut accessor,
        &creds.account_id,
        profile,
        None,
    )
    .await?;

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
/// from what we sent — `project:{project_id}:{agent}` for a project,
/// `wasm_hash:{hash}:{agent}` for one build. Rebuilding
/// it and comparing turns "the key came back for a different agent" from
/// something invisible into a refusal. It cannot prove the key belongs
/// to the seed — only the holder of the master can — but it does catch
/// the answer being for another agent entirely, which is the shape a
/// mix-up takes.
fn check_agent_secret_pubkey(
    pubkey: &crate::api::AgentSecretPubkey,
    scope: &AgentSecretScope,
) -> Result<()> {
    if pubkey.agent_account.trim().is_empty() {
        anyhow::bail!("The coordinator returned no agent account to store the secret under");
    }

    let expected_seed = scope.seed(&pubkey.agent_account);
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
    scope: &AgentSecretScope,
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

    let expected_accessor = scope.accessor_json();
    let accessor = args
        .get("accessor")
        .context("The prepared call is missing its 'accessor' argument")?;
    if accessor != &expected_accessor {
        anyhow::bail!(
            "The prepared call stores the secret against {}, not against '{}'. \
             Nothing was signed.",
            format_accessor(accessor),
            scope.describe(),
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
    scope: AgentSecretScope,
    api_key: Option<&str>,
    vault_id: Option<String>,
    agent_pays: bool,
) -> Result<()> {
    let secrets_map = parse_secrets_json(&secrets_json)?;
    let secrets_str = Value::Object(secrets_map.clone()).to_string();

    let wallet_key = super::checks::resolve_wallet_key(api_key)?;
    let api = ApiClient::new(network);

    let pubkey = api
        .agent_secret_pubkey(&wallet_key, &scope)
        .await
        .context("Failed to get the agent's encryption key")?;
    check_agent_secret_pubkey(&pubkey, &scope)?;

    let encrypted = crypto::encrypt_secrets(&pubkey.pubkey, &secrets_str)?;

    let agent_account = if agent_pays {
        let stored = api
            .store_agent_secret(&wallet_key, &scope, &encrypted)
            .await?;
        eprintln!("Stored by the agent's own wallet, tx {}", stored.tx_hash);
        stored.agent_account
    } else {
        let creds = config::load_credentials(network)?;
        let prepared = api
            .prepare_agent_secret(&wallet_key, &scope, &encrypted, &creds.account_id)
            .await?;
        check_prepared_agent_secret(
            &prepared,
            &network.contract_id,
            &scope,
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
        "Secret for {agent_account} on {} (keys: {})",
        scope.describe(),
        keys.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(", "),
    );

    Ok(())
}

// ── Delete for an agent ──────────────────────────────────────────────

/// Refuse to sign a prepared DELETE that is not the one we asked for.
///
/// Every argument arrives over the same wire as the signature that makes
/// it valid, so none of it is trustworthy until checked — and a delete
/// cannot be undone by sending a corrected one afterwards. What is
/// checked is what the contract looks the secret up by: the receiver, the
/// method, the accessor and the name.
///
/// There is no deposit to bound here. `delete_agent_secret` is not
/// payable, so a call that attaches anything is refused by the runtime
/// before the contract runs — and this command attaches nothing.
fn check_prepared_agent_secret_delete(
    prepared: &crate::api::PreparedAgentSecretDelete,
    contract_id: &str,
    scope: &AgentSecretScope,
) -> Result<()> {
    if prepared.contract_id != contract_id {
        anyhow::bail!(
            "The prepared call is addressed to '{}', not to the OutLayer contract \
             '{contract_id}'. Nothing was signed.",
            prepared.contract_id,
        );
    }
    if prepared.method_name != "delete_agent_secret" {
        anyhow::bail!(
            "The prepared call invokes '{}', not 'delete_agent_secret'. Nothing was signed.",
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

    let expected_accessor = scope.accessor_json();
    let accessor = args
        .get("accessor")
        .context("The prepared call is missing its 'accessor' argument")?;
    if accessor != &expected_accessor {
        anyhow::bail!(
            "The prepared call deletes the secret held against {}, not the one against '{}'. \
             Nothing was signed.",
            format_accessor(accessor),
            scope.describe(),
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

    if str_arg("agent_pubkey")?.is_empty() || str_arg("wallet_signature")?.is_empty() {
        anyhow::bail!(
            "The prepared call carries no wallet signature. The contract would reject it; \
             nothing was signed."
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

/// `outlayer secrets delete-for-agent --project <owner>/<name>`
///
/// Removes the credential left for an agent and returns the storage
/// deposit to the account that sends the transaction — this one.
///
/// **The wallet key is the authority, not the account paying.** The
/// agent's key never moves, so a rotated `wk_` still speaks for it; a
/// wallet whose seed nobody kept can no longer delete its secrets at
/// all, only leave them.
pub async fn delete_for_agent(
    network: &NetworkConfig,
    scope: AgentSecretScope,
    api_key: Option<&str>,
    assume_yes: bool,
) -> Result<()> {
    // A delete cannot be undone by sending a corrected one afterwards, and the
    // plaintext is gone with it — nothing on chain or in the keystore keeps a
    // copy. So it asks, unless told not to. `--yes` exists because scripts have
    // no keyboard, not because the question is a formality.
    if !assume_yes {
        eprint!(
            "Delete the secret left for this agent on {}? This cannot be undone. [y/N]: ",
            scope.describe()
        );
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !matches!(input.trim(), "y" | "Y" | "yes" | "YES") {
            eprintln!("Nothing was deleted.");
            return Ok(());
        }
    }

    let wallet_key = super::checks::resolve_wallet_key(api_key)?;
    let api = ApiClient::new(network);
    let creds = config::load_credentials(network)?;

    let prepared = api
        .prepare_agent_secret_delete(&wallet_key, &scope, &creds.account_id)
        .await?;
    check_prepared_agent_secret_delete(&prepared, &network.contract_id, &scope)?;

    // The receiver is this network's contract id rather than the one the
    // answer named — they were just compared, and taking ours keeps the
    // destination of a signed transaction decided here.
    let caller = ContractCaller::from_credentials(&creds, network)?;
    let outcome = caller
        .call_contract(
            &prepared.method_name,
            prepared.args.clone(),
            prepared.gas.parse()?,
            0, // not payable; the storage deposit comes back to the sender
        )
        .await
        .context("Failed to delete the agent's secret")?;

    eprintln!(
        "Deleted the secret for {} on {}, tx {} — the storage deposit went back to {}",
        prepared.agent_account,
        scope.describe(),
        outcome.tx_hash.as_deref().unwrap_or("-"),
        creds.account_id,
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

/// A condition as a person reads it: the `--access` spelling wherever the
/// tree is one `parse_access` writes (`allow-all`, `whitelist:a,b@<deadline>`),
/// the structure in words otherwise — so `list` and every confirmation line
/// show what `--access` would take to reproduce the row.
fn format_access(access: &Value) -> String {
    if let Some(spelling) = whitelist_spelling(access) {
        return spelling;
    }
    match access.as_str() {
        Some("AllowAll") => return "allow-all".to_string(),
        Some(other) => return other.to_string(),
        None => {}
    }
    let Some(obj) = access.as_object() else {
        return access.to_string();
    };
    if let Some(until) = obj.get("ValidUntil").and_then(|v| v.get("until_ns")) {
        return format!("until {}", format_deadline(until));
    }
    if let Some(logic) = obj.get("Logic") {
        let joiner = match logic.get("operator").and_then(Value::as_str) {
            Some("And") => " and ",
            _ => " or ",
        };
        let parts: Vec<String> = logic
            .get("conditions")
            .and_then(Value::as_array)
            .map(|c| c.iter().map(format_access).collect())
            .unwrap_or_default();
        return format!("({})", parts.join(joiner));
    }
    if let Some(not) = obj.get("Not") {
        return format!("not {}", format_access(not.get("condition").unwrap_or(&Value::Null)));
    }
    if let Some(pattern) = obj.get("AccountPattern").and_then(|p| p.get("pattern")).and_then(Value::as_str) {
        return format!("pattern:{pattern}");
    }
    for chain_answered in ["NearBalance", "FtBalance", "NftOwned", "DaoMember"] {
        if let Some(inner) = obj.get(chain_answered) {
            return format!("{chain_answered}{inner}");
        }
    }
    access.to_string()
}

/// The inverse of [`parse_whitelist`]: `Some(spelling)` when the tree is one
/// it writes — a whitelist, a dated grant, or an `Or` of those — else `None`.
fn whitelist_spelling(access: &Value) -> Option<String> {
    fn accounts_of(v: &Value) -> Option<Vec<&str>> {
        v.get("Whitelist")?.get("accounts")?.as_array()?.iter().map(Value::as_str).collect()
    }
    fn dated_of(v: &Value) -> Option<String> {
        let logic = v.get("Logic")?;
        if logic.get("operator")?.as_str()? != "And" {
            return None;
        }
        let parts = logic.get("conditions")?.as_array()?;
        if parts.len() != 2 {
            return None;
        }
        let accounts = accounts_of(&parts[0])?;
        if accounts.len() != 1 {
            return None;
        }
        let until = parts[1].get("ValidUntil")?.get("until_ns")?;
        Some(format!("{}@{}", accounts[0], format_deadline(until)))
    }
    if let Some(accounts) = accounts_of(access) {
        return Some(format!("whitelist:{}", accounts.join(",")));
    }
    if let Some(dated) = dated_of(access) {
        return Some(format!("whitelist:{dated}"));
    }
    let logic = access.get("Logic")?;
    if logic.get("operator")?.as_str()? != "Or" {
        return None;
    }
    let mut entries: Vec<String> = Vec::new();
    for part in logic.get("conditions")?.as_array()? {
        if let Some(accounts) = accounts_of(part) {
            entries.extend(accounts.iter().map(|a| a.to_string()));
        } else {
            entries.push(dated_of(part)?);
        }
    }
    Some(format!("whitelist:{}", entries.join(",")))
}

/// `until_ns` as the contract writes it (a decimal string of nanoseconds) →
/// `YYYY-MM-DDTHH:MM:SSZ`; anything unreadable is shown as it is.
fn format_deadline(until_ns: &Value) -> String {
    let ns = match until_ns {
        Value::String(s) => s.parse::<u64>().ok(),
        Value::Number(n) => n.as_u64(),
        _ => None,
    };
    let Some(ns) = ns else {
        return until_ns.to_string();
    };
    let secs = (ns / 1_000_000_000) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3_600, (rem % 3_600) / 60, rem % 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{AgentSecretPubkey, PreparedAgentSecret, PreparedAgentSecretDelete};

    const PROJECT: &str = "connectors.outlayer.testnet/connector-probe";
    const AGENT: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    const CIPHERTEXT: &str = "AQIDBAUGBwgJCgsMDQ4PEA==";
    const CONTRACT: &str = "outlayer.testnet";
    /// A sha256, as the contract carries one: 64 hex characters.
    const WASM: &str = "0e0f0e0f0e0f0e0f0e0f0e0f0e0f0e0f0e0f0e0f0e0f0e0f0e0f0e0f0e0f0e0f";

    fn scope() -> AgentSecretScope {
        AgentSecretScope::Project(PROJECT.to_string())
    }

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
        check_agent_secret_pubkey(&pubkey_answer(), &scope()).unwrap();
        check_prepared_agent_secret(
            &prepared_call(),
            CONTRACT,
            &scope(),
            CIPHERTEXT,
            Some("vault.alice.testnet"),
        )
        .unwrap();
    }

    #[test]
    fn a_key_for_another_agent_is_refused() {
        let mut answer = pubkey_answer();
        answer.seed = format!("project:{PROJECT}:someone-else.testnet");
        let err = check_agent_secret_pubkey(&answer, &scope()).unwrap_err().to_string();
        assert!(err.contains("different secret"), "{err}");
    }

    #[test]
    fn a_key_for_another_project_is_refused() {
        // Same agent, same shape, another connector: the seed names the
        // project, so encrypting to this key would seal the credential
        // where a different connector's code can ask for it.
        let answer = pubkey_answer();
        let other = AgentSecretScope::Project("connectors.outlayer.testnet/other".to_string());
        assert!(check_agent_secret_pubkey(&answer, &other).is_err());
    }

    /// A project key answered for a WASM request, and the reverse.
    ///
    /// The two scopes seal to different seeds, so accepting the wrong
    /// answer stores a secret the reader will never be handed — and
    /// nothing downstream notices, because ciphertext is ciphertext.
    #[test]
    fn a_key_for_the_other_kind_of_scope_is_refused() {
        let wasm = AgentSecretScope::WasmHash(WASM.to_string());
        assert!(check_agent_secret_pubkey(&pubkey_answer(), &wasm).is_err());

        let mut answer = pubkey_answer();
        answer.seed = format!("wasm_hash:{WASM}:{AGENT}");
        assert!(check_agent_secret_pubkey(&answer, &scope()).is_err());
        // …and the same answer IS the right one for the WASM scope.
        check_agent_secret_pubkey(&answer, &wasm).unwrap();
    }

    /// A WASM-scoped store, end to end through both checks.
    #[test]
    fn a_wasm_scoped_call_is_accepted_on_its_own_terms() {
        let wasm = AgentSecretScope::WasmHash(WASM.to_string());

        let mut answer = pubkey_answer();
        answer.seed = format!("wasm_hash:{WASM}:{AGENT}");
        check_agent_secret_pubkey(&answer, &wasm).unwrap();

        let mut prepared = prepared_call();
        prepared.args["accessor"] = json!({ "WasmHash": { "hash": WASM } });
        check_prepared_agent_secret(
            &prepared,
            CONTRACT,
            &wasm,
            CIPHERTEXT,
            Some("vault.alice.testnet"),
        )
        .unwrap();

        // The project accessor is NOT interchangeable with it.
        assert!(check_prepared_agent_secret(
            &prepared,
            CONTRACT,
            &scope(),
            CIPHERTEXT,
            Some("vault.alice.testnet"),
        )
        .is_err());
    }

    /// The scope leaves this process in the field that MEANS it.
    ///
    /// The coordinator and the keystore rebuild the seed from these names, so a
    /// swap seals the secret where nothing will look for it — and the store
    /// still succeeds, which is what makes the mistake expensive.
    #[test]
    fn the_scope_travels_in_the_right_field() {
        assert_eq!(scope().query_pair(), ("project_id", PROJECT));
        assert_eq!(
            AgentSecretScope::WasmHash(WASM.to_string()).query_pair(),
            ("wasm_hash", WASM)
        );

        assert_eq!(scope().body_fields(), json!({ "project_id": PROJECT }));
        assert_eq!(
            AgentSecretScope::WasmHash(WASM.to_string()).body_fields(),
            json!({ "wasm_hash": WASM })
        );
    }

    /// One scope or the other; both, or neither, is a refusal.
    #[test]
    fn the_scope_flags_are_exclusive_and_required() {
        assert_eq!(
            AgentSecretScope::from_flags(Some(PROJECT.to_string()), None).unwrap(),
            AgentSecretScope::Project(PROJECT.to_string())
        );
        assert_eq!(
            AgentSecretScope::from_flags(None, Some(WASM.to_string())).unwrap(),
            AgentSecretScope::WasmHash(WASM.to_string())
        );
        assert!(AgentSecretScope::from_flags(None, None).is_err());
        assert!(
            AgentSecretScope::from_flags(Some(PROJECT.to_string()), Some(WASM.to_string()))
                .is_err()
        );
        // A blank flag is not a scope: it would seal to `project::{agent}`
        // and go on looking like a project scope forever after.
        assert!(AgentSecretScope::from_flags(Some("  ".to_string()), None).is_err());

        // A shouted hash is the same hash — the chain stores one spelling, and
        // a pasted upper-case sha256 must not seal to a seed nothing rebuilds.
        assert_eq!(
            AgentSecretScope::from_flags(None, Some(WASM.to_uppercase())).unwrap(),
            AgentSecretScope::WasmHash(WASM.to_string())
        );
    }

    #[test]
    fn a_nameless_agent_is_refused() {
        let mut answer = pubkey_answer();
        answer.agent_account = "  ".to_string();
        assert!(check_agent_secret_pubkey(&answer, &scope()).is_err());
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
                    &scope(),
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
        check_prepared_agent_secret(&prepared, CONTRACT, &scope(), CIPHERTEXT, None).unwrap();

        prepared.args["access"] = json!({ "Whitelist": ["attacker.testnet"] });
        assert!(
            check_prepared_agent_secret(&prepared, CONTRACT, &scope(), CIPHERTEXT, None).is_err()
        );
    }

    // ── The prepared DELETE ──────────────────────────────────────────

    fn prepared_delete() -> PreparedAgentSecretDelete {
        PreparedAgentSecretDelete {
            contract_id: CONTRACT.to_string(),
            method_name: "delete_agent_secret".to_string(),
            args: json!({
                "agent_pubkey": "ed25519:11111111111111111111111111111111",
                "accessor": { "Project": { "project_id": PROJECT } },
                "profile": AGENT,
                "wallet_signature": "ab".repeat(64),
            }),
            gas: "100000000000000".to_string(),
            agent_account: AGENT.to_string(),
        }
    }

    #[test]
    fn the_delete_this_request_asked_for_is_accepted() {
        check_prepared_agent_secret_delete(&prepared_delete(), CONTRACT, &scope()).unwrap();

        let wasm = AgentSecretScope::WasmHash(WASM.to_string());
        let mut prepared = prepared_delete();
        prepared.args["accessor"] = json!({ "WasmHash": { "hash": WASM } });
        check_prepared_agent_secret_delete(&prepared, CONTRACT, &wasm).unwrap();
    }

    /// A delete cannot be corrected afterwards, so every field of it is
    /// checked before anything is signed. A field that stops being
    /// checked fails here rather than by removing somebody's credential.
    #[test]
    fn a_prepared_delete_that_is_not_the_one_asked_for_is_refused() {
        let cases: Vec<(&str, Box<dyn Fn(&mut PreparedAgentSecretDelete)>)> = vec![
            (
                "another receiver",
                Box::new(|p| p.contract_id = "attacker.testnet".to_string()),
            ),
            (
                // The store's method under the delete's roof: the one
                // substitution that would still look like a working call.
                "the store method",
                Box::new(|p| p.method_name = "store_agent_secret".to_string()),
            ),
            (
                "another project's secret",
                Box::new(|p| {
                    p.args["accessor"] = json!({ "Project": { "project_id": "x.testnet/y" } })
                }),
            ),
            (
                "a WASM scope we did not ask for",
                Box::new(|p| p.args["accessor"] = json!({ "WasmHash": { "hash": WASM } })),
            ),
            (
                "another name",
                Box::new(|p| p.args["profile"] = json!("other.testnet")),
            ),
            (
                "no signature",
                Box::new(|p| p.args["wallet_signature"] = json!("")),
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
            let mut prepared = prepared_delete();
            tamper(&mut prepared);
            assert!(
                check_prepared_agent_secret_delete(&prepared, CONTRACT, &scope()).is_err(),
                "a prepared delete with {name} was accepted",
            );
        }
    }
}

#[cfg(test)]
mod repo_normalization_tests {
    use super::*;

    /// The contract accessor takes the spelling the keystore answered with.
    ///
    /// Not recomputed here: the rule lives in the keystore, and the reader
    /// (`accessor_to_contract_json`) applies it before asking the contract. A
    /// second copy of the rule in this binary would be the one that drifts.
    #[test]
    fn the_contract_accessor_takes_the_normalised_spelling() {
        let mut accessor = resolve_accessor(
            None,
            Some("https://github.com/alice/project.git".to_string()),
            Some("main".to_string()),
            None,
            None,
        )
        .unwrap();

        apply_repo_normalization(&mut accessor, Some("github.com/alice/project"));

        assert_eq!(
            accessor.contract,
            json!({"Repo": {"repo": "github.com/alice/project", "branch": "main"}}),
            "the on-chain accessor must carry the spelling the reader will ask for",
        );
    }

    /// The three shapes the verifier accepts, byte for byte.
    ///
    /// Taken from `keystore-worker/src/api.rs`, which builds the expected
    /// message the same way and refuses anything else. A section with nothing
    /// in it is ABSENT, not empty: writing `\nprotected:` with no names is what
    /// made every plain `secrets update` fail with "Invalid message format".
    #[test]
    fn the_update_message_omits_the_sections_it_has_nothing_for() {
        let keys = vec!["API_KEY".to_string(), "TOKEN".to_string()];
        let protected = vec!["PROTECTED_SEED".to_string()];

        assert_eq!(
            update_message("alice.near", "default", &keys, &[]),
            "Update Outlayer secrets for alice.near:default\nkeys:API_KEY,TOKEN",
            "no generated names means no protected section at all",
        );
        assert_eq!(
            update_message("alice.near", "default", &[], &protected),
            "Update Outlayer secrets for alice.near:default\nprotected:PROTECTED_SEED",
            "generating only means no keys section at all",
        );
        assert_eq!(
            update_message("alice.near", "default", &keys, &protected),
            "Update Outlayer secrets for alice.near:default\nkeys:API_KEY,TOKEN\nprotected:PROTECTED_SEED",
        );
        assert_eq!(
            update_message("alice.near", "default", &[], &[]),
            "Update Outlayer secrets for alice.near:default",
        );
    }

    /// A WasmHash accessor is spelled the way the contract stores and echoes
    /// it: lowercase. `set` and `update` compare the echoed accessor with
    /// this one byte for byte, so any other spelling would read as another
    /// row — NEW for `set`, with the default condition over the stored one.
    #[test]
    fn a_wasm_hash_is_lowercased_the_way_the_contract_stores_it() {
        let a = resolve_accessor(None, None, None, Some("  BEEF ".to_string()), None).unwrap();
        assert_eq!(a.contract, json!({"WasmHash": {"hash": "beef"}}));
        assert_eq!(a.coordinator, json!({"type": "WasmHash", "hash": "beef"}));
    }

    /// An answer without a normalised repo leaves the accessor alone — the
    /// other accessors have nothing to normalise, and a missing field must not
    /// blank the repo.
    #[test]
    fn an_absent_normalisation_changes_nothing() {
        let mut accessor =
            resolve_accessor(None, Some("github.com/a/b".to_string()), None, None, None).unwrap();
        let before = accessor.contract.clone();

        apply_repo_normalization(&mut accessor, None);
        assert_eq!(accessor.contract, before);

        let mut wasm = resolve_accessor(None, None, None, Some("beef".to_string()), None).unwrap();
        let before_wasm = wasm.contract.clone();
        apply_repo_normalization(&mut wasm, Some("github.com/a/b"));
        assert_eq!(
            wasm.contract, before_wasm,
            "a WASM accessor has no repo to re-spell",
        );
    }
}

#[cfg(test)]
mod access_parsing_tests {
    use super::*;

    /// The contract's shape: a struct variant with `accounts`, never a bare array.
    #[test]
    fn a_whitelist_is_the_contracts_struct_variant() {
        assert_eq!(
            parse_access("whitelist:alice.near,bob.near").unwrap(),
            json!({ "Whitelist": { "accounts": ["alice.near", "bob.near"] } })
        );
        assert_eq!(parse_access("allow-all").unwrap(), json!("AllowAll"));
        assert!(parse_access("whitelist:").is_err());
        assert!(parse_access("whitelist:a.near,").is_err());
        assert!(parse_access("friends").is_err());
    }

    /// Dated entries become their own `And[Whitelist, ValidUntil]`, joined by
    /// `Or` with the undated ones; a lone group is written bare.
    #[test]
    fn dated_entries_compose_into_the_grant_tree() {
        let tree = parse_access("whitelist:me.near,agent.near@2026-10-01T00:00:00Z").unwrap();
        assert_eq!(
            tree,
            json!({ "Logic": { "operator": "Or", "conditions": [
                { "Whitelist": { "accounts": ["me.near"] } },
                { "Logic": { "operator": "And", "conditions": [
                    { "Whitelist": { "accounts": ["agent.near"] } },
                    { "ValidUntil": { "until_ns": "1790812800000000000" } }
                ]}}
            ]}})
        );
        let lone = parse_access("whitelist:agent.near@2026-10-01T00:00:00Z").unwrap();
        assert_eq!(lone["Logic"]["operator"], "And", "one dated entry is the And itself");
        assert!(parse_access("whitelist:@2026-10-01").is_err(), "an empty account is refused");
        assert!(parse_access("whitelist:a.near@soon").is_err(), "a non-date is refused");
    }

    #[test]
    fn deadlines_read_as_utc_instants() {
        assert_eq!(parse_deadline("1970-01-01").unwrap(), 0);
        assert_eq!(parse_deadline("2023-11-14T22:13:20Z").unwrap(), 1_700_000_000_000_000_000);
        assert_eq!(parse_deadline("2000-02-29").unwrap(), 951_782_400_000_000_000, "a leap day");
        assert!(parse_deadline("2026-10-01T00:00:00").is_err(), "a time without Z is ambiguous");
        // A bare number is refused, and the refusal names both spellings. Read as
        // epoch seconds, `20261001` would mean August 1970 to somebody who meant
        // 2026-10-01, and the grant would be born expired.
        for bare in ["1700000000", "20261001", "2026", ""] {
            let why = parse_deadline(bare).expect_err(bare).to_string();
            assert!(why.contains("2026-10-01") && why.contains("2026-10-01T00:00:00Z"), "{why}");
        }
        assert!(parse_deadline("2026-13-01").is_err());
        assert!(parse_deadline("1969-12-31").is_err());
        assert!(parse_deadline("2026-02-30").is_err(), "February has no 30th");
        assert!(parse_deadline("2026-02-29").is_err(), "2026 is not a leap year");
        assert!(parse_deadline("2026-04-31").is_err());
        assert!(parse_deadline("2024-02-29").is_ok(), "2024 is");
        assert_eq!(civil_from_days(days_from_civil(2023, 11, 14)), (2023, 11, 14));
    }

    /// No `--access`: an existing row keeps its condition; a new project row is
    /// the signer's alone; a new repo or hash row is everyone's.
    #[test]
    fn the_default_follows_the_row() {
        let project = json!({ "Project": { "project_id": "me.near/app" } });
        let repo = json!({ "Repo": { "repo": "github.com/x/y", "branch": null } });
        let kept = json!({ "Whitelist": { "accounts": ["other.near"] } });
        assert_eq!(default_access(Some(kept.clone()), &project, "me.near").0, kept);
        assert_eq!(
            default_access(None, &project, "me.near").0,
            json!({ "Whitelist": { "accounts": ["me.near"] } })
        );
        assert_eq!(default_access(None, &repo, "me.near").0, json!("AllowAll"));
    }

    /// What `list` prints is what `--access` takes: the spelling round-trips
    /// for every shape the CLI writes, and the contract's struct-variant
    /// whitelist is rendered as a whitelist, not as raw JSON.
    #[test]
    fn a_stored_condition_is_shown_as_its_access_spelling() {
        for spelling in [
            "allow-all",
            "whitelist:alice.near,bob.near",
            "whitelist:me.near,agent.near@2026-10-01T00:00:00Z",
            "whitelist:agent.near@2026-10-01T00:00:00Z",
            "whitelist:a.near@2026-10-01T00:00:00Z,b.near@2027-01-01T12:30:00Z",
        ] {
            assert_eq!(format_access(&parse_access(spelling).unwrap()), spelling);
        }
        assert_eq!(
            format_access(&json!({ "Whitelist": { "accounts": ["alice.near"] } })),
            "whitelist:alice.near"
        );
        let hand_written = json!({ "Logic": { "operator": "And", "conditions": [
            { "AccountPattern": { "pattern": ".*\\.near" } },
            { "Not": { "condition": { "ValidUntil": { "until_ns": "0" } } } }
        ]}});
        assert_eq!(format_access(&hand_written), "(pattern:.*\\.near and not until 1970-01-01T00:00:00Z)");
    }
}
