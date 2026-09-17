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

/// The condition with every `WasmHash` leaf removed and the nodes that held
/// them simplified away: a `Logic` left with one branch becomes that branch,
/// one left with none disappears, and a `Not` over a vanished subtree goes with
/// it. `None` when nothing but build leaves remained.
///
/// Exists so that re-locking REPLACES the lock. Without it, `set --build`
/// against a row that is already locked takes the stored condition as "kept"
/// and wraps it again, so every release nests one `And` deeper and pays for
/// the extra bytes — `And[And[And[whitelist, build], build], build]`.
fn without_build_leaves(condition: &Value) -> Option<Value> {
    if condition.get("WasmHash").is_some() {
        return None;
    }
    if let Some(logic) = condition.get("Logic") {
        let kept: Vec<Value> = logic
            .get("conditions")
            .and_then(Value::as_array)
            .map(|cs| cs.iter().filter_map(without_build_leaves).collect())
            .unwrap_or_default();
        return match kept.len() {
            0 => None,
            1 => kept.into_iter().next(),
            _ => Some(json!({
                "Logic": {
                    "operator": logic.get("operator").cloned().unwrap_or_else(|| json!("And")),
                    "conditions": kept,
                }
            })),
        };
    }
    if let Some(not) = condition.get("Not") {
        let inner = without_build_leaves(not.get("condition")?)?;
        return Some(json!({ "Not": { "condition": inner } }));
    }
    Some(condition.clone())
}

/// The condition, locked to one build: `And[condition, WasmHash(hash)]`, or
/// the `WasmHash` leaf alone when what remained admitted everyone — an AND
/// with AllowAll says nothing AllowAll did not. Any lock the condition already
/// carried is replaced, not nested. The hash is the SHA-256 of the WebAssembly
/// bytes as 64 hex characters, the form the worker reports and the contract
/// stores (lowercased here, as the contract requires); anything else is
/// refused rather than stored as a leaf that admits nobody.
fn lock_to_build(condition: Value, build: Option<&str>) -> Result<Value> {
    let Some(build) = build else { return Ok(condition) };
    let hash = build.trim().to_ascii_lowercase();
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        anyhow::bail!(
            "--build must be the SHA-256 of the build as 64 hex characters \
             (\"Executed binary\" in an execution's details on the dashboard)"
        );
    }
    let leaf = json!({ "WasmHash": { "hash": hash } });
    match without_build_leaves(&condition) {
        None => Ok(leaf),
        Some(base) if base == json!("AllowAll") => Ok(leaf),
        Some(base) => Ok(json!({ "Logic": { "operator": "And", "conditions": [base, leaf] } })),
    }
}

/// Every `WasmHash` leaf in a stored condition, as the chain returned it.
fn build_locks_of(access: &Value) -> Vec<String> {
    let mut out = Vec::new();
    fn walk(node: &Value, out: &mut Vec<String>) {
        if let Some(hash) = node.get("WasmHash").and_then(|w| w.get("hash")).and_then(Value::as_str) {
            out.push(hash.to_string());
            return;
        }
        if let Some(cs) = node.get("Logic").and_then(|l| l.get("conditions")).and_then(Value::as_array) {
            cs.iter().for_each(|c| walk(c, out));
        }
        if let Some(inner) = node.get("Not").and_then(|n| n.get("condition")) {
            walk(inner, out);
        }
    }
    walk(access, &mut out);
    out
}

// ── The calling-account rule ─────────────────────────────────────────
//
// `Predecessor{Whitelist[accounts]}` ANDed onto the condition: a call is
// admitted only when the account that CALLED the contract — the relaying
// contract, or the signer on a direct call — is one of `accounts`. Every other
// leaf is judged on the signer, so a contract the owner signs any transaction
// to can relay a call naming the owner's row. `--direct` names the row's own
// readers, so each reads only by calling straight in; `--via` names contracts
// calls may come through as well — a DAO, a router. Written and replaced the
// way a build lock is: one rule, a direct conjunct of the root AND. A rule
// under an OR or a NOT is the owner's own composition and is left where it is
// (lifting it out and re-ANDing it would turn an OR into an AND). Over HTTPS
// nothing relays a call and the payment key's owner is judged as the caller.

/// Every account the condition names as a reader: the whitelists reachable
/// through `Logic` nodes — not those under a `Not` (a denylist names nobody),
/// nor inside a calling-account rule (those are callers, not readers).
fn named_readers(condition: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    fn walk(node: &Value, out: &mut Vec<String>) {
        if let Some(accounts) = node.get("Whitelist").and_then(|w| w.get("accounts")).and_then(Value::as_array) {
            for a in accounts.iter().filter_map(Value::as_str) {
                if !out.iter().any(|x| x == a) {
                    out.push(a.to_string());
                }
            }
            return;
        }
        if let Some(cs) = node.get("Logic").and_then(|l| l.get("conditions")).and_then(Value::as_array) {
            cs.iter().for_each(|c| walk(c, out));
        }
    }
    walk(condition, &mut out);
    out
}

/// A `Predecessor` holding nothing but a whitelist: its accounts.
fn plain_callers_of(node: &Value) -> Option<Vec<String>> {
    node.get("Predecessor")?
        .get("condition")?
        .get("Whitelist")?
        .get("accounts")?
        .as_array()?
        .iter()
        .map(|a| a.as_str().map(str::to_string))
        .collect()
}

/// How many `Predecessor` nodes sit anywhere in the tree.
fn caller_rules_anywhere(node: &Value) -> usize {
    if node.get("Predecessor").is_some() {
        return 1;
    }
    if let Some(cs) = node.get("Logic").and_then(|l| l.get("conditions")).and_then(Value::as_array) {
        return cs.iter().map(caller_rules_anywhere).sum();
    }
    node.get("Not").and_then(|n| n.get("condition")).map(caller_rules_anywhere).unwrap_or(0)
}

/// Whether any `Predecessor` sits anywhere in the tree.
fn has_caller_rule(node: &Value) -> bool {
    caller_rules_anywhere(node) > 0
}

/// A calling-account rule these flags cannot own: one under an OR or a NOT,
/// or one that is not a plain whitelist. `--direct`/`--via` would AND a rule
/// of their own over it and refuse whatever that branch admitted;
/// `--drop-callers` would leave it standing. Refused, naming it, rather
/// than rewritten around.
fn refuse_a_rule_these_flags_cannot_own(condition: &Value, flag: &str) -> Result<()> {
    let plain_on_spine = {
        fn count(node: &Value) -> usize {
            if plain_callers_of(node).is_some() {
                return 1;
            }
            match node.get("Logic") {
                Some(logic) if logic.get("operator").and_then(Value::as_str) == Some("And") => logic
                    .get("conditions")
                    .and_then(Value::as_array)
                    .map(|cs| cs.iter().map(count).sum())
                    .unwrap_or(0),
                _ => 0,
            }
        }
        count(condition)
    };
    if caller_rules_anywhere(condition) > plain_on_spine {
        anyhow::bail!(
            "this condition carries a calling-account rule {flag} cannot rewrite — under an OR or a NOT, or \
             holding something other than a whitelist: {}. Restate the whole condition with --access, or edit \
             it on the dashboard under Full condition.",
            format_access(condition)
        );
    }
    Ok(())
}

/// The accounts of the plain calling-account rules on the root's AND spine,
/// as the chain returned them.
fn callers_of(access: &Value) -> Vec<String> {
    let mut out = Vec::new();
    fn walk(node: &Value, out: &mut Vec<String>) {
        if let Some(accounts) = plain_callers_of(node) {
            out.extend(accounts);
            return;
        }
        if let Some(logic) = node.get("Logic") {
            if logic.get("operator").and_then(Value::as_str) == Some("And") {
                if let Some(cs) = logic.get("conditions").and_then(Value::as_array) {
                    cs.iter().for_each(|c| walk(c, out));
                }
            }
        }
    }
    walk(access, &mut out);
    out
}

/// The condition with the plain calling-account rules on its AND spine removed
/// and emptied nodes collapsed; `AllowAll` when nothing remains — a condition
/// that was only ever such a rule named nobody, so everyone was admitted from
/// the accounts it allowed.
fn without_caller_rules(condition: &Value) -> Value {
    fn prune(node: &Value) -> Option<Value> {
        if plain_callers_of(node).is_some() {
            return None;
        }
        if let Some(logic) = node.get("Logic") {
            if logic.get("operator").and_then(Value::as_str) == Some("And") {
                let kept: Vec<Value> = logic
                    .get("conditions")
                    .and_then(Value::as_array)
                    .map(|cs| cs.iter().filter_map(prune).collect())
                    .unwrap_or_default();
                return match kept.len() {
                    0 => None,
                    1 => kept.into_iter().next(),
                    _ => Some(json!({ "Logic": { "operator": "And", "conditions": kept } })),
                };
            }
        }
        Some(node.clone())
    }
    prune(condition).unwrap_or_else(|| json!("AllowAll"))
}

/// The condition with one calling-account rule naming `accounts`, replacing
/// any plain rule it carried: `And[condition, Predecessor{Whitelist[accounts]}]`,
/// or the rule alone over `AllowAll`.
fn with_callers(condition: &Value, accounts: &[String]) -> Value {
    let base = without_caller_rules(condition);
    let rule = json!({ "Predecessor": { "condition": { "Whitelist": { "accounts": accounts } } } });
    if base == json!("AllowAll") {
        rule
    } else {
        json!({ "Logic": { "operator": "And", "conditions": [base, rule] } })
    }
}

/// The calling accounts the flags ask for: with `--direct`, the readers the
/// condition names; with `--via`, those contracts as well — and with
/// `--direct` alone, the contracts the row's rule already named beside its
/// readers, so a grant made with `--access … --direct` does not silently
/// drop a `--via` given earlier. `None` when neither flag was given. A
/// condition that names nobody has nobody to require direct calls from, and
/// says so rather than storing a rule that admits no call.
fn callers_from_flags(condition: &Value, stored: Option<&Value>, direct: bool, via: Option<&str>) -> Result<Option<Vec<String>>> {
    if !direct && via.is_none() {
        return Ok(None);
    }
    let named = named_readers(condition);
    let mut accounts: Vec<String> = if direct { named.clone() } else { Vec::new() };
    if direct && via.is_none() {
        // The contracts the STORED rule named beyond the readers it had: the
        // owner's own `--via` list, carried across an edit that restates who
        // reads. Read from the stored row rather than from `condition`,
        // because `--access` builds a fresh tree that carries no rule at all
        // — and a grant made with `--access … --direct` would otherwise drop
        // the DAO the owner composes through, silently.
        if let Some(stored) = stored {
            let was_reader = named_readers(stored);
            for a in callers_of(stored) {
                if !was_reader.contains(&a) && !accounts.contains(&a) {
                    accounts.push(a);
                }
            }
        }
    }
    if let Some(list) = via {
        for entry in list.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                anyhow::bail!("--via holds an empty entry; use --via dao.near,router.near");
            }
            if !accounts.iter().any(|a| a == entry) {
                accounts.push(entry.to_string());
            }
        }
    }
    if accounts.is_empty() {
        anyhow::bail!(
            "--direct needs a condition that names somebody: this one ({}) names no reader, so there is \
             nobody to require direct calls from. Name accounts with --access whitelist:…, or the contracts \
             calls may come through with --via",
            format_access(condition)
        );
    }
    Ok(Some(accounts))
}

/// The guard both commands share: `--access` replaces the stored condition,
/// a calling-account rule included, and losing one is not what someone
/// changing readers expects.
fn refuse_silent_caller_rule_loss(stored: Option<&Value>, profile: &str, direct: bool, via: Option<&str>, drop_callers: bool) -> Result<()> {
    let Some(stored) = stored else { return Ok(()) };
    if has_caller_rule(stored) && !direct && via.is_none() && !drop_callers {
        anyhow::bail!(
            "{profile} is judged on the calling account ({}) and --access would replace that condition, \
             dropping the rule. Pass --direct and/or --via to keep such a rule on the new condition, or \
             --drop-callers to remove it deliberately.",
            format_access(stored)
        );
    }
    Ok(())
}

/// Apply the calling-account flags to a decided condition. The `bool` says
/// whether anything changed.
fn apply_caller_flags(access: Value, stored: Option<&Value>, direct: bool, via: Option<&str>, drop_callers: bool) -> Result<(Value, bool)> {
    if drop_callers {
        refuse_a_rule_these_flags_cannot_own(&access, "--drop-callers")?;
        let stripped = without_caller_rules(&access);
        let changed = stripped != access;
        if changed {
            eprintln!("Calling-account rule removed: {}", format_access(&stripped));
        }
        return Ok((stripped, changed));
    }
    if direct || via.is_some() {
        refuse_a_rule_these_flags_cannot_own(&access, if direct { "--direct" } else { "--via" })?;
    }
    match callers_from_flags(&access, stored, direct, via)? {
        None => Ok((access, false)),
        Some(accounts) => {
            let ruled = with_callers(&access, &accounts);
            // Read back off the tree that will be stored, not off the request.
            eprintln!("Calls admitted only from: {}", callers_of(&ruled).join(", "));
            Ok((ruled, true))
        }
    }
}

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
fn default_access(existing: Option<Value>, accessor_contract: &Value, owner: &str) -> (Value, AccessOrigin) {
    match existing {
        Some(access) => (access, AccessOrigin::Kept),
        None if accessor_contract.get("Project").is_some() => (whitelist_of(&[owner]), AccessOrigin::NewProjectRow),
        None => (json!("AllowAll"), AccessOrigin::NewRow),
    }
}

/// Which condition a `set` without `--access` writes, given what the chain
/// answered when asked for this profile.
///
/// The two refusals are the point. A row the chain answered for under ANOTHER
/// accessor is a wildcard row this write would SHADOW, or two normalisers
/// disagreeing about one repo; taking the new-row default there opens the value
/// to everyone and hides the row that was closed, on a command whose subject
/// was the value and not its readers. An answer that names no accessor at all
/// is the same problem without a name for it. Either way the caller is told
/// what to pass rather than having the readers decided for them.
fn condition_for_set(
    row: Option<&Value>,
    accessor: &Value,
    profile: &str,
    signer: &str,
) -> Result<(Value, AccessOrigin)> {
    let existing = match row {
        None => None,
        Some(r) => {
            let Some(found) = r.get("accessor") else {
                anyhow::bail!("the chain's answer names no accessor, so which row it is cannot be told — pass --access to store anyway");
            };
            if found != accessor {
                anyhow::bail!(
                    "{profile} is stored under a different accessor ({}), so this would write a NEW row \
                     that shadows it. Pass --access to say who may read the new row — \
                     `--access whitelist:{signer}` keeps it to you — or store under that accessor instead.",
                    format_accessor(found)
                );
            }
            r.get("access").cloned()
        }
    };
    Ok(default_access(existing, accessor, signer))
}

/// Where a condition written without `--access` came from. A value rather than
/// the sentence, because one caller ACTS on it — a rotation that forwards a
/// stored condition explains a refusal about that condition — and a rule that
/// reads its own wording breaks the moment the wording is edited.
#[derive(Debug, PartialEq)]
enum AccessOrigin {
    Kept,
    NewProjectRow,
    NewRow,
}

impl AccessOrigin {
    /// How the choice is worded for the person running the command.
    fn why(&self) -> &'static str {
        match self {
            AccessOrigin::Kept => "kept the stored condition",
            AccessOrigin::NewProjectRow => "new project row: only you",
            AccessOrigin::NewRow => "new row: everyone",
        }
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
    build: Option<&str>,
    drop_build: bool,
    direct: bool,
    via: Option<&str>,
    drop_callers: bool,
) -> Result<()> {
    let creds = config::load_credentials(network)?;
    if (direct || via.is_some()) && drop_callers {
        anyhow::bail!("--direct/--via and --drop-callers ask for opposite things; pass one");
    }

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
    // A rotation forwards the condition the row already holds. If the contract
    // refuses THAT, the refusal is about a rule this command never mentioned,
    // so it is worth saying where the rule lives and what fixes it.
    let mut kept_condition = false;
    // The row as it stands, kept for the calling-account flags: `--direct`
    // carries the contracts its rule already named across an `--access` edit.
    let stored_access: Option<Value>;
    let access = match explicit_access {
        // An explicit condition REPLACES the stored one — including any build
        // lock it carried. That is what `--access` means, but losing a lock is
        // not what someone changing readers expects, and nothing in the result
        // would say it happened. So the row is read first and the swap refused
        // unless the caller says which build the new condition is for, or says
        // out loud that the lock is to go.
        Some(access) => {
            canonicalize_repo(&api, &mut accessor, &creds.account_id, profile, vault_id.as_deref()).await?;
            let row = stored_row(&NearClient::new(network), &accessor.contract, profile, &creds.account_id).await?;
            // Only a row at the very accessor about to be written counts. A
            // branch-specific read is answered by the WILDCARD row when no
            // branch row exists, and a lock on that row says nothing about the
            // one this command creates — refusing on it would block a write
            // that could not have unlocked anything, naming another row.
            stored_access = row
                .as_ref()
                .filter(|r| r.get("accessor") == Some(&accessor.contract))
                .and_then(|r| r.get("access"))
                .cloned();
            let locked_to = stored_access.as_ref().map(build_locks_of).unwrap_or_default();
            if !locked_to.is_empty() && build.is_none() && !drop_build {
                anyhow::bail!(
                    "{profile} is locked to build {} and --access would replace that condition, \
                     unlocking the row. Pass --build <sha256> to keep it locked (to that build or \
                     another), or --drop-build to remove the lock deliberately.",
                    locked_to[0]
                );
            }
            refuse_silent_caller_rule_loss(stored_access.as_ref(), profile, direct, via, drop_callers)?;
            access
        }
        None => {
            canonicalize_repo(&api, &mut accessor, &creds.account_id, profile, vault_id.as_deref()).await?;
            // `get_secrets` answers a branch-specific read with the WILDCARD row
            // when no branch row exists, and echoes the accessor it actually
            // found. Copying that condition onto a new branch row and calling it
            // "kept" would be a lie: the wildcard row is a different row, and it
            // keeps its own condition. Only a row at the very accessor about to
            // be written counts as existing.
            let row = stored_row(&NearClient::new(network), &accessor.contract, profile, &creds.account_id).await?;
            stored_access = row
                .as_ref()
                .filter(|r| r.get("accessor") == Some(&accessor.contract))
                .and_then(|r| r.get("access"))
                .cloned();
            let (access, origin) =
                condition_for_set(row.as_ref(), &accessor.contract, profile, &creds.account_id)?;
            kept_condition = origin == AccessOrigin::Kept;
            eprintln!("Access: {} ({}; pass --access to choose)", format_access(&access), origin.why());
            access
        }
    };
    // `--build` narrows whatever was decided above, a kept condition included:
    // the row's readers do change, so it is no longer "kept".
    let access = if drop_build {
        // Asked for out loud, so it happens rather than merely being excused.
        let stripped = without_build_leaves(&access).unwrap_or_else(|| json!("AllowAll"));
        if stripped != access {
            kept_condition = false;
            eprintln!("Build lock removed: {}", format_access(&stripped));
        }
        stripped
    } else {
        lock_to_build(access, build)?
    };
    if build.is_some() {
        kept_condition = false;
        eprintln!("Locked to build: {}", format_access(&access));
    }
    // The calling-account rule goes on last, over everything decided above —
    // readers, dates, the build lock — so `--direct` names exactly the readers
    // this row will have.
    let (access, callers_changed) = apply_caller_flags(access, stored_access.as_ref(), direct, via, drop_callers)?;
    if callers_changed {
        kept_condition = false;
    }

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
        .map_err(|e| {
            if kept_condition && format!("{e:#}").to_lowercase().contains("condition") {
                e.context(
                    "this rotation kept the condition the row already holds, and the contract \
                     refuses it. Narrow the readers first — `outlayer secrets access …` or the \
                     dashboard's Access screen — then store the new value",
                )
            } else {
                e
            }
        })
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
        .map_err(|e| {
            // `update` re-presents the row's own condition, so a refusal about
            // it is about a rule this command never mentioned.
            if format!("{e:#}").to_lowercase().contains("condition") {
                e.context(
                    "this update kept the condition the row already holds, and the contract \
                     refuses it. Narrow the readers first — `outlayer secrets access …` or the \
                     dashboard's Access screen — then update the value",
                )
            } else {
                e
            }
        })
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
    access_str: Option<&str>,
    build: Option<&str>,
    drop_build: bool,
    direct: bool,
    via: Option<&str>,
    drop_callers: bool,
) -> Result<()> {
    let creds = config::load_credentials(network)?;
    if access_str.is_none() && build.is_none() && !drop_build && !direct && via.is_none() && !drop_callers {
        anyhow::bail!(
            "nothing to change: pass --access to set who may read, --build / --drop-build for the build lock, \
             --direct / --via / --drop-callers for the calling-account rule, or a combination"
        );
    }
    if build.is_some() && drop_build {
        anyhow::bail!("--build and --drop-build ask for opposite things; pass one");
    }
    if (direct || via.is_some()) && drop_callers {
        anyhow::bail!("--direct/--via and --drop-callers ask for opposite things; pass one");
    }

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

    // `--build` alone moves the lock and keeps the readers: the stored condition
    // is taken, its build leaves are lifted off by `lock_to_build`, and the new
    // one goes on. Without this an owner re-pointing a lock has to restate the
    // whole condition, and a slip to `allow-all` widens the row while reading
    // like a narrowing edit.
    let stored_locks = row.get("access").map(build_locks_of).unwrap_or_default();
    let base = match access_str {
        // Replacing the condition drops any lock it carried, and this is the
        // command the docs send an owner to when MOVING a lock — so the slip is
        // most likely here, not in `set`. Same guard, same two ways past it.
        Some(text) => {
            if !stored_locks.is_empty() && build.is_none() && !drop_build {
                anyhow::bail!(
                    "{profile} is locked to build {} and --access would replace that condition, \
                     unlocking the row. Pass --build <sha256> to keep it locked (to that build or \
                     another), or --drop-build to remove the lock deliberately.",
                    stored_locks[0]
                );
            }
            refuse_silent_caller_rule_loss(row.get("access"), profile, direct, via, drop_callers)?;
            parse_access(text)?
        }
        None => row
            .get("access")
            .cloned()
            .context("the stored row carries no access condition to keep")?,
    };
    let new_access = if drop_build && build.is_none() {
        without_build_leaves(&base).unwrap_or_else(|| json!("AllowAll"))
    } else {
        lock_to_build(base, build)?
    };
    // `--direct` alone re-derives the rule from the readers the row keeps, so
    // a grant or a revocation made with `--access` is followed by the rule.
    let (new_access, callers_changed) = apply_caller_flags(new_access, row.get("access"), direct, via, drop_callers)?;
    if drop_callers && !callers_changed && access_str.is_none() && build.is_none() && !drop_build {
        anyhow::bail!("{profile} carries no calling-account rule to drop — nothing to change");
    }
    eprintln!("Access: {}", format_access(&new_access));

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
    if let Some(hash) = obj.get("WasmHash").and_then(|w| w.get("hash")).and_then(Value::as_str) {
        return format!("build:{hash}");
    }
    if let Some(accounts) = plain_callers_of(access) {
        return format!("from:{}", accounts.join(","));
    }
    if let Some(inner) = obj.get("Predecessor").and_then(|p| p.get("condition")) {
        return format!("from:({})", format_access(inner));
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

    fn project_accessor() -> Value {
        json!({ "Project": { "project_id": "me.near/app" } })
    }

    fn row_under(accessor: Value, access: Value) -> Value {
        json!({ "accessor": accessor, "access": access, "encrypted_secrets": "x" })
    }

    /// A rotation forwards the condition the row already holds, and says so.
    #[test]
    fn a_row_at_this_very_accessor_keeps_its_condition() {
        let kept = json!({ "Whitelist": { "accounts": ["me.near", "agent.near"] } });
        let (access, origin) = condition_for_set(
            Some(&row_under(project_accessor(), kept.clone())),
            &project_accessor(),
            "mercury",
            "me.near",
        )
        .expect("the row is this row");
        assert_eq!(access, kept, "a rotation must not edit who may read");
        assert_eq!(origin, AccessOrigin::Kept);
    }

    /// The whole point of reading the chain first: the answer may be the
    /// WILDCARD row, which is a different row with a condition of its own.
    /// Writing here with the new-row default would open the value to everyone
    /// and hide the row that was closed.
    #[test]
    fn a_row_under_another_accessor_refuses_instead_of_shadowing_it() {
        let closed = json!({ "Whitelist": { "accounts": ["me.near"] } });
        let wildcard = json!({ "Repo": { "repo": "github.com/me/app", "branch": null } });
        let branch = json!({ "Repo": { "repo": "github.com/me/app", "branch": "next" } });
        let err = condition_for_set(
            Some(&row_under(wildcard, closed)),
            &branch,
            "mercury",
            "me.near",
        )
        .expect_err("a different accessor is a different row");
        let message = format!("{err:#}");
        assert!(message.contains("different accessor"), "{message}");
        assert!(message.contains("shadows it"), "{message}");
        assert!(message.contains("--access whitelist:me.near"), "the refusal must say what to pass: {message}");
    }

    #[test]
    fn an_answer_that_names_no_accessor_refuses_too() {
        let err = condition_for_set(
            Some(&json!({ "access": "AllowAll" })),
            &project_accessor(),
            "mercury",
            "me.near",
        )
        .expect_err("an answer that cannot say which row it is decides nothing");
        assert!(format!("{err:#}").contains("names no accessor"));
    }

    /// The control: no row at all is a NEW row, and a new project row is the
    /// signer's alone. Without this the two refusals above would only say
    /// "this function returns errors".
    #[test]
    fn no_row_at_all_is_a_new_row() {
        let (access, origin) =
            condition_for_set(None, &project_accessor(), "mercury", "me.near").expect("a new row");
        assert_eq!(access, whitelist_of(&["me.near"]));
        assert_eq!(origin, AccessOrigin::NewProjectRow);
    }

    /// A live run has to reach the chain through a KEYED endpoint; a key is
    /// never a default, so the environment is the only place one comes from.
    #[test]
    fn the_environment_can_name_the_rpc_and_a_blank_value_does_not() {
        use crate::config::chosen_rpc_url;
        let default = "https://test.rpc.fastnear.com";
        assert_eq!(chosen_rpc_url(None, default), default);
        assert_eq!(chosen_rpc_url(Some(String::new()), default), default, "an empty value is an unset one");
        assert_eq!(chosen_rpc_url(Some("   ".to_string()), default), default, "and so is a blank one");
        assert_eq!(
            chosen_rpc_url(Some("  https://rpc.example/key  ".to_string()), default),
            "https://rpc.example/key",
            "a named endpoint wins over the default, trimmed"
        );
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

/// `--build` locks a row to one build, and re-locking REPLACES the lock.
///
/// The nesting this guards against is not cosmetic. `set` without `--access`
/// keeps the stored condition, so a second `set --build` takes a condition
/// that already carries a leaf and wraps it again — one `And` deeper and a few
/// dozen more paid-for bytes on every release, forever.
#[cfg(test)]
mod the_build_lock_replaces_rather_than_nests {
    use super::*;

    const H1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const H2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn leaf(hash: &str) -> Value {
        json!({ "WasmHash": { "hash": hash } })
    }
    fn wl() -> Value {
        json!({ "Whitelist": { "accounts": ["me.near"] } })
    }
    /// Every `WasmHash` leaf anywhere in the tree.
    fn leaves(condition: &Value) -> Vec<String> {
        let mut out = Vec::new();
        fn walk(node: &Value, out: &mut Vec<String>) {
            if let Some(h) = node.get("WasmHash").and_then(|w| w.get("hash")).and_then(Value::as_str) {
                out.push(h.to_string());
                return;
            }
            if let Some(cs) = node.get("Logic").and_then(|l| l.get("conditions")).and_then(Value::as_array) {
                cs.iter().for_each(|c| walk(c, out));
            }
            if let Some(inner) = node.get("Not").and_then(|n| n.get("condition")) {
                walk(inner, out);
            }
        }
        walk(condition, &mut out);
        out
    }

    #[test]
    fn no_build_leaves_the_condition_alone() {
        assert_eq!(lock_to_build(wl(), None).unwrap(), wl());
    }

    #[test]
    fn a_first_lock_ands_the_leaf_on() {
        let locked = lock_to_build(wl(), Some(H1)).unwrap();
        assert_eq!(locked, json!({ "Logic": { "operator": "And", "conditions": [wl(), leaf(H1)] } }));
    }

    /// An AND with AllowAll says nothing AllowAll did not.
    #[test]
    fn allow_all_narrows_to_the_leaf_alone() {
        assert_eq!(lock_to_build(json!("AllowAll"), Some(H1)).unwrap(), leaf(H1));
    }

    #[test]
    fn locking_twice_leaves_one_leaf() {
        let once = lock_to_build(wl(), Some(H1)).unwrap();
        let twice = lock_to_build(once.clone(), Some(H1)).unwrap();
        assert_eq!(twice, once, "a repeat must be a no-op, not another wrapper");
        assert_eq!(leaves(&twice).len(), 1);
    }

    #[test]
    fn a_new_build_replaces_the_old_one() {
        let locked = lock_to_build(lock_to_build(wl(), Some(H1)).unwrap(), Some(H2)).unwrap();
        assert_eq!(leaves(&locked), vec![H2.to_string()], "the old lock is gone, not kept beside");
        assert_eq!(locked, json!({ "Logic": { "operator": "And", "conditions": [wl(), leaf(H2)] } }));
    }

    /// A row whose whole condition was the lock: nothing remains to AND onto.
    #[test]
    fn a_bare_lock_becomes_the_new_bare_lock() {
        assert_eq!(lock_to_build(leaf(H1), Some(H2)).unwrap(), leaf(H2));
    }

    /// Stripping must not leave an empty `Logic` node behind — the contract
    /// would store it and the keystore would evaluate an `And` of nothing as
    /// admitting everyone.
    #[test]
    fn emptied_nodes_disappear_rather_than_stay_empty() {
        let nested = json!({ "Logic": { "operator": "Or", "conditions": [
            leaf(H1),
            { "Logic": { "operator": "And", "conditions": [leaf(H1), leaf(H2)] } }
        ] } });
        assert_eq!(lock_to_build(nested, Some(H2)).unwrap(), leaf(H2));

        let under_not = json!({ "Not": { "condition": leaf(H1) } });
        assert_eq!(lock_to_build(under_not, Some(H2)).unwrap(), leaf(H2));
    }

    /// A branch that is not about builds survives the strip.
    #[test]
    fn only_build_leaves_are_removed() {
        let mixed = json!({ "Logic": { "operator": "Or", "conditions": [wl(), leaf(H1)] } });
        let locked = lock_to_build(mixed, Some(H2)).unwrap();
        assert_eq!(locked, json!({ "Logic": { "operator": "And", "conditions": [wl(), leaf(H2)] } }));
    }

    /// Refused before anything is signed, and lowercased on the way in.
    #[test]
    fn only_a_sha256_is_accepted() {
        assert_eq!(lock_to_build(wl(), Some(&H1.to_uppercase())).unwrap(), lock_to_build(wl(), Some(H1)).unwrap());
        assert_eq!(lock_to_build(wl(), Some(&format!("  {H1}  "))).unwrap(), lock_to_build(wl(), Some(H1)).unwrap());
        for bad in [&H1[..63], "", "zz", &format!("{}g", &H1[..63])] {
            assert!(lock_to_build(wl(), Some(bad)).is_err(), "{bad} must be refused");
        }
    }

    /// `list` and every confirmation line read the leaf back.
    #[test]
    fn a_locked_condition_reads_back_as_a_build() {
        assert_eq!(format_access(&leaf(H1)), format!("build:{H1}"));
        assert_eq!(
            format_access(&lock_to_build(wl(), Some(H1)).unwrap()),
            format!("(whitelist:me.near and build:{H1})")
        );
    }
}

/// A stored lock is found before `--access` can replace it.
#[cfg(test)]
mod a_stored_lock_is_seen_before_it_is_replaced {
    use super::*;

    const H: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn a_lock_is_found_wherever_it_sits() {
        let wl = json!({ "Whitelist": { "accounts": ["me.near"] } });
        assert_eq!(build_locks_of(&json!({ "WasmHash": { "hash": H } })), vec![H.to_string()]);
        assert_eq!(
            build_locks_of(&json!({ "Logic": { "operator": "And", "conditions": [wl, { "WasmHash": { "hash": H } }] } })),
            vec![H.to_string()]
        );
        assert_eq!(
            build_locks_of(&json!({ "Not": { "condition": { "WasmHash": { "hash": H } } } })),
            vec![H.to_string()],
            "a negated lock is still a lock this command must not drop silently"
        );
    }

    #[test]
    fn a_row_with_no_lock_reports_none() {
        assert!(build_locks_of(&json!("AllowAll")).is_empty());
        assert!(build_locks_of(&json!({ "Whitelist": { "accounts": ["me.near"] } })).is_empty());
        assert!(build_locks_of(&json!({ "Logic": { "operator": "Or", "conditions": [] } })).is_empty());
    }
}

/// The calling-account rule as `--direct` / `--via` / `--drop-callers` write
/// it: one rule on the AND spine, replaced rather than nested, naming the
/// readers and the contracts asked for — and never lifted out of an OR or a
/// NOT the owner composed.
#[cfg(test)]
mod the_calling_account_rule_is_written_once_and_read_back {
    use super::*;

    fn wl(accounts: &[&str]) -> Value {
        json!({ "Whitelist": { "accounts": accounts } })
    }
    fn via(inner: Value) -> Value {
        json!({ "Predecessor": { "condition": inner } })
    }
    fn and(conditions: Vec<Value>) -> Value {
        json!({ "Logic": { "operator": "And", "conditions": conditions } })
    }
    fn or(conditions: Vec<Value>) -> Value {
        json!({ "Logic": { "operator": "Or", "conditions": conditions } })
    }
    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn direct_names_the_readers_and_via_adds_contracts() {
        let readers = or(vec![wl(&["me.near"]), and(vec![wl(&["agent.near"]), json!({ "ValidUntil": { "until_ns": "9" } })])]);
        assert_eq!(callers_from_flags(&readers, None, true, None).unwrap(), Some(s(&["me.near", "agent.near"])));
        assert_eq!(callers_from_flags(&readers, None, true, Some("dao.near, me.near")).unwrap(), Some(s(&["me.near", "agent.near", "dao.near"])));
        assert_eq!(callers_from_flags(&readers, None, false, Some("dao.near")).unwrap(), Some(s(&["dao.near"])));
        assert_eq!(callers_from_flags(&readers, None, false, None).unwrap(), None);
        let err = callers_from_flags(&json!("AllowAll"), None, true, None).unwrap_err().to_string();
        assert!(err.contains("names no reader"), "{err}");
        assert!(callers_from_flags(&readers, None, false, Some("a.near,,b.near")).is_err(), "an empty entry is refused");
    }

    #[test]
    fn the_rule_is_written_once_and_replaced_not_nested() {
        let once = with_callers(&wl(&["me.near"]), &s(&["me.near"]));
        assert_eq!(once, and(vec![wl(&["me.near"]), via(wl(&["me.near"]))]));
        let again = with_callers(&once, &s(&["me.near", "dao.near"]));
        assert_eq!(again, and(vec![wl(&["me.near"]), via(wl(&["me.near", "dao.near"]))]));
        assert_eq!(callers_of(&again), s(&["me.near", "dao.near"]));
        assert_eq!(without_caller_rules(&again), wl(&["me.near"]));
        assert_eq!(with_callers(&json!("AllowAll"), &s(&["me.near"])), via(wl(&["me.near"])));
        assert_eq!(without_caller_rules(&via(wl(&["me.near"]))), json!("AllowAll"));
    }

    #[test]
    fn a_build_lock_and_the_rule_coexist() {
        let locked = lock_to_build(wl(&["me.near"]), Some(&"a".repeat(64))).unwrap();
        let both = with_callers(&locked, &s(&["me.near"]));
        assert_eq!(build_locks_of(&both), vec!["a".repeat(64)]);
        assert_eq!(callers_of(&both), s(&["me.near"]));
        // Moving the lock keeps the rule; re-deriving the rule keeps the lock.
        let moved = lock_to_build(both.clone(), Some(&"b".repeat(64))).unwrap();
        assert_eq!(callers_of(&moved), s(&["me.near"]));
        assert_eq!(build_locks_of(&with_callers(&moved, &s(&["me.near", "dao.near"]))), vec!["b".repeat(64)]);
    }

    /// A rule under an OR or a NOT is the owner's composition: these flags
    /// neither rewrite around it nor drop it — they refuse, naming it.
    #[test]
    fn a_rule_under_an_or_or_a_not_refuses_the_flags() {
        let composed = or(vec![wl(&["me.near"]), via(wl(&["dao.near"]))]);
        assert!(callers_of(&composed).is_empty(), "not on the spine, so not a rule this command owns");
        assert!(has_caller_rule(&composed), "but it is there, and --access must not drop it unasked");
        assert_eq!(without_caller_rules(&composed), composed);
        for (direct, via_arg, drop) in [(true, None, false), (false, Some("x.near"), false), (false, None, true)] {
            let err = apply_caller_flags(composed.clone(), None, direct, via_arg, drop).unwrap_err().to_string();
            assert!(err.contains("cannot rewrite"), "{err}");
        }
        let negated = and(vec![wl(&["me.near"]), json!({ "Not": { "condition": via(wl(&["deputy.near"])) } })]);
        assert!(apply_caller_flags(negated.clone(), None, true, None, false).is_err());
        let dao_inside = and(vec![wl(&["me.near"]), via(json!({ "DaoMember": { "dao_contract": "d.near", "role": "council" } }))]);
        assert!(apply_caller_flags(dao_inside, None, true, None, false).is_err(), "not a whitelist inside");
        // A plain rule on the spine beside nothing else is owned, and rewritten.
        let owned = and(vec![wl(&["me.near"]), via(wl(&["me.near"]))]);
        assert!(apply_caller_flags(owned.clone(), None, true, Some("dao.near"), false).is_ok());
        assert_eq!(apply_caller_flags(owned, None, false, None, true).unwrap(), (wl(&["me.near"]), true));
        assert_eq!(apply_caller_flags(wl(&["me.near"]), None, false, None, true).unwrap().1, false, "nothing to drop, nothing changed");
    }

    /// `--direct` alone keeps the contracts a `--via` named earlier; `--via`
    /// given again restates them.
    #[test]
    fn direct_alone_keeps_the_via_contracts_the_row_already_names() {
        let stored = and(vec![wl(&["me.near"]), via(wl(&["me.near", "dao.near"]))]);
        assert_eq!(callers_from_flags(&stored, Some(&stored), true, None).unwrap(), Some(s(&["me.near", "dao.near"])));
        // The case the live run caught: `--access` builds a FRESH tree that
        // carries no rule, so the DAO can only come from the stored row.
        let restated = wl(&["me.near", "agent.near"]);
        assert_eq!(
            callers_from_flags(&restated, Some(&stored), true, None).unwrap(),
            Some(s(&["me.near", "agent.near", "dao.near"])),
            "a grant restated with --access must not drop the via contracts"
        );
        // With no stored row there is nothing to carry.
        assert_eq!(callers_from_flags(&restated, None, true, None).unwrap(), Some(s(&["me.near", "agent.near"])));
        // An account that WAS a reader and is revoked is not mistaken for a via contract.
        let had_agent = and(vec![wl(&["me.near", "agent.near"]), via(wl(&["me.near", "agent.near"]))]);
        assert_eq!(callers_from_flags(&wl(&["me.near"]), Some(&had_agent), true, None).unwrap(), Some(s(&["me.near"])));
        // --via restates the list of contracts.
        assert_eq!(callers_from_flags(&stored, Some(&stored), true, Some("router.near")).unwrap(), Some(s(&["me.near", "router.near"])));
        // --via alone names only contracts, whatever the row had.
        assert_eq!(callers_from_flags(&stored, Some(&stored), false, Some("router.near")).unwrap(), Some(s(&["router.near"])));
    }

    #[test]
    fn readers_are_the_whitelists_not_the_callers_nor_a_denylist() {
        let tree = and(vec![
            or(vec![wl(&["me.near"]), wl(&["agent.near"])]),
            json!({ "Not": { "condition": wl(&["banned.near"]) } }),
            via(wl(&["dao.near"])),
        ]);
        assert_eq!(named_readers(&tree), s(&["me.near", "agent.near"]));
    }

    #[test]
    fn the_guard_refuses_a_silent_loss_and_the_flags_lift_it() {
        let stored = and(vec![wl(&["me.near"]), via(wl(&["me.near"]))]);
        let err = refuse_silent_caller_rule_loss(Some(&stored), "p", false, None, false).unwrap_err().to_string();
        assert!(err.contains("--drop-callers"), "{err}");
        assert!(refuse_silent_caller_rule_loss(Some(&stored), "p", true, None, false).is_ok());
        assert!(refuse_silent_caller_rule_loss(Some(&stored), "p", false, Some("dao.near"), false).is_ok());
        assert!(refuse_silent_caller_rule_loss(Some(&stored), "p", false, None, true).is_ok());
        assert!(refuse_silent_caller_rule_loss(Some(&wl(&["me.near"])), "p", false, None, false).is_ok());
        assert!(refuse_silent_caller_rule_loss(None, "p", false, None, false).is_ok());
    }

    #[test]
    fn the_rule_reads_back_as_from() {
        assert_eq!(format_access(&via(wl(&["me.near", "dao.near"]))), "from:me.near,dao.near");
        assert_eq!(
            format_access(&and(vec![wl(&["me.near"]), via(wl(&["me.near"]))])),
            "(whitelist:me.near and from:me.near)"
        );
        assert_eq!(
            format_access(&via(json!({ "DaoMember": { "dao_contract": "d.near", "role": "council" } }))),
            r#"from:(DaoMember{"dao_contract":"d.near","role":"council"})"#
        );
    }
}
