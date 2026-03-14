use anyhow::{Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::api::{ApiClient, HttpsCallRequest, SecretsRef};
use crate::config::{self, NetworkConfig};
use crate::near::{ContractCaller, NearClient};

// ── Source types ──────────────────────────────────────────────────────

pub enum RunSource {
    Project {
        project_id: String,
        version: Option<String>,
    },
    GitHub {
        repo: String,
        commit: Option<String>,
    },
    WasmUrl {
        url: String,
        hash: Option<String>,
    },
}

impl RunSource {
    /// Build contract-format JSON for request_execution
    async fn to_contract_json(&self, build_target: &str) -> Result<Value> {
        match self {
            RunSource::Project { project_id, version } => Ok(json!({
                "Project": {
                    "project_id": project_id,
                    "version_key": version
                }
            })),
            RunSource::GitHub { repo, commit } => {
                let commit = commit.as_deref().unwrap_or("main");
                Ok(json!({
                    "GitHub": {
                        "repo": repo,
                        "commit": commit,
                        "build_target": build_target
                    }
                }))
            }
            RunSource::WasmUrl { url, hash } => {
                let hash = match hash.as_deref() {
                    Some(h) => h.to_string(),
                    None => {
                        eprintln!("Downloading WASM to compute hash...");
                        compute_wasm_hash(url).await?
                    }
                };
                Ok(json!({
                    "WasmUrl": {
                        "url": url,
                        "hash": hash,
                        "build_target": build_target
                    }
                }))
            }
        }
    }

    fn label(&self) -> String {
        match self {
            RunSource::Project { project_id, .. } => project_id.clone(),
            RunSource::GitHub { repo, .. } => format!("github:{repo}"),
            RunSource::WasmUrl { url, .. } => format!("wasm:{url}"),
        }
    }
}

// ── Run ──────────────────────────────────────────────────────────────

/// `outlayer run` — execute agent from project, github, or wasm url
#[allow(clippy::too_many_arguments)]
pub async fn run(
    network: &NetworkConfig,
    source: RunSource,
    input: Option<String>,
    input_file: Option<String>,
    is_async: bool,
    deposit: Option<String>,
    compute_limit: Option<u64>,
    build_target: &str,
    secrets_ref: Option<SecretsRef>,
) -> Result<()> {
    let input_value = parse_input(input, input_file)?;

    // HTTPS API only works for Project source with payment key
    if let RunSource::Project { ref project_id, ref version } = source {
        if let Ok(payment_key) = find_payment_key() {
            return run_https(
                network,
                project_id,
                &payment_key,
                input_value,
                is_async,
                deposit,
                version.clone(),
                compute_limit,
                secrets_ref,
            )
            .await;
        }
    }

    // On-chain for all source types
    if is_async {
        anyhow::bail!("--async is only supported with payment key (HTTPS API)");
    }

    eprintln!("Executing on-chain with NEAR deposit.\n");
    run_on_chain(network, &source, input_value, compute_limit, build_target, secrets_ref).await
}

/// Execute via HTTPS API (Project source + payment key)
async fn run_https(
    network: &NetworkConfig,
    project_id: &str,
    payment_key: &str,
    input_value: Value,
    is_async: bool,
    deposit: Option<String>,
    version: Option<String>,
    compute_limit: Option<u64>,
    secrets_ref: Option<SecretsRef>,
) -> Result<()> {
    let (owner, project) = split_project(project_id)?;

    let api = ApiClient::new(network);
    let body = HttpsCallRequest {
        input: input_value,
        is_async,
        version_key: version,
        secrets_ref,
    };

    eprintln!("Running {owner}/{project}...");

    let response = api
        .call_project(
            owner,
            project,
            payment_key,
            &body,
            compute_limit,
            deposit.as_deref(),
        )
        .await?;

    if is_async {
        eprintln!("Call ID: {}", response.call_id);
        eprintln!("Status:  {}", response.status);
        if let Some(poll_url) = &response.poll_url {
            eprintln!("Poll:    {poll_url}");
        }
    } else {
        if let Some(output) = &response.output {
            println!(
                "{}",
                serde_json::to_string_pretty(output).unwrap_or_else(|_| output.to_string())
            );
        }
        if let Some(error) = &response.error {
            eprintln!("Error: {error}");
        }
        if let Some(cost) = &response.compute_cost {
            eprintln!("Cost: {cost}");
        }
        if let Some(time_ms) = response.time_ms {
            eprintln!("Time: {time_ms}ms");
        }
    }

    Ok(())
}

/// Execute on-chain via request_execution (any source type)
async fn run_on_chain(
    network: &NetworkConfig,
    source: &RunSource,
    input_value: Value,
    compute_limit: Option<u64>,
    build_target: &str,
    secrets_ref: Option<SecretsRef>,
) -> Result<()> {
    let creds = config::load_credentials(network)?;
    let near = NearClient::new(network);
    let caller = ContractCaller::from_credentials(&creds, network)?;

    let resource_limits = json!({
        "max_instructions": compute_limit.unwrap_or(1_000_000_000),
        "max_memory_mb": 128,
        "max_execution_seconds": 10
    });

    // Estimate cost
    let cost_str: String = near
        .estimate_execution_cost(Some(resource_limits.clone()))
        .await?;
    let cost_yocto: u128 = cost_str
        .trim_matches('"')
        .parse()
        .context("Failed to parse execution cost")?;

    let cost_near = cost_yocto as f64 / 1e24;
    let label = source.label();
    eprintln!("Running {label} (on-chain, ~{cost_near:.4} NEAR)...");

    let source_json = source.to_contract_json(build_target).await?;
    let input_data = serde_json::to_string(&input_value)?;
    let gas = 300_000_000_000_000u64; // 300 TGas

    let secrets_ref_json = secrets_ref
        .map(|sr| json!({"profile": sr.profile, "account_id": sr.account_id}))
        .unwrap_or(Value::Null);

    let result = caller
        .call_contract(
            "request_execution",
            json!({
                "source": source_json,
                "resource_limits": resource_limits,
                "input_data": input_data,
                "secrets_ref": secrets_ref_json,
                "response_format": "Json",
                "payer_account_id": null,
                "params": null
            }),
            gas,
            cost_yocto,
        )
        .await
        .context("On-chain execution failed")?;

    if let Some(hash) = &result.tx_hash {
        eprintln!("Tx: {hash}");
    }

    // Print result
    if let Some(value) = &result.value {
        if !value.is_null() {
            println!(
                "{}",
                serde_json::to_string_pretty(value)
                    .unwrap_or_else(|_| value.to_string())
            );
        }
    }

    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────────

fn split_project(project_id: &str) -> Result<(&str, &str)> {
    project_id
        .split_once('/')
        .context("Project must be in format owner/name (e.g. alice.near/my-agent)")
}

async fn compute_wasm_hash(url: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("Failed to download WASM from {url}"))?;

    if !resp.status().is_success() {
        anyhow::bail!("Failed to download WASM: HTTP {}", resp.status());
    }

    let bytes = resp.bytes().await.context("Failed to read WASM body")?;
    let hash = hex::encode(Sha256::digest(&bytes));
    eprintln!("Hash: {hash} ({} bytes)", bytes.len());
    Ok(hash)
}

fn find_payment_key() -> Result<String> {
    if let Ok(key) = std::env::var("PAYMENT_KEY") {
        return Ok(key);
    }

    let cwd = std::env::current_dir()?;
    let env_path = cwd.join(".env");
    if env_path.exists() {
        let content = std::fs::read_to_string(&env_path)?;
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("PAYMENT_KEY=") {
                return Ok(val.to_string());
            }
        }
    }

    anyhow::bail!("No payment key found")
}

fn parse_input(input: Option<String>, input_file: Option<String>) -> Result<Value> {
    if let Some(file) = input_file {
        let data = std::fs::read_to_string(&file)
            .with_context(|| format!("Failed to read input file: {file}"))?;
        serde_json::from_str(&data).with_context(|| format!("Invalid JSON in {file}"))
    } else if let Some(json_str) = input {
        serde_json::from_str(&json_str).context("Invalid JSON input")
    } else if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        Ok(Value::Object(serde_json::Map::new()))
    } else {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
        if buf.trim().is_empty() {
            Ok(Value::Object(serde_json::Map::new()))
        } else {
            serde_json::from_str(&buf).context("Invalid JSON from stdin")
        }
    }
}
