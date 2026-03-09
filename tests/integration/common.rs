use near_primitives::views::FinalExecutionStatus;
use serde_json::{json, Value};

use outlayer_cli::api::{ApiClient, HttpsCallRequest, SecretsRef};
use outlayer_cli::config::{self, Credentials, NetworkConfig};
use outlayer_cli::near::{NearClient, NearSigner};

#[allow(dead_code)]
pub struct TestContext {
    pub network: NetworkConfig,
    pub creds: Credentials,
    pub private_key: String,
    pub account_id: String,
    pub near: NearClient,
    pub api: ApiClient,
    pub payment_key: Option<PaymentKey>,
}

impl TestContext {
    pub fn signer(&self) -> NearSigner {
        NearSigner::new(&self.network, &self.account_id, &self.private_key)
            .expect("Failed to create NearSigner")
    }

    /// Call a project. Uses HTTPS API if payment key is available, otherwise on-chain.
    pub async fn call_project(
        &self,
        owner: &str,
        project: &str,
        input: Value,
    ) -> CallResult {
        self.call_project_with_secrets(owner, project, input, None).await
    }

    /// Call a project with secrets_ref attached.
    pub async fn call_project_with_secrets(
        &self,
        owner: &str,
        project: &str,
        input: Value,
        secrets_ref: Option<SecretsRef>,
    ) -> CallResult {
        if let Some(key) = &self.payment_key {
            self.call_project_https(owner, project, &key.api_key, input, secrets_ref).await
        } else {
            self.call_project_on_chain(owner, project, input, secrets_ref).await
        }
    }

    async fn call_project_https(
        &self,
        owner: &str,
        project: &str,
        api_key: &str,
        input: Value,
        secrets_ref: Option<SecretsRef>,
    ) -> CallResult {
        eprintln!("  [HTTPS] calling {owner}/{project}");
        let response = self
            .api
            .call_project(
                owner,
                project,
                api_key,
                &HttpsCallRequest {
                    input,
                    is_async: false,
                    version_key: None,
                    secrets_ref,
                },
                None,
                None,
            )
            .await
            .expect("HTTPS call_project failed");

        CallResult {
            status: response.status.clone(),
            output: response.output,
            error: response.error,
            call_id: Some(response.call_id),
            tx_hash: None,
        }
    }

    async fn call_project_on_chain(
        &self,
        owner: &str,
        project: &str,
        input: Value,
        secrets_ref: Option<SecretsRef>,
    ) -> CallResult {
        let project_id = format!("{owner}/{project}");
        eprintln!("  [on-chain] calling {project_id} (no payment key, paying NEAR)");
        let signer = self.signer();

        let resource_limits = json!({
            "max_instructions": 1_000_000_000u64,
            "max_memory_mb": 128,
            "max_execution_seconds": 10
        });

        let cost_str = self
            .near
            .estimate_execution_cost(Some(resource_limits.clone()))
            .await
            .expect("estimate_execution_cost failed");
        let cost_yocto: u128 = cost_str.trim_matches('"').parse().expect("bad cost");
        eprintln!("  cost: {:.4} NEAR", cost_yocto as f64 / 1e24);

        let input_data = serde_json::to_string(&input).unwrap();
        let secrets_ref_json = secrets_ref
            .map(|sr| json!({"profile": sr.profile, "account_id": sr.account_id}))
            .unwrap_or(Value::Null);

        let outcome = signer
            .call_contract(
                "request_execution",
                json!({
                    "source": { "Project": { "project_id": project_id, "version_key": null } },
                    "resource_limits": resource_limits,
                    "input_data": input_data,
                    "secrets_ref": secrets_ref_json,
                    "response_format": "Json",
                    "payer_account_id": null,
                    "params": null
                }),
                300_000_000_000_000u64,
                cost_yocto,
            )
            .await
            .expect("request_execution failed");

        let tx_hash = outcome.transaction_outcome.id.to_string();
        eprintln!("  tx: https://testnet.nearblocks.io/txns/{tx_hash}");

        match &outcome.status {
            FinalExecutionStatus::SuccessValue(val) => {
                let output: Option<Value> = serde_json::from_slice(val).ok().filter(|v: &Value| !v.is_null());
                CallResult {
                    status: "completed".to_string(),
                    output,
                    error: None,
                    call_id: None,
                    tx_hash: Some(tx_hash),
                }
            }
            FinalExecutionStatus::Failure(err) => CallResult {
                status: "failed".to_string(),
                output: None,
                error: Some(format!("{err:?}")),
                call_id: None,
                tx_hash: Some(tx_hash),
            },
            status => panic!("Unexpected execution status: {status:?}"),
        }
    }
}

/// Unified result from either HTTPS API or on-chain execution.
#[allow(dead_code)]
pub struct CallResult {
    pub status: String,
    pub output: Option<Value>,
    pub error: Option<String>,
    /// HTTPS only
    pub call_id: Option<String>,
    /// On-chain only
    pub tx_hash: Option<String>,
}

/// Payment key parsed from TESTNET_PAYMENT_KEY env var (format: owner:nonce:secret)
#[allow(dead_code)]
pub struct PaymentKey {
    pub owner: String,
    pub nonce: u32,
    pub secret: String,
    pub api_key: String,
}

/// Load testnet credentials and build a TestContext.
/// Returns None if no testnet credentials are available.
pub fn setup_testnet() -> Option<TestContext> {
    let network = NetworkConfig::testnet();
    let creds = config::load_credentials(&network).ok()?;
    let private_key =
        config::load_private_key(&network.network_id, &creds.account_id, &creds).ok()?;
    let account_id = creds.account_id.clone();
    let near = NearClient::new(&network);
    let api = ApiClient::new(&network);
    let payment_key = load_payment_key();

    if payment_key.is_some() {
        eprintln!("  payment key: available (HTTPS mode)");
    } else {
        eprintln!("  payment key: not set (on-chain mode, costs NEAR)");
    }

    Some(TestContext {
        network,
        creds,
        private_key,
        account_id,
        near,
        api,
        payment_key,
    })
}

/// Parse TESTNET_PAYMENT_KEY env var. Format: owner:nonce:secret
pub fn load_payment_key() -> Option<PaymentKey> {
    let raw = std::env::var("TESTNET_PAYMENT_KEY").ok()?;
    let parts: Vec<&str> = raw.splitn(3, ':').collect();
    if parts.len() != 3 {
        eprintln!("TESTNET_PAYMENT_KEY must be owner:nonce:secret");
        return None;
    }
    let nonce: u32 = parts[1].parse().ok()?;
    Some(PaymentKey {
        owner: parts[0].to_string(),
        nonce,
        secret: parts[2].to_string(),
        api_key: raw,
    })
}

/// Skip a test gracefully if testnet credentials are not available.
macro_rules! require_testnet {
    () => {
        match $crate::common::setup_testnet() {
            Some(ctx) => ctx,
            None => {
                eprintln!("SKIP: no testnet credentials (run `outlayer login testnet`)");
                return;
            }
        }
    };
}

/// Wait for a view call predicate to become true (handles finality propagation).
/// Retries up to 3 times with 2s delay.
pub async fn wait_for_view<F, Fut>(predicate: F, label: &str)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        if predicate().await {
            return;
        }
    }
    panic!("Timed out waiting for: {label}");
}

pub(crate) use require_testnet;
