use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::NetworkConfig;

pub struct ApiClient {
    client: reqwest::Client,
    base_url: String,
}

#[derive(Debug, Serialize)]
pub struct HttpsCallRequest {
    pub input: Value,
    #[serde(rename = "async")]
    pub is_async: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets_ref: Option<SecretsRef>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecretsRef {
    pub profile: String,
    pub account_id: String,
}

#[derive(Debug, Deserialize)]
pub struct HttpsCallResponse {
    pub call_id: String,
    pub status: String,
    pub output: Option<Value>,
    pub error: Option<String>,
    pub compute_cost: Option<String>,
    #[allow(dead_code)]
    pub instructions: Option<u64>,
    pub time_ms: Option<u64>,
    pub poll_url: Option<String>,
    #[allow(dead_code)]
    pub attestation_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GetPubkeyRequest {
    pub accessor: Value,
    pub owner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub secrets_json: String,
}

impl ApiClient {
    pub fn new(network: &NetworkConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: network.api_base_url.clone(),
        }
    }

    /// POST /call/{owner}/{project} — execute agent
    pub async fn call_project(
        &self,
        owner: &str,
        project: &str,
        payment_key: &str,
        body: &HttpsCallRequest,
        compute_limit: Option<u64>,
        deposit: Option<&str>,
    ) -> Result<HttpsCallResponse> {
        let url = format!("{}/call/{}/{}", self.base_url, owner, project);

        let mut req = self
            .client
            .post(&url)
            .header("X-Payment-Key", payment_key)
            .json(body);

        if let Some(limit) = compute_limit {
            req = req.header("X-Compute-Limit", limit.to_string());
        }
        if let Some(deposit) = deposit {
            req = req.header("X-Attached-Deposit", deposit);
        }

        let response = req.send().await.context("Failed to call project")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("API error ({status}): {text}");
        }

        response
            .json()
            .await
            .context("Failed to parse call response")
    }

    /// GET /calls/{call_id} — poll async call status
    pub async fn get_call_result(
        &self,
        call_id: &str,
        payment_key: &str,
    ) -> Result<HttpsCallResponse> {
        let url = format!("{}/calls/{}", self.base_url, call_id);

        let response = self
            .client
            .get(&url)
            .header("X-Payment-Key", payment_key)
            .send()
            .await
            .context("Failed to poll call status")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("API error ({status}): {text}");
        }

        response.json().await.context("Failed to parse call result")
    }

    /// GET /public/payment-keys/{owner}/{nonce}/balance
    pub async fn get_payment_key_balance(
        &self,
        owner: &str,
        nonce: u32,
    ) -> Result<PaymentKeyBalanceResponse> {
        let url = format!(
            "{}/public/payment-keys/{}/{}/balance",
            self.base_url, owner, nonce
        );

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to get balance ({status}): {text}");
        }

        response
            .json()
            .await
            .context("Failed to parse balance response")
    }

    /// GET /public/payment-keys/{owner}/{nonce}/usage
    pub async fn get_payment_key_usage(
        &self,
        owner: &str,
        nonce: u32,
        limit: i64,
        offset: i64,
    ) -> Result<PaymentKeyUsageResponse> {
        let url = format!(
            "{}/public/payment-keys/{}/{}/usage?limit={}&offset={}",
            self.base_url, owner, nonce, limit, offset
        );

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to get usage ({status}): {text}");
        }

        response
            .json()
            .await
            .context("Failed to parse usage response")
    }

    /// GET /public/project-earnings/{project_owner}
    pub async fn get_project_owner_earnings(
        &self,
        owner: &str,
    ) -> Result<ProjectOwnerEarningsResponse> {
        let url = format!("{}/public/project-earnings/{}", self.base_url, owner);

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to get earnings ({status}): {text}");
        }

        response
            .json()
            .await
            .context("Failed to parse earnings response")
    }

    /// GET /public/project-earnings/{project_owner}/history
    pub async fn get_earnings_history(
        &self,
        owner: &str,
        source: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<EarningsHistoryResponse> {
        let mut url = format!(
            "{}/public/project-earnings/{}/history?limit={}&offset={}",
            self.base_url, owner, limit, offset
        );
        if let Some(source) = source {
            url.push_str(&format!("&source={}", source));
        }

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to get earnings history ({status}): {text}");
        }

        response
            .json()
            .await
            .context("Failed to parse earnings history")
    }

    /// POST /secrets/add_generated_secret — generate PROTECTED_* in TEE
    pub async fn add_generated_secret(
        &self,
        req: &Value,
    ) -> Result<AddGeneratedSecretResponse> {
        let url = format!("{}/secrets/add_generated_secret", self.base_url);

        let response = self
            .client
            .post(&url)
            .json(req)
            .send()
            .await
            .context("Failed to call add_generated_secret")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to generate secrets ({status}): {text}");
        }

        response
            .json()
            .await
            .context("Failed to parse add_generated_secret response")
    }

    /// POST /secrets/update_user_secrets — merge/update secrets with NEP-413 auth
    pub async fn update_user_secrets(
        &self,
        payload: &Value,
    ) -> Result<UpdateUserSecretsResponse> {
        let url = format!("{}/secrets/update_user_secrets", self.base_url);

        let response = self
            .client
            .post(&url)
            .json(payload)
            .send()
            .await
            .context("Failed to call update_user_secrets")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to update secrets ({status}): {text}");
        }

        response
            .json()
            .await
            .context("Failed to parse update_user_secrets response")
    }

    /// POST /secrets/pubkey — get keystore pubkey for encryption
    pub async fn get_secrets_pubkey(&self, request: &GetPubkeyRequest) -> Result<String> {
        let url = format!("{}/secrets/pubkey", self.base_url);

        let response = self
            .client
            .post(&url)
            .json(request)
            .send()
            .await
            .context("Failed to get secrets pubkey")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to get pubkey ({status}): {text}");
        }

        #[derive(Deserialize)]
        struct PubkeyResponse {
            pubkey: String,
        }

        let resp: PubkeyResponse = response
            .json()
            .await
            .context("Failed to parse pubkey response")?;

        Ok(resp.pubkey)
    }

    // ── Payment Check Methods ──────────────────────────────────────────

    /// POST /wallet/v1/payment-check/create
    pub async fn create_payment_check(
        &self,
        api_key: &str,
        token: &str,
        amount: &str,
        memo: Option<&str>,
        expires_in: Option<u64>,
    ) -> Result<PaymentCheckCreateResponse> {
        let url = format!("{}/wallet/v1/payment-check/create", self.base_url);

        let mut body = serde_json::json!({
            "token": token,
            "amount": amount,
        });
        if let Some(memo) = memo {
            body["memo"] = serde_json::Value::String(memo.to_string());
        }
        if let Some(expires_in) = expires_in {
            body["expires_in"] = serde_json::Value::Number(expires_in.into());
        }

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&body)
            .send()
            .await
            .context("Failed to create payment check")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to create payment check ({status}): {text}");
        }

        response
            .json()
            .await
            .context("Failed to parse create check response")
    }

    /// POST /wallet/v1/payment-check/batch-create
    pub async fn batch_create_payment_checks(
        &self,
        api_key: &str,
        checks: &[serde_json::Value],
    ) -> Result<PaymentCheckBatchCreateResponse> {
        let url = format!("{}/wallet/v1/payment-check/batch-create", self.base_url);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&serde_json::json!({ "checks": checks }))
            .send()
            .await
            .context("Failed to batch create payment checks")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to batch create checks ({status}): {text}");
        }

        response
            .json()
            .await
            .context("Failed to parse batch create response")
    }

    /// POST /wallet/v1/payment-check/claim
    pub async fn claim_payment_check(
        &self,
        api_key: &str,
        check_key: &str,
        amount: Option<&str>,
    ) -> Result<PaymentCheckClaimResponse> {
        let url = format!("{}/wallet/v1/payment-check/claim", self.base_url);

        let mut body = serde_json::json!({ "check_key": check_key });
        if let Some(amount) = amount {
            body["amount"] = serde_json::Value::String(amount.to_string());
        }

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&body)
            .send()
            .await
            .context("Failed to claim payment check")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to claim check ({status}): {text}");
        }

        response
            .json()
            .await
            .context("Failed to parse claim response")
    }

    /// POST /wallet/v1/payment-check/reclaim
    pub async fn reclaim_payment_check(
        &self,
        api_key: &str,
        check_id: &str,
        amount: Option<&str>,
    ) -> Result<PaymentCheckReclaimResponse> {
        let url = format!("{}/wallet/v1/payment-check/reclaim", self.base_url);

        let mut body = serde_json::json!({ "check_id": check_id });
        if let Some(amount) = amount {
            body["amount"] = serde_json::Value::String(amount.to_string());
        }

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&body)
            .send()
            .await
            .context("Failed to reclaim payment check")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to reclaim check ({status}): {text}");
        }

        response
            .json()
            .await
            .context("Failed to parse reclaim response")
    }

    /// GET /wallet/v1/payment-check/status?check_id=...
    pub async fn get_payment_check_status(
        &self,
        api_key: &str,
        check_id: &str,
    ) -> Result<PaymentCheckStatusResponse> {
        let url = format!(
            "{}/wallet/v1/payment-check/status?check_id={}",
            self.base_url, check_id
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await
            .context("Failed to get check status")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to get check status ({status}): {text}");
        }

        response
            .json()
            .await
            .context("Failed to parse check status response")
    }

    /// GET /wallet/v1/payment-check/list
    pub async fn list_payment_checks(
        &self,
        api_key: &str,
        status_filter: Option<&str>,
        limit: i64,
    ) -> Result<PaymentCheckListResponse> {
        let mut url = format!(
            "{}/wallet/v1/payment-check/list?limit={}",
            self.base_url, limit
        );
        if let Some(status) = status_filter {
            url.push_str(&format!("&status={}", status));
        }

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await
            .context("Failed to list payment checks")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to list checks ({status}): {text}");
        }

        response
            .json()
            .await
            .context("Failed to parse check list response")
    }

    /// POST /wallet/v1/sign-message — NEP-413 message signing for external auth
    pub async fn sign_message(
        &self,
        api_key: &str,
        message: &str,
        recipient: &str,
        nonce: Option<&str>,
    ) -> Result<SignMessageResponse> {
        let url = format!("{}/wallet/v1/sign-message", self.base_url);

        let mut body = serde_json::json!({
            "message": message,
            "recipient": recipient,
        });
        if let Some(nonce) = nonce {
            body["nonce"] = serde_json::Value::String(nonce.to_string());
        }

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&body)
            .send()
            .await
            .context("Failed to sign message")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to sign message ({status}): {text}");
        }

        response
            .json()
            .await
            .context("Failed to parse sign message response")
    }

    /// POST /wallet/v1/call — sign and send a NEAR function call via custody wallet
    pub async fn wallet_call(
        &self,
        wallet_key: &str,
        receiver_id: &str,
        method_name: &str,
        args: serde_json::Value,
        gas: u64,
        deposit: u128,
    ) -> Result<WalletCallResponse> {
        let url = format!("{}/wallet/v1/call", self.base_url);

        let body = serde_json::json!({
            "receiver_id": receiver_id,
            "method_name": method_name,
            "args": args,
            "gas": gas.to_string(),
            "deposit": deposit.to_string(),
        });

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", wallet_key))
            .json(&body)
            .send()
            .await
            .context("Failed to call wallet API")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Wallet call failed ({status}): {text}");
        }

        response
            .json()
            .await
            .context("Failed to parse wallet call response")
    }

    /// POST /wallet/v1/payment-check/peek
    pub async fn peek_payment_check(
        &self,
        api_key: &str,
        check_key: &str,
    ) -> Result<PaymentCheckPeekResponse> {
        let url = format!("{}/wallet/v1/payment-check/peek", self.base_url);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&serde_json::json!({ "check_key": check_key }))
            .send()
            .await
            .context("Failed to peek payment check")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to peek check ({status}): {text}");
        }

        response
            .json()
            .await
            .context("Failed to parse peek response")
    }
}

// ── Response Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PaymentKeyBalanceResponse {
    pub owner: String,
    pub nonce: u32,
    pub initial_balance: String,
    pub spent: String,
    pub reserved: String,
    pub available: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PaymentKeyUsageResponse {
    pub usage: Vec<PaymentKeyUsageItem>,
    pub total: i64,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PaymentKeyUsageItem {
    pub call_id: String,
    pub project_id: String,
    pub compute_cost: String,
    pub attached_deposit: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ProjectOwnerEarningsResponse {
    pub project_owner: String,
    pub balance: String,
    pub total_earned: String,
}

#[derive(Debug, Deserialize)]
pub struct EarningsHistoryResponse {
    pub earnings: Vec<EarningRecord>,
    pub total_count: i64,
}

#[derive(Debug, Deserialize)]
pub struct EarningRecord {
    pub project_id: String,
    pub amount: String,
    pub source: String,
    pub created_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct AddGeneratedSecretResponse {
    pub encrypted_data_base64: String,
    #[allow(dead_code)]
    pub all_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserSecretsResponse {
    pub encrypted_secrets_base64: String,
}

// ── Sign Message Response Type ────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct SignMessageResponse {
    pub account_id: String,
    pub signature: String,
    pub public_key: String,
    pub nonce: String,
}

// ── Wallet Call Response Type ─────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct WalletCallResponse {
    pub request_id: String,
    pub status: String,
    pub tx_hash: Option<String>,
    pub result: Option<serde_json::Value>,
    pub approval_id: Option<String>,
}

// ── Payment Check Response Types ──────────────────────────────────────

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PaymentCheckCreateResponse {
    pub check_id: String,
    pub check_key: String,
    pub token: String,
    pub amount: String,
    pub memo: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PaymentCheckBatchCreateResponse {
    pub checks: Vec<PaymentCheckCreateResponse>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PaymentCheckClaimResponse {
    pub token: String,
    pub amount_claimed: String,
    pub remaining: String,
    pub memo: Option<String>,
    pub claimed_at: String,
    pub intent_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PaymentCheckReclaimResponse {
    pub token: String,
    pub amount_reclaimed: String,
    pub remaining: String,
    pub reclaimed_at: String,
    pub intent_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PaymentCheckStatusResponse {
    pub check_id: String,
    pub token: String,
    pub amount: String,
    pub claimed_amount: String,
    pub reclaimed_amount: String,
    pub status: String,
    pub memo: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub claimed_at: Option<String>,
    pub claimed_by: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PaymentCheckListResponse {
    pub checks: Vec<PaymentCheckStatusResponse>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PaymentCheckPeekResponse {
    pub token: String,
    pub balance: String,
    pub memo: Option<String>,
    pub status: String,
    pub expires_at: Option<String>,
}
