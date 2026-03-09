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
