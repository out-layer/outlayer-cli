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

    /// POST /secrets/pubkey — get keystore pubkey for encryption.
    ///
    /// `vault_id`, when set, MUST be forwarded to the keystore as
    /// `X-Customer-Vault` so the returned pubkey is derived from the
    /// per-vault master (not the operator default master). Skipping
    /// it produces silent corruption: ciphertext encrypted with the
    /// default-master pubkey is later stored on chain with
    /// `vault_id: ...` binding, the worker derives the vault master
    /// for decrypt, the bytes don't decrypt, the env var is never
    /// injected and the agent reports the secret as missing.
    pub async fn get_secrets_pubkey(
        &self,
        request: &GetPubkeyRequest,
        vault_id: Option<&str>,
    ) -> Result<SecretsPubkey> {
        let url = format!("{}/secrets/pubkey", self.base_url);

        let mut req = self.client.post(&url).json(request);
        if let Some(vid) = vault_id {
            req = req.header("X-Customer-Vault", vid);
        }
        let response = req
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
            #[serde(default)]
            accessor: Option<PubkeyAccessor>,
        }

        /// Only the field this needs: what the coordinator made of the repo.
        ///
        /// Read tolerantly — an accessor that is not a repository has no such
        /// field. The cost of that tolerance is that a REMOVED field looks
        /// exactly like a non-repository accessor: normalisation would switch
        /// itself off and secrets would go back to being stored under whatever
        /// the user typed, with nothing failing. The field is marked
        /// accordingly on the answering side (`PubkeyResponseAccessor`); if it
        /// ever has to change, this is the other half that must change with it.
        #[derive(Deserialize)]
        struct PubkeyAccessor {
            #[serde(default)]
            repo_normalized: Option<String>,
        }

        let resp: PubkeyResponse = response
            .json()
            .await
            .context("Failed to parse pubkey response")?;

        Ok(SecretsPubkey {
            pubkey: resp.pubkey,
            repo_normalized: resp.accessor.and_then(|a| a.repo_normalized),
        })
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

    /// POST /wallet/v1/call with raw (Borsh) args as base64.
    ///
    /// An `onchain_tx_failed` error (HTTP 422) means the tx was broadcast and
    /// is on chain, but its execution reverted. It is returned as
    /// `Ok(status: "failed")` with the real `tx_hash` instead of `Err`, so
    /// callers can decide whether the revert matters (FastFS uploads revert
    /// by design) and never re-broadcast an already-recorded transaction.
    pub async fn wallet_call_raw(
        &self,
        wallet_key: &str,
        receiver_id: &str,
        method_name: &str,
        args_raw: &[u8],
        gas: u64,
        deposit: u128,
    ) -> Result<WalletCallResponse> {
        let url = format!("{}/wallet/v1/call", self.base_url);

        use base64::Engine;
        let args_b64 = base64::engine::general_purpose::STANDARD.encode(args_raw);

        let body = serde_json::json!({
            "receiver_id": receiver_id,
            "method_name": method_name,
            "args_base64": args_b64,
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

        let status = response.status();
        let text = response.text().await.unwrap_or_default();

        if !status.is_success() {
            if let Ok(err) = serde_json::from_str::<Value>(&text) {
                if err.get("error").and_then(|v| v.as_str()) == Some("onchain_tx_failed") {
                    return Ok(WalletCallResponse {
                        request_id: String::new(),
                        status: "failed".to_string(),
                        tx_hash: err
                            .get("tx_hash")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .map(String::from),
                        result: err.get("failure").cloned(),
                        approval_id: None,
                    });
                }
            }
            anyhow::bail!("Wallet call failed ({status}): {text}");
        }

        serde_json::from_str(&text).context("Failed to parse wallet call response")
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

    // ── A secret left for an agent ─────────────────────────────────────

    /// `GET /wallet/v1/agent-secret/pubkey` — the key to seal a secret
    /// for this agent, plus the name it will be stored under.
    ///
    /// The key is fetched under the caller's own authentication rather
    /// than accepted as an argument. A key handed in from outside is a
    /// key nobody checked: sealing a live credential to it hands the
    /// credential to whoever produced it, and nothing later in the flow
    /// would notice, because ciphertext is ciphertext.
    pub async fn agent_secret_pubkey(
        &self,
        wallet_key: &str,
        scope: &AgentSecretScope,
    ) -> Result<AgentSecretPubkey> {
        let url = format!("{}/wallet/v1/agent-secret/pubkey", self.base_url);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", wallet_key))
            .query(&[scope.query_pair()])
            .send()
            .await
            .context("Failed to get the agent secret pubkey")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to get the agent secret pubkey ({status}): {text}");
        }

        response
            .json()
            .await
            .context("Failed to parse the agent secret pubkey response")
    }

    /// `POST /wallet/v1/agent-secret` — store it, with the agent's own
    /// wallet paying the storage deposit.
    pub async fn store_agent_secret(
        &self,
        wallet_key: &str,
        scope: &AgentSecretScope,
        encrypted_secrets_base64: &str,
    ) -> Result<StoredAgentSecret> {
        let url = format!("{}/wallet/v1/agent-secret", self.base_url);

        let mut body = scope.body_fields();
        body["encrypted_secrets_base64"] = serde_json::json!(encrypted_secrets_base64);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", wallet_key))
            .json(&body)
            .send()
            .await
            .context("Failed to store the agent secret")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to store the agent secret ({status}): {text}");
        }

        response
            .json()
            .await
            .context("Failed to parse the store response")
    }

    /// `POST /wallet/v1/agent-secret/prepare` — the same store, as a
    /// call for `payer` to send and pay for.
    ///
    /// What comes back is signed by the agent's wallet but addressed by
    /// us: validate it before signing anything (see
    /// `commands::secrets::check_prepared_agent_secret`).
    pub async fn prepare_agent_secret(
        &self,
        wallet_key: &str,
        scope: &AgentSecretScope,
        encrypted_secrets_base64: &str,
        payer: &str,
    ) -> Result<PreparedAgentSecret> {
        let url = format!("{}/wallet/v1/agent-secret/prepare", self.base_url);

        let mut body = scope.body_fields();
        body["encrypted_secrets_base64"] = serde_json::json!(encrypted_secrets_base64);
        body["payer"] = serde_json::json!(payer);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", wallet_key))
            .json(&body)
            .send()
            .await
            .context("Failed to prepare the agent secret call")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to prepare the agent secret call ({status}): {text}");
        }

        response
            .json()
            .await
            .context("Failed to parse the prepared call")
    }

    /// `POST /wallet/v1/agent-secret/delete/prepare` — the removal, as a
    /// call for `payer` to send.
    ///
    /// Checked before signing exactly as the store is, and for a sharper
    /// reason: a delete is irreversible, and the arguments arrive over
    /// the same wire as the signature that makes them valid.
    pub async fn prepare_agent_secret_delete(
        &self,
        wallet_key: &str,
        scope: &AgentSecretScope,
        payer: &str,
    ) -> Result<PreparedAgentSecretDelete> {
        let url = format!("{}/wallet/v1/agent-secret/delete/prepare", self.base_url);

        let mut body = scope.body_fields();
        body["payer"] = serde_json::json!(payer);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", wallet_key))
            .json(&body)
            .send()
            .await
            .context("Failed to prepare the agent secret delete")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to prepare the agent secret delete ({status}): {text}");
        }

        response
            .json()
            .await
            .context("Failed to parse the prepared delete call")
    }

    // ── Vault init helpers ─────────────────────────────────────────────

    /// `POST /customer/derive-tee-key` — fetch the deterministic TEE
    /// public key the customer must install on their vault during the
    /// atomic deploy. No auth (IP-rate-limited on the coordinator).
    pub async fn derive_vault_tee_key(&self, vault_account_id: &str) -> Result<String> {
        let url = format!("{}/customer/derive-tee-key", self.base_url);
        let response = self
            .client
            .post(&url)
            .json(&serde_json::json!({ "vault_account_id": vault_account_id }))
            .send()
            .await
            .context("Failed to call /customer/derive-tee-key")?;
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("derive-tee-key failed ({status}): {text}");
        }
        #[derive(Deserialize)]
        struct Resp {
            public_key: String,
        }
        let resp: Resp = response
            .json()
            .await
            .context("Failed to parse derive-tee-key response")?;
        Ok(resp.public_key)
    }

    /// `POST /customer/sign-verification` — drive
    /// `/sign-vault-verification` on the keystore. Idempotent;
    /// short-circuits if `is_vault_verified == true` already.
    pub async fn sign_vault_verification(
        &self,
        vault_account_id: &str,
    ) -> Result<SignVerificationResponse> {
        let url = format!("{}/customer/sign-verification", self.base_url);
        let response = self
            .client
            .post(&url)
            .json(&serde_json::json!({ "vault_account_id": vault_account_id }))
            .send()
            .await
            .context("Failed to call /customer/sign-verification")?;
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("sign-verification failed ({status}): {text}");
        }
        response
            .json()
            .await
            .context("Failed to parse sign-verification response")
    }

}

#[derive(Debug, Deserialize)]
pub struct SignVerificationResponse {
    pub tx_hash: Option<String>,
    pub already_verified: bool,
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
    /// The accessor as the keystore reads it — carrying `repo_normalized` for
    /// the same reason [`SecretsPubkey`] does. This flow never calls the pubkey
    /// endpoint when there is nothing to encrypt by hand, so it is the only
    /// place the normalised spelling can come from.
    #[serde(default)]
    pub accessor: Option<serde_json::Value>,
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
    /// Signature in NEAR format: "ed25519:<base58>"
    pub signature: String,
    /// Signature as raw base64 (NEP-413 standard)
    pub signature_base64: String,
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

/// What an agent's secret is stored against.
///
/// A project secret is readable by every version of that project; a
/// `wasm_hash` secret is readable only by that exact build. They seal to
/// DIFFERENT seeds, so the choice made when storing is the one that must
/// be made when reading — which is why it travels as one value rather
/// than as two optional strings that could both be set, or neither.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentSecretScope {
    Project(String),
    WasmHash(String),
}

impl AgentSecretScope {
    /// Exactly one of `--project` and `--wasm-hash`.
    pub fn from_flags(project: Option<String>, wasm_hash: Option<String>) -> Result<Self> {
        let project = project.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let hash = wasm_hash.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());

        match (project, hash) {
            (Some(_), Some(_)) => anyhow::bail!(
                "Give either --project or --wasm-hash, not both. A secret is sealed to one \
                 scope, and the two seal it differently."
            ),
            (Some(p), None) => Ok(Self::Project(p)),
            // LOWER CASE: hex has two spellings and the chain stores one. A
            // hash pasted from a tool that shouts would otherwise seal the
            // secret to a seed nothing rebuilds.
            (None, Some(h)) => Ok(Self::WasmHash(h.to_lowercase())),
            (None, None) => anyhow::bail!(
                "--project or --wasm-hash is required: a secret is stored against the \
                 connector's project, or against one exact WASM hash."
            ),
        }
    }

    /// The seed the coordinator will name — `project:{id}:{agent}` or
    /// `wasm_hash:{hash}:{agent}`. Rebuilt here so that a key answered
    /// for a different secret is a refusal rather than a silent
    /// mis-seal.
    pub fn seed(&self, agent_account: &str) -> String {
        match self {
            Self::Project(project_id) => format!("project:{}:{}", project_id, agent_account),
            Self::WasmHash(hash) => format!("wasm_hash:{}:{}", hash, agent_account),
        }
    }

    /// The accessor the prepared call must carry, in the contract's own
    /// JSON. Anything else means the call stores somewhere we did not ask
    /// for.
    pub fn accessor_json(&self) -> Value {
        match self {
            Self::Project(project_id) => {
                serde_json::json!({ "Project": { "project_id": project_id } })
            }
            Self::WasmHash(hash) => serde_json::json!({ "WasmHash": { "hash": hash } }),
        }
    }

    /// As a query parameter for the pubkey endpoint.
    pub fn query_pair(&self) -> (&'static str, &str) {
        match self {
            Self::Project(project_id) => ("project_id", project_id.as_str()),
            Self::WasmHash(hash) => ("wasm_hash", hash.as_str()),
        }
    }

    /// As the body fields the POST endpoints take.
    pub fn body_fields(&self) -> Value {
        let (key, value) = self.query_pair();
        serde_json::json!({ key: value })
    }

    /// For a message a human reads.
    pub fn describe(&self) -> String {
        match self {
            Self::Project(project_id) => project_id.clone(),
            Self::WasmHash(hash) => format!("wasm {hash}"),
        }
    }
}

/// The answer to `/secrets/pubkey`: the key to encrypt to, and — for a
/// repository — the spelling the rest of the system uses.
///
/// **The normalised repo is not decoration.** The keystore normalises a
/// repository URL before it asks the CONTRACT for a secret
/// (`accessor_to_contract_json`), so a secret stored under the spelling a
/// person typed — `https://github.com/a/b`, `git@github.com:a/b` — is one the
/// reader never asks for. It stores, it encrypts to the right key, and it is
/// never found at run time. Taking the normalised form from this answer is how
/// the dashboard has always avoided that, and now how this does: one authority
/// for the rule, which lives in the keystore.
#[derive(Debug, Clone)]
pub struct SecretsPubkey {
    /// X25519 public key, hex. Encrypt-only.
    pub pubkey: String,
    /// The repository as the keystore spells it. `None` for the accessors that
    /// have nothing to normalise.
    pub repo_normalized: Option<String>,
}

/// What to seal a secret to, and the name it will be stored under.
#[derive(Debug, Deserialize)]
pub struct AgentSecretPubkey {
    /// X25519 public key, hex. Encrypt-only.
    pub pubkey: String,
    /// The seed the key belongs to. Returned so that a mismatch is
    /// visible instead of silent — see `check_agent_secret_pubkey`.
    pub seed: String,
    /// The agent's account: both the secret's name and its owner.
    pub agent_account: String,
}

#[derive(Debug, Deserialize)]
pub struct StoredAgentSecret {
    pub tx_hash: String,
    pub agent_account: String,
}

/// A `store_agent_secret` call, ready for the payer to send.
#[derive(Debug, Deserialize)]
pub struct PreparedAgentSecret {
    pub contract_id: String,
    pub method_name: String,
    /// Complete JSON arguments, including the agent wallet's signature.
    pub args: Value,
    /// Attached deposit in yoctoNEAR; the contract refunds the excess.
    pub deposit: String,
    pub gas: String,
    pub agent_account: String,
}

/// A `delete_agent_secret` call, ready for the payer to send.
///
/// No deposit: the method is not payable, and the storage stake travels
/// the other way — back to whoever sends this.
#[derive(Debug, Deserialize)]
pub struct PreparedAgentSecretDelete {
    pub contract_id: String,
    pub method_name: String,
    /// Complete JSON arguments, including the agent wallet's signature.
    pub args: Value,
    pub gas: String,
    pub agent_account: String,
}
