use anyhow::{Context, Result};
use near_crypto::{InMemorySigner, SecretKey};
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_primitives::hash::CryptoHash;
use near_primitives::transaction::{Action, FunctionCallAction, Transaction, TransactionV0};
use near_primitives::types::{AccountId, BlockReference, Finality};
use near_primitives::views::FinalExecutionOutcomeView;
use serde_json::Value;

use crate::config::NetworkConfig;

// ── NearClient (view calls, no auth) ───────────────────────────────────

pub struct NearClient {
    client: JsonRpcClient,
    pub network: NetworkConfig,
}

impl NearClient {
    pub fn new(network: &NetworkConfig) -> Self {
        let client = JsonRpcClient::connect(&network.rpc_url);
        Self {
            client,
            network: network.clone(),
        }
    }

    pub async fn view_call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        args: Value,
    ) -> Result<T> {
        let contract_id: AccountId = self
            .network
            .contract_id
            .parse()
            .context("Invalid contract_id")?;

        let request = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: near_primitives::views::QueryRequest::CallFunction {
                account_id: contract_id,
                method_name: method.to_string(),
                args: args.to_string().into_bytes().into(),
            },
        };

        let response = self
            .client
            .call(request)
            .await
            .with_context(|| format!("Failed to call view method '{method}'"))?;

        if let near_jsonrpc_primitives::types::query::QueryResponseKind::CallResult(result) =
            response.kind
        {
            serde_json::from_slice(&result.result)
                .with_context(|| format!("Failed to parse response from '{method}'"))
        } else {
            anyhow::bail!("Unexpected response kind from '{method}'");
        }
    }

    pub async fn get_project(&self, project_id: &str) -> Result<Option<ProjectView>> {
        let result: Option<ProjectView> = self
            .view_call("get_project", serde_json::json!({ "project_id": project_id }))
            .await?;
        Ok(result)
    }

    pub async fn get_next_payment_key_nonce(&self, account_id: &str) -> Result<u32> {
        let result: u32 = self
            .view_call(
                "get_next_payment_key_nonce",
                serde_json::json!({ "account_id": account_id }),
            )
            .await?;
        Ok(result)
    }

    pub async fn list_user_secrets(&self, account_id: &str) -> Result<Vec<UserSecretInfo>> {
        self.view_call(
            "list_user_secrets",
            serde_json::json!({ "account_id": account_id }),
        )
        .await
    }

    pub async fn list_versions(
        &self,
        project_id: &str,
        from_index: Option<u64>,
        limit: Option<u64>,
    ) -> Result<Vec<VersionView>> {
        self.view_call(
            "list_versions",
            serde_json::json!({
                "project_id": project_id,
                "from_index": from_index,
                "limit": limit
            }),
        )
        .await
    }

    pub async fn get_developer_earnings(&self, account_id: &str) -> Result<String> {
        self.view_call(
            "get_developer_earnings",
            serde_json::json!({ "account_id": account_id }),
        )
        .await
    }

    pub async fn estimate_execution_cost(
        &self,
        resource_limits: Option<Value>,
    ) -> Result<String> {
        self.view_call(
            "estimate_execution_cost",
            serde_json::json!({ "resource_limits": resource_limits }),
        )
        .await
    }

    pub async fn get_version(
        &self,
        project_id: &str,
        version_key: &str,
    ) -> Result<Option<VersionView>> {
        self.view_call(
            "get_version",
            serde_json::json!({
                "project_id": project_id,
                "version_key": version_key
            }),
        )
        .await
    }
}

// ── NearSigner (mutations, requires auth) ──────────────────────────────

pub struct NearSigner {
    client: JsonRpcClient,
    signer: InMemorySigner,
    contract_id: AccountId,
}

impl NearSigner {
    pub fn new(network: &NetworkConfig, account_id: &str, private_key: &str) -> Result<Self> {
        let account_id: AccountId = account_id.parse().context("Invalid account_id")?;
        let contract_id: AccountId = network.contract_id.parse().context("Invalid contract_id")?;
        let secret_key: SecretKey = private_key.parse().context("Invalid private key")?;
        let signer = InMemorySigner::from_secret_key(account_id, secret_key);
        let client = JsonRpcClient::connect(&network.rpc_url);

        Ok(Self {
            client,
            signer,
            contract_id,
        })
    }

    pub async fn call_contract(
        &self,
        method_name: &str,
        args: Value,
        gas: u64,
        deposit: u128,
    ) -> Result<FinalExecutionOutcomeView> {
        // Get access key nonce
        let access_key_query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: near_primitives::views::QueryRequest::ViewAccessKey {
                account_id: self.signer.account_id.clone(),
                public_key: self.signer.public_key(),
            },
        };

        let access_key_response = self
            .client
            .call(access_key_query)
            .await
            .context("Failed to query access key")?;

        let current_nonce = match access_key_response.kind {
            near_jsonrpc_primitives::types::query::QueryResponseKind::AccessKey(access_key) => {
                access_key.nonce
            }
            _ => anyhow::bail!("Unexpected query response for access key"),
        };

        // Get latest block hash
        let block = self
            .client
            .call(methods::block::RpcBlockRequest {
                block_reference: BlockReference::Finality(Finality::Final),
            })
            .await
            .context("Failed to query block")?;

        let block_hash = block.header.hash;

        // Build TransactionV0
        let transaction_v0 = TransactionV0 {
            signer_id: self.signer.account_id.clone(),
            public_key: self.signer.public_key(),
            nonce: current_nonce + 1,
            receiver_id: self.contract_id.clone(),
            block_hash,
            actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: method_name.to_string(),
                args: args.to_string().into_bytes(),
                gas,
                deposit,
            }))],
        };

        let transaction = Transaction::V0(transaction_v0);

        // Sign
        let signature = self
            .signer
            .sign(transaction.get_hash_and_size().0.as_ref());
        let signed_transaction =
            near_primitives::transaction::SignedTransaction::new(signature, transaction);

        // Broadcast with commit
        let outcome = self
            .client
            .call(methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
                signed_transaction,
            })
            .await
            .context("Transaction failed")?;

        Ok(outcome)
    }

    /// Get current access key nonce and latest block hash for building transactions.
    pub async fn get_tx_context(&self) -> Result<(u64, CryptoHash)> {
        let access_key_query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: near_primitives::views::QueryRequest::ViewAccessKey {
                account_id: self.signer.account_id.clone(),
                public_key: self.signer.public_key(),
            },
        };

        let access_key_response = self
            .client
            .call(access_key_query)
            .await
            .context("Failed to query access key")?;

        let current_nonce = match access_key_response.kind {
            near_jsonrpc_primitives::types::query::QueryResponseKind::AccessKey(access_key) => {
                access_key.nonce
            }
            _ => anyhow::bail!("Unexpected query response for access key"),
        };

        let block = self
            .client
            .call(methods::block::RpcBlockRequest {
                block_reference: BlockReference::Finality(Finality::Final),
            })
            .await
            .context("Failed to query block")?;

        Ok((current_nonce, block.header.hash))
    }

    /// Send a raw function call to an arbitrary receiver (broadcast async, does not wait).
    /// Returns the transaction hash.
    pub async fn send_function_call_async(
        &self,
        receiver_id: &AccountId,
        method_name: &str,
        args: Vec<u8>,
        gas: u64,
        deposit: u128,
        nonce: u64,
        block_hash: CryptoHash,
    ) -> Result<CryptoHash> {
        let transaction_v0 = TransactionV0 {
            signer_id: self.signer.account_id.clone(),
            public_key: self.signer.public_key(),
            nonce,
            receiver_id: receiver_id.clone(),
            block_hash,
            actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: method_name.to_string(),
                args,
                gas,
                deposit,
            }))],
        };

        let transaction = Transaction::V0(transaction_v0);
        let signature = self
            .signer
            .sign(transaction.get_hash_and_size().0.as_ref());
        let signed_transaction =
            near_primitives::transaction::SignedTransaction::new(signature, transaction);

        let tx_hash = self
            .client
            .call(methods::broadcast_tx_async::RpcBroadcastTxAsyncRequest {
                signed_transaction,
            })
            .await
            .context("Failed to broadcast transaction")?;

        Ok(tx_hash)
    }
}

// ── Types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProjectView {
    pub uuid: String,
    pub owner: String,
    pub name: String,
    pub project_id: String,
    pub active_version: String,
    #[serde(default)]
    pub created_at: Option<u64>,
    #[serde(default)]
    pub storage_deposit: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VersionView {
    pub wasm_hash: String,
    pub source: Value,
    pub added_at: u64,
    pub is_active: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserSecretInfo {
    pub accessor: Value,
    pub profile: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub storage_deposit: String,
    pub access: Value,
}
