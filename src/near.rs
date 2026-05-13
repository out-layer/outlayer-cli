use anyhow::{Context, Result};
use near_crypto::{InMemorySigner, PublicKey, SecretKey, Signer};
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_primitives::account::{AccessKey, AccessKeyPermission, FunctionCallPermission};
use near_primitives::hash::CryptoHash;
use near_primitives::action::{GlobalContractIdentifier, UseGlobalContractAction};
use near_primitives::transaction::{
    Action, AddKeyAction, CreateAccountAction, FunctionCallAction, Transaction,
    TransactionV0, TransferAction,
};
use near_primitives::types::{AccountId, BlockReference, Finality};
use near_primitives::views::FinalExecutionOutcomeView;
use serde_json::Value;

use crate::api::ApiClient;
use crate::config::{self, Credentials, NetworkConfig};

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
        self.view_call_on(&self.network.contract_id, method, args)
            .await
    }

    /// Like [`view_call`] but targets an arbitrary contract — used by
    /// `outlayer vault` for keystore-DAO and per-vault contract reads.
    pub async fn view_call_on<T: serde::de::DeserializeOwned>(
        &self,
        contract_id: &str,
        method: &str,
        args: Value,
    ) -> Result<T> {
        let account_id: AccountId = contract_id
            .parse()
            .with_context(|| format!("Invalid contract_id '{contract_id}'"))?;

        let request = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: near_primitives::views::QueryRequest::CallFunction {
                account_id,
                method_name: method.to_string(),
                args: args.to_string().into_bytes().into(),
            },
        };

        let response = self
            .client
            .call(request)
            .await
            .with_context(|| format!("Failed to call view method '{contract_id}.{method}'"))?;

        if let near_jsonrpc_primitives::types::query::QueryResponseKind::CallResult(result) =
            response.kind
        {
            serde_json::from_slice(&result.result).with_context(|| {
                format!("Failed to parse response from '{contract_id}.{method}'")
            })
        } else {
            anyhow::bail!("Unexpected response kind from '{contract_id}.{method}'");
        }
    }

    /// View `Account` data — returns the LOCAL code hash, the optional
    /// NEP-591 global-contract hash, the balance and an existence flag.
    /// Used by `outlayer vault init` for parent-balance pre-flight and
    /// by `outlayer vault verify` to confirm the vault is running an
    /// approved code hash.
    ///
    /// Uses a raw JSON-RPC `query { view_account }` call rather than the
    /// typed `near-jsonrpc-client` request because near-primitives
    /// 0.29.2's `AccountView` struct lacks the `global_contract_hash`
    /// field added by NEP-591 (UseGlobalContract). The raw response
    /// surfaces both `code_hash` (always `11111…` for global-contract
    /// accounts) and the optional `global_contract_hash` so verify can
    /// pick whichever is set via `AccountInfo::effective_code_hash`.
    pub async fn view_account_info(&self, account_id: &str) -> Result<AccountInfo> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "view_account",
            "method": "query",
            "params": {
                "request_type": "view_account",
                "finality": "final",
                "account_id": account_id,
            }
        });

        let resp: Value = reqwest::Client::new()
            .post(&self.network.rpc_url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("view_account('{account_id}') HTTP failed"))?
            .json()
            .await
            .with_context(|| format!("view_account('{account_id}') decode failed"))?;

        // RPC layer error: distinguish "no such account" (return
        // exists=false) from real failures (bubble up).
        if let Some(err) = resp.get("error") {
            let err_str = err.to_string();
            if err_str.contains("UnknownAccount") || err_str.contains("does not exist") {
                return Ok(AccountInfo::not_found());
            }
            anyhow::bail!("view_account('{account_id}') RPC error: {err_str}");
        }

        let result = resp
            .get("result")
            .ok_or_else(|| anyhow::anyhow!("view_account('{account_id}'): no result"))?;

        // NEAR JSON-RPC also encodes UnknownAccount inside result.error in
        // some versions. Probe before parsing fields.
        if let Some(name) = result.pointer("/cause/name").and_then(|v| v.as_str()) {
            if name == "UNKNOWN_ACCOUNT" {
                return Ok(AccountInfo::not_found());
            }
        }

        let code_hash = result
            .get("code_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let global_contract_hash = result
            .get("global_contract_hash")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        // `amount` is a decimal string of yoctoNEAR. A missing field or
        // parse failure here would normally read as "account has zero
        // balance" downstream and silently break the parent-funding
        // pre-flight check in `vault init`. Surface the malformed
        // response explicitly so debugging RPC mismatches doesn't take
        // a detour through "why does my vault deploy say I have 0 NEAR".
        let amount_str = result
            .get("amount")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "view_account('{account_id}'): RPC response missing `amount` field"
                )
            })?;
        let amount_yocto: u128 = amount_str.parse().with_context(|| {
            format!(
                "view_account('{account_id}'): malformed `amount` field '{amount_str}'"
            )
        })?;

        Ok(AccountInfo {
            exists: true,
            code_hash,
            global_contract_hash,
            amount_yocto,
        })
    }

    /// List all access keys on `account_id`. Used by `outlayer vault
    /// verify` to assert that the only access key is the TEE
    /// function-call key restricted to `request_app_private_key`.
    pub async fn view_access_key_list(&self, account_id: &str) -> Result<Vec<AccessKeyEntry>> {
        let parsed: AccountId = account_id
            .parse()
            .with_context(|| format!("Invalid account_id '{account_id}'"))?;
        let request = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: near_primitives::views::QueryRequest::ViewAccessKeyList {
                account_id: parsed,
            },
        };
        let response = self
            .client
            .call(request)
            .await
            .with_context(|| format!("Failed to view_access_key_list('{account_id}')"))?;
        let list = match response.kind {
            near_jsonrpc_primitives::types::query::QueryResponseKind::AccessKeyList(list) => list,
            _ => anyhow::bail!(
                "Unexpected response kind from view_access_key_list('{account_id}')"
            ),
        };
        let entries = list
            .keys
            .into_iter()
            .map(|info| {
                use near_primitives::views::{AccessKeyPermissionView, AccessKeyView};
                let AccessKeyView { permission, .. } = info.access_key;
                let permission = match permission {
                    AccessKeyPermissionView::FullAccess => AccessKeyPerm::FullAccess,
                    AccessKeyPermissionView::FunctionCall {
                        allowance,
                        receiver_id,
                        method_names,
                    } => AccessKeyPerm::FunctionCall {
                        allowance: allowance.map(|a| a.to_string()),
                        receiver_id,
                        method_names,
                    },
                };
                AccessKeyEntry {
                    public_key: info.public_key.to_string(),
                    permission,
                }
            })
            .collect();
        Ok(entries)
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
    // near-crypto 0.29 changed `InMemorySigner::from_secret_key` to
    // return a `Signer` enum (with `Signer::InMemory(InMemorySigner)`).
    // The enum exposes `public_key()` and `sign()` but not
    // `account_id` directly, so we keep the account id alongside it.
    signer: Signer,
    account_id: AccountId,
    contract_id: AccountId,
}

impl NearSigner {
    pub fn new(network: &NetworkConfig, account_id: &str, private_key: &str) -> Result<Self> {
        let account_id: AccountId = account_id.parse().context("Invalid account_id")?;
        let contract_id: AccountId = network.contract_id.parse().context("Invalid contract_id")?;
        let secret_key: SecretKey = private_key.parse().context("Invalid private key")?;
        let signer = InMemorySigner::from_secret_key(account_id.clone(), secret_key);
        let client = JsonRpcClient::connect(&network.rpc_url);

        Ok(Self {
            client,
            signer,
            account_id,
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
        let receiver = self.contract_id.clone();
        self.call_contract_at(&receiver, method_name, args, gas, deposit).await
    }

    /// Sign and submit a function call to an arbitrary receiver,
    /// blocking until tx finality (`broadcast_tx_commit`).
    pub async fn call_contract_at(
        &self,
        receiver_id: &AccountId,
        method_name: &str,
        args: Value,
        gas: u64,
        deposit: u128,
    ) -> Result<FinalExecutionOutcomeView> {
        // Get access key nonce
        let access_key_query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: near_primitives::views::QueryRequest::ViewAccessKey {
                account_id: self.account_id.clone(),
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

        let transaction_v0 = TransactionV0 {
            signer_id: self.account_id.clone(),
            public_key: self.signer.public_key(),
            nonce: current_nonce + 1,
            receiver_id: receiver_id.clone(),
            block_hash,
            actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: method_name.to_string(),
                args: args.to_string().into_bytes(),
                gas,
                deposit,
            }))],
        };

        let transaction = Transaction::V0(transaction_v0);
        let signature = self.signer.sign(transaction.get_hash_and_size().0.as_ref());
        let signed_transaction =
            near_primitives::transaction::SignedTransaction::new(signature, transaction);

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
                account_id: self.account_id.clone(),
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

    /// Build + sign + broadcast an atomic deploy of a vault sub-account.
    /// 5 actions in ONE transaction (so any single failure rolls the
    /// whole thing back — there is no half-deployed account state):
    ///   1. CreateAccount(vault_account_id)
    ///   2. Transfer(initial_balance) — storage stake (~0.004 NEAR
    ///      with `UseGlobalContract`) + gas reserve for the vault to
    ///      drive its own MPC CKD calls.
    ///   3. UseGlobalContract(code_hash) — NEP-591. The WASM bytes
    ///      live in NEAR's global-contract registry, not on this
    ///      account; the tx only carries the 32-byte hash. The hash
    ///      MUST already be deployed via
    ///      `near contract deploy-as-global ... as-global-hash` AND
    ///      whitelisted on keystore-DAO via `is_vault_code_approved`.
    ///   4. FunctionCall("new", new_args, gas, deposit=0)
    ///   5. AddKey(tee_pubkey, FCAK on vault.request_master, unlimited
    ///      allowance) — the proxy method on the vault contract that
    ///      adds the 1 yocto MPC's `assert_one_yocto` requires from the
    ///      vault's own balance via cross-contract call. Function-call
    ///      access keys cannot attach deposit themselves on NEAR.
    ///
    /// Used by `outlayer vault init`. Returns the final outcome so the
    /// caller can extract the tx hash and check the status.
    #[allow(clippy::too_many_arguments)]
    pub async fn atomic_deploy_vault(
        &self,
        vault_account_id: &AccountId,
        initial_balance: u128,
        // Raw 32-byte sha256 of the canonical vault WASM. The bytes
        // must already be in NEAR's global-contract registry under
        // this hash — no inline WASM is sent in this tx.
        vault_code_hash: [u8; 32],
        new_method_args: Value,
        new_gas: u64,
        tee_pubkey: PublicKey,
        // The vault contract account (= `vault_account_id`) becomes the
        // FCAK receiver. The keystore-worker calls `vault.request_master`
        // which proxies the MPC `request_app_private_key` call. Direct
        // MPC calls are blocked because MPC asserts 1 yocto and FC keys
        // can't attach deposit. Kept as a separate parameter to make the
        // intent explicit at call sites.
        _mpc_contract: &AccountId,
    ) -> Result<FinalExecutionOutcomeView> {
        let access_key_query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: near_primitives::views::QueryRequest::ViewAccessKey {
                account_id: self.account_id.clone(),
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

        let actions = vec![
            Action::CreateAccount(CreateAccountAction {}),
            Action::Transfer(TransferAction {
                deposit: initial_balance,
            }),
            Action::UseGlobalContract(Box::new(UseGlobalContractAction {
                contract_identifier: GlobalContractIdentifier::CodeHash(CryptoHash(
                    vault_code_hash,
                )),
            })),
            Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: "new".to_string(),
                args: new_method_args.to_string().into_bytes(),
                gas: new_gas,
                deposit: 0,
            })),
            Action::AddKey(Box::new(AddKeyAction {
                public_key: tee_pubkey,
                access_key: AccessKey {
                    nonce: 0,
                    permission: AccessKeyPermission::FunctionCall(FunctionCallPermission {
                        // `None` allowance = unlimited. The vault is funded
                        // by the Transfer action above; the TEE's calls
                        // pull gas from this balance via the FCAK.
                        allowance: None,
                        // Self-call into the vault's `request_master`
                        // proxy. MPC's `assert_one_yocto` is satisfied
                        // out of the vault's balance via the proxy's
                        // cross-contract call.
                        receiver_id: vault_account_id.to_string(),
                        method_names: vec!["request_master".to_string()],
                    }),
                },
            })),
        ];

        let transaction_v0 = TransactionV0 {
            signer_id: self.account_id.clone(),
            public_key: self.signer.public_key(),
            nonce: current_nonce + 1,
            receiver_id: vault_account_id.clone(),
            block_hash: block.header.hash,
            actions,
        };
        let transaction = Transaction::V0(transaction_v0);
        let signature = self.signer.sign(transaction.get_hash_and_size().0.as_ref());
        let signed_transaction =
            near_primitives::transaction::SignedTransaction::new(signature, transaction);

        let outcome = self
            .client
            .call(methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
                signed_transaction,
            })
            .await
            .context("Atomic vault-deploy transaction failed")?;
        Ok(outcome)
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
            signer_id: self.account_id.clone(),
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

// ── ContractCaller (local key or wallet API) ────────────────────────

/// Result of a contract call — includes the parsed return value and tx hash.
pub struct ContractCallResult {
    pub value: Option<Value>,
    pub tx_hash: Option<String>,
}

/// Unified interface for calling NEAR contracts — either with a local key
/// (NearSigner) or via the coordinator wallet API (wallet_key).
pub enum ContractCaller {
    Local(NearSigner),
    Wallet {
        api: ApiClient,
        wallet_key: String,
        contract_id: String,
    },
}

impl ContractCaller {
    /// Build a ContractCaller from stored credentials.
    pub fn from_credentials(creds: &Credentials, network: &NetworkConfig) -> Result<Self> {
        if creds.is_wallet_key() {
            let wk = creds
                .wallet_key
                .as_ref()
                .context("wallet_key missing from credentials")?;
            Ok(Self::Wallet {
                api: ApiClient::new(network),
                wallet_key: wk.clone(),
                contract_id: network.contract_id.clone(),
            })
        } else {
            let pk = config::load_private_key(&network.network_id, &creds.account_id, creds)?;
            Ok(Self::Local(NearSigner::new(
                network,
                &creds.account_id,
                &pk,
            )?))
        }
    }

    /// Call a method on the OutLayer contract. Returns parsed result value and tx hash.
    pub async fn call_contract(
        &self,
        method_name: &str,
        args: Value,
        gas: u64,
        deposit: u128,
    ) -> Result<ContractCallResult> {
        let receiver = self.default_receiver().to_string();
        self.call_contract_at(&receiver, method_name, args, gas, deposit).await
    }

    /// The receiver this caller targets when [`call_contract`] is used —
    /// the OutLayer contract for both backends. Custody-wallet calls can
    /// already retarget via the underlying `/wallet/v1/call` API, but
    /// `call_contract` keeps the network-default behaviour.
    fn default_receiver(&self) -> &str {
        match self {
            Self::Local(signer) => signer.contract_id.as_str(),
            Self::Wallet { contract_id, .. } => contract_id.as_str(),
        }
    }

    /// Call `method_name` on `receiver_id` (any contract — vault account,
    /// keystore-DAO, etc). Returns the parsed return value and tx hash.
    /// `Local`: signs with the user's NEAR key; `Wallet`: forwards through
    /// the coordinator's `/wallet/v1/call` (which itself only authorises
    /// calls the custody policy permits).
    pub async fn call_contract_at(
        &self,
        receiver_id: &str,
        method_name: &str,
        args: Value,
        gas: u64,
        deposit: u128,
    ) -> Result<ContractCallResult> {
        match self {
            Self::Local(signer) => {
                let receiver: AccountId = receiver_id
                    .parse()
                    .with_context(|| format!("Invalid receiver_id '{receiver_id}'"))?;
                let outcome = signer
                    .call_contract_at(&receiver, method_name, args, gas, deposit)
                    .await?;
                let tx_hash = Some(outcome.transaction_outcome.id.to_string());
                match &outcome.status {
                    near_primitives::views::FinalExecutionStatus::SuccessValue(bytes) => {
                        Ok(ContractCallResult {
                            value: serde_json::from_slice::<Value>(bytes).ok(),
                            tx_hash,
                        })
                    }
                    near_primitives::views::FinalExecutionStatus::Failure(err) => {
                        anyhow::bail!(
                            "Transaction failed (tx: {}): {:?}",
                            outcome.transaction_outcome.id, err
                        );
                    }
                    _ => Ok(ContractCallResult {
                        value: None,
                        tx_hash,
                    }),
                }
            }
            Self::Wallet {
                api,
                wallet_key,
                contract_id: _,
            } => {
                let resp = api
                    .wallet_call(wallet_key, receiver_id, method_name, args, gas, deposit)
                    .await?;
                if resp.status == "pending_approval" {
                    if let Some(id) = &resp.approval_id {
                        anyhow::bail!(
                            "Transaction requires approval (approval_id: {}). \
                             Approve it in the wallet dashboard.",
                            id
                        );
                    }
                    anyhow::bail!("Transaction requires approval.");
                }
                if resp.status != "success" {
                    let detail = resp.result.as_ref().map(|v| v.to_string()).unwrap_or_default();
                    let tx_info = resp.tx_hash.as_deref().unwrap_or("unknown");
                    anyhow::bail!(
                        "Transaction failed (tx: {}, status: {}): {}",
                        tx_info, resp.status, detail
                    );
                }
                Ok(ContractCallResult {
                    tx_hash: resp.tx_hash,
                    value: resp.result,
                })
            }
        }
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

/// Sentinel code hash returned by NEAR's `view_account` for accounts
/// that have no LOCAL contract deployed (32 zero bytes, base58). Note
/// that this is ALSO the value of `code_hash` for accounts using
/// NEP-591 `UseGlobalContract` — for those, the real hash sits in
/// `global_contract_hash`. Use `AccountInfo::effective_code_hash()` to
/// get whichever is meaningful.
pub const NO_CONTRACT_CODE_HASH: &str = "11111111111111111111111111111111";

#[derive(Debug, Clone)]
pub struct AccountInfo {
    /// `false` if the RPC returned `UnknownAccount` — the account does
    /// not exist on chain.
    pub exists: bool,
    /// LOCAL code hash. Sentinel `11111…` either means (a) no contract
    /// deployed or (b) the account uses a global contract — check
    /// `global_contract_hash` to disambiguate.
    pub code_hash: String,
    /// NEP-591 global-contract hash. `Some(b58)` when the account was
    /// deployed via `UseGlobalContract`; `None` for plain
    /// `DeployContract` or accounts with no contract.
    pub global_contract_hash: Option<String>,
    /// Account balance in yoctoNEAR. Zero when `exists = false`.
    pub amount_yocto: u128,
}

impl AccountInfo {
    fn not_found() -> Self {
        Self {
            exists: false,
            code_hash: String::new(),
            global_contract_hash: None,
            amount_yocto: 0,
        }
    }

    /// Return whichever code hash actually identifies the contract code
    /// running at this account: `global_contract_hash` if present (the
    /// account uses `UseGlobalContract`), otherwise `code_hash` if it
    /// isn't the empty-account sentinel. Returns `None` when the
    /// account has no contract at all.
    pub fn effective_code_hash(&self) -> Option<&str> {
        if let Some(h) = &self.global_contract_hash {
            return Some(h);
        }
        if self.code_hash != NO_CONTRACT_CODE_HASH && !self.code_hash.is_empty() {
            return Some(&self.code_hash);
        }
        None
    }
}

#[derive(Debug, Clone)]
pub struct AccessKeyEntry {
    pub public_key: String,
    pub permission: AccessKeyPerm,
}

#[derive(Debug, Clone)]
pub enum AccessKeyPerm {
    FullAccess,
    FunctionCall {
        /// `None` means unlimited allowance.
        allowance: Option<String>,
        receiver_id: String,
        method_names: Vec<String>,
    },
}
