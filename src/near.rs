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

// ── Paged views ────────────────────────────────────────────────────────

/// How many index entries a page of `list_user_secrets` asks for. Below the
/// contract's own ceiling of 500, so the window is exactly what is requested.
const SECRETS_PAGE: u64 = 200;

/// Walk a paged view until a page comes back EMPTY, and return everything.
///
/// `from_index` counts INDEX ENTRIES, not answers. `list_user_secrets` takes
/// its window first and only then drops entries whose secret is gone, so a
/// window of `page` keys can answer with fewer items — and advancing by what
/// came back would re-read part of the window and, worse, read a short page as
/// the end of the list. This advances by the window size, and an empty answer
/// is the only signal it treats as "nothing left".
///
/// Written as its own function so the walk can be exercised without a network:
/// the loop is the part with the interesting failure modes, and the version
/// before this one shipped with two of them.
async fn collect_pages<T, F, Fut>(page: u64, mut fetch: F) -> Result<Vec<T>>
where
    F: FnMut(u64) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<T>>>,
{
    let mut all: Vec<T> = Vec::new();
    let mut from_index: u64 = 0;
    loop {
        let batch = fetch(from_index).await?;
        if batch.is_empty() {
            return Ok(all);
        }
        all.extend(batch);
        from_index += page;
    }
}

// ── NearClient (view calls, no auth) ───────────────────────────────────

/// How long a transaction that has executed is given to reach a final block:
/// finality follows execution by two or three blocks.
const FINALITY_WAIT: std::time::Duration = std::time::Duration::from_secs(30);
/// How long to wait before asking again about a transaction a node had no
/// answer for. The next block is about a second away; asking sooner gets the
/// same answer.
const FINALITY_POLL: std::time::Duration = std::time::Duration::from_secs(2);

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
        self.view_call_at(contract_id, method, args, Finality::Final).await
    }

    /// A view at the given finality. `Final` for anything shown to a person;
    /// `None` (optimistic) where a value this process just wrote must be seen
    /// at once — see [`Self::get_next_payment_key_nonce`].
    async fn view_call_at<T: serde::de::DeserializeOwned>(
        &self,
        contract_id: &str,
        method: &str,
        args: Value,
        finality: Finality,
    ) -> Result<T> {
        let account_id: AccountId = contract_id
            .parse()
            .with_context(|| format!("Invalid contract_id '{contract_id}'"))?;

        let request = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(finality),
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

    /// Wait until the transaction `tx_hash`, sent by `sender`, is in a FINAL
    /// block. A transaction call answers once the transaction has executed,
    /// two or three blocks before its block is final, and the views of this
    /// client read at final finality: one made after this wait sees what the
    /// transaction wrote.
    ///
    /// A node that has not seen the transaction yet, one that gave up waiting
    /// (its own timeout, a 408), one that is unavailable (a 503), or no answer
    /// at all says nothing about it, so the status is asked again until
    /// [`FINALITY_WAIT`]. Any other answer is
    /// the error. Only the status read is repeated, never the transaction.
    pub async fn wait_until_final(&self, tx_hash: &str, sender: &str) -> Result<()> {
        use near_jsonrpc_client::errors::{
            JsonRpcError, JsonRpcServerError, JsonRpcServerResponseStatusError,
        };
        use near_jsonrpc_primitives::types::transactions::{RpcTransactionError, TransactionInfo};
        use near_primitives::views::TxExecutionStatus;

        let hash: CryptoHash = tx_hash
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid transaction hash '{tx_hash}': {e}"))?;
        let sender: AccountId = sender
            .parse()
            .with_context(|| format!("Invalid account_id '{sender}'"))?;

        let deadline = tokio::time::Instant::now() + FINALITY_WAIT;
        loop {
            let request = methods::tx::RpcTransactionStatusRequest {
                transaction_info: TransactionInfo::TransactionId {
                    tx_hash: hash,
                    sender_account_id: sender.clone(),
                },
                wait_until: TxExecutionStatus::Final,
            };
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let error = match tokio::time::timeout(left, self.client.call(request)).await {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(e)) => e,
                Err(_) => anyhow::bail!("its block is not final after {} s", FINALITY_WAIT.as_secs()),
            };
            let says_nothing = matches!(
                error.handler_error(),
                Some(RpcTransactionError::UnknownTransaction { .. })
                    | Some(RpcTransactionError::TimeoutError)
            ) || matches!(
                error,
                JsonRpcError::TransportError(_)
                    | JsonRpcError::ServerError(JsonRpcServerError::ResponseStatusError(
                        JsonRpcServerResponseStatusError::TimeoutError
                            | JsonRpcServerResponseStatusError::ServiceUnavailable
                    ))
            );
            if !says_nothing {
                return Err(anyhow::Error::from(error))
                    .context("the node could not say whether its block is final");
            }
            if tokio::time::Instant::now() + FINALITY_POLL >= deadline {
                anyhow::bail!("its block is not final after {} s", FINALITY_WAIT.as_secs());
            }
            tokio::time::sleep(FINALITY_POLL).await;
        }
    }

    /// The next free payment-key nonce, read at OPTIMISTIC finality: a final
    /// read lags the head by a block or two, so a `keys create` right after
    /// another would be handed the nonce that create just took, and write the
    /// new key over the live one in the local store.
    pub async fn get_next_payment_key_nonce(&self, account_id: &str) -> Result<u32> {
        let result: u32 = self
            .view_call_at(
                &self.network.contract_id,
                "get_next_payment_key_nonce",
                serde_json::json!({ "account_id": account_id }),
                Finality::None,
            )
            .await?;
        Ok(result)
    }

    /// Every secret of an account, by asking for pages until one comes back
    /// empty.
    ///
    /// The contract hands out a PAGE — it walks a set and reads storage per
    /// entry, so an unbounded answer is a view that eventually cannot be called
    /// at all. Taking the first page and calling it "the list" would show
    /// somebody a truncated inventory of their own secrets with nothing to say
    /// so, which is the failure this loop exists to prevent.
    ///
    /// **`from_index` counts KEYS, not answers.** The contract skips and takes
    /// over the index and only then drops entries whose secret is gone, so a
    /// window of `PAGE` keys can come back with fewer items — advancing by what
    /// was RETURNED would re-read part of the window and, worse, treat a short
    /// page as the end of the list. This walks by the window size and stops on
    /// an empty answer, which is the only reading of "nothing left" that does
    /// not depend on how many entries the contract filtered out.
    pub async fn list_user_secrets(&self, account_id: &str) -> Result<Vec<UserSecretInfo>> {
        collect_pages(SECRETS_PAGE, |from_index| async move {
            self.view_call(
                "list_user_secrets",
                serde_json::json!({
                    "account_id": account_id,
                    "from_index": from_index,
                    "limit": SECRETS_PAGE,
                }),
            )
            .await
        })
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

    /// What `request_execution` requires attached for these limits, an
    /// `input_data` of `input_len` bytes and an output of up to `output_len`
    /// bytes. The contract holds a deposit for the input beyond 32 KB and for
    /// every byte of a stored output, and returns it at settlement.
    pub async fn estimate_execution_cost(
        &self,
        resource_limits: Option<Value>,
        input_len: usize,
        output_len: usize,
    ) -> Result<String> {
        self.view_call(
            "estimate_execution_cost",
            serde_json::json!({
                "resource_limits": resource_limits,
                "input_len": input_len,
                "output_len": output_len,
            }),
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
        let actions = vec![Action::FunctionCall(Box::new(FunctionCallAction {
            method_name: method_name.to_string(),
            args: args.to_string().into_bytes(),
            gas,
            deposit,
        }))];
        self.commit_actions(receiver_id, actions)
            .await
            .context("Transaction failed")
    }

    /// Sign `actions` to `receiver_id` as one transaction and block until it
    /// is executed (`broadcast_tx_commit`).
    ///
    /// Signed from a fresh context; refused once for its nonce, signed
    /// again from a fresher one. A refusal here is pre-inclusion: the
    /// transaction never ran, so the second try is the first that can. Any
    /// other failure is returned as it is and nothing is sent again.
    async fn commit_actions(
        &self,
        receiver_id: &AccountId,
        actions: Vec<Action>,
    ) -> Result<FinalExecutionOutcomeView> {
        let mut nonce_refusals = 0u32;
        loop {
            let (current_nonce, block_hash) = self.get_tx_context().await?;
            let transaction = Transaction::V0(TransactionV0 {
                signer_id: self.account_id.clone(),
                public_key: self.signer.public_key(),
                nonce: current_nonce + 1,
                receiver_id: receiver_id.clone(),
                block_hash,
                actions: actions.clone(),
            });
            let signature = self.signer.sign(transaction.get_hash_and_size().0.as_ref());
            let signed_transaction =
                near_primitives::transaction::SignedTransaction::new(signature, transaction);

            match self
                .client
                .call(methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
                    signed_transaction,
                })
                .await
            {
                Ok(outcome) => return Ok(outcome),
                Err(e) if is_invalid_nonce(&e) && nonce_refusals < 1 => nonce_refusals += 1,
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// The access key's nonce and a block hash to sign the next transaction
    /// with. The nonce is read at OPTIMISTIC finality: a transaction sent a
    /// moment ago (by this process, or by near-cli in the same script) has
    /// already taken the nonce a final read still shows free, and the chain
    /// refuses the duplicate as `InvalidNonce`. The block hash stays FINAL:
    /// a transaction built on a block that is then dropped is invalid.
    pub async fn get_tx_context(&self) -> Result<(u64, CryptoHash)> {
        let access_key_query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::None),
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

        self.commit_actions(vault_account_id, actions)
            .await
            .context("Atomic vault-deploy transaction failed")
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

/// Whether the chain refused a transaction for its nonce: the one refusal
/// that is this signer's own doing and goes away with a fresh read.
fn is_invalid_nonce(
    e: &near_jsonrpc_client::errors::JsonRpcError<
        near_jsonrpc_primitives::types::transactions::RpcTransactionError,
    >,
) -> bool {
    use near_jsonrpc_client::errors::{JsonRpcError, JsonRpcServerError};
    use near_jsonrpc_primitives::types::transactions::RpcTransactionError;
    use near_primitives::errors::InvalidTxError;
    matches!(
        e,
        JsonRpcError::ServerError(JsonRpcServerError::HandlerError(
            RpcTransactionError::InvalidTransaction {
                context: InvalidTxError::InvalidNonce { .. },
            }
        ))
    )
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
                if resp.status == "processing" {
                    anyhow::bail!("{}", processing_message(&resp));
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

/// A call the wallet sent and the node did not confirm in time: not a failure, and not to be
/// sent again — it is charged, and a second send is a second call.
fn processing_message(resp: &crate::api::WalletCallResponse) -> String {
    let poll = resp
        .poll_url
        .clone()
        .unwrap_or_else(|| format!("/wallet/v1/requests/{}", resp.request_id));
    format!(
        "Transaction sent, outcome not confirmed yet (request: {}, tx: {}). It may still \
         complete: read GET {} for its outcome. Do not send it again — that would be a second \
         call.",
        resp.request_id,
        resp.tx_hash.as_deref().unwrap_or("unknown"),
        poll
    )
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

#[cfg(test)]
mod paged_view_tests {
    use super::*;
    use std::cell::RefCell;

    /// Serve `total` items in windows of `page`, dropping the entries listed in
    /// `holes` — the shape `list_user_secrets` produces when the index holds a
    /// key whose secret is gone. Records the offsets it was asked for.
    fn server<'a>(
        total: u64,
        page: u64,
        holes: &'static [u64],
        asked: &'a RefCell<Vec<u64>>,
    ) -> impl Fn(u64) -> std::future::Ready<Result<Vec<u64>>> + 'a {
        move |from_index: u64| {
            asked.borrow_mut().push(from_index);
            let items: Vec<u64> = (from_index..(from_index + page).min(total))
                .filter(|i| !holes.contains(i))
                .collect();
            std::future::ready(Ok(items))
        }
    }

    /// The whole list comes back, and the walk stops one page past the end.
    #[tokio::test]
    async fn it_collects_every_page() {
        let asked = RefCell::new(Vec::new());
        let got = collect_pages(10, server(25, 10, &[], &asked)).await.unwrap();

        assert_eq!(got.len(), 25);
        assert_eq!(got, (0..25).collect::<Vec<u64>>());
        assert_eq!(*asked.borrow(), vec![0, 10, 20, 30], "one empty page ends it");
    }

    /// A SHORT page is not the end of the list.
    ///
    /// This is the bug the walk was written for: the contract filters after it
    /// takes its window, so a page can be short while entries remain behind it.
    /// A loop that stopped here would silently show somebody part of their own
    /// inventory.
    #[tokio::test]
    async fn a_short_page_does_not_end_the_walk() {
        let asked = RefCell::new(Vec::new());
        // Every entry in the second window is missing but the third is full.
        let holes: &'static [u64] = &[10, 11, 12, 13, 14, 15, 16, 17, 18];
        let got = collect_pages(10, server(25, 10, holes, &asked)).await.unwrap();

        assert_eq!(got.len(), 16, "nine dropped entries, everything else kept");
        assert!(got.contains(&24), "the page BEHIND the short one must be read");
        assert_eq!(*asked.borrow(), vec![0, 10, 20, 30]);
    }

    /// An account with nothing asks once and answers nothing.
    #[tokio::test]
    async fn an_empty_account_costs_one_call() {
        let asked = RefCell::new(Vec::new());
        let got = collect_pages(10, server(0, 10, &[], &asked)).await.unwrap();

        assert!(got.is_empty());
        assert_eq!(*asked.borrow(), vec![0]);
    }

    /// A failing page fails the walk rather than truncating it: half a list
    /// reported as the whole list is the failure this must never produce.
    #[tokio::test]
    async fn a_failed_page_is_not_a_short_list() {
        let asked = RefCell::new(Vec::new());
        let result = collect_pages(10, |from_index: u64| {
            asked.borrow_mut().push(from_index);
            std::future::ready(if from_index == 0 {
                Ok((0..10).collect::<Vec<u64>>())
            } else {
                Err(anyhow::anyhow!("rpc said no"))
            })
        })
        .await;

        assert!(result.is_err(), "the caller must not receive a partial list");
        assert_eq!(*asked.borrow(), vec![0, 10]);
    }
}

#[cfg(test)]
mod processing_tests {
    #[test]
    fn a_processing_call_is_reported_as_sent_not_failed() {
        let resp: crate::api::WalletCallResponse = serde_json::from_str(
            r#"{"request_id":"r1","status":"processing","tx_hash":"Hx","poll_url":"/wallet/v1/requests/r1"}"#,
        )
        .unwrap();
        let msg = super::processing_message(&resp);
        assert!(msg.contains("r1") && msg.contains("Hx") && msg.contains("/wallet/v1/requests/r1"), "{msg}");
        assert!(!msg.contains("failed"), "{msg}");
        assert!(msg.contains("Do not send it again"), "{msg}");
    }
}

/// A JSON-RPC endpoint for tests: one connection per request (every answer
/// says `Connection: close`), answered by a closure over the request's JSON.
#[cfg(test)]
pub(crate) mod fake_rpc {
    use std::io::{Read, Write};

    /// An HTTP status and a body.
    pub type Answer = (u16, String);

    /// Serve requests until the test process ends; returns the URL.
    pub fn serve<F>(answer: F) -> String
    where
        F: Fn(&serde_json::Value) -> Answer + Send + 'static,
    {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.expect("accept");
                let request = read_body(&mut stream);
                let (status, body) = answer(&request);
                let reply = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    fn read_body(stream: &mut std::net::TcpStream) -> serde_json::Value {
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).expect("read");
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&data);
            if let Some(end) = text.find("\r\n\r\n") {
                let length = text[..end]
                    .lines()
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                if data.len() >= end + 4 + length {
                    return serde_json::from_slice(&data[end + 4..end + 4 + length]).expect("json body");
                }
            }
        }
        serde_json::Value::Null
    }

    /// A `tx` answer: the transaction's block is final.
    pub fn tx_final() -> Answer {
        (200, r#"{"jsonrpc":"2.0","id":"dontcare","result":{"final_execution_status":"FINAL"}}"#.to_string())
    }

    /// A `tx` answer: the node has not seen the transaction.
    pub fn tx_unknown() -> Answer {
        (200, r#"{"jsonrpc":"2.0","id":"dontcare","error":{"name":"HANDLER_ERROR","cause":{"name":"UNKNOWN_TRANSACTION","info":{"requested_transaction_hash":"11111111111111111111111111111111"}},"code":-32000,"message":"Server error","data":"unknown"}}"#.to_string())
    }

    /// A `tx` answer: the node gave up waiting, with the status nearcore sends.
    pub fn tx_timeout_408() -> Answer {
        (408, r#"{"jsonrpc":"2.0","id":"dontcare","error":{"name":"HANDLER_ERROR","cause":{"name":"TIMEOUT_ERROR"},"code":-32000,"message":"Server error","data":"timeout"}}"#.to_string())
    }

    /// A `tx` answer: the node, or the load balancer before it, is unavailable.
    pub fn tx_unavailable_503() -> Answer {
        (503, "Service Unavailable".to_string())
    }

    /// A `tx` answer about the transaction itself: it is invalid. The cause
    /// carries no detail; the client reads it from `data`, as nearcore sends it.
    pub fn tx_invalid() -> Answer {
        (200, r#"{"jsonrpc":"2.0","id":"dontcare","error":{"name":"HANDLER_ERROR","cause":{"name":"INVALID_TRANSACTION","info":{}},"code":-32000,"message":"Server error","data":{"TxExecutionError":{"InvalidTxError":{"InvalidNonce":{"tx_nonce":1,"ak_nonce":2}}}}}}"#.to_string())
    }

    /// A `query` answer to a view call that returned `value`.
    pub fn view_result(value: &serde_json::Value) -> Answer {
        let bytes: Vec<u8> = value.to_string().into_bytes();
        (
            200,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": "dontcare",
                "result": {
                    "result": bytes,
                    "logs": [],
                    "block_height": 1,
                    "block_hash": "11111111111111111111111111111111"
                }
            })
            .to_string(),
        )
    }

    /// A network config whose RPC is `url`.
    pub fn network(url: &str) -> crate::config::NetworkConfig {
        let mut network = crate::config::NetworkConfig::testnet();
        network.rpc_url = url.to_string();
        network
    }
}

#[cfg(test)]
mod finality_tests {
    use super::fake_rpc::*;
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const HASH: &str = "11111111111111111111111111111111";

    /// `tx` requests answered from `answers` in order; counts them.
    fn tx_server(answers: Vec<Answer>) -> (String, Arc<AtomicUsize>) {
        let asked = Arc::new(AtomicUsize::new(0));
        let counted = asked.clone();
        let url = serve(move |request| {
            assert_eq!(request["method"], "tx", "{request}");
            assert_eq!(request["params"]["wait_until"], "FINAL", "{request}");
            let i = counted.fetch_add(1, Ordering::SeqCst);
            answers[i].clone()
        });
        (url, asked)
    }

    /// A node that has not seen the transaction, gave up waiting with a 408,
    /// or is unavailable with a 503, is asked again; the wait ends when one
    /// says the block is final.
    #[tokio::test]
    async fn the_finality_wait_asks_again_until_a_node_says_final() {
        let (url, asked) = tx_server(vec![tx_unknown(), tx_timeout_408(), tx_unavailable_503(), tx_final()]);
        NearClient::new(&network(&url))
            .wait_until_final(HASH, "alice.testnet")
            .await
            .expect("final on the fourth answer");
        assert_eq!(asked.load(Ordering::SeqCst), 4);
    }

    /// Any other answer of the node is the error, at once.
    #[tokio::test]
    async fn the_finality_wait_ends_on_an_answer_about_the_transaction() {
        let (url, asked) = tx_server(vec![tx_invalid(), tx_final()]);
        let e = NearClient::new(&network(&url))
            .wait_until_final(HASH, "alice.testnet")
            .await
            .expect_err("an invalid transaction is not waited on");
        assert!(format!("{e:#}").contains("could not say whether its block is final"), "{e:#}");
        assert_eq!(asked.load(Ordering::SeqCst), 1);
    }
}

#[cfg(test)]
mod nonce_retry_tests {
    use super::fake_rpc::*;
    use super::*;
    use std::sync::{Arc, Mutex};

    const BLOCK: &str = r#"{"author": "node.testnet", "chunks": [], "header": {"approvals": [], "block_body_hash": "11111111111111111111111111111111", "block_merkle_root": "11111111111111111111111111111111", "block_ordinal": 230977814, "challenges_result": [], "challenges_root": "11111111111111111111111111111111", "chunk_endorsements": null, "chunk_headers_root": "11111111111111111111111111111111", "chunk_mask": [], "chunk_receipts_root": "11111111111111111111111111111111", "chunk_tx_root": "11111111111111111111111111111111", "chunks_included": 10, "epoch_id": "11111111111111111111111111111111", "epoch_sync_data_hash": null, "gas_price": "100000000", "hash": "11111111111111111111111111111111", "height": 278986906, "last_ds_final_block": "11111111111111111111111111111111", "last_final_block": "11111111111111111111111111111111", "latest_protocol_version": 88, "next_bp_hash": "11111111111111111111111111111111", "next_epoch_id": "11111111111111111111111111111111", "outcome_root": "11111111111111111111111111111111", "prev_hash": "11111111111111111111111111111111", "prev_height": 278986905, "prev_state_root": "11111111111111111111111111111111", "random_value": "11111111111111111111111111111111", "rent_paid": "0", "shard_split": null, "signature": "ed25519:1111111111111111111111111111111111111111111111111111111111111111", "timestamp": 1795447465768503351, "timestamp_nanosec": "1795447465768503351", "total_supply": "2682033009173494030395088250616153", "validator_proposals": [], "validator_reward": "0"}}"#;

    fn rpc_ok(result: serde_json::Value) -> Answer {
        (200, serde_json::json!({"jsonrpc": "2.0", "id": "dontcare", "result": result}).to_string())
    }

    /// The chain refuses a transaction, for a reason other than its nonce.
    fn tx_expired() -> Answer {
        (200, r#"{"jsonrpc":"2.0","id":"dontcare","error":{"name":"HANDLER_ERROR","cause":{"name":"INVALID_TRANSACTION","info":{}},"code":-32000,"message":"Server error","data":{"TxExecutionError":{"InvalidTxError":"Expired"}}}}"#.to_string())
    }

    /// A node whose access key moves on by one with every read, and that
    /// answers broadcasts from `answers`; the nonces it was sent.
    fn node(answers: Vec<Answer>) -> (NearSigner, Arc<Mutex<Vec<u64>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let seen = sent.clone();
        let reads = Mutex::new(100u64);
        let url = serve(move |request| match request["method"].as_str() {
            Some("query") => {
                assert_eq!(request["params"]["finality"], "optimistic", "{request}");
                let mut nonce = reads.lock().unwrap();
                *nonce += 1;
                rpc_ok(serde_json::json!({
                    "nonce": *nonce, "permission": "FullAccess", "block_height": 1,
                    "block_hash": "11111111111111111111111111111111"
                }))
            }
            Some("block") => rpc_ok(serde_json::from_str(BLOCK).expect("block")),
            Some("broadcast_tx_commit") => {
                let bytes = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    request["params"][0].as_str().or(request["params"]["signed_tx_base64"].as_str()).expect("tx"),
                )
                .expect("base64");
                let tx: near_primitives::transaction::SignedTransaction = borsh::from_slice(&bytes).expect("tx");
                let mut sent = seen.lock().unwrap();
                sent.push(tx.transaction.nonce());
                answers[sent.len() - 1].clone()
            }
            other => panic!("unexpected {other:?}"),
        });
        let key = SecretKey::from_random(near_crypto::KeyType::ED25519).to_string();
        (NearSigner::new(&network(&url), "alice.testnet", &key).expect("signer"), sent)
    }

    async fn deploy(signer: &NearSigner) -> anyhow::Error {
        signer
            .atomic_deploy_vault(
                &"vault.alice.testnet".parse().unwrap(),
                1,
                [7; 32],
                serde_json::json!({}),
                1,
                SecretKey::from_random(near_crypto::KeyType::ED25519).public_key(),
                &"mpc.testnet".parse().unwrap(),
            )
            .await
            .expect_err("the node accepts nothing")
    }

    async fn call(signer: &NearSigner) -> anyhow::Error {
        signer
            .call_contract("m", serde_json::json!({}), 1, 0)
            .await
            .expect_err("the node accepts nothing")
    }

    /// Refused for its nonce, a vault deploy is signed once more, from a
    /// nonce read again, and the second answer is the answer.
    #[tokio::test]
    async fn a_vault_deploy_refused_for_its_nonce_is_signed_once_more() {
        let (signer, sent) = node(vec![tx_invalid(), tx_expired()]);
        let e = deploy(&signer).await;
        assert!(format!("{e:#}").contains("Atomic vault-deploy transaction failed"), "{e:#}");
        assert!(format!("{e:#}").contains("xpired"), "{e:#}");
        assert_eq!(*sent.lock().unwrap(), vec![102, 103]);
    }

    /// A second refusal for the nonce is the error: nothing is sent a third time.
    #[tokio::test]
    async fn a_second_nonce_refusal_ends_the_deploy() {
        let (signer, sent) = node(vec![tx_invalid(), tx_invalid(), tx_expired()]);
        deploy(&signer).await;
        assert_eq!(sent.lock().unwrap().len(), 2);
    }

    /// Any other failure sends nothing again: a transaction whose answer did
    /// not come may have run.
    #[tokio::test]
    async fn no_other_failure_is_sent_again() {
        for answer in [tx_expired(), tx_timeout_408(), tx_unavailable_503()] {
            let (signer, sent) = node(vec![answer.clone(), tx_expired()]);
            deploy(&signer).await;
            assert_eq!(sent.lock().unwrap().len(), 1, "deploy: {answer:?}");
            let (signer, sent) = node(vec![answer.clone(), tx_expired()]);
            call(&signer).await;
            assert_eq!(sent.lock().unwrap().len(), 1, "call: {answer:?}");
        }
    }

    /// A contract call takes the same one retry.
    #[tokio::test]
    async fn a_call_refused_for_its_nonce_is_signed_once_more() {
        let (signer, sent) = node(vec![tx_invalid(), tx_expired()]);
        let e = call(&signer).await;
        assert!(format!("{e:#}").contains("Transaction failed"), "{e:#}");
        assert_eq!(*sent.lock().unwrap(), vec![102, 103]);
    }
}
