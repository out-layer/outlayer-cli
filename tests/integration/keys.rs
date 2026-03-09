use near_primitives::views::FinalExecutionStatus;
use serde_json::json;
use serial_test::serial;

use outlayer_cli::api::GetPubkeyRequest;
use outlayer_cli::crypto;

use crate::common::require_testnet;

#[tokio::test]
#[serial]
async fn test_get_next_nonce() {
    let ctx = require_testnet!();

    let nonce = ctx
        .near
        .get_next_payment_key_nonce(&ctx.account_id)
        .await
        .expect("get_next_payment_key_nonce failed");

    assert!(nonce >= 1, "Nonce should be >= 1, got: {nonce}");
}

#[tokio::test]
#[serial]
async fn test_payment_key_lifecycle() {
    let ctx = require_testnet!();
    let signer = ctx.signer();

    // 1. Read current nonce (used as profile for the new key)
    let nonce = ctx
        .near
        .get_next_payment_key_nonce(&ctx.account_id)
        .await
        .expect("get_next_payment_key_nonce failed");

    // 2. Generate payment key secret
    let secret = crypto::generate_payment_key_secret();
    assert_eq!(secret.len(), 64, "Secret should be 64 hex chars");

    // 3. Encrypt
    let secrets_json = json!({
        "key": secret,
        "project_ids": [],
        "max_per_call": null,
        "initial_balance": null
    })
    .to_string();

    let pubkey = ctx
        .api
        .get_secrets_pubkey(&GetPubkeyRequest {
            accessor: json!({"type": "System", "PaymentKey": {}}),
            owner: ctx.account_id.clone(),
            profile: Some(nonce.to_string()),
            secrets_json: secrets_json.clone(),
        })
        .await
        .expect("get_secrets_pubkey failed");

    let encrypted =
        crypto::encrypt_secrets(&pubkey, &secrets_json).expect("encrypt_secrets failed");

    // 4. Store on contract
    let deposit = 100_000_000_000_000_000_000_000u128; // 0.1 NEAR
    let gas = 100_000_000_000_000u64; // 100 TGas

    let outcome = signer
        .call_contract(
            "store_secrets",
            json!({
                "accessor": { "System": "PaymentKey" },
                "profile": nonce.to_string(),
                "encrypted_secrets_base64": encrypted,
                "access": "AllowAll"
            }),
            gas,
            deposit,
        )
        .await
        .expect("store_secrets (payment key) failed");

    match &outcome.status {
        FinalExecutionStatus::SuccessValue(_) => {}
        status => panic!("store_secrets tx failed: {status:?}"),
    }

    // 5. Verify key appears in list_user_secrets (retry for finality propagation)
    let nonce_str = nonce.to_string();
    crate::common::wait_for_view(
        || async {
            ctx.near
                .list_user_secrets(&ctx.account_id)
                .await
                .map(|s| {
                    s.iter().any(|s| {
                        s.accessor.to_string().contains("System") && s.profile == nonce_str
                    })
                })
                .unwrap_or(false)
        },
        &format!("payment key nonce {nonce} to appear in list"),
    )
    .await;

    // 6. Cleanup: delete payment key
    signer
        .call_contract(
            "delete_payment_key",
            json!({ "nonce": nonce }),
            100_000_000_000_000u64,
            1, // 1 yoctoNEAR
        )
        .await
        .expect("delete_payment_key failed");

    // 7. Verify deleted (retry for finality propagation)
    crate::common::wait_for_view(
        || async {
            ctx.near
                .list_user_secrets(&ctx.account_id)
                .await
                .map(|s| {
                    !s.iter().any(|s| {
                        s.accessor.to_string().contains("System") && s.profile == nonce_str
                    })
                })
                .unwrap_or(false)
        },
        "payment key to be deleted",
    )
    .await;
}
