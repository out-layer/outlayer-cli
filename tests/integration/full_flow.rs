use serde_json::json;
use serial_test::serial;

use outlayer_cli::api::GetPubkeyRequest;
use outlayer_cli::crypto;

use crate::common::require_testnet;

const KNOWN_PROJECT: &str = "zavodil2.testnet/test-storage";

/// Helper: poll list_user_secrets until predicate matches (or timeout).
async fn wait_for_secrets(
    near: &outlayer_cli::near::NearClient,
    account_id: &str,
    predicate: impl Fn(&[outlayer_cli::near::UserSecretInfo]) -> bool,
    label: &str,
) {
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        let secrets = near
            .list_user_secrets(account_id)
            .await
            .unwrap_or_default();
        if predicate(&secrets) {
            return;
        }
    }
    panic!("Timed out waiting for: {label}");
}

#[tokio::test]
#[serial]
async fn test_full_flow() {
    let ctx = require_testnet!();
    let signer = ctx.signer();

    // 1. Verify known project exists
    let project = ctx
        .near
        .get_project(KNOWN_PROJECT)
        .await
        .expect("get_project failed")
        .expect("Known project should exist");
    assert_eq!(project.project_id, KNOWN_PROJECT);
    eprintln!("  project {KNOWN_PROJECT} exists");

    // 2. Verify has active version
    let versions = ctx
        .near
        .list_versions(KNOWN_PROJECT, None, Some(10))
        .await
        .expect("list_versions failed");
    assert!(
        versions.iter().any(|v| v.is_active),
        "Project should have an active version"
    );

    // 3. Create payment key
    let nonce = ctx
        .near
        .get_next_payment_key_nonce(&ctx.account_id)
        .await
        .expect("get_next_payment_key_nonce failed");

    let secret = crypto::generate_payment_key_secret();
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

    let encrypted_key =
        crypto::encrypt_secrets(&pubkey, &secrets_json).expect("encrypt failed");

    signer
        .call_contract(
            "store_secrets",
            json!({
                "accessor": { "System": "PaymentKey" },
                "profile": nonce.to_string(),
                "encrypted_secrets_base64": encrypted_key,
                "access": "AllowAll"
            }),
            100_000_000_000_000u64,
            100_000_000_000_000_000_000_000u128,
        )
        .await
        .expect("store payment key failed");
    eprintln!("  payment key nonce={nonce} created");

    // 4. Verify key in list
    let nonce_str = nonce.to_string();
    wait_for_secrets(
        &ctx.near,
        &ctx.account_id,
        |secrets| {
            secrets.iter().any(|s| {
                s.accessor.to_string().contains("System") && s.profile == nonce_str
            })
        },
        "payment key to appear",
    )
    .await;

    // 5. Store project secrets
    let random_hash = crypto::generate_payment_key_secret();
    let accessor_coordinator = json!({"type": "WasmHash", "hash": &random_hash});
    let accessor_contract = json!({"WasmHash": {"hash": &random_hash}});
    let profile = "integ-test";

    let secret_data = json!({"INTEG_KEY": "integ_value"}).to_string();
    let pubkey_s = ctx
        .api
        .get_secrets_pubkey(&GetPubkeyRequest {
            accessor: accessor_coordinator,
            owner: ctx.account_id.clone(),
            profile: Some(profile.to_string()),
            secrets_json: secret_data.clone(),
        })
        .await
        .expect("get_secrets_pubkey failed");

    let encrypted_s =
        crypto::encrypt_secrets(&pubkey_s, &secret_data).expect("encrypt failed");

    signer
        .call_contract(
            "store_secrets",
            json!({
                "accessor": accessor_contract,
                "profile": profile,
                "encrypted_secrets_base64": encrypted_s,
                "access": "AllowAll",
            }),
            50_000_000_000_000u64,
            100_000_000_000_000_000_000_000u128,
        )
        .await
        .expect("store secrets failed");
    eprintln!("  secrets stored (hash={:.8}...)", &random_hash);

    // 6. Verify secret in list
    let hash_clone = random_hash.clone();
    wait_for_secrets(
        &ctx.near,
        &ctx.account_id,
        |secrets| {
            secrets
                .iter()
                .any(|s| s.accessor.to_string().contains(&hash_clone) && s.profile == profile)
        },
        "secret to appear",
    )
    .await;

    // 7. Execute test-storage
    let result = ctx
        .call_project("zavodil2.testnet", "test-storage", json!({"command": "test_all"}))
        .await;
    assert_eq!(result.status, "completed");
    eprintln!("  execution completed");

    // 8. Cleanup
    signer
        .call_contract(
            "delete_secrets",
            json!({
                "accessor": {"WasmHash": {"hash": &random_hash}},
                "profile": profile,
            }),
            30_000_000_000_000u64,
            0,
        )
        .await
        .expect("delete secrets failed");

    signer
        .call_contract(
            "delete_payment_key",
            json!({ "nonce": nonce }),
            100_000_000_000_000u64,
            1,
        )
        .await
        .expect("delete payment key failed");

    let hash_clone2 = random_hash.clone();
    let nonce_str2 = nonce.to_string();
    wait_for_secrets(
        &ctx.near,
        &ctx.account_id,
        |secrets| {
            let secret_gone = !secrets.iter().any(|s| s.accessor.to_string().contains(&hash_clone2));
            let key_gone = !secrets.iter().any(|s| {
                s.accessor.to_string().contains("System") && s.profile == nonce_str2
            });
            secret_gone && key_gone
        },
        "cleanup to complete",
    )
    .await;
    eprintln!("  cleanup done");
}
