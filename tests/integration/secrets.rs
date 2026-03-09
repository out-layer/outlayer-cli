use serde_json::json;
use serial_test::serial;

use outlayer_cli::api::{GetPubkeyRequest, SecretsRef};
use outlayer_cli::crypto;

use crate::common::require_testnet;

/// Store a secret for test-storage project, verify it appears in list_user_secrets,
/// call project with `get_secret` to read it back, then clean up.
#[tokio::test]
#[serial]
async fn test_secrets_lifecycle() {
    let ctx = require_testnet!();
    let signer = ctx.signer();

    let project_id = format!("{}/test-secrets", ctx.account_id);
    let random_suffix = &crypto::generate_payment_key_secret()[..8];
    let secret_name = format!("INTEG_SECRET_{}", random_suffix.to_uppercase());
    let secret_value = format!("test_value_{random_suffix}");
    let profile = "default".to_string();

    let accessor_coordinator = json!({"type": "Project", "project_id": &project_id});
    let accessor_contract = json!({"Project": {"project_id": &project_id}});

    eprintln!("  storing secret {secret_name} for {project_id} (profile={profile})");

    // 1. Encrypt
    let secrets_json = json!({ &secret_name: &secret_value }).to_string();

    let pubkey = ctx
        .api
        .get_secrets_pubkey(&GetPubkeyRequest {
            accessor: accessor_coordinator,
            owner: ctx.account_id.clone(),
            profile: Some(profile.clone()),
            secrets_json: secrets_json.clone(),
        })
        .await
        .expect("get_secrets_pubkey failed");

    let encrypted =
        crypto::encrypt_secrets(&pubkey, &secrets_json).expect("encrypt_secrets failed");

    // 2. Store on contract
    signer
        .call_contract(
            "store_secrets",
            json!({
                "accessor": accessor_contract,
                "profile": &profile,
                "encrypted_secrets_base64": encrypted,
                "access": "AllowAll",
            }),
            50_000_000_000_000u64,
            100_000_000_000_000_000_000_000u128,
        )
        .await
        .expect("store_secrets failed");

    // 3. Verify in list (with finality retry)
    let pid = project_id.clone();
    let prof = profile.clone();
    crate::common::wait_for_view(
        || async {
            ctx.near
                .list_user_secrets(&ctx.account_id)
                .await
                .map(|s| {
                    s.iter().any(|s| {
                        s.accessor.to_string().contains(&pid) && s.profile == prof
                    })
                })
                .unwrap_or(false)
        },
        "secret to appear in list",
    )
    .await;
    eprintln!("  secret {secret_name} found in list_user_secrets");

    // 4. Call project with get_secret to read it back (passing secrets_ref)
    let (owner, project) = project_id.split_once('/').unwrap();
    let result = ctx
        .call_project_with_secrets(
            owner,
            project,
            json!({
                "command": "get_secret",
                "key": &secret_name
            }),
            Some(SecretsRef {
                profile: profile.clone(),
                account_id: ctx.account_id.clone(),
            }),
        )
        .await;
    assert_eq!(
        result.status, "completed",
        "get_secret call failed: {:?}",
        result.error
    );

    let output = result.output.expect("get_secret should return output");
    eprintln!(
        "  get_secret output: {}",
        serde_json::to_string_pretty(&output).unwrap()
    );

    // Verify the secret was found and value matches
    assert_eq!(output["success"], true, "get_secret should succeed");
    assert_eq!(output["found_count"], 1, "should find exactly 1 secret");

    let secret_info = &output["secrets"][0];
    assert_eq!(secret_info["key"], secret_name);
    assert_eq!(secret_info["found"], true, "secret should be found");
    assert_eq!(
        secret_info["value"].as_str().unwrap(),
        &secret_value,
        "secret value should match"
    );
    eprintln!("  secret {secret_name} = {secret_value} verified via get_secret ✓");

    // 5. Cleanup
    signer
        .call_contract(
            "delete_secrets",
            json!({
                "accessor": {"Project": {"project_id": &project_id}},
                "profile": &profile,
            }),
            30_000_000_000_000u64,
            0,
        )
        .await
        .expect("delete_secrets failed");

    // 6. Verify deleted
    let pid2 = project_id.clone();
    let prof2 = profile.clone();
    crate::common::wait_for_view(
        || async {
            ctx.near
                .list_user_secrets(&ctx.account_id)
                .await
                .map(|s| {
                    !s.iter().any(|s| {
                        s.accessor.to_string().contains(&pid2) && s.profile == prof2
                    })
                })
                .unwrap_or(false)
        },
        "secret to be deleted",
    )
    .await;
    eprintln!("  secret deleted, cleanup done");
}
