use serde_json::json;
use serial_test::serial;

use crate::common::require_testnet;

/// Execute test-storage, then verify the call appears in payment key usage logs.
/// Only works with payment key (HTTPS calls are tracked; on-chain are not).
#[tokio::test]
#[serial]
async fn test_logs_after_execution() {
    let ctx = require_testnet!();

    let key = match &ctx.payment_key {
        Some(k) => k,
        None => {
            eprintln!("  SKIP: logs test requires TESTNET_PAYMENT_KEY (on-chain calls have no usage log)");
            return;
        }
    };

    // 1. Execute test-storage via HTTPS
    let result = ctx
        .call_project("zavodil2.testnet", "test-storage", json!({"command": "test_all"}))
        .await;
    assert_eq!(result.status, "completed");

    let call_id = result.call_id.as_deref().expect("HTTPS call should have call_id");
    eprintln!("  executed call_id={call_id}");

    // 2. Query usage logs
    let usage = ctx
        .api
        .get_payment_key_usage(&key.owner, key.nonce, 20, 0)
        .await
        .expect("get_payment_key_usage failed");

    eprintln!("  usage log: {} entries", usage.usage.len());

    // 3. Our call should appear
    let entry = usage.usage.iter().find(|u| u.call_id == call_id);
    assert!(entry.is_some(), "call_id {call_id} should appear in usage log");

    let entry = entry.unwrap();
    assert_eq!(entry.status, "completed");
    assert_eq!(entry.project_id, "zavodil2.testnet/test-storage");
    eprintln!("  log: call_id={} project={} cost={}", entry.call_id, entry.project_id, entry.compute_cost);
}
