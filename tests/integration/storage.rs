use serde_json::json;
use serial_test::serial;

use outlayer_cli::crypto;

use crate::common::require_testnet;

#[tokio::test]
#[serial]
async fn test_storage_builtin_test_all() {
    let ctx = require_testnet!();

    let result = ctx
        .call_project("zavodil2.testnet", "test-storage", json!({"command": "test_all"}))
        .await;

    assert_eq!(result.status, "completed", "test_all should complete");

    let output = result.output.expect("test_all should have output");
    let output_str = output.to_string();
    assert!(
        output_str.contains("passed"),
        "test_all output should mention 'passed', got: {output_str}"
    );
    eprintln!("  test_all: {}", output.get("value").and_then(|v| v.as_str()).unwrap_or("ok"));
}

#[tokio::test]
#[serial]
async fn test_storage_set_and_get() {
    let ctx = require_testnet!();

    let random_suffix = &crypto::generate_payment_key_secret()[..8];
    let storage_key = format!("integ_{random_suffix}");

    // Set
    let set_result = ctx
        .call_project(
            "zavodil2.testnet",
            "test-storage",
            json!({"command": "set", "key": &storage_key, "value": "hello"}),
        )
        .await;
    assert_eq!(set_result.status, "completed", "Set should complete");

    // Get
    let get_result = ctx
        .call_project(
            "zavodil2.testnet",
            "test-storage",
            json!({"command": "get", "key": &storage_key}),
        )
        .await;
    assert_eq!(get_result.status, "completed", "Get should complete");

    let output = get_result.output.expect("Get should return output");
    let output_str = output.to_string();
    assert!(
        output_str.contains("hello"),
        "Get output should contain 'hello', got: {output_str}"
    );
    eprintln!("  storage[{storage_key}] = hello");
}
