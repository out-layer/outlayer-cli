use serial_test::serial;

use crate::common::require_testnet;

const KNOWN_PROJECT: &str = "zavodil2.testnet/test-storage";

#[tokio::test]
#[serial]
async fn test_get_existing_project() {
    let ctx = require_testnet!();

    let project = ctx
        .near
        .get_project(KNOWN_PROJECT)
        .await
        .expect("get_project failed");

    let project = project.expect("Known project should exist");
    assert_eq!(project.owner, "zavodil2.testnet");
    assert_eq!(project.name, "test-storage");
    assert_eq!(project.project_id, KNOWN_PROJECT);
}

#[tokio::test]
#[serial]
async fn test_get_nonexistent_project() {
    let ctx = require_testnet!();

    let project = ctx
        .near
        .get_project("nonexistent.testnet/fake-project-xyz")
        .await
        .expect("get_project should not error on missing project");

    assert!(project.is_none(), "Nonexistent project should return None");
}

#[tokio::test]
#[serial]
async fn test_list_versions() {
    let ctx = require_testnet!();

    let versions = ctx
        .near
        .list_versions(KNOWN_PROJECT, None, Some(10))
        .await
        .expect("list_versions failed");

    assert!(!versions.is_empty(), "Known project should have versions");

    let has_active = versions.iter().any(|v| v.is_active);
    assert!(has_active, "At least one version should be active");
}

#[tokio::test]
#[serial]
async fn test_get_developer_earnings() {
    let ctx = require_testnet!();

    let earnings = ctx
        .near
        .get_developer_earnings(&ctx.account_id)
        .await
        .expect("get_developer_earnings failed");

    // Should return a string (possibly "0")
    assert!(
        earnings.parse::<u128>().is_ok(),
        "Earnings should be a numeric string, got: {earnings}"
    );
}
