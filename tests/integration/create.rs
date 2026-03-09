use serial_test::serial;

use crate::common::require_testnet;

#[tokio::test]
#[serial]
async fn test_create_basic_template() {
    let ctx = require_testnet!();

    let tempdir = tempfile::tempdir().expect("Failed to create temp dir");
    let dir_path = tempdir.path().to_str().unwrap().to_string();
    let project_name = format!(
        "test-basic-{}",
        &outlayer_cli::crypto::generate_payment_key_secret()[..8]
    );

    outlayer_cli::commands::create::create(
        &ctx.network,
        &project_name,
        "basic",
        Some(dir_path.clone()),
    )
    .await
    .expect("create basic template failed");

    let project_dir = tempdir.path().join(&project_name);
    assert!(project_dir.join("Cargo.toml").exists(), "Cargo.toml should exist");
    assert!(project_dir.join("src/main.rs").exists(), "src/main.rs should exist");
    assert!(project_dir.join("build.sh").exists(), "build.sh should exist");
    assert!(project_dir.join(".gitignore").exists(), ".gitignore should exist");
    assert!(project_dir.join("skill.md").exists(), "skill.md should exist");
    assert!(project_dir.join("outlayer.toml").exists(), "outlayer.toml should exist");
    assert!(!project_dir.join("wit").exists(), "wit/ should not exist");

    let cargo_toml = std::fs::read_to_string(project_dir.join("Cargo.toml"))
        .expect("Failed to read Cargo.toml");
    let cargo_name = project_name.replace('-', "_");
    assert!(
        cargo_toml.contains(&cargo_name),
        "Cargo.toml should contain project name '{cargo_name}'"
    );
}

#[tokio::test]
#[serial]
async fn test_create_contract_template() {
    let ctx = require_testnet!();

    let tempdir = tempfile::tempdir().expect("Failed to create temp dir");
    let dir_path = tempdir.path().to_str().unwrap().to_string();
    let project_name = format!(
        "test-contract-{}",
        &outlayer_cli::crypto::generate_payment_key_secret()[..8]
    );

    outlayer_cli::commands::create::create(
        &ctx.network,
        &project_name,
        "contract",
        Some(dir_path.clone()),
    )
    .await
    .expect("create contract template failed");

    let project_dir = tempdir.path().join(&project_name);
    assert!(project_dir.join("Cargo.toml").exists(), "Cargo.toml should exist");
    assert!(project_dir.join("src/main.rs").exists(), "src/main.rs should exist");
    assert!(project_dir.join("build.sh").exists(), "build.sh should exist");
    assert!(project_dir.join("outlayer.toml").exists(), "outlayer.toml should exist");
    assert!(!project_dir.join("wit").exists(), "wit/ should not exist (SDK includes it)");

    let cargo_toml = std::fs::read_to_string(project_dir.join("Cargo.toml"))
        .expect("Failed to read Cargo.toml");
    assert!(
        cargo_toml.contains("outlayer"),
        "Contract template Cargo.toml should reference outlayer SDK"
    );
}
