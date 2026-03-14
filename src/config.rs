use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ── Credentials ────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct Credentials {
    pub account_id: String,
    pub public_key: String,
    /// None if stored in OS keychain
    pub private_key: Option<String>,
    pub contract_id: String,
    /// "near_key" (default) or "wallet_key"
    #[serde(default = "default_auth_type")]
    pub auth_type: String,
    /// Wallet API key for custody-based auth (wk_...)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_key: Option<String>,
}

fn default_auth_type() -> String {
    "near_key".to_string()
}

impl Credentials {
    pub fn is_wallet_key(&self) -> bool {
        self.auth_type == "wallet_key"
    }
}

// ── Project Config (outlayer.toml) ─────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub project: ProjectSection,
    pub build: Option<BuildSection>,
    pub deploy: Option<DeploySection>,
    pub run: Option<RunSection>,
    pub network: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectSection {
    pub name: String,
    pub owner: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BuildSection {
    #[serde(default = "default_target")]
    pub target: String,
    #[serde(default = "default_source")]
    pub source: String,
}

fn default_target() -> String {
    "wasm32-wasip2".to_string()
}
fn default_source() -> String {
    "github".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeploySection {
    pub repo: Option<String>,
    pub wasm_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RunSection {
    pub max_instructions: Option<u64>,
    pub max_memory_mb: Option<u32>,
    pub max_execution_seconds: Option<u32>,
    pub secrets_profile: Option<String>,
    pub payment_key_nonce: Option<u32>,
}

// ── Network Config ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub network_id: String,
    pub rpc_url: String,
    pub contract_id: String,
    #[allow(dead_code)]
    pub wallet_url: String,
    pub api_base_url: String,
}

impl NetworkConfig {
    pub fn mainnet() -> Self {
        Self {
            network_id: "mainnet".to_string(),
            rpc_url: "https://rpc.mainnet.near.org".to_string(),
            contract_id: "outlayer.near".to_string(),
            wallet_url: "https://app.mynearwallet.com".to_string(),
            api_base_url: "https://api.outlayer.fastnear.com".to_string(),
        }
    }

    pub fn testnet() -> Self {
        Self {
            network_id: "testnet".to_string(),
            rpc_url: "https://test.rpc.fastnear.com".to_string(),
            contract_id: "outlayer.testnet".to_string(),
            wallet_url: "https://testnet.mynearwallet.com".to_string(),
            api_base_url: "https://testnet-api.outlayer.fastnear.com".to_string(),
        }
    }
}

/// Resolve network from flag > env > project config > saved default > auto-detect > mainnet
pub fn resolve_network(flag: Option<&str>, project: Option<&str>) -> Result<NetworkConfig> {
    let network = flag
        .or(project)
        .map(|s| s.to_string())
        .or_else(load_default_network)
        .or_else(|| detect_logged_in_network())
        .unwrap_or_else(|| "mainnet".to_string());

    match network.as_str() {
        "mainnet" => Ok(NetworkConfig::mainnet()),
        "testnet" => Ok(NetworkConfig::testnet()),
        other => anyhow::bail!("Unknown network: {other}. Use 'mainnet' or 'testnet'."),
    }
}

pub fn save_default_network(network: &str) {
    if let Ok(home) = outlayer_home() {
        let _ = std::fs::create_dir_all(&home);
        let _ = std::fs::write(home.join("default-network"), network);
    }
}

fn load_default_network() -> Option<String> {
    let home = outlayer_home().ok()?;
    std::fs::read_to_string(home.join("default-network"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// If no default is set, check which network has credentials
fn detect_logged_in_network() -> Option<String> {
    let home = outlayer_home().ok()?;
    let has_mainnet = home.join("mainnet/credentials.json").exists();
    let has_testnet = home.join("testnet/credentials.json").exists();
    match (has_mainnet, has_testnet) {
        (true, false) => Some("mainnet".to_string()),
        (false, true) => Some("testnet".to_string()),
        _ => None, // ambiguous or none — fall through to default
    }
}

// ── Paths ──────────────────────────────────────────────────────────────

fn outlayer_home() -> Result<PathBuf> {
    if let Ok(home) = std::env::var("OUTLAYER_HOME") {
        return Ok(PathBuf::from(home));
    }
    let home = dirs::home_dir().context("Cannot determine home directory")?;
    Ok(home.join(".outlayer"))
}

fn credentials_path(network: &str) -> Result<PathBuf> {
    let home = outlayer_home()?;
    Ok(home.join(network).join("credentials.json"))
}

// ── Keyring ────────────────────────────────────────────────────────────

const KEYRING_SERVICE: &str = "outlayer-cli";

fn keyring_key(network: &str, account_id: &str) -> String {
    format!("{network}:{account_id}")
}

pub fn save_private_key(network: &str, account_id: &str, key: &str) -> bool {
    let entry = match keyring::Entry::new(KEYRING_SERVICE, &keyring_key(network, account_id)) {
        Ok(e) => e,
        Err(_) => return false,
    };
    if entry.set_password(key).is_err() {
        return false;
    }
    // Verify we can read it back (some keychains report success but fail on read)
    entry.get_password().is_ok()
}

pub fn load_private_key(network: &str, account_id: &str, creds: &Credentials) -> Result<String> {
    // Try keychain first
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &keyring_key(network, account_id)) {
        if let Ok(key) = entry.get_password() {
            return Ok(key);
        }
    }
    // Fall back to file
    creds
        .private_key
        .clone()
        .context("Private key not found in credentials or keychain")
}

fn delete_private_key(network: &str, account_id: &str) {
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &keyring_key(network, account_id)) {
        let _ = entry.delete_credential();
    }
}

// ── Credential Operations ──────────────────────────────────────────────

pub fn load_credentials(network: &NetworkConfig) -> Result<Credentials> {
    let path = credentials_path(&network.network_id)?;
    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("Not logged in. Run: outlayer login --network {}", network.network_id))?;
    serde_json::from_str(&data).context("Invalid credentials file")
}

pub fn save_credentials(network: &NetworkConfig, creds: &Credentials) -> Result<()> {
    let path = credentials_path(&network.network_id)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(creds)?;
    std::fs::write(&path, data)?;
    Ok(())
}

pub fn delete_credentials(network: &NetworkConfig) -> Result<()> {
    let path = credentials_path(&network.network_id)?;
    if path.exists() {
        // Try to load account_id to clean up keyring
        if let Ok(data) = std::fs::read_to_string(&path) {
            if let Ok(creds) = serde_json::from_str::<Credentials>(&data) {
                delete_private_key(&network.network_id, &creds.account_id);
            }
        }
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

// ── Project Config Operations ──────────────────────────────────────────

pub fn load_project_config() -> Result<ProjectConfig> {
    let path = std::env::current_dir()?.join("outlayer.toml");
    let data = std::fs::read_to_string(&path)
        .context("outlayer.toml not found. Run 'outlayer create <name>' first.")?;
    toml::from_str(&data).context("Invalid outlayer.toml")
}

