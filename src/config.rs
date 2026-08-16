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
    /// keystore-DAO contract — used by vault contract for `is_ceased` /
    /// `is_keystore_approved` and read by `outlayer vault verify` for
    /// `is_vault_verified` / `is_vault_code_approved`.
    pub keystore_dao_id: String,
    /// MPC signer contract that the vault's TEE function-call key is
    /// allowed to call (`request_app_private_key` only). Burned into the
    /// vault contract at deploy time.
    pub mpc_contract_id: String,
}

impl NetworkConfig {
    pub fn mainnet() -> Self {
        Self {
            network_id: "mainnet".to_string(),
            rpc_url: "https://rpc.mainnet.near.org".to_string(),
            contract_id: "outlayer.near".to_string(),
            wallet_url: "https://app.mynearwallet.com".to_string(),
            api_base_url: "https://api.outlayer.fastnear.com".to_string(),
            // Production deploy uses `dao.outlayer.near` per docker
            // .env.mainnet-keystore-phala. The keystore worker's
            // KEYSTORE_DAO_CONTRACT is the canonical source.
            keystore_dao_id: "dao.outlayer.near".to_string(),
            mpc_contract_id: "v1.signer".to_string(),
        }
    }

    pub fn testnet() -> Self {
        Self {
            network_id: "testnet".to_string(),
            rpc_url: "https://test.rpc.fastnear.com".to_string(),
            contract_id: "outlayer.testnet".to_string(),
            wallet_url: "https://testnet.mynearwallet.com".to_string(),
            api_base_url: "https://testnet-api.outlayer.fastnear.com".to_string(),
            keystore_dao_id: "dao.outlayer.testnet".to_string(),
            mpc_contract_id: "v1.signer-prod.testnet".to_string(),
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

// ── Payment keys ───────────────────────────────────────────────────────
//
// A payment key is not a stored secret that can be fetched back later. It is
// the CREDENTIAL — the `owner:nonce:key` string sent as `X-Payment-Key` — and
// it exists in exactly two places: this process, and the blob on chain that
// only the keystore can decrypt and that nothing is allowed to reveal. Lose the
// plaintext and the key is unusable forever, while still holding its storage
// deposit and any balance topped into it.
//
// So it has to be written down before the transaction that creates it is sent,
// not after it comes back. What is irreversible is the transaction; everything
// after it is a place a process can die.

fn payment_key_ref(network: &str, account_id: &str, nonce: u32) -> String {
    format!("{network}:{account_id}:payment-key:{nonce}")
}

fn payment_keys_path(network: &str) -> Result<PathBuf> {
    let home = outlayer_home()?;
    Ok(home.join(network).join("payment-keys.json"))
}

/// Keep a payment key before anything irreversible happens to it.
///
/// A file, deliberately, and NOT the keyring that holds the account's private
/// key. `keyring = "3"` is built here with no platform feature, and the crate
/// documents what that means: every platform gets the *mock* store, which lives
/// in the calling process's memory. A write to it succeeds, a read back in the
/// same process succeeds, and nothing exists afterwards — verified against the
/// login keychain, which has no entry for a key this reported saving.
///
/// For the account key that is merely useless: `login` writes it to
/// `credentials.json` regardless and throws the keyring's answer away. For a
/// payment key it would be worse than useless, because there is no second copy
/// to fall back on — reporting "saved" and storing nothing is precisely the
/// failure this function exists to prevent.
pub fn save_payment_key(network: &str, account_id: &str, nonce: u32, key: &str) -> Result<PathBuf> {
    let path = payment_keys_path(network)?;
    write_key_file(&path, &payment_key_ref(network, account_id, nonce), key)?;

    // Read back through the same path `show` will use. A save that cannot be
    // read is the whole bug in a different costume, and it must not be
    // discovered later by somebody holding an unusable key.
    if load_payment_key(network, account_id, nonce).as_deref() != Some(key) {
        anyhow::bail!(
            "Wrote {} but could not read the key back from it",
            path.display()
        );
    }

    Ok(path)
}

/// Add one key to the on-disk store, keeping whatever is already there.
///
/// Split out from [`save_payment_key`] so the path can be exercised against a
/// temporary directory: the public function derives its path from the user's
/// home, and a test that wrote there would be editing the operator's real keys.
fn write_key_file(path: &PathBuf, reference: &str, key: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Merged, never overwritten: the file holds every key this machine made,
    // and a create that replaced the file would destroy the earlier ones.
    //
    // A file that EXISTS but cannot be read is the dangerous case — unreadable
    // and empty are the same answer from `read_key_file`, so merging into an
    // empty map and truncating would silently destroy every other key on the
    // machine, none of which can be recovered from anywhere. It is moved aside
    // instead, and the operator is told where it went.
    let mut all = read_key_file(path);
    if all.is_empty() && path.exists() {
        let kept = path.with_extension("json.unreadable");
        std::fs::rename(path, &kept).with_context(|| {
            format!(
                "{} exists but could not be read, and could not be moved aside either. \
                 Refusing to overwrite it: it may hold keys that exist nowhere else.",
                path.display()
            )
        })?;
        eprintln!(
            "warning: {} could not be read; moved to {} rather than overwritten",
            path.display(),
            kept.display()
        );
    }

    all.insert(reference.to_string(), key.to_string());
    let data = serde_json::to_string_pretty(&all)?;

    // Owner-only from the moment it exists. Narrowing the mode after writing
    // would leave the secret readable for the window in between, which is the
    // whole thing this is guarding against.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("Could not write {}", path.display()))?;
        f.write_all(data.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &data)
            .with_context(|| format!("Could not write {}", path.display()))?;
    }

    Ok(())
}

/// Every key in the on-disk store, or none. A missing or unreadable file is an
/// empty store rather than an error: it is how the first key ever saved finds
/// the file, and a parse failure must not stop the NEXT key being written down.
fn read_key_file(path: &PathBuf) -> std::collections::BTreeMap<String, String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Read back a payment key this machine created.
pub fn load_payment_key(network: &str, account_id: &str, nonce: u32) -> Option<String> {
    let path = payment_keys_path(network).ok()?;
    read_key_file(&path)
        .get(&payment_key_ref(network, account_id, nonce))
        .cloned()
}

#[cfg(test)]
mod payment_key_store_tests {
    use super::*;

    /// A key survives being written, and writing a second one does not take the
    /// first with it.
    ///
    /// The whole reason this store exists is that a payment key has no other
    /// copy: the chain holds it encrypted for the keystore and nothing gives it
    /// back. A `create` that clobbered the file would destroy every earlier key
    /// on the machine, silently, and the balances behind them with it.
    #[test]
    fn keys_accumulate_rather_than_replace_each_other() {
        let dir = std::env::temp_dir().join(format!(
            "outlayer-keystore-test-{}",
            std::process::id()
        ));
        let path = dir.join("payment-keys.json");
        let _ = std::fs::remove_file(&path);

        write_key_file(&path, "testnet:alice.testnet:payment-key:1", "alice:1:aaa").unwrap();
        write_key_file(&path, "testnet:alice.testnet:payment-key:2", "alice:2:bbb").unwrap();

        let all = read_key_file(&path);
        assert_eq!(all.len(), 2, "the second write kept the first key");
        assert_eq!(all["testnet:alice.testnet:payment-key:1"], "alice:1:aaa");
        assert_eq!(all["testnet:alice.testnet:payment-key:2"], "alice:2:bbb");

        // Same nonce again replaces just that one — a re-created key at the
        // same nonce is a different key, and keeping the old one would hand
        // back a string that no longer opens anything.
        write_key_file(&path, "testnet:alice.testnet:payment-key:1", "alice:1:ccc").unwrap();
        let all = read_key_file(&path);
        assert_eq!(all.len(), 2);
        assert_eq!(all["testnet:alice.testnet:payment-key:1"], "alice:1:ccc");

        // Nobody but the owner can read it. This file is a plaintext credential
        // on disk; the mode is what makes that acceptable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "the key file must be owner-only");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An absent or corrupt store still accepts the next key — and a corrupt
    /// one is PRESERVED rather than replaced.
    ///
    /// Both halves matter and they pull against each other. The next key has to
    /// be writable, or a file somebody edited by hand turns into an unspendable
    /// key. But "unreadable" and "empty" are the same answer from
    /// `read_key_file`, so merging into it and truncating would wipe every
    /// other key on the machine — and those exist nowhere else, so there would
    /// be nothing to restore from.
    #[test]
    fn a_corrupt_store_is_moved_aside_not_overwritten() {
        let dir = std::env::temp_dir().join(format!(
            "outlayer-keystore-broken-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("payment-keys.json");

        assert!(read_key_file(&path).is_empty(), "no file is an empty store");

        std::fs::write(&path, "{not json — but it may hold keys").unwrap();
        assert!(read_key_file(&path).is_empty(), "a corrupt file reads as empty");

        write_key_file(&path, "testnet:alice.testnet:payment-key:7", "alice:7:ddd").unwrap();

        // The new key went in...
        assert_eq!(read_key_file(&path)["testnet:alice.testnet:payment-key:7"], "alice:7:ddd");
        assert_eq!(read_key_file(&path).len(), 1);

        // ...and the bytes nobody could parse are still on disk.
        let kept = path.with_extension("json.unreadable");
        assert_eq!(
            std::fs::read_to_string(&kept).unwrap(),
            "{not json — but it may hold keys",
            "the unreadable store must survive verbatim — it cannot be recovered from anywhere else",
        );

        let _ = std::fs::remove_dir_all(&dir);
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

