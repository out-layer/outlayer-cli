use anyhow::{Context, Result};

use crate::config::{self, Credentials, NetworkConfig};

/// `outlayer login [network]` — import full access key
pub async fn login(network_name: &str) -> Result<()> {
    let network = config::resolve_network(Some(network_name), None)?;

    // Prompt account_id
    eprint!("Account ID: ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let account_id = input.trim().to_string();
    if account_id.is_empty() {
        anyhow::bail!("Account ID is required");
    }

    // Prompt private key
    eprint!("Private key (ed25519:...): ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let secret_key = input.trim().to_string();
    if secret_key.is_empty() {
        anyhow::bail!("Private key is required");
    }

    // Validate key format
    let parsed: near_crypto::SecretKey = secret_key
        .parse()
        .context("Invalid private key format. Expected: ed25519:...")?;
    let public_key = parsed.public_key().to_string();

    // Save credentials (always save key to file; keyring is a bonus)
    let _use_keyring = config::save_private_key(&network.network_id, &account_id, &secret_key);

    let creds = Credentials {
        account_id: account_id.clone(),
        public_key: public_key.clone(),
        private_key: Some(secret_key),
        contract_id: network.contract_id.clone(),
    };

    config::save_credentials(&network, &creds)?;
    config::save_default_network(&network.network_id);

    eprintln!("Logged in as {account_id} ({network_name})");
    eprintln!("Public key: {public_key}");

    Ok(())
}

/// `outlayer logout` — delete stored credentials
pub fn logout(network: &NetworkConfig) -> Result<()> {
    config::delete_credentials(network)?;
    eprintln!("Logged out from {}", network.network_id);
    Ok(())
}

/// `outlayer whoami` — show current account
pub fn whoami(network: &NetworkConfig) -> Result<()> {
    let creds = config::load_credentials(network)?;
    println!("Account:  {}", creds.account_id);
    println!("Network:  {}", network.network_id);
    println!("Contract: {}", creds.contract_id);
    println!("Key:      {}", creds.public_key);
    Ok(())
}
