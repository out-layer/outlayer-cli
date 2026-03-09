use anyhow::{Context, Result};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit};
use rand::rngs::OsRng;

/// Encrypt plaintext with ChaCha20-Poly1305 using hex-encoded pubkey as symmetric key.
///
/// Matches dashboard's JS implementation exactly:
/// 1. Parse hex pubkey → 32-byte key
/// 2. Generate 12-byte random nonce
/// 3. Encrypt plaintext
/// 4. Result: base64([12-byte nonce] + [ciphertext + 16-byte auth tag])
pub fn encrypt_secrets(pubkey_hex: &str, plaintext: &str) -> Result<String> {
    let key_bytes = hex::decode(pubkey_hex).context("Invalid hex pubkey")?;
    anyhow::ensure!(key_bytes.len() == 32, "Pubkey must be 32 bytes");

    let key = chacha20poly1305::Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;

    // [12-byte nonce] + [ciphertext + 16-byte tag]
    let mut encrypted = Vec::with_capacity(12 + ciphertext.len());
    encrypted.extend_from_slice(&nonce);
    encrypted.extend_from_slice(&ciphertext);

    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &encrypted,
    ))
}

/// Generate a 32-byte random hex string for payment key secret
pub fn generate_payment_key_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
    hex::encode(bytes)
}

/// Sign a NEP-413 message using a NEAR private key (for `secrets update`).
///
/// Returns `(signature_str, public_key_str, nonce_base64)`.
/// - `signature_str`: near-crypto Signature string (e.g. "ed25519:base58...")
/// - `public_key_str`: near-crypto PublicKey string (e.g. "ed25519:base58...")
/// - `nonce_base64`: base64-encoded random 32-byte nonce
pub fn sign_nep413(
    private_key: &str,
    message: &str,
    recipient: &str,
) -> Result<(String, String, String)> {
    use borsh::BorshSerialize;
    use near_crypto::SecretKey;
    use sha2::{Digest, Sha256};

    let secret_key: SecretKey = private_key
        .parse()
        .context("Invalid private key for NEP-413 signing")?;
    let public_key = secret_key.public_key();

    // Random 32-byte nonce
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce);

    // NEP-413 payload (Borsh-serialized)
    #[derive(BorshSerialize)]
    struct Nep413Payload {
        message: String,
        nonce: [u8; 32],
        recipient: String,
        callback_url: Option<String>,
    }

    let payload = Nep413Payload {
        message: message.to_string(),
        nonce,
        recipient: recipient.to_string(),
        callback_url: None,
    };

    // NEP-413 tag: 2**31 + 413 = 2147484061
    let tag: u32 = 2_147_484_061;
    let mut data = borsh::to_vec(&tag)?;
    let payload_bytes = borsh::to_vec(&payload)?;
    data.extend_from_slice(&payload_bytes);

    // SHA-256 hash, then sign
    let hash = Sha256::digest(&data);
    let signature = secret_key.sign(&hash);

    let nonce_base64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &nonce,
    );

    Ok((signature.to_string(), public_key.to_string(), nonce_base64))
}
