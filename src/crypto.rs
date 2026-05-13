use anyhow::{Context, Result};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

/// HKDF info string — must match `dashboard/lib/ecies.ts` and
/// `keystore-worker/src/crypto.rs::HKDF_INFO`. Any drift here breaks
/// every encrypt/decrypt pair.
const HKDF_INFO: &[u8] = b"outlayer-keystore-v1";

/// ECIES v1 wire-format version byte.
const ECIES_VERSION: u8 = 0x01;

/// Encrypt plaintext for the recipient `pubkey_hex` using ECIES v1
/// (X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305).
///
/// `pubkey_hex` is the **X25519** public key returned by
/// `/secrets/pubkey` (keystore-worker's `public_key_hex` calls
/// `derive_x25519_keypair`, NOT `derive_keypair`). Older versions of
/// this function treated the hex pubkey as a 32-byte ChaCha20
/// symmetric key — that "legacy" path is broken for vault-bound
/// secrets because the keystore's `decrypt_legacy` derives an Ed25519
/// verifying_key (different bytes from the same seed), so the AEAD
/// never matches. ECIES has the right structure to interop with the
/// keystore's `decrypt_ecies` path.
///
/// Wire format (exactly what `keystore-worker/src/crypto.rs::decrypt`
/// expects on its ECIES branch, and what `dashboard/lib/ecies.ts`
/// produces):
///
///     [ 0x01 | ephemeral_x25519_pub(32) | nonce(12) | ciphertext | tag(16) ]
///
/// Returns base64 of the above.
pub fn encrypt_secrets(pubkey_hex: &str, plaintext: &str) -> Result<String> {
    let recipient_bytes = hex::decode(pubkey_hex).context("Invalid hex pubkey")?;
    anyhow::ensure!(
        recipient_bytes.len() == 32,
        "Pubkey must be 32 bytes (X25519 public key)"
    );
    let mut recipient_arr = [0u8; 32];
    recipient_arr.copy_from_slice(&recipient_bytes);
    let recipient_pub = X25519PublicKey::from(recipient_arr);

    // Ephemeral sender keypair — one-shot, never reused.
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    // ECDH → 32-byte shared secret.
    let shared = ephemeral_secret.diffie_hellman(&recipient_pub);

    // HKDF-SHA256 stretch with the canonical info string.
    let hk = Hkdf::<sha2::Sha256>::new(None, shared.as_bytes());
    let mut sym_key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut sym_key)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {e}"))?;

    // AEAD: ChaCha20-Poly1305 with a random 12-byte nonce.
    let cipher = ChaCha20Poly1305::new((&sym_key).into());
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;

    // Assemble: [0x01 | ephemeral_pub(32) | nonce(12) | ciphertext+tag]
    let mut out = Vec::with_capacity(1 + 32 + 12 + ciphertext.len());
    out.push(ECIES_VERSION);
    out.extend_from_slice(ephemeral_public.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &out,
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
