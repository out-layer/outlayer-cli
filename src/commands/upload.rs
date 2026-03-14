use anyhow::{Context, Result};
use borsh::BorshSerialize;
use sha2::{Digest, Sha256};

use crate::config::{self, NetworkConfig};
use crate::near::NearSigner;

const CHUNK_SIZE: usize = 1 << 20; // 1 MB

// ── Borsh FastFS Schemas ─────────────────────────────────────────────
//
// Matches the TypeScript reference (fastnear/fastdata-drag-and-drop):
//
// enum FastfsData {
//   Simple(SimpleFastfs),     // variant 0
//   Partial(PartialFastfs),   // variant 1
// }

#[derive(BorshSerialize)]
struct FastfsFileContent {
    mime_type: String,
    content: Vec<u8>,
}

#[derive(BorshSerialize)]
struct SimpleFastfs {
    relative_path: String,
    content: Option<FastfsFileContent>,
}

#[derive(BorshSerialize)]
struct PartialFastfs {
    relative_path: String,
    offset: u32,
    full_size: u32,
    mime_type: String,
    content_chunk: Vec<u8>,
    nonce: u32,
}

/// Borsh-serialize a SimpleFastfs payload (enum variant 0).
fn encode_simple(relative_path: &str, mime_type: &str, content: &[u8]) -> Vec<u8> {
    let simple = SimpleFastfs {
        relative_path: relative_path.to_string(),
        content: Some(FastfsFileContent {
            mime_type: mime_type.to_string(),
            content: content.to_vec(),
        }),
    };

    // Enum variant 0 (Simple)
    let mut data = vec![0u8];
    data.extend(borsh::to_vec(&simple).expect("borsh serialization"));
    data
}

/// Borsh-serialize a PartialFastfs payload (enum variant 1).
fn encode_partial(
    relative_path: &str,
    offset: u32,
    full_size: u32,
    mime_type: &str,
    chunk: &[u8],
    nonce: u32,
) -> Vec<u8> {
    let partial = PartialFastfs {
        relative_path: relative_path.to_string(),
        offset,
        full_size,
        mime_type: mime_type.to_string(),
        content_chunk: chunk.to_vec(),
        nonce,
    };

    // Enum variant 1 (Partial)
    let mut data = vec![1u8];
    data.extend(borsh::to_vec(&partial).expect("borsh serialization"));
    data
}

/// Prepare FastFS payloads for a file (simple for ≤1MB, chunked for >1MB).
fn prepare_fastfs_payloads(relative_path: &str, mime_type: &str, content: &[u8]) -> Vec<Vec<u8>> {
    if content.len() <= CHUNK_SIZE {
        return vec![encode_simple(relative_path, mime_type, content)];
    }

    let nonce = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 1_769_376_240) as u32;

    let full_size = content.len() as u32;
    let mut payloads = Vec::new();

    let mut offset = 0usize;
    while offset < content.len() {
        let end = (offset + CHUNK_SIZE).min(content.len());
        let chunk = &content[offset..end];
        payloads.push(encode_partial(
            relative_path,
            offset as u32,
            full_size,
            mime_type,
            chunk,
            nonce,
        ));
        offset = end;
    }

    payloads
}

/// `outlayer upload <file>` — upload a file to FastFS via NEAR transaction.
pub async fn upload(
    network: &NetworkConfig,
    file_path: &str,
    receiver: Option<String>,
    mime_type: Option<String>,
) -> Result<()> {
    let creds = config::load_credentials(network)?;

    if creds.is_wallet_key() {
        anyhow::bail!(
            "FastFS upload is not yet supported with wallet_key auth.\n\
             Upload requires raw Borsh-encoded transaction args which the wallet API \
             does not support yet. Use 'outlayer login' with a NEAR private key instead."
        );
    }

    let private_key = config::load_private_key(&network.network_id, &creds.account_id, &creds)?;

    // Read file
    let content = std::fs::read(file_path)
        .with_context(|| format!("Failed to read file: {file_path}"))?;

    // SHA-256 hash
    let hash = hex::encode(Sha256::digest(&content));

    // Determine extension and mime type
    let extension = std::path::Path::new(file_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("bin");
    let mime = mime_type.unwrap_or_else(|| match extension {
        "wasm" => "application/wasm".to_string(),
        "json" => "application/json".to_string(),
        "html" => "text/html".to_string(),
        "js" => "application/javascript".to_string(),
        "css" => "text/css".to_string(),
        "png" => "image/png".to_string(),
        "jpg" | "jpeg" => "image/jpeg".to_string(),
        "svg" => "image/svg+xml".to_string(),
        _ => "application/octet-stream".to_string(),
    });

    let relative_path = format!("{hash}.{extension}");
    let receiver_id = receiver.unwrap_or_else(|| network.contract_id.clone());

    eprintln!("Uploading to FastFS...");
    eprintln!("  File: {file_path}");
    eprintln!("  Size: {} bytes", content.len());
    eprintln!("  SHA256: {hash}");
    eprintln!("  Sender: {}", creds.account_id);
    eprintln!("  Receiver: {receiver_id}");

    let payloads = prepare_fastfs_payloads(&relative_path, &mime, &content);
    let num_chunks = payloads.len();

    if num_chunks > 1 {
        eprintln!("  Chunks: {num_chunks} x {}KB max", CHUNK_SIZE / 1024);
    }
    eprintln!();

    let receiver_account_id: near_primitives::types::AccountId = receiver_id
        .parse()
        .context("Invalid receiver account ID")?;
    let signer = NearSigner::new(network, &creds.account_id, &private_key)?;
    let (current_nonce, block_hash) = signer.get_tx_context().await?;

    for (i, payload) in payloads.iter().enumerate() {
        if num_chunks > 1 {
            eprint!("  Uploading chunk {}/{}... ", i + 1, num_chunks);
        } else {
            eprint!("  Uploading... ");
        }

        let tx_hash = signer
            .send_function_call_async(
                &receiver_account_id,
                "__fastdata_fastfs",
                payload.clone(),
                1,  // gas=1: intentionally fails, but data is recorded on-chain
                0,  // no deposit
                current_nonce + 1 + i as u64,
                block_hash,
            )
            .await
            .with_context(|| format!("Failed to upload chunk {}/{}", i + 1, num_chunks))?;

        eprintln!("tx: {tx_hash}");
    }

    let fastfs_url = format!(
        "https://{}.fastfs.io/{}/{}",
        creds.account_id, receiver_id, relative_path
    );

    eprintln!();
    eprintln!("Upload complete!");
    eprintln!();
    eprintln!("FastFS URL: {fastfs_url}");
    eprintln!();

    if extension == "wasm" {
        eprintln!("Run directly:");
        eprintln!("  outlayer run --wasm {fastfs_url} '{{}}' ");
        eprintln!();
        eprintln!("Or deploy as project version:");
        eprintln!("  outlayer deploy <name> --wasm-url {fastfs_url}");
    }

    Ok(())
}
