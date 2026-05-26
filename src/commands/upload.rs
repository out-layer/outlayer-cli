use anyhow::{Context, Result};
use borsh::BorshSerialize;
use sha2::{Digest, Sha256};

use crate::api::ApiClient;
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
pub fn prepare_fastfs_payloads(relative_path: &str, mime_type: &str, content: &[u8]) -> Vec<Vec<u8>> {
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

    if creds.is_wallet_key() {
        upload_via_wallet(network, &creds, &receiver_id, &payloads).await?;
    } else {
        upload_via_near_key(network, &creds, &receiver_id, &payloads).await?;
    }

    // FastFS host is per-network: testnet uses `test.fastfs.io`,
    // mainnet uses `main.fastfs.io`. Otherwise the CDN can't find
    // the receipt because it only indexes one network per host.
    let fastfs_host = match network.network_id.as_str() {
        "mainnet" => "main.fastfs.io",
        "testnet" => "test.fastfs.io",
        other => anyhow::bail!(
            "unknown network '{}' — FastFS only knows mainnet/testnet",
            other
        ),
    };
    let fastfs_url = format!(
        "https://{}/{}/{}/{}",
        fastfs_host, creds.account_id, receiver_id, relative_path
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

/// Upload via direct NEAR transaction (private key auth).
pub async fn upload_via_near_key(
    network: &NetworkConfig,
    creds: &config::Credentials,
    receiver_id: &str,
    payloads: &[Vec<u8>],
) -> Result<()> {
    let private_key = config::load_private_key(&network.network_id, &creds.account_id, creds)?;
    let receiver_account_id: near_primitives::types::AccountId = receiver_id
        .parse()
        .context("Invalid receiver account ID")?;
    let signer = NearSigner::new(network, &creds.account_id, &private_key)?;
    let (current_nonce, block_hash) = signer.get_tx_context().await?;
    let num_chunks = payloads.len();

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

    Ok(())
}

/// Upload via wallet API (wallet_key auth) — sends Borsh args as base64.
pub async fn upload_via_wallet(
    network: &NetworkConfig,
    creds: &config::Credentials,
    receiver_id: &str,
    payloads: &[Vec<u8>],
) -> Result<()> {
    let wallet_key = creds
        .wallet_key
        .as_ref()
        .context("Missing wallet_key in credentials")?;
    let api = ApiClient::new(network);
    let num_chunks = payloads.len();

    for (i, payload) in payloads.iter().enumerate() {
        if num_chunks > 1 {
            eprint!("  Uploading chunk {}/{}... ", i + 1, num_chunks);
        } else {
            eprint!("  Uploading... ");
        }

        let resp = api
            .wallet_call_raw(
                wallet_key,
                receiver_id,
                "__fastdata_fastfs",
                payload,
                1,  // gas=1
                0,  // no deposit
            )
            .await
            .with_context(|| format!("Failed to upload chunk {}/{}", i + 1, num_chunks))?;

        if let Some(tx_hash) = &resp.tx_hash {
            eprintln!("tx: {tx_hash}");
        } else {
            eprintln!("request: {}", resp.request_id);
        }
    }

    Ok(())
}

// ── Webapp Upload ────────────────────────────────────────────────────

const ASSET_EXTENSIONS: &[&str] = &[
    "css", "js", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf", "eot",
    "webp", "webm", "mp4", "mp3", "ogg", "wav", "json", "wasm", "map",
];

fn mime_for_ext(ext: &str) -> String {
    match ext {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "application/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }.to_string()
}

/// Upload a directory as a static webapp. Rewrites asset references in HTML to FastFS URLs.
pub async fn upload_webapp(
    network: &NetworkConfig,
    dir_path: &str,
    receiver: Option<String>,
) -> Result<()> {
    let dir = std::path::Path::new(dir_path);
    if !dir.is_dir() {
        anyhow::bail!("'{dir_path}' is not a directory. Use --webapp with a directory.");
    }

    let creds = config::load_credentials(network)?;
    let receiver_id = receiver.unwrap_or_else(|| network.contract_id.clone());
    let fastfs_host = match network.network_id.as_str() {
        "mainnet" => "main.fastfs.io",
        "testnet" => "test.fastfs.io",
        other => anyhow::bail!("unknown network '{other}'"),
    };

    // 1. Collect all files
    let mut all_files: Vec<std::path::PathBuf> = Vec::new();
    collect_files(dir, dir, &mut all_files)?;

    if all_files.is_empty() {
        anyhow::bail!("No files found in '{dir_path}'");
    }

    // Separate assets (CSS, JS, images...) from HTML files
    let mut asset_files: Vec<std::path::PathBuf> = Vec::new();
    let mut html_files: Vec<std::path::PathBuf> = Vec::new();
    for f in &all_files {
        let ext = f.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext == "html" || ext == "htm" {
            html_files.push(f.clone());
        } else {
            asset_files.push(f.clone());
        }
    }

    eprintln!("Uploading webapp to FastFS...");
    eprintln!("  Directory: {}", dir.canonicalize()?.display());
    eprintln!("  Assets: {} files", asset_files.len());
    eprintln!("  HTML: {} files", html_files.len());
    eprintln!();

    // 2. Upload all assets first, build URL map
    //    But we need to know ALL FastFS URLs before rewriting JS.
    //    Strategy: upload non-JS assets, compute URLs, rewrite JS content, then upload JS.
    let mut url_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let private_key = config::load_private_key(&network.network_id, &creds.account_id, &creds)?;
    let signer = crate::near::NearSigner::new(network, &creds.account_id, &private_key)?;
    let (mut current_nonce, block_hash) = signer.get_tx_context().await?;

    // 2a. Separate JS files from other assets
    let mut js_files: Vec<std::path::PathBuf> = Vec::new();
    let mut other_assets: Vec<std::path::PathBuf> = Vec::new();
    for f in &asset_files {
        let ext = f.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext == "js" || ext == "mjs" {
            js_files.push(f.clone());
        } else {
            other_assets.push(f.clone());
        }
    }

    // 2b. Upload non-JS assets first (images, CSS, fonts, etc.)
    for (i, asset_path) in other_assets.iter().enumerate() {
        let content = std::fs::read(asset_path)
            .with_context(|| format!("Failed to read {}", asset_path.display()))?;
        let hash = hex::encode(Sha256::digest(&content));
        let ext = asset_path.extension().and_then(|e| e.to_str()).unwrap_or("bin");
        let relative_path = format!("{hash}.{ext}");
        let mime = mime_for_ext(ext);

        let payloads = prepare_fastfs_payloads(&relative_path, &mime, &content);

        for payload in &payloads {
            current_nonce += 1;
            signer.send_function_call_async(
                &receiver_id.parse()?,
                "__fastdata_fastfs",
                payload.clone(),
                1, 0, current_nonce, block_hash,
            ).await?;
        }

        let fastfs_url = format!(
            "https://{}/{}/{}/{}",
            fastfs_host, creds.account_id, receiver_id, relative_path
        );

        // Map all possible relative paths for this asset
        let rel = asset_path.strip_prefix(dir).unwrap_or(asset_path);
        let rel_str = rel.to_str().unwrap_or("").to_string();
        url_map.insert(rel_str.clone(), fastfs_url.clone());
        url_map.insert(format!("/{}", rel_str), fastfs_url.clone());
        if let Some(name) = asset_path.file_name().and_then(|n| n.to_str()) {
            url_map.insert(name.to_string(), fastfs_url.clone());
            url_map.insert(format!("/{}", name), fastfs_url);
        }

        eprintln!("  [{}/{}] {} → uploaded", i + 1, other_assets.len(), rel.display());
    }

    // 2c. Now upload JS files with URLs rewritten
    let sorted_pairs: Vec<(String, String)> = {
        let mut pairs: Vec<_> = url_map.iter().collect();
        pairs.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        pairs.into_iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    };

    for (i, js_path) in js_files.iter().enumerate() {
        let mut content = std::fs::read_to_string(js_path)
            .with_context(|| format!("Failed to read {}", js_path.display()))?;

        // Rewrite asset references inside JS bundles
        for (rel, fastfs_url) in &sorted_pairs {
            content = content.replace(rel.as_str(), fastfs_url);
        }

        let content_bytes = content.into_bytes();
        let hash = hex::encode(Sha256::digest(&content_bytes));
        let relative_path = format!("{hash}.js");

        let payloads = prepare_fastfs_payloads(&relative_path, "application/javascript", &content_bytes);

        for payload in &payloads {
            current_nonce += 1;
            signer.send_function_call_async(
                &receiver_id.parse()?,
                "__fastdata_fastfs",
                payload.clone(),
                1, 0, current_nonce, block_hash,
            ).await?;
        }

        let fastfs_url = format!(
            "https://{}/{}/{}/{}",
            fastfs_host, creds.account_id, receiver_id, relative_path
        );

        let rel = js_path.strip_prefix(dir).unwrap_or(js_path);
        let rel_str = rel.to_str().unwrap_or("").to_string();
        eprintln!("  [{}/{}] {} → uploaded (rewritten)", i + 1, js_files.len(), rel.display());

        // Add JS URLs to map after the immutable borrow is done
        url_map.insert(rel_str, fastfs_url.clone());
    }

    // 3. Rewrite URLs in HTML files and upload them
    let mut entry_url: Option<String> = None;

    for (i, html_path) in html_files.iter().enumerate() {
        let mut content = std::fs::read_to_string(html_path)
            .with_context(|| format!("Failed to read {}", html_path.display()))?;

        // Rewrite relative URLs to FastFS URLs (longest path first to avoid partial matches)
        let mut pairs: Vec<_> = url_map.iter().collect();
        pairs.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        for (rel, fastfs_url) in &pairs {
            // Match both "path" and "/path" (absolute and relative)
            content = content.replace(&format!("\"{}\"", rel), &format!("\"{}\"", fastfs_url));
            content = content.replace(&format!("\"/{}\"", rel), &format!("\"{}\"", fastfs_url));
            content = content.replace(&format!("'{}'", rel), &format!("'{}'", fastfs_url));
        }

        let content_bytes = content.into_bytes();
        let hash = hex::encode(Sha256::digest(&content_bytes));
        let relative_path = format!("{hash}.html");
        let payloads = prepare_fastfs_payloads(&relative_path, "text/html", &content_bytes);

        for payload in &payloads {
            current_nonce += 1;
            signer.send_function_call_async(
                &receiver_id.parse()?,
                "__fastdata_fastfs",
                payload.clone(),
                1, 0, current_nonce, block_hash,
            ).await?;
        }

        let fastfs_url = format!(
            "https://{}/{}/{}/{}",
            fastfs_host, creds.account_id, receiver_id, relative_path
        );

        let rel = html_path.strip_prefix(dir).unwrap_or(html_path);
        eprintln!("  [{}/{}] {} → uploaded", i + 1, html_files.len(), rel.display());

        let rel_str = rel.to_str().unwrap_or("");
        if rel_str == "index.html" || (entry_url.is_none() && html_files.len() == 1) {
            entry_url = Some(fastfs_url);
        }
    }

    eprintln!();
    eprintln!("  \x1b[32m✓\x1b[0m Webapp uploaded ({} files)", all_files.len());

    if let Some(url) = &entry_url {
        eprintln!();
        eprintln!("  \x1b[1mURL:\x1b[0m {url}");
    }
    eprintln!();

    Ok(())
}

fn collect_files(base: &std::path::Path, dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.starts_with('.') && name != "node_modules" && name != "target" {
                collect_files(base, &path, files)?;
            }
        } else {
            files.push(path);
        }
    }
    Ok(())
}