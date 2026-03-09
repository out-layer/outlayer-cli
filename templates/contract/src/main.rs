use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Input {
    /// User seed for VRF randomness (e.g. "coin-flip", "dice-roll")
    seed: Option<String>,
    /// Maximum value (result will be 0..=max). Default: 100
    max: Option<u64>,
}

#[derive(Serialize)]
struct Output {
    success: bool,
    sender: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    random_value: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vrf_proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vrf_alpha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    call_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn main() {
    // Get caller identity
    let sender = outlayer::env::signer_account_id()
        .unwrap_or_else(|| "anonymous".to_string());

    // Read input
    let input: Input = outlayer::env::input_json()
        .ok()
        .flatten()
        .unwrap_or(Input { seed: None, max: None });

    let seed = input.seed.unwrap_or_else(|| "default".to_string());
    let max = input.max.unwrap_or(100);

    // Generate verifiable random number
    match outlayer::vrf::random(&seed) {
        Ok(vrf) => {
            // Convert VRF output to number in range 0..=max
            let bytes = hex_to_bytes(&vrf.output_hex);
            let raw = u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8]));
            let value = if max > 0 { raw % (max + 1) } else { 0 };

            // Track total calls per sender in persistent storage
            let call_count = outlayer::storage::increment(&format!("calls:{sender}"), 1).ok();

            let output = Output {
                success: true,
                sender,
                random_value: Some(value),
                vrf_proof: Some(vrf.signature_hex),
                vrf_alpha: Some(vrf.alpha),
                call_count,
                error: None,
            };
            outlayer::env::output_json(&output).unwrap();
        }
        Err(e) => {
            let output = Output {
                success: false,
                sender,
                random_value: None,
                vrf_proof: None,
                vrf_alpha: None,
                call_count: None,
                error: Some(e),
            };
            outlayer::env::output_json(&output).unwrap();
        }
    }
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}
