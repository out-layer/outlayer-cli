use std::env;
use std::io::{self, Read};

fn main() {
    // Read JSON input from stdin
    let input: serde_json::Value = {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf).unwrap();
        if buf.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(&buf).unwrap_or(serde_json::Value::Null)
        }
    };

    // Get caller identity from NEAR environment
    let sender_id = env::var("NEAR_SENDER_ID").unwrap_or_else(|_| "anonymous".to_string());

    let output = serde_json::json!({
        "success": true,
        "message": format!("Hello, {}!", sender_id),
        "input": input,
    });

    println!("{}", serde_json::to_string(&output).unwrap());
}
