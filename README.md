# OutLayer CLI

Command-line tool for deploying, running, and managing [OutLayer](https://outlayer.fastnear.com) agents.

```bash
outlayer login                                              # Import NEAR full access key
outlayer create my-agent                                    # Create project from template
outlayer deploy my-agent                                    # Deploy agent to OutLayer
outlayer run alice.near/my-agent '{"command": "hello"}'     # Execute agent
```

## Install

### From source (requires [Rust](https://rustup.rs))

```bash
# From GitHub
cargo install --git https://github.com/out-layer/outlayer-cli

# From local checkout
cd outlayer-cli
cargo install --path .
```

## Quick Start

```bash
# 1. Login (prompts for Account ID and Private Key)
outlayer login              # mainnet
outlayer login testnet      # testnet

# 2. Create a new agent
outlayer create my-agent                    # basic template (stdin/stdout)
outlayer create my-agent --template contract # with OutLayer SDK (VRF, storage, RPC)
cd my-agent

# 3. Edit src/main.rs, push to GitHub, then deploy
git init && git remote add origin <your-repo-url>
git push
outlayer deploy my-agent

# 4. Create a payment key for HTTPS calls
outlayer keys create

# 5. Run your agent
outlayer run alice.near/my-agent '{"command": "hello"}'
```

## Commands

### Auth

| Command | Description |
|---------|-------------|
| `outlayer login` | Import NEAR full access key (mainnet) |
| `outlayer login testnet` | Login to testnet |
| `outlayer logout` | Delete stored credentials |
| `outlayer whoami` | Show current account and network |

### Project Workflow

| Command | Description |
|---------|-------------|
| `outlayer create <name>` | Create project from template (basic) in `./<name>/` |
| `outlayer create <name> --template contract` | Create with OutLayer SDK (VRF, storage, RPC) |
| `outlayer create <name> --dir /path` | Create in a custom directory |
| `outlayer deploy <name> <wasm-url>` | Deploy from WASM URL (FastFS, etc.) |
| `outlayer deploy <name>` | Deploy from current git repo (origin + HEAD) |
| `outlayer deploy <name> --github` | Explicitly deploy from git (same as no URL) |
| `outlayer deploy <name> --no-activate` | Deploy without activating |
| `outlayer run <project> [input]` | Execute agent (HTTPS or on-chain fallback) |
| `outlayer projects [account]` | List projects for a user |
| `outlayer status [call_id]` | Project info or poll async call |

```bash
# Run from project (uses payment key if available, else on-chain NEAR)
outlayer run alice.near/my-agent '{"command": "hello"}'
outlayer run alice.near/my-agent --input request.json             # input from file
outlayer run alice.near/my-agent '{"command": "heavy"}' --async           # async (HTTPS only)
outlayer run alice.near/my-agent '{"command": "premium"}' --deposit 0.01  # attached deposit
outlayer run alice.near/my-agent '{}' --compute-limit 1000000000          # custom compute limit

# Attach secrets to execution (secrets must be stored via `outlayer secrets set`)
outlayer run alice.near/my-agent '{}' --secrets-profile default --secrets-account alice.near

# Run from GitHub repo (on-chain)
outlayer run --github github.com/user/repo '{"command": "hello"}'
outlayer run --github github.com/user/repo --commit abc123 '{"input": 1}'

# Run from WASM URL (on-chain) — FastFS, any HTTP URL
outlayer run --wasm https://alice.near.fastfs.io/outlayer.near/abc.wasm '{"cmd": "hi"}'
outlayer run --wasm https://example.com/file.wasm --hash abc123... '{}'

# List your projects
outlayer projects
outlayer projects bob.near
```

### Secrets

| Command | Description |
|---------|-------------|
| `outlayer secrets set '{"KEY":"val"}'` | Encrypt and store secrets |
| `outlayer secrets update '{"KEY":"val"}'` | Merge with existing (preserves PROTECTED_*) |
| `outlayer secrets set --generate PROTECTED_X:hex32` | Generate protected secret in TEE |
| `outlayer secrets list` | List stored secrets (metadata only) |
| `outlayer secrets delete` | Delete secrets for a profile |

```bash
# Set secrets (JSON object, overwrites existing)
outlayer secrets set '{"API_KEY":"sk-...","DB_URL":"postgres://..."}'
outlayer secrets set '{"API_KEY":"sk-..."}' --project alice.near/my-agent
outlayer secrets set '{"API_KEY":"sk-..."}' --repo github.com/user/repo --branch main
outlayer secrets set '{"API_KEY":"sk-..."}' --wasm-hash abc123...

# Generate protected secrets in TEE (values never visible)
outlayer secrets set --generate PROTECTED_MASTER_KEY:hex32
outlayer secrets set '{"API_KEY":"sk-..."}' --generate PROTECTED_DB:hex64   # mixed

# Access control
outlayer secrets set '{"KEY":"val"}' --access allow-all                      # default
outlayer secrets set '{"KEY":"val"}' --access whitelist:alice.near,bob.near

# Update (merge with existing, preserves all PROTECTED_* variables)
outlayer secrets update '{"NEW_KEY":"val"}' --project alice.near/my-agent
outlayer secrets update --generate PROTECTED_NEW:ed25519

# Generation types: hex16, hex32, hex64, ed25519, ed25519_seed, password, password:N

# List / delete
outlayer secrets list
outlayer secrets delete --project alice.near/my-agent
outlayer secrets delete --profile production
```

Default accessor: `--project` auto-resolved from `outlayer.toml` if present.

### Payment Keys

Payment keys are required for HTTPS API calls. Created separately (requires USDC top-up).

| Command | Description |
|---------|-------------|
| `outlayer keys create` | Create a new payment key |
| `outlayer keys list` | List keys with balances |
| `outlayer keys balance <nonce>` | Check key balance |
| `outlayer keys topup <nonce> <amount>` | Top up with NEAR (mainnet, swaps to USDC) |
| `outlayer keys delete <nonce>` | Delete key (refunds storage) |

### Upload (FastFS)

Upload files to on-chain storage via NEAR transactions (indexed by FastFS).

| Command | Description |
|---------|-------------|
| `outlayer upload <file>` | Upload file to FastFS |
| `outlayer upload <file> --receiver <account>` | Custom receiver (default: OutLayer contract) |
| `outlayer upload <file> --mime-type <type>` | Override MIME type |

```bash
outlayer upload ./target/wasm32-wasip2/release/my-agent.wasm
# Uploading to FastFS...
#   File: ./target/wasm32-wasip2/release/my-agent.wasm
#   Size: 234567 bytes
#   SHA256: abcdef...
# Upload complete!
# FastFS URL: https://alice.near.fastfs.io/outlayer.near/abcdef.wasm
```

### Versions

| Command | Description |
|---------|-------------|
| `outlayer versions` | List project versions |
| `outlayer versions activate <key>` | Switch active version |
| `outlayer versions remove <key>` | Remove a version |

### Earnings

| Command | Description |
|---------|-------------|
| `outlayer earnings` | View developer earnings |
| `outlayer earnings withdraw` | Withdraw blockchain earnings |
| `outlayer earnings history` | View earnings history |

### Logs

| Command | Description |
|---------|-------------|
| `outlayer logs` | View execution history |
| `outlayer logs --nonce 2 --limit 50` | Specific key, more entries |

## Global Flags

```bash
outlayer --verbose ...            # Verbose output
outlayer --json ...               # JSON output
OUTLAYER_NETWORK=testnet outlayer run ...  # Override network via env
```

## Configuration

### Credentials

Stored at `~/.outlayer/{network}/credentials.json`. Requires a NEAR full access key. Private key optionally stored in OS keychain (macOS Keychain, Linux Secret Service).

After login, the active network is saved to `~/.outlayer/default-network`. If not set, the CLI auto-detects based on which network has credentials.

### Project Config

`outlayer.toml` in your project root (created by `outlayer create`):

```toml
[project]
name = "my-agent"
owner = "alice.near"

[build]
target = "wasm32-wasip2"
source = "github"

[run]
payment_key_nonce = 1
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `OUTLAYER_HOME` | Config directory (default: `~/.outlayer`) |
| `OUTLAYER_NETWORK` | Network: `mainnet` or `testnet` |
| `PAYMENT_KEY` | Payment key for `outlayer run` (format: `owner:nonce:secret`) |

## Testing

Integration tests run against testnet. Requires `outlayer login testnet`.

Execution tests auto-detect: if `TESTNET_PAYMENT_KEY` is set, calls go via HTTPS API; otherwise they use on-chain `request_execution` (costs ~0.002 NEAR per call).

```bash
# Run all tests (on-chain mode — no payment key needed)
cargo test --test integration -- --show-output

# With payment key (HTTPS mode — faster, no NEAR cost)
TESTNET_PAYMENT_KEY="owner:nonce:secret" cargo test --test integration -- --show-output

# Individual modules
cargo test --test integration -- projects --show-output
cargo test --test integration -- run --show-output
cargo test --test integration -- secrets --show-output
cargo test --test integration -- full_flow --show-output
```

`--show-output` prints test logs (mode, tx hashes, results). Use `--nocapture` to see logs even for passing tests in real-time.

## Documentation

Full documentation: [docs/CLI.md](https://github.com/out-layer/near-offshore/blob/main/docs/CLI.md)
