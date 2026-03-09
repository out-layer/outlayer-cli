use outlayer_cli::commands;
use outlayer_cli::config;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "outlayer", about = "CLI for deploying, running, and managing OutLayer agents")]
struct Cli {
    /// Verbose output
    #[arg(long, short, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Login with NEAR full access key
    Login {
        /// mainnet (default) or testnet
        #[arg(default_value = "mainnet")]
        network: String,
    },
    /// Delete stored credentials
    Logout,
    /// Show current account
    Whoami,
    /// Create a new agent project from template
    Create {
        /// Project name (also used as directory name)
        name: String,

        /// Template: basic (default) or contract (with NEAR RPC bindings)
        #[arg(long, default_value = "basic")]
        template: String,

        /// Parent directory (defaults to current dir)
        #[arg(long)]
        dir: Option<String>,
    },
    /// Deploy agent to OutLayer
    Deploy {
        /// Project name (e.g. my-agent)
        name: String,

        /// WASM URL to deploy (e.g. FastFS URL). If omitted, deploys from current git repo
        wasm_url: Option<String>,

        /// WASM SHA256 hash (auto-computed from URL if omitted)
        #[arg(long)]
        hash: Option<String>,

        /// Deploy from current git repo (origin remote + HEAD commit)
        #[arg(long)]
        github: bool,

        /// Build target (default: wasm32-wasip2)
        #[arg(long, default_value = "wasm32-wasip2")]
        target: String,

        /// Deploy version without activating
        #[arg(long)]
        no_activate: bool,
    },
    /// Execute agent
    Run {
        /// Project to run (owner/name, e.g. alice.near/my-agent)
        #[arg(required_unless_present_any = ["github", "wasm"])]
        project: Option<String>,

        /// JSON input
        input: Option<String>,

        /// Run from GitHub repo (url or owner/repo)
        #[arg(long)]
        github: Option<String>,

        /// Git commit (for --github, defaults to latest)
        #[arg(long)]
        commit: Option<String>,

        /// Run from WASM URL
        #[arg(long)]
        wasm: Option<String>,

        /// WASM SHA256 hash (for --wasm)
        #[arg(long)]
        hash: Option<String>,

        /// Input from file
        #[arg(long = "input")]
        input_file: Option<String>,

        /// Async execution (HTTPS only)
        #[arg(long = "async")]
        is_async: bool,

        /// Attached payment to developer (USD, HTTPS only)
        #[arg(long)]
        deposit: Option<String>,

        /// Run a specific version (for project source)
        #[arg(long)]
        version: Option<String>,

        /// Compute limit (instructions)
        #[arg(long)]
        compute_limit: Option<u64>,

        /// Build target (default: wasm32-wasip2)
        #[arg(long, default_value = "wasm32-wasip2")]
        target: String,

        /// Secrets profile to attach (requires --secrets-account)
        #[arg(long)]
        secrets_profile: Option<String>,

        /// Account that owns the secrets (requires --secrets-profile)
        #[arg(long)]
        secrets_account: Option<String>,
    },
    /// Manage payment keys
    Keys {
        #[command(subcommand)]
        command: KeysCommands,
    },
    /// Manage encrypted secrets
    Secrets {
        #[command(subcommand)]
        command: SecretsCommands,
    },
    /// View developer earnings
    Earnings {
        #[command(subcommand)]
        command: Option<EarningsCommands>,
    },
    /// Check project status or poll async call
    Status {
        /// Call ID to poll (omit for project info)
        call_id: Option<String>,
    },
    /// Manage project versions
    Versions {
        #[command(subcommand)]
        command: Option<VersionsCommands>,
    },
    /// Upload file to FastFS (on-chain storage via NEAR transactions)
    Upload {
        /// File to upload
        file: String,

        /// Receiver account (defaults to OutLayer contract)
        #[arg(long)]
        receiver: Option<String>,

        /// MIME type (auto-detected from extension if omitted)
        #[arg(long)]
        mime_type: Option<String>,
    },
    /// List projects for a user
    Projects {
        /// Account ID (defaults to logged-in user)
        account: Option<String>,
    },
    /// View execution history
    Logs {
        /// Payment key nonce (defaults to outlayer.toml config)
        #[arg(long)]
        nonce: Option<u32>,

        /// Number of entries
        #[arg(long, default_value = "20")]
        limit: i64,
    },
}

#[derive(Subcommand)]
enum KeysCommands {
    /// Create a new payment key
    Create,
    /// List payment keys with balances
    List,
    /// Check payment key balance
    Balance {
        /// Payment key nonce
        nonce: u32,
    },
    /// Top up payment key with NEAR
    Topup {
        /// Payment key nonce
        nonce: u32,
        /// Amount in NEAR
        amount: f64,
    },
    /// Delete payment key (refunds storage)
    Delete {
        /// Payment key nonce
        nonce: u32,
    },
}

#[derive(Subcommand)]
enum SecretsCommands {
    /// Store encrypted secrets (overwrites existing)
    Set {
        /// JSON object: '{"KEY":"value"}'
        secrets: Option<String>,

        /// Secrets profile name
        #[arg(long, default_value = "default")]
        profile: String,

        /// Project accessor (owner/name, e.g. alice.near/my-agent)
        #[arg(long)]
        project: Option<String>,

        /// Repository accessor (e.g. github.com/user/repo)
        #[arg(long)]
        repo: Option<String>,

        /// Branch (use with --repo)
        #[arg(long)]
        branch: Option<String>,

        /// WASM hash accessor
        #[arg(long)]
        wasm_hash: Option<String>,

        /// Generate protected variable: PROTECTED_NAME:type (hex16, hex32, hex64, ed25519, ed25519_seed, password, password:N)
        #[arg(long)]
        generate: Vec<String>,

        /// Access control: allow-all (default), whitelist:acc1,acc2
        #[arg(long, default_value = "allow-all")]
        access: String,
    },
    /// Update secrets (preserves PROTECTED_*, merges with existing)
    Update {
        /// JSON object to merge: '{"KEY":"value"}'
        secrets: Option<String>,

        /// Secrets profile name
        #[arg(long, default_value = "default")]
        profile: String,

        /// Project accessor (owner/name)
        #[arg(long)]
        project: Option<String>,

        /// Repository accessor
        #[arg(long)]
        repo: Option<String>,

        /// Branch (use with --repo)
        #[arg(long)]
        branch: Option<String>,

        /// WASM hash accessor
        #[arg(long)]
        wasm_hash: Option<String>,

        /// Generate new protected variable: PROTECTED_NAME:type
        #[arg(long)]
        generate: Vec<String>,
    },
    /// List stored secrets (metadata only)
    List,
    /// Delete secrets for a profile
    Delete {
        /// Secrets profile name
        #[arg(long, default_value = "default")]
        profile: String,

        /// Project accessor (owner/name)
        #[arg(long)]
        project: Option<String>,

        /// Repository accessor
        #[arg(long)]
        repo: Option<String>,

        /// Branch (use with --repo)
        #[arg(long)]
        branch: Option<String>,

        /// WASM hash accessor
        #[arg(long)]
        wasm_hash: Option<String>,
    },
}

#[derive(Subcommand)]
enum EarningsCommands {
    /// Withdraw blockchain earnings
    Withdraw,
    /// View earnings history
    History {
        /// Filter by source: blockchain, https
        #[arg(long)]
        source: Option<String>,
        /// Number of entries
        #[arg(long, default_value = "20")]
        limit: i64,
    },
}

#[derive(Subcommand)]
enum VersionsCommands {
    /// Switch active version
    Activate {
        /// Version key to activate
        version_key: String,
    },
    /// Remove a version
    Remove {
        /// Version key to remove
        version_key: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Env var override (rarely needed — network is saved on login)
    let env_net = std::env::var("OUTLAYER_NETWORK").ok();
    let env_net = env_net.as_deref();

    match cli.command {
        Commands::Login { network } => {
            commands::auth::login(&network).await?;
        }
        Commands::Logout => {
            let network = config::resolve_network(env_net, None)?;
            commands::auth::logout(&network)?;
        }
        Commands::Whoami => {
            let network = config::resolve_network(env_net, None)?;
            commands::auth::whoami(&network)?;
        }
        Commands::Create { name, template, dir } => {
            let network = config::resolve_network(env_net, None)?;
            commands::create::create(&network, &name, &template, dir).await?;
        }
        Commands::Deploy {
            name,
            wasm_url,
            hash,
            github,
            target,
            no_activate,
        } => {
            let network = resolve_with_project(env_net)?;
            // --github forces GitHub mode (ignores wasm_url)
            let wasm_url = if github { None } else { wasm_url };
            commands::deploy::deploy(&network, &name, wasm_url, hash, &target, no_activate)
                .await?;
        }
        Commands::Run {
            project,
            input,
            github,
            commit,
            wasm,
            hash,
            input_file,
            is_async,
            deposit,
            version,
            compute_limit,
            target,
            secrets_profile,
            secrets_account,
        } => {
            let network = resolve_with_project(env_net)?;
            let source = if let Some(repo) = github {
                commands::run::RunSource::GitHub { repo, commit }
            } else if let Some(url) = wasm {
                commands::run::RunSource::WasmUrl { url, hash }
            } else {
                commands::run::RunSource::Project {
                    project_id: project.unwrap(),
                    version,
                }
            };
            let secrets_ref = match (secrets_profile, secrets_account) {
                (Some(profile), Some(account_id)) => {
                    Some(outlayer_cli::api::SecretsRef { profile, account_id })
                }
                (None, None) => None,
                _ => anyhow::bail!("--secrets-profile and --secrets-account must be used together"),
            };
            commands::run::run(
                &network, source, input, input_file, is_async, deposit, compute_limit,
                &target, secrets_ref,
            )
            .await?;
        }
        Commands::Keys { command } => {
            let network = resolve_with_project(env_net)?;
            match command {
                KeysCommands::Create => commands::keys::create(&network).await?,
                KeysCommands::List => commands::keys::list(&network).await?,
                KeysCommands::Balance { nonce } => {
                    commands::keys::balance(&network, nonce).await?
                }
                KeysCommands::Topup { nonce, amount } => {
                    commands::keys::topup(&network, nonce, amount).await?
                }
                KeysCommands::Delete { nonce } => {
                    commands::keys::delete(&network, nonce).await?
                }
            }
        }
        Commands::Secrets { command } => {
            let project_config = config::load_project_config().ok();
            let network = config::resolve_network(
                env_net,
                project_config.as_ref().and_then(|c| c.network.as_deref()),
            )?;
            match command {
                SecretsCommands::Set {
                    secrets,
                    profile,
                    project,
                    repo,
                    branch,
                    wasm_hash,
                    generate,
                    access,
                } => {
                    commands::secrets::set(
                        &network,
                        project_config.as_ref(),
                        secrets,
                        &profile,
                        project,
                        repo,
                        branch,
                        wasm_hash,
                        generate,
                        &access,
                    )
                    .await?
                }
                SecretsCommands::Update {
                    secrets,
                    profile,
                    project,
                    repo,
                    branch,
                    wasm_hash,
                    generate,
                } => {
                    commands::secrets::update(
                        &network,
                        project_config.as_ref(),
                        secrets,
                        &profile,
                        project,
                        repo,
                        branch,
                        wasm_hash,
                        generate,
                    )
                    .await?
                }
                SecretsCommands::List => commands::secrets::list(&network).await?,
                SecretsCommands::Delete {
                    profile,
                    project,
                    repo,
                    branch,
                    wasm_hash,
                } => {
                    commands::secrets::delete(
                        &network,
                        project_config.as_ref(),
                        &profile,
                        project,
                        repo,
                        branch,
                        wasm_hash,
                    )
                    .await?
                }
            }
        }
        Commands::Earnings { command } => {
            let network = resolve_with_project(env_net)?;
            match command {
                None => commands::earnings::show(&network).await?,
                Some(EarningsCommands::Withdraw) => {
                    commands::earnings::withdraw(&network).await?
                }
                Some(EarningsCommands::History { source, limit }) => {
                    commands::earnings::history(&network, source, limit).await?
                }
            }
        }
        Commands::Status { call_id } => {
            let project_config = config::load_project_config()?;
            let network = config::resolve_network(
                env_net,
                project_config.network.as_deref(),
            )?;
            commands::status::status(&network, &project_config, call_id).await?;
        }
        Commands::Versions { command } => {
            let project_config = config::load_project_config()?;
            let network = config::resolve_network(
                env_net,
                project_config.network.as_deref(),
            )?;
            match command {
                None => commands::versions::list(&network, &project_config).await?,
                Some(VersionsCommands::Activate { version_key }) => {
                    commands::versions::activate(&network, &project_config, &version_key).await?
                }
                Some(VersionsCommands::Remove { version_key }) => {
                    commands::versions::remove(&network, &project_config, &version_key).await?
                }
            }
        }
        Commands::Upload {
            file,
            receiver,
            mime_type,
        } => {
            let network = resolve_with_project(env_net)?;
            commands::upload::upload(&network, &file, receiver, mime_type).await?;
        }
        Commands::Projects { account } => {
            let network = resolve_with_project(env_net)?;
            commands::projects::list(&network, account).await?;
        }
        Commands::Logs { nonce, limit } => {
            let project_config = config::load_project_config().ok();
            let network = config::resolve_network(
                env_net,
                project_config.as_ref().and_then(|c| c.network.as_deref()),
            )?;
            commands::logs::logs(&network, project_config.as_ref(), nonce, limit).await?;
        }
    }

    Ok(())
}

/// Resolve network, trying project config if available
fn resolve_with_project(env_net: Option<&str>) -> anyhow::Result<config::NetworkConfig> {
    let project_config = config::load_project_config().ok();
    config::resolve_network(
        env_net,
        project_config.as_ref().and_then(|c| c.network.as_deref()),
    )
}
