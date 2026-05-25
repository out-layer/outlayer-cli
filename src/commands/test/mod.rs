//! `outlayer test` — Run WASM modules locally with wasmtime for OutLayer compatibility.

pub mod rpc_proxy;

use anyhow::{Context, Result};
use std::path::PathBuf;
use wasmtime::component::Component;
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::preview1::{self, WasiP1Ctx};
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiView};
use wasmtime_wasi_http::{WasiHttpCtx, WasiHttpView};

use rpc_proxy::{add_rpc_to_linker, RpcHostState, RpcProxy};

#[derive(clap::Args)]
pub struct TestArgs {
    /// Path to WASM file
    #[arg(short, long)]
    pub wasm: PathBuf,

    /// Input JSON data (or use --input-file)
    #[arg(short, long, conflicts_with = "input_file")]
    pub input: Option<String>,

    /// Path to input JSON file
    #[arg(long)]
    pub input_file: Option<PathBuf>,

    /// Maximum instructions (fuel limit)
    #[arg(long, default_value = "10000000000")]
    pub max_instructions: u64,

    /// Maximum memory in MB
    #[arg(long, default_value = "128")]
    pub max_memory_mb: u64,

    /// Environment variables (KEY=value, repeatable)
    #[arg(short, long)]
    pub env: Vec<String>,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Enable NEAR RPC proxy (near:rpc/api host functions)
    #[arg(long)]
    pub rpc: bool,

    /// NEAR RPC URL (default: testnet)
    #[arg(long, default_value = "https://rpc.testnet.near.org")]
    pub rpc_url: String,

    /// Maximum RPC calls per execution
    #[arg(long, default_value = "100")]
    pub rpc_max_calls: u32,

    /// Allow transaction methods (send_tx, broadcast_tx_*)
    #[arg(long)]
    pub rpc_allow_transactions: bool,

    /// NEAR account ID for signing transactions
    #[arg(long)]
    pub rpc_signer_account: Option<String>,

    /// NEAR private key for signing (ed25519:...)
    #[arg(long)]
    pub rpc_signer_key: Option<String>,
}

struct HostState {
    wasi_ctx: WasiCtx,
    wasi_http_ctx: WasiHttpCtx,
    table: ResourceTable,
    rpc_state: Option<RpcHostState>,
}

impl WasiView for HostState {
    fn ctx(&mut self) -> &mut WasiCtx { &mut self.wasi_ctx }
    fn table(&mut self) -> &mut ResourceTable { &mut self.table }
}

impl WasiHttpView for HostState {
    fn ctx(&mut self) -> &mut WasiHttpCtx { &mut self.wasi_http_ctx }
    fn table(&mut self) -> &mut ResourceTable { &mut self.table }
}

pub async fn run(args: &TestArgs) -> Result<()> {
    let input_data = if let Some(ref input) = args.input {
        input.clone()
    } else if let Some(ref path) = args.input_file {
        std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read input file: {}", path.display()))?
    } else {
        "{}".to_string()
    };

    serde_json::from_str::<serde_json::Value>(&input_data).context("Input is not valid JSON")?;

    let wasm_bytes = std::fs::read(&args.wasm)
        .with_context(|| format!("Failed to read WASM file: {}", args.wasm.display()))?;

    println!("Testing WASM module: {}", args.wasm.display());
    println!("Input: {}", input_data);
    println!("Max instructions: {}", args.max_instructions);
    println!("Max memory: {} MB", args.max_memory_mb);
    if args.rpc {
        println!("RPC proxy: enabled ({})", args.rpc_url);
        println!("  - Max calls: {}", args.rpc_max_calls);
        println!("  - Transactions: {}", if args.rpc_allow_transactions { "allowed" } else { "disabled" });
        if let Some(ref account) = args.rpc_signer_account {
            println!("  - Signer: {}", account);
        }
    }
    println!();

    match execute_wasm(&wasm_bytes, &input_data, args).await {
        Ok((output, fuel_consumed)) => {
            println!("Execution successful!\n");
            println!("Results:");
            println!("  - Fuel consumed: {} instructions", fuel_consumed);
            println!("  - Output size: {} bytes", output.len());
            println!("\nOutput:\n{}\n", String::from_utf8_lossy(&output));
            validate_output(&output)?;
            println!("All checks passed! Module is compatible with NEAR OutLayer.");
            Ok(())
        }
        Err(e) => {
            println!("Execution failed!\nError: {}\n", e);
            println!("Common issues:");
            println!("  - Use [[bin]] format, not [lib]");
            println!("  - Check fn main() entry point");
            println!("  - Read from stdin, write to stdout");
            println!("  - Build target: wasm32-wasip1 or wasm32-wasip2");
            if args.rpc {
                println!("  - RPC: ensure WASM imports near:rpc/api correctly");
            }
            std::process::exit(1);
        }
    }
}

async fn execute_wasm(wasm_bytes: &[u8], input_data: &str, args: &TestArgs) -> Result<(Vec<u8>, u64)> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.async_support(true);
    config.consume_fuel(true);
    let engine = Engine::new(&config)?;

    if let Ok(component) = Component::from_binary(&engine, wasm_bytes) {
        println!("Detected: WASI Preview 2 Component");
        return execute_wasi_p2(&engine, &component, input_data, args).await;
    }

    let mut module_config = Config::new();
    module_config.async_support(true);
    module_config.consume_fuel(true);
    let module_engine = Engine::new(&module_config)?;

    if let Ok(module) = wasmtime::Module::from_binary(&module_engine, wasm_bytes) {
        println!("Detected: WASI Preview 1 Module");
        if args.rpc {
            println!("Warning: RPC proxy is only supported for WASI P2 components");
        }
        return execute_wasi_p1(&module_engine, &module, input_data, args).await;
    }

    anyhow::bail!("Not a valid WASI P1/P2 module. Build with --target wasm32-wasip1 or wasm32-wasip2")
}

async fn execute_wasi_p2(
    engine: &Engine, component: &Component, input_data: &str, args: &TestArgs,
) -> Result<(Vec<u8>, u64)> {
    use wasmtime::component::Linker;
    use wasmtime_wasi::bindings::Command;

    let mut linker = Linker::new(engine);
    wasmtime_wasi::add_to_linker_async(&mut linker)?;
    wasmtime_wasi_http::add_only_http_to_linker_async(&mut linker)?;

    let rpc_enabled = args.rpc || args.rpc_allow_transactions;
    if rpc_enabled {
        add_rpc_to_linker(&mut linker, |state: &mut HostState| {
            state.rpc_state.as_mut().expect("RPC state not initialized")
        })?;
    }

    let stdin_pipe = wasmtime_wasi::pipe::MemoryInputPipe::new(input_data.as_bytes().to_vec());
    let stdout_pipe = wasmtime_wasi::pipe::MemoryOutputPipe::new((args.max_memory_mb as usize) * 1024 * 1024);
    let stderr_pipe = wasmtime_wasi::pipe::MemoryOutputPipe::new(1024 * 1024);

    let mut wasi_builder = WasiCtxBuilder::new();
    wasi_builder.stdin(stdin_pipe);
    wasi_builder.stdout(stdout_pipe.clone());
    wasi_builder.stderr(stderr_pipe.clone());
    wasi_builder.preopened_dir("/tmp", ".", wasmtime_wasi::DirPerms::all(), wasmtime_wasi::FilePerms::all())?;

    for env_var in &args.env {
        if let Some((key, value)) = env_var.split_once('=') {
            wasi_builder.env(key, value);
        }
    }

    let rpc_state = if rpc_enabled {
        let signer = args.rpc_signer_account.clone().zip(args.rpc_signer_key.clone());
        Some(RpcHostState::new(RpcProxy::new(
            &args.rpc_url, args.rpc_max_calls, args.rpc_allow_transactions, signer,
        )?))
    } else {
        None
    };

    let host_state = HostState {
        wasi_ctx: wasi_builder.build(),
        wasi_http_ctx: WasiHttpCtx::new(),
        table: ResourceTable::new(),
        rpc_state,
    };

    let mut store = Store::new(engine, host_state);
    store.set_fuel(args.max_instructions)?;

    let command = Command::instantiate_async(&mut store, component, &linker).await?;
    command.wasi_cli_run().call_run(&mut store).await?.map_err(|_| anyhow::anyhow!("Command failed"))?;

    let fuel_consumed = args.max_instructions - store.get_fuel().unwrap_or(0);
    let output = stdout_pipe.contents().to_vec();

    if args.verbose && !&stderr_pipe.contents().is_empty() {
        println!("\nSTDERR:\n{}", String::from_utf8_lossy(&stderr_pipe.contents()));
    }

    Ok((output, fuel_consumed))
}

async fn execute_wasi_p1(
    engine: &Engine, module: &wasmtime::Module, input_data: &str, args: &TestArgs,
) -> Result<(Vec<u8>, u64)> {
    let mut linker = wasmtime::Linker::new(engine);
    preview1::add_to_linker_async(&mut linker, |t: &mut WasiP1Ctx| t)?;

    let stdin_pipe = wasmtime_wasi::pipe::MemoryInputPipe::new(input_data.as_bytes().to_vec());
    let stdout_pipe = wasmtime_wasi::pipe::MemoryOutputPipe::new((args.max_memory_mb as usize) * 1024 * 1024);
    let stderr_pipe = wasmtime_wasi::pipe::MemoryOutputPipe::new(1024 * 1024);

    let mut wasi_builder = WasiCtxBuilder::new();
    wasi_builder.stdin(stdin_pipe);
    wasi_builder.stdout(stdout_pipe.clone());
    wasi_builder.stderr(stderr_pipe.clone());

    for env_var in &args.env {
        if let Some((key, value)) = env_var.split_once('=') {
            wasi_builder.env(key, value);
        }
    }

    let wasi_p1_ctx = wasi_builder.build_p1();
    let mut store = Store::new(engine, wasi_p1_ctx);
    store.set_fuel(args.max_instructions)?;

    let instance = linker.instantiate_async(&mut store, module).await?;
    let start = instance.get_typed_func::<(), ()>(&mut store, "_start")
        .context("No _start function. Use [[bin]] format with fn main()")?;
    start.call_async(&mut store, ()).await?;

    let fuel_consumed = args.max_instructions - store.get_fuel().unwrap_or(0);
    let output = stdout_pipe.contents().to_vec();

    if args.verbose && !&stderr_pipe.contents().is_empty() {
        println!("\nSTDERR:\n{}", String::from_utf8_lossy(&stderr_pipe.contents()));
    }

    Ok((output, fuel_consumed))
}

fn validate_output(output: &[u8]) -> Result<()> {
    if output.is_empty() {
        anyhow::bail!("Output is empty! Write to stdout and flush: io::stdout().flush()?");
    }
    if output.len() > 900 {
        println!("Warning: Output is {} bytes (NEAR limit is 900)", output.len());
    }
    let output_str = String::from_utf8_lossy(output);
    match serde_json::from_str::<serde_json::Value>(&output_str) {
        Ok(_) => println!("Output is valid JSON"),
        Err(e) => println!("Warning: Output is not valid JSON: {}", e),
    }
    Ok(())
}
