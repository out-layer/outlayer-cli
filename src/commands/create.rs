use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::config::{
    self, BuildSection, DeploySection, NetworkConfig, ProjectConfig, ProjectSection,
    RunSection,
};

// ── Embedded templates ──────────────────────────────────────────────────

mod basic {
    pub const CARGO_TOML: &str = include_str!("../../templates/basic/Cargo.toml.tmpl");
    pub const MAIN_RS: &str = include_str!("../../templates/basic/src/main.rs");
    pub const BUILD_SH: &str = include_str!("../../templates/basic/build.sh");
    pub const GITIGNORE: &str = include_str!("../../templates/basic/gitignore.tmpl");
}

mod contract {
    pub const CARGO_TOML: &str = include_str!("../../templates/contract/Cargo.toml.tmpl");
    pub const MAIN_RS: &str = include_str!("../../templates/contract/src/main.rs");
    pub const BUILD_SH: &str = include_str!("../../templates/contract/build.sh");
    pub const GITIGNORE: &str = include_str!("../../templates/contract/gitignore.tmpl");
}

mod shared {
    pub const SKILL_MD: &str = include_str!("../../templates/shared/skill.md");
}

struct TemplateFiles {
    cargo_toml: &'static str,
    main_rs: &'static str,
    build_sh: &'static str,
    gitignore: &'static str,
}

fn get_template(name: &str) -> Result<TemplateFiles> {
    match name {
        "basic" => Ok(TemplateFiles {
            cargo_toml: basic::CARGO_TOML,
            main_rs: basic::MAIN_RS,
            build_sh: basic::BUILD_SH,
            gitignore: basic::GITIGNORE,
        }),
        "contract" => Ok(TemplateFiles {
            cargo_toml: contract::CARGO_TOML,
            main_rs: contract::MAIN_RS,
            build_sh: contract::BUILD_SH,
            gitignore: contract::GITIGNORE,
        }),
        _ => anyhow::bail!(
            "Unknown template: {name}. Available: basic, contract"
        ),
    }
}

/// `outlayer create <name>` — create a new agent project from template
pub async fn create(
    network: &NetworkConfig,
    name: &str,
    template: &str,
    dir: Option<String>,
) -> Result<()> {
    let creds = config::load_credentials(network)?;

    // Determine project directory
    let parent = dir
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let project_dir = parent.join(name);

    if project_dir.exists() && project_dir.join("outlayer.toml").exists() {
        anyhow::bail!(
            "Project already exists at {}. Use 'outlayer deploy' to update.",
            project_dir.display()
        );
    }

    std::fs::create_dir_all(&project_dir)
        .with_context(|| format!("Failed to create directory {}", project_dir.display()))?;

    eprintln!(
        "Creating project \"{}\" ({} template) for {} in {}/",
        name,
        template,
        creds.account_id,
        project_dir.display()
    );

    // Scaffold project files from template
    scaffold(&project_dir, name, template)?;

    // Write outlayer.toml
    let project_config = ProjectConfig {
        project: ProjectSection {
            name: name.to_string(),
            owner: creds.account_id.clone(),
        },
        build: Some(BuildSection {
            target: "wasm32-wasip2".to_string(),
            source: "github".to_string(),
        }),
        deploy: Some(DeploySection {
            repo: None,
            wasm_path: None,
        }),
        run: Some(RunSection {
            max_instructions: Some(1_000_000_000),
            max_memory_mb: Some(128),
            max_execution_seconds: Some(60),
            secrets_profile: Some("default".to_string()),
            payment_key_nonce: None,
        }),
        network: Some(network.network_id.clone()),
    };

    let toml_data = toml::to_string_pretty(&project_config)?;
    std::fs::write(project_dir.join("outlayer.toml"), toml_data)?;
    eprintln!("  Created outlayer.toml");

    eprintln!("\nYour agent is ready. Next steps:");
    eprintln!("  cd {name}");
    eprintln!("  git init && git remote add origin <your-repo-url>");
    eprintln!("  # edit src/main.rs");
    eprintln!("  git push");
    eprintln!("  outlayer deploy {name}");
    eprintln!(
        "  outlayer run {}/{name} '{{\"command\": \"hello\"}}'",
        creds.account_id
    );
    eprintln!();
    eprintln!("To create a payment key for HTTPS calls:");
    eprintln!("  outlayer keys create");

    Ok(())
}

fn scaffold(project_dir: &PathBuf, project_name: &str, template_name: &str) -> Result<()> {
    let cargo_name = project_name.replace('-', "_");
    let tmpl = get_template(template_name)?;

    let substitute = |s: &str| s.replace("{{PROJECT_NAME}}", &cargo_name);

    // Cargo.toml
    std::fs::write(project_dir.join("Cargo.toml"), substitute(tmpl.cargo_toml))?;

    // src/main.rs
    std::fs::create_dir_all(project_dir.join("src"))?;
    std::fs::write(project_dir.join("src/main.rs"), substitute(tmpl.main_rs))?;

    // build.sh
    let build_sh = project_dir.join("build.sh");
    std::fs::write(&build_sh, substitute(tmpl.build_sh))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&build_sh, std::fs::Permissions::from_mode(0o755))?;
    }

    // .gitignore
    std::fs::write(project_dir.join(".gitignore"), tmpl.gitignore)?;

    // Shared files (copied to every project)
    std::fs::write(project_dir.join("skill.md"), shared::SKILL_MD)?;

    let desc = match template_name {
        "contract" => "Rust + wasm32-wasip2 + OutLayer SDK (VRF, storage, RPC)",
        _ => "Rust + wasm32-wasip2",
    };
    eprintln!("  Generated project scaffold ({desc})");
    Ok(())
}
