use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use dtm_core::module_trait::Module;
use owo_colors::OwoColorize;

mod output;

#[derive(Parser)]
#[command(
    name = "dtm",
    about = "dont-track-me — privacy audit & protection toolkit"
)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Show module availability and status
    Status,

    /// Run privacy audits
    Audit {
        /// Specific module to audit (runs all if omitted)
        module: Option<String>,

        /// Comma-separated list of modules to audit
        #[arg(short, long)]
        modules: Option<String>,

        /// Output format
        #[arg(long, default_value = "rich")]
        format: String,

        /// Write output to file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Run in interactive mode (for checklist modules)
        #[arg(short, long)]
        interactive: bool,
    },

    /// Apply privacy protections
    Protect {
        /// Specific module to protect
        module: Option<String>,

        /// Actually apply changes (default is dry-run)
        #[arg(long)]
        apply: bool,

        /// Path to operate on
        #[arg(long)]
        path: Option<PathBuf>,

        /// Only apply hardening (no diversification)
        #[arg(long)]
        harden_only: bool,

        /// Only apply diversification (no hardening)
        #[arg(long)]
        diversify_only: bool,
    },

    /// Show overall privacy score
    Score {
        /// Output format
        #[arg(long, default_value = "rich")]
        format: String,

        /// Write output to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Show educational content for a module
    Info {
        /// Module name
        module: String,
    },

    /// Manage OAuth authentication
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },

    /// Generate noise to confuse trackers
    Noise {
        #[command(subcommand)]
        command: NoiseCommands,
    },

    /// Scan installed applications for tracking SDKs
    Apps {
        /// Run a fresh scan (default: show cached results from DB)
        #[arg(long)]
        scan: bool,

        /// Additional directories to scan
        #[arg(long)]
        dir: Vec<std::path::PathBuf>,

        /// Output format
        #[arg(long, default_value = "rich")]
        format: String,
    },

    /// Monitor DNS queries for tracker domains (requires root)
    Monitor {
        /// Start live capture (default: show stored events)
        #[arg(long)]
        live: bool,

        /// Network interface (auto-detected if not specified)
        #[arg(long)]
        interface: Option<String>,

        /// Only show tracker matches
        #[arg(long)]
        tracker_only: bool,

        /// Number of events to show
        #[arg(short = 'n', long, default_value = "50")]
        limit: u32,

        /// Output format
        #[arg(long, default_value = "rich")]
        format: String,
    },
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Show authentication status for all platforms
    Status,
    /// Authenticate with Reddit
    Reddit,
    /// Authenticate with YouTube
    Youtube,
    /// Revoke authentication for a platform
    Revoke {
        /// Platform name (reddit, youtube)
        platform: String,
    },
}

#[derive(Subcommand)]
enum NoiseCommands {
    /// Generate search noise
    Search {
        /// Actually perform searches (default is dry-run)
        #[arg(long)]
        apply: bool,

        /// Categories to target
        #[arg(short, long)]
        categories: Option<String>,

        /// Number of queries to generate
        #[arg(short = 'n', long, default_value = "10")]
        count: usize,

        /// Search engines to use
        #[arg(short, long)]
        engines: Option<String>,

        /// Country code for locale-specific queries
        #[arg(short = 'C', long)]
        country: Option<String>,
    },

    /// Generate social media noise
    Social {
        /// Actually perform actions (default is dry-run)
        #[arg(long)]
        apply: bool,

        /// Platforms to target
        #[arg(short, long)]
        platforms: Option<String>,

        /// Categories to target
        #[arg(short, long)]
        categories: Option<String>,

        /// Accounts per subcategory
        #[arg(long, default_value = "3")]
        per_subcategory: usize,

        /// Country code for locale-specific data
        #[arg(short = 'C', long)]
        country: Option<String>,

        /// Output format
        #[arg(long, default_value = "rich")]
        format: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Status) => cmd_status().await,
        Some(Commands::Audit {
            module,
            modules,
            format,
            output,
            interactive,
        }) => cmd_audit(module, modules, format, output, interactive).await,
        Some(Commands::Protect {
            module,
            apply,
            path,
            harden_only,
            diversify_only,
        }) => cmd_protect(module, apply, path, harden_only, diversify_only).await,
        Some(Commands::Score { format, output }) => cmd_score(format, output).await,
        Some(Commands::Info { module }) => cmd_info(&module).await,
        Some(Commands::Auth { command }) => cmd_auth(command).await,
        Some(Commands::Noise { command }) => cmd_noise(command).await,
        Some(Commands::Apps { scan, dir, format }) => cmd_apps(scan, &dir, &format).await,
        Some(Commands::Monitor {
            live,
            interface,
            tracker_only,
            limit,
            format,
        }) => cmd_monitor(live, interface.as_deref(), tracker_only, limit, &format).await,
        None => {
            // Default: show status
            cmd_status().await
        }
    }
}

async fn cmd_status() -> Result<()> {
    let modules = dtm_modules::all_modules();
    output::print_status_table(&modules);
    Ok(())
}

async fn cmd_audit(
    module: Option<String>,
    modules_csv: Option<String>,
    format: String,
    output_path: Option<PathBuf>,
    interactive: bool,
) -> Result<()> {
    let all_modules = dtm_modules::all_modules();
    let opts = dtm_core::models::AuditOpts {
        interactive,
        ..Default::default()
    };

    // Determine which modules to audit
    let targets: Vec<&dyn dtm_core::module_trait::Module> = if let Some(ref name) = module {
        all_modules
            .iter()
            .filter(|m| m.name() == name)
            .map(|m| m.as_ref())
            .collect()
    } else if let Some(ref csv) = modules_csv {
        let names: Vec<&str> = csv.split(',').map(|s| s.trim()).collect();
        all_modules
            .iter()
            .filter(|m| names.contains(&m.name()))
            .map(|m| m.as_ref())
            .collect()
    } else {
        all_modules.iter().map(|m| m.as_ref()).collect()
    };

    if targets.is_empty() {
        let name = module.or(modules_csv).unwrap_or_default();
        eprintln!("Module not found: {name}");
        eprintln!("Run 'dtm status' to see available modules.");
        std::process::exit(1);
    }

    if format == "rich" {
        println!();
        println!("  {}", "dont-track-me".bold());
        println!("  {}", "Privacy Audit".dimmed());
    }

    let mut results = Vec::new();
    for target in &targets {
        match target.audit(&opts).await {
            Ok(result) => {
                // Print live results for non-html formats
                if format != "html" {
                    output::print_audit_result(&result, &format);
                }
                results.push(result);
            }
            Err(e) => {
                eprintln!("Error auditing {}: {e}", target.name());
            }
        }
    }

    if format == "rich" && results.len() > 1 {
        let total_findings: usize = results.iter().map(|r| r.findings.len()).sum();
        let avg_score: f64 =
            results.iter().map(|r| r.score as f64).sum::<f64>() / results.len() as f64;
        println!();
        println!(
            "  {} modules audited · {} total findings · avg score {:.0}",
            results.len(),
            total_findings,
            avg_score,
        );
        println!();
    }

    // Generate output
    match format.as_str() {
        "html" => {
            let config = dtm_core::scoring::load_scoring_config().unwrap_or(
                dtm_core::scoring::ScoringConfig {
                    module_weights: std::collections::HashMap::new(),
                    default_weight: 5.0,
                },
            );
            let overall = dtm_core::scoring::compute_overall_score(&results, &config);
            let html = dtm_core::report::generate_html_report(&results, overall);

            if let Some(path) = output_path {
                std::fs::write(&path, &html)?;
                eprintln!("HTML report written to {}", path.display());
            } else {
                // Write to temp file and open in browser
                let path = std::env::temp_dir().join("dtm-report.html");
                std::fs::write(&path, &html)?;
                eprintln!("Opening report in browser...");
                if let Err(e) = open::that(&path) {
                    eprintln!("Could not open browser: {e}");
                    eprintln!("Report saved to {}", path.display());
                }
            }
        }
        "json" => {
            if let Some(path) = output_path {
                let content = serde_json::to_string_pretty(&results)?;
                std::fs::write(&path, content)?;
                eprintln!("Output written to {}", path.display());
            }
        }
        _ => {
            if let Some(path) = output_path {
                let content = format!("{results:#?}");
                std::fs::write(&path, content)?;
                eprintln!("Output written to {}", path.display());
            }
        }
    }

    Ok(())
}

async fn cmd_protect(
    module: Option<String>,
    apply: bool,
    path: Option<PathBuf>,
    harden_only: bool,
    diversify_only: bool,
) -> Result<()> {
    let all_modules = dtm_modules::all_modules();
    let opts = dtm_core::models::ProtectOpts {
        apply,
        path,
        harden_only,
        diversify_only,
        ..Default::default()
    };

    let targets: Vec<&dyn dtm_core::module_trait::Module> = if let Some(ref name) = module {
        all_modules
            .iter()
            .filter(|m| m.name() == name)
            .map(|m| m.as_ref())
            .collect()
    } else {
        all_modules.iter().map(|m| m.as_ref()).collect()
    };

    for target in &targets {
        match target.protect(&opts).await {
            Ok(result) => output::print_protection_result(&result),
            Err(e) => eprintln!("Error protecting {}: {e}", target.name()),
        }
    }

    Ok(())
}

async fn cmd_score(format: String, output_path: Option<PathBuf>) -> Result<()> {
    let modules = dtm_modules::all_modules();
    let opts = dtm_core::models::AuditOpts::default();

    let mut results = Vec::new();
    for module in &modules {
        match module.audit(&opts).await {
            Ok(result) => results.push(result),
            Err(e) => eprintln!("Error auditing {}: {e}", module.name()),
        }
    }

    let config =
        dtm_core::scoring::load_scoring_config().unwrap_or(dtm_core::scoring::ScoringConfig {
            module_weights: std::collections::HashMap::new(),
            default_weight: 5.0,
        });

    let overall = dtm_core::scoring::compute_overall_score(&results, &config);

    match format.as_str() {
        "html" => {
            let html = dtm_core::report::generate_html_report(&results, overall);
            if let Some(path) = output_path {
                std::fs::write(&path, &html)?;
                eprintln!("HTML report written to {}", path.display());
            } else {
                let path = std::env::temp_dir().join("dtm-report.html");
                std::fs::write(&path, &html)?;
                eprintln!("Opening report in browser...");
                if let Err(e) = open::that(&path) {
                    eprintln!("Could not open browser: {e}");
                    eprintln!("Report saved to {}", path.display());
                }
            }
        }
        "json" => {
            let data = serde_json::json!({
                "overall_score": overall,
                "modules": results,
            });
            let json = serde_json::to_string_pretty(&data)?;
            if let Some(path) = output_path {
                std::fs::write(&path, &json)?;
                eprintln!("Output written to {}", path.display());
            } else {
                println!("{json}");
            }
        }
        _ => {
            output::print_score_table(&results, overall);
        }
    }

    Ok(())
}

async fn cmd_info(module_name: &str) -> Result<()> {
    if let Some(module) = dtm_modules::get_module(module_name) {
        let content = module.educational_content();
        output::print_educational_content(module_name, &content);
    } else {
        eprintln!("Module not found: {module_name}");
        eprintln!("Run 'dtm status' to see available modules.");
        std::process::exit(1);
    }
    Ok(())
}

async fn cmd_auth(command: AuthCommands) -> Result<()> {
    match command {
        AuthCommands::Status => {
            println!("OAuth authentication status:");
            for platform in &["reddit", "youtube"] {
                let status = if dtm_core::auth::TokenStore::is_authenticated(platform) {
                    "authenticated"
                } else {
                    "not authenticated"
                };
                println!("  {platform}: {status}");
            }
        }
        AuthCommands::Reddit => {
            run_oauth_flow(
                "reddit",
                dtm_modules::reddit::client::AUTHORIZE_URL,
                dtm_modules::reddit::client::TOKEN_URL,
                dtm_modules::reddit::client::SCOPES,
                vec![
                    ("duration".to_string(), "permanent".to_string()),
                    ("response_type".to_string(), "code".to_string()),
                ],
            )?;
        }
        AuthCommands::Youtube => {
            run_oauth_flow(
                "youtube",
                dtm_modules::youtube::client::AUTHORIZE_URL,
                dtm_modules::youtube::client::TOKEN_URL,
                dtm_modules::youtube::client::SCOPES,
                vec![("access_type".to_string(), "offline".to_string())],
            )?;
        }
        AuthCommands::Revoke { platform } => {
            dtm_core::auth::TokenStore::delete(&platform);
            println!("Revoked authentication for {platform}.");
        }
    }
    Ok(())
}

fn run_oauth_flow(
    platform: &str,
    authorize_url: &str,
    token_url: &str,
    scopes: &[&str],
    extra_params: Vec<(String, String)>,
) -> Result<()> {
    let (client_id, client_secret) = dtm_core::auth::get_platform_credentials(platform)?;

    println!("Starting {platform} OAuth flow...");
    println!("A browser window will open. Please authorize the application.");

    let flow = dtm_core::auth::OAuthFlow {
        authorize_url: authorize_url.to_string(),
        token_url: token_url.to_string(),
        client_id,
        client_secret,
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        extra_params,
    };

    let token = flow.run()?;
    dtm_core::auth::TokenStore::save(platform, &token)?;
    println!("Successfully authenticated with {platform}!");
    Ok(())
}

async fn cmd_noise(command: NoiseCommands) -> Result<()> {
    match command {
        NoiseCommands::Search {
            apply,
            categories,
            count,
            country,
            ..
        } => {
            let module = dtm_modules::search_noise::SearchNoiseModule;
            let opts = dtm_core::models::ProtectOpts {
                apply,
                count: Some(count),
                categories: categories
                    .map(|c| c.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default(),
                country,
                ..Default::default()
            };
            match module.protect(&opts).await {
                Ok(result) => output::print_protection_result(&result),
                Err(e) => eprintln!("Error generating search noise: {e}"),
            }
        }
        NoiseCommands::Social {
            apply,
            categories,
            country,
            ..
        } => {
            let module = dtm_modules::social_noise::SocialNoiseModule;
            let opts = dtm_core::models::ProtectOpts {
                apply,
                categories: categories
                    .map(|c| c.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default(),
                country,
                ..Default::default()
            };
            match module.protect(&opts).await {
                Ok(result) => output::print_protection_result(&result),
                Err(e) => eprintln!("Error generating social noise: {e}"),
            }
        }
    }
    Ok(())
}

async fn cmd_apps(scan: bool, extra_dirs: &[std::path::PathBuf], format: &str) -> Result<()> {
    if scan {
        // Run a fresh scan
        println!("Scanning applications for tracking SDKs...");
        let results = dtm_modules::app_scanner::scanner::scan_apps(extra_dirs);

        // Store in DB
        if let Err(e) = dtm_modules::app_scanner::scanner::store_results(&results) {
            eprintln!("Warning: Failed to store scan results: {e}");
        }

        // Filter to apps with findings for display
        let with_findings: Vec<_> = results
            .iter()
            .filter(|r| !r.tracking_sdks.is_empty() || !r.ats_exceptions.is_empty())
            .collect();

        let total = results.len();
        println!("\nScanned {total} applications.");

        if with_findings.is_empty() {
            println!("No tracking SDKs or ATS exceptions found.");
            return Ok(());
        }

        if format == "json" {
            println!("{}", serde_json::to_string_pretty(&with_findings)?);
        } else {
            println!(
                "{} apps with tracking SDKs or ATS exceptions:\n",
                with_findings.len()
            );
            for app in &with_findings {
                println!(
                    "  {} ({}):",
                    app.app_name,
                    app.bundle_id.as_deref().unwrap_or("unknown")
                );
                for sdk in &app.tracking_sdks {
                    println!("    SDK: {} [{}]", sdk.name, sdk.category);
                }
                for exc in &app.ats_exceptions {
                    println!("    ATS: {exc}");
                }
            }
        }
    } else {
        // Show cached results from DB
        let db_path = dtm_core::db::default_db_path();
        if !db_path.exists() {
            eprintln!("No scan results found. Run 'dtm apps --scan' first.");
            return Ok(());
        }

        let conn = dtm_core::db::open_db(&db_path)?;
        let results = dtm_core::db::get_app_scan_results(&conn)?;

        if results.is_empty() {
            println!("No app scan results found. Run 'dtm apps --scan' first.");
            return Ok(());
        }

        output::print_app_scan_results(&results, format);
    }
    Ok(())
}

async fn cmd_monitor(
    live: bool,
    interface: Option<&str>,
    tracker_only: bool,
    limit: u32,
    format: &str,
) -> Result<()> {
    if live {
        // Start live DNS capture
        println!("\n=== DNS Tracker Monitor ===\n");
        println!("Capturing DNS queries and matching against known tracker domains.");
        println!("Press Ctrl+C to stop.\n");

        let db_path = dtm_core::db::default_db_path();
        let conn = dtm_core::db::open_db(&db_path)?;

        dtm_modules::dns_monitor::capture::monitor_dns(&conn, interface)?;
    } else {
        // Show stored events from DB
        let db_path = dtm_core::db::default_db_path();
        if !db_path.exists() {
            eprintln!("No DNS monitoring data found. Run 'sudo dtm monitor --live' first.");
            return Ok(());
        }

        let conn = dtm_core::db::open_db(&db_path)?;
        let events = dtm_core::db::get_dns_events(&conn, tracker_only, limit)?;

        if events.is_empty() {
            println!("No DNS events found. Run 'sudo dtm monitor --live' first.");
            return Ok(());
        }

        output::print_dns_events(&events, format);
    }
    Ok(())
}
