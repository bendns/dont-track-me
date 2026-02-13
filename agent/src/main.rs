mod app_scanner;
mod db;
mod dns_monitor;
mod models;
mod tracker_domains;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use log::info;

#[derive(Parser)]
#[command(
    name = "dtm-agent",
    about = "Real-time privacy monitoring daemon for dont-track-me",
    version
)]
struct Cli {
    /// Path to the event database (default: ~/.local/share/dtm/events.db)
    #[arg(long, global = true)]
    db: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan installed applications for tracking SDKs
    ScanApps {
        /// Output format: "summary" (default) or "json"
        #[arg(long, default_value = "summary")]
        format: String,

        /// Additional directories to scan (besides /Applications)
        #[arg(long)]
        dir: Vec<PathBuf>,
    },

    /// Monitor DNS queries for tracker domains (requires root or bpf group)
    MonitorDns {
        /// Network interface to capture on (auto-detected if not specified)
        #[arg(long)]
        interface: Option<String>,
    },
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    let db_path = cli.db.unwrap_or_else(db::default_db_path);
    info!("Using database: {}", db_path.display());

    let conn = match db::open_db(&db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "Error: Failed to open database at {}: {e}",
                db_path.display()
            );
            std::process::exit(1);
        }
    };

    match cli.command {
        Commands::ScanApps { format, dir } => {
            let results = app_scanner::scan_apps(&dir);

            // Store results in database
            if let Err(e) = db::clear_app_scans(&conn) {
                eprintln!("Warning: Failed to clear old scan results: {e}");
            }
            for result in &results {
                if let Err(e) = db::insert_app_scan(&conn, result) {
                    eprintln!(
                        "Warning: Failed to store scan result for {}: {e}",
                        result.app_name
                    );
                }
            }

            match format.as_str() {
                "json" => app_scanner::print_results_json(&results),
                _ => app_scanner::print_results_summary(&results),
            }
        }

        Commands::MonitorDns { interface } => {
            dns_monitor::print_monitor_header();

            if let Err(e) = dns_monitor::monitor_dns(&conn, interface.as_deref()) {
                eprintln!("Error: DNS monitor failed: {e}");
                eprintln!();
                eprintln!("Common causes:");
                eprintln!("  - Not running as root (try: sudo dtm-agent monitor-dns)");
                eprintln!("  - Not in the 'bpf' group (macOS)");
                eprintln!("  - libpcap not installed");
                std::process::exit(1);
            }
        }
    }
}
