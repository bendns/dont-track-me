use comfy_table::{Cell, Color, Table};
use dtm_core::db::{AppScanRow, DnsEventRow};
use dtm_core::models::{AuditResult, ProtectionResult, ThreatLevel};
use dtm_core::module_trait::Module;
use dtm_core::scoring::get_score_tier;
use owo_colors::OwoColorize;

fn tier_color(color: &str) -> Color {
    match color {
        "green" => Color::Green,
        "blue" => Color::Blue,
        "yellow" => Color::Yellow,
        "red" => Color::Red,
        "dark_orange" => Color::DarkYellow,
        _ => Color::White,
    }
}

/// Print the module status table.
pub fn print_status_table(modules: &[Box<dyn Module>]) {
    println!();
    println!("  {}", "dont-track-me".bold());
    println!("  {}", "Module Status".dimmed());
    println!();

    let mut table = Table::new();
    table.set_header(vec!["Module", "Display Name", "Available", "Description"]);

    for module in modules {
        let avail = module.is_available();
        let avail_cell = if avail {
            Cell::new("Yes").fg(Color::Green)
        } else {
            Cell::new("No").fg(Color::DarkGrey)
        };
        table.add_row(vec![
            Cell::new(module.name()),
            Cell::new(module.display_name()),
            avail_cell,
            Cell::new(module.description()),
        ]);
    }

    println!("{table}");
    println!();
    let total = modules.len();
    let available = modules.iter().filter(|m| m.is_available()).count();
    println!(
        "  {} modules total, {} available",
        total.to_string().bold(),
        available.to_string().green().bold()
    );
    println!();
}

/// Print a single audit result.
pub fn print_audit_result(result: &AuditResult, format: &str) {
    if format == "json" {
        if let Ok(json) = serde_json::to_string_pretty(result) {
            println!("{json}");
        }
        return;
    }

    let tier = get_score_tier(result.score);
    let score_colored = match tier.color {
        "green" => format!("{}", result.score).green().to_string(),
        "blue" => format!("{}", result.score).blue().to_string(),
        "yellow" => format!("{}", result.score).yellow().to_string(),
        "red" | "dark_orange" => format!("{}", result.score).red().to_string(),
        _ => format!("{}", result.score),
    };

    let finding_count = result.findings.len();
    let count_str = if finding_count == 0 {
        "no issues".dimmed().to_string()
    } else {
        format!(
            "{} finding{}",
            finding_count,
            if finding_count != 1 { "s" } else { "" }
        )
    };

    println!();
    println!(
        "  {} {} {}/100 {}",
        "▸".bold(),
        result.module_name.bold(),
        score_colored,
        format_args!("({}) · {count_str}", tier.label).dimmed(),
    );

    if result.findings.is_empty() {
        return;
    }

    for finding in &result.findings {
        let level_str = match finding.threat_level {
            ThreatLevel::Critical => " CRIT ".on_red().white().bold().to_string(),
            ThreatLevel::High => " HIGH ".on_red().white().to_string(),
            ThreatLevel::Medium => " WARN ".on_yellow().black().to_string(),
            ThreatLevel::Low => " LOW  ".on_blue().white().to_string(),
            ThreatLevel::Info => " INFO ".on_white().black().to_string(),
        };

        println!("    {level_str} {}", finding.title);
        if finding.threat_level != ThreatLevel::Info {
            println!("           {}", finding.description.dimmed());
            println!("           {} {}", "Fix:".blue(), finding.remediation);
        }
    }
}

/// Print a protection result.
pub fn print_protection_result(result: &ProtectionResult) {
    let mode = if result.dry_run {
        "dry run".dimmed().to_string()
    } else {
        "applied".green().bold().to_string()
    };

    println!();
    println!("  {} {} [{}]", "▸".bold(), result.module_name.bold(), mode);

    if !result.actions_taken.is_empty() {
        for action in &result.actions_taken {
            println!("    {} {action}", "+".green());
        }
    }

    if !result.actions_available.is_empty() {
        if !result.actions_taken.is_empty() {
            println!();
        }
        println!("    {}", "Available:".dimmed());
        for action in &result.actions_available {
            println!("    {} {action}", "·".dimmed());
        }
    }
}

/// Print the score breakdown table.
pub fn print_score_table(results: &[AuditResult], overall: f64) {
    let tier = get_score_tier(overall as u32);

    println!();
    println!("  {}", "dont-track-me".bold());
    println!("  {}", "Privacy Score".dimmed());
    println!();

    let mut table = Table::new();
    table.set_header(vec!["Module", "Score", "Rating", "Findings"]);

    // Sort by score ascending (worst first)
    let mut sorted: Vec<&AuditResult> = results.iter().collect();
    sorted.sort_by_key(|r| r.score);

    for result in &sorted {
        let t = get_score_tier(result.score);
        let c = tier_color(t.color);

        table.add_row(vec![
            Cell::new(&result.module_name),
            Cell::new(result.score).fg(c),
            Cell::new(t.label).fg(c),
            Cell::new(result.findings.len()),
        ]);
    }

    println!("{table}");
    println!();

    let total_findings: usize = results.iter().map(|r| r.findings.len()).sum();
    let score_str = format!("{:.1}", overall);
    let colored_score = match tier.color {
        "green" => score_str.green().to_string(),
        "blue" => score_str.blue().to_string(),
        "yellow" => score_str.yellow().to_string(),
        "red" | "dark_orange" => score_str.red().to_string(),
        _ => score_str,
    };
    println!(
        "  Overall: {} — {} ({} findings across {} modules)",
        colored_score,
        tier.label,
        total_findings,
        results.len(),
    );
    println!();
}

/// Print educational content.
pub fn print_educational_content(module_name: &str, content: &str) {
    println!("{}", format!("Educational Content: {module_name}").bold());
    println!();
    // Use termimad for markdown rendering
    termimad::print_text(content);
}

/// Print app scan results.
pub fn print_app_scan_results(results: &[AppScanRow], format: &str) {
    if format == "json" {
        // Simple JSON output
        println!("[");
        for (i, r) in results.iter().enumerate() {
            let comma = if i < results.len() - 1 { "," } else { "" };
            println!(
                "  {{\"app_name\": \"{}\", \"bundle_id\": {:?}, \"tracking_sdks\": {}, \"ats_exceptions\": {}}}{}",
                r.app_name,
                r.bundle_id,
                r.tracking_sdks_json,
                r.ats_exceptions_json.as_deref().unwrap_or("[]"),
                comma,
            );
        }
        println!("]");
        return;
    }

    println!("{}", "App Tracking SDK Analysis".bold());
    println!();

    let mut table = Table::new();
    table.set_header(vec![
        "Application",
        "Bundle ID",
        "Tracking SDKs",
        "ATS Exceptions",
    ]);

    for result in results {
        table.add_row(vec![
            &result.app_name,
            result.bundle_id.as_deref().unwrap_or("-"),
            &result.tracking_sdks_json,
            result.ats_exceptions_json.as_deref().unwrap_or("[]"),
        ]);
    }

    println!("{table}");
}

/// Print DNS events.
pub fn print_dns_events(events: &[DnsEventRow], format: &str) {
    if format == "json" {
        println!("[");
        for (i, e) in events.iter().enumerate() {
            let comma = if i < events.len() - 1 { "," } else { "" };
            println!(
                "  {{\"timestamp\": \"{}\", \"domain\": \"{}\", \"is_tracker\": {}, \"category\": {:?}, \"process\": {:?}}}{}",
                e.timestamp, e.domain, e.is_tracker, e.tracker_category, e.process_name, comma,
            );
        }
        println!("]");
        return;
    }

    println!("{}", "DNS Tracking Events".bold());
    println!();

    let mut table = Table::new();
    table.set_header(vec![
        "Timestamp",
        "Domain",
        "Tracker",
        "Category",
        "Process",
    ]);

    for event in events {
        let tracker_str = if event.is_tracker {
            "Yes".to_string()
        } else {
            "No".to_string()
        };
        table.add_row(vec![
            &event.timestamp,
            &event.domain,
            &tracker_str,
            event.tracker_category.as_deref().unwrap_or("-"),
            event.process_name.as_deref().unwrap_or("-"),
        ]);
    }

    println!("{table}");
}
