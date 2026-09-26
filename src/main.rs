use auth_spray_watch::{detect, parse_log, Alert, AlertKind, Config};
use chrono::Duration;
use clap::{Parser, ValueEnum};
use serde::Serialize;
use std::io::{self, Read};
use std::process::ExitCode;

/// Detect password-spraying and distributed brute-force activity in authentication logs.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Log file to analyze, or "-" to read from standard input.
    #[arg(short, long, default_value = "auth.log")]
    input: String,

    /// Sliding window length in minutes.
    #[arg(short, long, default_value_t = 15, value_parser = clap::value_parser!(u32).range(1..))]
    window: u32,

    /// Distinct accounts one IP must fail against within the window to be flagged.
    #[arg(short, long, default_value_t = 3, value_parser = clap::value_parser!(u32).range(2..))]
    threshold: u32,

    /// Distinct IPs one account must fail from within the window to be flagged
    /// (defaults to the value of --threshold).
    #[arg(long, value_parser = clap::value_parser!(u32).range(2..))]
    ip_threshold: Option<u32>,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Exit with an error if any line cannot be parsed.
    #[arg(long)]
    strict: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Serialize)]
struct JsonReport<'a> {
    events: usize,
    skipped_lines: usize,
    window_minutes: u32,
    alerts: &'a [Alert],
}

const EXIT_ALERTS: u8 = 1;
const EXIT_ERROR: u8 = 2;

fn read_input(path: &str) -> io::Result<String> {
    if path == "-" {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path)
    }
}

fn print_text(alerts: &[Alert], events: usize, window: u32) {
    println!("Analyzed {events} events with a {window}-minute window.");
    if alerts.is_empty() {
        println!("No suspicious activity found.");
        return;
    }
    println!();

    for alert in alerts {
        let when = format!(
            "{} → {}",
            alert.first_seen.format("%Y-%m-%d %H:%M:%S"),
            alert.last_seen.format("%H:%M:%S")
        );
        let label = format!("{:?}", alert.severity).to_uppercase();
        match alert.kind {
            AlertKind::Compromise => println!(
                "[{label}] possible compromise: {} logged in as {} after spraying",
                alert.subject,
                alert.related.join(", ")
            ),
            AlertKind::Spray => println!(
                "[{label}] password spray from {}: {} failures across {} accounts ({})",
                alert.subject,
                alert.failures,
                alert.related.len(),
                alert.related.join(", ")
            ),
            AlertKind::Distributed => println!(
                "[{label}] distributed attack on '{}': {} failures from {} IPs ({})",
                alert.subject,
                alert.failures,
                alert.related.len(),
                alert.related.join(", ")
            ),
        }
        println!("         {when}");
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let raw = match read_input(&cli.input) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", cli.input);
            return ExitCode::from(EXIT_ERROR);
        }
    };

    let (events, errors) = parse_log(&raw);
    for e in errors.iter().take(10) {
        eprintln!("warning: skipped {e}");
    }
    if errors.len() > 10 {
        eprintln!(
            "warning: {} more malformed lines skipped",
            errors.len() - 10
        );
    }
    if cli.strict && !errors.is_empty() {
        eprintln!("error: {} malformed line(s) in strict mode", errors.len());
        return ExitCode::from(EXIT_ERROR);
    }

    let config = Config {
        window: Duration::minutes(i64::from(cli.window)),
        users_per_ip: cli.threshold as usize,
        ips_per_user: cli.ip_threshold.unwrap_or(cli.threshold) as usize,
    };
    let alerts = detect(&events, &config);

    match cli.format {
        Format::Text => print_text(&alerts, events.len(), cli.window),
        Format::Json => {
            let report = JsonReport {
                events: events.len(),
                skipped_lines: errors.len(),
                window_minutes: cli.window,
                alerts: &alerts,
            };
            match serde_json::to_string_pretty(&report) {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(EXIT_ERROR);
                }
            }
        }
    }

    if alerts.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_ALERTS)
    }
}
