use anyhow::{Context, Result};
use clap::Parser;
use oxideprobe_parser::parse_database;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_SOURCE: &str =
    "https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes";

#[derive(Debug, Parser)]
#[command(
    name = "oxideprobe-parser",
    version,
    about = "Convert Nmap service probes into OxideProbe JSON"
)]
struct Cli {
    /// HTTPS URL or local path to nmap-service-probes.
    #[arg(long, default_value = DEFAULT_SOURCE)]
    source: String,

    /// Destination JSON file.
    #[arg(short, long, default_value = "probes.json")]
    output: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let content = read_source(&cli.source).await?;
    let outcome = parse_database(&content);
    if !outcome.warnings.is_empty() {
        eprintln!(
            "Parser completed with {} warning(s); the first 20 follow:",
            outcome.warnings.len()
        );
        for warning in outcome.warnings.iter().take(20) {
            eprintln!("- {warning}");
        }
    }

    let json = serde_json::to_string_pretty(&outcome.probes)?;
    fs::write(&cli.output, json)
        .with_context(|| format!("failed to write {}", cli.output.display()))?;
    println!(
        "Wrote {} probes to {}.",
        outcome.probes.len(),
        cli.output.display()
    );
    Ok(())
}

async fn read_source(source: &str) -> Result<String> {
    if source.starts_with("https://") {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("OxideProbe/0.2 (+https://github.com/JoaoVSF99/OxideProbe)")
            .build()?;
        return client
            .get(source)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await
            .with_context(|| format!("failed to download {source}"));
    }

    fs::read_to_string(Path::new(source))
        .with_context(|| format!("failed to read local source {source}"))
}
