use anyhow::{bail, Context, Result};
use clap::Parser;
use oxideprobe::{run_scan, ScanConfig};
use oxideprobe_core::{parse_ports, NmapProbe};
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(
    name = "oxideprobe",
    version,
    about = "Bounded asynchronous TCP connect scanner for authorized service discovery"
)]
struct Cli {
    /// Single IPv4 or IPv6 target that you are authorized to scan.
    #[arg(short, long)]
    target: IpAddr,

    /// Comma-separated ports and ranges, for example: 22,80,443,8000-8010.
    #[arg(short, long, default_value = "1-1024")]
    ports: String,

    /// Path to the JSON probe database produced by oxideprobe-parser.
    #[arg(long, default_value = "probes.json")]
    probes: PathBuf,

    /// Maximum simultaneous connections.
    #[arg(short, long, default_value_t = 128)]
    concurrency: usize,

    /// TCP connection timeout in milliseconds.
    #[arg(long, default_value_t = 500)]
    timeout_ms: u64,

    /// Banner read/write timeout in milliseconds.
    #[arg(long, default_value_t = 1500)]
    banner_timeout_ms: u64,

    /// Maximum number of service probes sent to each open port.
    #[arg(long, default_value_t = 2)]
    max_probes: usize,

    /// Report open ports without sending service-identification probes.
    #[arg(long)]
    no_service_detection: bool,

    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if !(1..=4096).contains(&cli.concurrency) {
        bail!("--concurrency must be between 1 and 4096");
    }
    if !(1..=32).contains(&cli.max_probes) {
        bail!("--max-probes must be between 1 and 32");
    }

    let ports = parse_ports(&cli.ports).map_err(anyhow::Error::msg)?;
    let service_detection = !cli.no_service_detection;
    let probes = if service_detection {
        let data = fs::read_to_string(&cli.probes)
            .with_context(|| format!("failed to read {}", cli.probes.display()))?;
        serde_json::from_str::<Vec<NmapProbe>>(&data)
            .with_context(|| format!("invalid probe database: {}", cli.probes.display()))?
    } else {
        Vec::new()
    };

    let config = ScanConfig {
        target: cli.target,
        ports,
        connect_timeout: Duration::from_millis(cli.timeout_ms),
        banner_timeout: Duration::from_millis(cli.banner_timeout_ms),
        concurrency: cli.concurrency,
        max_probes: cli.max_probes,
        service_detection,
    };

    let findings = run_scan(&config, &probes).await;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else if findings.is_empty() {
        println!("No open ports found on {}.", cli.target);
    } else {
        for finding in findings {
            let service = finding.service.as_deref().unwrap_or("unknown");
            let details = finding.details.as_deref().unwrap_or("");
            println!(
                "{}:{:<5} {:<5} service={:<12} {}",
                finding.target, finding.port, finding.state, service, details
            );
        }
    }

    Ok(())
}
