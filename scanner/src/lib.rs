use futures::{stream, StreamExt};
use oxideprobe_core::{match_probe_response, port_spec_contains, NmapProbe};
use serde::Serialize;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub target: IpAddr,
    pub ports: Vec<u16>,
    pub connect_timeout: Duration,
    pub banner_timeout: Duration,
    pub concurrency: usize,
    pub max_probes: usize,
    pub service_detection: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Finding {
    pub target: IpAddr,
    pub port: u16,
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

pub async fn run_scan(config: &ScanConfig, probes: &[NmapProbe]) -> Vec<Finding> {
    let open_ports = scan_open_ports(config).await;
    if !config.service_detection {
        return open_ports
            .into_iter()
            .map(|port| open_finding(config.target, port))
            .collect();
    }

    let probes = Arc::new(probes.to_vec());
    let mut findings = stream::iter(open_ports)
        .map(|port| {
            let probes = Arc::clone(&probes);
            async move { identify_service(config, port, &probes).await }
        })
        .buffer_unordered(config.concurrency.max(1))
        .collect::<Vec<_>>()
        .await;
    findings.sort_by_key(|finding| finding.port);
    findings
}

pub async fn scan_open_ports(config: &ScanConfig) -> Vec<u16> {
    let mut ports = stream::iter(config.ports.iter().copied())
        .map(|port| async move {
            let address = SocketAddr::new(config.target, port);
            match timeout(config.connect_timeout, TcpStream::connect(address)).await {
                Ok(Ok(_)) => Some(port),
                _ => None,
            }
        })
        .buffer_unordered(config.concurrency.max(1))
        .filter_map(|port| async move { port })
        .collect::<Vec<_>>()
        .await;
    ports.sort_unstable();
    ports
}

async fn identify_service(config: &ScanConfig, port: u16, probes: &[NmapProbe]) -> Finding {
    let candidates = select_probes(probes, port, config.max_probes);
    if candidates.is_empty() {
        return open_finding(config.target, port);
    }

    let mut last_probe = None;
    let mut received_response = false;
    for probe in candidates {
        last_probe = Some(probe.probename.clone());
        let Some(response) = send_probe(config, port, probe).await else {
            continue;
        };
        if response.is_empty() {
            continue;
        }
        received_response = true;
        if let Some(service_match) = match_probe_response(probe, &response) {
            return Finding {
                target: config.target,
                port,
                state: "open",
                service: Some(service_match.service),
                probe: Some(probe.probename.clone()),
                details: Some(if service_match.soft {
                    format!("softmatch {}", service_match.summary)
                } else {
                    service_match.summary
                }),
            };
        }
    }

    Finding {
        target: config.target,
        port,
        state: "open",
        service: None,
        probe: last_probe,
        details: Some(if received_response {
            "response received, but no supported signature matched".to_string()
        } else {
            "no banner received before timeout".to_string()
        }),
    }
}

async fn send_probe(config: &ScanConfig, port: u16, probe: &NmapProbe) -> Option<Vec<u8>> {
    let address = SocketAddr::new(config.target, port);
    let mut stream = timeout(config.connect_timeout, TcpStream::connect(address))
        .await
        .ok()?
        .ok()?;

    if !probe.probestring.is_empty()
        && timeout(config.banner_timeout, stream.write_all(&probe.probestring))
            .await
            .ok()?
            .is_err()
    {
        return None;
    }

    let mut response = vec![0_u8; 4096];
    match timeout(config.banner_timeout, stream.read(&mut response)).await {
        Ok(Ok(size)) => {
            response.truncate(size);
            Some(response)
        }
        _ => Some(Vec::new()),
    }
}

fn select_probes(probes: &[NmapProbe], port: u16, limit: usize) -> Vec<&NmapProbe> {
    let mut selected = Vec::new();
    let mut names = HashSet::new();

    let preferred_name = match port {
        80 | 8000 | 8080 => Some("GetRequest"),
        443 | 8443 => Some("SSLSessionReq"),
        _ => None,
    };

    if let Some(name) = preferred_name {
        if let Some(probe) = probes
            .iter()
            .find(|probe| probe.protocol == "TCP" && probe.probename == name)
        {
            names.insert(probe.probename.as_str());
            selected.push(probe);
        }
    }

    let mut exact = probes
        .iter()
        .filter(|probe| {
            probe.protocol == "TCP"
                && (port_spec_contains(&probe.ports, port)
                    || port_spec_contains(&probe.sslports, port))
        })
        .collect::<Vec<_>>();
    exact.sort_by_key(|probe| probe.rarity.parse::<u8>().unwrap_or(u8::MAX));
    for probe in exact {
        if names.insert(probe.probename.as_str()) {
            selected.push(probe);
        }
    }

    if let Some(probe) = probes
        .iter()
        .find(|probe| probe.protocol == "TCP" && probe.probename == "NULL")
    {
        if names.insert(probe.probename.as_str()) {
            selected.push(probe);
        }
    }

    selected.truncate(limit);
    selected
}

fn open_finding(target: IpAddr, port: u16) -> Finding {
    Finding {
        target,
        port,
        state: "open",
        service: None,
        probe: None,
        details: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxideprobe_core::{MatchRule, VersionInfo};
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::TcpListener;

    fn config(port: u16) -> ScanConfig {
        ScanConfig {
            target: IpAddr::V4(Ipv4Addr::LOCALHOST),
            ports: vec![port],
            connect_timeout: Duration::from_millis(500),
            banner_timeout: Duration::from_millis(500),
            concurrency: 8,
            max_probes: 2,
            service_detection: true,
        }
    }

    #[tokio::test]
    async fn detects_an_open_local_port() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });

        assert_eq!(scan_open_ports(&config(port)).await, vec![port]);
        accept.await.unwrap();
    }

    #[tokio::test]
    async fn identifies_a_mock_http_service() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 256];
            let _ = stream.read(&mut request).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nServer: oxide-test\r\n\r\n")
                .await
                .unwrap();
        });

        let probe = NmapProbe {
            protocol: "TCP".to_string(),
            probename: "GetRequest".to_string(),
            probestring: b"GET / HTTP/1.0\r\n\r\n".to_vec(),
            ports: port.to_string(),
            matches: vec![MatchRule {
                service: "http".to_string(),
                pattern: "^HTTP/1\\.[01]".to_string(),
                versioninfo: VersionInfo {
                    vendorproductname: "mock-http".to_string(),
                    ..VersionInfo::default()
                },
                ..MatchRule::default()
            }],
            ..NmapProbe::default()
        };

        let finding = identify_service(&config(port), port, &[probe]).await;
        server.await.unwrap();
        assert_eq!(finding.service.as_deref(), Some("http"));
        assert_eq!(finding.probe.as_deref(), Some("GetRequest"));
    }
}
