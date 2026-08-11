use regex::bytes::RegexBuilder;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    #[serde(default)]
    pub vendorproductname: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub info: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub operatingsystem: String,
    #[serde(default)]
    pub devicetype: String,
    #[serde(default)]
    pub cpename: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq)]
pub struct MatchRule {
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub pattern: String,
    #[serde(default)]
    pub pattern_flag: String,
    #[serde(default)]
    pub versioninfo: VersionInfo,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq)]
pub struct NmapProbe {
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub probename: String,
    #[serde(default, with = "serde_bytes")]
    pub probestring: Vec<u8>,
    #[serde(default)]
    pub ports: String,
    #[serde(default)]
    pub sslports: String,
    #[serde(default)]
    pub rarity: String,
    #[serde(default)]
    pub fallback: String,
    #[serde(default)]
    pub matches: Vec<MatchRule>,
    #[serde(default)]
    pub softmatches: Vec<MatchRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceMatch {
    pub service: String,
    pub summary: String,
    pub soft: bool,
}

pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut ports = BTreeSet::new();

    for item in spec
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        if let Some((start, end)) = item.split_once('-') {
            let start = parse_port(start)?;
            let end = parse_port(end)?;
            if start > end {
                return Err(format!("invalid descending port range: {item}"));
            }
            ports.extend(start..=end);
        } else {
            ports.insert(parse_port(item)?);
        }
    }

    if ports.is_empty() {
        return Err("at least one port is required".to_string());
    }

    Ok(ports.into_iter().collect())
}

fn parse_port(value: &str) -> Result<u16, String> {
    let port = value
        .trim()
        .parse::<u16>()
        .map_err(|_| format!("invalid port: {value}"))?;
    if port == 0 {
        return Err("port 0 is not supported".to_string());
    }
    Ok(port)
}

pub fn port_spec_contains(spec: &str, port: u16) -> bool {
    spec.split(',').map(str::trim).any(|item| {
        if let Some((start, end)) = item.split_once('-') {
            match (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
                (Ok(start), Ok(end)) => (start..=end).contains(&port),
                _ => false,
            }
        } else {
            item.parse::<u16>() == Ok(port)
        }
    })
}

pub fn match_probe_response(probe: &NmapProbe, response: &[u8]) -> Option<ServiceMatch> {
    probe
        .matches
        .iter()
        .find_map(|rule| match_rule(rule, response, false))
        .or_else(|| {
            probe
                .softmatches
                .iter()
                .find_map(|rule| match_rule(rule, response, true))
        })
}

fn match_rule(rule: &MatchRule, response: &[u8], soft: bool) -> Option<ServiceMatch> {
    let regex = RegexBuilder::new(&rule.pattern)
        .case_insensitive(rule.pattern_flag.contains('i'))
        .dot_matches_new_line(rule.pattern_flag.contains('s'))
        .build()
        .ok()?;
    let captures = regex.captures(response)?;

    let render = |template: &str| {
        let mut output = template.to_string();
        for index in 1..captures.len() {
            if let Some(value) = captures.get(index) {
                output = output.replace(
                    &format!("${index}"),
                    &String::from_utf8_lossy(value.as_bytes()),
                );
            }
        }
        output
    };

    let version = &rule.versioninfo;
    let mut fields = vec![format!("service={}", rule.service)];
    push_field(&mut fields, "product", &render(&version.vendorproductname));
    push_field(&mut fields, "version", &render(&version.version));
    push_field(&mut fields, "info", &render(&version.info));
    push_field(&mut fields, "hostname", &render(&version.hostname));
    push_field(&mut fields, "os", &render(&version.operatingsystem));
    push_field(&mut fields, "device", &render(&version.devicetype));
    if !version.cpename.is_empty() {
        fields.push(format!(
            "cpe={}",
            version
                .cpename
                .iter()
                .map(|value| render(value))
                .collect::<Vec<_>>()
                .join(",")
        ));
    }

    Some(ServiceMatch {
        service: rule.service.clone(),
        summary: fields.join(" "),
        soft,
    })
}

fn push_field(fields: &mut Vec<String>, name: &str, value: &str) {
    if !value.is_empty() {
        fields.push(format!("{name}={value}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_sorts_port_lists() {
        assert_eq!(
            parse_ports("443,80,8000-8002,80").unwrap(),
            vec![80, 443, 8000, 8001, 8002]
        );
        assert!(parse_ports("100-99").is_err());
        assert!(parse_ports("0").is_err());
    }

    #[test]
    fn matches_ports_exactly_instead_of_by_substring() {
        assert!(port_spec_contains("80,443,8000-8010", 80));
        assert!(port_spec_contains("80,443,8000-8010", 8005));
        assert!(!port_spec_contains("8080", 80));
    }

    #[test]
    fn renders_regex_captures() {
        let probe = NmapProbe {
            matches: vec![MatchRule {
                service: "ssh".to_string(),
                pattern: r"^SSH-([0-9.]+)-([^\r\n]+)".to_string(),
                versioninfo: VersionInfo {
                    vendorproductname: "OpenSSH".to_string(),
                    version: "$2".to_string(),
                    ..VersionInfo::default()
                },
                ..MatchRule::default()
            }],
            ..NmapProbe::default()
        };

        let result = match_probe_response(&probe, b"SSH-2.0-OpenSSH_9.6\r\n").unwrap();
        assert_eq!(result.service, "ssh");
        assert!(result.summary.contains("version=OpenSSH_9.6"));
        assert!(!result.soft);
    }

    #[test]
    fn unsupported_regex_is_skipped_without_panicking() {
        let probe = NmapProbe {
            matches: vec![MatchRule {
                service: "invalid".to_string(),
                pattern: "(?=unsupported-lookahead)".to_string(),
                ..MatchRule::default()
            }],
            ..NmapProbe::default()
        };
        assert!(match_probe_response(&probe, b"anything").is_none());
    }
}
