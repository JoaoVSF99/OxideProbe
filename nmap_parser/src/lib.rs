use oxideprobe_core::{MatchRule, NmapProbe, VersionInfo};

#[derive(Debug, Default)]
pub struct ParseOutcome {
    pub probes: Vec<NmapProbe>,
    pub warnings: Vec<String>,
}

pub fn parse_database(input: &str) -> ParseOutcome {
    let mut outcome = ParseOutcome::default();
    let mut current_probe: Option<NmapProbe> = None;

    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim_end();
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with("Probe ") {
            if let Some(probe) = current_probe.take() {
                outcome.probes.push(probe);
            }
            match parse_probe_line(line) {
                Ok(probe) => current_probe = Some(probe),
                Err(error) => outcome
                    .warnings
                    .push(format!("line {line_number}: {error}")),
            }
            continue;
        }

        let Some(probe) = current_probe.as_mut() else {
            outcome.warnings.push(format!(
                "line {line_number}: directive appeared before the first probe"
            ));
            continue;
        };

        if line.starts_with("match ") || line.starts_with("softmatch ") {
            match parse_match_line(line) {
                Ok((rule, soft)) if soft => probe.softmatches.push(rule),
                Ok((rule, _)) => probe.matches.push(rule),
                Err(error) => outcome
                    .warnings
                    .push(format!("line {line_number}: {error}")),
            }
        } else if let Some(value) = line.strip_prefix("ports ") {
            probe.ports = value.trim().to_string();
        } else if let Some(value) = line.strip_prefix("sslports ") {
            probe.sslports = value.trim().to_string();
        } else if let Some(value) = line.strip_prefix("rarity ") {
            probe.rarity = value.trim().to_string();
        } else if let Some(value) = line.strip_prefix("fallback ") {
            probe.fallback = value.trim().to_string();
        }
    }

    if let Some(probe) = current_probe {
        outcome.probes.push(probe);
    }
    outcome
}

fn parse_probe_line(line: &str) -> Result<NmapProbe, String> {
    let mut fields = line
        .strip_prefix("Probe ")
        .ok_or_else(|| "missing Probe prefix".to_string())?
        .splitn(3, ' ');
    let protocol = fields
        .next()
        .filter(|value| *value == "TCP" || *value == "UDP")
        .ok_or_else(|| "probe protocol must be TCP or UDP".to_string())?;
    let probename = fields
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "missing probe name".to_string())?;
    let quoted = fields
        .next()
        .filter(|value| value.starts_with('q'))
        .ok_or_else(|| "missing q-delimited probe payload".to_string())?;

    let delimiter = quoted
        .chars()
        .nth(1)
        .ok_or_else(|| "missing probe payload delimiter".to_string())?;
    let payload_start = 1 + delimiter.len_utf8();
    let payload_and_suffix = &quoted[payload_start..];
    let payload_end = find_unescaped(payload_and_suffix, delimiter)
        .ok_or_else(|| "unterminated probe payload".to_string())?;
    let probestring = parse_probe_string(&payload_and_suffix[..payload_end])?;

    Ok(NmapProbe {
        protocol: protocol.to_string(),
        probename: probename.to_string(),
        probestring,
        ..NmapProbe::default()
    })
}

fn parse_match_line(line: &str) -> Result<(MatchRule, bool), String> {
    let (content, soft) = if let Some(content) = line.strip_prefix("softmatch ") {
        (content, true)
    } else {
        (
            line.strip_prefix("match ")
                .ok_or_else(|| "missing match prefix".to_string())?,
            false,
        )
    };

    let service_end = content
        .find(" m")
        .ok_or_else(|| "missing m-delimited match expression".to_string())?;
    let service = content[..service_end].trim();
    let matcher = &content[service_end + 2..];
    let delimiter = matcher
        .chars()
        .next()
        .ok_or_else(|| "missing match delimiter".to_string())?;
    let pattern_start = delimiter.len_utf8();
    let pattern_and_suffix = &matcher[pattern_start..];
    let pattern_end = find_unescaped(pattern_and_suffix, delimiter)
        .ok_or_else(|| "unterminated match pattern".to_string())?;
    let pattern = pattern_and_suffix[..pattern_end].to_string();
    let suffix = &pattern_and_suffix[pattern_end + delimiter.len_utf8()..];
    let flag_end = suffix.find(char::is_whitespace).unwrap_or(suffix.len());
    let pattern_flag = suffix[..flag_end].to_string();
    let version_text = suffix[flag_end..].trim_start();

    Ok((
        MatchRule {
            service: service.to_string(),
            pattern,
            pattern_flag,
            versioninfo: parse_version_info(version_text),
        },
        soft,
    ))
}

fn parse_version_info(text: &str) -> VersionInfo {
    VersionInfo {
        vendorproductname: first_field(text, "p/").unwrap_or_default(),
        version: first_field(text, "v/").unwrap_or_default(),
        info: first_field(text, "i/").unwrap_or_default(),
        hostname: first_field(text, "h/").unwrap_or_default(),
        operatingsystem: first_field(text, "o/").unwrap_or_default(),
        devicetype: first_field(text, "d/").unwrap_or_default(),
        cpename: all_fields(text, "cpe:/")
            .into_iter()
            .map(|value| format!("cpe:/{value}"))
            .collect(),
    }
}

fn first_field(text: &str, marker: &str) -> Option<String> {
    all_fields(text, marker).into_iter().next()
}

fn all_fields(text: &str, marker: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut offset = 0;
    while offset < text.len() {
        let Some(relative_start) = text[offset..].find(marker) else {
            break;
        };
        let marker_start = offset + relative_start;
        if marker_start > 0
            && !text[..marker_start]
                .chars()
                .next_back()
                .is_some_and(char::is_whitespace)
        {
            offset = marker_start + marker.len();
            continue;
        }
        let value_start = marker_start + marker.len();
        let Some(relative_end) = find_unescaped(&text[value_start..], '/') else {
            break;
        };
        let value_end = value_start + relative_end;
        fields.push(unescape_delimiter(&text[value_start..value_end], '/'));
        offset = value_end + 1;
    }
    fields
}

fn find_unescaped(text: &str, delimiter: char) -> Option<usize> {
    let mut escaped = false;
    for (index, character) in text.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == delimiter {
            return Some(index);
        }
    }
    None
}

fn unescape_delimiter(text: &str, delimiter: char) -> String {
    text.replace(&format!("\\{delimiter}"), &delimiter.to_string())
}

fn parse_probe_string(value: &str) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            let mut encoded = [0_u8; 4];
            output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
            continue;
        }

        let escaped = chars
            .next()
            .ok_or_else(|| "incomplete escape sequence".to_string())?;
        match escaped {
            'x' => {
                let high = chars
                    .next()
                    .ok_or_else(|| "incomplete hex escape".to_string())?;
                let low = chars
                    .next()
                    .ok_or_else(|| "incomplete hex escape".to_string())?;
                let value = u8::from_str_radix(&format!("{high}{low}"), 16)
                    .map_err(|_| "invalid hex escape".to_string())?;
                output.push(value);
            }
            '0' => output.push(0),
            'a' => output.push(7),
            'b' => output.push(8),
            'f' => output.push(12),
            'n' => output.push(b'\n'),
            'r' => output.push(b'\r'),
            't' => output.push(b'\t'),
            'v' => output.push(11),
            other => {
                let mut encoded = [0_u8; 4];
                output.extend_from_slice(other.encode_utf8(&mut encoded).as_bytes());
            }
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_small_probe_database() {
        let input = r#"
# fixture
Probe TCP NULL q||
ports 21,22
rarity 1
match ssh m|^SSH-([0-9.]+)-([^\r\n]+)| p/OpenSSH/ v/$2/ cpe:/a:openbsd:openssh:$2/
softmatch ftp m|^220.*FTP|i
fallback GenericLines
"#;
        let outcome = parse_database(input);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(outcome.probes.len(), 1);
        let probe = &outcome.probes[0];
        assert_eq!(probe.probename, "NULL");
        assert_eq!(probe.ports, "21,22");
        assert_eq!(probe.matches[0].versioninfo.version, "$2");
        assert_eq!(probe.softmatches[0].pattern_flag, "i");
        assert_eq!(probe.fallback, "GenericLines");
    }

    #[test]
    fn decodes_probe_escapes_and_delimiters() {
        let probe = parse_probe_line(r"Probe TCP Test q|GET / HTTP/1.0\r\n\x00\||").unwrap();
        assert_eq!(probe.probestring, b"GET / HTTP/1.0\r\n\0|");
    }

    #[test]
    fn records_malformed_lines_as_warnings() {
        let outcome = parse_database("Probe TCP Broken q|unterminated");
        assert!(outcome.probes.is_empty());
        assert_eq!(outcome.warnings.len(), 1);
    }
}
