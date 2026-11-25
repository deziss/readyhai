use super::checks::junit_output;
use super::docker::read_out;
use super::pinning::warn_unpinned;
use super::sarif_junit::parse_sarif_report;
use super::types::{ToolSpec, gate, out_err, partial, tool_failed};
use crate::checks::Check;
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, Finding, Profile, TargetKind, sha256_hex};
use anyhow::{Result, bail};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Plugin {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) kinds: Vec<String>,
    #[serde(default)]
    pub(crate) profile: String,
    pub(crate) image: String,
    #[serde(default)]
    pub(crate) args: Vec<String>,
    #[serde(default)]
    pub(crate) network: bool,
    #[serde(default)]
    pub(crate) entrypoint: Option<String>,
    #[serde(default)]
    pub(crate) output: String,
    /// Report format: `sarif` | `junit` | `readyhai-json` | `lines` (JSONL recon) |
    /// `nmap` | `nikto-xml` | `testssl` | `sqlmap` | `portline` (scanner natives,
    /// see the reference block in `plugins/README.md`).
    pub(crate) format: String,
    /// Capture the container's stdout instead of reading a file under /out
    /// (stdout-only CLIs: `npm audit`, `clairctl`). When true, `output` is unused.
    #[serde(default)]
    pub(crate) stdout: bool,
    /// Writable `/cache` mount for tools with persistent DBs/feed caches
    /// (trivy-db, NVD feed, nuclei templates). Default false = read-only.
    #[serde(default)]
    pub(crate) cache_rw: bool,
    /// Names     of ReadyHai-process environment variables to pass into the container
    /// (vendor tokens: WPScanAPIToken, SNYK_TOKEN, ...). Values are passed via the
    /// docker client env (`-e NAME`), never through args, so secrets do not appear
    /// in the host process list.
    #[serde(default)]
    pub(crate) env: Vec<String>,
    /// Map host.docker.internal to the host gateway (targets bound to localhost).
    #[serde(default)]
    pub(crate) host_gateway: bool,
    /// Run as this uid:gid instead of the default nobody (65534:65534), e.g. an
    /// image whose tool needs its own home. Must be numeric; validated here.
    #[serde(default)]
    pub(crate) user: Option<String>,
    /// Intrusive: like core checks, only runs under `--profile deep` and a nonprod target.
    #[serde(default)]
    pub(crate) intrusive: bool,
    /// `lines` format: rule id for the generated inventory findings.
    #[serde(default)]
    pub(crate) rule: String,
    /// `lines` format: category (security/supply_chain/...) default security.
    #[serde(default)]
    pub(crate) category: String,
    /// `lines` format: severity of generated findings, default info.
    #[serde(default)]
    pub(crate) severity: String,
    /// `lines` format: title prefix, e.g. "Subdomain" -> "Subdomain: a.example.com".
    #[serde(default)]
    pub(crate) title_prefix: String,
}

/// First non-empty string under any of the recon-tool keys, searched one level
/// into `request`/`data` (katana nests under request.url; ferox uses url_full).
fn pick_url_key(v: &serde_json::Value) -> Option<&str> {
    const KEYS: [&str; 8] = [
        "host", "url", "url_full", "input", "endpoint", "name", "value", "path",
    ];
    for k in KEYS {
        if let Some(s) = v.get(k).and_then(|x| x.as_str())
            && !s.is_empty()
        {
            return Some(s);
        }
    }
    ["request", "data"]
        .iter()
        .find_map(|o| v.get(*o).and_then(pick_url_key))
}

/// Turn one text line into an inventory finding. Accepts bare hosts/URLs and
/// JSON object lines ({"host": "..."} / {"url": "..."} / {"input": "..."});
/// anything else contributes the raw line. Recon tools (subfinder/httpx/katana)
/// emit exactly these shapes, so no jq wrapper is needed in their images.
fn line_finding(check: &str, p: &Plugin, line: &str) -> Option<Finding> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let value = if line.starts_with('{') {
        serde_json::from_str::<serde_json::Value>(line)
            .ok()
            .and_then(|v| pick_url_key(&v).map(str::to_string))
            .unwrap_or_else(|| line.to_string())
    } else {
        line.to_string()
    };
    if value.is_empty() {
        return None;
    }
    let sev = match p.severity.as_str() {
        "critical" => crate::model::Severity::Critical,
        "high" => crate::model::Severity::High,
        "medium" => crate::model::Severity::Medium,
        "low" => crate::model::Severity::Low,
        _ => crate::model::Severity::Info,
    };
    let cat = match p.category.as_str() {
        "supply_chain" => crate::model::Category::SupplyChain,
        "reliability" => crate::model::Category::Reliability,
        "observability" => crate::model::Category::Observability,
        "quality" => crate::model::Category::Quality,
        "operability" => crate::model::Category::Operability,
        "performance" => crate::model::Category::Performance,
        _ => crate::model::Category::Security,
    };
    let rule = if p.rule.is_empty() {
        format!("recon.{}.line", p.id)
    } else {
        p.rule.clone()
    };
    let title = if p.title_prefix.is_empty() {
        value.clone()
    } else {
        format!("{}: {}", p.title_prefix, value)
    };
    Some(
        Finding::new(check, &rule, cat, sev, title, value)
            .detail("inventory from plugin output (lines format)"),
    )
}

fn parse_lines(check: &str, p: &Plugin, text: &str) -> Vec<Finding> {
    let mut seen = std::collections::BTreeSet::new();
    text.lines()
        .filter_map(|l| line_finding(check, p, l))
        .filter(|f| seen.insert(f.location.clone()))
        .collect()
}

// ------------------------------------------------- scanner-native XML/JSON formats
//
// Hand-rolled XML like `parse_junit`: no XML crate is a dependency of this binary and
// adding one is not worth it for three flat report shapes.

/// Attribute pairs of one XML start tag (`port protocol="tcp" portid="22"`), with the
/// usual entities unescaped. Bare names map to an empty value.
fn xml_attrs(tag: &str) -> Vec<(String, String)> {
    let cs: Vec<char> = tag.chars().collect();
    let name_char = |c: char| c.is_alphanumeric() || matches!(c, '_' | ':' | '-' | '.');
    let mut out = Vec::new();
    let mut i = 0;
    while i < cs.len() {
        while i < cs.len() && (cs[i].is_whitespace() || cs[i] == '/') {
            i += 1;
        }
        let n0 = i;
        while i < cs.len() && name_char(cs[i]) {
            i += 1;
        }
        if i == n0 {
            break;
        }
        let name: String = cs[n0..i].iter().collect();
        while i < cs.len() && cs[i].is_whitespace() {
            i += 1;
        }
        if i >= cs.len() || cs[i] != '=' {
            out.push((name, String::new()));
            continue;
        }
        i += 1;
        while i < cs.len() && cs[i].is_whitespace() {
            i += 1;
        }
        let Some(q) = cs.get(i).copied().filter(|c| *c == '"' || *c == '\'') else {
            out.push((name, String::new()));
            continue; // unquoted values do not occur in nmap/nikto output
        };
        i += 1;
        let v0 = i;
        while i < cs.len() && cs[i] != q {
            i += 1;
        }
        out.push((name, xml_unescape(&cs[v0..i].iter().collect::<String>())));
        if i < cs.len() {
            i += 1;
        }
    }
    out
}

fn xml_attr(tag: &str, name: &str) -> String {
    xml_attrs(tag)
        .into_iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v)
        .unwrap_or_default()
}

fn xml_unescape(v: &str) -> String {
    v.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

/// `(attrs, inner)` for every `<name ...>` element, self-closed ones with empty inner.
/// Non-greedy and non-nesting, like `parse_junit`'s element scan: enough for the flat
/// reports these tools emit, wrong for arbitrary XML (by design, and never recursive).
/// The closing tag must end exactly at the name, so `</host>` never swallows `</hostname>`.
fn xml_elements(xml: &str, name: &str) -> Vec<(String, String)> {
    let re = regex::Regex::new(&format!(
        r"(?s)<{name}\b([^>]*?)(?:/>|>(.*?)</{name}(?:\s[^>]*)?>)"
    ))
    .unwrap();
    re.captures_iter(xml)
        .map(|c| {
            (
                c.get(1).map(|m| m.as_str()).unwrap_or("").to_string(),
                c.get(2).map(|m| m.as_str()).unwrap_or("").to_string(),
            )
        })
        .collect()
}

/// Text content of the first `<name>` element, CDATA unwrapped and trimmed.
fn xml_text(xml: &str, name: &str) -> String {
    let body = xml_elements(xml, name)
        .into_iter()
        .next()
        .map(|(_, b)| b)
        .unwrap_or_default();
    let body = body.trim();
    let inner = body
        .strip_prefix("<![CDATA[")
        .and_then(|b| b.strip_suffix("]]>"))
        .unwrap_or(body);
    xml_unescape(inner.trim()).trim().to_string()
}

/// Ports whose exposure is worth a step up from `low`: the classic cleartext/DB/admin
/// surface. Kept deliberately short — nmap version probes are noisy, and `high` is
/// intentionally unused so a port scan can never out-rank a real vulnerability.
const RISKY_PORTS: &[u16] = &[
    21, 23, 25, 110, 135, 136, 137, 138, 139, 445, 1433, 2049, 3306, 3389, 5432, 5900, 5901, 5902,
    5903, 5904, 5905, 5906, 5907, 5908, 5909, 5910, 6379, 27017, 9200,
];

fn risky_port(p: u16) -> bool {
    RISKY_PORTS.contains(&p)
}

/// nmap `-oX`: one finding per open port of every `<host status="up">`. Hosts that are
/// down (they carry `<hostport>`/`<status state="down">` and no `<ports>`) are skipped,
/// as are `<times>`/`<extrareasons>`, which carry no per-finding signal.
pub(crate) fn parse_nmap(check: &str, xml: &str) -> Vec<Finding> {
    let mut out = vec![];
    for (_, host_body) in xml_elements(xml, "host") {
        // `<status state="up"/>` and `<hostname name=".." type="PTR"/>` are attribute-only
        // elements; a down host carries `<hostport>` instead of `<ports>`.
        let status = xml_elements(&host_body, "status")
            .into_iter()
            .next()
            .map(|(a, _)| xml_attr(&a, "state"))
            .unwrap_or_default();
        let up = (status.is_empty() || status == "up") && !host_body.contains("<hostport");
        if !up {
            continue;
        }
        let addr = xml_elements(&host_body, "address")
            .into_iter()
            .find(|(a, _)| {
                let t = xml_attr(a, "addrtype");
                t != "mac"
            })
            .map(|(a, _)| xml_attr(&a, "addr"))
            .unwrap_or_default();
        let ptr = xml_elements(&host_body, "hostname")
            .into_iter()
            .next()
            .map(|(a, _)| xml_attr(&a, "name"))
            .unwrap_or_default();
        let host = if ptr.is_empty() {
            addr.clone()
        } else if addr.is_empty() {
            ptr.clone()
        } else {
            format!("{ptr} ({addr})")
        };
        let host_key = if addr.is_empty() { &host } else { &addr };
        for (port_attrs, port_body) in xml_elements(&host_body, "port") {
            let proto = xml_attr(&port_attrs, "protocol");
            let id_s = xml_attr(&port_attrs, "portid");
            let Ok(num) = id_s.parse::<u16>() else {
                continue;
            };
            let state_attrs = xml_elements(&port_body, "state")
                .into_iter()
                .next()
                .map(|(a, _)| a)
                .unwrap_or_default();
            let state = xml_attr(&state_attrs, "state");
            if state != "open" {
                continue; // filtered/closed/updown are inventory noise, not findings
            }
            let svc_attrs = xml_elements(&port_body, "service")
                .into_iter()
                .next()
                .map(|(a, _)| a)
                .unwrap_or_default();
            let service = xml_attr(&svc_attrs, "name");
            let version = xml_attr(&svc_attrs, "version");
            let product = xml_attr(&svc_attrs, "product");
            let sev = if risky_port(num) {
                crate::model::Severity::Medium
            } else {
                crate::model::Severity::Low
            };
            let label = if service.is_empty() {
                format!("{proto}/{num}")
            } else {
                format!("{proto}/{num} {service}")
            };
            let state_reason = xml_attr(&state_attrs, "reason");
            let detail = {
                let mut d = vec![format!("state=open ({state_reason})")];
                if !product.is_empty() {
                    d.push(product.clone());
                }
                if !version.is_empty() {
                    d.push(version.clone());
                }
                let ex = xml_attr(&svc_attrs, "extrainfo");
                if !ex.is_empty() {
                    d.push(ex);
                }
                d
            };
            out.push(
                Finding::new(
                    check,
                    "nmap-open-port",
                    Category::Security,
                    sev,
                    format!("Open port {label} on {host}"),
                    format!("{host_key}:{num}"),
                )
                .fp_key(format!("{host_key}|{proto}|{num}"))
                .detail({
                    let mut d = vec![format!("host={host_key}")];
                    d.extend(detail);
                    d.join(" | ")
                }),
            );
        }
    }
    out
}

/// Nikto `-Format xml`: `<item id>` with `<description>`/`<uri>` and optional
/// `<osvdb>`/`<cve>`/`<edbid>` children. An item with a known vulnerability id gets
/// `medium` (there is a published advisory to patch against); the rest is `low` info.
pub(crate) fn parse_nikto(check: &str, xml: &str) -> Vec<Finding> {
    let mut out = vec![];
    for (attrs, body) in xml_elements(xml, "item") {
        let id = xml_attr(&attrs, "id");
        let description = xml_text(&body, "description");
        let uri = xml_text(&body, "uri");
        if description.is_empty() {
            continue; // `<statistics>` and header blocks carry no `<description>`
        }
        let osvdb = xml_text(&body, "osvdb");
        let cve = xml_text(&body, "cve");
        let edb = xml_text(&body, "edbid");
        let known = !osvdb.is_empty()
            || !cve.is_empty()
            || !edb.is_empty()
            || description.contains("CVE-")
            || body.to_ascii_lowercase().contains("<cve");
        let sev = if known {
            crate::model::Severity::Medium
        } else {
            crate::model::Severity::Low
        };
        let mut ids: Vec<String> = vec![];
        for tag in [("CVE-", &cve), ("OSVDB-", &osvdb), ("EDB-ID-", &edb)] {
            if !tag.1.is_empty() {
                ids.push(format!("{}{}", tag.0, tag.1));
            }
        }
        let location = if uri.is_empty() {
            id.clone()
        } else {
            uri.clone()
        };
        let mut f = Finding::new(
            check,
            "nikto-item",
            Category::Security,
            sev,
            super::parsers::first_line(&description, 200),
            location,
        )
        .fp_key(format!(
            "{}|{}",
            if uri.is_empty() { "?" } else { &uri },
            &sha256_hex(description.as_bytes())[..8]
        ));
        if !ids.is_empty() {
            f = f.ids(ids);
        }
        out.push(f.detail(format!(
            "nikto item id={}",
            if id.is_empty() { "-" } else { &id }
        )));
    }
    out
}

/// Top-level `{...}` objects in `text`, whether they arrive as one pretty-printed JSON
/// array (testssl `--jsonfile`, sqlmap's report), newline-delimited objects (the
/// `lines` shape) or concatenated objects. Brace depth alone is tracked — string
/// contents and escapes never move it — and an unparseable chunk is dropped rather
/// than failing the report, which is how a truncated tool run still yields findings.
pub(crate) fn json_objects(text: &str) -> Vec<serde_json::Value> {
    let mut out = vec![];
    let cs: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < cs.len() {
        if cs[i] != '{' {
            i += 1;
            continue;
        }
        let start = i;
        let mut depth = 0usize;
        let mut in_str = false;
        let mut escaped = false;
        while i < cs.len() {
            let c = cs[i];
            if in_str {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_str = false;
                }
            } else if c == '"' {
                in_str = true;
            } else if c == '{' {
                depth += 1;
            } else if c == '}' {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            i += 1;
        }
        if depth != 0 {
            break; // truncated tail: keep what parsed so far
        }
        let chunk: String = cs[start..=i].iter().collect();
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&chunk) {
            out.push(v);
        }
        i += 1;
    }
    out
}

/// testssl.sh `--jsonfile`: `{"section","id","severity","finding"}` per line. `OK`
/// and `INFO` are the pass/noise lanes and are skipped, so a clean host yields zero
/// findings. Severities cap at `high` (testssl's `CRITICAL` is a cipher-suite label,
/// not an exploitable-vuln grade).
pub(crate) fn parse_testssl(check: &str, text: &str) -> Result<Vec<Finding>> {
    let objs = json_objects(text);
    if objs.is_empty() {
        bail!("testssl output has no JSON objects");
    }
    let mut out = vec![];
    for o in &objs {
        let severity = super::parsers::s(o, "severity");
        let finding = super::parsers::first_line(super::parsers::s(o, "finding"), 300);
        let section = super::parsers::s(o, "section");
        let id = o.get("id").map(|x| match x {
            serde_json::Value::String(t) => t.clone(),
            other => other.to_string(),
        });
        let sev = match severity.trim().to_ascii_uppercase().as_str() {
            "" | "OK" | "INFO" => continue,
            "LOW" => crate::model::Severity::Low,
            "MEDIUM" => crate::model::Severity::Medium,
            "HIGH" | "CRITICAL" => crate::model::Severity::High,
            _ => crate::model::Severity::Medium,
        };
        // Port-probe bookkeeping arrives without a finding; keep it out of the report.
        if finding.is_empty() || (finding == "-" && section.starts_with("Testing on ports")) {
            continue;
        }
        let id_s = match &id {
            Some(v) if !v.is_empty() => v.clone(),
            _ => super::parsers::first_line(section, 40).replace(' ', "_"),
        };
        let host = super::parsers::s(o, "host");
        let port = super::parsers::s(o, "port");
        out.push(
            Finding::new(
                check,
                &format!("testssl.{id_s}"),
                Category::Security,
                sev,
                if section.is_empty() {
                    finding.clone()
                } else {
                    format!("{section}: {}", super::parsers::first_line(&finding, 160))
                },
                if port.is_empty() {
                    host.to_string()
                } else if host.is_empty() {
                    port.to_string()
                } else {
                    format!("{host}:{port}")
                },
            )
            .fp_key(format!("{}|{}", id_s, super::parsers::s(o, "finding")))
            .detail(super::parsers::first_line(
                super::parsers::s(o, "finding"),
                300,
            )),
        );
    }
    Ok(out)
}

/// Parameter names and technique names named by sqlmap's prose (`parameter 'id'`,
/// `Type: boolean-based blind`, `'Boolean-based blind' injectable`).
fn sqlmap_names(text: &str) -> (Vec<String>, Vec<String>) {
    let mut params = vec![];
    let mut techs = vec![];
    let push = |v: &mut Vec<String>, s: &str| {
        let s = s
            .trim()
            .trim_matches(['\'', '"', ',', '.', '\\'])
            .to_string();
        if !s.is_empty() && !v.contains(&s) {
            v.push(s);
        }
    };
    let param_re = regex::Regex::new(r"(?i)parameter\s+'([^']+)'").unwrap();
    let type_re = regex::Regex::new(r"(?im)(?:^-|\s)Type:\s*([A-Za-z][^\n\r]*)").unwrap();
    let tech_re = regex::Regex::new(r"'([^']{3,60})'\s+(?:is\s+)?injectable").unwrap();
    for c in param_re.captures_iter(text) {
        push(&mut params, &c[1]);
    }
    for re in [&type_re, &tech_re] {
        for c in re.captures_iter(text) {
            for part in c[1].split('+') {
                push(&mut techs, part);
            }
        }
    }
    (params, techs)
}

/// Is this sqlmap message/value an actual injection rather than a probe note? sqlmap's
/// JSON report has no single stable field across versions, so the yes-signals are the
/// ones its own text commits to: a non-empty injection type, or wording that says the
/// parameter *is* vulnerable/injectable.
fn sqlmap_injectable(v: &serde_json::Value) -> bool {
    let it = v.get("injection_type").or(v.get("injectionType"));
    match it {
        Some(serde_json::Value::String(t)) if !t.trim().is_empty() => return true,
        Some(serde_json::Value::Array(a)) if !a.is_empty() => return true,
        _ => {}
    }
    let mut text = String::new();
    for k in ["message", "Message", "note", "info", "description"] {
        if let Some(t) = v.get(k).and_then(|x| x.as_str()) {
            text.push_str(t);
            text.push('\n');
        }
    }
    let t = text.to_ascii_lowercase();
    // sqlmap's own negatives ("does not seem to be injectable", "not vulnerable",
    // "might not be injectable") share the vocabulary of the positives, so veto on
    // a `not` within the same sentence as the yes-word.
    static NEG: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let neg = NEG.get_or_init(|| {
        regex::Regex::new(r"\b(?:not|never)[\s\S]{0,40}(?:injectab|vulnerab|exploit)").unwrap()
    });
    if neg.is_match(&t) || t.contains("no injection") {
        return false;
    }
    t.contains("is vulnerable") || t.contains("injectable") || t.contains("is '")
}

/// sqlmap's JSON report (`--output-format=JSON`): injectable url/parameter pairs only,
/// each `high` — a confirmed injection is the loudest thing a scanner in this set can say.
pub(crate) fn parse_sqlmap(check: &str, text: &str) -> Result<Vec<Finding>> {
    let objs = json_objects(text);
    if objs.is_empty() {
        bail!("sqlmap output has no JSON objects");
    }
    // One finding per (url, parameter): sqlmap repeats a payload line per technique.
    let mut groups: std::collections::BTreeMap<(String, String), (Vec<String>, String)> =
        std::collections::BTreeMap::new();
    for o in &objs {
        let url = ["url", "URI", "uri"]
            .iter()
            .find_map(|k| o.get(*k).and_then(|x| x.as_str()))
            .unwrap_or("")
            .to_string();
        // Shape A: sqlmap's own report — `{url, messages[..], values[{parameter,type,payload}]}`.
        if o.get("messages").is_some() || o.get("values").is_some() {
            if let Some(msgs) = o.get("messages").and_then(|x| x.as_array()) {
                for m in msgs {
                    let body = m.get("message").and_then(|x| x.as_str()).unwrap_or("");
                    if !sqlmap_injectable(m) {
                        continue;
                    }
                    let (params, techs) = sqlmap_names(body);
                    let param = params.first().cloned().unwrap_or_default();
                    let e = groups
                        .entry((url.clone(), param))
                        .or_insert_with(|| (Vec::new(), super::parsers::first_line(body, 300)));
                    for t in techs {
                        if !e.0.contains(&t) {
                            e.0.push(t);
                        }
                    }
                }
            }
            if let Some(vals) = o.get("values").and_then(|x| x.as_array()) {
                for v in vals {
                    let typ = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
                    if typ.is_empty() && !sqlmap_injectable(v) {
                        continue;
                    }
                    let param = v
                        .get("parameter")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    let payload = v.get("payload").and_then(|x| x.as_str()).unwrap_or(typ);
                    let e = groups
                        .entry((url.clone(), param))
                        .or_insert_with(|| (Vec::new(), super::parsers::first_line(payload, 300)));
                    if !typ.is_empty() && !e.0.iter().any(|t| t == typ) {
                        e.0.push(typ.to_string());
                    }
                }
            }
            continue;
        }
        // Shape B: a map keyed by url or parameter (`{"http://x/?a=1": {…}}`).
        for (key, v) in o.as_object().into_iter().flatten() {
            if !v.is_object() || !sqlmap_injectable(v) {
                continue;
            }
            let blob = v.to_string();
            let (params, mut techs) = sqlmap_names(&blob);
            let key_url = key.contains("://");
            let own_url = ["url", "uri", "URI"]
                .iter()
                .find_map(|k| v.get(*k).and_then(|x| x.as_str()))
                .map(str::to_string)
                .unwrap_or_else(|| if key_url { key.clone() } else { url.clone() });
            let own_param = if key_url {
                params.first().cloned()
            } else {
                Some(key.clone())
            };
            // sqlmap's per-parameter report names the technique in `type`.
            if let Some(t) = v.get("type").and_then(|x| x.as_str()) {
                let trimmed = t.trim().trim_matches(['\'', '"', '.', '\\']);
                let dup = trimmed.is_empty()
                    || trimmed.eq_ignore_ascii_case("null")
                    || techs.iter().any(|x| x.eq_ignore_ascii_case(trimmed));
                if !dup {
                    techs.push(trimmed.to_string());
                }
            }
            let e = groups
                .entry((own_url.clone(), own_param.clone().unwrap_or_default()))
                .or_insert((Vec::new(), String::new()));
            techs.retain(|t| !e.0.contains(t));
            e.0.extend(techs);
            if e.1.is_empty() {
                e.1 = super::parsers::first_line(&blob, 300);
            }
        }
    }
    let mut out = vec![];
    for ((url, param), (techs, detail)) in groups {
        let host = host_of(&url);
        let title = match (param.is_empty(), techs.is_empty()) {
            (true, true) => format!("SQL injection at {url}"),
            (true, false) => format!("SQL injection at {url} ({})", techs.join(", ")),
            (false, true) => format!("SQL injection in parameter '{param}'"),
            (false, false) => {
                format!(
                    "SQL injection in parameter '{param}' ({})",
                    techs.join(", ")
                )
            }
        };
        let mut f = Finding::new(
            check,
            "sqlmap-injection",
            Category::Security,
            crate::model::Severity::High,
            title,
            if url.is_empty() { host } else { url.clone() },
        )
        .fp_key(format!(
            "{}|{}",
            if url.is_empty() { "?" } else { &url },
            param
        ));
        if !detail.is_empty() {
            f = f.detail(detail);
        }
        out.push(f);
    }
    Ok(out)
}

/// rustscan-style stdout (`127.0.0.1:8080`, `Open (TCP) 10.0.0.1:22 Open`): every
/// `host:port` token, deduped on `(host, port)`. Lines with no such token are ignored,
/// so banners and progress bars cost nothing — and, like `lines`, an empty report with
/// exit 0 is a clean scan rather than broken output.
pub(crate) fn parse_portline(check: &str, text: &str) -> Vec<Finding> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = vec![];
    let host_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':');
    for line in text.lines() {
        for tok in line.split_whitespace() {
            let tok = tok.trim_matches(|c: char| {
                matches!(
                    c,
                    '<' | '>'
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | ','
                        | ';'
                        | '"'
                        | '\''
                        | '*'
                        | '►'
                        | '•'
                        | '|'
                )
            });
            let Some((host, port)) = tok.rsplit_once(':') else {
                continue;
            };
            if host.is_empty() || host.contains(':') || !tok.starts_with(host) {
                continue; // IPv6 forms and stray timestamps are not rustscan pairs
            }
            let Ok(num) = port.parse::<u16>() else {
                continue;
            };
            if num == 0 || !host.contains('.') || !host.chars().all(host_char) {
                continue; // `12:30` timestamps lack the dot an ip/hostname always has
            }
            if !seen.insert((host.to_string(), num)) {
                continue;
            }
            out.push(
                Finding::new(
                    check,
                    "rustscan-open-port",
                    Category::Security,
                    crate::model::Severity::Low,
                    format!("Open port {host}:{num}"),
                    format!("{host}:{num}"),
                )
                .fp_key(format!("{host}|{num}"))
                .detail("open port from plugin output (portline format)"),
            );
        }
    }
    out
}

fn valid_user(u: &str) -> bool {
    let (uid, gid) = match u.split_once(':') {
        Some((a, b)) => (a, Some(b)),
        None => (u, None),
    };
    let num = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    num(uid) && gid.is_none_or(num)
}

/// Bare hostname from a URL/target string (no scheme/port/path).
fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    host.rsplit_once('@')
        .map_or(host, |(_, h)| h)
        .split(':')
        .next()
        .unwrap_or("")
        .to_string()
}

/// Non-zero exit with parseable output = a truncated run, not a clean one: the tool stopped
/// midway, so whatever it enumerated is partial coverage. The note becomes `CheckStatus::Partial`,
/// which the gate can warn or fail on but can never turn into PASS. The `lines` inventory format
/// is exempt — those capture stdout, and several recon tools exit non-zero on partial input while
/// their inventory is still valid.
pub(crate) fn exit_incompleteness(
    format: &str,
    exit_code: i32,
    stderr_tail: &str,
) -> Option<String> {
    if exit_code == 0 || format == "lines" {
        return None;
    }
    Some(format!(
        "tool exited {exit_code}: findings may be incomplete ({})",
        super::parsers::first_line(stderr_tail.trim(), 160)
    ))
}

pub(crate) fn run_plugin(ctx: &Ctx, p: &Plugin) -> Result<CheckOutput> {
    if let Some(o) = gate(ctx) {
        return Ok(o);
    }
    let check = format!("plugin.{}", p.id);
    // Rewrite loopback targets to host.docker.internal so containers can reach a
    // localhost dev server (same rule the core web checks use), and remember to
    // request the host-gateway mapping either way.
    let (c_url, needs_gw) = ctx
        .target
        .url
        .as_deref()
        .map(crate::web::client::container_url)
        .unwrap_or_default();
    let url = c_url.as_str();
    let args: Vec<String> = p
        .args
        .iter()
        .map(|a| {
            a.replace("{src}", "/src")
                .replace("{out}", "/out")
                .replace("{url}", url)
                .replace("{domain}", &host_of(url))
                .replace("{image_tar}", "/src/image.tar")
        })
        .collect();
    let mut spec = ToolSpec::new(&format!("plugin-{}", p.id), &[]);
    spec.args = args;
    spec.image = Some(p.image.clone());
    spec.network = p.network;
    spec.cache_rw = p.cache_rw;
    spec.host_gateway = p.host_gateway || needs_gw;
    spec.entrypoint = p.entrypoint.clone();
    // Pass env by NAME; the docker client resolves values from our own environment
    // (same pattern as ToolSpec.env), so secrets never land in the host cmdline.
    spec.env = p
        .env
        .iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| (k.clone(), v)))
        .collect();
    let missing_env: Vec<&String> = p.env.iter().filter(|k| std::env::var(k).is_err()).collect();
    if let Some(u) = &p.user {
        if !valid_user(u) {
            bail!(
                "plugin {}: invalid user {u:?} (must be numeric uid[:gid])",
                p.id
            );
        }
        spec.user = Some(u.clone());
    }
    if !p.image.contains("@sha256:") {
        warn_unpinned(&format!("plugin:{}", p.id), &p.image);
    }
    let r = ctx.docker.run(ctx, &spec)?;
    let skipped_env = if missing_env.is_empty() {
        Vec::new()
    } else {
        vec![format!(
            "env not set, plugin may under-check: {}",
            missing_env
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )]
    };
    let txt = if p.stdout {
        if r.stdout_truncated {
            bail!(
                "plugin {}: stdout exceeded the capture cap; write findings to a file under /out instead",
                p.id
            );
        }
        r.stdout.clone()
    } else {
        let name = p.output.strip_prefix("/out/").unwrap_or(&p.output);
        read_out(ctx, name).map_err(|e| out_err(e, || tool_failed(&p.id, &r)))?
    };
    // An empty file for sarif/junit/readyhai-json is broken output, but for the
    // line-oriented recon formats (`lines`, `portline`) empty simply means "the tool
    // found nothing" (e.g. subfinder on an IP literal has no passive results, or
    // rustscan saw no open ports) — as long as the tool itself exited successfully.
    if txt.trim().is_empty()
        && !matches!(
            (p.format.as_str(), p.stdout, r.exit_code),
            ("lines", true, 0) | ("portline", true, 0)
        )
    {
        return Err(tool_failed(&p.id, &r));
    }
    let mut sarif_notes = Vec::new();
    let mut findings = match p.format.as_str() {
        "sarif" => {
            let (f, notes) = parse_sarif_report(&txt, &check)?;
            sarif_notes = notes;
            f
        }
        "junit" => match junit_output(&txt, if p.stdout { r.exit_code } else { 0 }) {
            CheckOutput {
                status: Some(st), ..
            } => return Ok(CheckOutput::status(st)),
            o => o.findings,
        },
        "readyhai-json" => serde_json::from_str::<Vec<Finding>>(&txt)?,
        "lines" => parse_lines(&check, p, &txt),
        "nmap" => parse_nmap(&check, &txt),
        "nikto-xml" => parse_nikto(&check, &txt),
        "testssl" => parse_testssl(&check, &txt)?,
        "sqlmap" => parse_sqlmap(&check, &txt)?,
        "portline" => parse_portline(&check, &txt),
        f => bail!("plugin {}: unknown format {f}", p.id),
    };
    for f in &mut findings {
        f.check = check.clone();
    }
    let mut notes = skipped_env;
    notes.extend(sarif_notes);
    notes.extend(exit_incompleteness(&p.format, r.exit_code, &r.stderr_tail));
    if !p.image.contains("@sha256:") {
        notes.push("plugin image unpinned".to_string());
    }
    Ok(partial(notes, findings))
}

/// Whether one candidate plugin directory loaded under the loader rules.
#[derive(Debug, Clone)]
pub enum PluginLoad {
    Loaded,
    Skipped,
}

/// One candidate plugin (a directory holding a readable `plugin.toml`) and why it
/// loaded or was skipped. Produced by [`plugin_diags`]; same rules as [`plugin_checks`].
#[derive(Debug, Clone)]
pub struct PluginDiag {
    /// The pack directory the manifest was read from (`<dir>/<pack>`).
    pub dir: String,
    /// Declared plugin id; the directory name when the manifest could not be parsed.
    pub id: String,
    pub status: PluginLoad,
    /// Rejection reason; `None` when loaded.
    pub reason: Option<String>,
    /// Image the manifest declares (empty when the manifest could not be parsed).
    pub image: String,
}

/// The single source of truth for rejecting malformed plugins — at load, not at
/// scan time (the loader is best-effort). `None` means the manifest is valid.
fn reject_reason(p: &Plugin) -> Option<String> {
    if !p.stdout && p.output.is_empty() {
        return Some("file format with no output path (empty `output` and `stdout=false`)".into());
    }
    if let Some(u) = p.user.as_deref().filter(|u| !valid_user(u)) {
        return Some(format!("invalid user {u:?} (must be numeric uid[:gid])"));
    }
    if let Some(k) = p
        .env
        .iter()
        .find(|k| k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
    {
        return Some(format!("invalid env name {k:?}"));
    }
    if p.kinds
        .iter()
        .all(|k| !matches!(k.as_str(), "repo" | "image" | "web"))
    {
        return Some("no valid kinds (repo/image/web)".into());
    }
    None
}

/// Pack subdirectories of `dir`, sorted: the loader reads one level, `<dir>/<pack>/plugin.toml`.
fn pack_dirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut v: Vec<PathBuf> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    v.sort();
    v
}

fn skip_diag(dir: &str, id: String, reason: String, image: String) -> PluginDiag {
    PluginDiag {
        dir: dir.to_string(),
        id,
        status: PluginLoad::Skipped,
        reason: Some(reason),
        image,
    }
}

/// Reads and validates one pack directory: `Ok(Some)` loads; `Err(diag)` is a
/// candidate that was rejected; `Ok(None)` has no readable `plugin.toml`, so the
/// directory is inert (a pack root like `official/`), not a candidate.
fn load_plugin(dir: &Path) -> Result<Option<Plugin>, PluginDiag> {
    let dir_s = dir.display().to_string();
    let name = || {
        dir.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string()
    };
    let Ok(text) = std::fs::read_to_string(dir.join("plugin.toml")) else {
        return Ok(None);
    };
    let p = match toml::from_str::<Plugin>(&text) {
        Ok(p) => p,
        Err(e) => {
            return Err(skip_diag(
                &dir_s,
                name(),
                format!("plugin.toml parse failed: {e}"),
                String::new(),
            ));
        }
    };
    match reject_reason(&p) {
        Some(reason) => {
            let id = if p.id.is_empty() {
                name()
            } else {
                p.id.clone()
            };
            Err(skip_diag(&dir_s, id, reason, p.image.clone()))
        }
        None => Ok(Some(p)),
    }
}

/// Every candidate plugin under `dir` sorted by directory, with load status and
/// skip reason — exactly what [`plugin_checks`] accepts or drops. Pure filesystem:
/// no docker, no network.
pub fn plugin_diags(dir: &Path) -> Vec<PluginDiag> {
    pack_dirs(dir)
        .into_iter()
        .filter_map(|d| match load_plugin(&d) {
            Ok(Some(p)) => Some(PluginDiag {
                dir: d.display().to_string(),
                id: p.id.clone(),
                status: PluginLoad::Loaded,
                reason: None,
                image: p.image.clone(),
            }),
            Ok(None) => None,
            Err(diag) => Some(diag),
        })
        .collect()
}

/// `(id, image)` for every plugin that loads successfully (validation shared with
/// [`plugin_checks`]), in directory order. Duplicates across plugins are kept;
/// callers dedup.
pub fn plugin_image_refs(dir: &Path) -> Vec<(String, String)> {
    pack_dirs(dir)
        .into_iter()
        .filter_map(|d| load_plugin(&d).ok().flatten().map(|p| (p.id, p.image)))
        .collect()
}

/// Plugin dir for commands without a `--plugins` flag: `READYHAI_PLUGINS` when set,
/// else `<data>/plugins`. A scan with neither loads no plugins; `doctor` and
/// `tools pull` also probe the data-dir location so an installed layout is visible.
pub fn plugins_dir() -> PathBuf {
    match std::env::var_os("READYHAI_PLUGINS") {
        Some(d) => PathBuf::from(d),
        None => crate::engine::data_dir().join("plugins"),
    }
}

/// On-the-go setup: pre-provision plugin packs a scan on `dir` would select but
/// has not provisioned yet — `docker pull` of missing images and creation of
/// writable `/cache` dirs — so the first check does not silently stall on a
/// multi-hundred-MB pull inside its own time budget. Best-effort: every problem
/// becomes an audit note and the scan proceeds. `pull`/`inspect`/`seed_cache`
/// are injected (production: real docker + the shared cache dir; tests: recorders).
pub fn ensure_packs(
    dir: &Path,
    settings: &crate::settings::Settings,
    target_kind: TargetKind,
    has_repo: bool,
    profile: Profile,
    offline: bool,
    pull: &dyn Fn(&str) -> std::io::Result<super::types::Captured>,
    inspect: &dyn Fn(&str) -> bool,
    seed_cache: &dyn Fn() -> std::io::Result<bool>,
) -> Vec<String> {
    const SETUP_BUDGET: std::time::Duration = std::time::Duration::from_secs(90);
    let mut notes = vec![];
    if offline {
        return notes;
    }
    // Exactly what `checks::all(Some(dir))` would select for this scan: valid pack,
    // kind/profile match (same math as the orchestrator loop) and not silenced by
    // operator settings (same skip() arguments as the loop computes). Intrusive
    // packs still provision under nonprod gating: pulling an image harms nothing.
    let mut seen: Vec<String> = vec![];
    let packs: Vec<(String, String, bool)> = pack_dirs(dir)
        .into_iter()
        .filter_map(|d| load_plugin(&d).ok().flatten())
        .filter(|p| {
            let kind_ok = p.kinds.iter().any(|k| {
                kind_matches(k, target_kind) || has_repo && kind_matches(k, TargetKind::Repo)
            });
            kind_ok
                && profile >= min_profile(&p.profile)
                && settings
                    .skip(&format!("plugin.{}", p.id), true, true, p.intrusive)
                    .is_none()
        })
        .filter(|p| {
            !p.image.is_empty() && !seen.contains(&p.image) && {
                seen.push(p.image.clone());
                true
            }
        })
        .map(|p| (p.id, p.image, p.cache_rw))
        .collect();
    let t0 = std::time::Instant::now();
    let mut cache_seeded = false;
    for (id, image, cache_rw) in &packs {
        if !inspect(image) {
            if !image.contains("@sha256:") {
                notes.push(format!(
                    "setup: {id} image is unpinned; provision it with a digest-pinned ref"
                ));
            }
            if t0.elapsed() >= SETUP_BUDGET {
                notes.push(
                    "setup: time budget reached; remaining images will pull on demand".into(),
                );
                break;
            }
            match pull(image) {
                Ok(c) if c.success() => {
                    notes.push(format!("setup: pulled {id} image (first-run provisioning)"))
                }
                Ok(c) => notes.push(format!(
                    "setup: pull failed for {id} ({}); scan will attempt it on demand",
                    super::parsers::first_line(&c.stderr_lossy(), 160)
                )),
                Err(e) => notes.push(format!(
                    "setup: pull failed for {id} ({e}); scan will attempt it on demand"
                )),
            }
        }
        // DB packs mount the shared <data>/cache as /cache; the runner would
        // create it anyway — pre-creating and noting it makes the first scan's
        // behavior auditable. Directory presence only; DB downloads are
        // `tools update`'s job.
        if *cache_rw && !cache_seeded {
            match seed_cache() {
                Ok(true) => notes.push(format!("setup: created cache dir for {id}")),
                Ok(false) => {}
                Err(e) => notes.push(format!("setup: cache dir unavailable ({e})")),
            }
            cache_seeded = true;
        }
    }
    notes
}

fn kind_matches(k: &str, kind: TargetKind) -> bool {
    match kind {
        TargetKind::Repo => k == "repo",
        TargetKind::Image => k == "image",
        TargetKind::Web => k == "web",
        // plugin_checks only maps repo/image/web kind strings; nothing else selects.
        TargetKind::Host | TargetKind::Android => false,
    }
}

fn min_profile(s: &str) -> Profile {
    match s {
        "quick" => Profile::Quick,
        "deep" => Profile::Deep,
        _ => Profile::Standard,
    }
}

/// Production `pull` for [`ensure_packs`]: `docker pull`, wall-capped so one
/// hung registry cannot eat the whole setup budget.
pub fn setup_pull(reference: &str) -> std::io::Result<super::types::Captured> {
    super::process::run_capped(
        std::process::Command::new("docker").args(["pull", reference]),
        std::time::Duration::from_secs(90),
        8192,
        None,
    )
}

/// Production `seed_cache` for [`ensure_packs`]: ensures the shared tool cache
/// dir exists (same creation + open mode as the container mount); true when new.
pub fn setup_seed_cache(cache_dir: &Path) -> std::io::Result<bool> {
    let fresh = !cache_dir.exists();
    if fresh {
        std::fs::create_dir_all(cache_dir)?;
    }
    Ok(fresh)
}

pub fn plugin_checks(dir: &Path) -> Vec<Check> {
    let mut v = vec![];
    for d in pack_dirs(dir) {
        // load_plugin applies reject_reason, so every plugin below is valid.
        let Ok(Some(p)) = load_plugin(&d) else {
            continue;
        };
        let kinds: Vec<TargetKind> = p
            .kinds
            .iter()
            .filter_map(|k| match k.as_str() {
                "repo" => Some(TargetKind::Repo),
                "image" => Some(TargetKind::Image),
                "web" => Some(TargetKind::Web),
                _ => None,
            })
            .collect();
        let profile = match p.profile.as_str() {
            "quick" => Profile::Quick,
            "deep" => Profile::Deep,
            _ => Profile::Standard,
        };
        let title = if p.title.is_empty() {
            p.id.clone()
        } else {
            p.title.clone()
        };
        let id = format!("plugin.{}", p.id);
        let tool = p.id.clone();
        let intrusive = p.intrusive;
        let mut c =
            Check::new(&id, &title, &kinds, profile, move |ctx| run_plugin(ctx, &p)).tool(&tool);
        if intrusive {
            c = c.intrusive();
        }
        v.push(c);
    }
    v
}
