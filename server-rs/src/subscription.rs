use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{NaiveDateTime, TimeZone, Utc};
use rand::seq::SliceRandom;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use urlencoding::encode;

#[derive(Clone)]
pub struct SubscriptionUser {
    pub id: i64,
    pub uuid: Option<String>,
    pub passwd: Option<String>,
    pub transfer_enable: i64,
    pub transfer_total: i64,
    pub upload_traffic: i64,
    pub download_traffic: i64,
    pub class_expire_time: Option<NaiveDateTime>,
    pub expire_time: Option<NaiveDateTime>,
}

#[derive(Clone)]
pub struct SubscriptionNode {
    pub id: i64,
    pub name: String,
    pub node_type: String,
    pub node_config: Value,
}

const REGION_TAGS: [&str; 7] = [
    "🇭🇰 香港节点",
    "🇨🇳 台湾节点",
    "🇸🇬 狮城节点",
    "🇯🇵 日本节点",
    "🇺🇲 美国节点",
    "🇰🇷 韩国节点",
    "🎥 奈飞节点",
];
const VMESS_PROXY_KEYS: [&str; 23] = [
    "name",
    "type",
    "server",
    "port",
    "udp",
    "uuid",
    "alterId",
    "cipher",
    "packet-encoding",
    "global-padding",
    "authenticated-length",
    "tls",
    "servername",
    "alpn",
    "fingerprint",
    "client-fingerprint",
    "skip-cert-verify",
    "reality-opts",
    "ech-opts",
    "network",
    "ws-opts",
    "grpc-opts",
    "smux",
];
const VLESS_PROXY_KEYS: [&str; 21] = [
    "name",
    "type",
    "server",
    "port",
    "udp",
    "uuid",
    "flow",
    "packet-encoding",
    "tls",
    "servername",
    "alpn",
    "fingerprint",
    "client-fingerprint",
    "skip-cert-verify",
    "reality-opts",
    "ech-opts",
    "encryption",
    "network",
    "ws-opts",
    "grpc-opts",
    "smux",
];
const TROJAN_PROXY_KEYS: [&str; 18] = [
    "name",
    "type",
    "server",
    "port",
    "password",
    "udp",
    "sni",
    "alpn",
    "client-fingerprint",
    "fingerprint",
    "skip-cert-verify",
    "ss-opts",
    "reality-opts",
    "ech-opts",
    "network",
    "ws-opts",
    "grpc-opts",
    "smux",
];
const SS_PROXY_KEYS: [&str; 13] = [
    "name",
    "type",
    "server",
    "port",
    "cipher",
    "password",
    "udp",
    "udp-over-tcp",
    "udp-over-tcp-version",
    "ip-version",
    "plugin",
    "plugin-opts",
    "smux",
];
const SSR_PROXY_KEYS: [&str; 11] = [
    "name",
    "type",
    "server",
    "port",
    "cipher",
    "password",
    "obfs",
    "protocol",
    "obfs-param",
    "protocol-param",
    "udp",
];
const ANYTLS_PROXY_KEYS: [&str; 14] = [
    "name",
    "type",
    "server",
    "port",
    "password",
    "client-fingerprint",
    "udp",
    "idle-session-check-interval",
    "idle-session-timeout",
    "min-idle-session",
    "sni",
    "alpn",
    "skip-cert-verify",
    "ech-opts",
];
const HYSTERIA2_PROXY_KEYS: [&str; 15] = [
    "name",
    "type",
    "server",
    "port",
    "ports",
    "password",
    "up",
    "down",
    "obfs",
    "obfs-password",
    "sni",
    "skip-cert-verify",
    "fingerprint",
    "alpn",
    "ech-opts",
];
const WS_OPTS_KEYS: [&str; 2] = ["path", "headers"];
const HEADERS_KEYS: [&str; 1] = ["Host"];
const REALITY_OPTS_KEYS: [&str; 2] = ["public-key", "short-id"];
const ECH_OPTS_KEYS: [&str; 2] = ["enable", "config"];
const GRPC_OPTS_KEYS: [&str; 1] = ["grpc-service-name"];
const PLUGIN_OPTS_KEYS: [&str; 2] = ["mode", "host"];
const SS_OPTS_KEYS: [&str; 3] = ["enabled", "method", "password"];
const SMUX_KEYS: [&str; 1] = ["enabled"];

static CLASH_RULES: OnceLock<Vec<Value>> = OnceLock::new();
static CLASH_TEMPLATE: OnceLock<Value> = OnceLock::new();
static SINGBOX_TEMPLATE: OnceLock<Value> = OnceLock::new();
static SURGE_TEMPLATE: OnceLock<String> = OnceLock::new();

fn load_clash_rules() -> &'static Vec<Value> {
    CLASH_RULES.get_or_init(|| {
        let raw = include_str!("templates/clashRules.json");
        serde_json::from_str::<Vec<Value>>(raw).unwrap_or_default()
    })
}

fn clone_clash_template() -> Value {
    let raw = include_str!("templates/clashTemplate.json");
    let template = CLASH_TEMPLATE
        .get_or_init(|| serde_json::from_str::<Value>(raw).unwrap_or_else(|_| json!({})));
    template.clone()
}

fn clone_singbox_template() -> Value {
    let raw = include_str!("templates/singboxTemplate.json");
    let template = SINGBOX_TEMPLATE
        .get_or_init(|| serde_json::from_str::<Value>(raw).unwrap_or_else(|_| json!({})));
    template.clone()
}

fn clone_surge_template() -> String {
    SURGE_TEMPLATE
        .get_or_init(|| include_str!("templates/surgeTemplate.conf").to_string())
        .clone()
}

fn b64encode_utf8(input: &str) -> String {
    STANDARD.encode(input.as_bytes())
}

fn normalize_base64(input: &str) -> Option<String> {
    let cleaned = input.trim();
    if cleaned.is_empty() {
        return None;
    }
    if !cleaned
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=')
    {
        return None;
    }
    let modulo = cleaned.len() % 4;
    if modulo == 1 {
        return None;
    }
    if modulo == 0 {
        Some(cleaned.to_string())
    } else {
        Some(format!("{cleaned}{}", "=".repeat(4 - modulo)))
    }
}

fn decode_base64_bytes(input: &str) -> Option<Vec<u8>> {
    let normalized = normalize_base64(input)?;
    STANDARD.decode(normalized.as_bytes()).ok()
}

fn ensure_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        _ => String::new(),
    }
}

fn ensure_i64(value: Option<&Value>, default: i64) -> i64 {
    match value {
        Some(Value::Number(value)) => value.as_i64().unwrap_or(default),
        Some(Value::String(value)) => value.trim().parse::<i64>().unwrap_or(default),
        Some(Value::Bool(value)) => {
            if *value {
                1
            } else {
                0
            }
        }
        _ => default,
    }
}

fn ensure_f64(value: Option<&Value>, default: f64) -> f64 {
    match value {
        Some(Value::Number(value)) => value.as_f64().unwrap_or(default),
        Some(Value::String(value)) => value.trim().parse::<f64>().unwrap_or(default),
        Some(Value::Bool(value)) => {
            if *value {
                1.0
            } else {
                0.0
            }
        }
        _ => default,
    }
}

fn normalize_string_list(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| ensure_string(Some(value)).trim().to_string())
            .filter(|value| !value.is_empty())
            .collect(),
        Some(Value::String(value)) => value
            .split(',')
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

fn pick_random_short_id(value: Option<&Value>) -> String {
    let list = normalize_string_list(value);
    if list.is_empty() {
        return String::new();
    }
    let mut rng = rand::thread_rng();
    list.choose(&mut rng).cloned().unwrap_or_default()
}

fn resolve_reality_public_key(config: &Value, client: &Value) -> String {
    ensure_string(
        client
            .get("publickey")
            .or_else(|| client.get("public_key"))
            .or_else(|| config.get("public_key")),
    )
}

fn resolve_ech_state<'a>(config: &'a Value, client: &'a Value) -> Option<&'a Value> {
    if let Some(ech) = client.get("ech") {
        if ech.is_object() {
            return Some(ech);
        }
    }
    if let Some(ech) = config.get("ech") {
        if ech.is_object() {
            return Some(ech);
        }
    }
    None
}

fn parse_boolean_flag(value: Option<&Value>) -> Option<bool> {
    match value {
        Some(Value::Bool(value)) => Some(*value),
        Some(Value::Number(value)) => value.as_i64().map(|v| v != 0),
        Some(Value::String(value)) => {
            let normalized = value.trim().to_lowercase();
            if ["1", "true", "yes", "on"].contains(&normalized.as_str()) {
                Some(true)
            } else if ["0", "false", "no", "off", ""].contains(&normalized.as_str()) {
                Some(false)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn resolve_skip_cert_verify(config: &Value, client: &Value, fallback: bool) -> bool {
    let from_client = parse_boolean_flag(
        client
            .get("skip-cert-verify")
            .or_else(|| client.get("skip_cert_verify"))
            .or_else(|| client.get("insecure"))
            .or_else(|| client.get("allow_insecure"))
            .or_else(|| client.get("allowInsecure")),
    );
    if let Some(value) = from_client {
        return value;
    }

    let from_config = parse_boolean_flag(
        config
            .get("skip-cert-verify")
            .or_else(|| config.get("skip_cert_verify"))
            .or_else(|| config.get("insecure"))
            .or_else(|| config.get("allow_insecure"))
            .or_else(|| config.get("allowInsecure")),
    );
    if let Some(value) = from_config {
        return value;
    }

    fallback
}

fn resolve_ech_config(config: &Value, client: &Value) -> String {
    if let Some(ech) = client.get("ech").and_then(|value| value.as_object()) {
        let value = ensure_string(ech.get("config")).trim().to_string();
        if !value.is_empty() {
            return value;
        }
    }
    if let Some(ech) = config.get("ech").and_then(|value| value.as_object()) {
        let value = ensure_string(ech.get("config")).trim().to_string();
        if !value.is_empty() {
            return value;
        }
    }
    String::new()
}

fn split_pem_lines(raw: &str) -> Vec<String> {
    raw.lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect()
}

fn to_singbox_pem_lines(label: &str, raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if trimmed.contains("-----BEGIN") {
        return split_pem_lines(trimmed);
    }
    let compact: String = trimmed.chars().filter(|ch| !ch.is_whitespace()).collect();
    if compact.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![format!("-----BEGIN {label}-----")];
    let bytes = compact.as_bytes();
    for chunk in bytes.chunks(64) {
        lines.push(String::from_utf8_lossy(chunk).to_string());
    }
    lines.push(format!("-----END {label}-----"));
    lines
}

fn build_clash_ech_opts(config: &Value, client: &Value) -> Option<Value> {
    let ech_state = resolve_ech_state(config, client);
    let ech_config = resolve_ech_config(config, client);
    if ech_state.is_none() && ech_config.is_empty() {
        return None;
    }
    let mut opts = serde_json::Map::new();
    opts.insert("enable".to_string(), json!(true));
    if !ech_config.is_empty() {
        opts.insert("config".to_string(), json!(ech_config));
    }
    Some(Value::Object(opts))
}

fn build_singbox_ech(config: &Value, client: &Value) -> Option<Value> {
    let ech_state = resolve_ech_state(config, client);
    let ech_config = resolve_ech_config(config, client);
    if ech_state.is_none() && ech_config.is_empty() {
        return None;
    }
    let mut ech = serde_json::Map::new();
    ech.insert("enabled".to_string(), json!(true));
    if !ech_config.is_empty() {
        let pem_lines = to_singbox_pem_lines("ECH CONFIGS", &ech_config);
        if !pem_lines.is_empty() {
            ech.insert("config".to_string(), json!(pem_lines));
        }
    }
    Some(Value::Object(ech))
}

fn resolve_vless_client_encryption(config: &Value, client: &Value) -> String {
    let encryption = ensure_string(
        client
            .get("encryption")
            .or_else(|| config.get("encryption")),
    )
    .trim()
    .to_string();
    if encryption.is_empty() {
        "none".to_string()
    } else {
        encryption
    }
}

fn is_vless_encryption_enabled(config: &Value, client: &Value) -> bool {
    resolve_vless_client_encryption(config, client).to_lowercase() != "none"
}

fn format_host_for_url(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') && !host.ends_with(']') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn normalize_path(path: Option<&Value>) -> String {
    let path = ensure_string(path);
    if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path
    } else {
        format!("/{path}")
    }
}

fn apply_query_param(params: &mut Vec<(String, String)>, key: &str, value: &str) {
    if value.is_empty() {
        return;
    }
    params.push((key.to_string(), value.to_string()));
}

fn build_query_string(params: Vec<(String, String)>) -> String {
    params
        .into_iter()
        .map(|(key, value)| format!("{key}={}", encode(&value)))
        .collect::<Vec<String>>()
        .join("&")
}

fn derive_ss2022_user_key(method: &str, user_password: &str) -> String {
    let needs = if method.to_lowercase().contains("aes-128") {
        16
    } else {
        32
    };
    let mut bytes =
        decode_base64_bytes(user_password).unwrap_or_else(|| user_password.as_bytes().to_vec());
    if bytes.is_empty() {
        bytes = vec![0];
    }
    let mut out = vec![0u8; needs];
    for i in 0..needs {
        out[i] = bytes[i % bytes.len()];
    }
    STANDARD.encode(out)
}

fn build_ss2022_password(config: &Value, user_password: &str) -> String {
    let method = ensure_string(config.get("cipher").or_else(|| config.get("method")));
    let server_password = ensure_string(config.get("password"));
    if !method.to_lowercase().contains("2022-blake3") {
        if !user_password.is_empty() {
            return user_password.to_string();
        }
        return server_password;
    }
    let user_part = derive_ss2022_user_key(
        &method,
        if user_password.is_empty() {
            &server_password
        } else {
            user_password
        },
    );
    if server_password.is_empty() {
        user_part
    } else {
        format!("{server_password}:{user_part}")
    }
}

fn normalize_alpn(value: Option<&Value>) -> Option<Vec<String>> {
    let list = match value {
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| ensure_string(Some(value)).trim().to_string())
            .filter(|value| !value.is_empty())
            .collect::<Vec<String>>(),
        Some(Value::String(value)) => value
            .split(',')
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect::<Vec<String>>(),
        _ => Vec::new(),
    };
    if list.is_empty() {
        None
    } else {
        Some(list)
    }
}

fn resolve_first_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::Array(values)) => values
            .first()
            .map(|value| ensure_string(Some(value)))
            .unwrap_or_default(),
        Some(Value::String(value)) => value.clone(),
        _ => String::new(),
    }
}

fn normalize_tokens(value: &str) -> Vec<String> {
    value
        .to_lowercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|item| !item.is_empty())
        .map(|item| item.to_string())
        .collect()
}

fn contains_token(tokens: &[String], token: &str) -> bool {
    tokens.iter().any(|item| item == token)
}

fn compact_lowercase(value: &str) -> String {
    value
        .to_lowercase()
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect()
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn match_region(tag: &str, name: &str) -> bool {
    let lower = name.to_lowercase();
    let compact = compact_lowercase(name);
    let tokens = normalize_tokens(&lower);

    match tag {
        "🇭🇰 香港节点" => {
            contains_any(name, &["香港", "🇭🇰"])
                || compact.contains("hongkong")
                || contains_token(&tokens, "hk")
        }
        "🇨🇳 台湾节点" => {
            contains_any(name, &["台湾", "台北", "🇹🇼"])
                || compact.contains("taiwan")
                || compact.contains("taipei")
                || contains_token(&tokens, "tw")
        }
        "🇸🇬 狮城节点" => {
            contains_any(name, &["狮城", "新加坡", "🇸🇬"])
                || compact.contains("singapore")
                || contains_token(&tokens, "sg")
        }
        "🇯🇵 日本节点" => {
            contains_any(name, &["日本", "东京", "大阪", "🇯🇵"])
                || compact.contains("japan")
                || contains_token(&tokens, "jp")
        }
        "🇺🇲 美国节点" => {
            contains_any(name, &["美国", "洛杉矶", "纽约", "硅谷", "🇺🇸", "🇺🇲"])
                || compact.contains("unitedstates")
                || contains_token(&tokens, "usa")
                || contains_token(&tokens, "us")
        }
        "🇰🇷 韩国节点" => {
            contains_any(name, &["韩国", "首尔", "🇰🇷"])
                || compact.contains("korea")
                || contains_token(&tokens, "kr")
        }
        "🎥 奈飞节点" => {
            contains_any(name, &["奈飞"])
                || compact.contains("netflix")
                || contains_token(&tokens, "nf")
        }
        _ => false,
    }
}

fn collect_region_matches(proxy_names: &[String]) -> HashMap<String, Vec<String>> {
    let mut matches: HashMap<String, Vec<String>> = HashMap::new();
    for tag in REGION_TAGS.iter() {
        matches.insert((*tag).to_string(), Vec::new());
    }
    for name in proxy_names {
        for tag in REGION_TAGS.iter() {
            if match_region(tag, name) {
                if let Some(values) = matches.get_mut(*tag) {
                    values.push(name.clone());
                }
            }
        }
    }
    matches
}

fn unique_names(values: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    for item in values {
        let name = item.trim();
        if name.is_empty() || seen.contains(name) {
            continue;
        }
        seen.insert(name.to_string());
        result.push(name.to_string());
    }
    result
}

fn filter_region_tags(values: Vec<String>, available_region_set: &HashSet<String>) -> Vec<String> {
    values
        .into_iter()
        .filter(|item| !REGION_TAGS.contains(&item.as_str()) || available_region_set.contains(item))
        .collect()
}

fn with_fallback(values: Vec<String>, fallback: &[&str]) -> Vec<String> {
    if values.is_empty() {
        fallback.iter().map(|item| (*item).to_string()).collect()
    } else {
        values
    }
}

fn dump_yaml(value: &Value) -> String {
    stringify_yaml(value, 0, None)
}

fn stringify_yaml(value: &Value, indent: usize, parent_key: Option<&str>) -> String {
    let spaces = "  ".repeat(indent);
    let mut result = String::new();
    match value {
        Value::Array(items) => {
            for item in items {
                match item {
                    Value::Object(_) | Value::Array(_) => {
                        result.push_str(&format!("{spaces}-\n"));
                        result.push_str(&stringify_yaml(item, indent + 1, parent_key));
                    }
                    _ => {
                        result.push_str(&format!("{spaces}- {}\n", value_to_yaml(item)));
                    }
                }
            }
        }
        Value::Object(map) => {
            let keys = ordered_yaml_keys(map, parent_key);
            for key in keys {
                let value = map.get(&key).unwrap_or(&Value::Null);
                if value.is_array() || value.is_object() {
                    result.push_str(&format!("{spaces}{key}:\n"));
                    result.push_str(&stringify_yaml(value, indent + 1, Some(&key)));
                } else {
                    result.push_str(&format!("{spaces}{key}: {}\n", value_to_yaml(value)));
                }
            }
        }
        _ => {
            result.push_str(&format!("{spaces}{}\n", value_to_yaml(value)));
        }
    }
    result
}

fn ordered_yaml_keys(
    map: &serde_json::Map<String, Value>,
    parent_key: Option<&str>,
) -> Vec<String> {
    let preferred = preferred_yaml_key_order(map, parent_key);
    let mut ordered = Vec::new();
    let mut used = HashSet::new();
    if let Some(order) = preferred {
        for key in order {
            if map.contains_key(*key) {
                let key_string = (*key).to_string();
                if used.insert(key_string.clone()) {
                    ordered.push(key_string);
                }
            }
        }
    }
    let mut rest: Vec<String> = map
        .keys()
        .filter(|key| !used.contains(key.as_str()))
        .cloned()
        .collect();
    rest.sort();
    ordered.extend(rest);
    ordered
}

fn preferred_yaml_key_order(
    map: &serde_json::Map<String, Value>,
    parent_key: Option<&str>,
) -> Option<&'static [&'static str]> {
    if let Some(key) = parent_key {
        let order = match key {
            "ws-opts" => Some(&WS_OPTS_KEYS[..]),
            "headers" => Some(&HEADERS_KEYS[..]),
            "reality-opts" => Some(&REALITY_OPTS_KEYS[..]),
            "ech-opts" => Some(&ECH_OPTS_KEYS[..]),
            "grpc-opts" => Some(&GRPC_OPTS_KEYS[..]),
            "plugin-opts" => Some(&PLUGIN_OPTS_KEYS[..]),
            "ss-opts" => Some(&SS_OPTS_KEYS[..]),
            "smux" => Some(&SMUX_KEYS[..]),
            _ => None,
        };
        if order.is_some() {
            return order;
        }
    }

    match map.get("type") {
        Some(Value::String(proxy_type)) => match proxy_type.as_str() {
            "vmess" => Some(&VMESS_PROXY_KEYS[..]),
            "vless" => Some(&VLESS_PROXY_KEYS[..]),
            "trojan" => Some(&TROJAN_PROXY_KEYS[..]),
            "ss" => Some(&SS_PROXY_KEYS[..]),
            "ssr" => Some(&SSR_PROXY_KEYS[..]),
            "anytls" => Some(&ANYTLS_PROXY_KEYS[..]),
            "hysteria2" => Some(&HYSTERIA2_PROXY_KEYS[..]),
            _ => None,
        },
        _ => None,
    }
}

fn value_to_yaml(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => {
            if *value {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Null => "null".to_string(),
        _ => value.to_string(),
    }
}

fn decode_value_to_object(value: Value) -> Option<Value> {
    let mut current = value;
    for _ in 0..3 {
        match current {
            Value::String(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return None;
                }
                current = serde_json::from_str::<Value>(trimmed).ok()?;
            }
            Value::Object(_) => return Some(current),
            _ => return None,
        }
    }
    if current.is_object() {
        Some(current)
    } else {
        None
    }
}

fn parse_node_config(node_config: &Value) -> (Value, Value, Value) {
    let root = decode_value_to_object(node_config.clone());
    if let Some(Value::Object(map)) = root {
        let basic = decode_value_to_object(map.get("basic").cloned().unwrap_or_else(|| json!({})))
            .unwrap_or_else(|| json!({}));
        let config = if let Some(config_value) = map.get("config").cloned() {
            decode_value_to_object(config_value).unwrap_or_else(|| json!({}))
        } else {
            Value::Object(map.clone())
        };
        let client =
            decode_value_to_object(map.get("client").cloned().unwrap_or_else(|| json!({})))
                .unwrap_or_else(|| json!({}));
        (basic, config, client)
    } else {
        (json!({}), json!({}), json!({}))
    }
}

struct NodeEndpoint {
    server: String,
    port: i64,
    tls_host: String,
    config: Value,
    client: Value,
}

fn resolve_node_endpoint(node: &SubscriptionNode) -> NodeEndpoint {
    let (_basic, config, client) = parse_node_config(&node.node_config);
    let server = ensure_string(client.get("server"));
    let port = ensure_i64(client.get("port").or_else(|| config.get("port")), 443);
    let tls_host = ensure_string(client.get("tls_host").or_else(|| config.get("host")));
    let tls_host = if tls_host.is_empty() {
        server.clone()
    } else {
        tls_host
    };
    NodeEndpoint {
        server,
        port,
        tls_host,
        config,
        client,
    }
}

fn resolve_config_string(config: &Value, keys: &[&str]) -> String {
    for key in keys {
        let value = ensure_string(config.get(*key));
        if !value.is_empty() {
            return value;
        }
    }
    String::new()
}

fn resolve_config_string_value(config: &Value, keys: &[&str], fallback: &str) -> String {
    let value = resolve_config_string(config, keys);
    if value.is_empty() {
        fallback.to_string()
    } else {
        value
    }
}

pub fn generate_v2ray_config(nodes: &[SubscriptionNode], user: &SubscriptionUser) -> String {
    let mut links: Vec<String> = Vec::new();
    for node in nodes {
        let endpoint = resolve_node_endpoint(node);
        let mut resolved = node.clone();
        resolved.node_type = resolved.node_type.to_lowercase();
        let server = endpoint.server.clone();
        let tls_host = endpoint.tls_host.clone();
        let port = endpoint.port;
        let config = endpoint.config;
        let client = endpoint.client;

        match resolved.node_type.as_str() {
            "v2ray" => links.push(generate_vmess_link(
                &resolved.name,
                &server,
                port,
                &tls_host,
                &config,
                &client,
                user,
            )),
            "vless" => links.push(generate_vless_link(
                &resolved.name,
                &server,
                port,
                &tls_host,
                &config,
                &client,
                user,
            )),
            "trojan" => links.push(generate_trojan_link(
                &resolved.name,
                &server,
                port,
                &tls_host,
                &config,
                &client,
                user,
            )),
            "ss" => links.push(generate_shadowsocks_link(
                &resolved.name,
                &server,
                port,
                &tls_host,
                &config,
                user,
            )),
            "hysteria" => links.push(generate_hysteria_link(
                &resolved.name,
                &server,
                port,
                &tls_host,
                &config,
                &client,
                user,
            )),
            _ => {}
        }
    }
    b64encode_utf8(&links.join("\n"))
}

fn generate_vmess_link(
    name: &str,
    server: &str,
    port: i64,
    tls_host: &str,
    config: &Value,
    client: &Value,
    user: &SubscriptionUser,
) -> String {
    let stream_type = ensure_string(config.get("stream_type"));
    let stream_type = if stream_type.is_empty() {
        "tcp".to_string()
    } else {
        stream_type
    };
    let stream_lower = stream_type.to_lowercase();
    let host_candidate = resolve_config_string(config, &["server", "host", "sni"]);
    let host_candidate = if host_candidate.is_empty() {
        if !tls_host.is_empty() {
            tls_host.to_string()
        } else {
            server.to_string()
        }
    } else {
        host_candidate
    };
    let sni = resolve_config_string_value(
        config,
        &["sni", "host", "server"],
        if !tls_host.is_empty() {
            tls_host
        } else {
            server
        },
    );
    let needs_host = ["ws", "http", "h2"].contains(&stream_lower.as_str());
    let host = if needs_host {
        host_candidate
    } else {
        resolve_config_string(config, &["server"])
    };
    let tls_type = ensure_string(config.get("tls_type"));
    let mut vmess = serde_json::Map::new();
    vmess.insert("v".to_string(), json!("2"));
    vmess.insert("ps".to_string(), json!(name));
    vmess.insert("add".to_string(), json!(server));
    vmess.insert("port".to_string(), json!(port));
    vmess.insert(
        "id".to_string(),
        json!(user.uuid.clone().unwrap_or_default()),
    );
    vmess.insert("aid".to_string(), json!(ensure_i64(config.get("aid"), 0)));
    vmess.insert("net".to_string(), json!(stream_type));
    vmess.insert("type".to_string(), json!("none"));
    vmess.insert("host".to_string(), json!(host));
    vmess.insert(
        "path".to_string(),
        json!(resolve_config_string(config, &["path"])),
    );
    vmess.insert(
        "tls".to_string(),
        json!(if tls_type == "reality" {
            "reality"
        } else if tls_type == "tls" {
            "tls"
        } else {
            ""
        }),
    );
    vmess.insert("sni".to_string(), json!(sni));
    vmess.insert(
        "alpn".to_string(),
        json!(resolve_config_string(config, &["alpn"])),
    );
    if tls_type == "reality" {
        vmess.insert("security".to_string(), json!("reality"));
        vmess.insert(
            "pbk".to_string(),
            json!(resolve_reality_public_key(config, client)),
        );
        vmess.insert(
            "fp".to_string(),
            json!(resolve_config_string_value(
                config,
                &["fingerprint"],
                "chrome"
            )),
        );
        let short_id = pick_random_short_id(config.get("short_ids"));
        if !short_id.is_empty() {
            vmess.insert("sid".to_string(), json!(short_id));
        }
    }
    if tls_type == "tls" {
        let ech_config = resolve_ech_config(config, client);
        if !ech_config.is_empty() {
            vmess.insert("ech".to_string(), json!(ech_config));
            vmess.insert("echConfigList".to_string(), json!(ech_config));
        }
    }
    format!(
        "vmess://{}",
        b64encode_utf8(&Value::Object(vmess).to_string())
    )
}

fn generate_vless_link(
    name: &str,
    server: &str,
    port: i64,
    tls_host: &str,
    config: &Value,
    client: &Value,
    user: &SubscriptionUser,
) -> String {
    let stream_type = ensure_string(config.get("stream_type"));
    let stream_type = if stream_type.is_empty() {
        "tcp".to_string()
    } else {
        stream_type
    };
    let stream_lower = stream_type.to_lowercase();
    let host_candidate = resolve_config_string(config, &["server", "host", "sni"]);
    let host_candidate = if host_candidate.is_empty() {
        if !tls_host.is_empty() {
            tls_host.to_string()
        } else {
            server.to_string()
        }
    } else {
        host_candidate
    };
    let sni = resolve_config_string_value(
        config,
        &["sni", "host", "server"],
        if !tls_host.is_empty() {
            tls_host
        } else {
            server
        },
    );

    let mut params: Vec<(String, String)> = Vec::new();
    params.push((
        "encryption".to_string(),
        resolve_vless_client_encryption(config, client),
    ));
    params.push(("type".to_string(), stream_type));

    let tls_type = ensure_string(config.get("tls_type"));
    if tls_type == "tls" {
        params.push(("security".to_string(), "tls".to_string()));
        apply_query_param(&mut params, "sni", &sni);
        apply_query_param(
            &mut params,
            "alpn",
            &resolve_config_string(config, &["alpn"]),
        );
    } else if tls_type == "reality" {
        params.push(("security".to_string(), "reality".to_string()));
        apply_query_param(
            &mut params,
            "pbk",
            &resolve_reality_public_key(config, client),
        );
        let fingerprint = resolve_config_string_value(config, &["fingerprint"], "chrome");
        apply_query_param(&mut params, "fp", &fingerprint);
        apply_query_param(&mut params, "sni", &sni);
        let short_id = pick_random_short_id(config.get("short_ids"));
        apply_query_param(&mut params, "sid", &short_id);
    }
    if tls_type == "tls" {
        let ech_config = resolve_ech_config(config, client);
        apply_query_param(&mut params, "ech", &ech_config);
        apply_query_param(&mut params, "echConfigList", &ech_config);
    }

    let flow = resolve_config_string(config, &["flow"]);
    apply_query_param(&mut params, "flow", &flow);
    let path = resolve_config_string(config, &["path"]);
    apply_query_param(&mut params, "path", &path);
    let host_value = resolve_config_string(config, &["server"]);
    if !host_value.is_empty() {
        apply_query_param(&mut params, "host", &host_value);
    } else if ["ws", "http", "h2"].contains(&stream_lower.as_str()) && !host_candidate.is_empty() {
        apply_query_param(&mut params, "host", &host_candidate);
    }
    let service_name = resolve_config_string(config, &["service_name"]);
    apply_query_param(&mut params, "serviceName", &service_name);

    let host = format_host_for_url(server);
    let query = build_query_string(params);
    format!(
        "vless://{}@{}:{}?{}#{}",
        user.uuid.clone().unwrap_or_default(),
        host,
        port,
        query,
        encode(name)
    )
}

fn generate_trojan_link(
    name: &str,
    server: &str,
    port: i64,
    tls_host: &str,
    config: &Value,
    client: &Value,
    user: &SubscriptionUser,
) -> String {
    let stream_type = ensure_string(config.get("stream_type"));
    let stream_type = if stream_type.is_empty() {
        "tcp".to_string()
    } else {
        stream_type
    };
    let stream_lower = stream_type.to_lowercase();
    let host_candidate = resolve_config_string(config, &["server", "host", "sni"]);
    let host_candidate = if host_candidate.is_empty() {
        if !tls_host.is_empty() {
            tls_host.to_string()
        } else {
            server.to_string()
        }
    } else {
        host_candidate
    };
    let sni = resolve_config_string_value(
        config,
        &["sni", "host", "server"],
        if !tls_host.is_empty() {
            tls_host
        } else {
            server
        },
    );
    let mut params: Vec<(String, String)> = Vec::new();
    let tls_type = ensure_string(config.get("tls_type"));
    let security = if tls_type == "reality" {
        "reality"
    } else {
        "tls"
    };
    params.push(("security".to_string(), security.to_string()));
    apply_query_param(&mut params, "sni", &sni);
    apply_query_param(
        &mut params,
        "alpn",
        &resolve_config_string(config, &["alpn"]),
    );
    if tls_type == "reality" {
        apply_query_param(
            &mut params,
            "pbk",
            &resolve_reality_public_key(config, client),
        );
        apply_query_param(
            &mut params,
            "fp",
            &resolve_config_string_value(config, &["fingerprint"], "chrome"),
        );
        let short_id = pick_random_short_id(config.get("short_ids"));
        apply_query_param(&mut params, "sid", &short_id);
    }
    if tls_type != "reality" {
        let ech_config = resolve_ech_config(config, client);
        apply_query_param(&mut params, "ech", &ech_config);
        apply_query_param(&mut params, "echConfigList", &ech_config);
    }
    apply_query_param(
        &mut params,
        "path",
        &resolve_config_string(config, &["path"]),
    );
    let host_value = resolve_config_string(config, &["server"]);
    if !host_value.is_empty() {
        apply_query_param(&mut params, "host", &host_value);
    } else if ["ws", "http", "h2"].contains(&stream_lower.as_str()) && !host_candidate.is_empty() {
        apply_query_param(&mut params, "host", &host_candidate);
    }
    let query = build_query_string(params);
    let host = format_host_for_url(server);
    let password = encode(user.passwd.as_deref().unwrap_or(""));
    if query.is_empty() {
        format!("trojan://{}@{}:{}#{}", password, host, port, encode(name))
    } else {
        format!(
            "trojan://{}@{}:{}?{}#{}",
            password,
            host,
            port,
            query,
            encode(name)
        )
    }
}

fn generate_shadowsocks_link(
    name: &str,
    server: &str,
    port: i64,
    _tls_host: &str,
    config: &Value,
    user: &SubscriptionUser,
) -> String {
    let method = resolve_config_string_value(config, &["cipher"], "aes-128-gcm");
    let password = build_ss2022_password(config, &user.passwd.clone().unwrap_or_default());
    let user_info = format!("{method}:{password}");
    let encoded = b64encode_utf8(&user_info);
    let host = format_host_for_url(server);
    let mut link = format!("ss://{encoded}@{host}:{port}");

    let obfs = resolve_config_string(config, &["obfs"]);
    if !obfs.is_empty() && obfs != "plain" {
        let mut params: Vec<(String, String)> = Vec::new();
        params.push(("plugin".to_string(), "obfs-local".to_string()));
        let mut plugin_opts = format!("obfs={obfs}");
        let obfs_host = resolve_config_string(config, &["server"]);
        if !obfs_host.is_empty() {
            plugin_opts.push_str(&format!(";obfs-host={obfs_host}"));
        }
        let obfs_uri = resolve_config_string(config, &["path"]);
        if !obfs_uri.is_empty() {
            plugin_opts.push_str(&format!(";obfs-uri={obfs_uri}"));
        }
        params.push(("plugin-opts".to_string(), plugin_opts));
        let query = build_query_string(params);
        link = format!("{link}?{query}");
    }

    format!("{link}#{}", encode(name))
}

fn generate_hysteria_link(
    name: &str,
    server: &str,
    port: i64,
    tls_host: &str,
    config: &Value,
    client: &Value,
    user: &SubscriptionUser,
) -> String {
    let mut params: Vec<(String, String)> = Vec::new();
    params.push(("protocol".to_string(), "udp".to_string()));
    params.push(("auth".to_string(), user.passwd.clone().unwrap_or_default()));
    let peer = if !tls_host.is_empty() {
        tls_host.to_string()
    } else {
        server.to_string()
    };
    params.push(("peer".to_string(), peer));
    if resolve_skip_cert_verify(config, client, false) {
        params.push(("insecure".to_string(), "1".to_string()));
    }
    params.push((
        "upmbps".to_string(),
        resolve_config_string_value(config, &["up_mbps"], "100"),
    ));
    params.push((
        "downmbps".to_string(),
        resolve_config_string_value(config, &["down_mbps"], "100"),
    ));
    let obfs = resolve_config_string(config, &["obfs"]);
    if !obfs.is_empty() && obfs != "plain" {
        params.push(("obfs".to_string(), obfs));
        let obfs_param = resolve_config_string(config, &["obfs_password"]);
        apply_query_param(&mut params, "obfsParam", &obfs_param);
    }
    let ech_config = resolve_ech_config(config, client);
    apply_query_param(&mut params, "ech", &ech_config);
    apply_query_param(&mut params, "echConfigList", &ech_config);
    let host = format_host_for_url(server);
    let query = build_query_string(params);
    format!("hysteria2://{}:{}?{}#{}", host, port, query, encode(name))
}

fn generate_anytls_link(
    name: &str,
    server: &str,
    port: i64,
    tls_host: &str,
    config: &Value,
    client: &Value,
    user: &SubscriptionUser,
) -> String {
    let host = format_host_for_url(server);
    let password = encode(user.passwd.as_deref().unwrap_or(""));
    let peer = resolve_config_string_value(
        config,
        &["sni", "host", "server"],
        if !tls_host.is_empty() {
            tls_host
        } else {
            server
        },
    );
    let mut params = vec![
        ("peer".to_string(), peer),
        ("udp".to_string(), "1".to_string()),
    ];
    if resolve_skip_cert_verify(config, client, false) {
        params.push(("insecure".to_string(), "1".to_string()));
    }
    let query = build_query_string(params);
    format!(
        "anytls://{}@{}:{}?{}#{}",
        password,
        host,
        port,
        query,
        encode(name)
    )
}

pub fn generate_clash_config(nodes: &[SubscriptionNode], user: &SubscriptionUser) -> String {
    let mut proxies: Vec<Value> = Vec::new();
    let mut proxy_names: Vec<String> = Vec::new();

    for node in nodes {
        let endpoint = resolve_node_endpoint(node);
        let mut node_type = node.node_type.to_lowercase();
        if node_type == "shadowsocksr" {
            node_type = "ssr".to_string();
        }

        let server = endpoint.server;
        let port = endpoint.port;
        let tls_host = endpoint.tls_host;
        let config = endpoint.config;
        let client = endpoint.client;

        let mut proxy: Option<serde_json::Map<String, Value>> = None;
        let name = node.name.clone();

        match node_type.as_str() {
            "v2ray" => {
                let mut value = serde_json::Map::new();
                value.insert("name".to_string(), json!(name));
                value.insert("type".to_string(), json!("vmess"));
                value.insert("server".to_string(), json!(server));
                value.insert("port".to_string(), json!(port));
                value.insert(
                    "uuid".to_string(),
                    json!(user.uuid.clone().unwrap_or_default()),
                );
                value.insert(
                    "alterId".to_string(),
                    json!(ensure_i64(config.get("aid"), 0)),
                );
                value.insert("cipher".to_string(), json!("auto"));
                let tls_mode = ensure_string(config.get("tls_type"));
                let tls_enabled = tls_mode == "tls" || tls_mode == "reality";
                value.insert("tls".to_string(), json!(tls_enabled));
                if tls_enabled {
                    value.insert(
                        "skip-cert-verify".to_string(),
                        json!(resolve_skip_cert_verify(&config, &client, false)),
                    );
                }
                value.insert(
                    "network".to_string(),
                    json!(resolve_config_string_value(
                        &config,
                        &["stream_type"],
                        "tcp"
                    )),
                );
                if tls_mode == "tls" || tls_mode == "reality" {
                    let servername = resolve_config_string_value(
                        &config,
                        &["sni"],
                        if !tls_host.is_empty() { &tls_host } else { "" },
                    );
                    if !servername.is_empty() {
                        value.insert("servername".to_string(), json!(servername));
                    }
                    if let Some(alpn) = normalize_alpn(config.get("alpn")) {
                        value.insert("alpn".to_string(), json!(alpn));
                    }
                }
                if tls_mode == "reality" {
                    let mut reality_opts = serde_json::Map::new();
                    reality_opts.insert(
                        "public-key".to_string(),
                        json!(resolve_reality_public_key(&config, &client)),
                    );
                    let short_id = pick_random_short_id(config.get("short_ids"));
                    if !short_id.is_empty() {
                        reality_opts.insert("short-id".to_string(), json!(short_id));
                    }
                    value.insert("reality-opts".to_string(), Value::Object(reality_opts));
                    value.insert(
                        "client-fingerprint".to_string(),
                        json!(resolve_config_string_value(
                            &config,
                            &["fingerprint"],
                            "chrome"
                        )),
                    );
                }
                if tls_mode == "tls" {
                    if let Some(ech_opts) = build_clash_ech_opts(&config, &client) {
                        value.insert("ech-opts".to_string(), ech_opts);
                    }
                }
                if ensure_string(config.get("stream_type")) == "ws" {
                    let mut ws_opts = serde_json::Map::new();
                    ws_opts.insert(
                        "path".to_string(),
                        json!(normalize_path(config.get("path"))),
                    );
                    let host = if tls_mode == "tls" || tls_mode == "reality" {
                        tls_host.clone()
                    } else {
                        resolve_config_string_value(&config, &["server", "host", "sni"], &server)
                    };
                    ws_opts.insert("headers".to_string(), json!({ "Host": host }));
                    value.insert("ws-opts".to_string(), Value::Object(ws_opts));
                } else if ensure_string(config.get("stream_type")) == "grpc" {
                    value.insert(
            "grpc-opts".to_string(),
            json!({ "grpc-service-name": resolve_config_string_value(&config, &["service_name"], "grpc") })
          );
                }
                proxy = Some(value);
            }
            "vless" => {
                let mut value = serde_json::Map::new();
                value.insert("name".to_string(), json!(name));
                value.insert("type".to_string(), json!("vless"));
                value.insert("server".to_string(), json!(server));
                value.insert("port".to_string(), json!(port));
                value.insert(
                    "uuid".to_string(),
                    json!(user.uuid.clone().unwrap_or_default()),
                );
                value.insert(
                    "encryption".to_string(),
                    json!(resolve_vless_client_encryption(&config, &client)),
                );
                let tls_mode = ensure_string(config.get("tls_type"));
                let tls_enabled = tls_mode == "tls" || tls_mode == "reality";
                value.insert("tls".to_string(), json!(tls_enabled));
                if tls_enabled {
                    value.insert(
                        "skip-cert-verify".to_string(),
                        json!(resolve_skip_cert_verify(&config, &client, false)),
                    );
                }
                value.insert(
                    "network".to_string(),
                    json!(resolve_config_string_value(
                        &config,
                        &["stream_type"],
                        "tcp"
                    )),
                );
                if tls_mode == "tls" {
                    let servername = resolve_config_string_value(
                        &config,
                        &["sni"],
                        if !tls_host.is_empty() { &tls_host } else { "" },
                    );
                    if !servername.is_empty() {
                        value.insert("servername".to_string(), json!(servername));
                    }
                    if let Some(alpn) = normalize_alpn(config.get("alpn")) {
                        value.insert("alpn".to_string(), json!(alpn));
                    }
                }
                if tls_mode == "reality" {
                    let mut reality_opts = serde_json::Map::new();
                    reality_opts.insert(
                        "public-key".to_string(),
                        json!(resolve_reality_public_key(&config, &client)),
                    );
                    let short_id = pick_random_short_id(config.get("short_ids"));
                    if !short_id.is_empty() {
                        reality_opts.insert("short-id".to_string(), json!(short_id));
                    }
                    value.insert("reality-opts".to_string(), Value::Object(reality_opts));
                    value.insert(
                        "client-fingerprint".to_string(),
                        json!(resolve_config_string_value(
                            &config,
                            &["fingerprint"],
                            "chrome"
                        )),
                    );
                    if !tls_host.is_empty() {
                        value.insert("servername".to_string(), json!(tls_host));
                    }
                }
                if tls_mode == "tls" {
                    if let Some(ech_opts) = build_clash_ech_opts(&config, &client) {
                        value.insert("ech-opts".to_string(), ech_opts);
                    }
                }
                let flow = resolve_config_string(&config, &["flow"]);
                if !flow.is_empty() {
                    value.insert("flow".to_string(), json!(flow));
                }
                if ensure_string(config.get("stream_type")) == "ws" {
                    let mut ws_opts = serde_json::Map::new();
                    ws_opts.insert(
                        "path".to_string(),
                        json!(normalize_path(config.get("path"))),
                    );
                    let host = if tls_mode == "tls" || tls_mode == "reality" {
                        tls_host.clone()
                    } else {
                        resolve_config_string_value(&config, &["server", "host", "sni"], &server)
                    };
                    ws_opts.insert("headers".to_string(), json!({ "Host": host }));
                    value.insert("ws-opts".to_string(), Value::Object(ws_opts));
                } else if ensure_string(config.get("stream_type")) == "grpc" {
                    value.insert(
            "grpc-opts".to_string(),
            json!({ "grpc-service-name": resolve_config_string_value(&config, &["service_name"], "grpc") })
          );
                }
                proxy = Some(value);
            }
            "trojan" => {
                let mut value = serde_json::Map::new();
                value.insert("name".to_string(), json!(name));
                value.insert("type".to_string(), json!("trojan"));
                value.insert("server".to_string(), json!(server));
                value.insert("port".to_string(), json!(port));
                value.insert(
                    "password".to_string(),
                    json!(user.passwd.clone().unwrap_or_default()),
                );
                value.insert(
                    "skip-cert-verify".to_string(),
                    json!(resolve_skip_cert_verify(&config, &client, false)),
                );
                let sni = resolve_config_string_value(
                    &config,
                    &["sni"],
                    if !tls_host.is_empty() {
                        &tls_host
                    } else {
                        &server
                    },
                );
                value.insert("sni".to_string(), json!(sni));
                if ensure_string(config.get("tls_type")) == "reality" {
                    let mut reality_opts = serde_json::Map::new();
                    reality_opts.insert(
                        "public-key".to_string(),
                        json!(resolve_reality_public_key(&config, &client)),
                    );
                    let short_id = pick_random_short_id(config.get("short_ids"));
                    if !short_id.is_empty() {
                        reality_opts.insert("short-id".to_string(), json!(short_id));
                    }
                    value.insert("reality-opts".to_string(), Value::Object(reality_opts));
                    value.insert(
                        "client-fingerprint".to_string(),
                        json!(resolve_config_string_value(
                            &config,
                            &["fingerprint"],
                            "chrome"
                        )),
                    );
                }
                if ensure_string(config.get("tls_type")) != "reality" {
                    if let Some(ech_opts) = build_clash_ech_opts(&config, &client) {
                        value.insert("ech-opts".to_string(), ech_opts);
                    }
                }
                if ensure_string(config.get("stream_type")) == "ws" {
                    value.insert("network".to_string(), json!("ws"));
                    let mut ws_opts = serde_json::Map::new();
                    ws_opts.insert(
                        "path".to_string(),
                        json!(normalize_path(config.get("path"))),
                    );
                    let host = tls_host.clone();
                    ws_opts.insert("headers".to_string(), json!({ "Host": host }));
                    value.insert("ws-opts".to_string(), Value::Object(ws_opts));
                } else if ensure_string(config.get("stream_type")) == "grpc" {
                    value.insert("network".to_string(), json!("grpc"));
                    value.insert(
            "grpc-opts".to_string(),
            json!({ "grpc-service-name": resolve_config_string_value(&config, &["service_name"], "grpc") })
          );
                }
                proxy = Some(value);
            }
            "ss" => {
                let mut value = serde_json::Map::new();
                value.insert("name".to_string(), json!(name));
                value.insert("type".to_string(), json!("ss"));
                value.insert("server".to_string(), json!(server));
                value.insert("port".to_string(), json!(port));
                value.insert(
                    "cipher".to_string(),
                    json!(resolve_config_string_value(
                        &config,
                        &["cipher"],
                        "aes-128-gcm"
                    )),
                );
                value.insert(
                    "password".to_string(),
                    json!(build_ss2022_password(
                        &config,
                        &user.passwd.clone().unwrap_or_default()
                    )),
                );
                value.insert("udp".to_string(), json!(true));
                let obfs = resolve_config_string(&config, &["obfs"]);
                if !obfs.is_empty() && obfs != "plain" {
                    value.insert("plugin".to_string(), json!("obfs"));
                    let mode = if obfs == "simple_obfs_http" {
                        "http"
                    } else {
                        "tls"
                    };
                    let host = resolve_config_string_value(&config, &["server"], "bing.com");
                    value.insert(
                        "plugin-opts".to_string(),
                        json!({ "mode": mode, "host": host }),
                    );
                }
                proxy = Some(value);
            }
            "ssr" => {
                let mut value = serde_json::Map::new();
                value.insert("name".to_string(), json!(name));
                value.insert("type".to_string(), json!("ssr"));
                value.insert("server".to_string(), json!(server));
                value.insert("port".to_string(), json!(port));
                value.insert(
                    "cipher".to_string(),
                    json!(resolve_config_string_value(
                        &config,
                        &["method", "cipher"],
                        "aes-256-cfb"
                    )),
                );
                value.insert(
                    "password".to_string(),
                    json!(resolve_config_string(&config, &["password"])),
                );
                value.insert(
                    "protocol".to_string(),
                    json!(resolve_config_string_value(
                        &config,
                        &["protocol"],
                        "origin"
                    )),
                );
                value.insert(
                    "obfs".to_string(),
                    json!(resolve_config_string_value(&config, &["obfs"], "plain")),
                );
                value.insert("udp".to_string(), json!(true));
                let protocol_param = resolve_config_string(
                    &config,
                    &["protocol_param", "protocol-param", "protocolparam"],
                );
                let fallback_param = if user.id > 0 {
                    format!("{}:{}", user.id, user.passwd.clone().unwrap_or_default())
                } else {
                    String::new()
                };
                let resolved_protocol_param = if protocol_param.is_empty() {
                    fallback_param
                } else {
                    protocol_param
                };
                let obfs_param =
                    resolve_config_string(&config, &["obfs_param", "obfs-param", "obfsparam"]);
                let obfs_param_candidate = if obfs_param.is_empty() {
                    resolve_config_string_value(&config, &["server"], "")
                } else {
                    obfs_param
                };
                let obfs_name = resolve_config_string(&config, &["obfs"]).to_lowercase();
                let need_obfs_param = [
                    "http_simple",
                    "http_post",
                    "tls1.2_ticket_auth",
                    "simple_obfs_http",
                    "simple_obfs_tls",
                ]
                .contains(&obfs_name.as_str());
                if !resolved_protocol_param.is_empty() {
                    value.insert("protocol-param".to_string(), json!(resolved_protocol_param));
                }
                if need_obfs_param && !obfs_param_candidate.is_empty() {
                    value.insert("obfs-param".to_string(), json!(obfs_param_candidate));
                }
                proxy = Some(value);
            }
            "anytls" => {
                let mut value = serde_json::Map::new();
                value.insert("name".to_string(), json!(name));
                value.insert("type".to_string(), json!("anytls"));
                value.insert("server".to_string(), json!(server));
                value.insert("port".to_string(), json!(port));
                value.insert(
                    "password".to_string(),
                    json!(resolve_config_string_value(
                        &config,
                        &["password"],
                        &user.passwd.clone().unwrap_or_default()
                    )),
                );
                value.insert(
                    "client-fingerprint".to_string(),
                    json!(resolve_config_string_value(
                        &config,
                        &["fingerprint"],
                        "chrome"
                    )),
                );
                value.insert("udp".to_string(), json!(true));
                value.insert(
                    "idle-session-check-interval".to_string(),
                    json!(ensure_i64(config.get("idle_session_check_interval"), 30)),
                );
                value.insert(
                    "idle-session-timeout".to_string(),
                    json!(ensure_i64(config.get("idle_session_timeout"), 30)),
                );
                value.insert(
                    "min-idle-session".to_string(),
                    json!(ensure_i64(config.get("min_idle_session"), 0)),
                );
                value.insert(
                    "skip-cert-verify".to_string(),
                    json!(resolve_skip_cert_verify(&config, &client, false)),
                );
                let sni = resolve_config_string_value(&config, &["sni"], &tls_host);
                if !sni.is_empty() {
                    value.insert("sni".to_string(), json!(sni));
                }
                if let Some(alpn) = normalize_alpn(config.get("alpn")) {
                    value.insert("alpn".to_string(), json!(alpn));
                }
                if let Some(ech_opts) = build_clash_ech_opts(&config, &client) {
                    value.insert("ech-opts".to_string(), ech_opts);
                }
                proxy = Some(value);
            }
            "hysteria" => {
                let mut value = serde_json::Map::new();
                value.insert("name".to_string(), json!(name));
                value.insert("type".to_string(), json!("hysteria2"));
                value.insert("server".to_string(), json!(server));
                value.insert("port".to_string(), json!(port));
                value.insert(
                    "password".to_string(),
                    json!(user.passwd.clone().unwrap_or_default()),
                );
                value.insert(
                    "skip-cert-verify".to_string(),
                    json!(resolve_skip_cert_verify(&config, &client, false)),
                );
                let sni = resolve_config_string_value(&config, &["sni"], &tls_host);
                if !sni.is_empty() {
                    value.insert("sni".to_string(), json!(sni));
                }
                let obfs = resolve_config_string(&config, &["obfs"]);
                if !obfs.is_empty() && obfs != "plain" {
                    value.insert("obfs".to_string(), json!(obfs));
                    let obfs_password = resolve_config_string(&config, &["obfs_password"]);
                    if !obfs_password.is_empty() {
                        value.insert("obfs-password".to_string(), json!(obfs_password));
                    }
                }
                let up = resolve_config_string(&config, &["up_mbps"]);
                if !up.is_empty() {
                    value.insert("up".to_string(), json!(format!("{up} Mbps")));
                }
                let down = resolve_config_string(&config, &["down_mbps"]);
                if !down.is_empty() {
                    value.insert("down".to_string(), json!(format!("{down} Mbps")));
                }
                if let Some(alpn) = normalize_alpn(config.get("alpn")) {
                    value.insert("alpn".to_string(), json!(alpn));
                }
                if let Some(ech_opts) = build_clash_ech_opts(&config, &client) {
                    value.insert("ech-opts".to_string(), ech_opts);
                }
                proxy = Some(value);
            }
            _ => {}
        }

        if let Some(proxy_value) = proxy {
            proxies.push(Value::Object(proxy_value));
            proxy_names.push(name);
        }
    }

    let clash = build_clash_template(&proxy_names, proxies);
    dump_yaml(&clash)
}

fn build_clash_template(proxy_names: &[String], proxies: Vec<Value>) -> Value {
    let safe_proxy_names = unique_names(proxy_names);
    let manual_list = with_fallback(safe_proxy_names.clone(), &["DIRECT"]);
    let region_matches = collect_region_matches(&safe_proxy_names);
    let available_region_tags: Vec<String> = REGION_TAGS
        .iter()
        .filter(|tag| {
            region_matches
                .get(&tag.to_string())
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        })
        .map(|tag| (*tag).to_string())
        .collect();
    let available_region_set: HashSet<String> = available_region_tags.iter().cloned().collect();

    let mut groups: Vec<Value> = Vec::new();
    let mut node_select = vec!["🚀 手动切换".to_string()];
    node_select.extend(available_region_tags.clone());
    node_select.push("DIRECT".to_string());
    groups.push(json!({
      "name": "🚀 节点选择",
      "type": "select",
      "proxies": node_select
    }));
    groups.push(json!({
      "name": "🚀 手动切换",
      "type": "select",
      "proxies": manual_list
    }));
    groups.push(json!({
      "name": "📲 电报消息",
      "type": "select",
      "proxies": filter_region_tags(
        vec![
          "🚀 节点选择",
          "🇸🇬 狮城节点",
          "🇭🇰 香港节点",
          "🇨🇳 台湾节点",
          "🇯🇵 日本节点",
          "🇺🇲 美国节点",
          "🇰🇷 韩国节点",
          "🚀 手动切换",
          "DIRECT"
        ]
        .iter()
        .map(|item| item.to_string())
        .collect(),
        &available_region_set
      )
    }));
    groups.push(json!({
      "name": "💬 Ai平台",
      "type": "select",
      "proxies": filter_region_tags(
        vec![
          "🚀 节点选择",
          "🇸🇬 狮城节点",
          "🇭🇰 香港节点",
          "🇨🇳 台湾节点",
          "🇯🇵 日本节点",
          "🇺🇲 美国节点",
          "🇰🇷 韩国节点",
          "🚀 手动切换",
          "DIRECT"
        ]
        .iter()
        .map(|item| item.to_string())
        .collect(),
        &available_region_set
      )
    }));
    groups.push(json!({
      "name": "📹 油管视频",
      "type": "select",
      "proxies": filter_region_tags(
        vec![
          "🚀 节点选择",
          "🇸🇬 狮城节点",
          "🇭🇰 香港节点",
          "🇨🇳 台湾节点",
          "🇯🇵 日本节点",
          "🇺🇲 美国节点",
          "🇰🇷 韩国节点",
          "🚀 手动切换",
          "DIRECT"
        ]
        .iter()
        .map(|item| item.to_string())
        .collect(),
        &available_region_set
      )
    }));
    groups.push(json!({
      "name": "🎥 奈飞视频",
      "type": "select",
      "proxies": filter_region_tags(
        vec![
          "🎥 奈飞节点",
          "🚀 节点选择",
          "🇸🇬 狮城节点",
          "🇭🇰 香港节点",
          "🇨🇳 台湾节点",
          "🇯🇵 日本节点",
          "🇺🇲 美国节点",
          "🇰🇷 韩国节点",
          "🚀 手动切换",
          "DIRECT"
        ]
        .iter()
        .map(|item| item.to_string())
        .collect(),
        &available_region_set
      )
    }));
    groups.push(json!({
      "name": "📺 巴哈姆特",
      "type": "select",
      "proxies": filter_region_tags(
        vec!["🇨🇳 台湾节点", "🚀 节点选择", "🚀 手动切换", "DIRECT"]
          .iter()
          .map(|item| item.to_string())
          .collect(),
        &available_region_set
      )
    }));
    groups.push(json!({
      "name": "📺 哔哩哔哩",
      "type": "select",
      "proxies": filter_region_tags(
        vec!["🎯 全球直连", "🇨🇳 台湾节点", "🇭🇰 香港节点"]
          .iter()
          .map(|item| item.to_string())
          .collect(),
        &available_region_set
      )
    }));
    groups.push(json!({
      "name": "🌍 国外媒体",
      "type": "select",
      "proxies": filter_region_tags(
        vec![
          "🚀 节点选择",
          "🇭🇰 香港节点",
          "🇨🇳 台湾节点",
          "🇸🇬 狮城节点",
          "🇯🇵 日本节点",
          "🇺🇲 美国节点",
          "🇰🇷 韩国节点",
          "🚀 手动切换",
          "DIRECT"
        ]
        .iter()
        .map(|item| item.to_string())
        .collect(),
        &available_region_set
      )
    }));
    groups.push(json!({
      "name": "🌏 国内媒体",
      "type": "select",
      "proxies": filter_region_tags(
        vec!["DIRECT", "🇭🇰 香港节点", "🇨🇳 台湾节点", "🇸🇬 狮城节点", "🇯🇵 日本节点", "🚀 手动切换"]
          .iter()
          .map(|item| item.to_string())
          .collect(),
        &available_region_set
      )
    }));
    groups.push(json!({
      "name": "📢 谷歌FCM",
      "type": "select",
      "proxies": filter_region_tags(
        vec![
          "DIRECT",
          "🚀 节点选择",
          "🇺🇲 美国节点",
          "🇭🇰 香港节点",
          "🇨🇳 台湾节点",
          "🇸🇬 狮城节点",
          "🇯🇵 日本节点",
          "🇰🇷 韩国节点",
          "🚀 手动切换"
        ]
        .iter()
        .map(|item| item.to_string())
        .collect(),
        &available_region_set
      )
    }));
    groups.push(json!({
      "name": "Ⓜ️ 微软Bing",
      "type": "select",
      "proxies": filter_region_tags(
        vec![
          "DIRECT",
          "🚀 节点选择",
          "🇺🇲 美国节点",
          "🇭🇰 香港节点",
          "🇨🇳 台湾节点",
          "🇸🇬 狮城节点",
          "🇯🇵 日本节点",
          "🇰🇷 韩国节点",
          "🚀 手动切换"
        ]
        .iter()
        .map(|item| item.to_string())
        .collect(),
        &available_region_set
      )
    }));
    groups.push(json!({
      "name": "Ⓜ️ 微软云盘",
      "type": "select",
      "proxies": filter_region_tags(
        vec![
          "DIRECT",
          "🚀 节点选择",
          "🇺🇲 美国节点",
          "🇭🇰 香港节点",
          "🇨🇳 台湾节点",
          "🇸🇬 狮城节点",
          "🇯🇵 日本节点",
          "🇰🇷 韩国节点",
          "🚀 手动切换"
        ]
        .iter()
        .map(|item| item.to_string())
        .collect(),
        &available_region_set
      )
    }));
    groups.push(json!({
      "name": "Ⓜ️ 微软服务",
      "type": "select",
      "proxies": filter_region_tags(
        vec![
          "DIRECT",
          "🚀 节点选择",
          "🇺🇲 美国节点",
          "🇭🇰 香港节点",
          "🇨🇳 台湾节点",
          "🇸🇬 狮城节点",
          "🇯🇵 日本节点",
          "🇰🇷 韩国节点",
          "🚀 手动切换"
        ]
        .iter()
        .map(|item| item.to_string())
        .collect(),
        &available_region_set
      )
    }));
    groups.push(json!({
      "name": "🍎 苹果服务",
      "type": "select",
      "proxies": filter_region_tags(
        vec![
          "DIRECT",
          "🚀 节点选择",
          "🇺🇲 美国节点",
          "🇭🇰 香港节点",
          "🇨🇳 台湾节点",
          "🇸🇬 狮城节点",
          "🇯🇵 日本节点",
          "🇰🇷 韩国节点",
          "🚀 手动切换"
        ]
        .iter()
        .map(|item| item.to_string())
        .collect(),
        &available_region_set
      )
    }));
    groups.push(json!({
      "name": "🎮 游戏平台",
      "type": "select",
      "proxies": filter_region_tags(
        vec![
          "DIRECT",
          "🚀 节点选择",
          "🇺🇲 美国节点",
          "🇭🇰 香港节点",
          "🇨🇳 台湾节点",
          "🇸🇬 狮城节点",
          "🇯🇵 日本节点",
          "🇰🇷 韩国节点",
          "🚀 手动切换"
        ]
        .iter()
        .map(|item| item.to_string())
        .collect(),
        &available_region_set
      )
    }));
    groups.push(json!({
      "name": "🎶 网易音乐",
      "type": "select",
      "proxies": vec!["DIRECT", "🚀 节点选择"]
    }));
    groups.push(json!({
      "name": "🎯 全球直连",
      "type": "select",
      "proxies": vec!["DIRECT", "🚀 节点选择"]
    }));
    groups.push(json!({
      "name": "🛑 广告拦截",
      "type": "select",
      "proxies": vec!["REJECT", "DIRECT"]
    }));
    groups.push(json!({
      "name": "🍃 应用净化",
      "type": "select",
      "proxies": vec!["REJECT", "DIRECT"]
    }));
    groups.push(json!({
      "name": "🐟 漏网之鱼",
      "type": "select",
      "proxies": filter_region_tags(
        vec![
          "🚀 节点选择",
          "DIRECT",
          "🇭🇰 香港节点",
          "🇨🇳 台湾节点",
          "🇸🇬 狮城节点",
          "🇯🇵 日本节点",
          "🇺🇲 美国节点",
          "🇰🇷 韩国节点",
          "🚀 手动切换"
        ]
        .iter()
        .map(|item| item.to_string())
        .collect(),
        &available_region_set
      )
    }));

    for tag in available_region_tags {
        let matched = region_matches.get(&tag).cloned().unwrap_or_default();
        let matched = unique_names(&matched);
        if matched.is_empty() {
            continue;
        }
        groups.push(json!({
          "name": tag,
          "type": "select",
          "proxies": matched
        }));
    }

    let rules = load_clash_rules().clone();
    let mut clash = match clone_clash_template() {
        Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    clash.insert("proxies".to_string(), Value::Array(proxies));
    clash.insert("proxy-groups".to_string(), Value::Array(groups));
    clash.insert("rules".to_string(), Value::Array(rules));
    Value::Object(clash)
}

fn resolve_outbound_tag(name: &str, used_tags: &mut HashSet<String>, fallback: &str) -> String {
    let base = if name.trim().is_empty() {
        fallback
    } else {
        name.trim()
    };
    let mut tag = base.to_string();
    let mut index = 2;
    while used_tags.contains(&tag) {
        tag = format!("{base}-{index}");
        index += 1;
    }
    used_tags.insert(tag.clone());
    tag
}

fn resolve_sni(config: &Value, tls_host: &str, server: &str) -> String {
    let sni = resolve_config_string_value(
        config,
        &["sni"],
        if !tls_host.is_empty() {
            tls_host
        } else {
            server
        },
    );
    sni
}

fn build_singbox_tls(
    config: &Value,
    tls_host: &str,
    server: &str,
    mode: &str,
    client: &Value,
) -> Option<Value> {
    if mode == "none" {
        return None;
    }
    let mut tls = serde_json::Map::new();
    tls.insert("enabled".to_string(), json!(true));
    tls.insert(
        "server_name".to_string(),
        json!(resolve_sni(config, tls_host, server)),
    );
    tls.insert(
        "insecure".to_string(),
        json!(resolve_skip_cert_verify(config, client, false)),
    );
    if let Some(alpn) = normalize_alpn(config.get("alpn")) {
        tls.insert("alpn".to_string(), json!(alpn));
    }
    if mode == "tls" {
        if let Some(ech) = build_singbox_ech(config, client) {
            tls.insert("ech".to_string(), ech);
        }
    }

    if mode == "reality" {
        let server_name = if !tls_host.is_empty() {
            tls_host.to_string()
        } else {
            resolve_first_string(config.get("server_names"))
        };
        let server_name = if server_name.is_empty() {
            server.to_string()
        } else {
            server_name
        };
        tls.insert("server_name".to_string(), json!(server_name));
        let utls = json!({ "enabled": true, "fingerprint": resolve_config_string_value(config, &["fingerprint"], "chrome") });
        tls.insert("utls".to_string(), utls);
        let mut reality = serde_json::Map::new();
        reality.insert("enabled".to_string(), json!(true));
        reality.insert(
            "public_key".to_string(),
            json!(resolve_reality_public_key(config, client)),
        );
        let short_id = pick_random_short_id(config.get("short_ids"));
        if !short_id.is_empty() {
            reality.insert("short_id".to_string(), json!(short_id));
        }
        tls.insert("reality".to_string(), Value::Object(reality));
    }

    Some(Value::Object(tls))
}

fn apply_singbox_transport(
    outbound: &mut serde_json::Map<String, Value>,
    config: &Value,
    server: &str,
    tls_host: &str,
) {
    let stream_type = resolve_config_string_value(config, &["stream_type"], "tcp").to_lowercase();
    if stream_type == "ws" {
        let host = resolve_config_string_value(
            config,
            &["server"],
            if !tls_host.is_empty() {
                tls_host
            } else {
                server
            },
        );
        let mut transport = serde_json::Map::new();
        transport.insert("type".to_string(), json!("ws"));
        transport.insert(
            "path".to_string(),
            json!(normalize_path(config.get("path"))),
        );
        if !host.is_empty() {
            transport.insert("headers".to_string(), json!({ "Host": host }));
        }
        outbound.insert("transport".to_string(), Value::Object(transport));
    } else if stream_type == "grpc" {
        outbound.insert(
      "transport".to_string(),
      json!({ "type": "grpc", "service_name": resolve_config_string_value(config, &["service_name"], "grpc") })
    );
    }
}

fn collect_singbox_groups(name: &str, tag: &str, groups: &mut HashMap<String, Vec<String>>) {
    for group in REGION_TAGS.iter() {
        if match_region(group, name) {
            groups
                .entry((*group).to_string())
                .or_default()
                .push(tag.to_string());
        }
    }
}

pub fn generate_singbox_config(nodes: &[SubscriptionNode], user: &SubscriptionUser) -> String {
    let mut node_outbounds: Vec<Value> = Vec::new();
    let mut node_tags: Vec<String> = Vec::new();
    let mut used_tags: HashSet<String> = HashSet::new();
    let mut group_matches: HashMap<String, Vec<String>> = HashMap::new();
    for tag in REGION_TAGS.iter() {
        group_matches.insert((*tag).to_string(), Vec::new());
    }

    for node in nodes {
        let endpoint = resolve_node_endpoint(node);
        let node_type = node.node_type.to_lowercase();
        let server = endpoint.server;
        let port = endpoint.port;
        let tls_host = endpoint.tls_host;
        let config = endpoint.config;
        let client = endpoint.client;
        if node_type == "vless" && is_vless_encryption_enabled(&config, &client) {
            continue;
        }

        let tag = resolve_outbound_tag(
            &node.name,
            &mut used_tags,
            &format!("{}-{}", node.node_type, node.id),
        );
        let match_name = if node.name.is_empty() {
            tag.clone()
        } else {
            node.name.clone()
        };
        let mut outbound: Option<serde_json::Map<String, Value>> = None;

        match node_type.as_str() {
            "ss" => {
                let mut value = serde_json::Map::new();
                value.insert("type".to_string(), json!("shadowsocks"));
                value.insert("tag".to_string(), json!(tag));
                value.insert("server".to_string(), json!(server));
                value.insert("server_port".to_string(), json!(port));
                value.insert(
                    "method".to_string(),
                    json!(resolve_config_string_value(
                        &config,
                        &["cipher"],
                        "aes-128-gcm"
                    )),
                );
                value.insert(
                    "password".to_string(),
                    json!(build_ss2022_password(
                        &config,
                        &user.passwd.clone().unwrap_or_default()
                    )),
                );
                outbound = Some(value);
            }
            "v2ray" => {
                let mut value = serde_json::Map::new();
                value.insert("type".to_string(), json!("vmess"));
                value.insert("tag".to_string(), json!(tag));
                value.insert("server".to_string(), json!(server));
                value.insert("server_port".to_string(), json!(port));
                value.insert(
                    "uuid".to_string(),
                    json!(user.uuid.clone().unwrap_or_default()),
                );
                value.insert(
                    "alter_id".to_string(),
                    json!(ensure_i64(config.get("aid"), 0)),
                );
                value.insert(
                    "security".to_string(),
                    json!(resolve_config_string_value(&config, &["security"], "auto")),
                );
                let tls_type = ensure_string(config.get("tls_type"));
                let tls_mode = if tls_type == "reality" {
                    "reality"
                } else if tls_type == "tls" {
                    "tls"
                } else {
                    "none"
                };
                if let Some(tls) = build_singbox_tls(&config, &tls_host, &server, tls_mode, &client)
                {
                    value.insert("tls".to_string(), tls);
                }
                apply_singbox_transport(&mut value, &config, &server, &tls_host);
                outbound = Some(value);
            }
            "vless" => {
                let mut value = serde_json::Map::new();
                value.insert("type".to_string(), json!("vless"));
                value.insert("tag".to_string(), json!(tag));
                value.insert("server".to_string(), json!(server));
                value.insert("server_port".to_string(), json!(port));
                value.insert(
                    "uuid".to_string(),
                    json!(user.uuid.clone().unwrap_or_default()),
                );
                let flow = resolve_config_string(&config, &["flow"]);
                if !flow.is_empty() {
                    value.insert("flow".to_string(), json!(flow));
                }
                let tls_type = ensure_string(config.get("tls_type"));
                let tls_mode = if tls_type == "reality" {
                    "reality"
                } else if tls_type == "tls" {
                    "tls"
                } else {
                    "none"
                };
                if let Some(tls) = build_singbox_tls(&config, &tls_host, &server, tls_mode, &client)
                {
                    value.insert("tls".to_string(), tls);
                }
                apply_singbox_transport(&mut value, &config, &server, &tls_host);
                outbound = Some(value);
            }
            "trojan" => {
                let mut value = serde_json::Map::new();
                value.insert("type".to_string(), json!("trojan"));
                value.insert("tag".to_string(), json!(tag));
                value.insert("server".to_string(), json!(server));
                value.insert("server_port".to_string(), json!(port));
                value.insert(
                    "password".to_string(),
                    json!(user.passwd.clone().unwrap_or_default()),
                );
                let tls_mode = if ensure_string(config.get("tls_type")) == "reality" {
                    "reality"
                } else {
                    "tls"
                };
                if let Some(tls) = build_singbox_tls(&config, &tls_host, &server, tls_mode, &client)
                {
                    value.insert("tls".to_string(), tls);
                }
                apply_singbox_transport(&mut value, &config, &server, &tls_host);
                outbound = Some(value);
            }
            "hysteria" => {
                let mut value = serde_json::Map::new();
                value.insert("type".to_string(), json!("hysteria2"));
                value.insert("tag".to_string(), json!(tag));
                value.insert("server".to_string(), json!(server));
                value.insert("server_port".to_string(), json!(port));
                value.insert(
                    "password".to_string(),
                    json!(user.passwd.clone().unwrap_or_default()),
                );
                value.insert(
                    "up_mbps".to_string(),
                    json!(ensure_f64(config.get("up_mbps"), 100.0)),
                );
                value.insert(
                    "down_mbps".to_string(),
                    json!(ensure_f64(config.get("down_mbps"), 100.0)),
                );
                if let Some(tls) = build_singbox_tls(&config, &tls_host, &server, "tls", &client) {
                    value.insert("tls".to_string(), tls);
                }
                let obfs = resolve_config_string(&config, &["obfs"]);
                if !obfs.is_empty() && obfs != "plain" {
                    let mut obfs_value = serde_json::Map::new();
                    obfs_value.insert("type".to_string(), json!(obfs));
                    let obfs_password = resolve_config_string(&config, &["obfs_password"]);
                    if !obfs_password.is_empty() {
                        obfs_value.insert("password".to_string(), json!(obfs_password));
                    }
                    value.insert("obfs".to_string(), Value::Object(obfs_value));
                }
                outbound = Some(value);
            }
            "anytls" => {
                let mut value = serde_json::Map::new();
                value.insert("type".to_string(), json!("anytls"));
                value.insert("tag".to_string(), json!(tag));
                value.insert("server".to_string(), json!(server));
                value.insert("server_port".to_string(), json!(port));
                value.insert(
                    "password".to_string(),
                    json!(resolve_config_string_value(
                        &config,
                        &["password"],
                        &user.passwd.clone().unwrap_or_default()
                    )),
                );
                if let Some(tls) = build_singbox_tls(&config, &tls_host, &server, "tls", &client) {
                    value.insert("tls".to_string(), tls);
                }
                outbound = Some(value);
            }
            _ => {}
        }

        if let Some(outbound_value) = outbound {
            node_outbounds.push(Value::Object(outbound_value));
            node_tags.push(tag.clone());
            collect_singbox_groups(&match_name, &tag, &mut group_matches);
        }
    }

    let all_region_tags: Vec<String> = REGION_TAGS.iter().map(|tag| (*tag).to_string()).collect();
    let available_region_tags: Vec<String> = all_region_tags
        .iter()
        .filter(|tag| {
            group_matches
                .get(*tag)
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    let mut group_overrides: HashMap<String, Option<Vec<String>>> = HashMap::new();
    group_overrides.insert(
        "🚀 节点选择".to_string(),
        Some({
            let mut list = vec!["🚀 手动切换".to_string()];
            list.extend(available_region_tags.clone());
            list.push("DIRECT".to_string());
            unique_names(&list)
        }),
    );
    group_overrides.insert("🚀 手动切换".to_string(), Some(node_tags.clone()));
    group_overrides.insert(
        "GLOBAL".to_string(),
        Some({
            let mut list = vec!["DIRECT".to_string()];
            list.extend(node_tags.clone());
            list
        }),
    );
    for tag in available_region_tags.iter() {
        if let Some(list) = group_matches.get(tag) {
            if !list.is_empty() {
                group_overrides.insert(tag.clone(), Some(list.clone()));
            }
        }
    }

    let singbox = build_singbox_template(
        node_outbounds,
        &group_overrides,
        &all_region_tags,
        &available_region_tags,
    );
    serde_json::to_string_pretty(&singbox).unwrap_or_else(|_| "{}".to_string())
}

fn build_singbox_template(
    node_outbounds: Vec<Value>,
    group_overrides: &HashMap<String, Option<Vec<String>>>,
    region_tags: &[String],
    available_region_tags: &[String],
) -> Value {
    let mut template = clone_singbox_template();
    let mut base_outbounds: Vec<Value> = Vec::new();
    let mut selector_outbounds: Vec<Value> = Vec::new();
    let mut existing_selector_tags: HashSet<String> = HashSet::new();

    let region_tag_set: HashSet<String> = region_tags.iter().cloned().collect();
    let available_region_set: HashSet<String> = available_region_tags.iter().cloned().collect();

    if let Some(outbounds) = template.get_mut("outbounds") {
        if let Value::Array(list) = outbounds {
            for outbound in list.iter() {
                if let Value::Object(map) = outbound {
                    let outbound_type = ensure_string(map.get("type"));
                    if outbound_type == "selector" {
                        selector_outbounds.push(outbound.clone());
                        let tag = ensure_string(map.get("tag"));
                        if !tag.is_empty() {
                            existing_selector_tags.insert(tag);
                        }
                    } else if ["direct", "block"].contains(&outbound_type.as_str()) {
                        base_outbounds.push(outbound.clone());
                    }
                }
            }
        }
    }

    for tag in available_region_tags.iter() {
        if existing_selector_tags.contains(tag) {
            continue;
        }
        let outbounds = match group_overrides.get(tag) {
            Some(Some(values)) if !values.is_empty() => unique_names(values),
            _ => continue,
        };
        selector_outbounds.push(json!({
            "type": "selector",
            "tag": tag,
            "outbounds": outbounds
        }));
        existing_selector_tags.insert(tag.clone());
    }

    let mut filtered_selectors: Vec<Value> = Vec::new();

    for outbound in selector_outbounds {
        let mut outbound_value = outbound.clone();
        let tag = if let Value::Object(map) = &outbound_value {
            ensure_string(map.get("tag"))
        } else {
            String::new()
        };

        if region_tag_set.contains(&tag) && !available_region_set.contains(&tag) {
            continue;
        }

        if let Some(override_value) = group_overrides.get(&tag) {
            if override_value.is_none() {
                continue;
            }
        }

        let mut outbounds_list: Option<Vec<String>> = None;
        if let Some(override_value) = group_overrides.get(&tag) {
            if let Some(values) = override_value.clone() {
                outbounds_list = Some(unique_names(&values));
            }
        }

        if outbounds_list.is_none() {
            if let Value::Object(map) = &outbound_value {
                if let Some(Value::Array(items)) = map.get("outbounds") {
                    let list = items
                        .iter()
                        .map(|item| ensure_string(Some(item)))
                        .collect::<Vec<String>>();
                    outbounds_list = Some(list);
                }
            }
        }

        if let Some(mut list) = outbounds_list {
            if !region_tag_set.is_empty() {
                list = filter_region_tags(list, &available_region_set);
            }
            let list = unique_names(&list);
            if let Value::Object(map) = &mut outbound_value {
                map.insert(
                    "outbounds".to_string(),
                    Value::Array(list.into_iter().map(Value::String).collect()),
                );
            }
        }

        filtered_selectors.push(outbound_value);
    }

    let mut combined = Vec::new();
    combined.extend(base_outbounds);
    combined.extend(node_outbounds);
    combined.extend(filtered_selectors);
    if let Value::Object(map) = &mut template {
        map.insert("outbounds".to_string(), Value::Array(combined));
    }
    template
}

fn push_option(options: &mut Vec<String>, key: &str, value: &Value) {
    if value.is_null() {
        return;
    }
    match value {
        Value::Bool(value) => {
            options.push(format!("{key}={}", if *value { "true" } else { "false" }))
        }
        Value::String(value) => {
            if !value.is_empty() {
                options.push(format!("{key}={value}"));
            }
        }
        Value::Number(value) => options.push(format!("{key}={value}")),
        _ => {}
    }
}

fn format_quantumultx_entry(protocol: &str, server: &str, port: i64, options: &[String]) -> String {
    let endpoint = format!("{}:{}", format_host_for_url(server), port);
    if options.is_empty() {
        format!("{protocol}={endpoint}")
    } else {
        format!("{protocol}={endpoint}, {}", options.join(", "))
    }
}

fn get_header_host(server: &str, tls_host: &str, config: &Value) -> String {
    let candidate = resolve_config_string(config, &["sni", "host", "server"]);
    if !candidate.is_empty() {
        candidate
    } else if !tls_host.is_empty() {
        tls_host.to_string()
    } else {
        server.to_string()
    }
}

fn apply_stream_options(options: &mut Vec<String>, server: &str, tls_host: &str, config: &Value) {
    let stream_type = resolve_config_string_value(config, &["stream_type"], "tcp").to_lowercase();
    let is_tls = ensure_string(config.get("tls_type")) == "tls";
    let host = get_header_host(server, tls_host, config);
    if stream_type == "ws" {
        options.push(format!("obfs={}", if is_tls { "wss" } else { "ws" }));
        options.push(format!("obfs-host={host}"));
        options.push(format!("obfs-uri={}", normalize_path(config.get("path"))));
    } else if stream_type == "http" {
        options.push("obfs=http".to_string());
        options.push(format!("obfs-host={host}"));
        options.push(format!("obfs-uri={}", normalize_path(config.get("path"))));
    } else if is_tls {
        options.push("obfs=over-tls".to_string());
        options.push(format!("obfs-host={host}"));
    }
}

fn normalize_obfs(obfs: &str) -> String {
    match obfs.to_lowercase().as_str() {
        "simple_obfs_http" => "http".to_string(),
        "simple_obfs_tls" => "tls".to_string(),
        _ => obfs.to_string(),
    }
}

fn build_quantumultx_ss_entry(
    name: &str,
    server: &str,
    port: i64,
    tls_host: &str,
    config: &Value,
    user: &SubscriptionUser,
) -> String {
    let mut options: Vec<String> = Vec::new();
    let password = build_ss2022_password(config, &user.passwd.clone().unwrap_or_default());
    options.push(format!(
        "method={}",
        resolve_config_string_value(config, &["cipher"], "aes-128-gcm")
    ));
    options.push(format!("password={password}"));
    options.push("fast-open=false".to_string());
    options.push("udp-relay=true".to_string());
    let obfs_raw = resolve_config_string(config, &["obfs"]);
    let obfs = normalize_obfs(&obfs_raw);
    if !obfs.is_empty() && obfs != "plain" {
        options.push(format!("obfs={obfs}"));
        options.push(format!(
            "obfs-host={}",
            get_header_host(server, tls_host, config)
        ));
        options.push(format!("obfs-uri={}", normalize_path(config.get("path"))));
    }
    options.push(format!("tag={name}"));
    format_quantumultx_entry("shadowsocks", server, port, &options)
}

fn build_quantumultx_vmess_entry(
    name: &str,
    server: &str,
    port: i64,
    tls_host: &str,
    config: &Value,
    user: &SubscriptionUser,
) -> String {
    let stream_type = resolve_config_string_value(config, &["stream_type"], "tcp").to_lowercase();
    if stream_type == "grpc" {
        return String::new();
    }
    let mut options: Vec<String> = Vec::new();
    options.push("method=chacha20-poly1305".to_string());
    options.push(format!(
        "password={}",
        user.uuid.clone().unwrap_or_default()
    ));
    options.push("fast-open=false".to_string());
    options.push("udp-relay=false".to_string());
    if let Some(aead) = config.get("aead") {
        if !aead.is_null() {
            push_option(&mut options, "aead", aead);
        }
    }
    apply_stream_options(&mut options, server, tls_host, config);
    options.push(format!("tag={name}"));
    format_quantumultx_entry("vmess", server, port, &options)
}

fn build_quantumultx_vless_entry(
    name: &str,
    server: &str,
    port: i64,
    tls_host: &str,
    config: &Value,
    user: &SubscriptionUser,
    client: &Value,
) -> String {
    let stream_type = resolve_config_string_value(config, &["stream_type"], "tcp").to_lowercase();
    if stream_type == "grpc" {
        return String::new();
    }
    let mut options: Vec<String> = Vec::new();
    options.push("method=none".to_string());
    options.push(format!(
        "password={}",
        user.uuid.clone().unwrap_or_default()
    ));
    options.push("fast-open=false".to_string());
    options.push("udp-relay=true".to_string());
    if ensure_string(config.get("tls_type")) == "reality" {
        options.push("obfs=over-tls".to_string());
        options.push(format!(
            "obfs-host={}",
            get_header_host(server, tls_host, config)
        ));
        options.push(format!(
            "reality-base64-pubkey={}",
            resolve_reality_public_key(config, client)
        ));
        let short_id = pick_random_short_id(config.get("short_ids"));
        if !short_id.is_empty() {
            options.push(format!("reality-hex-shortid={short_id}"));
        }
        let flow = resolve_config_string(config, &["flow"]);
        if !flow.is_empty() {
            options.push(format!("vless-flow={flow}"));
        }
    } else {
        apply_stream_options(&mut options, server, tls_host, config);
    }
    options.push(format!("tag={name}"));
    format_quantumultx_entry("vless", server, port, &options)
}

fn build_quantumultx_trojan_entry(
    name: &str,
    server: &str,
    port: i64,
    tls_host: &str,
    config: &Value,
    user: &SubscriptionUser,
) -> String {
    let stream_type = resolve_config_string_value(config, &["stream_type"], "tcp").to_lowercase();
    if stream_type == "grpc" {
        return String::new();
    }
    let mut options: Vec<String> = Vec::new();
    let is_websocket = stream_type == "ws";
    let host = get_header_host(server, tls_host, config);
    options.push(format!(
        "password={}",
        user.passwd.clone().unwrap_or_default()
    ));
    options.push("fast-open=false".to_string());
    options.push("tls-verification=false".to_string());
    if is_websocket {
        options.push("obfs=wss".to_string());
        options.push(format!("obfs-host={host}"));
        options.push(format!("obfs-uri={}", normalize_path(config.get("path"))));
        options.push("udp-relay=true".to_string());
    } else {
        options.push("over-tls=true".to_string());
        options.push(format!("tls-host={host}"));
        options.push("udp-relay=false".to_string());
    }
    options.push(format!("tag={name}"));
    format_quantumultx_entry("trojan", server, port, &options)
}

fn build_quantumultx_anytls_entry(
    name: &str,
    server: &str,
    port: i64,
    tls_host: &str,
    config: &Value,
    user: &SubscriptionUser,
    client: &Value,
) -> String {
    let mut options: Vec<String> = Vec::new();
    let user_password = user.passwd.clone().unwrap_or_default();
    let password = if !user_password.is_empty() {
        user_password
    } else {
        resolve_config_string(config, &["password"])
    };
    options.push(format!("password={password}"));
    options.push("over-tls=true".to_string());

    let host = get_header_host(server, tls_host, config);
    if !host.is_empty() {
        options.push(format!("tls-host={host}"));
    }

    if ensure_string(config.get("tls_type")) == "reality" {
        let public_key = resolve_reality_public_key(config, client);
        if !public_key.is_empty() {
            options.push(format!("reality-base64-pubkey={public_key}"));
        }
        let short_id = pick_random_short_id(config.get("short_ids"));
        if !short_id.is_empty() {
            options.push(format!("reality-hex-shortid={short_id}"));
        }
    }

    options.push("udp-relay=true".to_string());
    options.push(format!("tag={name}"));
    format_quantumultx_entry("anytls", server, port, &options)
}

pub fn generate_quantumultx_config(nodes: &[SubscriptionNode], user: &SubscriptionUser) -> String {
    let mut entries: Vec<String> = Vec::new();
    for node in nodes {
        let endpoint = resolve_node_endpoint(node);
        let node_type = node.node_type.to_lowercase();
        let server = endpoint.server;
        let port = endpoint.port;
        let tls_host = endpoint.tls_host;
        let config = endpoint.config;
        let client = endpoint.client;
        if node_type == "vless" && is_vless_encryption_enabled(&config, &client) {
            continue;
        }
        let name = node.name.clone();
        let line = match node_type.as_str() {
            "v2ray" => {
                build_quantumultx_vmess_entry(&name, &server, port, &tls_host, &config, user)
            }
            "vless" => build_quantumultx_vless_entry(
                &name, &server, port, &tls_host, &config, user, &client,
            ),
            "trojan" => {
                build_quantumultx_trojan_entry(&name, &server, port, &tls_host, &config, user)
            }
            "ss" => build_quantumultx_ss_entry(&name, &server, port, &tls_host, &config, user),
            "anytls" => build_quantumultx_anytls_entry(
                &name, &server, port, &tls_host, &config, user, &client,
            ),
            _ => String::new(),
        };
        if !line.is_empty() {
            entries.push(line);
        }
    }
    entries.join("\n")
}

pub fn generate_shadowrocket_config(nodes: &[SubscriptionNode], user: &SubscriptionUser) -> String {
    let mut lines: Vec<String> = Vec::new();
    for node in nodes {
        let endpoint = resolve_node_endpoint(node);
        let node_type = node.node_type.to_lowercase();
        let server = endpoint.server;
        let port = endpoint.port;
        let tls_host = endpoint.tls_host;
        let config = endpoint.config;
        let client = endpoint.client;
        let name = node.name.clone();

        let line = match node_type.as_str() {
            "v2ray" => generate_vmess_link(&name, &server, port, &tls_host, &config, &client, user),
            "vless" => generate_vless_link(&name, &server, port, &tls_host, &config, &client, user),
            "trojan" => {
                generate_trojan_link(&name, &server, port, &tls_host, &config, &client, user)
            }
            "ss" => generate_shadowsocks_link(&name, &server, port, &tls_host, &config, user),
            "hysteria" => {
                generate_hysteria_link(&name, &server, port, &tls_host, &config, &client, user)
            }
            "anytls" => {
                generate_anytls_link(&name, &server, port, &tls_host, &config, &client, user)
            }
            _ => String::new(),
        };
        if !line.is_empty() {
            lines.push(line);
        }
    }
    lines.join("\n")
}

pub fn generate_surge_config(nodes: &[SubscriptionNode], user: &SubscriptionUser) -> String {
    let mut proxies: Vec<String> = Vec::new();
    let mut proxy_names: Vec<String> = Vec::new();
    for node in nodes {
        let endpoint = resolve_node_endpoint(node);
        let node_type = node.node_type.to_lowercase();
        let server = endpoint.server;
        let port = endpoint.port;
        let tls_host = endpoint.tls_host;
        let config = endpoint.config;
        let client = endpoint.client;
        if node_type == "vless" && is_vless_encryption_enabled(&config, &client) {
            continue;
        }
        let name = node.name.clone();

        let proxy = match node_type.as_str() {
            "v2ray" | "vless" => format!(
                "{name} = vmess, {server}, {port}, username=\"{}\", tls=true",
                user.uuid.clone().unwrap_or_default()
            ),
            "trojan" => format!(
                "{name} = trojan, {server}, {port}, password={}, sni={}",
                user.passwd.clone().unwrap_or_default(),
                resolve_config_string_value(
                    &config,
                    &["sni"],
                    if !tls_host.is_empty() {
                        &tls_host
                    } else {
                        &server
                    }
                )
            ),
            "ss" => format!(
                "{name} = shadowsocks, {server}, {port}, encrypt-method={}, password={}",
                resolve_config_string_value(&config, &["cipher"], "aes-128-gcm"),
                build_ss2022_password(&config, &user.passwd.clone().unwrap_or_default())
            ),
            "hysteria" => format!(
                "{name} = hysteria2, {server}, {port}, password={}",
                user.passwd.clone().unwrap_or_default()
            ),
            "anytls" => {
                let mut line = format!(
                    "{name} = anytls, {server}, {port}, password={}",
                    resolve_config_string_value(
                        &config,
                        &["password"],
                        &user.passwd.clone().unwrap_or_default()
                    )
                );
                if resolve_skip_cert_verify(&config, &client, false) {
                    line.push_str(", skip-cert-verify=true");
                }
                let sni = resolve_config_string(&config, &["sni"]);
                let sni = if !sni.is_empty() {
                    sni
                } else if !tls_host.is_empty() {
                    tls_host.clone()
                } else {
                    String::new()
                };
                if !sni.is_empty() {
                    line.push_str(&format!(", sni={sni}"));
                }
                line
            }
            _ => String::new(),
        };

        if !proxy.is_empty() {
            proxies.push(proxy);
            proxy_names.push(name);
        }
    }
    build_surge_template(&proxies, &proxy_names)
}

fn build_surge_template(proxies: &[String], proxy_names: &[String]) -> String {
    let safe_proxy_names = unique_names(&proxy_names.to_vec());
    let manual_list = with_fallback(safe_proxy_names.clone(), &["DIRECT"]);
    let region_matches = collect_region_matches(&safe_proxy_names);
    let available_region_tags: Vec<String> = REGION_TAGS
        .iter()
        .filter(|tag| {
            region_matches
                .get(&tag.to_string())
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        })
        .map(|tag| (*tag).to_string())
        .collect();
    let available_region_set: HashSet<String> = available_region_tags.iter().cloned().collect();

    let mut proxy_lines = vec!["DIRECT = direct".to_string()];
    proxy_lines.extend_from_slice(proxies);
    let proxy_section = proxy_lines.join("\n");

    let mut groups: Vec<String> = Vec::new();
    groups.push(format!(
        "🚀 节点选择 = select,{}",
        ["🚀 手动切换".to_string()]
            .into_iter()
            .chain(available_region_tags.clone())
            .chain(std::iter::once("DIRECT".to_string()))
            .collect::<Vec<String>>()
            .join(",")
    ));
    groups.push(format!("🚀 手动切换 = select,{}", manual_list.join(",")));
    groups.push(format!(
        "📲 电报消息 = select,{}",
        filter_region_tags(
            vec![
                "🚀 节点选择",
                "🇸🇬 狮城节点",
                "🇭🇰 香港节点",
                "🇨🇳 台湾节点",
                "🇯🇵 日本节点",
                "🇺🇲 美国节点",
                "🇰🇷 韩国节点",
                "🚀 手动切换",
                "DIRECT"
            ]
            .iter()
            .map(|item| item.to_string())
            .collect(),
            &available_region_set
        )
        .join(",")
    ));
    groups.push(format!(
        "💬 Ai平台 = select,{}",
        filter_region_tags(
            vec![
                "🚀 节点选择",
                "🇸🇬 狮城节点",
                "🇭🇰 香港节点",
                "🇨🇳 台湾节点",
                "🇯🇵 日本节点",
                "🇺🇲 美国节点",
                "🇰🇷 韩国节点",
                "🚀 手动切换",
                "DIRECT"
            ]
            .iter()
            .map(|item| item.to_string())
            .collect(),
            &available_region_set
        )
        .join(",")
    ));
    groups.push(format!(
        "📹 油管视频 = select,{}",
        filter_region_tags(
            vec![
                "🚀 节点选择",
                "🇸🇬 狮城节点",
                "🇭🇰 香港节点",
                "🇨🇳 台湾节点",
                "🇯🇵 日本节点",
                "🇺🇲 美国节点",
                "🇰🇷 韩国节点",
                "🚀 手动切换",
                "DIRECT"
            ]
            .iter()
            .map(|item| item.to_string())
            .collect(),
            &available_region_set
        )
        .join(",")
    ));
    groups.push(format!(
        "🎥 奈飞视频 = select,{}",
        filter_region_tags(
            vec![
                "🎥 奈飞节点",
                "🚀 节点选择",
                "🇸🇬 狮城节点",
                "🇭🇰 香港节点",
                "🇨🇳 台湾节点",
                "🇯🇵 日本节点",
                "🇺🇲 美国节点",
                "🇰🇷 韩国节点",
                "🚀 手动切换",
                "DIRECT"
            ]
            .iter()
            .map(|item| item.to_string())
            .collect(),
            &available_region_set
        )
        .join(",")
    ));
    groups.push(format!(
        "📺 巴哈姆特 = select,{}",
        filter_region_tags(
            vec!["🇨🇳 台湾节点", "🚀 节点选择", "🚀 手动切换", "DIRECT"]
                .iter()
                .map(|item| item.to_string())
                .collect(),
            &available_region_set
        )
        .join(",")
    ));
    groups.push(format!(
        "📺 哔哩哔哩 = select,{}",
        filter_region_tags(
            vec!["🎯 全球直连", "🇨🇳 台湾节点", "🇭🇰 香港节点"]
                .iter()
                .map(|item| item.to_string())
                .collect(),
            &available_region_set
        )
        .join(",")
    ));
    groups.push(format!(
        "🌍 国外媒体 = select,{}",
        filter_region_tags(
            vec![
                "🚀 节点选择",
                "🇭🇰 香港节点",
                "🇨🇳 台湾节点",
                "🇸🇬 狮城节点",
                "🇯🇵 日本节点",
                "🇺🇲 美国节点",
                "🇰🇷 韩国节点",
                "🚀 手动切换",
                "DIRECT"
            ]
            .iter()
            .map(|item| item.to_string())
            .collect(),
            &available_region_set
        )
        .join(",")
    ));
    groups.push(format!(
        "🌏 国内媒体 = select,{}",
        filter_region_tags(
            vec![
                "DIRECT",
                "🇭🇰 香港节点",
                "🇨🇳 台湾节点",
                "🇸🇬 狮城节点",
                "🇯🇵 日本节点",
                "🚀 手动切换"
            ]
            .iter()
            .map(|item| item.to_string())
            .collect(),
            &available_region_set
        )
        .join(",")
    ));
    groups.push(format!(
        "📢 谷歌FCM = select,{}",
        filter_region_tags(
            vec![
                "DIRECT",
                "🚀 节点选择",
                "🇺🇲 美国节点",
                "🇭🇰 香港节点",
                "🇨🇳 台湾节点",
                "🇸🇬 狮城节点",
                "🇯🇵 日本节点",
                "🇰🇷 韩国节点",
                "🚀 手动切换"
            ]
            .iter()
            .map(|item| item.to_string())
            .collect(),
            &available_region_set
        )
        .join(",")
    ));
    groups.push(format!(
        "Ⓜ️ 微软Bing = select,{}",
        filter_region_tags(
            vec![
                "DIRECT",
                "🚀 节点选择",
                "🇺🇲 美国节点",
                "🇭🇰 香港节点",
                "🇨🇳 台湾节点",
                "🇸🇬 狮城节点",
                "🇯🇵 日本节点",
                "🇰🇷 韩国节点",
                "🚀 手动切换"
            ]
            .iter()
            .map(|item| item.to_string())
            .collect(),
            &available_region_set
        )
        .join(",")
    ));
    groups.push(format!(
        "Ⓜ️ 微软云盘 = select,{}",
        filter_region_tags(
            vec![
                "DIRECT",
                "🚀 节点选择",
                "🇺🇲 美国节点",
                "🇭🇰 香港节点",
                "🇨🇳 台湾节点",
                "🇸🇬 狮城节点",
                "🇯🇵 日本节点",
                "🇰🇷 韩国节点",
                "🚀 手动切换"
            ]
            .iter()
            .map(|item| item.to_string())
            .collect(),
            &available_region_set
        )
        .join(",")
    ));
    groups.push(format!(
        "Ⓜ️ 微软服务 = select,{}",
        filter_region_tags(
            vec![
                "DIRECT",
                "🚀 节点选择",
                "🇺🇲 美国节点",
                "🇭🇰 香港节点",
                "🇨🇳 台湾节点",
                "🇸🇬 狮城节点",
                "🇯🇵 日本节点",
                "🇰🇷 韩国节点",
                "🚀 手动切换"
            ]
            .iter()
            .map(|item| item.to_string())
            .collect(),
            &available_region_set
        )
        .join(",")
    ));
    groups.push(format!(
        "🍎 苹果服务 = select,{}",
        filter_region_tags(
            vec![
                "DIRECT",
                "🚀 节点选择",
                "🇺🇲 美国节点",
                "🇭🇰 香港节点",
                "🇨🇳 台湾节点",
                "🇸🇬 狮城节点",
                "🇯🇵 日本节点",
                "🇰🇷 韩国节点",
                "🚀 手动切换"
            ]
            .iter()
            .map(|item| item.to_string())
            .collect(),
            &available_region_set
        )
        .join(",")
    ));
    groups.push(format!(
        "🎮 游戏平台 = select,{}",
        filter_region_tags(
            vec![
                "DIRECT",
                "🚀 节点选择",
                "🇺🇲 美国节点",
                "🇭🇰 香港节点",
                "🇨🇳 台湾节点",
                "🇸🇬 狮城节点",
                "🇯🇵 日本节点",
                "🇰🇷 韩国节点",
                "🚀 手动切换"
            ]
            .iter()
            .map(|item| item.to_string())
            .collect(),
            &available_region_set
        )
        .join(",")
    ));
    groups.push("🎶 网易音乐 = select,DIRECT,🚀 节点选择".to_string());
    groups.push("🎯 全球直连 = select,DIRECT,🚀 节点选择".to_string());
    groups.push("🛑 广告拦截 = select,REJECT,DIRECT".to_string());
    groups.push("🍃 应用净化 = select,REJECT,DIRECT".to_string());
    groups.push(format!(
        "🐟 漏网之鱼 = select,{}",
        filter_region_tags(
            vec![
                "🚀 节点选择",
                "DIRECT",
                "🇭🇰 香港节点",
                "🇨🇳 台湾节点",
                "🇸🇬 狮城节点",
                "🇯🇵 日本节点",
                "🇺🇲 美国节点",
                "🇰🇷 韩国节点",
                "🚀 手动切换"
            ]
            .iter()
            .map(|item| item.to_string())
            .collect(),
            &available_region_set
        )
        .join(",")
    ));

    for tag in available_region_tags {
        let matched = region_matches.get(&tag).cloned().unwrap_or_default();
        let matched = unique_names(&matched);
        if matched.is_empty() {
            continue;
        }
        groups.push(format!("{tag} = select,{}", matched.join(",")));
    }

    let groups_section = groups.join("\n");
    clone_surge_template()
        .replace("{proxy_section}", &proxy_section)
        .replace("{groups}", &groups_section)
}

pub fn subscription_expire_timestamp(expire_time: Option<NaiveDateTime>) -> i64 {
    expire_time
        .map(|value| Utc.from_utc_datetime(&value).timestamp())
        .unwrap_or(0)
}
