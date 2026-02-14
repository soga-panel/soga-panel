use serde_json::{json, Value};
use std::collections::HashSet;

fn normalize_ids(list: Vec<i64>) -> Vec<i64> {
  let mut result: Vec<i64> = Vec::new();
  let mut seen: HashSet<i64> = HashSet::new();
  for item in list {
    if item <= 0 {
      continue;
    }
    if seen.contains(&item) {
      continue;
    }
    seen.insert(item);
    result.push(item);
  }
  result
}

fn parse_id_value(value: &Value) -> Option<i64> {
  value
    .as_i64()
    .or_else(|| value.as_str().and_then(|text| text.trim().parse::<i64>().ok()))
}

pub fn parse_remote_account_id_list(value: &Value) -> Vec<i64> {
  match value {
    Value::Number(num) => normalize_ids(num.as_i64().into_iter().collect()),
    Value::Array(items) => normalize_ids(items.iter().filter_map(parse_id_value).collect()),
    Value::String(text) => parse_remote_account_id_list_text(text),
    _ => Vec::new()
  }
}

pub fn parse_remote_account_id_list_text(value: &str) -> Vec<i64> {
  let trimmed = value.trim();
  if trimmed.is_empty() {
    return Vec::new();
  }

  if trimmed.chars().all(|c| c.is_ascii_digit()) {
    if let Ok(num) = trimmed.parse::<i64>() {
      return normalize_ids(vec![num]);
    }
  }

  if let Ok(parsed) = serde_json::from_str::<Value>(trimmed) {
    if let Value::Number(_) | Value::Array(_) | Value::String(_) = parsed {
      return parse_remote_account_id_list(&parsed);
    }
  }

  normalize_ids(
    trimmed
      .split(|c: char| c == ',' || c == '，' || c.is_whitespace())
      .filter_map(|item| {
        let part = item.trim();
        if part.is_empty() {
          None
        } else {
          part.parse::<i64>().ok()
        }
      })
      .collect()
  )
}

pub fn format_remote_account_id_for_response_text(value: &str) -> Value {
  let ids = parse_remote_account_id_list_text(value);
  if ids.is_empty() {
    return json!(0);
  }
  if ids.len() == 1 {
    return json!(ids[0]);
  }
  json!(ids)
}

pub fn serialize_remote_account_id_for_db(value: &Value) -> Result<String, String> {
  let ids = parse_remote_account_id_list(value);
  if ids.is_empty() {
    return Err("远程账号 ID 不能为空".to_string());
  }
  if ids.len() == 1 {
    return Ok(ids[0].to_string());
  }
  serde_json::to_string(&ids).map_err(|_| "远程账号 ID 格式不正确".to_string())
}

