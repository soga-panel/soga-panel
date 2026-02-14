use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use chrono::{Datelike, Duration, Local, NaiveDateTime, Utc};
use data_encoding::BASE32_NOPAD;
use rand::Rng;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;
use urlencoding::encode;

use crate::crypto::{hash_password, random_string, sha256_hex, verify_password};
use crate::referral::{ensure_user_invite_code_with_length, regenerate_invite_code};
use crate::response::{error, success};
use crate::shared_ids::{
  format_remote_account_id_for_response_text,
  parse_remote_account_id_list_text
};
use crate::state::AppState;
use crate::totp::verify_totp;

use super::auth::{
  decrypt_two_factor_secret,
  encrypt_two_factor_secret,
  list_passkeys,
  normalize_backup_code,
  parse_backup_codes,
  require_user_id,
  list_system_configs
};

pub fn router() -> Router<AppState> {
  Router::new()
    .route("/profile", get(get_profile))
    .route("/profile", put(put_profile))
    .route("/login-logs", get(get_login_logs))
    .route("/change-password", post(post_change_password))
    .route("/nodes", get(get_nodes))
    .route("/reset-subscription-token", post(post_reset_subscription_token))
    .route("/subscription-logs", get(get_subscription_logs))
    .route("/traffic-records", get(get_traffic_records))
    .route("/traffic/trends", get(get_traffic_trends))
    .route("/traffic/summary", get(get_traffic_summary))
    .route("/traffic-stats", get(get_traffic_stats))
    .route("/traffic/manual-update", post(post_traffic_manual_update))
    .route("/online-ips", get(get_online_ips))
    .route("/online-ips-detail", get(get_online_ips_detail))
    .route("/online-devices", get(get_online_devices))
    .route("/bark-settings", get(get_bark_settings))
    .route("/bark-settings", put(put_bark_settings))
    .route("/bark-test", post(post_bark_test))
    .route("/passkeys", get(get_passkeys))
    .route("/passkeys/{id}", delete(delete_passkey))
    .route("/two-factor/setup", post(post_two_factor_setup))
    .route("/two-factor/enable", post(post_two_factor_enable))
    .route("/two-factor/backup-codes", post(post_two_factor_backup_codes))
    .route("/two-factor/disable", post(post_two_factor_disable))
    .route("/invite", get(get_invite))
    .route("/invite/regenerate", post(post_invite_regenerate))
    .route("/invite/referrals", get(get_invite_referrals))
    .route("/referrals", get(get_referrals))
    .route("/tickets/unread-count", get(get_ticket_unread_count))
    .route("/tickets", get(get_tickets))
    .route("/tickets", post(post_ticket))
    .route("/tickets/{id}", get(get_ticket_detail))
    .route("/tickets/{id}/replies", post(post_ticket_reply))
    .route("/tickets/{id}/close", post(post_ticket_close))
    .route("/audit-rules", get(get_audit_rules))
    .route("/audit-logs", get(get_audit_logs))
    .route("/audit-overview", get(get_audit_overview))
    .route("/shared-ids", get(get_shared_ids))
}

async fn get_passkeys(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let passkeys = match list_passkeys(&state, user_id).await {
    Ok(value) => value,
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  let items: Vec<Value> = passkeys.into_iter().map(|row| row.to_value()).collect();
  success(json!({ "items": items }), "Success").into_response()
}

async fn get_profile(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let user = match get_user_profile(&state, user_id).await {
    Ok(Some(value)) => value,
    Ok(None) => return error(StatusCode::NOT_FOUND, "用户不存在", None),
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  let transfer_enable = user.transfer_enable;
  let transfer_used = user.transfer_total;
  let transfer_remain = if transfer_enable > transfer_used {
    transfer_enable - transfer_used
  } else {
    0
  };
  let traffic_percentage = if transfer_enable > 0 {
    ((transfer_used as f64 / transfer_enable as f64) * 100.0).round() as i64
  } else {
    0
  };

  let now = Local::now().naive_local();
  let is_expired = user.expire_time.map(|value| value <= now).unwrap_or(false);
  let days_remaining = user.expire_time.map(|value| {
    if value <= now {
      0
    } else {
      let seconds = (value - now).num_seconds();
      let days = (seconds as f64 / 86_400.0).ceil() as i64;
      if days < 0 { 0 } else { days }
    }
  });

  let configs = list_system_configs(&state).await.unwrap_or_default();
  let traffic_reset_day = configs
    .get("traffic_reset_day")
    .and_then(|value| value.parse::<i64>().ok())
    .unwrap_or(0);
  let mut subscription_url = configs
    .get("subscription_url")
    .or_else(|| configs.get("site_url"))
    .cloned()
    .or_else(|| state.env.site_url.clone())
    .unwrap_or_default();
  if subscription_url.is_empty() {
    if let Some(value) = state.env.site_url.clone() {
      subscription_url = value;
    }
  }

  success(
    json!({
      "id": user.id,
      "email": user.email,
      "username": user.username,
      "uuid": user.uuid,
      "passwd": user.passwd,
      "token": user.token,
      "is_admin": user.is_admin == 1,
      "class": user.class_level,
      "class_expire_time": format_datetime(user.class_expire_time),
      "expire_time": format_datetime(user.expire_time),
      "is_expired": is_expired,
      "days_remaining": days_remaining,
      "speed_limit": user.speed_limit,
      "device_limit": user.device_limit,
      "tcp_limit": user.tcp_limit,
      "upload_traffic": user.upload_traffic,
      "download_traffic": user.download_traffic,
      "upload_today": user.upload_today,
      "download_today": user.download_today,
      "transfer_total": transfer_used,
      "transfer_enable": transfer_enable,
      "transfer_remain": transfer_remain,
      "traffic_percentage": traffic_percentage,
      "reg_date": format_datetime(user.reg_date),
      "last_login_time": format_datetime(user.last_login_time),
      "last_login_ip": user.last_login_ip,
      "status": user.status,
      "invite_code": user.invite_code,
      "invited_by": user.invited_by,
      "invite_limit": user.invite_limit,
      "invite_used": user.invite_used,
      "rebate_available": user.rebate_available,
      "rebate_total": user.rebate_total,
      "register_ip": user.register_ip,
      "traffic_reset_day": traffic_reset_day,
      "subscription_url": subscription_url,
      "two_factor_enabled": user.two_factor_enabled == 1,
      "has_two_factor_backup_codes": user
        .two_factor_backup_codes
        .as_ref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    }),
    "Success"
  )
  .into_response()
}

#[derive(Deserialize)]
struct UpdateProfileRequest {
  username: Option<String>,
  email: Option<String>
}

async fn put_profile(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Json(body): Json<UpdateProfileRequest>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let current = match get_user_profile(&state, user_id).await {
    Ok(Some(value)) => value,
    Ok(None) => return error(StatusCode::NOT_FOUND, "用户不存在", None),
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  let has_username_input = body.username.is_some();
  let has_email_input = body.email.is_some();

  let next_username = body
    .username
    .unwrap_or_else(|| current.username.clone())
    .trim()
    .to_string();
  let next_email_raw = body
    .email
    .unwrap_or_else(|| current.email.clone())
    .trim()
    .to_string();
  let next_email = if next_email_raw.is_empty() {
    next_email_raw
  } else {
    next_email_raw.to_lowercase()
  };

  let is_username_changed = has_username_input && next_username != current.username;
  let is_email_changed = has_email_input && next_email != current.email.to_lowercase();

  if is_username_changed && is_email_changed {
    return error(StatusCode::BAD_REQUEST, "不能同时修改用户名和邮箱，请分别修改", None);
  }

  let mut new_username: Option<String> = None;
  let mut new_email: Option<String> = None;

  if is_username_changed {
    if next_username.is_empty() {
      return error(StatusCode::BAD_REQUEST, "用户名不能为空", None);
    }
    match get_user_id_by_username(&state, &next_username).await {
      Ok(Some(existing_id)) if existing_id != user_id => {
        return error(StatusCode::BAD_REQUEST, "用户名已被占用", None);
      }
      Ok(_) => {}
      Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
    }
    new_username = Some(next_username);
  }

  if is_email_changed {
    if next_email.is_empty() {
      return error(StatusCode::BAD_REQUEST, "邮箱不能为空", None);
    }
    match get_user_id_by_email(&state, &next_email).await {
      Ok(Some(existing_id)) if existing_id != user_id => {
        return error(StatusCode::BAD_REQUEST, "该邮箱已被使用，请选择其他邮箱", None);
      }
      Ok(_) => {}
      Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
    }
    new_email = Some(next_email);
  }

  if new_username.is_none() && new_email.is_none() {
    return error(StatusCode::BAD_REQUEST, "没有需要更新的字段", None);
  }

  if let Err(message) = update_user_profile(&state, user_id, new_username, new_email).await {
    return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None);
  }

  success(Value::Null, "资料已更新").into_response()
}

#[derive(Deserialize)]
struct LoginLogQuery {
  limit: Option<i64>
}

async fn get_login_logs(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Query(query): Query<LoginLogQuery>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let mut limit = query.limit.unwrap_or(20);
  if limit <= 0 {
    limit = 20;
  }
  if limit > 100 {
    limit = 100;
  }

  let logs = match list_login_logs(&state, user_id, limit).await {
    Ok(value) => value,
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  success(Value::Array(logs), "Success").into_response()
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
  old_password: Option<String>,
  current_password: Option<String>,
  new_password: Option<String>
}

async fn post_change_password(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Json(body): Json<ChangePasswordRequest>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let current = body.old_password.or(body.current_password).unwrap_or_default();
  let new_password = body.new_password.unwrap_or_default();
  if current.trim().is_empty() || new_password.trim().is_empty() {
    return error(StatusCode::BAD_REQUEST, "参数缺失", None);
  }

  let user = match get_user_password_info(&state, user_id).await {
    Ok(Some(value)) => value,
    Ok(None) => return error(StatusCode::NOT_FOUND, "用户不存在", None),
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  if !verify_password(&current, &user.password_hash) {
    return error(StatusCode::BAD_REQUEST, "原密码错误", None);
  }

  if let Err(message) = update_user_password(&state, user_id, &hash_password(&new_password)).await {
    return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None);
  }

  success(Value::Null, "密码已更新").into_response()
}

#[derive(Deserialize)]
struct NodesQuery {
  page: Option<i64>,
  limit: Option<i64>,
  #[serde(rename = "type")]
  node_type: Option<String>,
  status: Option<String>
}

async fn get_nodes(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Query(query): Query<NodesQuery>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let page = query.page.unwrap_or(1).max(1);
  let mut limit = query.limit.unwrap_or(10);
  if limit <= 0 {
    limit = 10;
  }
  if limit > 200 {
    limit = 200;
  }
  let offset = (page - 1) * limit;

  let type_filter = query
    .node_type
    .as_ref()
    .map(|value| value.trim().to_lowercase())
    .filter(|value| !value.is_empty());

  let status_filter = query.status.as_ref().and_then(|value| {
    let trimmed = value.trim();
    if trimmed.is_empty() {
      None
    } else {
      Some(trimmed == "1")
    }
  });

  let user_class = match get_user_class(&state, user_id).await {
    Ok(Some(value)) => value,
    Ok(None) => return error(StatusCode::NOT_FOUND, "用户不存在", None),
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  let mut where_clause = "WHERE status = 1".to_string();
  if type_filter.is_some() {
    where_clause.push_str(" AND LOWER(type) = ?");
  }

  let nodes_sql = format!(
    r#"
    SELECT
      id,
      name,
      type,
      node_class,
      node_bandwidth,
      node_bandwidth_limit,
      traffic_multiplier,
      bandwidthlimit_resetday,
      CAST(node_config AS CHAR) AS node_config,
      status,
      created_at
    FROM nodes
    {where_clause}
    ORDER BY node_class ASC,
      CASE
        WHEN LOWER(type) IN ('ss', 'shadowsocks') THEN 1
        WHEN LOWER(type) IN ('ssr', 'shadowsocksr') THEN 2
        WHEN LOWER(type) IN ('v2ray', 'vmess') THEN 3
        WHEN LOWER(type) IN ('vless') THEN 4
        WHEN LOWER(type) IN ('trojan') THEN 5
        WHEN LOWER(type) IN ('hysteria', 'hysteria2') THEN 6
        WHEN LOWER(type) IN ('anytls') THEN 7
        ELSE 99
      END ASC,
      name ASC,
      id ASC
    LIMIT ? OFFSET ?
    "#
  );

  let mut node_query = sqlx::query(&nodes_sql);
  if let Some(type_value) = type_filter.clone() {
    node_query = node_query.bind(type_value);
  }
  let rows = node_query
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await;

  let nodes = match rows {
    Ok(values) => values,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let total_row = sqlx::query("SELECT COUNT(*) as total FROM nodes WHERE status = 1")
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string());
  let total_row = match total_row {
    Ok(value) => value,
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  let filtered_total_sql = format!("SELECT COUNT(*) as total FROM nodes {where_clause}");
  let mut filtered_query = sqlx::query(&filtered_total_sql);
  if let Some(type_value) = type_filter.clone() {
    filtered_query = filtered_query.bind(type_value);
  }
  let filtered_total_row = filtered_query
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string());
  let filtered_total_row = match filtered_total_row {
    Ok(value) => value,
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  let accessible_row = sqlx::query("SELECT COUNT(*) as total FROM nodes WHERE status = 1 AND node_class <= ?")
    .bind(user_class)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string());
  let accessible_row = match accessible_row {
    Ok(value) => value,
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  let online_row = sqlx::query(
    r#"
    SELECT COUNT(DISTINCT ns.node_id) as total
    FROM node_status ns
    INNER JOIN nodes n ON ns.node_id = n.id
    WHERE ns.created_at >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)
      AND n.status = 1
    "#
  )
  .fetch_optional(&state.db)
  .await
  .map_err(|err| err.to_string());
  let online_row = match online_row {
    Ok(value) => value,
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  let total_enabled = total_row
    .and_then(|row| row.try_get::<Option<i64>, _>("total").ok().flatten())
    .unwrap_or(0);
  let filtered_total = filtered_total_row
    .and_then(|row| row.try_get::<Option<i64>, _>("total").ok().flatten())
    .unwrap_or(0);
  let total_online = online_row
    .and_then(|row| row.try_get::<Option<i64>, _>("total").ok().flatten())
    .unwrap_or(0);
  let accessible_total = accessible_row
    .and_then(|row| row.try_get::<Option<i64>, _>("total").ok().flatten())
    .unwrap_or(0);
  let offline_count = (total_enabled - total_online).max(0);

  let mut enriched = Vec::with_capacity(nodes.len());
  for row in nodes {
    let node = NodeRow::from_row(&row);
    let (server, server_port, tls_host, config_value) = resolve_node_connection(&node.node_config);

    let traffic = sqlx::query(
      r#"
      SELECT
        CAST(COALESCE(SUM(upload_traffic), 0) AS SIGNED) as upload_traffic,
        CAST(COALESCE(SUM(download_traffic), 0) AS SIGNED) as download_traffic,
        CAST(COALESCE(SUM(upload_traffic + download_traffic), 0) AS SIGNED) as total_traffic,
        CAST(COALESCE(SUM(actual_upload_traffic), 0) AS SIGNED) as actual_upload_traffic,
        CAST(COALESCE(SUM(actual_download_traffic), 0) AS SIGNED) as actual_download_traffic,
        CAST(COALESCE(SUM(actual_traffic), 0) AS SIGNED) as actual_total_traffic
      FROM traffic_logs
      WHERE user_id = ? AND node_id = ?
      "#
    )
    .bind(user_id)
    .bind(node.id)
    .fetch_optional(&state.db)
    .await;

    let traffic = traffic.ok().flatten();
    let online_row = sqlx::query(
      r#"
      SELECT COUNT(*) as total
      FROM node_status
      WHERE node_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)
      "#
    )
    .bind(node.id)
    .fetch_optional(&state.db)
    .await;

    let is_online = online_row
      .ok()
      .flatten()
      .and_then(|value| value.try_get::<Option<i64>, _>("total").ok().flatten())
      .unwrap_or(0)
      > 0;

    let payload = node
      .to_value()
      .as_object()
      .cloned()
      .unwrap_or_default();
    let mut value = serde_json::Map::new();
    value.extend(payload);
    value.insert("server".to_string(), json!(server));
    value.insert("server_port".to_string(), json!(server_port));
    value.insert("tls_host".to_string(), json!(tls_host));
    value.insert("config".to_string(), config_value.clone());
    value.insert(
      "user_upload_traffic".to_string(),
      json!(traffic_value(traffic.as_ref(), "upload_traffic"))
    );
    value.insert(
      "user_download_traffic".to_string(),
      json!(traffic_value(traffic.as_ref(), "download_traffic"))
    );
    value.insert(
      "user_total_traffic".to_string(),
      json!(traffic_value(traffic.as_ref(), "actual_total_traffic"))
    );
    value.insert(
      "user_raw_total_traffic".to_string(),
      json!(traffic_value(traffic.as_ref(), "total_traffic"))
    );
    value.insert(
      "user_actual_upload_traffic".to_string(),
      json!(traffic_value(traffic.as_ref(), "actual_upload_traffic"))
    );
    value.insert(
      "user_actual_download_traffic".to_string(),
      json!(traffic_value(traffic.as_ref(), "actual_download_traffic"))
    );
    value.insert(
      "user_actual_total_traffic".to_string(),
      json!(traffic_value(traffic.as_ref(), "actual_total_traffic"))
    );
    value.insert("tags".to_string(), json!([format!("等级{}", node.node_class)]));
    value.insert("is_online".to_string(), json!(is_online));

    enriched.push(Value::Object(value));
  }

  let mut filtered_nodes = enriched;
  if let Some(is_online) = status_filter {
    filtered_nodes = filtered_nodes
      .into_iter()
      .filter(|node| node.get("is_online").and_then(Value::as_bool).unwrap_or(false) == is_online)
      .collect();
  }

  let total = if status_filter.is_some() {
    filtered_nodes.len() as i64
  } else {
    filtered_total
  };

  success(
    json!({
      "nodes": filtered_nodes,
      "statistics": {
        "total": total_enabled,
        "online": total_online,
        "offline": offline_count,
        "accessible": accessible_total
      },
      "pagination": {
        "total": total,
        "page": page,
        "limit": limit
      }
    }),
    "Success"
  )
  .into_response()
}

async fn post_reset_subscription_token(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let new_token = random_string(32);
  match update_subscription_token(&state, user_id, &new_token).await {
    Ok(()) => success(json!({ "token": new_token }), "订阅 Token 已重置").into_response(),
    Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  }
}

#[derive(Deserialize)]
struct SubscriptionLogsQuery {
  page: Option<i64>,
  limit: Option<i64>,
  #[serde(rename = "type")]
  log_type: Option<String>
}

async fn get_subscription_logs(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Query(query): Query<SubscriptionLogsQuery>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let page = query.page.unwrap_or(1).max(1);
  let mut limit = query.limit.unwrap_or(20);
  if limit <= 0 {
    limit = 20;
  }
  if limit > 200 {
    limit = 200;
  }
  let offset = (page - 1) * limit;

  let mut filters = vec!["user_id = ?"];
  let mut params = vec![SqlParam::I64(user_id)];
  if let Some(log_type) = query.log_type.as_ref().map(|value| value.trim()).filter(|value| !value.is_empty()) {
    filters.push("type = ?");
    params.push(SqlParam::String(log_type.to_string()));
  }
  let where_clause = format!("WHERE {}", filters.join(" AND "));

  let data_sql = format!(
    r#"
    SELECT id, user_id, type, request_ip, request_time, request_user_agent
    FROM subscriptions
    {where_clause}
    ORDER BY request_time DESC
    LIMIT ? OFFSET ?
    "#
  );
  let mut data_query = sqlx::query(&data_sql);
  data_query = bind_params(data_query, &params);
  let rows = data_query
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await;

  let rows = match rows {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let total_sql = format!("SELECT COUNT(*) as total FROM subscriptions {where_clause}");
  let mut total_query = sqlx::query(&total_sql);
  total_query = bind_params(total_query, &params);
  let total_row = total_query
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string());

  let total_row = match total_row {
    Ok(value) => value,
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };
  let total = total_row
    .and_then(|row| row.try_get::<Option<i64>, _>("total").ok().flatten())
    .unwrap_or(0);

  let data: Vec<Value> = rows
    .into_iter()
    .map(|row| {
      json!({
        "id": row.try_get::<i64, _>("id").unwrap_or(0),
        "user_id": row.try_get::<i64, _>("user_id").unwrap_or(0),
        "type": row.try_get::<String, _>("type").unwrap_or_default(),
        "request_ip": row.try_get::<Option<String>, _>("request_ip").ok().flatten(),
        "request_time": format_datetime(row.try_get::<Option<NaiveDateTime>, _>("request_time").ok().flatten()),
        "request_user_agent": row.try_get::<Option<String>, _>("request_user_agent").ok().flatten()
      })
    })
    .collect();

  let total_pages = if limit > 0 { ((total as f64) / (limit as f64)).ceil() as i64 } else { 1 };
  success(
    json!({
      "data": data,
      "total": total,
      "page": page,
      "limit": limit,
      "pagination": {
        "total": total,
        "page": page,
        "limit": limit,
        "totalPages": total_pages.max(1)
      }
    }),
    "Success"
  )
  .into_response()
}

#[derive(Deserialize)]
struct TrafficRecordsQuery {
  page: Option<i64>,
  limit: Option<i64>,
  start_date: Option<String>,
  end_date: Option<String>,
  start_time: Option<String>,
  end_time: Option<String>,
  node_id: Option<String>,
  node_name: Option<String>
}

async fn get_traffic_records(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Query(query): Query<TrafficRecordsQuery>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let page = query.page.unwrap_or(1).max(1);
  let mut limit = query.limit.unwrap_or(20);
  if limit <= 0 {
    limit = 20;
  }
  if limit > 200 {
    limit = 200;
  }
  let offset = (page - 1) * limit;

  let start_date = query
    .start_date
    .unwrap_or_default()
    .trim()
    .to_string();
  let end_date = query.end_date.unwrap_or_default().trim().to_string();
  let start_time = normalize_time(query.start_time.unwrap_or_default());
  let end_time = normalize_time(query.end_time.unwrap_or_default());
  let node_name = query.node_name.unwrap_or_default().trim().to_string();
  let node_id = query
    .node_id
    .as_ref()
    .and_then(|value| value.trim().parse::<i64>().ok())
    .unwrap_or(0);

  let has_time_range = !start_time.is_empty() || !end_time.is_empty();
  let has_node_filter = !node_name.is_empty() || node_id > 0;

  let mut filters = vec!["tl.user_id = ?"];
  let mut params = vec![SqlParam::I64(user_id)];
  if !start_date.is_empty() {
    filters.push("tl.date >= ?");
    params.push(SqlParam::String(start_date.clone()));
  }
  if !end_date.is_empty() {
    filters.push("tl.date <= ?");
    params.push(SqlParam::String(end_date.clone()));
  }
  if !start_time.is_empty() {
    filters.push("tl.created_at >= ?");
    params.push(SqlParam::String(start_time.clone()));
  }
  if !end_time.is_empty() {
    filters.push("tl.created_at <= ?");
    params.push(SqlParam::String(end_time.clone()));
  }
  if node_id > 0 {
    filters.push("tl.node_id = ?");
    params.push(SqlParam::I64(node_id));
  }
  if !node_name.is_empty() {
    filters.push("n.name LIKE ?");
    params.push(SqlParam::String(format!("%{node_name}%")));
  }

  let where_clause = format!("WHERE {}", filters.join(" AND "));
  let count_join = if node_name.is_empty() { "" } else { "LEFT JOIN nodes n ON n.id = tl.node_id" };

  let count_sql = format!(
    "SELECT COUNT(*) as total FROM traffic_logs tl {count_join} {where_clause}"
  );
  let mut count_query = sqlx::query(&count_sql);
  count_query = bind_params(count_query, &params);
  let total_row = count_query
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string());

  let total_row = match total_row {
    Ok(value) => value,
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };
  let traffic_total = total_row
    .and_then(|row| row.try_get::<Option<i64>, _>("total").ok().flatten())
    .unwrap_or(0);

  if traffic_total == 0 && !has_time_range && !has_node_filter {
    let mut daily_filters = vec!["dt.user_id = ?"];
    let mut daily_params = vec![SqlParam::I64(user_id)];
    if !start_date.is_empty() {
      daily_filters.push("dt.record_date >= ?");
      daily_params.push(SqlParam::String(start_date.clone()));
    }
    if !end_date.is_empty() {
      daily_filters.push("dt.record_date <= ?");
      daily_params.push(SqlParam::String(end_date.clone()));
    }
    let daily_where = format!("WHERE {}", daily_filters.join(" AND "));

    let daily_sql = format!(
      r#"
      SELECT
        id,
        user_id,
        0 as node_id,
        'Multiple Nodes' as node_name,
        upload_traffic,
        download_traffic,
        upload_traffic as actual_upload_traffic,
        download_traffic as actual_download_traffic,
        total_traffic,
        total_traffic as actual_traffic,
        1 as deduction_multiplier,
        DATE_FORMAT(record_date, '%Y-%m-%d') as log_time,
        created_at
      FROM daily_traffic dt
      {daily_where}
      ORDER BY record_date DESC
      LIMIT ? OFFSET ?
      "#
    );

    let mut daily_query = sqlx::query(&daily_sql);
    daily_query = bind_params(daily_query, &daily_params);
    let daily_rows = daily_query
      .bind(limit)
      .bind(offset)
      .fetch_all(&state.db)
      .await;

    let daily_rows = match daily_rows {
      Ok(value) => value,
      Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
    };

    let daily_total_sql = format!("SELECT COUNT(*) as total FROM daily_traffic dt {daily_where}");
    let mut daily_total_query = sqlx::query(&daily_total_sql);
    daily_total_query = bind_params(daily_total_query, &daily_params);
    let daily_total_row = daily_total_query
      .fetch_optional(&state.db)
      .await
      .map_err(|err| err.to_string());
    let daily_total_row = match daily_total_row {
      Ok(value) => value,
      Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
    };
    let daily_total = daily_total_row
      .and_then(|row| row.try_get::<Option<i64>, _>("total").ok().flatten())
      .unwrap_or(0);

    let data = map_traffic_rows(daily_rows);
    let pages = if limit > 0 { ((daily_total as f64) / (limit as f64)).ceil() as i64 } else { 1 };
    return success(
      json!({
        "data": data,
        "total": daily_total,
        "page": page,
        "limit": limit,
        "pages": pages.max(1)
      }),
      "Success"
    )
    .into_response();
  }

  let data_sql = format!(
    r#"
    SELECT
      tl.id,
      tl.user_id,
      tl.node_id,
      n.name as node_name,
      tl.upload_traffic,
      tl.download_traffic,
      tl.actual_upload_traffic,
      tl.actual_download_traffic,
      (tl.upload_traffic + tl.download_traffic) as total_traffic,
      tl.actual_traffic,
      tl.deduction_multiplier,
      DATE_FORMAT(tl.date, '%Y-%m-%d') as log_time,
      tl.created_at
    FROM traffic_logs tl
    LEFT JOIN nodes n ON n.id = tl.node_id
    {where_clause}
    ORDER BY tl.date DESC, tl.created_at DESC
    LIMIT ? OFFSET ?
    "#
  );

  let mut data_query = sqlx::query(&data_sql);
  data_query = bind_params(data_query, &params);
  let rows = data_query
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await;

  let rows = match rows {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let data = map_traffic_rows(rows);
  let pages = if limit > 0 { ((traffic_total as f64) / (limit as f64)).ceil() as i64 } else { 1 };
  success(
    json!({
      "data": data,
      "total": traffic_total,
      "page": page,
      "limit": limit,
      "pages": pages.max(1)
    }),
    "Success"
  )
  .into_response()
}

#[derive(Deserialize)]
struct TrafficTrendsQuery {
  period: Option<String>
}

async fn get_traffic_trends(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Query(query): Query<TrafficTrendsQuery>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let period = query.period.unwrap_or_else(|| "today".to_string());
  let days_count = if period == "3days" {
    3
  } else if period == "7days" {
    7
  } else {
    1
  };

  let beijing = Utc::now() + Duration::hours(8);
  let mut date_list: Vec<(String, String)> = Vec::new();
  for i in (0..days_count).rev() {
    let target = beijing - Duration::days(i as i64);
    let date = target.date_naive();
    let date_str = date.format("%Y-%m-%d").to_string();
    let label = if i == 0 {
      "今天".to_string()
    } else {
      weekday_label(date.weekday().number_from_sunday())
    };
    date_list.push((date_str, label));
  }

  let start_date = date_list
    .first()
    .map(|(date, _)| date.clone())
    .unwrap_or_else(|| beijing.date_naive().format("%Y-%m-%d").to_string());

  let rows = sqlx::query(
    r#"
    SELECT
      DATE_FORMAT(date, '%Y-%m-%d') as date,
      CAST(COALESCE(SUM(actual_upload_traffic), 0) AS SIGNED) as upload_traffic,
      CAST(COALESCE(SUM(actual_download_traffic), 0) AS SIGNED) as download_traffic,
      CAST(COALESCE(SUM(actual_traffic), 0) AS SIGNED) as total_traffic
    FROM traffic_logs
    WHERE user_id = ?
      AND date >= ?
    GROUP BY date
    ORDER BY date ASC
    "#
  )
  .bind(user_id)
  .bind(start_date)
  .fetch_all(&state.db)
  .await;

  let rows = match rows {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let mut data_map = std::collections::HashMap::new();
  for row in rows {
    let date = row.try_get::<Option<String>, _>("date").ok().flatten();
    if let Some(date) = date {
      data_map.insert(
        date,
        (
          row.try_get::<Option<i64>, _>("upload_traffic").unwrap_or(Some(0)).unwrap_or(0),
          row.try_get::<Option<i64>, _>("download_traffic").unwrap_or(Some(0)).unwrap_or(0),
          row.try_get::<Option<i64>, _>("total_traffic").unwrap_or(Some(0)).unwrap_or(0)
        )
      );
    }
  }

  let mut trends = Vec::with_capacity(date_list.len());
  for (date, label) in date_list {
    let (upload, download, total) = data_map.get(&date).cloned().unwrap_or((0, 0, 0));
    trends.push(json!({
      "date": date,
      "label": label,
      "upload_traffic": upload,
      "download_traffic": download,
      "total_traffic": total
    }));
  }

  let has_any = trends.iter().any(|item| {
    item.get("total_traffic").and_then(Value::as_i64).unwrap_or(0) > 0
      || item.get("upload_traffic").and_then(Value::as_i64).unwrap_or(0) > 0
      || item.get("download_traffic").and_then(Value::as_i64).unwrap_or(0) > 0
  });

  success(
    if has_any { Value::Array(trends) } else { Value::Array(Vec::new()) },
    "Success"
  )
  .into_response()
}

async fn get_traffic_summary(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  match fetch_user_traffic_summary(&state, user_id).await {
    Ok(summary) => success(summary, "Success").into_response(),
    Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  }
}

#[derive(Deserialize)]
struct TrafficStatsQuery {
  days: Option<i64>
}

async fn get_traffic_stats(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Query(query): Query<TrafficStatsQuery>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let mut days = query.days.unwrap_or(30);
  if days <= 0 {
    days = 30;
  }
  if days > 180 {
    days = 180;
  }

  match fetch_user_traffic_stats(&state, user_id, days).await {
    Ok(Some(stats)) => success(stats, "Success").into_response(),
    Ok(None) => error(StatusCode::NOT_FOUND, "用户不存在", None),
    Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  }
}

async fn post_traffic_manual_update(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>
) -> Response {
  let _ = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let record_date = (Utc::now() + Duration::hours(8))
    .date_naive()
    .format("%Y-%m-%d")
    .to_string();
  match aggregate_traffic_for_date(&state, &record_date).await {
    Ok(_) => success(Value::Null, "已触发手动同步").into_response(),
    Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  }
}

#[derive(Deserialize)]
struct OnlineIpsQuery {
  limit: Option<i64>
}

async fn get_online_ips(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Query(query): Query<OnlineIpsQuery>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let mut limit = query.limit.unwrap_or(50);
  if limit <= 0 {
    limit = 50;
  }
  if limit > 200 {
    limit = 200;
  }

  let rows = sqlx::query(
    r#"
    SELECT oi.id, oi.node_id, oi.ip, oi.last_seen, n.name as node_name
    FROM online_ips oi
    LEFT JOIN nodes n ON oi.node_id = n.id
    WHERE oi.user_id = ?
      AND oi.last_seen >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)
    ORDER BY oi.last_seen DESC
    LIMIT ?
    "#
  )
  .bind(user_id)
  .bind(limit)
  .fetch_all(&state.db)
  .await;

  let rows = match rows {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let data: Vec<Value> = rows
    .into_iter()
    .map(|row| {
      json!({
        "id": row.try_get::<i64, _>("id").unwrap_or(0),
        "node_id": row.try_get::<i64, _>("node_id").unwrap_or(0),
        "node_name": row.try_get::<Option<String>, _>("node_name").ok().flatten(),
        "ip": row.try_get::<String, _>("ip").unwrap_or_default(),
        "last_seen": format_datetime(row.try_get::<Option<NaiveDateTime>, _>("last_seen").ok().flatten())
      })
    })
    .collect();

  success(Value::Array(data), "Success").into_response()
}

async fn get_online_ips_detail(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Query(query): Query<OnlineIpsQuery>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let mut limit = query.limit.unwrap_or(50);
  if limit <= 0 {
    limit = 50;
  }
  if limit > 200 {
    limit = 200;
  }

  let rows = sqlx::query(
    r#"
    SELECT oi.id, oi.node_id, oi.ip, oi.last_seen, n.name as node_name
    FROM online_ips oi
    LEFT JOIN nodes n ON oi.node_id = n.id
    WHERE oi.user_id = ?
      AND oi.last_seen >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)
    ORDER BY oi.last_seen DESC
    LIMIT ?
    "#
  )
  .bind(user_id)
  .bind(limit)
  .fetch_all(&state.db)
  .await;

  let rows = match rows {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let data: Vec<Value> = rows
    .into_iter()
    .map(|row| {
      json!({
        "id": row.try_get::<i64, _>("id").unwrap_or(0),
        "node_id": row.try_get::<i64, _>("node_id").unwrap_or(0),
        "node_name": row.try_get::<Option<String>, _>("node_name").ok().flatten(),
        "ip": row.try_get::<String, _>("ip").unwrap_or_default(),
        "last_seen": format_datetime(row.try_get::<Option<NaiveDateTime>, _>("last_seen").ok().flatten())
      })
    })
    .collect();

  success(
    json!({
      "data": data,
      "count": data.len(),
      "user_id": user_id,
      "check_time": Utc::now().to_rfc3339()
    }),
    "Success"
  )
  .into_response()
}

async fn get_online_devices(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let rows = sqlx::query(
    r#"
    SELECT
      ip,
      MIN(node_id) as node_id,
      MAX(last_seen) as last_seen
    FROM online_ips
    WHERE user_id = ?
      AND last_seen >= DATE_SUB(NOW(), INTERVAL 2 MINUTE)
    GROUP BY ip
    ORDER BY last_seen DESC
    "#
  )
  .bind(user_id)
  .fetch_all(&state.db)
  .await;

  let rows = match rows {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let devices: Vec<Value> = rows
    .into_iter()
    .map(|row| {
      json!({
        "ip": row.try_get::<String, _>("ip").unwrap_or_default(),
        "node_id": row.try_get::<Option<i64>, _>("node_id").unwrap_or(Some(0)).unwrap_or(0),
        "last_seen": format_datetime(row.try_get::<Option<NaiveDateTime>, _>("last_seen").ok().flatten())
      })
    })
    .collect();

  success(
    json!({
      "count": devices.len(),
      "user_id": user_id,
      "check_time": Utc::now().to_rfc3339(),
      "devices": devices
    }),
    "Success"
  )
  .into_response()
}

async fn get_bark_settings(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let row = sqlx::query("SELECT bark_key, bark_enabled FROM users WHERE id = ?")
    .bind(user_id)
    .fetch_optional(&state.db)
    .await;

  let row = match row {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };
  let row = match row {
    Some(value) => value,
    None => return error(StatusCode::NOT_FOUND, "用户不存在", None)
  };

  let bark_key = row
    .try_get::<Option<String>, _>("bark_key")
    .ok()
    .flatten()
    .unwrap_or_default();
  let bark_enabled = row
    .try_get::<Option<i64>, _>("bark_enabled")
    .unwrap_or(Some(0))
    .unwrap_or(0)
    == 1;

  success(
    json!({
      "bark_key": bark_key,
      "bark_enabled": bark_enabled
    }),
    "Success"
  )
  .into_response()
}

#[derive(Deserialize)]
struct BarkSettingsRequest {
  bark_key: Option<String>,
  bark_enabled: Option<bool>
}

async fn put_bark_settings(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Json(body): Json<BarkSettingsRequest>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let bark_key = body.bark_key;
  let bark_enabled = body.bark_enabled.unwrap_or(false);

  if let Err(message) = update_user_bark_settings(&state, user_id, bark_key, bark_enabled).await {
    return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None);
  }

  success(Value::Null, "Bark 设置已更新").into_response()
}

#[derive(Deserialize)]
struct BarkTestRequest {
  bark_key: Option<String>
}

async fn post_bark_test(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Json(body): Json<BarkTestRequest>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let mut test_key = body
    .bark_key
    .map(|value| value.trim().to_string())
    .filter(|value| !value.is_empty());

  if test_key.is_none() {
    let row = sqlx::query("SELECT bark_key FROM users WHERE id = ?")
      .bind(user_id)
      .fetch_optional(&state.db)
      .await;
    match row {
      Ok(Some(row)) => {
        test_key = row
          .try_get::<Option<String>, _>("bark_key")
          .ok()
          .flatten()
          .map(|value| value.trim().to_string())
          .filter(|value| !value.is_empty());
      }
      Ok(None) => return error(StatusCode::NOT_FOUND, "用户不存在", None),
      Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
    }
  }

  let test_key = match test_key {
    Some(value) => value,
    None => return error(StatusCode::BAD_REQUEST, "请先设置 Bark Key", None)
  };

  let title = encode("Bark通知测试");
  let content = encode("如果您收到这条消息，说明Bark配置正确！");
  let test_url = if test_key.starts_with("http://") || test_key.starts_with("https://") {
    let base = if test_key.ends_with('/') {
      test_key.trim_end_matches('/').to_string()
    } else {
      test_key.clone()
    };
    format!("{}/{}/{}", base, title, content)
  } else {
    format!("https://api.day.app/{}/{}/{}", test_key, title, content)
  };

  let client = reqwest::Client::new();
  let response = client
    .get(test_url)
    .header("User-Agent", "Soga-Panel-Server/1.0")
    .send()
    .await;

  let response = match response {
    Ok(value) => value,
    Err(err) => {
      let _ = update_user_bark_settings(&state, user_id, Some(test_key.clone()), false).await;
      return error(
        StatusCode::BAD_REQUEST,
        &format!("网络请求失败: {}，已自动禁用 Bark 通知", err),
        None
      );
    }
  };

  if !response.status().is_success() {
    let _ = update_user_bark_settings(&state, user_id, Some(test_key.clone()), false).await;
    return error(
      StatusCode::BAD_REQUEST,
      &format!(
        "测试失败，HTTP 状态码: {}，已自动禁用 Bark 通知",
        response.status().as_u16()
      ),
      None
    );
  }

  let result = response.json::<Value>().await.ok();
  if let Some(value) = result.as_ref() {
    let ok_code = value.get("code").and_then(Value::as_i64) == Some(200)
      || value.get("message").and_then(Value::as_str) == Some("success");
    if !ok_code {
      let message = value
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("未知错误");
      let _ = update_user_bark_settings(&state, user_id, Some(test_key.clone()), false).await;
      return error(
        StatusCode::BAD_REQUEST,
        &format!("Bark 服务器返回错误: {}，已自动禁用 Bark 通知", message),
        None
      );
    }
  }

  success(
    json!({
      "message": "Bark 通知测试成功，请检查您的设备是否收到测试消息",
      "success": true,
      "bark_response": result
    }),
    "Success"
  )
  .into_response()
}

async fn delete_passkey(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Path(credential_id): Path<String>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let credential_id = credential_id.trim().to_string();
  if credential_id.is_empty() {
    return error(StatusCode::BAD_REQUEST, "缺少凭证ID", None);
  }

  match sqlx::query("DELETE FROM passkeys WHERE user_id = ? AND credential_id = ?")
    .bind(user_id)
    .bind(&credential_id)
    .execute(&state.db)
    .await
  {
    Ok(result) => {
      if result.rows_affected() == 0 {
        return error(StatusCode::NOT_FOUND, "未找到要删除的通行密钥", None);
      }
      success(json!({ "removed": credential_id }), "Success").into_response()
    }
    Err(err) => error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  }
}

#[derive(Deserialize)]
struct TwoFactorCodeRequest {
  code: Option<String>
}

#[derive(Deserialize)]
struct TwoFactorDisableRequest {
  password: Option<String>,
  code: Option<String>
}

async fn post_two_factor_setup(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let user = match get_two_factor_user(&state, user_id).await {
    Ok(Some(value)) => value,
    Ok(None) => return error(StatusCode::NOT_FOUND, "用户不存在", None),
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  if user.two_factor_enabled == 1 && user.two_factor_secret.as_deref().unwrap_or("").is_empty() == false {
    return error(StatusCode::BAD_REQUEST, "二步验证已启用", None);
  }

  let secret = generate_totp_secret(32);
  let encrypted = match encrypt_two_factor_secret(&state, &secret) {
    Ok(value) => value,
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  if let Err(message) = set_two_factor_temp_secret(&state, user.id, &encrypted).await {
    return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None);
  }

  let account = if !user.email.is_empty() {
    user.email.clone()
  } else if !user.username.is_empty() {
    user.username.clone()
  } else {
    format!("user_{}", user.id)
  };
  let issuer = state
    .env
    .site_name
    .clone()
    .unwrap_or_else(|| "Soga Panel".to_string());
  let otp_auth_url = create_otp_auth_url(&secret, &account, &issuer);

  success(
    json!({
      "secret": secret,
      "otp_auth_url": otp_auth_url,
      "provisioning_uri": otp_auth_url
    }),
    "Success"
  )
  .into_response()
}

async fn post_two_factor_enable(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Json(body): Json<TwoFactorCodeRequest>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let code = body.code.unwrap_or_default().trim().to_string();
  if code.is_empty() {
    return error(StatusCode::BAD_REQUEST, "请输入验证码", None);
  }

  let user = match get_two_factor_user(&state, user_id).await {
    Ok(Some(value)) => value,
    Ok(None) => return error(StatusCode::NOT_FOUND, "用户不存在", None),
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  let temp_secret = match user.two_factor_temp_secret.as_deref() {
    Some(value) if !value.trim().is_empty() => value,
    _ => return error(StatusCode::BAD_REQUEST, "请先获取新的密钥", None)
  };

  let secret = match decrypt_two_factor_secret(&state, Some(temp_secret)) {
    Ok(value) => value,
    Err(_) => return error(StatusCode::BAD_REQUEST, "临时密钥无效，请重新生成", None)
  };

  if !verify_totp(&secret, &code, 1) {
    return error(StatusCode::UNAUTHORIZED, "验证码无效，请重试", None);
  }

  let backup_codes = generate_backup_codes(8);
  let hashed_codes = hash_backup_codes(&backup_codes);

  if let Err(message) = enable_two_factor(&state, user.id, &hashed_codes).await {
    return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None);
  }

  success(json!({ "backup_codes": backup_codes }), "二步验证已启用").into_response()
}

async fn post_two_factor_backup_codes(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Json(body): Json<TwoFactorCodeRequest>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let code = body.code.unwrap_or_default().trim().to_string();
  if code.is_empty() {
    return error(StatusCode::BAD_REQUEST, "请输入验证码", None);
  }

  let user = match get_two_factor_user(&state, user_id).await {
    Ok(Some(value)) => value,
    Ok(None) => return error(StatusCode::NOT_FOUND, "用户不存在", None),
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  if user.two_factor_enabled != 1 {
    return error(StatusCode::BAD_REQUEST, "尚未启用二步验证", None);
  }

  let verification = match verify_user_two_factor_code(&state, &user, &code).await {
    Ok(value) => value,
    Err(message) => return error(StatusCode::BAD_REQUEST, &message, None)
  };
  if !verification.success {
    return error(StatusCode::UNAUTHORIZED, "验证码无效，请重试", None);
  }

  let backup_codes = generate_backup_codes(8);
  let hashed_codes = hash_backup_codes(&backup_codes);
  if let Err(message) = update_backup_codes(&state, user.id, &hashed_codes).await {
    return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None);
  }

  success(json!({ "backup_codes": backup_codes }), "已生成新的备用验证码").into_response()
}

async fn post_two_factor_disable(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Json(body): Json<TwoFactorDisableRequest>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let password = body.password.unwrap_or_default();
  let code = body.code.unwrap_or_default();
  if password.trim().is_empty() || code.trim().is_empty() {
    return error(StatusCode::BAD_REQUEST, "请输入密码和验证码", None);
  }

  let user = match get_two_factor_user(&state, user_id).await {
    Ok(Some(value)) => value,
    Ok(None) => return error(StatusCode::NOT_FOUND, "用户不存在", None),
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  if user.two_factor_enabled != 1 {
    return error(StatusCode::BAD_REQUEST, "尚未启用二步验证", None);
  }

  if !verify_password(&password, &user.password_hash) {
    return error(StatusCode::UNAUTHORIZED, "密码错误", None);
  }

  let verification = match verify_user_two_factor_code(&state, &user, &code).await {
    Ok(value) => value,
    Err(message) => return error(StatusCode::BAD_REQUEST, &message, None)
  };
  if !verification.success {
    return error(StatusCode::UNAUTHORIZED, "验证码无效，请重试", None);
  }

  if let Err(message) = disable_two_factor(&state, user.id).await {
    return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None);
  }

  success(Value::Null, "二步验证已关闭").into_response()
}

#[derive(Deserialize)]
struct InviteReferralsQuery {
  page: Option<i64>,
  #[serde(rename = "pageSize")]
  page_size: Option<i64>
}

async fn get_invite(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let stats = match get_user_invite_stats(&state, user_id).await {
    Ok(Some(value)) => value,
    Ok(None) => return error(StatusCode::NOT_FOUND, "用户不存在", None),
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  let mut invite_code = stats.invite_code.clone().unwrap_or_default();
  if invite_code.trim().is_empty() {
    match ensure_user_invite_code_with_length(&state, user_id, 8).await {
      Ok(value) => invite_code = value,
      Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
    }
  } else {
    invite_code = invite_code.trim().to_string();
  }

  let base = state.env.site_url.clone().unwrap_or_default();
  let invite_link = if base.trim().is_empty() {
    None
  } else {
    Some(format!(
      "{}/register?invite={}",
      base.trim_end_matches('/'),
      invite_code
    ))
  };

  let configs = list_system_configs(&state).await.unwrap_or_default();
  let rebate_rate = configs
    .get("rebate_rate")
    .and_then(|value| value.parse::<f64>().ok())
    .unwrap_or(0.0);
  let rebate_mode = configs
    .get("rebate_mode")
    .map(|value| value.to_string())
    .unwrap_or_else(|| "every_order".to_string());
  let invite_default_limit = configs
    .get("invite_default_limit")
    .and_then(|value| value.parse::<i64>().ok())
    .unwrap_or(stats.invite_limit);

  success(
    json!({
      "invite_code": invite_code,
      "invite_link": invite_link,
      "invited_by": stats.invited_by,
      "invite_used": stats.invite_used,
      "invite_limit": stats.invite_limit,
      "total_invitees": stats.total_invitees,
      "confirmed_invitees": stats.confirmed_invitees,
      "rebate_available": stats.rebate_available,
      "rebate_total": stats.rebate_total,
      "rebate_rate": rebate_rate,
      "rebate_mode": rebate_mode,
      "invite_default_limit": invite_default_limit
    }),
    "Success"
  )
  .into_response()
}

async fn post_invite_regenerate(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let code = match regenerate_invite_code(&state, user_id, 6).await {
    Ok(value) => value,
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  let base = state.env.site_url.clone().unwrap_or_default();
  let invite_link = if base.trim().is_empty() {
    None
  } else {
    Some(format!(
      "{}/register?invite={}",
      base.trim_end_matches('/'),
      code
    ))
  };

  success(
    json!({
      "invite_code": code,
      "invite_link": invite_link
    }),
    "邀请码已重置"
  )
  .into_response()
}

async fn get_invite_referrals(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Query(query): Query<InviteReferralsQuery>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let page = query.page.unwrap_or(1).max(1);
  let mut page_size = query.page_size.unwrap_or(20);
  if page_size <= 0 {
    page_size = 20;
  }
  if page_size > 200 {
    page_size = 200;
  }

  let (rows, total) = match list_referral_rows(&state, user_id, page, page_size).await {
    Ok(value) => value,
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  let data: Vec<Value> = rows.iter().map(referral_row_full_value).collect();
  success(json!({ "data": data, "total": total }), "Success").into_response()
}

#[derive(Deserialize)]
struct ReferralsQuery {
  page: Option<i64>,
  limit: Option<i64>
}

async fn get_referrals(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Query(query): Query<ReferralsQuery>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let page = query.page.unwrap_or(1).max(1);
  let mut limit = query.limit.unwrap_or(10);
  if limit <= 0 {
    limit = 10;
  }
  if limit > 200 {
    limit = 200;
  }

  let (rows, total) = match list_referral_rows(&state, user_id, page, limit).await {
    Ok(value) => value,
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  let stats_row = sqlx::query(
    r#"
    SELECT COUNT(*) AS total,
           SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active_total
    FROM referral_relations
    WHERE inviter_id = ?
    "#
  )
  .bind(user_id)
  .fetch_optional(&state.db)
  .await;
  let stats_row = match stats_row {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let user_row = sqlx::query(
    r#"
    SELECT
      invite_code,
      invited_by,
      rebate_available,
      rebate_total,
      invite_limit,
      invite_used,
      CASE
        WHEN status = 1
          AND class > 0
          AND (class_expire_time IS NULL OR class_expire_time > CURRENT_TIMESTAMP)
        THEN 1
        ELSE 0
      END AS rebate_eligible
    FROM users
    WHERE id = ?
    "#
  )
  .bind(user_id)
  .fetch_optional(&state.db)
  .await;
  let user_row = match user_row {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let configs = list_system_configs(&state).await.unwrap_or_default();
  let invite_base_url = configs
    .get("site_url")
    .cloned()
    .filter(|value| !value.trim().is_empty())
    .or_else(|| state.env.site_url.clone())
    .unwrap_or_default();
  let rebate_settings = json!({
    "mode": configs
      .get("rebate_mode")
      .map(|value| value.to_string())
      .unwrap_or_else(|| "every_order".to_string()),
    "rate": configs
      .get("rebate_rate")
      .and_then(|value| value.parse::<f64>().ok())
      .unwrap_or(0.0)
  });
  let withdraw_settings = json!({
    "feeRate": configs
      .get("rebate_withdraw_fee_rate")
      .and_then(|value| value.parse::<f64>().ok())
      .unwrap_or(0.05),
    "minAmount": configs
      .get("rebate_withdraw_min_amount")
      .and_then(|value| value.parse::<f64>().ok())
      .unwrap_or(200.0)
  });

  let referrals: Vec<Value> = rows.iter().map(referral_row_summary_value).collect();
  let total_pages = if limit > 0 { ((total as f64) / (limit as f64)).ceil() as i64 } else { 1 };
  let total_invited = stats_row
    .as_ref()
    .and_then(|row| row.try_get::<Option<i64>, _>("total").ok().flatten())
    .unwrap_or(0);
  let active_invited = stats_row
    .as_ref()
    .and_then(|row| row.try_get::<Option<i64>, _>("active_total").ok().flatten())
    .unwrap_or(0);

  let rebate_available = user_row
    .as_ref()
    .map(|row| parse_decimal(row, "rebate_available", 0.0))
    .unwrap_or(0.0);
  let rebate_total = user_row
    .as_ref()
    .map(|row| parse_decimal(row, "rebate_total", 0.0))
    .unwrap_or(0.0);
  let invite_code = user_row
    .as_ref()
    .and_then(|row| row.try_get::<Option<String>, _>("invite_code").ok().flatten());
  let invited_by = user_row
    .as_ref()
    .and_then(|row| row.try_get::<Option<i64>, _>("invited_by").ok().flatten());
  let invite_limit = user_row
    .as_ref()
    .and_then(|row| row.try_get::<Option<i64>, _>("invite_limit").ok().flatten())
    .unwrap_or(0);
  let invite_used = user_row
    .as_ref()
    .and_then(|row| row.try_get::<Option<i64>, _>("invite_used").ok().flatten())
    .unwrap_or(0);
  let rebate_eligible = user_row
    .as_ref()
    .and_then(|row| row.try_get::<Option<i64>, _>("rebate_eligible").ok().flatten())
    .unwrap_or(0)
    == 1;

  success(
    json!({
      "inviteCode": invite_code,
      "invitedBy": invited_by,
      "rebateAvailable": rebate_available,
      "rebateTotal": rebate_total,
      "inviteLimit": invite_limit,
      "inviteUsed": invite_used,
      "rebateEligible": rebate_eligible,
      "stats": {
        "totalInvited": total_invited,
        "activeInvited": active_invited
      },
      "referrals": referrals,
      "pagination": {
        "page": page,
        "limit": limit,
        "total": total,
        "totalPages": total_pages.max(1)
      },
      "rebateSettings": rebate_settings,
      "withdrawSettings": withdraw_settings,
      "inviteBaseUrl": invite_base_url
    }),
    "Success"
  )
  .into_response()
}

async fn get_ticket_unread_count(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let row = sqlx::query(
    r#"
    SELECT COUNT(*) as total
    FROM tickets
    WHERE user_id = ?
      AND status = 'answered'
      AND updated_at > COALESCE(
        (SELECT MAX(created_at) FROM ticket_replies WHERE ticket_id = tickets.id AND author_role = 'user'),
        '1970-01-01'
      )
    "#
  )
  .bind(user_id)
  .fetch_optional(&state.db)
  .await;
  let row = match row {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };
  let total = row
    .and_then(|row| row.try_get::<Option<i64>, _>("total").ok().flatten())
    .unwrap_or(0);

  success(json!({ "count": total }), "Success").into_response()
}

#[derive(Deserialize)]
struct TicketsQuery {
  page: Option<i64>,
  #[serde(rename = "pageSize")]
  page_size: Option<i64>,
  status: Option<String>
}

async fn get_tickets(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Query(query): Query<TicketsQuery>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let page = query.page.unwrap_or(1).max(1);
  let mut page_size = query.page_size.unwrap_or(10);
  if page_size <= 0 {
    page_size = 10;
  }
  if page_size > 50 {
    page_size = 50;
  }
  let offset = (page - 1) * page_size;

  let status_filter = query
    .status
    .as_ref()
    .map(|value| value.trim().to_lowercase())
    .filter(|value| matches!(value.as_str(), "open" | "answered" | "closed"));

  let mut filters = vec!["user_id = ?"];
  let mut params = vec![SqlParam::I64(user_id)];
  if let Some(status_value) = status_filter.clone() {
    filters.push("status = ?");
    params.push(SqlParam::String(status_value));
  }
  let where_clause = format!("WHERE {}", filters.join(" AND "));

  let data_sql = format!(
    r#"
    SELECT id, user_id, title, content, status, last_reply_at, created_at, updated_at
    FROM tickets
    {where_clause}
    ORDER BY updated_at DESC
    LIMIT ? OFFSET ?
    "#
  );
  let mut data_query = sqlx::query(&data_sql);
  data_query = bind_params(data_query, &params);
  let rows = data_query
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.db)
    .await;
  let rows = match rows {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let total_sql = format!("SELECT COUNT(*) as total FROM tickets {where_clause}");
  let mut total_query = sqlx::query(&total_sql);
  total_query = bind_params(total_query, &params);
  let total_row = total_query
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string());
  let total_row = match total_row {
    Ok(value) => value,
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };
  let total = total_row
    .and_then(|row| row.try_get::<Option<i64>, _>("total").ok().flatten())
    .unwrap_or(0);

  let items: Vec<Value> = rows.into_iter().map(|row| build_ticket_value(&row, false)).collect();
  success(
    json!({
      "items": items,
      "pagination": {
        "page": page,
        "pageSize": page_size,
        "total": total
      }
    }),
    "Success"
  )
  .into_response()
}

#[derive(Deserialize)]
struct CreateTicketRequest {
  title: Option<String>,
  content: Option<String>
}

async fn post_ticket(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Json(body): Json<CreateTicketRequest>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let title = sanitize_text(body.title.as_deref().unwrap_or(""), MAX_TICKET_TITLE_LENGTH);
  let content = sanitize_text(
    body.content.as_deref().unwrap_or(""),
    MAX_TICKET_CONTENT_LENGTH
  );
  if title.is_empty() || content.is_empty() {
    return error(StatusCode::BAD_REQUEST, "标题和内容不能为空", None);
  }

  let result = sqlx::query(
    r#"
    INSERT INTO tickets (user_id, title, content, status, created_at, updated_at)
    VALUES (?, ?, ?, 'open', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    "#
  )
  .bind(user_id)
  .bind(&title)
  .bind(&content)
  .execute(&state.db)
  .await;
  let result = match result {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let ticket_id = result.last_insert_id() as i64;
  let ticket_row = sqlx::query(
    r#"
    SELECT id, user_id, title, content, status, last_reply_at, created_at, updated_at
    FROM tickets
    WHERE id = ?
    "#
  )
  .bind(ticket_id)
  .fetch_optional(&state.db)
  .await;
  let ticket_row = match ticket_row {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let ticket = match ticket_row {
    Some(row) => build_ticket_value(&row, true),
    None => json!({
      "id": ticket_id,
      "title": title,
      "content": content,
      "status": "open",
      "last_reply_at": null,
      "created_at": null,
      "updated_at": null
    })
  };

  success(ticket, "工单已提交").into_response()
}

async fn get_ticket_detail(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Path(ticket_id): Path<i64>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let row = sqlx::query(
    r#"
    SELECT id, user_id, title, content, status, last_reply_at, created_at, updated_at
    FROM tickets
    WHERE id = ? AND user_id = ?
    "#
  )
  .bind(ticket_id)
  .bind(user_id)
  .fetch_optional(&state.db)
  .await;
  let row = match row {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let ticket_row = match row {
    Some(value) => value,
    None => return error(StatusCode::NOT_FOUND, "未找到工单", None)
  };

  let replies = match list_ticket_replies(&state, ticket_id).await {
    Ok(value) => value,
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  success(json!({ "ticket": build_ticket_value(&ticket_row, true), "replies": replies }), "Success")
    .into_response()
}

#[derive(Deserialize)]
struct TicketReplyRequest {
  content: Option<String>
}

async fn post_ticket_reply(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Path(ticket_id): Path<i64>,
  Json(body): Json<TicketReplyRequest>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let content = sanitize_text(
    body.content.as_deref().unwrap_or(""),
    MAX_TICKET_CONTENT_LENGTH
  );
  if content.is_empty() {
    return error(StatusCode::BAD_REQUEST, "回复内容不能为空", None);
  }

  let ticket_row = sqlx::query("SELECT id, user_id FROM tickets WHERE id = ?")
    .bind(ticket_id)
    .fetch_optional(&state.db)
    .await;
  let ticket_row = match ticket_row {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };
  let ticket_row = match ticket_row {
    Some(value) => value,
    None => return error(StatusCode::NOT_FOUND, "未找到工单", None)
  };
  let ticket_user = ticket_row.try_get::<i64, _>("user_id").unwrap_or(0);
  if ticket_user != user_id {
    return error(StatusCode::NOT_FOUND, "未找到工单", None);
  }

  let insert_result = sqlx::query(
    r#"
    INSERT INTO ticket_replies (ticket_id, author_id, author_role, content, created_at)
    VALUES (?, ?, 'user', ?, CURRENT_TIMESTAMP)
    "#
  )
  .bind(ticket_id)
  .bind(user_id)
  .bind(&content)
  .execute(&state.db)
  .await;
  if let Err(err) = insert_result {
    return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None);
  }

  let update_result = sqlx::query(
    r#"
    UPDATE tickets
    SET status = 'open', last_reply_by_admin_id = NULL, last_reply_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
    "#
  )
  .bind(ticket_id)
  .execute(&state.db)
  .await;
  if let Err(err) = update_result {
    return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None);
  }

  let replies = match list_ticket_replies(&state, ticket_id).await {
    Ok(value) => value,
    Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)
  };

  success(json!({ "replies": replies, "status": "open" }), "回复成功").into_response()
}

async fn post_ticket_close(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Path(ticket_id): Path<i64>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let ticket_row = sqlx::query("SELECT id, user_id, status FROM tickets WHERE id = ?")
    .bind(ticket_id)
    .fetch_optional(&state.db)
    .await;
  let ticket_row = match ticket_row {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };
  let ticket_row = match ticket_row {
    Some(value) => value,
    None => return error(StatusCode::NOT_FOUND, "未找到工单", None)
  };
  let ticket_user = ticket_row.try_get::<i64, _>("user_id").unwrap_or(0);
  if ticket_user != user_id {
    return error(StatusCode::NOT_FOUND, "未找到工单", None);
  }

  let status = ticket_row
    .try_get::<Option<String>, _>("status")
    .ok()
    .flatten()
    .unwrap_or_else(|| "open".to_string());
  if status == "closed" {
    return success(json!({ "status": "closed" }), "工单已关闭").into_response();
  }

  let result = sqlx::query(
    r#"
    UPDATE tickets
    SET status = 'closed', updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
    "#
  )
  .bind(ticket_id)
  .execute(&state.db)
  .await;
  if let Err(err) = result {
    return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None);
  }

  success(json!({ "status": "closed" }), "工单已关闭").into_response()
}

#[derive(Deserialize)]
struct AuditQuery {
  page: Option<i64>,
  limit: Option<i64>
}

async fn get_audit_rules(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Query(query): Query<AuditQuery>
) -> Response {
  let _user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let page = query.page.unwrap_or(1).max(1);
  let mut limit = query.limit.unwrap_or(20);
  if limit <= 0 {
    limit = 20;
  }
  if limit > 100 {
    limit = 100;
  }
  let offset = (page - 1) * limit;

  let rows = sqlx::query(
    r#"
    SELECT name, rule as pattern, description
    FROM audit_rules
    WHERE enabled = 1
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
    "#
  )
  .bind(limit)
  .bind(offset)
  .fetch_all(&state.db)
  .await;
  let rows = match rows {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let total_row = sqlx::query("SELECT COUNT(*) as total FROM audit_rules WHERE enabled = 1")
    .fetch_optional(&state.db)
    .await;
  let total_row = match total_row {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };
  let total = total_row
    .and_then(|row| row.try_get::<Option<i64>, _>("total").ok().flatten())
    .unwrap_or(0);

  let rules: Vec<Value> = rows
    .into_iter()
    .map(|row| {
      json!({
        "name": row.try_get::<Option<String>, _>("name").unwrap_or(None).unwrap_or_default(),
        "pattern": row.try_get::<Option<String>, _>("pattern").unwrap_or(None).unwrap_or_default(),
        "description": row.try_get::<Option<String>, _>("description").unwrap_or(None)
      })
    })
    .collect();

  success(
    json!({
      "rules": rules,
      "pagination": {
        "page": page,
        "limit": limit,
        "total": total
      },
      "statistics": {
        "enabledRules": total,
        "blockRules": 0,
        "warnRules": 0
      }
    }),
    "Success"
  )
  .into_response()
}

async fn get_audit_logs(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>,
  Query(query): Query<AuditQuery>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let page = query.page.unwrap_or(1).max(1);
  let mut limit = query.limit.unwrap_or(20);
  if limit <= 0 {
    limit = 20;
  }
  if limit > 100 {
    limit = 100;
  }
  let offset = (page - 1) * limit;

  let rows = sqlx::query(
    r#"
    SELECT
      al.created_at as time,
      n.name as node_name,
      ar.name as triggered_rule,
      al.ip_address as client_ip
    FROM audit_logs al
    LEFT JOIN nodes n ON al.node_id = n.id
    LEFT JOIN audit_rules ar ON al.audit_rule_id = ar.id
    WHERE al.user_id = ?
    ORDER BY al.created_at DESC
    LIMIT ? OFFSET ?
    "#
  )
  .bind(user_id)
  .bind(limit)
  .bind(offset)
  .fetch_all(&state.db)
  .await;
  let rows = match rows {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let total_row = sqlx::query("SELECT COUNT(*) as total FROM audit_logs WHERE user_id = ?")
    .bind(user_id)
    .fetch_optional(&state.db)
    .await;
  let total_row = match total_row {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };
  let total = total_row
    .and_then(|row| row.try_get::<Option<i64>, _>("total").ok().flatten())
    .unwrap_or(0);

  let logs: Vec<Value> = rows
    .into_iter()
    .map(|row| {
      json!({
        "time": format_datetime(row.try_get::<Option<NaiveDateTime>, _>("time").ok().flatten()),
        "node_name": row.try_get::<Option<String>, _>("node_name").ok().flatten(),
        "triggered_rule": row.try_get::<Option<String>, _>("triggered_rule").ok().flatten(),
        "client_ip": row.try_get::<Option<String>, _>("client_ip").ok().flatten()
      })
    })
    .collect();

  success(
    json!({
      "logs": logs,
      "pagination": {
        "page": page,
        "limit": limit,
        "total": total
      },
      "statistics": {
        "totalLogs": total,
        "blockedLogs": 0,
        "warnedLogs": 0,
        "todayLogs": 0
      }
    }),
    "Success"
  )
  .into_response()
}

async fn get_audit_overview(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>
) -> Response {
  let user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let rules_stats = sqlx::query(
    r#"
    SELECT
      COUNT(*) as total_rules,
      SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as enabled_rules
    FROM audit_rules
    "#
  )
  .fetch_optional(&state.db)
  .await;
  let rules_stats = match rules_stats {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let logs_stats = sqlx::query(
    r#"
    SELECT
      COUNT(*) as total_logs,
      SUM(CASE WHEN DATE(created_at) = CURRENT_DATE THEN 1 ELSE 0 END) as today_logs,
      SUM(CASE WHEN created_at >= DATE_SUB(CURRENT_DATE, INTERVAL 7 DAY) THEN 1 ELSE 0 END) as week_logs,
      SUM(CASE WHEN created_at >= DATE_SUB(CURRENT_DATE, INTERVAL 30 DAY) THEN 1 ELSE 0 END) as month_logs
    FROM audit_logs
    WHERE user_id = ?
    "#
  )
  .bind(user_id)
  .fetch_optional(&state.db)
  .await;
  let logs_stats = match logs_stats {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let recent_rows = sqlx::query(
    r#"
    SELECT
      al.created_at as timestamp,
      n.name as node_name,
      ar.name as rule_name,
      al.ip_address as target_url,
      'log' as action
    FROM audit_logs al
    LEFT JOIN nodes n ON al.node_id = n.id
    LEFT JOIN audit_rules ar ON al.audit_rule_id = ar.id
    WHERE al.user_id = ?
    ORDER BY al.created_at DESC
    LIMIT 5
    "#
  )
  .bind(user_id)
  .fetch_all(&state.db)
  .await;
  let recent_rows = match recent_rows {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let total_rules = rules_stats
    .as_ref()
    .and_then(|row| row.try_get::<Option<i64>, _>("total_rules").ok().flatten())
    .unwrap_or(0);
  let enabled_rules = rules_stats
    .as_ref()
    .and_then(|row| row.try_get::<Option<i64>, _>("enabled_rules").ok().flatten())
    .unwrap_or(0);

  let total_logs = logs_stats
    .as_ref()
    .and_then(|row| row.try_get::<Option<i64>, _>("total_logs").ok().flatten())
    .unwrap_or(0);
  let today_logs = logs_stats
    .as_ref()
    .and_then(|row| row.try_get::<Option<i64>, _>("today_logs").ok().flatten())
    .unwrap_or(0);
  let week_logs = logs_stats
    .as_ref()
    .and_then(|row| row.try_get::<Option<i64>, _>("week_logs").ok().flatten())
    .unwrap_or(0);
  let month_logs = logs_stats
    .as_ref()
    .and_then(|row| row.try_get::<Option<i64>, _>("month_logs").ok().flatten())
    .unwrap_or(0);

  let recent_logs: Vec<Value> = recent_rows
    .into_iter()
    .map(|row| {
      json!({
        "timestamp": format_datetime(row.try_get::<Option<NaiveDateTime>, _>("timestamp").ok().flatten()),
        "action": row
          .try_get::<Option<String>, _>("action")
          .ok()
          .flatten()
          .unwrap_or_else(|| "log".to_string()),
        "target_url": row.try_get::<Option<String>, _>("target_url").ok().flatten(),
        "rule_name": row.try_get::<Option<String>, _>("rule_name").ok().flatten(),
        "node_name": row.try_get::<Option<String>, _>("node_name").ok().flatten()
      })
    })
    .collect();

  success(
    json!({
      "rules": {
        "totalRules": total_rules,
        "enabledRules": enabled_rules,
        "blockRules": 0,
        "warnRules": 0
      },
      "logs": {
        "totalLogs": total_logs,
        "blockedLogs": 0,
        "warnedLogs": 0,
        "todayLogs": today_logs,
        "weekLogs": week_logs,
        "monthLogs": month_logs
      },
      "recentLogs": recent_logs
    }),
    "Success"
  )
  .into_response()
}

async fn get_shared_ids(
  State(state): State<AppState>,
  Extension(headers): Extension<axum::http::HeaderMap>
) -> Response {
  let _user_id = match require_user_id(&state, &headers, None).await {
    Ok(value) => value,
    Err(resp) => return resp
  };

  let rows = sqlx::query(
    r#"
    SELECT id, name, fetch_url, remote_account_id, status
    FROM shared_ids
    WHERE status = 1
    ORDER BY id DESC
    "#
  )
  .fetch_all(&state.db)
  .await;
  let rows = match rows {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let client = match reqwest::Client::builder()
    .timeout(std::time::Duration::from_secs(8))
    .build()
  {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let mut items = Vec::with_capacity(rows.len());
  for row in rows {
    let record = SharedIdRow::from_row(&row);
    let item = fetch_shared_id(&client, record).await;
    items.push(item);
  }

  success(json!({ "items": items, "count": items.len() }), "Success").into_response()
}

#[derive(Clone)]
struct UserTwoFactorRow {
  id: i64,
  email: String,
  username: String,
  password_hash: String,
  two_factor_enabled: i64,
  two_factor_secret: Option<String>,
  two_factor_backup_codes: Option<String>,
  two_factor_temp_secret: Option<String>
}

impl UserTwoFactorRow {
  fn from_row(row: &sqlx::mysql::MySqlRow) -> Self {
    Self {
      id: row.try_get::<i64, _>("id").unwrap_or(0),
      email: row.try_get::<String, _>("email").unwrap_or_default(),
      username: row.try_get::<String, _>("username").unwrap_or_default(),
      password_hash: row.try_get::<String, _>("password_hash").unwrap_or_default(),
      two_factor_enabled: row.try_get::<Option<i64>, _>("two_factor_enabled").unwrap_or(Some(0)).unwrap_or(0),
      two_factor_secret: row.try_get::<Option<String>, _>("two_factor_secret").ok().flatten(),
      two_factor_backup_codes: row.try_get::<Option<String>, _>("two_factor_backup_codes").ok().flatten(),
      two_factor_temp_secret: row.try_get::<Option<String>, _>("two_factor_temp_secret").ok().flatten()
    }
  }
}

struct TwoFactorVerification {
  success: bool
}

#[derive(Clone)]
struct UserProfileRow {
  id: i64,
  email: String,
  username: String,
  uuid: String,
  passwd: String,
  token: String,
  is_admin: i64,
  class_level: i64,
  class_expire_time: Option<NaiveDateTime>,
  expire_time: Option<NaiveDateTime>,
  speed_limit: i64,
  device_limit: i64,
  tcp_limit: i64,
  upload_traffic: i64,
  download_traffic: i64,
  upload_today: i64,
  download_today: i64,
  transfer_total: i64,
  transfer_enable: i64,
  reg_date: Option<NaiveDateTime>,
  last_login_time: Option<NaiveDateTime>,
  last_login_ip: Option<String>,
  status: i64,
  invite_code: Option<String>,
  invited_by: i64,
  invite_limit: i64,
  invite_used: i64,
  rebate_available: f64,
  rebate_total: f64,
  register_ip: Option<String>,
  two_factor_enabled: i64,
  two_factor_backup_codes: Option<String>
}

impl UserProfileRow {
  fn from_row(row: &sqlx::mysql::MySqlRow) -> Self {
    Self {
      id: row.try_get::<i64, _>("id").unwrap_or(0),
      email: row.try_get::<String, _>("email").unwrap_or_default(),
      username: row.try_get::<String, _>("username").unwrap_or_default(),
      uuid: row.try_get::<String, _>("uuid").unwrap_or_default(),
      passwd: row.try_get::<String, _>("passwd").unwrap_or_default(),
      token: row.try_get::<String, _>("token").unwrap_or_default(),
      is_admin: row.try_get::<Option<i64>, _>("is_admin").unwrap_or(Some(0)).unwrap_or(0),
      class_level: row.try_get::<Option<i64>, _>("class").unwrap_or(Some(0)).unwrap_or(0),
      class_expire_time: row.try_get::<Option<NaiveDateTime>, _>("class_expire_time").ok().flatten(),
      expire_time: row.try_get::<Option<NaiveDateTime>, _>("expire_time").ok().flatten(),
      speed_limit: row.try_get::<Option<i64>, _>("speed_limit").unwrap_or(Some(0)).unwrap_or(0),
      device_limit: row.try_get::<Option<i64>, _>("device_limit").unwrap_or(Some(0)).unwrap_or(0),
      tcp_limit: row.try_get::<Option<i64>, _>("tcp_limit").unwrap_or(Some(0)).unwrap_or(0),
      upload_traffic: row.try_get::<Option<i64>, _>("upload_traffic").unwrap_or(Some(0)).unwrap_or(0),
      download_traffic: row.try_get::<Option<i64>, _>("download_traffic").unwrap_or(Some(0)).unwrap_or(0),
      upload_today: row.try_get::<Option<i64>, _>("upload_today").unwrap_or(Some(0)).unwrap_or(0),
      download_today: row.try_get::<Option<i64>, _>("download_today").unwrap_or(Some(0)).unwrap_or(0),
      transfer_total: row.try_get::<Option<i64>, _>("transfer_total").unwrap_or(Some(0)).unwrap_or(0),
      transfer_enable: row.try_get::<Option<i64>, _>("transfer_enable").unwrap_or(Some(0)).unwrap_or(0),
      reg_date: row.try_get::<Option<NaiveDateTime>, _>("reg_date").ok().flatten(),
      last_login_time: row.try_get::<Option<NaiveDateTime>, _>("last_login_time").ok().flatten(),
      last_login_ip: row.try_get::<Option<String>, _>("last_login_ip").ok().flatten(),
      status: row.try_get::<Option<i64>, _>("status").unwrap_or(Some(0)).unwrap_or(0),
      invite_code: row.try_get::<Option<String>, _>("invite_code").ok().flatten(),
      invited_by: row.try_get::<Option<i64>, _>("invited_by").unwrap_or(Some(0)).unwrap_or(0),
      invite_limit: row.try_get::<Option<i64>, _>("invite_limit").unwrap_or(Some(0)).unwrap_or(0),
      invite_used: row.try_get::<Option<i64>, _>("invite_used").unwrap_or(Some(0)).unwrap_or(0),
      rebate_available: parse_decimal(row, "rebate_available", 0.0),
      rebate_total: parse_decimal(row, "rebate_total", 0.0),
      register_ip: row.try_get::<Option<String>, _>("register_ip").ok().flatten(),
      two_factor_enabled: row.try_get::<Option<i64>, _>("two_factor_enabled").unwrap_or(Some(0)).unwrap_or(0),
      two_factor_backup_codes: row.try_get::<Option<String>, _>("two_factor_backup_codes").ok().flatten()
    }
  }
}

#[derive(Clone)]
struct UserPasswordRow {
  password_hash: String
}

impl UserPasswordRow {
  fn from_row(row: &sqlx::mysql::MySqlRow) -> Self {
    Self {
      password_hash: row.try_get::<String, _>("password_hash").unwrap_or_default()
    }
  }
}

async fn get_user_profile(state: &AppState, user_id: i64) -> Result<Option<UserProfileRow>, String> {
  let row = sqlx::query(
    r#"
    SELECT id, email, username, uuid, passwd, token, is_admin, class, class_expire_time,
           expire_time, speed_limit, device_limit, tcp_limit, upload_traffic, download_traffic,
           upload_today, download_today, transfer_total, transfer_enable, reg_date,
           last_login_time, last_login_ip, status, invite_code, invited_by, invite_limit, invite_used,
           rebate_available, rebate_total, register_ip, two_factor_enabled, two_factor_backup_codes
    FROM users WHERE id = ?
    "#
  )
  .bind(user_id)
  .fetch_optional(&state.db)
  .await
  .map_err(|err| err.to_string())?;
  Ok(row.map(|r| UserProfileRow::from_row(&r)))
}

async fn get_user_password_info(state: &AppState, user_id: i64) -> Result<Option<UserPasswordRow>, String> {
  let row = sqlx::query("SELECT password_hash FROM users WHERE id = ?")
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string())?;
  Ok(row.map(|r| UserPasswordRow::from_row(&r)))
}

async fn update_user_password(state: &AppState, user_id: i64, password_hash: &str) -> Result<(), String> {
  sqlx::query(
    r#"
    UPDATE users
    SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
    "#
  )
  .bind(password_hash)
  .bind(user_id)
  .execute(&state.db)
  .await
  .map_err(|err| err.to_string())?;
  Ok(())
}

async fn update_user_profile(
  state: &AppState,
  user_id: i64,
  username: Option<String>,
  email: Option<String>
) -> Result<(), String> {
  sqlx::query(
    r#"
    UPDATE users
    SET username = COALESCE(?, username),
        email = COALESCE(?, email),
        updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
    "#
  )
  .bind(username)
  .bind(email)
  .bind(user_id)
  .execute(&state.db)
  .await
  .map_err(|err| err.to_string())?;
  Ok(())
}

const MAX_TICKET_TITLE_LENGTH: usize = 120;
const MAX_TICKET_CONTENT_LENGTH: usize = 8000;

#[derive(Clone)]
struct InviteStats {
  invite_code: Option<String>,
  invited_by: Option<i64>,
  invite_used: i64,
  invite_limit: i64,
  rebate_available: f64,
  rebate_total: f64,
  total_invitees: i64,
  confirmed_invitees: i64
}

async fn get_user_invite_stats(
  state: &AppState,
  user_id: i64
) -> Result<Option<InviteStats>, String> {
  let row = sqlx::query(
    r#"
    SELECT invite_code, invited_by, invite_used, invite_limit, rebate_available, rebate_total
    FROM users WHERE id = ?
    "#
  )
  .bind(user_id)
  .fetch_optional(&state.db)
  .await
  .map_err(|err| err.to_string())?;
  let row = match row {
    Some(value) => value,
    None => return Ok(None)
  };

  let total_row = sqlx::query(
    r#"
    SELECT COUNT(*) as total,
           SUM(CASE WHEN status = 'confirmed' THEN 1 ELSE 0 END) as confirmed
    FROM referral_relations
    WHERE inviter_id = ?
    "#
  )
  .bind(user_id)
  .fetch_optional(&state.db)
  .await
  .map_err(|err| err.to_string())?;

  Ok(Some(InviteStats {
    invite_code: row.try_get::<Option<String>, _>("invite_code").ok().flatten(),
    invited_by: row.try_get::<Option<i64>, _>("invited_by").ok().flatten(),
    invite_used: row.try_get::<Option<i64>, _>("invite_used").unwrap_or(Some(0)).unwrap_or(0),
    invite_limit: row.try_get::<Option<i64>, _>("invite_limit").unwrap_or(Some(0)).unwrap_or(0),
    rebate_available: parse_decimal(&row, "rebate_available", 0.0),
    rebate_total: parse_decimal(&row, "rebate_total", 0.0),
    total_invitees: total_row
      .as_ref()
      .and_then(|row| row.try_get::<Option<i64>, _>("total").ok().flatten())
      .unwrap_or(0),
    confirmed_invitees: total_row
      .as_ref()
      .and_then(|row| row.try_get::<Option<i64>, _>("confirmed").ok().flatten())
      .unwrap_or(0)
  }))
}

async fn list_referral_rows(
  state: &AppState,
  inviter_id: i64,
  page: i64,
  page_size: i64
) -> Result<(Vec<sqlx::mysql::MySqlRow>, i64), String> {
  let offset = (page - 1) * page_size;
  let rows = sqlx::query(
    r#"
    SELECT
      rr.*,
      u.email as invitee_email,
      u.username as invitee_username,
      (
        SELECT COALESCE(SUM(amount), 0)
        FROM rebate_transactions rt
        WHERE rt.referral_id = rr.id AND rt.amount > 0
      ) AS total_rebate
    FROM referral_relations rr
    LEFT JOIN users u ON rr.invitee_id = u.id
    WHERE rr.inviter_id = ?
    ORDER BY rr.created_at DESC
    LIMIT ? OFFSET ?
    "#
  )
  .bind(inviter_id)
  .bind(page_size)
  .bind(offset)
  .fetch_all(&state.db)
  .await
  .map_err(|err| err.to_string())?;

  let total_row = sqlx::query("SELECT COUNT(*) as total FROM referral_relations WHERE inviter_id = ?")
    .bind(inviter_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string())?;
  let total = total_row
    .and_then(|row| row.try_get::<Option<i64>, _>("total").ok().flatten())
    .unwrap_or(0);

  Ok((rows, total))
}

fn referral_row_full_value(row: &sqlx::mysql::MySqlRow) -> Value {
  json!({
    "id": row.try_get::<i64, _>("id").unwrap_or(0),
    "inviter_id": row.try_get::<i64, _>("inviter_id").unwrap_or(0),
    "invitee_id": row.try_get::<i64, _>("invitee_id").unwrap_or(0),
    "invite_code": row
      .try_get::<Option<String>, _>("invite_code")
      .ok()
      .flatten()
      .unwrap_or_default(),
    "invite_ip": row.try_get::<Option<String>, _>("invite_ip").ok().flatten(),
    "registered_at": format_datetime(row.try_get::<Option<NaiveDateTime>, _>("registered_at").ok().flatten()),
    "first_payment_type": row.try_get::<Option<String>, _>("first_payment_type").ok().flatten(),
    "first_payment_id": row.try_get::<Option<i64>, _>("first_payment_id").ok().flatten(),
    "first_paid_at": format_datetime(row.try_get::<Option<NaiveDateTime>, _>("first_paid_at").ok().flatten()),
    "status": row
      .try_get::<Option<String>, _>("status")
      .ok()
      .flatten()
      .unwrap_or_else(|| "pending".to_string()),
    "created_at": format_datetime(row.try_get::<Option<NaiveDateTime>, _>("created_at").ok().flatten()),
    "updated_at": format_datetime(row.try_get::<Option<NaiveDateTime>, _>("updated_at").ok().flatten()),
    "invitee_email": row.try_get::<Option<String>, _>("invitee_email").ok().flatten(),
    "invitee_username": row.try_get::<Option<String>, _>("invitee_username").ok().flatten(),
    "total_rebate": parse_decimal(row, "total_rebate", 0.0)
  })
}

fn referral_row_summary_value(row: &sqlx::mysql::MySqlRow) -> Value {
  json!({
    "id": row.try_get::<i64, _>("id").unwrap_or(0),
    "inviteeId": row.try_get::<i64, _>("invitee_id").unwrap_or(0),
    "email": row.try_get::<Option<String>, _>("invitee_email").ok().flatten(),
    "username": row.try_get::<Option<String>, _>("invitee_username").ok().flatten(),
    "status": row
      .try_get::<Option<String>, _>("status")
      .ok()
      .flatten()
      .unwrap_or_else(|| "pending".to_string()),
    "registeredAt": format_datetime(row.try_get::<Option<NaiveDateTime>, _>("created_at").ok().flatten()),
    "firstPaidAt": format_datetime(row.try_get::<Option<NaiveDateTime>, _>("first_paid_at").ok().flatten()),
    "totalRebate": parse_decimal(row, "total_rebate", 0.0)
  })
}

fn sanitize_text(input: &str, max_length: usize) -> String {
  let trimmed = input.trim();
  if trimmed.is_empty() {
    return String::new();
  }
  trimmed.chars().take(max_length).collect()
}

fn build_ticket_value(row: &sqlx::mysql::MySqlRow, include_content: bool) -> Value {
  let id = row.try_get::<i64, _>("id").unwrap_or(0);
  let title = row
    .try_get::<Option<String>, _>("title")
    .ok()
    .flatten()
    .unwrap_or_default();
  let status = row
    .try_get::<Option<String>, _>("status")
    .ok()
    .flatten()
    .unwrap_or_else(|| "open".to_string());
  let last_reply_at = format_datetime(row.try_get::<Option<NaiveDateTime>, _>("last_reply_at").ok().flatten());
  let created_at = format_datetime(row.try_get::<Option<NaiveDateTime>, _>("created_at").ok().flatten());
  let updated_at = format_datetime(row.try_get::<Option<NaiveDateTime>, _>("updated_at").ok().flatten());

  if include_content {
    let content = row
      .try_get::<Option<String>, _>("content")
      .ok()
      .flatten()
      .unwrap_or_default();
    json!({
      "id": id,
      "title": title,
      "content": content,
      "status": status,
      "last_reply_at": last_reply_at,
      "created_at": created_at,
      "updated_at": updated_at
    })
  } else {
    json!({
      "id": id,
      "title": title,
      "status": status,
      "last_reply_at": last_reply_at,
      "created_at": created_at,
      "updated_at": updated_at
    })
  }
}

async fn list_ticket_replies(state: &AppState, ticket_id: i64) -> Result<Vec<Value>, String> {
  let rows = sqlx::query(
    r#"
    SELECT tr.id, tr.ticket_id, tr.author_id, tr.author_role, tr.content, tr.created_at,
           u.username AS author_username, u.email AS author_email
    FROM ticket_replies tr
    LEFT JOIN users u ON tr.author_id = u.id
    WHERE tr.ticket_id = ?
    ORDER BY tr.created_at ASC
    "#
  )
  .bind(ticket_id)
  .fetch_all(&state.db)
  .await
  .map_err(|err| err.to_string())?;

  let replies = rows
    .into_iter()
    .map(|row| {
      json!({
        "id": row.try_get::<i64, _>("id").unwrap_or(0),
        "content": row
          .try_get::<Option<String>, _>("content")
          .ok()
          .flatten()
          .unwrap_or_default(),
        "created_at": format_datetime(row.try_get::<Option<NaiveDateTime>, _>("created_at").ok().flatten()),
        "author": {
          "id": row.try_get::<i64, _>("author_id").unwrap_or(0),
          "role": row
            .try_get::<Option<String>, _>("author_role")
            .ok()
            .flatten()
            .unwrap_or_else(|| "user".to_string()),
          "username": row.try_get::<Option<String>, _>("author_username").ok().flatten(),
          "email": row.try_get::<Option<String>, _>("author_email").ok().flatten()
        }
      })
    })
    .collect();

  Ok(replies)
}

#[derive(Clone)]
struct SharedIdRow {
  id: i64,
  name: String,
  fetch_url: Option<String>,
  remote_account_id: String
}

impl SharedIdRow {
  fn from_row(row: &sqlx::mysql::MySqlRow) -> Self {
    let remote_account_id = row
      .try_get::<Option<String>, _>("remote_account_id")
      .ok()
      .flatten()
      .or_else(|| {
        row
          .try_get::<Option<i64>, _>("remote_account_id")
          .ok()
          .flatten()
          .map(|value| value.to_string())
      })
      .unwrap_or_default();
    Self {
      id: row.try_get::<i64, _>("id").unwrap_or(0),
      name: row.try_get::<Option<String>, _>("name").ok().flatten().unwrap_or_default(),
      fetch_url: row.try_get::<Option<String>, _>("fetch_url").ok().flatten(),
      remote_account_id
    }
  }
}

async fn fetch_shared_id(client: &reqwest::Client, record: SharedIdRow) -> Value {
  let SharedIdRow {
    id,
    name,
    fetch_url,
    remote_account_id
  } = record;
  let now = Utc::now().to_rfc3339();
  let remote_account_ids = parse_remote_account_id_list_text(&remote_account_id);
  let mut value = json!({
    "id": id,
    "name": name,
    "remote_account_id": format_remote_account_id_for_response_text(&remote_account_id),
    "status": "error",
    "account": null,
    "accounts": []
  });

  if remote_account_ids.is_empty() {
    if let Some(obj) = value.as_object_mut() {
      obj.insert("status".to_string(), json!("error"));
      obj.insert("fetched_at".to_string(), json!(now));
      obj.insert("error".to_string(), json!("未配置远程账号 ID"));
    }
    return value;
  }

  let fetch_url = fetch_url.unwrap_or_default();
  if fetch_url.trim().is_empty() {
    if let Some(obj) = value.as_object_mut() {
      obj.insert("status".to_string(), json!("error"));
      obj.insert("fetched_at".to_string(), json!(now));
      obj.insert("message".to_string(), json!("未配置拉取地址"));
      obj.insert("error".to_string(), json!("苹果账号未配置拉取地址"));
    }
    return value;
  }

  let response = client
    .get(fetch_url.trim())
    .header("Accept", "application/json")
    .send()
    .await;
  let response = match response {
    Ok(value) => value,
    Err(err) => {
      if let Some(obj) = value.as_object_mut() {
        obj.insert("status".to_string(), json!("error"));
        obj.insert("fetched_at".to_string(), json!(now));
        obj.insert("error".to_string(), json!(err.to_string()));
      }
      return value;
    }
  };

  if !response.status().is_success() {
    if let Some(obj) = value.as_object_mut() {
      obj.insert("status".to_string(), json!("error"));
      obj.insert("fetched_at".to_string(), json!(now));
      obj.insert(
        "error".to_string(),
        json!(format!("远程接口返回状态 {}", response.status().as_u16()))
      );
    }
    return value;
  }

  let payload = response.json::<Value>().await;
  let payload = match payload {
    Ok(value) => value,
    Err(err) => {
      if let Some(obj) = value.as_object_mut() {
        obj.insert("status".to_string(), json!("error"));
        obj.insert("fetched_at".to_string(), json!(now));
        obj.insert("error".to_string(), json!(format!("远程拉取失败: {}", err)));
      }
      return value;
    }
  };

  let message = payload
    .get("msg")
    .and_then(Value::as_str)
    .or_else(|| payload.get("message").and_then(Value::as_str))
    .map(|value| value.to_string());
  let accounts = payload
    .get("accounts")
    .and_then(Value::as_array)
    .cloned()
    .unwrap_or_default();
  let mut matched_accounts: Vec<Value> = Vec::new();
  let mut missing_ids: Vec<i64> = Vec::new();
  for remote_id in &remote_account_ids {
    let matched = accounts.iter().find(|item| {
      if let Some(obj) = item.as_object() {
        obj.get("id").map(parse_value_id).unwrap_or(0) == *remote_id
      } else {
        parse_value_id(item) == *remote_id
      }
    });
    if let Some(account) = matched {
      matched_accounts.push(account.clone());
    } else {
      missing_ids.push(*remote_id);
    }
  }

  if let Some(obj) = value.as_object_mut() {
    obj.insert("fetched_at".to_string(), json!(now));
    if let Some(msg) = message.clone() {
      obj.insert("message".to_string(), json!(msg));
    }
    if !matched_accounts.is_empty() {
      obj.insert("status".to_string(), json!("ok"));
      obj.insert("account".to_string(), matched_accounts.first().cloned().unwrap_or(Value::Null));
      obj.insert("accounts".to_string(), json!(matched_accounts));
      if !missing_ids.is_empty() {
        obj.insert("missing_ids".to_string(), json!(missing_ids));
      }
    } else {
      obj.insert("status".to_string(), json!("missing"));
      obj.insert("account".to_string(), Value::Null);
      obj.insert("accounts".to_string(), json!([]));
      obj.insert("missing_ids".to_string(), json!(remote_account_ids));
      obj.insert("error".to_string(), json!("未找到匹配的ID"));
    }
  }

  value
}

fn parse_value_id(value: &Value) -> i64 {
  value
    .as_i64()
    .or_else(|| value.as_str().and_then(|text| text.parse::<i64>().ok()))
    .unwrap_or(0)
}

async fn get_user_id_by_username(state: &AppState, username: &str) -> Result<Option<i64>, String> {
  let row = sqlx::query("SELECT id FROM users WHERE username = ?")
    .bind(username)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string())?;
  Ok(row.and_then(|r| r.try_get::<Option<i64>, _>("id").ok().flatten()))
}

async fn get_user_id_by_email(state: &AppState, email: &str) -> Result<Option<i64>, String> {
  let row = sqlx::query("SELECT id FROM users WHERE email = ?")
    .bind(email)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string())?;
  Ok(row.and_then(|r| r.try_get::<Option<i64>, _>("id").ok().flatten()))
}

fn format_datetime(value: Option<NaiveDateTime>) -> Option<String> {
  value.map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
}

async fn update_subscription_token(state: &AppState, user_id: i64, token: &str) -> Result<(), String> {
  sqlx::query(
    r#"
    UPDATE users
    SET token = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
    "#
  )
  .bind(token)
  .bind(user_id)
  .execute(&state.db)
  .await
  .map_err(|err| err.to_string())?;
  Ok(())
}

async fn update_user_bark_settings(
  state: &AppState,
  user_id: i64,
  bark_key: Option<String>,
  bark_enabled: bool
) -> Result<(), String> {
  sqlx::query(
    r#"
    UPDATE users
    SET bark_key = ?, bark_enabled = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
    "#
  )
  .bind(bark_key)
  .bind(if bark_enabled { 1 } else { 0 })
  .bind(user_id)
  .execute(&state.db)
  .await
  .map_err(|err| err.to_string())?;
  Ok(())
}

async fn get_user_class(state: &AppState, user_id: i64) -> Result<Option<i64>, String> {
  let row = sqlx::query("SELECT class FROM users WHERE id = ?")
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string())?;
  Ok(row.and_then(|r| r.try_get::<Option<i64>, _>("class").ok().flatten()))
}

#[derive(Clone)]
struct NodeRow {
  id: i64,
  name: String,
  node_type: String,
  node_class: i64,
  node_bandwidth: i64,
  node_bandwidth_limit: i64,
  traffic_multiplier: f64,
  bandwidthlimit_resetday: i64,
  node_config: String,
  status: i64,
  created_at: Option<NaiveDateTime>
}

impl NodeRow {
  fn from_row(row: &sqlx::mysql::MySqlRow) -> Self {
    Self {
      id: row.try_get::<i64, _>("id").unwrap_or(0),
      name: row.try_get::<String, _>("name").unwrap_or_default(),
      node_type: row.try_get::<String, _>("type").unwrap_or_default(),
      node_class: row.try_get::<Option<i64>, _>("node_class").unwrap_or(Some(0)).unwrap_or(0),
      node_bandwidth: row.try_get::<Option<i64>, _>("node_bandwidth").unwrap_or(Some(0)).unwrap_or(0),
      node_bandwidth_limit: row.try_get::<Option<i64>, _>("node_bandwidth_limit").unwrap_or(Some(0)).unwrap_or(0),
      traffic_multiplier: parse_decimal(row, "traffic_multiplier", 1.0),
      bandwidthlimit_resetday: row
        .try_get::<Option<i64>, _>("bandwidthlimit_resetday")
        .unwrap_or(Some(0))
        .unwrap_or(0),
      node_config: row
        .try_get::<Option<String>, _>("node_config")
        .unwrap_or(Some("{}".to_string()))
        .unwrap_or_else(|| "{}".to_string()),
      status: row.try_get::<Option<i64>, _>("status").unwrap_or(Some(0)).unwrap_or(0),
      created_at: row.try_get::<Option<NaiveDateTime>, _>("created_at").ok().flatten()
    }
  }

  fn to_value(&self) -> Value {
    json!({
      "id": self.id,
      "name": self.name,
      "type": self.node_type,
      "node_class": self.node_class,
      "node_bandwidth": self.node_bandwidth,
      "node_bandwidth_limit": self.node_bandwidth_limit,
      "traffic_multiplier": self.traffic_multiplier,
      "bandwidthlimit_resetday": self.bandwidthlimit_resetday,
      "node_config": self.node_config,
      "status": self.status,
      "created_at": format_datetime(self.created_at)
    })
  }
}

fn parse_decimal(row: &sqlx::mysql::MySqlRow, column: &str, fallback: f64) -> f64 {
  if let Ok(Some(value)) = row.try_get::<Option<f64>, _>(column) {
    return value;
  }
  if let Ok(Some(value)) = row.try_get::<Option<sqlx::types::BigDecimal>, _>(column) {
    return value.to_string().parse::<f64>().unwrap_or(fallback);
  }
  if let Ok(Some(value)) = row.try_get::<Option<String>, _>(column) {
    return value.parse::<f64>().unwrap_or(fallback);
  }
  fallback
}

fn resolve_node_connection(node_config: &str) -> (String, i64, String, Value) {
  let parsed: Value = serde_json::from_str(node_config).unwrap_or_else(|_| json!({}));
  let config = parsed
    .get("config")
    .cloned()
    .unwrap_or_else(|| parsed.clone());
  let client = parsed
    .get("client")
    .cloned()
    .unwrap_or_else(|| json!({}));

  let server = client
    .get("server")
    .and_then(Value::as_str)
    .unwrap_or("")
    .to_string();
  let port_value = client
    .get("port")
    .and_then(|value| value.as_i64().or_else(|| value.as_str().and_then(|v| v.parse::<i64>().ok())))
    .or_else(|| config.get("port").and_then(|value| value.as_i64().or_else(|| value.as_str().and_then(|v| v.parse::<i64>().ok()))))
    .unwrap_or(0);
  let server_port = if port_value > 0 { port_value } else { 443 };
  let tls_host = client
    .get("tls_host")
    .and_then(Value::as_str)
    .or_else(|| config.get("host").and_then(Value::as_str))
    .unwrap_or(&server)
    .to_string();
  (server, server_port, tls_host, parsed)
}

fn traffic_value(row: Option<&sqlx::mysql::MySqlRow>, column: &str) -> i64 {
  row.and_then(|value| value.try_get::<Option<i64>, _>(column).ok().flatten())
    .unwrap_or(0)
}

fn normalize_time(value: String) -> String {
  value.replace('+', " ").trim().to_string()
}

fn weekday_label(number: u32) -> String {
  match number {
    1 => "周一".to_string(),
    2 => "周二".to_string(),
    3 => "周三".to_string(),
    4 => "周四".to_string(),
    5 => "周五".to_string(),
    6 => "周六".to_string(),
    _ => "周日".to_string()
  }
}

async fn fetch_user_traffic_summary(state: &AppState, user_id: i64) -> Result<Value, String> {
  let today = (Utc::now() + Duration::hours(8)).date_naive();
  let week_start = (today - Duration::days(7)).format("%Y-%m-%d").to_string();
  let month_start = (today - Duration::days(30)).format("%Y-%m-%d").to_string();

  let weekly_row = sqlx::query(
    r#"
    SELECT
      COALESCE(SUM(upload_traffic), 0) as week_upload,
      COALESCE(SUM(download_traffic), 0) as week_download,
      COALESCE(SUM(total_traffic), 0) as week_total,
      COUNT(*) as active_days
    FROM daily_traffic
    WHERE user_id = ? AND record_date >= ?
    "#
  )
  .bind(user_id)
  .bind(&week_start)
  .fetch_optional(&state.db)
  .await
  .map_err(|err| err.to_string())?;

  let total_row = sqlx::query(
    r#"
    SELECT
      COALESCE(SUM(upload_traffic), 0) as total_upload,
      COALESCE(SUM(download_traffic), 0) as total_download,
      COALESCE(SUM(total_traffic), 0) as total_traffic
    FROM daily_traffic
    WHERE user_id = ?
    "#
  )
  .bind(user_id)
  .fetch_optional(&state.db)
  .await
  .map_err(|err| err.to_string())?;

  let monthly_row = sqlx::query(
    r#"
    SELECT
      COALESCE(SUM(upload_traffic), 0) as month_upload,
      COALESCE(SUM(download_traffic), 0) as month_download,
      COALESCE(SUM(total_traffic), 0) as month_total,
      COUNT(*) as active_days
    FROM daily_traffic
    WHERE user_id = ? AND record_date >= ?
    "#
  )
  .bind(user_id)
  .bind(&month_start)
  .fetch_optional(&state.db)
  .await
  .map_err(|err| err.to_string())?;

  let peak_row = sqlx::query(
    r#"
    SELECT record_date, total_traffic, upload_traffic, download_traffic
    FROM daily_traffic
    WHERE user_id = ?
    ORDER BY total_traffic DESC
    LIMIT 1
    "#
  )
  .bind(user_id)
  .fetch_optional(&state.db)
  .await
  .map_err(|err| err.to_string())?;

  let weekly = weekly_row
    .map(|row| {
      let active_days = row.try_get::<Option<i64>, _>("active_days").unwrap_or(Some(0)).unwrap_or(0);
      if active_days <= 0 {
        return json!({});
      }
      json!({
        "week_upload": row.try_get::<Option<i64>, _>("week_upload").unwrap_or(Some(0)).unwrap_or(0),
        "week_download": row.try_get::<Option<i64>, _>("week_download").unwrap_or(Some(0)).unwrap_or(0),
        "week_total": row.try_get::<Option<i64>, _>("week_total").unwrap_or(Some(0)).unwrap_or(0),
        "active_days": active_days
      })
    })
    .unwrap_or_else(|| json!({}));

  let monthly = monthly_row
    .map(|row| {
      let active_days = row.try_get::<Option<i64>, _>("active_days").unwrap_or(Some(0)).unwrap_or(0);
      if active_days <= 0 {
        return json!({});
      }
      json!({
        "month_upload": row.try_get::<Option<i64>, _>("month_upload").unwrap_or(Some(0)).unwrap_or(0),
        "month_download": row.try_get::<Option<i64>, _>("month_download").unwrap_or(Some(0)).unwrap_or(0),
        "month_total": row.try_get::<Option<i64>, _>("month_total").unwrap_or(Some(0)).unwrap_or(0),
        "active_days": active_days
      })
    })
    .unwrap_or_else(|| json!({}));

  let peak = peak_row
    .map(|row| {
      let record_date = row
        .try_get::<Option<String>, _>("record_date")
        .ok()
        .flatten()
        .or_else(|| {
          row
            .try_get::<Option<chrono::NaiveDate>, _>("record_date")
            .ok()
            .flatten()
            .map(|value| value.format("%Y-%m-%d").to_string())
        });
      json!({
        "record_date": record_date,
        "total_traffic": row.try_get::<Option<i64>, _>("total_traffic").unwrap_or(Some(0)).unwrap_or(0),
        "upload_traffic": row.try_get::<Option<i64>, _>("upload_traffic").unwrap_or(Some(0)).unwrap_or(0),
        "download_traffic": row.try_get::<Option<i64>, _>("download_traffic").unwrap_or(Some(0)).unwrap_or(0)
      })
    })
    .unwrap_or(Value::Null);

  Ok(json!({
    "total_upload": total_row
      .as_ref()
      .and_then(|row| row.try_get::<Option<i64>, _>("total_upload").ok().flatten())
      .unwrap_or(0),
    "total_download": total_row
      .as_ref()
      .and_then(|row| row.try_get::<Option<i64>, _>("total_download").ok().flatten())
      .unwrap_or(0),
    "total_traffic": total_row
      .as_ref()
      .and_then(|row| row.try_get::<Option<i64>, _>("total_traffic").ok().flatten())
      .unwrap_or(0),
    "weekly": weekly,
    "monthly": monthly,
    "peak": peak
  }))
}

async fn fetch_user_traffic_stats(
  state: &AppState,
  user_id: i64,
  days: i64
) -> Result<Option<Value>, String> {
  let user_row = sqlx::query(
    r#"
    SELECT upload_traffic, download_traffic, transfer_enable, transfer_total,
           upload_today, download_today, last_login_time
    FROM users WHERE id = ?
    "#
  )
  .bind(user_id)
  .fetch_optional(&state.db)
  .await
  .map_err(|err| err.to_string())?;

  let user_row = match user_row {
    Some(value) => value,
    None => return Ok(None)
  };

  let upload = user_row.try_get::<Option<i64>, _>("upload_traffic").unwrap_or(Some(0)).unwrap_or(0);
  let download = user_row
    .try_get::<Option<i64>, _>("download_traffic")
    .unwrap_or(Some(0))
    .unwrap_or(0);
  let transfer_enable = user_row
    .try_get::<Option<i64>, _>("transfer_enable")
    .unwrap_or(Some(0))
    .unwrap_or(0);
  let transfer_total = user_row
    .try_get::<Option<i64>, _>("transfer_total")
    .unwrap_or(Some(0))
    .unwrap_or(0);
  let today_upload = user_row
    .try_get::<Option<i64>, _>("upload_today")
    .unwrap_or(Some(0))
    .unwrap_or(0);
  let today_download = user_row
    .try_get::<Option<i64>, _>("download_today")
    .unwrap_or(Some(0))
    .unwrap_or(0);
  let transfer_today = today_upload + today_download;
  let remain = (transfer_enable - transfer_total).max(0);
  let percentage = if transfer_enable > 0 {
    ((transfer_total as f64 / transfer_enable as f64) * 100.0).round() as i64
  } else {
    0
  };
  let last_checkin_time = format_datetime(
    user_row.try_get::<Option<NaiveDateTime>, _>("last_login_time").ok().flatten()
  );

  let history_rows = sqlx::query(
    r#"
    SELECT record_date as date, upload_traffic as upload, download_traffic as download, total_traffic
    FROM daily_traffic
    WHERE user_id = ? AND record_date >= DATE_SUB(CURRENT_DATE, INTERVAL ? DAY)
    ORDER BY record_date ASC
    "#
  )
  .bind(user_id)
  .bind(days)
  .fetch_all(&state.db)
  .await
  .map_err(|err| err.to_string())?;

  let mut history = map_daily_stats_rows(history_rows);
  if history.is_empty() {
    let fallback_rows = sqlx::query(
      r#"
      SELECT date,
             CAST(SUM(upload_traffic) AS SIGNED) as upload,
             CAST(SUM(download_traffic) AS SIGNED) as download,
             CAST(SUM(actual_traffic) AS SIGNED) as total_traffic
      FROM traffic_logs
      WHERE user_id = ? AND date >= DATE_SUB(CURRENT_DATE, INTERVAL ? DAY)
      GROUP BY date
      ORDER BY date ASC
      "#
    )
    .bind(user_id)
    .bind(days)
    .fetch_all(&state.db)
    .await
    .map_err(|err| err.to_string())?;
    history = map_daily_stats_rows(fallback_rows);
  }

  Ok(Some(json!({
    "used": transfer_total,
    "total": transfer_enable,
    "percentage": percentage,
    "today_used": transfer_today,
    "transfer_enable": transfer_enable,
    "transfer_total": transfer_total,
    "transfer_today": transfer_today,
    "remain_traffic": remain,
    "traffic_percentage": percentage,
    "upload_traffic": upload,
    "download_traffic": download,
    "today_upload": today_upload,
    "today_download": today_download,
    "traffic_stats": history,
    "total_days": days,
    "last_checkin_time": last_checkin_time
  })))
}

fn map_daily_stats_rows(rows: Vec<sqlx::mysql::MySqlRow>) -> Vec<Value> {
  rows
    .into_iter()
    .map(|row| {
      let date = row
        .try_get::<Option<String>, _>("date")
        .ok()
        .flatten()
        .unwrap_or_else(|| "".to_string());
      json!({
        "date": date,
        "upload": row.try_get::<Option<i64>, _>("upload").unwrap_or(Some(0)).unwrap_or(0),
        "download": row.try_get::<Option<i64>, _>("download").unwrap_or(Some(0)).unwrap_or(0),
        "total_traffic": row.try_get::<Option<i64>, _>("total_traffic").unwrap_or(Some(0)).unwrap_or(0)
      })
    })
    .collect()
}

fn map_traffic_rows(rows: Vec<sqlx::mysql::MySqlRow>) -> Vec<Value> {
  rows
    .into_iter()
    .map(|row| {
      json!({
        "id": row.try_get::<i64, _>("id").unwrap_or(0),
        "user_id": row.try_get::<i64, _>("user_id").unwrap_or(0),
        "node_id": row.try_get::<i64, _>("node_id").unwrap_or(0),
        "node_name": row.try_get::<Option<String>, _>("node_name").ok().flatten(),
        "upload_traffic": row.try_get::<Option<i64>, _>("upload_traffic").unwrap_or(Some(0)).unwrap_or(0),
        "download_traffic": row.try_get::<Option<i64>, _>("download_traffic").unwrap_or(Some(0)).unwrap_or(0),
        "actual_upload_traffic": row.try_get::<Option<i64>, _>("actual_upload_traffic").unwrap_or(Some(0)).unwrap_or(0),
        "actual_download_traffic": row.try_get::<Option<i64>, _>("actual_download_traffic").unwrap_or(Some(0)).unwrap_or(0),
        "total_traffic": row.try_get::<Option<i64>, _>("total_traffic").unwrap_or(Some(0)).unwrap_or(0),
        "actual_traffic": row.try_get::<Option<i64>, _>("actual_traffic").unwrap_or(Some(0)).unwrap_or(0),
        "deduction_multiplier": parse_decimal(&row, "deduction_multiplier", 1.0),
        "log_time": row.try_get::<Option<String>, _>("log_time").ok().flatten(),
        "created_at": format_datetime(row.try_get::<Option<NaiveDateTime>, _>("created_at").ok().flatten())
      })
    })
    .collect()
}

#[derive(Clone)]
enum SqlParam {
  I64(i64),
  String(String)
}

fn bind_params<'a>(
  mut query: sqlx::query::Query<'a, sqlx::MySql, sqlx::mysql::MySqlArguments>,
  params: &[SqlParam]
) -> sqlx::query::Query<'a, sqlx::MySql, sqlx::mysql::MySqlArguments> {
  for param in params {
    query = match param {
      SqlParam::I64(value) => query.bind(*value),
      SqlParam::String(value) => query.bind(value.clone())
    };
  }
  query
}

async fn aggregate_traffic_for_date(state: &AppState, record_date: &str) -> Result<(), String> {
  aggregate_daily_traffic(state, record_date).await?;
  aggregate_system_traffic(state, record_date).await?;
  Ok(())
}

async fn aggregate_daily_traffic(state: &AppState, record_date: &str) -> Result<(), String> {
  let rows = sqlx::query(
    r#"
    SELECT user_id,
           COALESCE(SUM(actual_upload_traffic), 0) as upload,
           COALESCE(SUM(actual_download_traffic), 0) as download,
           COALESCE(SUM(actual_traffic), 0) as total
    FROM traffic_logs
    WHERE date = ?
    GROUP BY user_id
    "#
  )
  .bind(record_date)
  .fetch_all(&state.db)
  .await
  .map_err(|err| err.to_string())?;

  for row in rows {
    let user_id = row.try_get::<i64, _>("user_id").unwrap_or(0);
    let upload = row.try_get::<Option<i64>, _>("upload").unwrap_or(Some(0)).unwrap_or(0);
    let download = row.try_get::<Option<i64>, _>("download").unwrap_or(Some(0)).unwrap_or(0);
    let total = row.try_get::<Option<i64>, _>("total").unwrap_or(Some(0)).unwrap_or(0);

    sqlx::query(
      r#"
      INSERT INTO daily_traffic (user_id, record_date, upload_traffic, download_traffic, total_traffic, created_at)
      VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      ON DUPLICATE KEY UPDATE
        upload_traffic = VALUES(upload_traffic),
        download_traffic = VALUES(download_traffic),
        total_traffic = VALUES(total_traffic)
      "#
    )
    .bind(user_id)
    .bind(record_date)
    .bind(upload)
    .bind(download)
    .bind(total)
    .execute(&state.db)
    .await
    .map_err(|err| err.to_string())?;
  }

  Ok(())
}

async fn aggregate_system_traffic(state: &AppState, record_date: &str) -> Result<(), String> {
  let row = sqlx::query(
    r#"
    SELECT
      COUNT(DISTINCT user_id) as users,
      COALESCE(SUM(actual_upload_traffic), 0) as total_upload,
      COALESCE(SUM(actual_download_traffic), 0) as total_download,
      COALESCE(SUM(actual_traffic), 0) as total_traffic
    FROM traffic_logs
    WHERE date = ?
    "#
  )
  .bind(record_date)
  .fetch_optional(&state.db)
  .await
  .map_err(|err| err.to_string())?;

  let users = row
    .as_ref()
    .and_then(|row| row.try_get::<Option<i64>, _>("users").ok().flatten())
    .unwrap_or(0);
  let total_upload = row
    .as_ref()
    .and_then(|row| row.try_get::<Option<i64>, _>("total_upload").ok().flatten())
    .unwrap_or(0);
  let total_download = row
    .as_ref()
    .and_then(|row| row.try_get::<Option<i64>, _>("total_download").ok().flatten())
    .unwrap_or(0);
  let total_traffic = row
    .as_ref()
    .and_then(|row| row.try_get::<Option<i64>, _>("total_traffic").ok().flatten())
    .unwrap_or(0);

  sqlx::query(
    r#"
    INSERT INTO system_traffic_summary (record_date, total_users, total_upload, total_download, total_traffic, created_at)
    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON DUPLICATE KEY UPDATE
      total_users = VALUES(total_users),
      total_upload = VALUES(total_upload),
      total_download = VALUES(total_download),
      total_traffic = VALUES(total_traffic)
    "#
  )
  .bind(record_date)
  .bind(users)
  .bind(total_upload)
  .bind(total_download)
  .bind(total_traffic)
  .execute(&state.db)
  .await
  .map_err(|err| err.to_string())?;

  Ok(())
}

async fn list_login_logs(
  state: &AppState,
  user_id: i64,
  limit: i64
) -> Result<Vec<Value>, String> {
  let rows = sqlx::query(
    r#"
    SELECT id, login_ip, login_time, user_agent, login_status, failure_reason, login_method, created_at
    FROM login_logs
    WHERE user_id = ?
    ORDER BY created_at DESC
    LIMIT ?
    "#
  )
  .bind(user_id)
  .bind(limit)
  .fetch_all(&state.db)
  .await
  .map_err(|err| err.to_string())?;

  let mut items = Vec::with_capacity(rows.len());
  for row in rows {
    items.push(json!({
      "id": row.try_get::<i64, _>("id").unwrap_or(0),
      "login_ip": row.try_get::<String, _>("login_ip").unwrap_or_default(),
      "login_time": format_datetime(row.try_get::<Option<NaiveDateTime>, _>("login_time").ok().flatten()),
      "user_agent": row.try_get::<Option<String>, _>("user_agent").ok().flatten(),
      "login_status": row.try_get::<Option<i64>, _>("login_status").unwrap_or(Some(1)).unwrap_or(1),
      "failure_reason": row.try_get::<Option<String>, _>("failure_reason").ok().flatten(),
      "login_method": row.try_get::<Option<String>, _>("login_method").ok().flatten(),
      "created_at": format_datetime(row.try_get::<Option<NaiveDateTime>, _>("created_at").ok().flatten())
    }));
  }
  Ok(items)
}

async fn get_two_factor_user(state: &AppState, user_id: i64) -> Result<Option<UserTwoFactorRow>, String> {
  let row = sqlx::query(
    r#"
    SELECT id, email, username, password_hash,
           two_factor_enabled, two_factor_secret, two_factor_backup_codes, two_factor_temp_secret
    FROM users WHERE id = ?
    "#
  )
  .bind(user_id)
  .fetch_optional(&state.db)
  .await
  .map_err(|err| err.to_string())?;
  Ok(row.map(|r| UserTwoFactorRow::from_row(&r)))
}

fn generate_totp_secret(length: usize) -> String {
  let mut bytes = vec![0u8; length];
  rand::thread_rng().fill(&mut bytes[..]);
  BASE32_NOPAD.encode(&bytes)
}

fn create_otp_auth_url(secret: &str, account: &str, issuer: &str) -> String {
  let label = if issuer.is_empty() {
    account.to_string()
  } else {
    format!("{}:{}", issuer, account)
  };
  let label_encoded = urlencoding::encode(&label);
  let issuer_encoded = urlencoding::encode(issuer);
  format!(
    "otpauth://totp/{}?secret={}&issuer={}",
    label_encoded, secret, issuer_encoded
  )
}

fn generate_backup_codes(count: usize) -> Vec<String> {
  let mut rng = rand::thread_rng();
  let mut codes = Vec::with_capacity(count);
  for _ in 0..count {
    let num: u32 = rng.gen_range(0..10_000_000);
    codes.push(format!("{:07}", num));
  }
  codes
}

fn hash_backup_codes(codes: &[String]) -> Vec<String> {
  codes
    .iter()
    .map(|code| sha256_hex(&normalize_backup_code(code)))
    .collect()
}

async fn set_two_factor_temp_secret(state: &AppState, user_id: i64, secret: &str) -> Result<(), String> {
  sqlx::query("UPDATE users SET two_factor_temp_secret = ? WHERE id = ?")
    .bind(secret)
    .bind(user_id)
    .execute(&state.db)
    .await
    .map_err(|err| err.to_string())?;
  Ok(())
}

async fn enable_two_factor(
  state: &AppState,
  user_id: i64,
  backup_codes: &[String]
) -> Result<(), String> {
  let payload = if backup_codes.is_empty() {
    Value::Null
  } else {
    json!(backup_codes)
  };

  sqlx::query(
    r#"
    UPDATE users
    SET two_factor_enabled = 1,
        two_factor_secret = two_factor_temp_secret,
        two_factor_backup_codes = ?,
        two_factor_temp_secret = NULL,
        two_factor_confirmed_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
    "#
  )
  .bind(payload.to_string())
  .bind(user_id)
  .execute(&state.db)
  .await
  .map_err(|err| err.to_string())?;
  Ok(())
}

async fn update_backup_codes(
  state: &AppState,
  user_id: i64,
  backup_codes: &[String]
) -> Result<(), String> {
  let payload = if backup_codes.is_empty() {
    Value::Null
  } else {
    json!(backup_codes)
  };

  sqlx::query(
    "UPDATE users SET two_factor_backup_codes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
  )
  .bind(payload.to_string())
  .bind(user_id)
  .execute(&state.db)
  .await
  .map_err(|err| err.to_string())?;
  Ok(())
}

async fn disable_two_factor(state: &AppState, user_id: i64) -> Result<(), String> {
  sqlx::query(
    r#"
    UPDATE users
    SET two_factor_enabled = 0,
        two_factor_secret = NULL,
        two_factor_backup_codes = NULL,
        two_factor_temp_secret = NULL,
        two_factor_confirmed_at = NULL,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
    "#
  )
  .bind(user_id)
  .execute(&state.db)
  .await
  .map_err(|err| err.to_string())?;
  Ok(())
}

async fn verify_user_two_factor_code(
  state: &AppState,
  user: &UserTwoFactorRow,
  code: &str
) -> Result<TwoFactorVerification, String> {
  let secret = decrypt_two_factor_secret(state, user.two_factor_secret.as_deref())?;
  let trimmed = code.trim();
  if verify_totp(&secret, trimmed, 1) {
    return Ok(TwoFactorVerification { success: true });
  }

  let mut backup_codes = parse_backup_codes(user.two_factor_backup_codes.as_deref());
  let hashed = sha256_hex(&normalize_backup_code(trimmed));
  if let Some(pos) = backup_codes.iter().position(|value| value == &hashed) {
    backup_codes.remove(pos);
    update_backup_codes(state, user.id, &backup_codes).await?;
    return Ok(TwoFactorVerification { success: true });
  }

  Ok(TwoFactorVerification { success: false })
}
