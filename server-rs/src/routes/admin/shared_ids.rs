use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

use crate::response::{error, success};
use crate::shared_ids::{
  format_remote_account_id_for_response_text,
  serialize_remote_account_id_for_db
};
use crate::state::AppState;

use super::super::auth::require_admin_user_id;

#[derive(Deserialize)]
struct SharedIdQuery {
  page: Option<i64>,
  limit: Option<i64>,
  #[serde(rename = "pageSize")]
  page_size: Option<i64>,
  keyword: Option<String>,
  status: Option<String>
}

#[derive(Deserialize)]
struct SharedIdPayload {
  name: Option<String>,
  fetch_url: Option<String>,
  remote_account_id: Option<Value>,
  status: Option<i64>
}

pub fn router() -> Router<AppState> {
  Router::new()
    .route("/", get(get_shared_ids))
    .route("/", post(post_shared_id))
    .route("/{id}", put(put_shared_id))
    .route("/{id}", delete(delete_shared_id))
}

async fn get_shared_ids(
  State(state): State<AppState>,
  Extension(headers): Extension<HeaderMap>,
  Query(query): Query<SharedIdQuery>
) -> Response {
  if let Err(resp) = require_admin_user_id(&state, &headers, None).await {
    return resp;
  }

  let page = query.page.unwrap_or(1).max(1);
  let limit_raw = query.limit.or(query.page_size).unwrap_or(20);
  let limit = limit_raw.max(1).min(100);
  let offset = (page - 1) * limit;
  let keyword = query.keyword.unwrap_or_default().trim().to_string();
  let status = query.status.as_deref().map(|value| value.trim()).unwrap_or("");

  let mut conditions: Vec<String> = Vec::new();
  let mut params: Vec<SqlParam> = Vec::new();

  if !keyword.is_empty() {
    conditions.push("name LIKE ?".to_string());
    params.push(SqlParam::String(format!("%{keyword}%")));
  }
  if !status.is_empty() {
    if let Ok(value) = status.parse::<i64>() {
      conditions.push("status = ?".to_string());
      params.push(SqlParam::I64(value));
    }
  }

  let where_clause = if conditions.is_empty() {
    String::new()
  } else {
    format!("WHERE {}", conditions.join(" AND "))
  };

  let total_sql = format!("SELECT COUNT(*) as total FROM shared_ids {where_clause}");
  let mut total_query = sqlx::query(&total_sql);
  total_query = bind_params(total_query, &params);
  let total_row = match total_query.fetch_optional(&state.db).await {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };
  let total = total_row
    .and_then(|row| row.try_get::<Option<i64>, _>("total").ok().flatten())
    .unwrap_or(0);

  let list_sql = format!(
    r#"
    SELECT id, name, fetch_url, remote_account_id, status, created_at, updated_at
    FROM shared_ids
    {where_clause}
    ORDER BY id DESC
    LIMIT ? OFFSET ?
    "#
  );
  let mut list_query = sqlx::query(&list_sql);
  list_query = bind_params(list_query, &params);
  let rows = match list_query
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
  {
    Ok(value) => value,
    Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None)
  };

  let records = rows
    .into_iter()
    .map(|row| {
      let remote_text = row
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
      json!({
        "id": row.try_get::<i64, _>("id").unwrap_or(0),
        "name": row.try_get::<Option<String>, _>("name").ok().flatten().unwrap_or_default(),
        "fetch_url": row.try_get::<Option<String>, _>("fetch_url").ok().flatten().unwrap_or_default(),
        "remote_account_id": format_remote_account_id_for_response_text(&remote_text),
        "status": row.try_get::<Option<i64>, _>("status").unwrap_or(Some(0)).unwrap_or(0),
        "created_at": row.try_get::<Option<chrono::NaiveDateTime>, _>("created_at").ok().flatten().map(format_datetime),
        "updated_at": row.try_get::<Option<chrono::NaiveDateTime>, _>("updated_at").ok().flatten().map(format_datetime)
      })
    })
    .collect::<Vec<Value>>();

  success(
    json!({
      "records": records,
      "pagination": {
        "total": total,
        "page": page,
        "limit": limit,
        "totalPages": if total > 0 { ((total as f64) / (limit as f64)).ceil() as i64 } else { 0 }
      }
    }),
    "Success"
  )
  .into_response()
}

async fn post_shared_id(
  State(state): State<AppState>,
  Extension(headers): Extension<HeaderMap>,
  Json(body): Json<SharedIdPayload>
) -> Response {
  if let Err(resp) = require_admin_user_id(&state, &headers, None).await {
    return resp;
  }
  let name = body.name.unwrap_or_default().trim().to_string();
  let fetch_url = body.fetch_url.unwrap_or_default().trim().to_string();
  let remote_account_value = body.remote_account_id.unwrap_or(Value::Null);
  let remote_account_text = match serialize_remote_account_id_for_db(&remote_account_value) {
    Ok(value) => value,
    Err(message) => return error(StatusCode::BAD_REQUEST, &message, None)
  };
  if name.is_empty() || fetch_url.is_empty() {
    return error(StatusCode::BAD_REQUEST, "参数缺失", None);
  }
  let status = body.status.unwrap_or(1);

  if let Err(err) = sqlx::query(
    r#"
    INSERT INTO shared_ids (name, fetch_url, remote_account_id, status)
    VALUES (?, ?, ?, ?)
    "#
  )
  .bind(&name)
  .bind(&fetch_url)
  .bind(remote_account_text)
  .bind(status)
  .execute(&state.db)
  .await
  {
    return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None);
  }

  success(Value::Null, "已创建").into_response()
}

async fn put_shared_id(
  State(state): State<AppState>,
  Extension(headers): Extension<HeaderMap>,
  Path(shared_id): Path<i64>,
  Json(body): Json<SharedIdPayload>
) -> Response {
  if let Err(resp) = require_admin_user_id(&state, &headers, None).await {
    return resp;
  }
  if shared_id <= 0 {
    return error(StatusCode::BAD_REQUEST, "ID 无效", None);
  }

  let mut updates: Vec<String> = Vec::new();
  let mut params: Vec<SqlParam> = Vec::new();

  if let Some(value) = body.name {
    let trimmed = value.trim().to_string();
    if !trimmed.is_empty() {
      updates.push("name = ?".to_string());
      params.push(SqlParam::String(trimmed));
    }
  }
  if let Some(value) = body.fetch_url {
    let trimmed = value.trim().to_string();
    if !trimmed.is_empty() {
      updates.push("fetch_url = ?".to_string());
      params.push(SqlParam::String(trimmed));
    }
  }
  if let Some(value) = body.remote_account_id {
    let remote_account_text = match serialize_remote_account_id_for_db(&value) {
      Ok(value) => value,
      Err(message) => return error(StatusCode::BAD_REQUEST, &message, None)
    };
    updates.push("remote_account_id = ?".to_string());
    params.push(SqlParam::String(remote_account_text));
  }
  if let Some(value) = body.status {
    updates.push("status = ?".to_string());
    params.push(SqlParam::I64(value));
  }

  if updates.is_empty() {
    return error(StatusCode::BAD_REQUEST, "没有需要更新的字段", None);
  }

  let sql = format!(
    "UPDATE shared_ids SET {}, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
    updates.join(", ")
  );
  let mut query_builder = sqlx::query(&sql);
  query_builder = bind_params(query_builder, &params);
  if let Err(err) = query_builder.bind(shared_id).execute(&state.db).await {
    return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None);
  }

  success(Value::Null, "已更新").into_response()
}

async fn delete_shared_id(
  State(state): State<AppState>,
  Extension(headers): Extension<HeaderMap>,
  Path(shared_id): Path<i64>
) -> Response {
  if let Err(resp) = require_admin_user_id(&state, &headers, None).await {
    return resp;
  }
  if shared_id <= 0 {
    return error(StatusCode::BAD_REQUEST, "ID 无效", None);
  }

  if let Err(err) = sqlx::query("DELETE FROM shared_ids WHERE id = ?")
    .bind(shared_id)
    .execute(&state.db)
    .await
  {
    return error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string(), None);
  }

  success(Value::Null, "已删除").into_response()
}

fn format_datetime(value: chrono::NaiveDateTime) -> String {
  value.format("%Y-%m-%d %H:%M:%S").to_string()
}

type SqlxQuery<'a> = sqlx::query::Query<'a, sqlx::MySql, sqlx::mysql::MySqlArguments>;

enum SqlParam {
  I64(i64),
  String(String)
}

fn bind_params<'a>(mut query: SqlxQuery<'a>, params: &'a [SqlParam]) -> SqlxQuery<'a> {
  for param in params {
    query = match param {
      SqlParam::I64(value) => query.bind(*value),
      SqlParam::String(value) => query.bind(value)
    };
  }
  query
}
