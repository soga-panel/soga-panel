mod config;
mod cache;
mod crypto;
mod etag;
mod jobs;
mod mail;
mod passkey;
mod payment;
mod response;
mod referral;
mod shared_ids;
mod routes;
mod state;
mod subscription;
mod templates;
mod totp;

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{header, HeaderName, HeaderValue, Method, Request, Uri};
use axum::middleware::Next;
use axum::response::Response;
use redis::aio::ConnectionManager;
use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tower_http::cors::{Any, CorsLayer};
use tokio::sync::RwLock;

use crate::config::{apply_dotenv, load_env};
use crate::jobs::{job_descriptions, run_job, JobKind};
use crate::state::{AppState, RedisStatus};

#[tokio::main]
async fn main() {
  let cli = match parse_cli_args() {
    Ok(value) => value,
    Err(message) => {
      eprintln!("{message}");
      std::process::exit(1);
    }
  };

  if cli.show_help {
    print_help(cli.env_path.as_deref());
    return;
  }

  if cli.show_version {
    println!("soga-panel-server {}", env!("CARGO_PKG_VERSION"));
    return;
  }

  if let Err(err) = apply_dotenv(cli.env_path.as_deref()) {
    eprintln!("[server] failed to load .env: {err}");
    std::process::exit(1);
  }

  apply_cli_overrides(&cli.overrides);

  tracing_subscriber::fmt()
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .init();

  let env = match load_env() {
    Ok(value) => value,
    Err(err) => {
      eprintln!("[server] failed to load env: {err}");
      std::process::exit(1);
    }
  };

  let state = match build_state(env.clone()).await {
    Ok(value) => value,
    Err(err) => {
      eprintln!("[server] failed to init state: {err}");
      std::process::exit(1);
    }
  };

  if let Some(job_name) = cli.job.clone() {
    let job = match JobKind::from_name(&job_name) {
      Some(value) => value,
      None => {
        eprintln!("未知任务: {job_name}");
        eprintln!("可用任务:");
        for (name, desc) in job_descriptions() {
          eprintln!("  {name}: {desc}");
        }
        std::process::exit(1);
      }
    };
    if let Err(err) = run_job(&state, job).await {
      eprintln!("[job] failed: {err}");
      std::process::exit(1);
    }
    return;
  }

  let cors = CorsLayer::new()
    .allow_origin(Any)
    .allow_methods([
      Method::GET,
      Method::POST,
      Method::PUT,
      Method::DELETE,
      Method::OPTIONS
    ])
    .allow_headers([
      header::CONTENT_TYPE,
      header::AUTHORIZATION,
      HeaderName::from_static("api-key"),
      HeaderName::from_static("node-id"),
      HeaderName::from_static("node-type"),
      HeaderName::from_static("if-none-match"),
      HeaderName::from_static("x-api-secret"),
      HeaderName::from_static("x-frontend-auth"),
      HeaderName::from_static("x-cloudflare-service-binding")
    ])
    .max_age(std::time::Duration::from_secs(86400));

  let app = routes::create_router(state)
    .layer(cors)
    .layer(axum::middleware::from_fn(app_middleware));

  let addr = SocketAddr::new(env.listen, env.port);
  println!("[server] listening on http://{}", addr);

  let listener = tokio::net::TcpListener::bind(addr).await;
  let listener = match listener {
    Ok(value) => value,
    Err(err) => {
      eprintln!("[server] failed to bind: {err}");
      std::process::exit(1);
    }
  };

  if let Err(err) = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await {
    eprintln!("[server] failed to start: {err}");
  }
}

async fn build_state(env: config::AppEnv) -> Result<AppState, String> {
  let db_options = MySqlConnectOptions::new()
    .host(&env.db_host)
    .port(env.db_port)
    .username(&env.db_user)
    .password(&env.db_password)
    .database(&env.db_name);

  let db_timezone = env.db_timezone.clone();
  let db = MySqlPoolOptions::new()
    .max_connections(env.db_connection_limit)
    .after_connect(move |conn, _meta| {
      let db_timezone = db_timezone.clone();
      Box::pin(async move {
        if !db_timezone.trim().is_empty() {
          sqlx::query("SET time_zone = ?")
            .bind(&db_timezone)
            .execute(conn)
            .await?;
        }
        Ok(())
      })
    })
    .connect_with(db_options)
    .await
    .map_err(|err| err.to_string())?;

  let (redis, redis_status) = match &env.redis_host {
    Some(host) => match build_redis_manager(host, &env).await {
      Ok(manager) => (Some(manager), RedisStatus::Ready),
      Err(err) => {
        tracing::warn!("[redis] connect failed, fallback to MariaDB only: {err}");
        (None, RedisStatus::Error(err))
      }
    },
    None => (None, RedisStatus::Disabled)
  };

  Ok(AppState {
    env,
    db,
    redis,
    redis_status,
    oauth_pending: Arc::new(RwLock::new(HashMap::new())),
    passkey_challenges: Arc::new(RwLock::new(HashMap::new()))
  })
}

#[derive(Default)]
struct CliArgs {
  env_path: Option<String>,
  show_help: bool,
  show_version: bool,
  job: Option<String>,
  overrides: HashMap<String, String>
}

fn parse_cli_args() -> Result<CliArgs, String> {
  let mut args = env::args().skip(1).peekable();
  let mut parsed = CliArgs::default();

  while let Some(arg) = args.next() {
    match arg.as_str() {
      "-help" | "--help" | "-h" => {
        parsed.show_help = true;
      }
      "-v" | "-version" => {
        parsed.show_version = true;
      }
      "-c" => {
        let value = args.next().ok_or_else(|| "缺少 -c 的 .env 路径参数".to_string())?;
        parsed.env_path = Some(value);
      }
      "Job" | "job" => {
        let name = args.next().ok_or_else(|| "缺少 Job 的任务名称".to_string())?;
        parsed.job = Some(name);
      }
      _ if arg.starts_with('-') => {
        let trimmed = arg.trim_start_matches('-');
        if trimmed.is_empty() {
          continue;
        }
        let (key, value) = if let Some((left, right)) = trimmed.split_once('=') {
          (left.to_string(), right.to_string())
        } else {
          let next = args.peek().cloned();
          match next {
            Some(value) if !value.starts_with('-') => {
              args.next();
              (trimmed.to_string(), value)
            }
            _ => return Err(format!("参数 -{trimmed} 缺少值")),
          }
        };
        let key = key.trim().to_uppercase();
        if key == "C" || key == "HELP" || key == "H" || key == "V" || key == "VERSION" {
          continue;
        }
        parsed.overrides.insert(key, value);
      }
      _ => {}
    }
  }

  Ok(parsed)
}

fn apply_cli_overrides(overrides: &HashMap<String, String>) {
  for (key, value) in overrides {
    env::set_var(key, value);
  }
}

fn print_help(env_path: Option<&str>) {
  let path = env_path.unwrap_or("../server/.env");
  let keys = read_env_keys(path);
  println!("Usage:");
  println!("  soga-panel-server -c <.env路径> -PORT <端口> -LISTEN <地址> -KEY <值>");
  println!("  soga-panel-server Job <任务名>");
  println!();
  println!("常用参数:");
  println!("  -help / -h           显示帮助");
  println!("  -v / -version        显示版本号");
  println!("  -c <path>            指定 .env 路径");
  println!("  -PORT <port>         指定服务端口");
  println!("  -LISTEN <addr>       指定监听地址");
  println!();
  println!("任务执行:");
  for (name, desc) in job_descriptions() {
    println!("  Job {name}        {desc}");
  }
  println!();
  println!("优先级: 运行参数 > 环境变量 > .env");
  println!();
  if keys.is_empty() {
    println!("未找到可用的 .env 参数列表（路径: {path}）");
    return;
  }
  println!("支持的环境变量（来自 {}）：", path);
  for key in keys {
    println!("  -{key}");
  }
}

fn read_env_keys(path: &str) -> Vec<String> {
  let content = match fs::read_to_string(path) {
    Ok(value) => value,
    Err(_) => return Vec::new()
  };
  let mut keys: Vec<String> = Vec::new();
  for line in content.lines() {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
      continue;
    }
    if let Some((key, _)) = trimmed.split_once('=') {
      let key = key.trim().to_string();
      if !key.is_empty() && !keys.contains(&key) {
        keys.push(key);
      }
    }
  }
  keys
}

async fn build_redis_manager(host: &str, env: &config::AppEnv) -> Result<ConnectionManager, String> {
  let password = env.redis_password.clone().unwrap_or_default();
  let auth_part = if password.is_empty() {
    "".to_string()
  } else {
    format!(":{password}@")
  };
  let url = format!(
    "redis://{}{}:{}/{}",
    auth_part, host, env.redis_port, env.redis_db
  );
  let client = redis::Client::open(url.as_str()).map_err(|err| err.to_string())?;
  ConnectionManager::new(client).await.map_err(|err| err.to_string())
}

async fn app_middleware(mut req: Request<Body>, next: Next) -> Response {
  let start = Instant::now();
  let method = req.method().clone();
  let original_uri = req.uri().to_string();

  if let Some(connect_info) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
    if !req.headers().contains_key("x-real-ip") {
      let ip = connect_info.0.ip().to_string();
      if let Ok(value) = HeaderValue::from_str(&ip) {
        req.headers_mut().insert(HeaderName::from_static("x-real-ip"), value);
      }
    }
  }

  let headers_snapshot = req.headers().clone();

  if original_uri.starts_with("/api/api/") {
    let replaced = original_uri.replacen("/api/api/", "/api/", 1);
    if let Ok(new_uri) = replaced.parse::<Uri>() {
      *req.uri_mut() = new_uri;
    }
  }

  req.extensions_mut().insert(headers_snapshot);

  let mut response = next.run(req).await;
  let headers = response.headers_mut();
  headers.insert(
    header::CACHE_CONTROL,
    HeaderValue::from_static("no-store, no-cache, must-revalidate")
  );
  headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
  headers.insert(header::EXPIRES, HeaderValue::from_static("0"));

  let duration = start.elapsed().as_millis();
  println!(
    "[http] {} {} {} {}ms",
    method,
    original_uri,
    response.status().as_u16(),
    duration
  );

  response
}
