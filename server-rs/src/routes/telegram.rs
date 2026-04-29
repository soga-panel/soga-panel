use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{NaiveDateTime, Utc};
use rand::seq::SliceRandom;
use rand::Rng;
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::HashSet;
use urlencoding::encode;

use super::auth::list_system_configs;
use crate::crypto::{
    generate_uuid, hash_password, random_base64, random_numeric_code, random_string, sha256_hex,
    verify_password,
};
use crate::mail::EmailService;
use crate::referral::{
    ensure_user_invite_code, find_inviter_by_code, increment_invite_usage, normalize_invite_code,
    save_referral_relation,
};
use crate::response::{error, success};
use crate::state::AppState;
use crate::templates::email_templates::{
    build_email_subject, build_email_text, build_verification_html, get_verification_title_text,
};

const TELEGRAM_BIND_CODE_MIN_LEN: usize = 8;
const TELEGRAM_BIND_CODE_MAX_LEN: usize = 64;
const LINK_CALLBACK_PREFIX: &str = "link:";
const NOTIFY_CALLBACK_PREFIX: &str = "notify:";
const REGISTER_CAPTCHA_CALLBACK_PREFIX: &str = "regcap:";
const REGISTER_CAPTCHA_TTL_SECONDS: i64 = 10 * 60;
const REGISTER_SESSION_TTL_SECONDS: i64 = 30 * 60;
const REGISTER_COMMAND_COOLDOWN_SECONDS: i64 = 30;
const REGISTER_EMAIL_CODE_MAX_ATTEMPTS: i64 = 5;
const REGISTER_HUMAN_CODE_MAX_ATTEMPTS: i64 = 5;
const REGISTER_HUMAN_CODE_LENGTH: usize = 8;
const REGISTER_HUMAN_CODE_DIGITS: &str = "23456789";
const REGISTER_HUMAN_CODE_LETTERS: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const REGISTER_INVITE_SKIP_INPUTS: [&str; 5] = ["skip", "none", "-", "无", "跳过"];
const TELEGRAM_TICKET_TEXT_MAX_LEN: usize = 3800;

struct TelegramBotConfig {
    token: String,
    api_base: String,
    webhook_secret: String,
}

struct ParsedCommand {
    name: String,
    arg: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RegisterStage {
    CaptchaPending,
    EmailPending,
    UsernamePending,
    InvitePending,
    EmailCodePending,
}

impl RegisterStage {
    fn as_str(&self) -> &'static str {
        match self {
            Self::CaptchaPending => "captcha_pending",
            Self::EmailPending => "email_pending",
            Self::UsernamePending => "username_pending",
            Self::InvitePending => "invite_pending",
            Self::EmailCodePending => "email_code_pending",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "captcha_pending" => Some(Self::CaptchaPending),
            "email_pending" => Some(Self::EmailPending),
            "username_pending" => Some(Self::UsernamePending),
            "invite_pending" => Some(Self::InvitePending),
            "email_code_pending" => Some(Self::EmailCodePending),
            _ => None,
        }
    }
}

#[derive(Clone)]
struct TelegramRegisterSession {
    chat_id: String,
    stage: RegisterStage,
    human_code_hash: String,
    human_code_expires_at: i64,
    human_code_attempts: i64,
    email: String,
    username: String,
    invite_code: String,
    email_code_attempts: i64,
    session_expires_at: i64,
}

#[derive(Clone)]
struct BoundTelegramUser {
    id: i64,
    email: String,
    username: String,
    class_level: i64,
    class_expire_time: Option<NaiveDateTime>,
    expire_time: Option<NaiveDateTime>,
    transfer_total: i64,
    transfer_enable: i64,
    upload_today: i64,
    download_today: i64,
    status: i64,
    token: String,
    telegram_enabled: i64,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/webhook", get(get_webhook))
        .route("/webhook", post(post_webhook))
}

async fn get_webhook() -> Response {
    success(
        json!({ "ok": true, "message": "telegram webhook ready" }),
        "Success",
    )
    .into_response()
}

async fn post_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(update): Json<Value>,
) -> Response {
    if let Err(message) = ensure_telegram_register_session_table(&state).await {
        return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None);
    }
    if let Err(message) = ensure_ticket_telegram_topics_table(&state).await {
        return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None);
    }
    let _ = cleanup_expired_register_sessions(&state).await;

    let config = match load_telegram_bot_config(&state).await {
        Ok(value) => value,
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    };

    if !config.webhook_secret.is_empty() {
        let provided = headers
            .get("x-telegram-bot-api-secret-token")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .unwrap_or("");
        if provided != config.webhook_secret {
            return error(StatusCode::FORBIDDEN, "Unauthorized webhook request", None);
        }
    }

    if let Some(callback_query) = update.get("callback_query") {
        return match handle_callback_query(&state, &config, callback_query).await {
            Ok(payload) => success(payload, "Success").into_response(),
            Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
        };
    }

    let message = match extract_message(&update) {
        Some(value) => value,
        None => {
            return success(json!({ "ok": true, "skipped": "no_message" }), "Success")
                .into_response();
        }
    };
    let chat_id = message
        .get("chat")
        .and_then(|chat| chat.get("id"))
        .and_then(value_to_chat_id);
    let chat_id = match chat_id {
        Some(value) => value,
        None => {
            return success(
                json!({ "ok": true, "skipped": "invalid_chat_id" }),
                "Success",
            )
            .into_response();
        }
    };

    match handle_ticket_topic_reply_message(&state, &config, message, &chat_id).await {
        Ok(Some(payload)) => return success(payload, "Success").into_response(),
        Ok(None) => {}
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    }

    let text = message
        .get("text")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if text.is_empty() {
        return success(json!({ "ok": true, "skipped": "empty_text" }), "Success").into_response();
    }

    let command = match parse_command(text) {
        Some(value) => value,
        None => {
            let handled =
                match handle_register_text_input(&state, &config, &headers, &chat_id, text).await {
                    Ok(value) => value,
                    Err(message) => {
                        return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None);
                    }
                };
            if let Some(payload) = handled {
                return success(payload, "Success").into_response();
            }
            return success(json!({ "ok": true, "skipped": "not_command" }), "Success")
                .into_response();
        }
    };

    let result = match command.name.as_str() {
        "start" => handle_start_command(&state, &config, &chat_id, &command.arg).await,
        "register" => handle_register_command(&state, &config, &chat_id, &command.arg).await,
        "info" => handle_info_command(&state, &config, &chat_id).await,
        "link" => handle_sublink_command(&state, &config, &chat_id).await,
        "panel" => handle_panel_command(&state, &config, &chat_id).await,
        "notify" => handle_notify_command(&state, &config, &chat_id, &command.arg).await,
        "id" => handle_id_command(&config, message, &chat_id).await,
        "help" => handle_help_command(&config, &chat_id).await,
        _ => Ok(json!({ "ok": true, "skipped": "unsupported_command" })),
    };

    match result {
        Ok(payload) => success(payload, "Success").into_response(),
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    }
}

async fn handle_start_command(
    state: &AppState,
    config: &TelegramBotConfig,
    chat_id: &str,
    bind_code: &str,
) -> Result<Value, String> {
    let bind_code = bind_code.trim();
    if bind_code.is_empty() {
        if let Some(bound_user) = fetch_bound_user_by_chat_id(state, chat_id).await? {
            let account_name = if bound_user.username.trim().is_empty() {
                format!("#{}", bound_user.id)
            } else {
                bound_user.username
            };
            let _ = send_telegram_message(
                config,
                chat_id,
                &[
                    format!("当前 Telegram 已绑定账号：{}。", account_name),
                    "可发送 /info 查看账号信息，/panel 打开面板，/notify 管理通知。".to_string(),
                    "更多命令请发送 /help。".to_string(),
                ]
                .join("\n"),
                None,
            )
            .await;
            return Ok(json!({
              "ok": true,
              "skipped": "missing_bind_code_already_bound",
              "user_id": bound_user.id
            }));
        }

        let _ = send_telegram_message(
            config,
            chat_id,
            &[
                "未检测到绑定码。",
                "如果你已有面板账号：请先在面板中点击 Telegram 绑定，并复制 /start 绑定码后再发送。",
                "如果你还没有账号：可发送 /register 进行注册。",
                "更多命令请发送 /help。",
            ]
            .join("\n"),
            None,
        )
        .await;
        return Ok(json!({ "ok": true, "skipped": "missing_bind_code" }));
    }
    if !is_valid_bind_code(bind_code) {
        let _ = send_telegram_message(
            config,
            chat_id,
            "绑定码格式无效，请回到面板刷新绑定码后重试。",
            None,
        )
        .await;
        return Ok(json!({ "ok": true, "skipped": "invalid_bind_code" }));
    }

    let row = sqlx::query(
        "SELECT id, username, telegram_bind_code_expires_at FROM users WHERE telegram_bind_code = ? LIMIT 1",
    )
    .bind(bind_code)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string())?;

    let row = match row {
        Some(value) => value,
        None => {
            let _ = send_telegram_message(
                config,
                chat_id,
                "绑定码无效或已失效，请回到面板重新获取绑定码。",
                None,
            )
            .await;
            return Ok(json!({ "ok": true, "skipped": "bind_code_not_found" }));
        }
    };

    let user_id = row
        .try_get::<Option<i64>, _>("id")
        .unwrap_or(Some(0))
        .unwrap_or(0);
    let username = row
        .try_get::<Option<String>, _>("username")
        .ok()
        .flatten()
        .unwrap_or_default();
    let expires_at = row
        .try_get::<Option<i64>, _>("telegram_bind_code_expires_at")
        .unwrap_or(Some(0))
        .unwrap_or(0);

    let now = Utc::now().timestamp();
    if expires_at <= now {
        sqlx::query(
            r#"
            UPDATE users
            SET telegram_bind_code = NULL,
                telegram_bind_code_expires_at = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        "#,
        )
        .bind(user_id)
        .execute(&state.db)
        .await
        .map_err(|err| err.to_string())?;

        let _ = send_telegram_message(
            config,
            chat_id,
            "绑定码已过期，请回到面板点击“刷新绑定码”后重试。",
            None,
        )
        .await;
        return Ok(json!({ "ok": true, "skipped": "bind_code_expired" }));
    }

    sqlx::query(
        r#"
        UPDATE users
        SET telegram_id = NULL,
            telegram_enabled = 0,
            updated_at = CURRENT_TIMESTAMP
        WHERE telegram_id = ?
          AND id != ?
    "#,
    )
    .bind(chat_id)
    .bind(user_id)
    .execute(&state.db)
    .await
    .map_err(|err| err.to_string())?;

    sqlx::query(
        r#"
        UPDATE users
        SET telegram_id = ?,
            telegram_enabled = 1,
            telegram_bind_code = NULL,
            telegram_bind_code_expires_at = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    "#,
    )
    .bind(chat_id)
    .bind(user_id)
    .execute(&state.db)
    .await
    .map_err(|err| err.to_string())?;

    let account_name = if username.trim().is_empty() {
        format!("#{user_id}")
    } else {
        username
    };
    let _ = send_telegram_message(
        config,
        chat_id,
        &format!(
            "绑定成功，账号 {} 已关联当前 Telegram。\n后续公告和每日流量提醒会通过机器人发送。",
            account_name
        ),
        None,
    )
    .await;

    Ok(json!({ "ok": true, "bound_user_id": user_id }))
}

async fn handle_register_command(
    state: &AppState,
    config: &TelegramBotConfig,
    chat_id: &str,
    arg_text: &str,
) -> Result<Value, String> {
    if fetch_bound_user_by_chat_id(state, chat_id).await?.is_some() {
        let _ = send_telegram_message(
            config,
            chat_id,
            "当前 Telegram 已绑定账号，如需新注册请先解绑或更换 Telegram 账号。",
            None,
        )
        .await;
        return Ok(json!({ "ok": true, "skipped": "already_bound" }));
    }

    let args: Vec<&str> = arg_text
        .split_whitespace()
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect();

    if args.is_empty() {
        if let Some(session) = get_register_session(state, chat_id).await? {
            if session.stage == RegisterStage::CaptchaPending {
                let now = Utc::now().timestamp();
                let cooldown_window_end = session.human_code_expires_at
                    - (REGISTER_CAPTCHA_TTL_SECONDS - REGISTER_COMMAND_COOLDOWN_SECONDS);
                if cooldown_window_end > now {
                    let remaining = cooldown_window_end - now;
                    let _ = send_telegram_message(
                        config,
                        chat_id,
                        &format!(
                            "操作过于频繁，请 {} 秒后再试。\n你也可以直接点击上一条消息里的验证码按钮。",
                            remaining
                        ),
                        None,
                    )
                    .await;
                    return Ok(json!({ "ok": true, "skipped": "register_command_cooldown" }));
                }
            }
        }
        return start_register_flow(state, config, chat_id).await;
    }

    let _ = send_telegram_message(
        config,
        chat_id,
        &[
            "当前仅支持交互式注册，不需要在 /register 后附加参数。",
            "请直接发送 /register，然后按提示点击验证码按钮并继续下一步。",
        ]
        .join("\n"),
        None,
    )
    .await;
    Ok(json!({ "ok": true, "skipped": "register_args_not_supported" }))
}

async fn handle_register_text_input(
    state: &AppState,
    config: &TelegramBotConfig,
    headers: &HeaderMap,
    chat_id: &str,
    message_text: &str,
) -> Result<Option<Value>, String> {
    let session = match get_register_session(state, chat_id).await? {
        Some(value) => value,
        None => return Ok(None),
    };

    let text = message_text.trim();
    if text.is_empty() {
        return Ok(Some(
            json!({ "ok": true, "skipped": "empty_register_input" }),
        ));
    }

    let payload = match session.stage {
        RegisterStage::CaptchaPending => {
            let _ = send_telegram_message(
                config,
                chat_id,
                "请点击验证码按钮完成人机验证；如按钮失效请发送 /register 重新开始。",
                None,
            )
            .await;
            json!({ "ok": true, "skipped": "awaiting_captcha_button" })
        }
        RegisterStage::EmailPending => {
            handle_register_email_input(state, config, chat_id, text).await?
        }
        RegisterStage::UsernamePending => {
            handle_register_username_input(state, config, chat_id, text).await?
        }
        RegisterStage::InvitePending => {
            handle_register_invite_input(state, config, headers, chat_id, text).await?
        }
        RegisterStage::EmailCodePending => {
            if is_six_digit_code(text) {
                complete_register_by_email_code(state, config, headers, chat_id, text).await?
            } else {
                let _ =
                    send_telegram_message(config, chat_id, "请发送 6 位邮箱验证码。", None).await;
                json!({ "ok": true, "skipped": "awaiting_email_code" })
            }
        }
    };

    Ok(Some(payload))
}

async fn start_register_flow(
    state: &AppState,
    config: &TelegramBotConfig,
    chat_id: &str,
) -> Result<Value, String> {
    let human_code = generate_register_human_code();
    let human_code_hash = hash_password(&human_code);
    let now = Utc::now().timestamp();

    upsert_register_session(
        state,
        chat_id,
        &TelegramRegisterSession {
            chat_id: chat_id.to_string(),
            stage: RegisterStage::CaptchaPending,
            human_code_hash,
            human_code_expires_at: now + REGISTER_CAPTCHA_TTL_SECONDS,
            human_code_attempts: 0,
            email: String::new(),
            username: String::new(),
            invite_code: String::new(),
            email_code_attempts: 0,
            session_expires_at: now + REGISTER_SESSION_TTL_SECONDS,
        },
    )
    .await?;

    let captcha_keyboard = build_register_captcha_keyboard(&human_code);
    let _ = send_telegram_message(
        config,
        chat_id,
        &[
            format!("注册人机验证码：{}", human_code),
            format!(
                "请在 {} 分钟内点击下方正确验证码按钮。",
                REGISTER_CAPTCHA_TTL_SECONDS / 60
            ),
            "".to_string(),
            "发送 /register 可重新开始。".to_string(),
        ]
        .join("\n"),
        Some(captcha_keyboard),
    )
    .await;

    Ok(json!({ "ok": true, "command": "register_init" }))
}

async fn verify_register_human_code(
    state: &AppState,
    config: &TelegramBotConfig,
    chat_id: &str,
    human_code_raw: &str,
) -> Result<Value, String> {
    let session = match get_register_session(state, chat_id).await? {
        Some(value) if value.stage == RegisterStage::CaptchaPending => value,
        _ => {
            let _ = send_telegram_message(
                config,
                chat_id,
                "当前不在人机验证码步骤，请发送 /register 重新开始。",
                None,
            )
            .await;
            return Ok(json!({ "ok": true, "skipped": "missing_register_session" }));
        }
    };

    let now = Utc::now().timestamp();
    if session.human_code_expires_at <= now {
        clear_register_session(state, chat_id).await?;
        let _ = send_telegram_message(
            config,
            chat_id,
            "人机验证码已过期，请重新发送 /register 获取新验证码。",
            None,
        )
        .await;
        return Ok(json!({ "ok": true, "skipped": "register_human_code_expired" }));
    }

    let human_code = human_code_raw.trim().to_uppercase();
    if !is_valid_register_human_code_format(&human_code) {
        let _ = send_telegram_message(
            config,
            chat_id,
            &format!(
                "验证码格式无效，请点击 {} 位字母数字按钮完成验证。",
                REGISTER_HUMAN_CODE_LENGTH
            ),
            None,
        )
        .await;
        return Ok(json!({ "ok": true, "skipped": "register_human_code_format_invalid" }));
    }

    if !verify_password(&human_code, &session.human_code_hash) {
        let next_attempts = session.human_code_attempts + 1;
        if next_attempts >= REGISTER_HUMAN_CODE_MAX_ATTEMPTS {
            clear_register_session(state, chat_id).await?;
            let _ = send_telegram_message(
                config,
                chat_id,
                "人机验证码错误次数过多，已取消本次注册，请重新发送 /register。",
                None,
            )
            .await;
            return Ok(json!({ "ok": true, "skipped": "register_human_code_locked" }));
        }

        let mut next_session = session.clone();
        next_session.human_code_attempts = next_attempts;
        next_session.session_expires_at = now + REGISTER_SESSION_TTL_SECONDS;
        upsert_register_session(state, chat_id, &next_session).await?;

        let _ = send_telegram_message(
            config,
            chat_id,
            &format!(
                "人机验证码错误，请重试（剩余 {} 次）。",
                REGISTER_HUMAN_CODE_MAX_ATTEMPTS - next_attempts
            ),
            None,
        )
        .await;
        return Ok(json!({ "ok": true, "skipped": "register_human_code_invalid" }));
    }

    let mut next_session = session;
    next_session.stage = RegisterStage::EmailPending;
    next_session.human_code_attempts = 0;
    next_session.session_expires_at = now + REGISTER_SESSION_TTL_SECONDS;
    upsert_register_session(state, chat_id, &next_session).await?;

    let _ = send_telegram_message(config, chat_id, "人机验证通过，请输入注册邮箱：", None).await;
    Ok(json!({ "ok": true, "command": "register_captcha_ok" }))
}

async fn handle_register_email_input(
    state: &AppState,
    config: &TelegramBotConfig,
    chat_id: &str,
    email_raw: &str,
) -> Result<Value, String> {
    let session = match get_register_session(state, chat_id).await? {
        Some(value) if value.stage == RegisterStage::EmailPending => value,
        _ => {
            let _ = send_telegram_message(
                config,
                chat_id,
                "当前不在邮箱输入步骤，请发送 /register 重新开始。",
                None,
            )
            .await;
            return Ok(json!({ "ok": true, "skipped": "missing_email_pending_session" }));
        }
    };

    let email = email_raw.trim().to_lowercase();
    if !is_valid_email(&email) {
        let _ =
            send_telegram_message(config, chat_id, "邮箱格式无效，请重新输入邮箱。", None).await;
        return Ok(json!({ "ok": true, "skipped": "register_invalid_email" }));
    }
    if is_gmail_alias(&email) {
        let _ = send_telegram_message(
            config,
            chat_id,
            "暂不支持使用 Gmail 别名注册，请使用不含点和加号的原始邮箱地址。",
            None,
        )
        .await;
        return Ok(json!({ "ok": true, "skipped": "register_invalid_email" }));
    }

    let now = Utc::now().timestamp();
    let mut next_session = session;
    next_session.stage = RegisterStage::UsernamePending;
    next_session.email = email.clone();
    next_session.session_expires_at = now + REGISTER_SESSION_TTL_SECONDS;
    upsert_register_session(state, chat_id, &next_session).await?;

    let _ = send_telegram_message(
        config,
        chat_id,
        "邮箱已记录，请输入用户名（3-20 位字母、数字、下划线）：",
        None,
    )
    .await;
    Ok(json!({ "ok": true, "command": "register_email_ok", "email": email }))
}

async fn handle_register_username_input(
    state: &AppState,
    config: &TelegramBotConfig,
    chat_id: &str,
    username_raw: &str,
) -> Result<Value, String> {
    let session = match get_register_session(state, chat_id).await? {
        Some(value) if value.stage == RegisterStage::UsernamePending => value,
        _ => {
            let _ = send_telegram_message(
                config,
                chat_id,
                "当前不在用户名输入步骤，请发送 /register 重新开始。",
                None,
            )
            .await;
            return Ok(json!({ "ok": true, "skipped": "missing_username_pending_session" }));
        }
    };

    let username = username_raw.trim().to_string();
    if !is_valid_register_username(&username) {
        let _ = send_telegram_message(
            config,
            chat_id,
            "用户名格式无效，仅支持 3-20 位字母、数字、下划线，请重新输入。",
            None,
        )
        .await;
        return Ok(json!({ "ok": true, "skipped": "register_invalid_username" }));
    }

    let now = Utc::now().timestamp();
    let mut next_session = session;
    next_session.stage = RegisterStage::InvitePending;
    next_session.username = username.clone();
    next_session.session_expires_at = now + REGISTER_SESSION_TTL_SECONDS;
    upsert_register_session(state, chat_id, &next_session).await?;

    let _ = send_telegram_message(
        config,
        chat_id,
        "如有邀请码请直接输入；没有可发送 skip / 无 跳过。",
        None,
    )
    .await;
    Ok(json!({ "ok": true, "command": "register_username_ok", "username": username }))
}

async fn handle_register_invite_input(
    state: &AppState,
    config: &TelegramBotConfig,
    headers: &HeaderMap,
    chat_id: &str,
    invite_input_raw: &str,
) -> Result<Value, String> {
    let session = match get_register_session(state, chat_id).await? {
        Some(value) if value.stage == RegisterStage::InvitePending => value,
        _ => {
            let _ = send_telegram_message(
                config,
                chat_id,
                "当前不在邀请码输入步骤，请发送 /register 重新开始。",
                None,
            )
            .await;
            return Ok(json!({ "ok": true, "skipped": "missing_invite_pending_session" }));
        }
    };

    let invite_input = invite_input_raw.trim();
    let invite_code = if REGISTER_INVITE_SKIP_INPUTS
        .iter()
        .any(|item| invite_input.eq_ignore_ascii_case(item))
    {
        String::new()
    } else {
        invite_input.to_string()
    };

    let email = session.email.trim().to_lowercase();
    let username = session.username.trim().to_string();
    if email.is_empty() || username.is_empty() {
        clear_register_session(state, chat_id).await?;
        let _ = send_telegram_message(
            config,
            chat_id,
            "注册会话信息不完整，请重新发送 /register。",
            None,
        )
        .await;
        return Ok(json!({ "ok": true, "skipped": "register_profile_incomplete" }));
    }

    let expire_minutes = match send_register_email_code(state, headers, &email).await {
        Ok(value) => value,
        Err(message) => {
            let _ = send_telegram_message(
                config,
                chat_id,
                &format!("发送邮箱验证码失败：{}", message),
                None,
            )
            .await;
            return Ok(json!({ "ok": true, "skipped": "register_email_code_send_failed" }));
        }
    };

    let now = Utc::now().timestamp();
    let mut next_session = session;
    next_session.stage = RegisterStage::EmailCodePending;
    next_session.invite_code = invite_code;
    next_session.email_code_attempts = 0;
    next_session.session_expires_at = now + REGISTER_SESSION_TTL_SECONDS;
    upsert_register_session(state, chat_id, &next_session).await?;

    let _ = send_telegram_message(
        config,
        chat_id,
        &[
            format!(
                "已向 {} 发送邮箱验证码（有效期约 {} 分钟）。",
                email, expire_minutes
            ),
            "请直接发送 6 位验证码完成注册。".to_string(),
        ]
        .join("\n"),
        None,
    )
    .await;

    Ok(json!({
      "ok": true,
      "command": "register_email_code_sent",
      "email": email,
      "username": username
    }))
}

async fn complete_register_by_email_code(
    state: &AppState,
    config: &TelegramBotConfig,
    headers: &HeaderMap,
    chat_id: &str,
    email_code_raw: &str,
) -> Result<Value, String> {
    let session = match get_register_session(state, chat_id).await? {
        Some(value) if value.stage == RegisterStage::EmailCodePending => value,
        _ => {
            let _ = send_telegram_message(
                config,
                chat_id,
                "当前没有待完成的注册流程，请先发送 /register。",
                None,
            )
            .await;
            return Ok(json!({ "ok": true, "skipped": "missing_email_code_session" }));
        }
    };

    let email_code = email_code_raw.trim();
    if !is_six_digit_code(email_code) {
        let _ = send_telegram_message(
            config,
            chat_id,
            "邮箱验证码格式无效，请发送 6 位数字验证码。",
            None,
        )
        .await;
        return Ok(json!({ "ok": true, "skipped": "invalid_email_code_format" }));
    }

    let password = random_string(16);
    let register_result = register_by_email_code(
        state,
        headers,
        &session.email,
        &session.username,
        &session.invite_code,
        email_code,
        &password,
    )
    .await;

    let user_id = match register_result {
        Ok(value) => value,
        Err(message) => {
            let next_attempts = session.email_code_attempts + 1;
            if next_attempts >= REGISTER_EMAIL_CODE_MAX_ATTEMPTS {
                clear_register_session(state, chat_id).await?;
                let _ = send_telegram_message(
                    config,
                    chat_id,
                    &format!(
                        "注册失败：{}\n错误次数过多，已取消本次注册，请重新发送 /register。",
                        message
                    ),
                    None,
                )
                .await;
                return Ok(json!({ "ok": true, "skipped": "register_email_code_locked" }));
            }

            let mut next_session = session.clone();
            next_session.email_code_attempts = next_attempts;
            upsert_register_session(state, chat_id, &next_session).await?;
            let _ = send_telegram_message(
                config,
                chat_id,
                &format!(
                    "注册失败：{}\n请检查后重试（剩余 {} 次）。",
                    message,
                    REGISTER_EMAIL_CODE_MAX_ATTEMPTS - next_attempts
                ),
                None,
            )
            .await;
            return Ok(json!({ "ok": true, "skipped": "register_email_code_invalid" }));
        }
    };

    clear_register_session(state, chat_id).await?;
    bind_telegram_after_register(state, chat_id, user_id).await?;

    let _ = send_telegram_message(
        config,
        chat_id,
        &[
            "注册成功，已自动绑定当前 Telegram。".to_string(),
            format!("邮箱：{}", session.email),
            format!("用户名：{}", session.username),
            format!("初始密码：{}", password),
            "".to_string(),
            "请立即登录面板并在个人资料中修改登录密码。".to_string(),
        ]
        .join("\n"),
        None,
    )
    .await;

    Ok(json!({
      "ok": true,
      "command": "register_success",
      "user_id": user_id
    }))
}

async fn handle_info_command(
    state: &AppState,
    config: &TelegramBotConfig,
    chat_id: &str,
) -> Result<Value, String> {
    let user = match fetch_bound_user_by_chat_id(state, chat_id).await? {
        Some(value) => value,
        None => {
            let _ = send_telegram_message(
                config,
                chat_id,
                "当前 Telegram 未绑定账号，请先在面板点击绑定并发送 /start 绑定码。",
                None,
            )
            .await;
            return Ok(json!({ "ok": true, "skipped": "not_bound" }));
        }
    };

    let total = user.transfer_enable.max(0);
    let used = user.transfer_total.max(0);
    let remain = if total > 0 { (total - used).max(0) } else { 0 };
    let text = [
        "账号信息".to_string(),
        format!(
            "邮箱：{}",
            if user.email.is_empty() {
                "-"
            } else {
                &user.email
            }
        ),
        format!(
            "用户名：{}",
            if user.username.is_empty() {
                "-"
            } else {
                &user.username
            }
        ),
        format!("会员等级：Lv.{}", user.class_level),
        format!("等级到期：{}", format_datetime_text(user.class_expire_time)),
        format!("账户到期：{}", format_datetime_text(user.expire_time)),
        "".to_string(),
        "流量信息".to_string(),
        format!(
            "总额度：{}",
            if total > 0 {
                format_bytes(total)
            } else {
                "不限".to_string()
            }
        ),
        format!("已使用：{}", format_bytes(used)),
        format!(
            "剩余流量：{}",
            if total > 0 {
                format_bytes(remain)
            } else {
                "不限".to_string()
            }
        ),
        format!("今日上行：{}", format_bytes(user.upload_today.max(0))),
        format!("今日下行：{}", format_bytes(user.download_today.max(0))),
    ]
    .join("\n");

    let _ = send_telegram_message(config, chat_id, &text, None).await;
    Ok(json!({ "ok": true, "command": "info", "user_id": user.id }))
}

async fn handle_sublink_command(
    state: &AppState,
    config: &TelegramBotConfig,
    chat_id: &str,
) -> Result<Value, String> {
    let user = match fetch_bound_user_by_chat_id(state, chat_id).await? {
        Some(value) => value,
        None => {
            let _ = send_telegram_message(
                config,
                chat_id,
                "当前 Telegram 未绑定账号，请先在面板点击绑定并发送 /start 绑定码。",
                None,
            )
            .await;
            return Ok(json!({ "ok": true, "skipped": "not_bound" }));
        }
    };

    if user.status != 1 {
        let _ =
            send_telegram_message(config, chat_id, "当前账号不可用，请联系管理员。", None).await;
        return Ok(json!({ "ok": true, "skipped": "user_disabled" }));
    }

    if user.token.trim().is_empty() {
        let _ = send_telegram_message(
            config,
            chat_id,
            "未获取到订阅 token，请在面板中重置订阅后重试。",
            None,
        )
        .await;
        return Ok(json!({ "ok": true, "skipped": "missing_token" }));
    }

    let _ = send_telegram_message(
        config,
        chat_id,
        "请选择订阅类型，点击按钮后会返回对应订阅链接：",
        Some(build_sublink_keyboard()),
    )
    .await;

    Ok(json!({ "ok": true, "command": "link", "user_id": user.id }))
}

async fn handle_panel_command(
    state: &AppState,
    config: &TelegramBotConfig,
    chat_id: &str,
) -> Result<Value, String> {
    let user = match fetch_bound_user_by_chat_id(state, chat_id).await? {
        Some(value) => value,
        None => {
            let _ = send_telegram_message(
                config,
                chat_id,
                "当前 Telegram 未绑定账号，请先在面板点击绑定并发送 /start 绑定码。",
                None,
            )
            .await;
            return Ok(json!({ "ok": true, "skipped": "not_bound" }));
        }
    };

    if user.status != 1 {
        let _ =
            send_telegram_message(config, chat_id, "当前账号不可用，请联系管理员。", None).await;
        return Ok(json!({ "ok": true, "skipped": "user_disabled" }));
    }

    let panel_url = resolve_miniapp_url(state).await?;
    let keyboard = json!({
      "inline_keyboard": [
        [
          { "text": "打开面板", "web_app": { "url": panel_url } }
        ]
      ]
    });
    let _ = send_telegram_message(
        config,
        chat_id,
        "点击下方按钮在 Telegram 内打开面板：",
        Some(keyboard),
    )
    .await;

    Ok(json!({
      "ok": true,
      "command": "panel",
      "user_id": user.id,
      "panel_url": panel_url
    }))
}

async fn handle_help_command(config: &TelegramBotConfig, chat_id: &str) -> Result<Value, String> {
    let _ = send_telegram_message(config, chat_id, &build_help_text(), None).await;
    Ok(json!({ "ok": true, "command": "help" }))
}

async fn handle_id_command(
    config: &TelegramBotConfig,
    message: &Value,
    chat_id: &str,
) -> Result<Value, String> {
    let user_id = message
        .get("from")
        .and_then(|from| from.get("id"))
        .and_then(value_to_chat_id)
        .unwrap_or_default();
    let chat_type = message
        .get("chat")
        .and_then(|chat| chat.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let thread_id = value_to_thread_id(message.get("message_thread_id"));

    let mut lines = vec![
        "ID 信息：".to_string(),
        format!(
            "用户 ID：{}",
            if user_id.trim().is_empty() {
                "-"
            } else {
                user_id.trim()
            }
        ),
        format!("聊天 ID：{}", chat_id),
        format!("聊天类型：{}", chat_type),
    ];
    if thread_id > 0 {
        lines.push(format!("话题 ID：{}", thread_id));
    }

    let _ = send_telegram_message(config, chat_id, &lines.join("\n"), None).await;
    Ok(json!({
      "ok": true,
      "command": "id",
      "user_id": if user_id.trim().is_empty() { Value::Null } else { json!(user_id.trim()) },
      "chat_id": chat_id,
      "chat_type": chat_type,
      "message_thread_id": if thread_id > 0 { json!(thread_id) } else { Value::Null }
    }))
}

async fn handle_notify_command(
    state: &AppState,
    config: &TelegramBotConfig,
    chat_id: &str,
    arg_text: &str,
) -> Result<Value, String> {
    let user = match fetch_bound_user_by_chat_id(state, chat_id).await? {
        Some(value) => value,
        None => {
            let _ = send_telegram_message(
                config,
                chat_id,
                "当前 Telegram 未绑定账号，请先在面板点击绑定并发送 /start 绑定码。",
                None,
            )
            .await;
            return Ok(json!({ "ok": true, "skipped": "not_bound" }));
        }
    };

    let arg = arg_text.trim();
    let current_enabled = user.telegram_enabled == 1;
    if arg.is_empty() {
        let _ = send_notify_status_message(config, chat_id, current_enabled).await;
        return Ok(json!({
          "ok": true,
          "command": "notify_status",
          "telegram_enabled": current_enabled
        }));
    }

    let target_enabled = match parse_notify_command_arg(arg) {
        Some(value) => value,
        None => {
            let _ = send_telegram_message(
                config,
                chat_id,
                "参数无效。请发送 /notify on 开启通知，或发送 /notify off 关闭通知。",
                None,
            )
            .await;
            return Ok(json!({ "ok": true, "skipped": "notify_invalid_arg" }));
        }
    };

    if target_enabled == current_enabled {
        let _ = send_notify_status_message(config, chat_id, current_enabled).await;
        return Ok(json!({
          "ok": true,
          "command": "notify_no_change",
          "telegram_enabled": current_enabled
        }));
    }

    update_telegram_notify_setting(state, user.id, target_enabled).await?;
    let _ = send_notify_status_message(config, chat_id, target_enabled).await;

    Ok(json!({
      "ok": true,
      "command": "notify_updated",
      "telegram_enabled": target_enabled,
      "user_id": user.id
    }))
}

async fn handle_callback_query(
    state: &AppState,
    config: &TelegramBotConfig,
    callback_query: &Value,
) -> Result<Value, String> {
    let callback_id = callback_query
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let callback_data = callback_query
        .get("data")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let chat_id = callback_query
        .get("message")
        .and_then(|message| message.get("chat"))
        .and_then(|chat| chat.get("id"))
        .and_then(value_to_chat_id)
        .unwrap_or_default();
    let callback_message_id = callback_query
        .get("message")
        .and_then(|message| message.get("message_id"))
        .and_then(value_to_message_id);

    if chat_id.is_empty() {
        if !callback_id.is_empty() {
            let _ = answer_callback_query(config, &callback_id, Some("未获取到聊天信息")).await;
        }
        return Ok(json!({ "ok": true, "skipped": "callback_no_chat_id" }));
    }

    if callback_data.starts_with(REGISTER_CAPTCHA_CALLBACK_PREFIX) {
        return handle_register_captcha_callback(
            state,
            config,
            &chat_id,
            &callback_data,
            &callback_id,
        )
        .await;
    }
    if callback_data.starts_with(NOTIFY_CALLBACK_PREFIX) {
        return handle_notify_callback(
            state,
            config,
            &chat_id,
            &callback_data,
            &callback_id,
            callback_message_id,
        )
        .await;
    }

    if !callback_data.starts_with(LINK_CALLBACK_PREFIX) {
        if !callback_id.is_empty() {
            let _ = answer_callback_query(config, &callback_id, Some("不支持的操作")).await;
        }
        return Ok(json!({ "ok": true, "skipped": "unsupported_callback" }));
    }

    let sub_type_raw = &callback_data[LINK_CALLBACK_PREFIX.len()..];
    let sub_type = match parse_subscription_type(sub_type_raw) {
        Some(value) => value,
        None => {
            if !callback_id.is_empty() {
                let _ = answer_callback_query(config, &callback_id, Some("不支持的订阅类型")).await;
            }
            return Ok(json!({ "ok": true, "skipped": "invalid_subscription_type" }));
        }
    };

    let user = match fetch_bound_user_by_chat_id(state, &chat_id).await? {
        Some(value) => value,
        None => {
            let _ = send_telegram_message(
                config,
                &chat_id,
                "当前 Telegram 未绑定账号，请先在面板点击绑定并发送 /start 绑定码。",
                None,
            )
            .await;
            if !callback_id.is_empty() {
                let _ = answer_callback_query(config, &callback_id, Some("当前未绑定账号")).await;
            }
            return Ok(json!({ "ok": true, "skipped": "not_bound" }));
        }
    };

    if user.status != 1 {
        let _ =
            send_telegram_message(config, &chat_id, "当前账号不可用，请联系管理员。", None).await;
        if !callback_id.is_empty() {
            let _ = answer_callback_query(config, &callback_id, Some("账号不可用")).await;
        }
        return Ok(json!({ "ok": true, "skipped": "user_disabled" }));
    }

    if user.token.trim().is_empty() {
        let _ = send_telegram_message(
            config,
            &chat_id,
            "未获取到订阅 token，请在面板中重置订阅后重试。",
            None,
        )
        .await;
        if !callback_id.is_empty() {
            let _ = answer_callback_query(config, &callback_id, Some("缺少订阅 token")).await;
        }
        return Ok(json!({ "ok": true, "skipped": "missing_token" }));
    }

    let base_url = resolve_subscription_base_url(state).await?;
    let link = build_subscription_link(&base_url, sub_type, &user.token);
    let label = subscription_label(sub_type);
    let _ = send_telegram_message(
        config,
        &chat_id,
        &format!("{} 订阅链接：\n{}", label, link),
        None,
    )
    .await;

    if !callback_id.is_empty() {
        let _ = answer_callback_query(
            config,
            &callback_id,
            Some(&format!("已返回 {} 链接", label)),
        )
        .await;
    }

    Ok(json!({
      "ok": true,
      "command": "link_callback",
      "type": sub_type,
      "user_id": user.id
    }))
}

async fn handle_notify_callback(
    state: &AppState,
    config: &TelegramBotConfig,
    chat_id: &str,
    callback_data: &str,
    callback_id: &str,
    callback_message_id: Option<i64>,
) -> Result<Value, String> {
    let arg = callback_data
        .strip_prefix(NOTIFY_CALLBACK_PREFIX)
        .unwrap_or("")
        .trim();
    let target_enabled = match parse_notify_command_arg(arg) {
        Some(value) => value,
        None => {
            if !callback_id.is_empty() {
                let _ = answer_callback_query(config, callback_id, Some("按钮参数无效")).await;
            }
            return Ok(json!({ "ok": true, "skipped": "notify_invalid_callback_arg" }));
        }
    };

    let user = match fetch_bound_user_by_chat_id(state, chat_id).await? {
        Some(value) => value,
        None => {
            let _ = send_telegram_message(
                config,
                chat_id,
                "当前 Telegram 未绑定账号，请先在面板点击绑定并发送 /start 绑定码。",
                None,
            )
            .await;
            if !callback_id.is_empty() {
                let _ = answer_callback_query(config, callback_id, Some("当前未绑定账号")).await;
            }
            return Ok(json!({ "ok": true, "skipped": "not_bound" }));
        }
    };

    if user.telegram_enabled != if target_enabled { 1 } else { 0 } {
        update_telegram_notify_setting(state, user.id, target_enabled).await?;
    }
    if let Some(message_id) = callback_message_id {
        let _ = delete_telegram_message(config, chat_id, message_id).await;
    }
    let _ = send_notify_status_message(config, chat_id, target_enabled).await;

    if !callback_id.is_empty() {
        let _ = answer_callback_query(
            config,
            callback_id,
            Some(if target_enabled {
                "已开启通知"
            } else {
                "已关闭通知"
            }),
        )
        .await;
    }

    Ok(json!({
      "ok": true,
      "command": "notify_callback",
      "telegram_enabled": target_enabled,
      "user_id": user.id
    }))
}

async fn handle_register_captcha_callback(
    state: &AppState,
    config: &TelegramBotConfig,
    chat_id: &str,
    callback_data: &str,
    callback_id: &str,
) -> Result<Value, String> {
    let selected_code = callback_data
        .strip_prefix(REGISTER_CAPTCHA_CALLBACK_PREFIX)
        .unwrap_or("")
        .trim()
        .to_uppercase();

    if !is_valid_register_human_code_format(&selected_code) {
        if !callback_id.is_empty() {
            let _ = answer_callback_query(config, callback_id, Some("验证码按钮无效")).await;
        }
        return Ok(json!({ "ok": true, "skipped": "invalid_captcha_callback_data" }));
    }

    let payload = verify_register_human_code(state, config, chat_id, &selected_code).await?;
    if !callback_id.is_empty() {
        let _ = answer_callback_query(config, callback_id, Some("已提交验证")).await;
    }
    Ok(payload)
}

#[derive(Clone)]
struct RegisterFlags {
    register_mode: String,
    register_enabled: bool,
    email_verify_enabled: bool,
    email_provider_enabled: bool,
}

async fn ensure_telegram_register_session_table(state: &AppState) -> Result<(), String> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS telegram_register_sessions (
          chat_id VARCHAR(64) PRIMARY KEY,
          stage VARCHAR(32) NOT NULL,
          human_code_hash VARCHAR(255) NOT NULL DEFAULT '',
          human_code_expires_at BIGINT NOT NULL DEFAULT 0,
          human_code_attempts INT NOT NULL DEFAULT 0,
          email VARCHAR(255) NOT NULL DEFAULT '',
          username VARCHAR(255) NOT NULL DEFAULT '',
          invite_code VARCHAR(255) NOT NULL DEFAULT '',
          email_code_attempts INT NOT NULL DEFAULT 0,
          session_expires_at BIGINT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          KEY idx_tg_register_session_expires (session_expires_at),
          KEY idx_tg_register_session_stage (stage)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        "#,
    )
    .execute(&state.db)
    .await
    .map_err(|err| err.to_string())?;
    Ok(())
}

async fn cleanup_expired_register_sessions(state: &AppState) -> Result<(), String> {
    let now = Utc::now().timestamp();
    sqlx::query("DELETE FROM telegram_register_sessions WHERE session_expires_at <= ?")
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(|err| err.to_string())?;
    Ok(())
}

async fn get_register_session(
    state: &AppState,
    chat_id: &str,
) -> Result<Option<TelegramRegisterSession>, String> {
    let row = sqlx::query(
        r#"
        SELECT chat_id, stage, human_code_hash, human_code_expires_at, human_code_attempts,
               email, username, invite_code, email_code_attempts, session_expires_at
        FROM telegram_register_sessions
        WHERE chat_id = ?
        LIMIT 1
        "#,
    )
    .bind(chat_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string())?;

    let row = match row {
        Some(value) => value,
        None => return Ok(None),
    };

    let session = TelegramRegisterSession {
        chat_id: row
            .try_get::<Option<String>, _>("chat_id")
            .ok()
            .flatten()
            .unwrap_or_else(|| chat_id.to_string()),
        stage: row
            .try_get::<Option<String>, _>("stage")
            .ok()
            .flatten()
            .as_deref()
            .and_then(RegisterStage::parse)
            .unwrap_or(RegisterStage::CaptchaPending),
        human_code_hash: row
            .try_get::<Option<String>, _>("human_code_hash")
            .ok()
            .flatten()
            .unwrap_or_default(),
        human_code_expires_at: row
            .try_get::<Option<i64>, _>("human_code_expires_at")
            .unwrap_or(Some(0))
            .unwrap_or(0),
        human_code_attempts: row
            .try_get::<Option<i64>, _>("human_code_attempts")
            .unwrap_or(Some(0))
            .unwrap_or(0),
        email: row
            .try_get::<Option<String>, _>("email")
            .ok()
            .flatten()
            .unwrap_or_default(),
        username: row
            .try_get::<Option<String>, _>("username")
            .ok()
            .flatten()
            .unwrap_or_default(),
        invite_code: row
            .try_get::<Option<String>, _>("invite_code")
            .ok()
            .flatten()
            .unwrap_or_default(),
        email_code_attempts: row
            .try_get::<Option<i64>, _>("email_code_attempts")
            .unwrap_or(Some(0))
            .unwrap_or(0),
        session_expires_at: row
            .try_get::<Option<i64>, _>("session_expires_at")
            .unwrap_or(Some(0))
            .unwrap_or(0),
    };

    if session.session_expires_at <= Utc::now().timestamp() {
        clear_register_session(state, chat_id).await?;
        return Ok(None);
    }

    Ok(Some(session))
}

async fn upsert_register_session(
    state: &AppState,
    chat_id: &str,
    session: &TelegramRegisterSession,
) -> Result<(), String> {
    let target_chat_id = if session.chat_id.trim().is_empty() {
        chat_id
    } else {
        session.chat_id.as_str()
    };
    sqlx::query(
        r#"
        INSERT INTO telegram_register_sessions (
          chat_id, stage, human_code_hash, human_code_expires_at, human_code_attempts,
          email, username, invite_code, email_code_attempts, session_expires_at,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON DUPLICATE KEY UPDATE
          stage = VALUES(stage),
          human_code_hash = VALUES(human_code_hash),
          human_code_expires_at = VALUES(human_code_expires_at),
          human_code_attempts = VALUES(human_code_attempts),
          email = VALUES(email),
          username = VALUES(username),
          invite_code = VALUES(invite_code),
          email_code_attempts = VALUES(email_code_attempts),
          session_expires_at = VALUES(session_expires_at),
          updated_at = CURRENT_TIMESTAMP
        "#,
    )
    .bind(target_chat_id)
    .bind(session.stage.as_str())
    .bind(&session.human_code_hash)
    .bind(session.human_code_expires_at)
    .bind(session.human_code_attempts)
    .bind(&session.email)
    .bind(&session.username)
    .bind(&session.invite_code)
    .bind(session.email_code_attempts)
    .bind(session.session_expires_at)
    .execute(&state.db)
    .await
    .map_err(|err| err.to_string())?;
    Ok(())
}

async fn clear_register_session(state: &AppState, chat_id: &str) -> Result<(), String> {
    sqlx::query("DELETE FROM telegram_register_sessions WHERE chat_id = ?")
        .bind(chat_id)
        .execute(&state.db)
        .await
        .map_err(|err| err.to_string())?;
    Ok(())
}

fn generate_register_human_code() -> String {
    let mut rng = rand::thread_rng();
    let digits: Vec<char> = REGISTER_HUMAN_CODE_DIGITS.chars().collect();
    let letters: Vec<char> = REGISTER_HUMAN_CODE_LETTERS.chars().collect();
    let charset: Vec<char> = format!(
        "{}{}",
        REGISTER_HUMAN_CODE_DIGITS, REGISTER_HUMAN_CODE_LETTERS
    )
    .chars()
    .collect();

    let mut chars = Vec::with_capacity(REGISTER_HUMAN_CODE_LENGTH);
    chars.push(digits[rng.gen_range(0..digits.len())]);
    chars.push(letters[rng.gen_range(0..letters.len())]);
    for _ in 2..REGISTER_HUMAN_CODE_LENGTH {
        chars.push(charset[rng.gen_range(0..charset.len())]);
    }
    chars.shuffle(&mut rng);
    chars.into_iter().collect()
}

fn build_register_captcha_keyboard(correct_code: &str) -> Value {
    let mut options: HashSet<String> = HashSet::new();
    options.insert(correct_code.trim().to_uppercase());
    while options.len() < 4 {
        options.insert(generate_register_human_code());
    }

    let mut items: Vec<String> = options.into_iter().collect();
    items.shuffle(&mut rand::thread_rng());
    while items.len() < 4 {
        items.push(generate_register_human_code());
    }

    json!({
      "inline_keyboard": [
        [
          { "text": items[0], "callback_data": format!("{}{}", REGISTER_CAPTCHA_CALLBACK_PREFIX, items[0]) },
          { "text": items[1], "callback_data": format!("{}{}", REGISTER_CAPTCHA_CALLBACK_PREFIX, items[1]) }
        ],
        [
          { "text": items[2], "callback_data": format!("{}{}", REGISTER_CAPTCHA_CALLBACK_PREFIX, items[2]) },
          { "text": items[3], "callback_data": format!("{}{}", REGISTER_CAPTCHA_CALLBACK_PREFIX, items[3]) }
        ]
      ]
    })
}

fn is_valid_register_human_code_format(code: &str) -> bool {
    if code.len() != REGISTER_HUMAN_CODE_LENGTH {
        return false;
    }
    let upper = code.trim().to_uppercase();
    upper.chars().all(|ch| {
        REGISTER_HUMAN_CODE_DIGITS.contains(ch) || REGISTER_HUMAN_CODE_LETTERS.contains(ch)
    })
}

fn is_valid_register_username(username: &str) -> bool {
    let len = username.len();
    if !(3..=20).contains(&len) {
        return false;
    }
    username
        .bytes()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == b'_')
}

fn is_six_digit_code(value: &str) -> bool {
    value.len() == 6 && value.chars().all(|ch| ch.is_ascii_digit())
}

async fn send_register_email_code(
    state: &AppState,
    headers: &HeaderMap,
    email: &str,
) -> Result<i64, String> {
    if email.trim().is_empty() {
        return Err("请填写邮箱地址".to_string());
    }
    if !is_valid_email(email) {
        return Err("请输入有效的邮箱地址".to_string());
    }
    if is_gmail_alias(email) {
        return Err("暂不支持使用 Gmail 别名注册，请使用不含点和加号的原始邮箱地址".to_string());
    }

    let flags = load_register_flags(state).await?;
    let verification_enabled =
        flags.register_enabled && flags.email_verify_enabled && flags.email_provider_enabled;
    if !verification_enabled {
        return Err("当前未开启邮箱验证码功能".to_string());
    }
    if flags.register_mode != "1" {
        return Err("系统暂时关闭注册功能".to_string());
    }

    let existing_user = sqlx::query("SELECT id FROM users WHERE email = ? LIMIT 1")
        .bind(email)
        .fetch_optional(&state.db)
        .await
        .map_err(|err| err.to_string())?;
    if existing_user.is_some() {
        return Err("该邮箱已被注册，请使用其他邮箱或直接登录".to_string());
    }

    let _ = sqlx::query(
        r#"
        UPDATE email_verification_codes
        SET used_at = CURRENT_TIMESTAMP
        WHERE email = ? AND purpose = 'register' AND used_at IS NULL
        "#,
    )
    .bind(email)
    .execute(&state.db)
    .await;

    let client_ip = get_client_ip(headers).unwrap_or_else(|| "unknown".to_string());
    let user_agent = headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();

    let cooldown_seconds = to_int_config(
        state.env.mail_verification_cooldown_seconds.as_ref(),
        60,
        0,
        true,
    );
    let daily_limit = to_int_config(state.env.mail_verification_daily_limit.as_ref(), 5, 0, true);
    let ip_hourly_limit = to_int_config(
        state.env.mail_verification_ip_hourly_limit.as_ref(),
        10,
        0,
        true,
    );

    if cooldown_seconds > 0 {
        let row = sqlx::query(&format!(
            r#"
            SELECT COUNT(*) as count
            FROM email_verification_codes
            WHERE email = ?
              AND purpose = 'register'
              AND created_at > DATE_SUB(CURRENT_TIMESTAMP, INTERVAL {} SECOND)
            "#,
            cooldown_seconds
        ))
        .bind(email)
        .fetch_optional(&state.db)
        .await
        .map_err(|err| err.to_string())?;
        let count = row
            .and_then(|item| item.try_get::<Option<i64>, _>("count").ok().flatten())
            .unwrap_or(0);
        if count > 0 {
            return Err(format!(
                "验证码发送频繁，请在 {} 秒后重试",
                cooldown_seconds
            ));
        }
    }

    if daily_limit > 0 {
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM email_verification_codes
            WHERE email = ?
              AND purpose = 'register'
              AND created_at > DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 1 DAY)
            "#,
        )
        .bind(email)
        .fetch_optional(&state.db)
        .await
        .map_err(|err| err.to_string())?;
        let count = row
            .and_then(|item| item.try_get::<Option<i64>, _>("count").ok().flatten())
            .unwrap_or(0);
        if count >= daily_limit {
            return Err("今日验证码发送次数已达上限，请24小时后再试".to_string());
        }
    }

    if ip_hourly_limit > 0 && client_ip != "unknown" {
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM email_verification_codes
            WHERE request_ip = ?
              AND purpose = 'register'
              AND created_at > DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 1 HOUR)
            "#,
        )
        .bind(&client_ip)
        .fetch_optional(&state.db)
        .await
        .map_err(|err| err.to_string())?;
        let count = row
            .and_then(|item| item.try_get::<Option<i64>, _>("count").ok().flatten())
            .unwrap_or(0);
        if count >= ip_hourly_limit {
            return Err("请求过于频繁，请稍后再试或更换网络".to_string());
        }
    }

    let expire_minutes =
        send_email_code_for_register(state, email, "register", &client_ip, &user_agent).await?;
    Ok(expire_minutes)
}

async fn send_email_code_for_register(
    state: &AppState,
    email: &str,
    purpose: &str,
    ip: &str,
    user_agent: &str,
) -> Result<i64, String> {
    let expire_minutes = state
        .env
        .mail_verification_expire_minutes
        .as_ref()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(10);

    let code = random_numeric_code(6);
    let hash = sha256_hex(&code);
    let expires = Utc::now() + chrono::Duration::minutes(expire_minutes);
    let expires_db = expires.format("%F %T").to_string();

    sqlx::query(
        r#"
        INSERT INTO email_verification_codes (email, purpose, code_hash, expires_at, attempts, request_ip, user_agent, created_at)
        VALUES (?, ?, ?, ?, 0, ?, ?, CURRENT_TIMESTAMP)
        "#,
    )
    .bind(email)
    .bind(purpose)
    .bind(&hash)
    .bind(&expires_db)
    .bind(ip)
    .bind(user_agent)
    .execute(&state.db)
    .await
    .map_err(|err| err.to_string())?;

    let configs = list_system_configs(state).await.unwrap_or_default();
    let site_name = configs
        .get("site_name")
        .cloned()
        .or_else(|| state.env.site_name.clone())
        .unwrap_or_else(|| "Soga Panel".to_string());
    let site_url = configs
        .get("site_url")
        .cloned()
        .or_else(|| state.env.site_url.clone())
        .unwrap_or_default();

    let subject = build_email_subject(purpose, &site_name);
    let text = build_email_text(purpose, &code, expire_minutes, &site_name);
    let html = build_verification_html(
        &subject,
        &site_name,
        &site_url,
        &code,
        &text,
        expire_minutes,
        get_verification_title_text(purpose),
    );

    let email_service = EmailService::new(&state.env);
    email_service
        .send_mail(email, &subject, &text, Some(&html))
        .await?;

    Ok(expire_minutes)
}

async fn verify_email_code_for_register(
    state: &AppState,
    email: &str,
    purpose: &str,
    code: &str,
    attempt_limit: i64,
) -> Result<(), String> {
    let trimmed = code.trim();
    if trimmed.is_empty() {
        return Err("请填写邮箱验证码".to_string());
    }
    if !is_six_digit_code(trimmed) {
        return Err("验证码格式不正确，请输入6位数字验证码".to_string());
    }

    let row = sqlx::query(
        r#"
        SELECT id, code_hash, attempts
        FROM email_verification_codes
        WHERE email = ?
          AND purpose = ?
          AND expires_at > CURRENT_TIMESTAMP
          AND used_at IS NULL
        ORDER BY id DESC
        LIMIT 1
        "#,
    )
    .bind(email)
    .bind(purpose)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string())?;

    let row = match row {
        Some(value) => value,
        None => return Err("验证码不存在或已过期".to_string()),
    };

    let id = row
        .try_get::<Option<i64>, _>("id")
        .unwrap_or(Some(0))
        .unwrap_or(0);
    let code_hash = row
        .try_get::<Option<String>, _>("code_hash")
        .ok()
        .flatten()
        .unwrap_or_default();
    let attempts = row
        .try_get::<Option<i64>, _>("attempts")
        .unwrap_or(Some(0))
        .unwrap_or(0);
    let hash = sha256_hex(trimmed);

    if hash != code_hash {
        let next_attempts = attempts + 1;
        let reach_limit = attempt_limit > 0 && next_attempts >= attempt_limit;
        let update_sql = if reach_limit {
            "UPDATE email_verification_codes SET attempts = ?, used_at = CURRENT_TIMESTAMP WHERE id = ?"
        } else {
            "UPDATE email_verification_codes SET attempts = ? WHERE id = ?"
        };
        let _ = sqlx::query(update_sql)
            .bind(next_attempts)
            .bind(id)
            .execute(&state.db)
            .await;

        if reach_limit {
            return Err("验证码错误次数过多，请重新获取验证码".to_string());
        }
        return Err("验证码错误".to_string());
    }

    let _ =
        sqlx::query("UPDATE email_verification_codes SET used_at = CURRENT_TIMESTAMP WHERE id = ?")
            .bind(id)
            .execute(&state.db)
            .await;
    Ok(())
}

async fn register_by_email_code(
    state: &AppState,
    headers: &HeaderMap,
    email_raw: &str,
    username_raw: &str,
    invite_code_raw: &str,
    email_code: &str,
    password: &str,
) -> Result<i64, String> {
    let email = email_raw.trim().to_lowercase();
    let username = username_raw.trim().to_string();
    if email.is_empty() || username.is_empty() || password.trim().is_empty() {
        return Err("参数缺失".to_string());
    }
    if !is_valid_email(&email) {
        return Err("请输入有效的邮箱地址".to_string());
    }
    if is_gmail_alias(&email) {
        return Err("暂不支持使用 Gmail 别名注册，请使用不含点和加号的原始邮箱地址".to_string());
    }
    if !is_valid_register_username(&username) {
        return Err("用户名格式无效，仅支持 3-20 位字母、数字、下划线".to_string());
    }

    let flags = load_register_flags(state).await?;
    if flags.register_mode == "0" {
        return Err("系统暂时关闭注册功能".to_string());
    }

    let invite_code = normalize_invite_code(invite_code_raw);
    let mut inviter_id: Option<i64> = None;
    if !invite_code.is_empty() {
        match find_inviter_by_code(state, &invite_code).await? {
            Some(inviter) => {
                if inviter.invite_limit > 0 && inviter.invite_used >= inviter.invite_limit {
                    return Err("该邀请码使用次数已达上限，请联系邀请人".to_string());
                }
                inviter_id = Some(inviter.id);
            }
            None => {
                return Err("邀请码无效或已失效，请联系邀请人".to_string());
            }
        }
    } else if flags.register_mode == "2" {
        return Err("当前仅允许受邀注册，请填写有效邀请码".to_string());
    }

    if flags.email_verify_enabled && flags.email_provider_enabled {
        verify_email_code_for_register(
            state,
            &email,
            "register",
            email_code,
            get_verification_attempt_limit(state),
        )
        .await?;
    }

    let user_id = register_user_for_telegram(
        state,
        &email,
        &username,
        password,
        get_client_ip(headers),
        inviter_id,
    )
    .await?;

    if let Some(inviter_id) = inviter_id {
        save_referral_relation(
            state,
            inviter_id,
            user_id,
            &invite_code,
            get_client_ip(headers),
        )
        .await;
        increment_invite_usage(state, inviter_id).await;
    }

    let _ = ensure_user_invite_code(state, user_id).await;
    Ok(user_id)
}

async fn register_user_for_telegram(
    state: &AppState,
    email: &str,
    username: &str,
    password: &str,
    register_ip: Option<String>,
    invited_by: Option<i64>,
) -> Result<i64, String> {
    if sqlx::query("SELECT id FROM users WHERE email = ? LIMIT 1")
        .bind(email)
        .fetch_optional(&state.db)
        .await
        .map_err(|err| err.to_string())?
        .is_some()
    {
        return Err("邮箱已被注册".to_string());
    }
    if sqlx::query("SELECT id FROM users WHERE username = ? LIMIT 1")
        .bind(username)
        .fetch_optional(&state.db)
        .await
        .map_err(|err| err.to_string())?
        .is_some()
    {
        return Err("用户名已被占用".to_string());
    }

    let password_hash = hash_password(password);
    let uuid = generate_uuid();
    let passwd = random_base64(32);
    let token = random_string(32);

    let configs = list_system_configs(state).await.unwrap_or_default();
    let invite_limit = to_int_config(configs.get("invite_default_limit"), 0, 0, true);

    let result = sqlx::query(
        r#"
        INSERT INTO users (email, username, password_hash, uuid, passwd, token, register_ip, invited_by, invite_limit, reg_date, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        "#,
    )
    .bind(email)
    .bind(username)
    .bind(password_hash)
    .bind(uuid)
    .bind(passwd)
    .bind(token)
    .bind(register_ip)
    .bind(invited_by.unwrap_or(0))
    .bind(if invite_limit > 0 { invite_limit } else { 0 })
    .execute(&state.db)
    .await
    .map_err(|err| err.to_string())?;

    let user_id = result.last_insert_id() as i64;
    if user_id <= 0 {
        return Err("注册失败".to_string());
    }

    let transfer_enable = to_int_config(configs.get("default_traffic"), 10737418240, 0, true);
    let account_expire_days =
        to_int_config(configs.get("default_account_expire_days"), 3650, 0, true);
    let class_expire_days = to_int_config(configs.get("default_expire_days"), 30, 0, true);
    let default_class = to_int_config(configs.get("default_class"), 1, 0, true);

    let now = Utc::now() + chrono::Duration::hours(8);
    let account_expire_time = if account_expire_days > 0 {
        Some(
            (now + chrono::Duration::days(account_expire_days))
                .format("%F %T")
                .to_string(),
        )
    } else {
        None
    };
    let class_expire_time = if class_expire_days > 0 {
        Some(
            (now + chrono::Duration::days(class_expire_days))
                .format("%F %T")
                .to_string(),
        )
    } else {
        None
    };

    let _ = sqlx::query(
        r#"
        UPDATE users
        SET transfer_enable = ?,
            expire_time = ?,
            class = ?,
            class_expire_time = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        "#,
    )
    .bind(transfer_enable)
    .bind(account_expire_time)
    .bind(default_class)
    .bind(class_expire_time)
    .bind(user_id)
    .execute(&state.db)
    .await;

    Ok(user_id)
}

async fn bind_telegram_after_register(
    state: &AppState,
    chat_id: &str,
    user_id: i64,
) -> Result<(), String> {
    sqlx::query(
        r#"
        UPDATE users
        SET telegram_id = NULL,
            telegram_enabled = 0,
            updated_at = CURRENT_TIMESTAMP
        WHERE telegram_id = ?
          AND id != ?
        "#,
    )
    .bind(chat_id)
    .bind(user_id)
    .execute(&state.db)
    .await
    .map_err(|err| err.to_string())?;

    sqlx::query(
        r#"
        UPDATE users
        SET telegram_id = ?,
            telegram_enabled = 1,
            telegram_bind_code = NULL,
            telegram_bind_code_expires_at = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        "#,
    )
    .bind(chat_id)
    .bind(user_id)
    .execute(&state.db)
    .await
    .map_err(|err| err.to_string())?;
    Ok(())
}

async fn load_register_flags(state: &AppState) -> Result<RegisterFlags, String> {
    let configs = list_system_configs(state).await?;
    let register_mode = configs
        .get("register_enabled")
        .cloned()
        .unwrap_or_else(|| "1".to_string());
    let register_enabled = register_mode != "0";
    let email_verify_enabled = configs
        .get("register_email_verification_enabled")
        .map(|value| value != "0")
        .unwrap_or(true);
    let email_provider_enabled = is_email_configured(state);

    Ok(RegisterFlags {
        register_mode,
        register_enabled,
        email_verify_enabled,
        email_provider_enabled,
    })
}

fn is_email_configured(state: &AppState) -> bool {
    let provider = state
        .env
        .mail_provider
        .clone()
        .unwrap_or_else(|| "smtp".to_string())
        .to_lowercase();

    if provider == "resend" {
        return state
            .env
            .resend_api_key
            .as_ref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
            || state
                .env
                .mail_resend_key
                .as_ref()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false);
    }
    if provider == "smtp" {
        return state
            .env
            .mail_smtp_host
            .as_ref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
            || state
                .env
                .smtp_host
                .as_ref()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false);
    }
    if provider == "sendgrid" {
        return state
            .env
            .sendgrid_api_key
            .as_ref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);
    }
    if provider == "none" {
        return false;
    }

    state.env.mail_smtp_host.is_some()
        || state.env.smtp_host.is_some()
        || state.env.mail_resend_key.is_some()
        || state.env.resend_api_key.is_some()
        || state.env.sendgrid_api_key.is_some()
}

fn to_int_config(value: Option<&String>, fallback: i64, min: i64, allow_zero: bool) -> i64 {
    let parsed = value
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(fallback);
    if parsed < min {
        return fallback;
    }
    if !allow_zero && parsed == 0 {
        return fallback;
    }
    parsed
}

fn get_client_ip(headers: &HeaderMap) -> Option<String> {
    let candidates = [
        "x-client-ip",
        "x-forwarded-for",
        "cf-connecting-ip",
        "true-client-ip",
        "x-real-ip",
    ];
    for key in candidates {
        if let Some(raw) = headers.get(key).and_then(|value| value.to_str().ok()) {
            let first = raw.split(',').next().unwrap_or("").trim();
            if !first.is_empty() {
                return Some(first.to_string());
            }
        }
    }
    None
}

fn get_verification_attempt_limit(state: &AppState) -> i64 {
    state
        .env
        .mail_verification_attempt_limit
        .as_ref()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(5)
}

fn is_valid_email(email: &str) -> bool {
    if email.contains(' ') {
        return false;
    }
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let domain = parts[1];
    domain.contains('.')
}

fn is_gmail_alias(email: &str) -> bool {
    let normalized = email.to_lowercase();
    let parts: Vec<&str> = normalized.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let local = parts[0];
    let domain = parts[1];
    if domain != "gmail.com" && domain != "googlemail.com" {
        return false;
    }
    local.contains('+') || local.contains('.')
}

async fn load_telegram_bot_config(state: &AppState) -> Result<TelegramBotConfig, String> {
    let rows = sqlx::query(
        "SELECT `key`, `value` FROM system_configs WHERE `key` IN ('telegram_bot_token','telegram_bot_api_base','telegram_webhook_secret')",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|err| err.to_string())?;

    let mut token = String::new();
    let mut api_base = "https://api.telegram.org".to_string();
    let mut webhook_secret = String::new();

    for row in rows {
        let key = row
            .try_get::<Option<String>, _>("key")
            .ok()
            .flatten()
            .unwrap_or_default();
        let value = row
            .try_get::<Option<String>, _>("value")
            .ok()
            .flatten()
            .unwrap_or_default();

        if key == "telegram_bot_token" && !value.trim().is_empty() {
            token = value.trim().to_string();
        } else if key == "telegram_bot_api_base" && !value.trim().is_empty() {
            api_base = value.trim().to_string();
        } else if key == "telegram_webhook_secret" && !value.trim().is_empty() {
            webhook_secret = value.trim().to_string();
        }
    }

    Ok(TelegramBotConfig {
        token,
        api_base,
        webhook_secret,
    })
}

async fn ensure_ticket_telegram_topics_table(state: &AppState) -> Result<(), String> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ticket_telegram_topics (
          ticket_id BIGINT NOT NULL COMMENT '工单 ID',
          group_chat_id VARCHAR(64) NOT NULL COMMENT 'Telegram 论坛群组 Chat ID',
          message_thread_id BIGINT NOT NULL COMMENT 'Telegram 论坛话题 Thread ID',
          topic_message_id BIGINT COMMENT '创建话题时的消息 ID（可选）',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
          CONSTRAINT fk_ticket_tg_topics_ticket FOREIGN KEY (ticket_id) REFERENCES tickets (id) ON DELETE CASCADE,
          UNIQUE KEY uk_ticket_tg_topics_ticket (ticket_id),
          UNIQUE KEY uk_ticket_tg_topics_group_thread (group_chat_id, message_thread_id),
          INDEX idx_ticket_tg_topics_thread (message_thread_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        "#,
    )
    .execute(&state.db)
    .await
    .map_err(|err| err.to_string())?;
    Ok(())
}

async fn load_ticket_group_chat_id(state: &AppState) -> Result<String, String> {
    let row = sqlx::query(
        "SELECT value FROM system_configs WHERE `key` = 'telegram_ticket_group_id' LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string())?;
    let value = row
        .and_then(|item| item.try_get::<Option<String>, _>("value").ok().flatten())
        .unwrap_or_default()
        .trim()
        .to_string();
    if is_valid_chat_id_text(&value) {
        Ok(value)
    } else {
        Ok(String::new())
    }
}

fn is_valid_chat_id_text(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    let mut chars = trimmed.chars();
    if let Some(first) = chars.next() {
        if first == '-' {
            return chars.all(|ch| ch.is_ascii_digit());
        }
        if first.is_ascii_digit() {
            return chars.all(|ch| ch.is_ascii_digit());
        }
    }
    false
}

fn value_to_thread_id(value: Option<&Value>) -> i64 {
    value
        .and_then(Value::as_i64)
        .or_else(|| {
            value
                .and_then(Value::as_str)
                .and_then(|text| text.trim().parse::<i64>().ok())
        })
        .filter(|id| *id > 0)
        .unwrap_or(0)
}

fn truncate_ticket_text(text: &str, max_len: usize) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for ch in trimmed.chars().take(max_len) {
        out.push(ch);
    }
    if trimmed.chars().count() > max_len {
        out.push_str("...");
    }
    out
}

async fn handle_ticket_topic_reply_message(
    state: &AppState,
    config: &TelegramBotConfig,
    message: &Value,
    chat_id: &str,
) -> Result<Option<Value>, String> {
    let ticket_group_chat_id = load_ticket_group_chat_id(state).await?;
    if ticket_group_chat_id.is_empty() || ticket_group_chat_id != chat_id {
        return Ok(None);
    }

    let thread_id = value_to_thread_id(message.get("message_thread_id"));
    if thread_id <= 0 {
        return Ok(Some(
            json!({ "ok": true, "skipped": "ticket_topic_missing_thread_id" }),
        ));
    }

    if message
        .get("from")
        .and_then(|from| from.get("is_bot"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(Some(
            json!({ "ok": true, "skipped": "ticket_topic_sender_is_bot" }),
        ));
    }

    let reply_text = message
        .get("text")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if reply_text.is_empty() {
        return Ok(Some(
            json!({ "ok": true, "skipped": "ticket_topic_empty_text" }),
        ));
    }

    let sender_telegram_id = message
        .get("from")
        .and_then(|from| from.get("id"))
        .and_then(value_to_chat_id)
        .unwrap_or_default();
    if sender_telegram_id.is_empty() {
        return Ok(Some(
            json!({ "ok": true, "skipped": "ticket_topic_missing_sender" }),
        ));
    }

    let operator =
        sqlx::query("SELECT id, is_admin, username FROM users WHERE telegram_id = ? LIMIT 1")
            .bind(&sender_telegram_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|err| err.to_string())?;
    let operator = match operator {
        Some(value) => value,
        None => {
            return Ok(Some(
                json!({ "ok": true, "skipped": "ticket_topic_sender_not_bound" }),
            ))
        }
    };
    let operator_id = operator
        .try_get::<Option<i64>, _>("id")
        .unwrap_or(Some(0))
        .unwrap_or(0);
    let operator_is_admin = operator
        .try_get::<Option<i64>, _>("is_admin")
        .unwrap_or(Some(0))
        .unwrap_or(0)
        == 1;
    if operator_id <= 0 || !operator_is_admin {
        return Ok(Some(
            json!({ "ok": true, "skipped": "ticket_topic_sender_not_admin" }),
        ));
    }
    let operator_name = operator
        .try_get::<Option<String>, _>("username")
        .ok()
        .flatten()
        .unwrap_or_else(|| format!("#{}", operator_id));

    let ticket_binding = sqlx::query(
        r#"
        SELECT ticket_id
        FROM ticket_telegram_topics
        WHERE group_chat_id = ? AND message_thread_id = ?
        LIMIT 1
        "#,
    )
    .bind(chat_id)
    .bind(thread_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string())?;
    let ticket_id = ticket_binding
        .as_ref()
        .and_then(|row| row.try_get::<Option<i64>, _>("ticket_id").ok().flatten())
        .unwrap_or(0);
    if ticket_id <= 0 {
        return Ok(Some(
            json!({ "ok": true, "skipped": "ticket_topic_not_mapped" }),
        ));
    }

    let ticket = sqlx::query("SELECT id, user_id, title FROM tickets WHERE id = ? LIMIT 1")
        .bind(ticket_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|err| err.to_string())?;
    let ticket = match ticket {
        Some(value) => value,
        None => {
            return Ok(Some(
                json!({ "ok": true, "skipped": "ticket_topic_ticket_missing" }),
            ))
        }
    };
    let ticket_user_id = ticket
        .try_get::<Option<i64>, _>("user_id")
        .unwrap_or(Some(0))
        .unwrap_or(0);
    let ticket_title = ticket
        .try_get::<Option<String>, _>("title")
        .ok()
        .flatten()
        .unwrap_or_else(|| format!("工单 #{}", ticket_id));

    sqlx::query(
        r#"
        INSERT INTO ticket_replies (ticket_id, author_id, author_role, content, created_at)
        VALUES (?, ?, 'admin', ?, CURRENT_TIMESTAMP)
        "#,
    )
    .bind(ticket_id)
    .bind(operator_id)
    .bind(reply_text)
    .execute(&state.db)
    .await
    .map_err(|err| err.to_string())?;

    sqlx::query(
        r#"
        UPDATE tickets
        SET status = 'answered',
            last_reply_by_admin_id = ?,
            last_reply_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        "#,
    )
    .bind(operator_id)
    .bind(ticket_id)
    .execute(&state.db)
    .await
    .map_err(|err| err.to_string())?;

    if ticket_user_id > 0 {
        let owner = sqlx::query("SELECT telegram_id FROM users WHERE id = ? LIMIT 1")
            .bind(ticket_user_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|err| err.to_string())?;
        let owner_chat_id = owner
            .and_then(|row| {
                row.try_get::<Option<String>, _>("telegram_id")
                    .ok()
                    .flatten()
            })
            .unwrap_or_default();
        if !owner_chat_id.trim().is_empty() {
            let _ = send_telegram_message(
                config,
                owner_chat_id.trim(),
                &[
                    format!("你的工单 #{} 已收到客服回复。", ticket_id),
                    format!("标题：{}", ticket_title),
                    format!("回复人：{}", operator_name),
                    String::new(),
                    truncate_ticket_text(reply_text, TELEGRAM_TICKET_TEXT_MAX_LEN),
                ]
                .join("\n"),
                None,
            )
            .await;
        }
    }

    Ok(Some(json!({
      "ok": true,
      "command": "ticket_topic_reply_forwarded",
      "ticket_id": ticket_id,
      "operator_id": operator_id,
      "thread_id": thread_id
    })))
}

async fn fetch_bound_user_by_chat_id(
    state: &AppState,
    chat_id: &str,
) -> Result<Option<BoundTelegramUser>, String> {
    let row = sqlx::query(
        r#"
        SELECT id, email, username, class AS class_level, class_expire_time, expire_time,
               transfer_total, transfer_enable, upload_today, download_today, status, token, telegram_enabled
        FROM users
        WHERE telegram_id = ?
        LIMIT 1
    "#,
    )
    .bind(chat_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string())?;

    Ok(row.map(|row| BoundTelegramUser {
        id: row
            .try_get::<Option<i64>, _>("id")
            .unwrap_or(Some(0))
            .unwrap_or(0),
        email: row
            .try_get::<Option<String>, _>("email")
            .ok()
            .flatten()
            .unwrap_or_default(),
        username: row
            .try_get::<Option<String>, _>("username")
            .ok()
            .flatten()
            .unwrap_or_default(),
        class_level: row
            .try_get::<Option<i64>, _>("class_level")
            .unwrap_or(Some(0))
            .unwrap_or(0),
        class_expire_time: row
            .try_get::<Option<NaiveDateTime>, _>("class_expire_time")
            .ok()
            .flatten(),
        expire_time: row
            .try_get::<Option<NaiveDateTime>, _>("expire_time")
            .ok()
            .flatten(),
        transfer_total: row
            .try_get::<Option<i64>, _>("transfer_total")
            .unwrap_or(Some(0))
            .unwrap_or(0),
        transfer_enable: row
            .try_get::<Option<i64>, _>("transfer_enable")
            .unwrap_or(Some(0))
            .unwrap_or(0),
        upload_today: row
            .try_get::<Option<i64>, _>("upload_today")
            .unwrap_or(Some(0))
            .unwrap_or(0),
        download_today: row
            .try_get::<Option<i64>, _>("download_today")
            .unwrap_or(Some(0))
            .unwrap_or(0),
        status: row
            .try_get::<Option<i64>, _>("status")
            .unwrap_or(Some(0))
            .unwrap_or(0),
        token: row
            .try_get::<Option<String>, _>("token")
            .ok()
            .flatten()
            .unwrap_or_default(),
        telegram_enabled: row
            .try_get::<Option<i64>, _>("telegram_enabled")
            .unwrap_or(Some(0))
            .unwrap_or(0),
    }))
}

async fn resolve_subscription_base_url(state: &AppState) -> Result<String, String> {
    let rows = sqlx::query(
        "SELECT `key`, `value` FROM system_configs WHERE `key` IN ('subscription_url','site_url')",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|err| err.to_string())?;

    let mut subscription_url = String::new();
    let mut site_url = String::new();
    for row in rows {
        let key = row
            .try_get::<Option<String>, _>("key")
            .ok()
            .flatten()
            .unwrap_or_default();
        let value = row
            .try_get::<Option<String>, _>("value")
            .ok()
            .flatten()
            .unwrap_or_default();
        if key == "subscription_url" && !value.trim().is_empty() {
            subscription_url = value.trim().to_string();
        } else if key == "site_url" && !value.trim().is_empty() {
            site_url = value.trim().to_string();
        }
    }

    let base = if !subscription_url.is_empty() {
        subscription_url
    } else if !site_url.is_empty() {
        site_url
    } else {
        state.env.site_url.clone().unwrap_or_default()
    };

    Ok(base.trim_end_matches('/').to_string())
}

async fn resolve_miniapp_url(state: &AppState) -> Result<String, String> {
    let rows = sqlx::query(
        "SELECT `key`, `value` FROM system_configs WHERE `key` IN ('telegram_miniapp_url','site_url')",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|err| err.to_string())?;

    let mut miniapp_url = String::new();
    let mut site_url = String::new();
    for row in rows {
        let key = row
            .try_get::<Option<String>, _>("key")
            .ok()
            .flatten()
            .unwrap_or_default();
        let value = row
            .try_get::<Option<String>, _>("value")
            .ok()
            .flatten()
            .unwrap_or_default();
        if key == "telegram_miniapp_url" && !value.trim().is_empty() {
            miniapp_url = value.trim().to_string();
        } else if key == "site_url" && !value.trim().is_empty() {
            site_url = value.trim().to_string();
        }
    }

    let base = if !miniapp_url.is_empty() {
        miniapp_url
    } else if !site_url.is_empty() {
        site_url
    } else {
        state.env.site_url.clone().unwrap_or_default()
    };

    Ok(normalize_miniapp_url(&base))
}

fn normalize_miniapp_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "/auth/login?tgMiniApp=1".to_string();
    }

    let without_hash = trimmed.split('#').next().unwrap_or(trimmed);
    let mut url = if without_hash.contains("/auth/login") {
        without_hash.to_string()
    } else {
        format!("{}/auth/login", without_hash.trim_end_matches('/'))
    };

    if url.contains("tgMiniApp=") {
        return url;
    }

    if url.contains('?') {
        url.push_str("&tgMiniApp=1");
    } else {
        url.push_str("?tgMiniApp=1");
    }
    url
}

fn extract_message(update: &Value) -> Option<&Value> {
    update
        .get("message")
        .or_else(|| update.get("edited_message"))
}

fn parse_command(text: &str) -> Option<ParsedCommand> {
    let trimmed = text.trim();
    if !trimmed.starts_with('/') {
        return None;
    }

    let mut parts = trimmed.split_whitespace();
    let command_token = parts.next()?.trim_start_matches('/');
    let command_name = command_token
        .split('@')
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase();
    if command_name.is_empty() {
        return None;
    }

    let arg = parts.next().unwrap_or("").trim().to_string();
    Some(ParsedCommand {
        name: command_name,
        arg,
    })
}

fn value_to_chat_id(value: &Value) -> Option<String> {
    if let Some(text) = value.as_str() {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Some(number) = value.as_i64() {
        return Some(number.to_string());
    }
    if let Some(number) = value.as_u64() {
        return Some(number.to_string());
    }
    None
}

fn value_to_message_id(value: &Value) -> Option<i64> {
    if let Some(number) = value.as_i64() {
        return (number > 0).then_some(number);
    }
    if let Some(number) = value.as_u64() {
        return i64::try_from(number).ok().filter(|value| *value > 0);
    }
    if let Some(text) = value.as_str() {
        return text.trim().parse::<i64>().ok().filter(|value| *value > 0);
    }
    None
}

fn is_valid_bind_code(code: &str) -> bool {
    let len = code.len();
    if !(TELEGRAM_BIND_CODE_MIN_LEN..=TELEGRAM_BIND_CODE_MAX_LEN).contains(&len) {
        return false;
    }
    code.bytes()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == b'_' || ch == b'-')
}

fn parse_subscription_type(value: &str) -> Option<&'static str> {
    match value {
        "v2ray" => Some("v2ray"),
        "clash" => Some("clash"),
        "quantumultx" => Some("quantumultx"),
        "singbox" => Some("singbox"),
        "shadowrocket" => Some("shadowrocket"),
        "surge" => Some("surge"),
        _ => None,
    }
}

fn subscription_label(value: &str) -> &'static str {
    match value {
        "v2ray" => "V2Ray",
        "clash" => "Clash",
        "quantumultx" => "QuantumultX",
        "singbox" => "SingBox",
        "shadowrocket" => "Shadowrocket",
        "surge" => "Surge",
        _ => "Unknown",
    }
}

fn parse_notify_command_arg(raw: &str) -> Option<bool> {
    let normalized = raw.trim().to_lowercase();
    if matches!(
        normalized.as_str(),
        "on" | "enable" | "enabled" | "1" | "true" | "开" | "开启"
    ) {
        return Some(true);
    }
    if matches!(
        normalized.as_str(),
        "off" | "disable" | "disabled" | "0" | "false" | "关" | "关闭"
    ) {
        return Some(false);
    }
    None
}

fn build_notify_toggle_keyboard(enabled: bool) -> Value {
    json!({
      "inline_keyboard": [
        [
          {
            "text": format!("{}开启通知", if enabled { "✅ " } else { "" }),
            "callback_data": format!("{}on", NOTIFY_CALLBACK_PREFIX)
          },
          {
            "text": format!("{}关闭通知", if !enabled { "✅ " } else { "" }),
            "callback_data": format!("{}off", NOTIFY_CALLBACK_PREFIX)
          }
        ]
      ]
    })
}

async fn send_notify_status_message(
    config: &TelegramBotConfig,
    chat_id: &str,
    enabled: bool,
) -> Result<(), String> {
    send_telegram_message(
        config,
        chat_id,
        &[
            format!(
                "当前 Telegram 通知：{}。",
                if enabled { "已开启" } else { "已关闭" }
            ),
            if enabled {
                "你将通过当前 Bot 接收公告和每日流量推送。".to_string()
            } else {
                "你将不会收到公告和每日流量推送。".to_string()
            },
            "可直接点击下方按钮切换。".to_string(),
        ]
        .join("\n"),
        Some(build_notify_toggle_keyboard(enabled)),
    )
    .await
}

async fn update_telegram_notify_setting(
    state: &AppState,
    user_id: i64,
    enabled: bool,
) -> Result<(), String> {
    sqlx::query(
        r#"
        UPDATE users
        SET telegram_enabled = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        "#,
    )
    .bind(if enabled { 1 } else { 0 })
    .bind(user_id)
    .execute(&state.db)
    .await
    .map_err(|err| err.to_string())?;
    Ok(())
}

fn build_sublink_keyboard() -> Value {
    json!({
      "inline_keyboard": [
        [
          { "text": "V2Ray", "callback_data": "link:v2ray" },
          { "text": "Clash", "callback_data": "link:clash" }
        ],
        [
          { "text": "QuantumultX", "callback_data": "link:quantumultx" },
          { "text": "SingBox", "callback_data": "link:singbox" }
        ],
        [
          { "text": "Shadowrocket", "callback_data": "link:shadowrocket" },
          { "text": "Surge", "callback_data": "link:surge" }
        ]
      ]
    })
}

fn build_help_text() -> String {
    [
        "可用命令：",
        "/register - Telegram 内注册账号（未绑定时）",
        "/info - 查看账号信息和流量信息",
        "/link - 返回订阅链接按钮",
        "/panel - 在 Telegram 内打开面板",
        "/notify - 开启或关闭 Telegram 通知",
        "/help - 显示帮助",
        "",
        "首次绑定：",
        "在面板复制绑定命令后，发送 /start <绑定码> 完成绑定。",
    ]
    .join("\n")
}

fn build_subscription_link(base_url: &str, sub_type: &str, token: &str) -> String {
    let encoded_token = encode(token).to_string();
    if base_url.trim().is_empty() {
        return format!("/api/subscription/{}?token={}", sub_type, encoded_token);
    }
    format!(
        "{}/api/subscription/{}?token={}",
        base_url.trim_end_matches('/'),
        sub_type,
        encoded_token
    )
}

fn format_datetime_text(value: Option<NaiveDateTime>) -> String {
    match value {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        None => "永久".to_string(),
    }
}

fn format_bytes(bytes: i64) -> String {
    if bytes <= 0 {
        return "0 B".to_string();
    }

    let units = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut value = bytes as f64;
    let mut unit_index = 0usize;
    while value >= 1024.0 && unit_index < units.len() - 1 {
        value /= 1024.0;
        unit_index += 1;
    }

    let precision = if value >= 100.0 {
        0
    } else if value >= 10.0 {
        1
    } else {
        2
    };
    format!("{:.*} {}", precision, value, units[unit_index])
}

async fn send_telegram_message(
    config: &TelegramBotConfig,
    chat_id: &str,
    text: &str,
    reply_markup: Option<Value>,
) -> Result<(), String> {
    if config.token.trim().is_empty() {
        return Ok(());
    }
    if chat_id.trim().is_empty() {
        return Ok(());
    }

    let endpoint = format!(
        "{}/bot{}/sendMessage",
        config.api_base.trim_end_matches('/'),
        config.token
    );

    let mut payload = json!({
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": true
    });
    if let Some(value) = reply_markup {
        payload["reply_markup"] = value;
    }

    let response = reqwest::Client::new()
        .post(endpoint)
        .header("User-Agent", "Soga-Panel-Server/1.0")
        .json(&payload)
        .send()
        .await
        .map_err(|err| err.to_string())?;

    if !response.status().is_success() {
        return Err(format!(
            "Telegram 响应状态码异常: {}",
            response.status().as_u16()
        ));
    }

    let body = response.json::<Value>().await.unwrap_or(Value::Null);
    if body.get("ok").and_then(Value::as_bool).unwrap_or(true) == false {
        let desc = body
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("未知错误");
        return Err(format!("Telegram API 返回失败: {desc}"));
    }

    Ok(())
}

async fn answer_callback_query(
    config: &TelegramBotConfig,
    callback_query_id: &str,
    text: Option<&str>,
) -> Result<(), String> {
    if config.token.trim().is_empty() || callback_query_id.trim().is_empty() {
        return Ok(());
    }

    let endpoint = format!(
        "{}/bot{}/answerCallbackQuery",
        config.api_base.trim_end_matches('/'),
        config.token
    );
    let payload = json!({
      "callback_query_id": callback_query_id,
      "text": text.unwrap_or(""),
      "show_alert": false
    });

    let response = reqwest::Client::new()
        .post(endpoint)
        .header("User-Agent", "Soga-Panel-Server/1.0")
        .json(&payload)
        .send()
        .await
        .map_err(|err| err.to_string())?;

    if !response.status().is_success() {
        return Err(format!(
            "answerCallbackQuery 失败，状态码: {}",
            response.status().as_u16()
        ));
    }

    Ok(())
}

async fn delete_telegram_message(
    config: &TelegramBotConfig,
    chat_id: &str,
    message_id: i64,
) -> Result<(), String> {
    if config.token.trim().is_empty() || chat_id.trim().is_empty() || message_id <= 0 {
        return Ok(());
    }

    let endpoint = format!(
        "{}/bot{}/deleteMessage",
        config.api_base.trim_end_matches('/'),
        config.token
    );
    let payload = json!({
      "chat_id": chat_id,
      "message_id": message_id
    });

    let response = reqwest::Client::new()
        .post(endpoint)
        .header("User-Agent", "Soga-Panel-Server/1.0")
        .json(&payload)
        .send()
        .await
        .map_err(|err| err.to_string())?;

    if !response.status().is_success() {
        return Err(format!(
            "deleteMessage 失败，状态码: {}",
            response.status().as_u16()
        ));
    }

    Ok(())
}
