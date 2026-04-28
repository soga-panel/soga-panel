use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use base64::Engine;
use chrono::{NaiveDateTime, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::Row;
use std::collections::HashSet;

use crate::cache::{
    cache_delete, cache_get, cache_get_redis_only, cache_set, cache_set_redis_only,
};
use crate::crypto::{
    generate_uuid, hash_password, random_base64, random_numeric_code, random_string, sha256_hex,
    verify_password,
};
use crate::mail::EmailService;
use crate::passkey::{
    base64url_encode, extract_client_challenge, random_challenge, validate_authentication_response,
    validate_registration_response, AuthenticationCredential, RegistrationCredential,
};
use crate::referral::{
    ensure_user_invite_code, find_inviter_by_code, increment_invite_usage, normalize_invite_code,
    save_referral_relation,
};
use crate::response::{error, success};
use crate::state::{
    AppState, PasskeyChallenge, PasskeyChallengeCache, PendingOAuthCache, PendingOAuthRegistration,
};
use crate::templates::email_templates::{
    build_email_subject, build_email_text, build_verification_html, get_verification_title_text,
};
use crate::totp::verify_totp;

const SESSION_TTL: u64 = 60 * 60 * 24 * 7;
const TRUST_TTL: u64 = 60 * 60 * 24 * 30;
const TWO_FACTOR_TTL: u64 = 60 * 5;
const OAUTH_PENDING_TTL: i64 = 600;
const PASSKEY_CHALLENGE_TTL: i64 = 300;
const TELEGRAM_INIT_DATA_MAX_AGE_SECONDS: i64 = 86400;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/register-config", get(get_register_config))
        .route("/register", post(post_register))
        .route("/login", post(post_login))
        .route("/telegram-miniapp", post(post_telegram_miniapp_login))
        .route("/verify-2fa", post(post_verify_2fa))
        .route("/logout", post(post_logout))
        .route("/send-email-code", post(post_send_email_code))
        .route("/password-reset/request", post(post_password_reset_request))
        .route("/password-reset/confirm", post(post_password_reset_confirm))
        .route("/oauth/login", post(post_oauth_login))
        .route("/oauth/complete", post(post_oauth_complete))
        .route("/google", post(post_google_oauth))
        .route("/github", post(post_github_oauth))
        .route(
            "/passkey/register/options",
            post(post_passkey_register_options),
        )
        .route(
            "/passkey/register/verify",
            post(post_passkey_register_verify),
        )
        .route("/passkey/login/options", post(post_passkey_login_options))
        .route("/passkey/login/verify", post(post_passkey_login_verify))
}

#[derive(Deserialize)]
struct LoginRequest {
    email: Option<String>,
    password: Option<String>,
    two_factor_code: Option<String>,
    backup_code: Option<String>,
    remember: Option<bool>,
    #[serde(alias = "twoFactorTrustToken")]
    two_factor_trust_token: Option<String>,
    #[serde(alias = "turnstileToken")]
    turnstile_token: Option<String>,
    #[serde(rename = "cf-turnstile-response")]
    cf_turnstile_response: Option<String>,
}

#[derive(Deserialize)]
struct TelegramMiniAppLoginRequest {
    #[serde(alias = "initData", alias = "init_data")]
    init_data: Option<String>,
    remember: Option<bool>,
    #[serde(alias = "twoFactorTrustToken")]
    two_factor_trust_token: Option<String>,
}

#[derive(Deserialize)]
struct Verify2faRequest {
    #[serde(alias = "challengeId")]
    challenge_id: Option<String>,
    code: Option<String>,
    #[serde(alias = "rememberDevice")]
    remember_device: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct SessionPayload {
    id: i64,
    email: String,
    username: String,
    is_admin: i64,
}

struct VerificationFlags {
    configs: std::collections::HashMap<String, String>,
    register_mode: String,
    register_enabled: bool,
    email_verify_enabled: bool,
    email_provider_enabled: bool,
}

#[derive(Deserialize)]
struct OAuthLoginRequest {
    provider: Option<String>,
    email: Option<String>,
    #[serde(rename = "provider_id")]
    provider_id: Option<String>,
    username: Option<String>,
}

#[derive(Deserialize)]
struct RegisterRequest {
    email: Option<String>,
    username: Option<String>,
    password: Option<String>,
    #[serde(alias = "verificationCode", alias = "verification_code")]
    verification_code: Option<String>,
    #[serde(alias = "inviteCode", alias = "invite_code")]
    invite_code: Option<String>,
}

#[derive(Deserialize)]
struct OAuthCompleteRequest {
    #[serde(alias = "inviteCode", alias = "invite_code")]
    invite_code: Option<String>,
    #[serde(alias = "pendingToken", alias = "pending_token")]
    pending_token: Option<String>,
}

#[derive(Deserialize)]
struct GoogleOAuthRequest {
    #[serde(alias = "idToken", alias = "id_token")]
    id_token: Option<String>,
    remember: Option<bool>,
    #[serde(alias = "twoFactorTrustToken")]
    #[allow(dead_code)]
    two_factor_trust_token: Option<String>,
}

#[derive(Deserialize)]
struct GithubOAuthRequest {
    code: Option<String>,
    #[serde(alias = "redirectUri", alias = "redirect_uri")]
    redirect_uri: Option<String>,
    #[allow(dead_code)]
    state: Option<String>,
    remember: Option<bool>,
    #[serde(alias = "twoFactorTrustToken")]
    #[allow(dead_code)]
    two_factor_trust_token: Option<String>,
}

#[derive(Deserialize)]
struct PasskeyRegisterVerifyRequest {
    credential: RegistrationCredential,
    #[serde(alias = "deviceName")]
    device_name: Option<String>,
}

#[derive(Deserialize)]
struct PasskeyLoginOptionsRequest {
    email: Option<String>,
    remember: Option<bool>,
}

#[derive(Deserialize)]
struct PasskeyLoginVerifyRequest {
    credential: AuthenticationCredential,
}

async fn get_register_config(State(state): State<AppState>) -> impl IntoResponse {
    let configs = list_system_configs(&state).await.unwrap_or_default();
    let register_mode = configs
        .get("register_enabled")
        .cloned()
        .unwrap_or_else(|| "1".to_string());
    let register_enabled = register_mode != "0";
    let invite_required = register_mode == "2";
    let email_verify_enabled = configs
        .get("register_email_verification_enabled")
        .map(|value| value != "0")
        .unwrap_or(true);
    let email_provider_enabled = is_email_configured(&state);

    let verification_enabled = register_enabled && email_verify_enabled && email_provider_enabled;
    let password_reset_enabled = email_verify_enabled && email_provider_enabled;

    success(
        json!({
          "registerEnabled": register_enabled,
          "registerMode": register_mode,
          "inviteRequired": invite_required,
          "verificationEnabled": verification_enabled,
          "passwordResetEnabled": password_reset_enabled,
          "emailProviderEnabled": email_provider_enabled
        }),
        "Success",
    )
}

async fn post_register(
    State(state): State<AppState>,
    Extension(headers): Extension<axum::http::HeaderMap>,
    Json(body): Json<RegisterRequest>,
) -> Response {
    let email = body.email.unwrap_or_default().trim().to_lowercase();
    let username = body.username.unwrap_or_default().trim().to_string();
    let password = body.password.unwrap_or_default();

    let verification_code = body
        .verification_code
        .unwrap_or_default()
        .trim()
        .to_string();

    let invite_code_raw = body.invite_code.unwrap_or_default();

    if email.is_empty() || username.is_empty() || password.is_empty() {
        return error(StatusCode::BAD_REQUEST, "参数缺失", None);
    }
    if !is_valid_email(&email) {
        return error(StatusCode::BAD_REQUEST, "请输入有效的邮箱地址", None);
    }
    if is_gmail_alias(&email) {
        return error(
            StatusCode::BAD_REQUEST,
            "暂不支持使用 Gmail 别名注册，请使用不含点和加号的原始邮箱地址",
            None,
        );
    }

    let flags = match resolve_verification_flags(&state).await {
        Ok(value) => value,
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    };

    if flags.register_mode == "0" {
        return error(StatusCode::FORBIDDEN, "系统暂时关闭注册功能", None);
    }

    let mut inviter_id: Option<i64> = None;
    let invite_code = normalize_invite_code(&invite_code_raw);
    if !invite_code.is_empty() {
        match find_inviter_by_code(&state, &invite_code).await {
            Ok(Some(inviter)) => {
                if inviter.invite_limit > 0 && inviter.invite_used >= inviter.invite_limit {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "该邀请码使用次数已达上限，请联系邀请人",
                        None,
                    );
                }
                inviter_id = Some(inviter.id);
            }
            Ok(None) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "邀请码无效或已失效，请联系邀请人",
                    None,
                );
            }
            Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
        }
    } else if flags.register_mode == "2" {
        return error(
            StatusCode::FORBIDDEN,
            "当前仅允许受邀注册，请填写有效邀请码",
            None,
        );
    }

    if flags.email_verify_enabled && flags.email_provider_enabled {
        match verify_email_code(
            &state,
            &email,
            "register",
            &verification_code,
            get_verification_attempt_limit(&state),
        )
        .await
        {
            Ok(_) => {}
            Err(message) => {
                let status = if message.contains("次数过多") {
                    StatusCode::TOO_MANY_REQUESTS
                } else {
                    StatusCode::BAD_REQUEST
                };
                return error(status, &message, None);
            }
        }
    }

    let register_result = register_user(
        &state,
        &email,
        &username,
        &password,
        get_client_ip(&headers),
        inviter_id,
    )
    .await;
    let user_id = match register_result {
        Ok(value) => value,
        Err(message) => return error(StatusCode::BAD_REQUEST, &message, None),
    };

    if let Some(inviter_id) = inviter_id {
        save_referral_relation(
            &state,
            inviter_id,
            user_id,
            &invite_code,
            get_client_ip(&headers),
        )
        .await;
        increment_invite_usage(&state, inviter_id).await;
    }

    let _ = ensure_user_invite_code(&state, user_id).await;

    let created = match get_user_by_id(&state, user_id).await {
        Ok(value) => value,
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    };

    if let Some(created) = created {
        let response =
            issue_session(&state, &created, Some("register".to_string()), &headers).await;
        return match response {
            Ok((token, payload)) => {
                let user_payload = json!({
                  "id": payload.id,
                  "email": payload.email,
                  "username": payload.username,
                  "is_admin": payload.is_admin
                });
                success(json!({ "token": token, "user": user_payload }), "注册成功").into_response()
            }
            Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
        };
    }

    success(json!({ "user_id": user_id }), "注册成功").into_response()
}

async fn post_send_email_code(
    State(state): State<AppState>,
    Extension(headers): Extension<axum::http::HeaderMap>,
    Json(body): Json<Value>,
) -> Response {
    handle_verification_code_request(&state, &headers, &body, "register", false, true).await
}

async fn post_password_reset_request(
    State(state): State<AppState>,
    Extension(headers): Extension<axum::http::HeaderMap>,
    Json(body): Json<Value>,
) -> Response {
    handle_verification_code_request(&state, &headers, &body, "password_reset", true, false).await
}

async fn post_password_reset_confirm(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Response {
    let email = body
        .get("email")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let code = body
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let new_password = body
        .get("new_password")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    if email.is_empty() || code.is_empty() || new_password.is_empty() {
        return error(StatusCode::BAD_REQUEST, "参数缺失", None);
    }
    if !is_valid_email(&email) {
        return error(StatusCode::BAD_REQUEST, "请输入有效的邮箱地址", None);
    }

    let flags = match resolve_verification_flags(&state).await {
        Ok(value) => value,
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    };
    if !flags.email_verify_enabled || !flags.email_provider_enabled {
        return error(StatusCode::FORBIDDEN, "当前未开启密码重置功能", None);
    }

    match reset_password_with_code(&state, &email, &code, &new_password).await {
        Ok(true) => success(Value::Null, "密码已重置").into_response(),
        Ok(false) => error(StatusCode::BAD_REQUEST, "重置失败", None),
        Err(message) => {
            let status = if message.contains("次数过多") {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::BAD_REQUEST
            };
            error(status, &message, None)
        }
    }
}

async fn post_oauth_login(
    State(state): State<AppState>,
    Extension(headers): Extension<axum::http::HeaderMap>,
    Json(body): Json<OAuthLoginRequest>,
) -> Response {
    let provider = body.provider.unwrap_or_default();
    let email = body.email.unwrap_or_default();
    let provider_id = body.provider_id.unwrap_or_default();
    if provider.trim().is_empty() || email.trim().is_empty() || provider_id.trim().is_empty() {
        return error(StatusCode::BAD_REQUEST, "参数缺失", None);
    }

    let provider_key = provider.to_lowercase();
    let normalized_email = email.trim().to_lowercase();
    let username = body.username.unwrap_or_default();
    let client_ip = get_client_ip(&headers);

    let user = match get_user_by_email(&state, &normalized_email).await {
        Ok(Some(user)) => Some(user),
        Ok(None) => None,
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    };

    let user = if let Some(user) = user {
        user
    } else {
        let fallback = normalized_email
            .split('@')
            .next()
            .unwrap_or("user")
            .to_string();
        let username_value = if username.trim().is_empty() {
            format!("{}_{}", fallback, random_string(4))
        } else {
            username
        };
        let temp_password = random_string(12);
        let register_result = register_user(
            &state,
            &normalized_email,
            &username_value,
            &temp_password,
            client_ip.clone(),
            None,
        )
        .await;
        if let Err(message) = register_result {
            return error(StatusCode::UNAUTHORIZED, &message, None);
        }
        match get_user_by_email(&state, &normalized_email).await {
            Ok(Some(user)) => user,
            Ok(None) => return error(StatusCode::UNAUTHORIZED, "账户不存在", None),
            Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
        }
    };

    let response = issue_session_with_extra(
        &state,
        &user,
        Some(provider_key.clone()),
        &headers,
        json!({ "provider": provider_key })
            .as_object()
            .cloned()
            .unwrap_or_default(),
    )
    .await;
    match response {
        Ok((token, payload)) => {
            let user_payload = json!({
              "id": payload.id,
              "email": payload.email,
              "username": payload.username,
              "is_admin": payload.is_admin
            });
            success(json!({ "token": token, "user": user_payload }), "登录成功").into_response()
        }
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    }
}

async fn post_oauth_complete(
    State(state): State<AppState>,
    Extension(headers): Extension<axum::http::HeaderMap>,
    Json(body): Json<OAuthCompleteRequest>,
) -> Response {
    let invite_code_raw = body.invite_code.unwrap_or_default();
    let pending_token = body.pending_token.unwrap_or_default();

    if pending_token.trim().is_empty() {
        return error(StatusCode::BAD_REQUEST, "缺少注册会话标识", None);
    }

    let pending = consume_pending_oauth_registration(&state, &pending_token).await;
    let pending = match pending {
        Some(value) => value,
        None => {
            return error(
                StatusCode::GONE,
                "注册会话已过期，请重新登录并同意条款",
                None,
            )
        }
    };

    let identifier_field = if pending.provider == "google" {
        "google_sub"
    } else {
        "github_id"
    };
    let oauth_user = get_user_by_identifier(&state, identifier_field, &pending.provider_id).await;
    if let Err(message) = oauth_user {
        return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None);
    }
    let mut oauth_user = oauth_user.unwrap();

    if oauth_user.is_none() {
        let by_email = get_oauth_user_by_email(&state, &pending.email).await;
        match by_email {
            Ok(Some(user)) => {
                if identifier_field == "google_sub" {
                    if let Some(existing) = &user.google_sub {
                        if existing != &pending.provider_id {
                            return error(
                                StatusCode::CONFLICT,
                                "该邮箱已绑定其他第三方账号，请使用原账号登录",
                                None,
                            );
                        }
                    }
                } else if let Some(existing) = &user.github_id {
                    if existing != &pending.provider_id {
                        return error(
                            StatusCode::CONFLICT,
                            "该邮箱已绑定其他第三方账号，请使用原账号登录",
                            None,
                        );
                    }
                }
                oauth_user = Some(user);
            }
            Ok(None) => {}
            Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
        }
    }

    let mut is_new_user = false;
    let mut temp_password: Option<String> = None;
    let mut password_email_sent = false;

    let configs = match resolve_verification_flags(&state).await {
        Ok(value) => value.configs,
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    };
    let register_mode = configs
        .get("register_enabled")
        .cloned()
        .unwrap_or_else(|| "1".to_string());
    let invite_code = normalize_invite_code(&invite_code_raw);
    let mut inviter_id: Option<i64> = None;

    if oauth_user.is_none() {
        if register_mode == "0" {
            return error(StatusCode::FORBIDDEN, "系统暂时关闭注册功能", None);
        }
        if !invite_code.is_empty() {
            match find_inviter_by_code(&state, &invite_code).await {
                Ok(Some(inviter)) => {
                    if inviter.invite_limit > 0 && inviter.invite_used >= inviter.invite_limit {
                        return error(
                            StatusCode::BAD_REQUEST,
                            "该邀请码使用次数已达上限，请联系邀请人",
                            None,
                        );
                    }
                    inviter_id = Some(inviter.id);
                }
                Ok(None) => {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "邀请码无效或已失效，请联系邀请人",
                        None,
                    );
                }
                Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
            }
        } else if register_mode == "2" {
            return error(
                StatusCode::FORBIDDEN,
                "当前仅允许受邀注册，请输入有效邀请码",
                None,
            );
        }

        let username = generate_unique_username(
            &state,
            &pending.username_candidates,
            &pending.fallback_username_seed,
        )
        .await;
        let password = random_string(32);
        temp_password = Some(password.clone());
        let register_result = register_user(
            &state,
            &pending.email,
            &username,
            &password,
            pending.client_ip.clone(),
            inviter_id,
        )
        .await;
        let user_id = match register_result {
            Ok(value) => value,
            Err(message) => return error(StatusCode::BAD_REQUEST, &message, None),
        };

        if let Some(inviter_id) = inviter_id {
            save_referral_relation(
                &state,
                inviter_id,
                user_id,
                &invite_code,
                pending.client_ip.clone(),
            )
            .await;
            increment_invite_usage(&state, inviter_id).await;
        }

        let _ = ensure_user_invite_code(&state, user_id).await;
        oauth_user = get_oauth_user_by_id(&state, user_id).await.ok().flatten();

        let provider_label = if pending.provider == "google" {
            "Google"
        } else {
            "GitHub"
        };
        if let Some(temp_password) = temp_password.as_ref() {
            password_email_sent =
                send_oauth_welcome_email(&state, provider_label, &pending.email, temp_password)
                    .await;
        }
        is_new_user = true;
    }

    let user = match oauth_user {
        Some(user) => user,
        None => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法创建或加载用户信息",
                None,
            )
        }
    };
    if user.status != 1 {
        return error(StatusCode::FORBIDDEN, "账户已禁用", None);
    }

    if let Err(message) = update_oauth_binding(
        &state,
        identifier_field,
        &pending.provider_id,
        &pending.provider,
        user.id,
    )
    .await
    {
        return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None);
    }

    let refreshed = get_user_by_id(&state, user.id).await;
    let refreshed = match refreshed {
        Ok(Some(user)) => user,
        Ok(None) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法创建或加载用户信息",
                None,
            )
        }
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    };

    let method = if pending.provider == "google" {
        "google_oauth"
    } else {
        "github_oauth"
    };
    let result = finalize_oauth_login(
        &state,
        &refreshed,
        method,
        &headers,
        json!({
          "provider": pending.provider,
          "isNewUser": is_new_user,
          "tempPassword": temp_password,
          "passwordEmailSent": password_email_sent
        }),
    )
    .await;
    match result {
        Ok(value) => success(value, "登录成功").into_response(),
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    }
}

async fn post_google_oauth(
    State(state): State<AppState>,
    Extension(headers): Extension<axum::http::HeaderMap>,
    Json(body): Json<GoogleOAuthRequest>,
) -> Response {
    let id_token = body.id_token.unwrap_or_default();
    let remember = body.remember.unwrap_or(false);

    if id_token.trim().is_empty() {
        return error(StatusCode::BAD_REQUEST, "缺少 idToken", None);
    }
    let client_id = match state.env.google_client_id.as_ref() {
        Some(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => return error(StatusCode::BAD_REQUEST, "未配置 Google OAuth", None),
    };

    let token_info = match fetch_google_token_info(&id_token).await {
        Ok(value) => value,
        Err(message) => return error(StatusCode::UNAUTHORIZED, &message, None),
    };

    let aud = token_info.get("aud").and_then(Value::as_str).unwrap_or("");
    if aud != client_id {
        return error(StatusCode::UNAUTHORIZED, "aud 不匹配", None);
    }
    let issuer = token_info.get("iss").and_then(Value::as_str).unwrap_or("");
    if issuer != "accounts.google.com" && issuer != "https://accounts.google.com" {
        return error(StatusCode::UNAUTHORIZED, "iss 不合法", None);
    }

    let google_sub = token_info
        .get("sub")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let email = token_info
        .get("email")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let email_verified = match token_info.get("email_verified") {
        Some(Value::Bool(value)) => *value,
        Some(Value::String(value)) => value == "true",
        _ => false,
    };
    if google_sub.is_empty() {
        return error(StatusCode::BAD_REQUEST, "无效的 Google sub", None);
    }
    if email.is_empty() {
        return error(StatusCode::BAD_REQUEST, "未获取到邮箱", None);
    }

    let mut user = match get_user_by_identifier(&state, "google_sub", &google_sub).await {
        Ok(value) => value,
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    };
    if user.is_none() {
        match get_oauth_user_by_email(&state, &email).await {
            Ok(Some(found)) => {
                if let Some(existing) = found.google_sub.clone() {
                    if existing != google_sub {
                        return error(StatusCode::BAD_REQUEST, "邮箱已绑定其它 Google 账号", None);
                    }
                }
                user = Some(found);
            }
            Ok(None) => {}
            Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
        }
    }

    if user.is_none() {
        let email_local = email.split('@').next().unwrap_or("").to_string();
        let mut candidates = vec![];
        if let Some(value) = token_info.get("given_name").and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                candidates.push(trimmed.to_string());
            }
        }
        if let Some(value) = token_info.get("name").and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                candidates.push(trimmed.to_string());
            }
        }
        if !email_local.is_empty() {
            candidates.push(email_local.clone());
        }
        candidates.push(format!("google_{}", tail_suffix(&google_sub, 6)));

        let pending_token = cache_pending_oauth_registration(
            &state,
            PendingOAuthRegistration {
                provider: "google".to_string(),
                email: email.clone(),
                provider_id: google_sub.clone(),
                username_candidates: candidates.clone(),
                fallback_username_seed: if !email_local.is_empty() {
                    email_local.clone()
                } else {
                    tail_suffix(&google_sub, 6)
                },
                remember,
                client_ip: get_client_ip(&headers),
                user_agent: headers
                    .get("user-agent")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.to_string()),
            },
        )
        .await;

        let profile_username = candidates.first().cloned().unwrap_or_else(|| {
            if !email_local.is_empty() {
                email_local.clone()
            } else {
                format!("google_{}", tail_suffix(&google_sub, 6))
            }
        });

        return success(
            json!({
              "need_terms_agreement": true,
              "pending_terms_token": pending_token,
              "provider": "google",
              "profile": {
                "email": email,
                "username": profile_username,
                "avatar": token_info.get("picture").and_then(Value::as_str).unwrap_or("")
              }
            }),
            "请先同意服务条款",
        )
        .into_response();
    }

    let user = user.unwrap();
    if user.status != 1 {
        return error(StatusCode::FORBIDDEN, "账户已禁用", None);
    }

    if let Err(message) =
        update_oauth_binding(&state, "google_sub", &google_sub, "google", user.id).await
    {
        return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None);
    }

    let refreshed = match get_user_by_id(&state, user.id).await {
        Ok(Some(user)) => user,
        Ok(None) => return error(StatusCode::INTERNAL_SERVER_ERROR, "创建用户失败", None),
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    };

    let result = finalize_oauth_login(
        &state,
        &refreshed,
        "google_oauth",
        &headers,
        json!({
          "provider": "google",
          "email_verified": email_verified,
          "isNewUser": false,
          "tempPassword": Value::Null,
          "passwordEmailSent": false
        }),
    )
    .await;

    match result {
        Ok(value) => success(value, "登录成功").into_response(),
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    }
}

async fn post_github_oauth(
    State(state): State<AppState>,
    Extension(headers): Extension<axum::http::HeaderMap>,
    Json(body): Json<GithubOAuthRequest>,
) -> Response {
    let code = body.code.unwrap_or_default();
    if code.trim().is_empty() {
        return error(StatusCode::BAD_REQUEST, "缺少 code", None);
    }
    let client_id = match state.env.github_client_id.as_ref() {
        Some(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => return error(StatusCode::BAD_REQUEST, "未配置 GitHub OAuth", None),
    };
    let client_secret = match state.env.github_client_secret.as_ref() {
        Some(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => return error(StatusCode::BAD_REQUEST, "未配置 GitHub OAuth", None),
    };

    let redirect_uri = body
        .redirect_uri
        .map(|value| value.to_string())
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            state
                .env
                .github_redirect_uri
                .as_ref()
                .map(|value| value.to_string())
        })
        .unwrap_or_default();
    let remember = body.remember.unwrap_or(false);

    let access_token =
        match exchange_github_token(&client_id, &client_secret, &code, &redirect_uri).await {
            Ok(value) => value,
            Err(message) => return error(StatusCode::UNAUTHORIZED, &message, None),
        };

    let gh_user = match fetch_github_user(&access_token).await {
        Ok(value) => value,
        Err(message) => return error(StatusCode::UNAUTHORIZED, &message, None),
    };

    let github_id = gh_user
        .get("id")
        .and_then(Value::as_i64)
        .map(|v| v.to_string())
        .unwrap_or_default();
    if github_id.is_empty() {
        return error(StatusCode::BAD_REQUEST, "无效的 GitHub ID", None);
    }

    let mut email = gh_user
        .get("email")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if email.trim().is_empty() {
        if let Ok(value) = fetch_github_email(&access_token).await {
            email = value;
        }
    }
    if email.trim().is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "未获取到邮箱，请在 GitHub 公开邮箱后重试",
            None,
        );
    }
    let normalized_email = email.trim().to_lowercase();

    let mut user = match get_user_by_identifier(&state, "github_id", &github_id).await {
        Ok(value) => value,
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    };
    if user.is_none() {
        match get_oauth_user_by_email(&state, &normalized_email).await {
            Ok(Some(found)) => {
                if let Some(existing) = found.github_id.clone() {
                    if existing != github_id {
                        return error(StatusCode::BAD_REQUEST, "邮箱已绑定其它 GitHub 账号", None);
                    }
                }
                user = Some(found);
            }
            Ok(None) => {}
            Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
        }
    }

    if user.is_none() {
        let email_local = normalized_email.split('@').next().unwrap_or("").to_string();
        let mut candidates = vec![];
        if let Some(value) = gh_user.get("login").and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                candidates.push(trimmed.to_string());
            }
        }
        if let Some(value) = gh_user.get("name").and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                candidates.push(trimmed.to_string());
            }
        }
        if !email_local.is_empty() {
            candidates.push(email_local.clone());
        }
        candidates.push(format!("github_{}", tail_suffix(&github_id, 6)));

        let pending_token = cache_pending_oauth_registration(
            &state,
            PendingOAuthRegistration {
                provider: "github".to_string(),
                email: normalized_email.clone(),
                provider_id: github_id.clone(),
                username_candidates: candidates.clone(),
                fallback_username_seed: if !email_local.is_empty() {
                    email_local.clone()
                } else {
                    tail_suffix(&github_id, 6)
                },
                remember,
                client_ip: get_client_ip(&headers),
                user_agent: headers
                    .get("user-agent")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.to_string()),
            },
        )
        .await;

        let profile_username = candidates.first().cloned().unwrap_or_else(|| {
            if !email_local.is_empty() {
                email_local.clone()
            } else {
                format!("github_{}", tail_suffix(&github_id, 6))
            }
        });

        return success(
            json!({
              "need_terms_agreement": true,
              "pending_terms_token": pending_token,
              "provider": "github",
              "profile": {
                "email": normalized_email,
                "username": profile_username,
                "avatar": gh_user.get("avatar_url").and_then(Value::as_str).unwrap_or("")
              }
            }),
            "请先同意服务条款",
        )
        .into_response();
    }

    let user = user.unwrap();
    if user.status != 1 {
        return error(StatusCode::FORBIDDEN, "账户已禁用", None);
    }

    if let Err(message) =
        update_oauth_binding(&state, "github_id", &github_id, "github", user.id).await
    {
        return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None);
    }

    let refreshed = match get_user_by_id(&state, user.id).await {
        Ok(Some(user)) => user,
        Ok(None) => return error(StatusCode::INTERNAL_SERVER_ERROR, "创建用户失败", None),
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    };

    let result = finalize_oauth_login(
        &state,
        &refreshed,
        "github_oauth",
        &headers,
        json!({
          "provider": "github",
          "isNewUser": false,
          "tempPassword": Value::Null,
          "passwordEmailSent": false
        }),
    )
    .await;

    match result {
        Ok(value) => success(value, "登录成功").into_response(),
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    }
}

async fn post_passkey_register_options(
    State(state): State<AppState>,
    Extension(headers): Extension<axum::http::HeaderMap>,
) -> Response {
    let user = match require_user(&state, &headers, None).await {
        Ok(value) => value,
        Err(resp) => return resp,
    };

    let configs = list_system_configs(&state).await.unwrap_or_default();
    let site_name = configs
        .get("site_name")
        .cloned()
        .or_else(|| state.env.site_name.clone())
        .unwrap_or_else(|| "Soga Panel".to_string());
    let rp_id = get_rp_id(&headers, &state);
    let origin = get_expected_origin(&headers, &state);
    let challenge = random_challenge(32);

    let passkeys = match list_passkeys(&state, user.id).await {
        Ok(value) => value,
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    };

    let _ = save_passkey_challenge(
        &state,
        PasskeyChallenge {
            challenge_type: "registration".to_string(),
            user_id: user.id,
            challenge: challenge.clone(),
            rp_id: rp_id.clone(),
            origin: origin.clone(),
            remember: false,
            created_at: Utc::now().timestamp_millis(),
        },
    )
    .await;

    let exclude_credentials: Vec<Value> = passkeys
        .iter()
        .map(|row| {
            json!({
              "id": row.credential_id,
              "type": "public-key",
              "transports": parse_transports(row.transports.as_deref())
            })
        })
        .collect();

    let display_name = if !user.username.is_empty() {
        user.username.clone()
    } else if !user.email.is_empty() {
        user.email.clone()
    } else {
        format!("user_{}", user.id)
    };

    let user_id = base64url_encode(user.id.to_string().as_bytes());
    success(
        json!({
          "challenge": challenge,
          "rp": { "id": rp_id, "name": site_name },
          "user": {
            "id": user_id,
            "name": if !user.email.is_empty() { user.email.clone() } else { display_name.clone() },
            "displayName": display_name
          },
          "pubKeyCredParams": [
            { "type": "public-key", "alg": -7 },
            { "type": "public-key", "alg": -257 }
          ],
          "timeout": 120000,
          "attestation": "none",
          "authenticatorSelection": {
            "userVerification": "preferred",
            "residentKey": "preferred"
          },
          "excludeCredentials": exclude_credentials
        }),
        "Success",
    )
    .into_response()
}

async fn post_passkey_register_verify(
    State(state): State<AppState>,
    Extension(headers): Extension<axum::http::HeaderMap>,
    Json(body): Json<PasskeyRegisterVerifyRequest>,
) -> Response {
    let user = match require_user(&state, &headers, None).await {
        Ok(value) => value,
        Err(resp) => return resp,
    };

    let credential = body.credential;
    if credential.response.client_data_json.trim().is_empty()
        || credential.response.attestation_object.trim().is_empty()
    {
        return error(StatusCode::BAD_REQUEST, "缺少凭证数据", None);
    }

    let received_challenge =
        extract_client_challenge(&credential.response.client_data_json).unwrap_or_default();
    if received_challenge.is_empty() {
        return error(StatusCode::BAD_REQUEST, "挑战码无效，请重试", None);
    }

    let challenge = load_passkey_challenge(&state, &received_challenge).await;
    let challenge = match challenge {
        Some(value) => value,
        None => {
            return error(
                StatusCode::BAD_REQUEST,
                "Passkey 注册会话已过期，请重试",
                None,
            )
        }
    };
    if challenge.challenge_type != "registration" || challenge.user_id != user.id {
        return error(
            StatusCode::BAD_REQUEST,
            "Passkey 注册会话已过期，请重试",
            None,
        );
    }

    let validated = match validate_registration_response(
        &credential,
        &challenge.challenge,
        &challenge.origin,
        &challenge.rp_id,
    ) {
        Ok(value) => value,
        Err(message) => {
            clear_passkey_challenge(&state, &received_challenge).await;
            return error(StatusCode::BAD_REQUEST, &message, None);
        }
    };

    match get_passkey_by_credential_id(&state, &validated.credential_id).await {
        Ok(Some(_)) => {
            clear_passkey_challenge(&state, &received_challenge).await;
            return error(StatusCode::BAD_REQUEST, "该 Passkey 已被绑定", None);
        }
        Ok(None) => {}
        Err(message) => {
            clear_passkey_challenge(&state, &received_challenge).await;
            return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None);
        }
    }

    let safe_device_name = body
        .device_name
        .and_then(|value| {
            let trimmed = value.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
        .map(|value| value.chars().take(64).collect::<String>());

    let user_handle = validated
        .user_handle
        .clone()
        .unwrap_or_else(|| base64url_encode(user.id.to_string().as_bytes()));

    let result = insert_passkey(
        &state,
        PasskeyInsert {
            user_id: user.id,
            credential_id: validated.credential_id.clone(),
            public_key: validated.public_key.clone(),
            alg: validated.alg,
            user_handle: Some(user_handle),
            rp_id: Some(challenge.rp_id.clone()),
            transports: validated.transports.clone(),
            sign_count: validated.sign_count as i64,
            device_name: safe_device_name,
        },
    )
    .await;

    clear_passkey_challenge(&state, &received_challenge).await;

    match result {
        Ok(()) => success(
            json!({ "credential_id": validated.credential_id }),
            "Passkey 已绑定",
        )
        .into_response(),
        Err(message) => error(StatusCode::BAD_REQUEST, &message, None),
    }
}

async fn post_passkey_login_options(
    State(state): State<AppState>,
    Extension(headers): Extension<axum::http::HeaderMap>,
    Json(body): Json<PasskeyLoginOptionsRequest>,
) -> Response {
    let email = body.email.unwrap_or_default().trim().to_lowercase();
    if email.is_empty() {
        return error(StatusCode::BAD_REQUEST, "请填写邮箱", None);
    }

    let user = match get_user_by_email(&state, &email).await {
        Ok(Some(user)) => user,
        Ok(None) => return error(StatusCode::NOT_FOUND, "账户不存在", None),
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    };

    let passkeys = match list_passkeys(&state, user.id).await {
        Ok(value) => value,
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    };
    if passkeys.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "该账户未绑定 Passkey，请先使用密码登录绑定",
            None,
        );
    }

    let rp_id = passkeys
        .iter()
        .find_map(|row| row.rp_id.clone())
        .unwrap_or_else(|| get_rp_id(&headers, &state));
    let origin = get_expected_origin(&headers, &state);
    let challenge = random_challenge(32);

    let _ = save_passkey_challenge(
        &state,
        PasskeyChallenge {
            challenge_type: "authentication".to_string(),
            user_id: user.id,
            challenge: challenge.clone(),
            rp_id: rp_id.clone(),
            origin: origin.clone(),
            remember: body.remember.unwrap_or(false),
            created_at: Utc::now().timestamp_millis(),
        },
    )
    .await;

    let allow_credentials: Vec<Value> = passkeys
        .iter()
        .map(|row| {
            json!({
              "id": row.credential_id,
              "type": "public-key",
              "transports": parse_transports(row.transports.as_deref())
            })
        })
        .collect();

    success(
        json!({
          "challenge": challenge,
          "rpId": rp_id,
          "timeout": 120000,
          "allowCredentials": allow_credentials,
          "userVerification": "required"
        }),
        "Success",
    )
    .into_response()
}

async fn post_passkey_login_verify(
    State(state): State<AppState>,
    Extension(headers): Extension<axum::http::HeaderMap>,
    Json(body): Json<PasskeyLoginVerifyRequest>,
) -> Response {
    let credential = body.credential;
    if credential.response.client_data_json.trim().is_empty()
        || credential.response.authenticator_data.trim().is_empty()
        || credential.response.signature.trim().is_empty()
    {
        return error(StatusCode::BAD_REQUEST, "缺少凭证数据", None);
    }

    let client_challenge =
        extract_client_challenge(&credential.response.client_data_json).unwrap_or_default();
    if client_challenge.is_empty() {
        return error(StatusCode::BAD_REQUEST, "挑战码无效，请重试", None);
    }

    let challenge = load_passkey_challenge(&state, &client_challenge).await;
    let challenge = match challenge {
        Some(value) => value,
        None => return error(StatusCode::BAD_REQUEST, "登录会话已失效，请重试", None),
    };
    if challenge.challenge_type != "authentication" {
        return error(StatusCode::BAD_REQUEST, "登录会话已失效，请重试", None);
    }

    let credential_id = credential.id.clone();
    let passkey = match get_passkey_by_credential_id(&state, &credential_id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            clear_passkey_challenge(&state, &client_challenge).await;
            return error(StatusCode::NOT_FOUND, "未找到匹配的 Passkey", None);
        }
        Err(message) => {
            clear_passkey_challenge(&state, &client_challenge).await;
            return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None);
        }
    };
    if passkey.user_id != challenge.user_id {
        clear_passkey_challenge(&state, &client_challenge).await;
        return error(StatusCode::NOT_FOUND, "未找到匹配的 Passkey", None);
    }

    let user = match get_user_by_id(&state, passkey.user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            clear_passkey_challenge(&state, &client_challenge).await;
            return error(StatusCode::NOT_FOUND, "账户不存在", None);
        }
        Err(message) => {
            clear_passkey_challenge(&state, &client_challenge).await;
            return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None);
        }
    };
    if user.status != 1 {
        clear_passkey_challenge(&state, &client_challenge).await;
        return error(StatusCode::FORBIDDEN, "账户已禁用", None);
    }

    let expected_rp_id = if !challenge.rp_id.is_empty() {
        challenge.rp_id.clone()
    } else {
        get_rp_id(&headers, &state)
    };

    let validated = match validate_authentication_response(
        &credential,
        &challenge.challenge,
        &challenge.origin,
        &expected_rp_id,
        &passkey.public_key,
        passkey.alg,
        passkey.user_handle.as_deref(),
    ) {
        Ok(value) => value,
        Err(message) => {
            clear_passkey_challenge(&state, &client_challenge).await;
            return error(StatusCode::BAD_REQUEST, &message, None);
        }
    };

    let new_count = validated.new_sign_count as i64;
    let final_count = if new_count > passkey.sign_count {
        new_count
    } else {
        passkey.sign_count
    };
    let _ = update_passkey_usage(&state, &credential_id, final_count).await;

    clear_passkey_challenge(&state, &client_challenge).await;

    match issue_session(&state, &user, Some("passkey".to_string()), &headers).await {
        Ok((token, payload)) => {
            let user_payload = json!({
              "id": payload.id,
              "email": payload.email,
              "username": payload.username,
              "is_admin": payload.is_admin == 1
            });
            success(json!({ "token": token, "user": user_payload }), "登录成功").into_response()
        }
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    }
}

async fn post_login(
    State(state): State<AppState>,
    Extension(headers): Extension<axum::http::HeaderMap>,
    Json(body): Json<LoginRequest>,
) -> Response {
    let email = body.email.unwrap_or_default().trim().to_lowercase();
    let password = body.password.unwrap_or_default();
    if email.is_empty() || password.is_empty() {
        return error(StatusCode::BAD_REQUEST, "参数缺失", None);
    }

    if let Some(secret) = state
        .env
        .turnstile_secret_key
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        let token = body
            .turnstile_token
            .or(body.cf_turnstile_response)
            .unwrap_or_default()
            .trim()
            .to_string();
        if token.is_empty() {
            return error(StatusCode::BAD_REQUEST, "请完成人机验证后再登录", None);
        }
        match verify_turnstile(secret, &token, get_client_ip(&headers)).await {
            Ok(true) => {}
            Ok(false) => return error(StatusCode::BAD_REQUEST, "人机验证未通过，请重试", None),
            Err(TurnstileError::RequestFailed) => {
                return error(StatusCode::BAD_REQUEST, "人机验证失败，请稍后重试", None)
            }
            Err(TurnstileError::InvalidResponse) => {
                return error(StatusCode::BAD_REQUEST, "人机验证异常，请稍后重试", None)
            }
        }
    }

    let user = match get_user_by_email(&state, &email).await {
        Ok(Some(user)) => user,
        Ok(None) => return error(StatusCode::UNAUTHORIZED, "账户不存在", None),
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    };

    if user.status != 1 {
        return error(StatusCode::UNAUTHORIZED, "账户已禁用", None);
    }
    if !verify_password(&password, &user.password_hash) {
        return error(StatusCode::UNAUTHORIZED, "密码错误", None);
    }

    if user.two_factor_enabled == 1 {
        let trust_token = body.two_factor_trust_token.clone().unwrap_or_default();
        if !trust_token.is_empty() {
            if let Some(value) =
                cache_get_redis_only(&state, &format!("2fa_trust_{trust_token}")).await
            {
                if value == user.id.to_string() {
                    return finalize_login(&state, &user, "password", &headers).await;
                }
            }
        }

        let code = body.two_factor_code.clone().unwrap_or_default();
        let backup_code = body.backup_code.clone().unwrap_or_default();
        if code.is_empty() && backup_code.is_empty() {
            let challenge_id =
                create_two_factor_challenge(&state, user.id, body.remember.unwrap_or(false)).await;
            return success(
                json!({
                  "need_2fa": true,
                  "challenge_id": challenge_id,
                  "two_factor_enabled": true
                }),
                "Success",
            )
            .into_response();
        }

        let secret = match decrypt_two_factor_secret(&state, user.two_factor_secret.as_deref()) {
            Ok(secret) => secret,
            Err(message) => return error(StatusCode::UNAUTHORIZED, &message, None),
        };
        let mut backup_codes = parse_backup_codes(user.two_factor_backup_codes.as_deref());
        let mut verified = false;
        let mut used_index: Option<usize> = None;

        if !code.is_empty() && verify_totp(&secret, &code, 1) {
            verified = true;
        } else if !backup_code.is_empty() {
            let hashed = sha256_hex(&normalize_backup_code(&backup_code));
            if let Some(pos) = backup_codes.iter().position(|code| code == &hashed) {
                verified = true;
                used_index = Some(pos);
            }
        }

        if !verified {
            return error(StatusCode::UNAUTHORIZED, "需要二步验证码或备份码", None);
        }

        if let Some(index) = used_index {
            backup_codes.remove(index);
            let _ = update_two_factor_data(
                &state,
                user.id,
                1,
                user.two_factor_secret.as_deref(),
                &backup_codes,
            )
            .await;
        }
    }

    finalize_login(&state, &user, "password", &headers).await
}

async fn post_telegram_miniapp_login(
    State(state): State<AppState>,
    Extension(headers): Extension<axum::http::HeaderMap>,
    Json(body): Json<TelegramMiniAppLoginRequest>,
) -> Response {
    let init_data = body.init_data.unwrap_or_default().trim().to_string();
    if init_data.is_empty() {
        return error(StatusCode::BAD_REQUEST, "缺少 Telegram initData", None);
    }

    let configs = list_system_configs(&state).await.unwrap_or_default();
    let mut bot_token = configs
        .get("telegram_bot_token")
        .cloned()
        .unwrap_or_default();
    if bot_token.trim().is_empty() {
        bot_token = std::env::var("TELEGRAM_BOT_TOKEN")
            .ok()
            .map(|value| value.trim().to_string())
            .unwrap_or_default();
    }
    if bot_token.trim().is_empty() {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "未配置 telegram_bot_token，请联系管理员",
            None,
        );
    }

    let telegram_user_id = match verify_telegram_init_data(&init_data, &bot_token) {
        Ok(value) => value,
        Err(message) => return error(StatusCode::UNAUTHORIZED, &message, None),
    };
    let telegram_id = telegram_user_id.to_string();

    let user = match get_user_by_telegram_id(&state, &telegram_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return error(
                StatusCode::NOT_FOUND,
                "当前 Telegram 未绑定账号，请先在面板完成绑定",
                None,
            )
        }
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    };

    if user.status != 1 {
        return error(StatusCode::UNAUTHORIZED, "账户已禁用", None);
    }

    if user.two_factor_enabled == 1 {
        let trust_token = body.two_factor_trust_token.unwrap_or_default();
        if !trust_token.trim().is_empty() {
            if let Some(value) =
                cache_get_redis_only(&state, &format!("2fa_trust_{trust_token}")).await
            {
                if value == user.id.to_string() {
                    return finalize_login(&state, &user, "telegram_miniapp", &headers).await;
                }
            }
        }

        let challenge_id =
            create_two_factor_challenge(&state, user.id, body.remember.unwrap_or(true)).await;
        return success(
            json!({
              "need_2fa": true,
              "challenge_id": challenge_id,
              "two_factor_enabled": true,
              "provider": "telegram"
            }),
            "Success",
        )
        .into_response();
    }

    finalize_login(&state, &user, "telegram_miniapp", &headers).await
}

async fn post_verify_2fa(
    State(state): State<AppState>,
    Extension(headers): Extension<axum::http::HeaderMap>,
    Json(body): Json<Verify2faRequest>,
) -> Response {
    let challenge_id = body.challenge_id.unwrap_or_default();
    let code = body.code.unwrap_or_default();
    if challenge_id.is_empty() || code.trim().is_empty() {
        return error(StatusCode::BAD_REQUEST, "缺少参数", None);
    }

    let key = format!("2fa_challenge_{challenge_id}");
    let cached = match cache_get_redis_only(&state, &key).await {
        Some(value) => value,
        None => return error(StatusCode::UNAUTHORIZED, "验证会话已过期，请重新登录", None),
    };
    let parsed: Value = serde_json::from_str(&cached).unwrap_or_else(|_| json!({}));
    let user_id = parsed.get("userId").and_then(Value::as_i64).unwrap_or(0);
    if user_id <= 0 {
        return error(StatusCode::UNAUTHORIZED, "验证会话无效", None);
    }

    let user = match get_user_by_id(&state, user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return error(StatusCode::UNAUTHORIZED, "用户不存在", None),
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    };
    if user.two_factor_enabled != 1 {
        return error(StatusCode::UNAUTHORIZED, "未启用二步验证", None);
    }

    let secret = match decrypt_two_factor_secret(&state, user.two_factor_secret.as_deref()) {
        Ok(secret) => secret,
        Err(message) => return error(StatusCode::UNAUTHORIZED, &message, None),
    };
    let mut backup_codes = parse_backup_codes(user.two_factor_backup_codes.as_deref());
    let mut verified = false;
    let mut used_index: Option<usize> = None;
    let trimmed = code.trim();

    if verify_totp(&secret, trimmed, 1) {
        verified = true;
    } else {
        let hashed = sha256_hex(&normalize_backup_code(trimmed));
        if let Some(pos) = backup_codes.iter().position(|value| value == &hashed) {
            verified = true;
            used_index = Some(pos);
        }
    }

    if !verified {
        return error(StatusCode::UNAUTHORIZED, "验证码无效，请重试", None);
    }

    if let Some(index) = used_index {
        backup_codes.remove(index);
        let _ = update_two_factor_data(
            &state,
            user.id,
            1,
            user.two_factor_secret.as_deref(),
            &backup_codes,
        )
        .await;
    }

    cache_delete(&state, &key).await;

    let trust_token = if body.remember_device.unwrap_or(false) {
        let token = random_string(48);
        cache_set_redis_only(
            &state,
            &format!("2fa_trust_{token}"),
            &user.id.to_string(),
            TRUST_TTL,
        )
        .await;
        Some(token)
    } else {
        None
    };

    let response = issue_session(&state, &user, Some("password".to_string()), &headers).await;
    match response {
        Ok((token, payload)) => {
            let mut data = serde_json::Map::new();
            data.insert("token".to_string(), json!(token));
            data.insert(
                "user".to_string(),
                json!({
                  "id": payload.id,
                  "email": payload.email,
                  "username": payload.username,
                  "is_admin": payload.is_admin == 1
                }),
            );
            if let Some(value) = trust_token {
                data.insert("trust_token".to_string(), json!(value));
            }
            success(Value::Object(data), "登录成功").into_response()
        }
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    }
}

async fn post_logout(
    State(state): State<AppState>,
    Extension(headers): Extension<axum::http::HeaderMap>,
    body: Option<Json<Value>>,
) -> Response {
    let body_value = body.map(|value| value.0).unwrap_or_else(|| json!({}));
    let token = body_value
        .get("token")
        .and_then(Value::as_str)
        .map(|value| value.to_string())
        .or_else(|| parse_auth_header(&headers));
    let token = match token {
        Some(value) => value,
        None => return error(StatusCode::BAD_REQUEST, "缺少 token", None),
    };

    cache_delete(&state, &format!("session_{token}")).await;
    success(Value::Null, "已登出").into_response()
}

async fn finalize_login(
    state: &AppState,
    user: &UserRow,
    login_method: &str,
    headers: &axum::http::HeaderMap,
) -> Response {
    let response = issue_session(state, user, Some(login_method.to_string()), headers).await;
    match response {
        Ok((token, payload)) => {
            let mut data = serde_json::Map::new();
            data.insert("token".to_string(), json!(token));
            data.insert(
                "user".to_string(),
                json!({
                  "id": payload.id,
                  "email": payload.email,
                  "username": payload.username,
                  "is_admin": payload.is_admin == 1
                }),
            );
            success(Value::Object(data), "登录成功").into_response()
        }
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    }
}

async fn issue_session(
    state: &AppState,
    user: &UserRow,
    login_method: Option<String>,
    headers: &axum::http::HeaderMap,
) -> Result<(String, SessionPayload), String> {
    let payload = SessionPayload {
        id: user.id,
        email: user.email.clone(),
        username: user.username.clone(),
        is_admin: user.is_admin,
    };
    let session_token = random_string(48);
    let session_payload = json!({
      "id": payload.id,
      "email": payload.email,
      "username": payload.username,
      "is_admin": payload.is_admin,
      "login_time": Utc::now().to_rfc3339()
    });
    cache_set(
        state,
        &format!("session_{session_token}"),
        &session_payload.to_string(),
        SESSION_TTL,
    )
    .await;

    update_login_info(state, payload.id, get_client_ip(headers)).await;
    insert_login_log(
        state,
        payload.id,
        get_client_ip(headers),
        headers
            .get("user-agent")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string(),
        login_method.unwrap_or_else(|| "password".to_string()),
    )
    .await;

    Ok((session_token, payload))
}

async fn issue_session_with_extra(
    state: &AppState,
    user: &UserRow,
    login_method: Option<String>,
    headers: &axum::http::HeaderMap,
    extra: serde_json::Map<String, Value>,
) -> Result<(String, SessionPayload), String> {
    let payload = SessionPayload {
        id: user.id,
        email: user.email.clone(),
        username: user.username.clone(),
        is_admin: user.is_admin,
    };
    let session_token = random_string(48);
    let mut session_payload = serde_json::Map::new();
    session_payload.insert("id".to_string(), json!(payload.id));
    session_payload.insert("email".to_string(), json!(payload.email));
    session_payload.insert("username".to_string(), json!(payload.username));
    session_payload.insert("is_admin".to_string(), json!(payload.is_admin));
    session_payload.insert("login_time".to_string(), json!(Utc::now().to_rfc3339()));
    for (key, value) in extra {
        session_payload.insert(key, value);
    }
    cache_set(
        state,
        &format!("session_{session_token}"),
        &Value::Object(session_payload).to_string(),
        SESSION_TTL,
    )
    .await;

    update_login_info(state, payload.id, get_client_ip(headers)).await;
    insert_login_log(
        state,
        payload.id,
        get_client_ip(headers),
        headers
            .get("user-agent")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string(),
        login_method.unwrap_or_else(|| "password".to_string()),
    )
    .await;

    Ok((session_token, payload))
}

async fn finalize_oauth_login(
    state: &AppState,
    user: &UserRow,
    method: &str,
    headers: &axum::http::HeaderMap,
    extra: Value,
) -> Result<Value, String> {
    let (token, payload) = issue_session(state, user, Some(method.to_string()), headers).await?;
    let mut data = serde_json::Map::new();
    data.insert("token".to_string(), json!(token));
    data.insert(
        "user".to_string(),
        json!({
          "id": payload.id,
          "email": payload.email,
          "username": payload.username,
          "is_admin": payload.is_admin == 1
        }),
    );
    if let Value::Object(extra_map) = extra {
        for (key, value) in extra_map {
            data.insert(key, value);
        }
    }
    let _ = ensure_user_invite_code(state, payload.id).await;
    Ok(Value::Object(data))
}

async fn cache_pending_oauth_registration(
    state: &AppState,
    payload: PendingOAuthRegistration,
) -> String {
    let token = random_string(48);
    let cache_key = format!("oauth_pending_{token}");
    if let Ok(raw) = serde_json::to_string(&payload) {
        cache_set_redis_only(state, &cache_key, &raw, OAUTH_PENDING_TTL as u64).await;
    }

    let mut pending = state.oauth_pending.write().await;
    pending.insert(
        cache_key.clone(),
        PendingOAuthCache {
            payload,
            expires_at: Utc::now().timestamp() + OAUTH_PENDING_TTL,
        },
    );
    token
}

async fn consume_pending_oauth_registration(
    state: &AppState,
    token: &str,
) -> Option<PendingOAuthRegistration> {
    if token.trim().is_empty() {
        return None;
    }
    let cache_key = format!("oauth_pending_{token}");
    if let Some(raw) = cache_get_redis_only(state, &cache_key).await {
        cache_delete(state, &cache_key).await;
        let _ = state.oauth_pending.write().await.remove(&cache_key);
        return serde_json::from_str::<PendingOAuthRegistration>(&raw).ok();
    }

    let mut pending = state.oauth_pending.write().await;
    let cached = pending.remove(&cache_key)?;
    if cached.expires_at <= Utc::now().timestamp() {
        return None;
    }
    Some(cached.payload)
}

fn build_passkey_cache_key(challenge: &str) -> String {
    format!("passkey_challenge_{challenge}")
}

async fn save_passkey_challenge(state: &AppState, payload: PasskeyChallenge) {
    let cache_key = build_passkey_cache_key(&payload.challenge);
    if let Ok(raw) = serde_json::to_string(&payload) {
        cache_set_redis_only(state, &cache_key, &raw, PASSKEY_CHALLENGE_TTL as u64).await;
    }

    let mut cache = state.passkey_challenges.write().await;
    cache.insert(
        cache_key,
        PasskeyChallengeCache {
            payload,
            expires_at: Utc::now().timestamp() + PASSKEY_CHALLENGE_TTL,
        },
    );
}

async fn load_passkey_challenge(state: &AppState, challenge: &str) -> Option<PasskeyChallenge> {
    if challenge.trim().is_empty() {
        return None;
    }
    let cache_key = build_passkey_cache_key(challenge);
    if let Some(raw) = cache_get_redis_only(state, &cache_key).await {
        let _ = state.passkey_challenges.write().await.remove(&cache_key);
        return serde_json::from_str::<PasskeyChallenge>(&raw).ok();
    }

    let mut cache = state.passkey_challenges.write().await;
    let cached = cache.get(&cache_key)?;
    if cached.expires_at <= Utc::now().timestamp() {
        cache.remove(&cache_key);
        return None;
    }
    Some(cached.payload.clone())
}

async fn clear_passkey_challenge(state: &AppState, challenge: &str) {
    if challenge.trim().is_empty() {
        return;
    }
    let cache_key = build_passkey_cache_key(challenge);
    cache_delete(state, &cache_key).await;
    let _ = state.passkey_challenges.write().await.remove(&cache_key);
}

fn parse_transports(raw: Option<&str>) -> Option<Vec<String>> {
    let value = raw?.trim();
    if value.is_empty() {
        return None;
    }
    let parsed: Value = serde_json::from_str(value).ok()?;
    let list = match parsed {
        Value::Array(items) => items,
        _ => return None,
    };
    let transports: Vec<String> = list
        .into_iter()
        .map(|item| match item {
            Value::String(value) => value,
            other => other.to_string(),
        })
        .filter(|item| !item.is_empty())
        .collect();
    if transports.is_empty() {
        None
    } else {
        Some(transports)
    }
}

fn get_expected_origin(headers: &axum::http::HeaderMap, state: &AppState) -> String {
    if let Some(origin) = state
        .env
        .passkey_origin
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        return origin.trim_end_matches('/').to_string();
    }

    let host = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .unwrap_or("http");
    let origin = if host.is_empty() {
        format!("{proto}://localhost")
    } else {
        format!("{proto}://{host}")
    };
    origin.trim_end_matches('/').to_string()
}

fn get_rp_id(headers: &axum::http::HeaderMap, state: &AppState) -> String {
    if let Some(rp_id) = state
        .env
        .passkey_rp_id
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        return rp_id.to_string();
    }

    let host = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("localhost");
    let host = host.split(',').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host).trim();
    if host.is_empty() {
        "localhost".to_string()
    } else {
        host.to_string()
    }
}

fn normalize_username_candidate(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut output = String::new();
    let mut last_was_underscore = false;
    for ch in trimmed.chars() {
        if ch.is_whitespace() {
            if !last_was_underscore && !output.is_empty() {
                output.push('_');
                last_was_underscore = true;
            }
        } else {
            output.push(ch);
            last_was_underscore = false;
        }
    }
    output
}

async fn generate_unique_username(
    state: &AppState,
    candidates: &[String],
    fallback_seed: &str,
) -> String {
    let mut seen = HashSet::new();
    for candidate in candidates {
        let normalized = normalize_username_candidate(candidate);
        if normalized.is_empty() || seen.contains(&normalized) {
            continue;
        }
        seen.insert(normalized.clone());
        if get_user_by_username(state, &normalized)
            .await
            .ok()
            .flatten()
            .is_none()
        {
            return normalized;
        }
    }

    let base = {
        let normalized = normalize_username_candidate(fallback_seed);
        if normalized.is_empty() {
            "user".to_string()
        } else {
            normalized
        }
    };
    for _ in 0..6 {
        let next = format!("{}_{}", base, random_string(4));
        if get_user_by_username(state, &next)
            .await
            .ok()
            .flatten()
            .is_none()
        {
            return next;
        }
    }

    format!("{}_{}", base, random_string(6))
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

async fn send_oauth_welcome_email(
    state: &AppState,
    provider_label: &str,
    email: &str,
    password: &str,
) -> bool {
    if !is_email_configured(state) {
        return false;
    }
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
        .unwrap_or_default()
        .trim()
        .to_string();
    let subject = format!("{} 账户已创建", site_name);
    let safe_site_url = if site_url.is_empty() {
        String::new()
    } else {
        escape_html(&site_url)
    };
    let html = format!(
        r#"
      <p>您好，</p>
      <p>您已使用 {provider} 账号成功创建 {site} 账户。</p>
      <p>我们为您生成了一组初始密码，请妥善保管：</p>
      <pre style="padding:12px;background:#f4f4f5;border-radius:6px;">{password}</pre>
      <p>建议您登录后尽快在个人资料页面修改密码。</p>
      {site_link}
      <p>祝您使用愉快！</p>
    "#,
        provider = escape_html(provider_label),
        site = escape_html(&site_name),
        password = escape_html(password),
        site_link = if safe_site_url.is_empty() {
            "".to_string()
        } else {
            format!(
                r#"<p>立即访问：<a href="{url}" target="_blank" rel="noopener">{url}</a></p>"#,
                url = safe_site_url
            )
        }
    );

    let mut text_lines = vec![
        "您好，".to_string(),
        format!(
            "您已使用 {} 账号成功创建 {} 账户。",
            provider_label, site_name
        ),
        "我们为您生成了一组初始密码，请妥善保管：".to_string(),
        password.to_string(),
        "建议您登录后尽快在个人资料页面修改密码。".to_string(),
    ];
    if !site_url.is_empty() {
        text_lines.push(format!("立即访问：{}", site_url));
    }
    text_lines.push("祝您使用愉快！".to_string());
    let text = text_lines.join("\n");

    let email_service = EmailService::new(&state.env);
    match email_service
        .send_mail(email, &subject, &text, Some(&html))
        .await
    {
        Ok(()) => true,
        Err(message) => {
            println!("[oauth] welcome email send failed: {}", message);
            false
        }
    }
}

async fn fetch_google_token_info(id_token: &str) -> Result<Value, String> {
    let client = reqwest::Client::new();
    let resp = client
        .get("https://oauth2.googleapis.com/tokeninfo")
        .query(&[("id_token", id_token)])
        .send()
        .await
        .map_err(|_| "Google token 校验失败".to_string())?;
    if !resp.status().is_success() {
        return Err("Google token 校验失败".to_string());
    }
    resp.json::<Value>()
        .await
        .map_err(|_| "Google token 校验失败".to_string())
}

async fn exchange_github_token(
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<String, String> {
    let mut params = vec![
        ("client_id", client_id.to_string()),
        ("client_secret", client_secret.to_string()),
        ("code", code.to_string()),
    ];
    if !redirect_uri.trim().is_empty() {
        params.push(("redirect_uri", redirect_uri.to_string()));
    }

    let resp = reqwest::Client::new()
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&params)
        .send()
        .await
        .map_err(|_| "GitHub token 交换失败".to_string())?;
    if !resp.status().is_success() {
        return Err("GitHub token 交换失败".to_string());
    }
    let payload = resp
        .json::<Value>()
        .await
        .map_err(|_| "GitHub token 交换失败".to_string())?;
    let access_token = payload
        .get("access_token")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if access_token.is_empty() {
        return Err("缺少 access_token".to_string());
    }
    Ok(access_token)
}

async fn fetch_github_user(access_token: &str) -> Result<Value, String> {
    let resp = reqwest::Client::new()
        .get("https://api.github.com/user")
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", format!("Bearer {access_token}"))
        .header("User-Agent", "soga-panel-server")
        .send()
        .await
        .map_err(|_| "获取 GitHub 用户信息失败".to_string())?;
    if !resp.status().is_success() {
        return Err("获取 GitHub 用户信息失败".to_string());
    }
    resp.json::<Value>()
        .await
        .map_err(|_| "获取 GitHub 用户信息失败".to_string())
}

async fn fetch_github_email(access_token: &str) -> Result<String, String> {
    let resp = reqwest::Client::new()
        .get("https://api.github.com/user/emails")
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", format!("Bearer {access_token}"))
        .header("User-Agent", "soga-panel-server")
        .send()
        .await
        .map_err(|_| "获取 GitHub 邮箱失败".to_string())?;
    if !resp.status().is_success() {
        return Err("获取 GitHub 邮箱失败".to_string());
    }
    let payload = resp
        .json::<Value>()
        .await
        .map_err(|_| "获取 GitHub 邮箱失败".to_string())?;
    let list = payload.as_array().cloned().unwrap_or_default();
    let mut first: Option<String> = None;
    let mut verified_email: Option<String> = None;
    for item in &list {
        let email = item
            .get("email")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if email.is_empty() {
            continue;
        }
        let primary = item
            .get("primary")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let verified = item
            .get("verified")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if first.is_none() {
            first = Some(email.clone());
        }
        if primary && verified {
            return Ok(email);
        }
        if verified && verified_email.is_none() {
            verified_email = Some(email);
        }
    }
    Ok(verified_email.or(first).unwrap_or_default())
}

async fn get_user_by_identifier(
    state: &AppState,
    identifier_field: &str,
    identifier: &str,
) -> Result<Option<UserRow>, String> {
    let query = match identifier_field {
        "google_sub" => {
            r#"
      SELECT id, email, username, is_admin, status, password_hash,
             two_factor_enabled, two_factor_secret, two_factor_backup_codes,
             google_sub, github_id
      FROM users WHERE google_sub = ?
      "#
        }
        "github_id" => {
            r#"
      SELECT id, email, username, is_admin, status, password_hash,
             two_factor_enabled, two_factor_secret, two_factor_backup_codes,
             google_sub, github_id
      FROM users WHERE github_id = ?
      "#
        }
        _ => return Err("不支持的 OAuth 标识".to_string()),
    };
    let row = sqlx::query(query)
        .bind(identifier)
        .fetch_optional(&state.db)
        .await
        .map_err(|err| err.to_string())?;
    Ok(row.map(|r| UserRow::from_row(&r)))
}

async fn get_oauth_user_by_email(state: &AppState, email: &str) -> Result<Option<UserRow>, String> {
    get_user_by_email(state, email).await
}

async fn get_oauth_user_by_id(state: &AppState, user_id: i64) -> Result<Option<UserRow>, String> {
    get_user_by_id(state, user_id).await
}

async fn update_oauth_binding(
    state: &AppState,
    identifier_field: &str,
    provider_id: &str,
    provider: &str,
    user_id: i64,
) -> Result<(), String> {
    let column = match identifier_field {
        "google_sub" => "google_sub",
        "github_id" => "github_id",
        _ => return Err("不支持的 OAuth 标识".to_string()),
    };
    sqlx::query(&format!(
        r#"
      UPDATE users
      SET {column} = ?,
          oauth_provider = ?,
          first_oauth_login_at = COALESCE(first_oauth_login_at, CURRENT_TIMESTAMP),
          last_oauth_login_at = CURRENT_TIMESTAMP,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
      "#,
        column = column
    ))
    .bind(provider_id)
    .bind(provider)
    .bind(user_id)
    .execute(&state.db)
    .await
    .map_err(|err| err.to_string())?;
    Ok(())
}

fn tail_suffix(value: &str, len: usize) -> String {
    if len == 0 {
        return String::new();
    }
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= len {
        return value.to_string();
    }
    chars[chars.len() - len..].iter().collect()
}

async fn create_two_factor_challenge(state: &AppState, user_id: i64, remember: bool) -> String {
    let challenge_id = random_string(32);
    let payload = json!({
      "userId": user_id,
      "remember": remember,
      "loginMethod": "password"
    });
    cache_set_redis_only(
        state,
        &format!("2fa_challenge_{challenge_id}"),
        &payload.to_string(),
        TWO_FACTOR_TTL,
    )
    .await;
    challenge_id
}

async fn update_login_info(state: &AppState, user_id: i64, ip: Option<String>) {
    let _ = sqlx::query(
        r#"
    UPDATE users
    SET last_login_time = CURRENT_TIMESTAMP,
        last_login_ip = COALESCE(?, last_login_ip),
        updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
    "#,
    )
    .bind(ip)
    .bind(user_id)
    .execute(&state.db)
    .await;
}

async fn insert_login_log(
    state: &AppState,
    user_id: i64,
    ip: Option<String>,
    user_agent: String,
    login_method: String,
) {
    let ip_value = ip.unwrap_or_default();
    let result = sqlx::query(
    r#"
    INSERT INTO login_logs (user_id, login_ip, login_time, user_agent, login_status, failure_reason, login_method, created_at)
    VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    "#
  )
  .bind(user_id)
  .bind(&ip_value)
  .bind(&user_agent)
  .bind(1)
  .bind::<Option<String>>(None)
  .bind(&login_method)
  .execute(&state.db)
  .await;

    if result.is_ok() {
        return;
    }

    let err = result.err().unwrap();
    if !should_fallback_login_log(&err) {
        tracing::warn!("[login] insert login log failed: {err}");
        return;
    }

    let result = sqlx::query(
    r#"
    INSERT INTO login_logs (user_id, login_ip, user_agent, login_status, failure_reason, login_method)
    VALUES (?, ?, ?, ?, ?, ?)
    "#
  )
  .bind(user_id)
  .bind(&ip_value)
  .bind(&user_agent)
  .bind(1)
  .bind::<Option<String>>(None)
  .bind(&login_method)
  .execute(&state.db)
  .await;

    if result.is_ok() {
        return;
    }

    let err = result.err().unwrap();
    if !should_fallback_login_log(&err) {
        tracing::warn!("[login] insert login log failed: {err}");
        return;
    }

    if let Err(err) = sqlx::query(
        r#"
    INSERT INTO login_logs (user_id, login_ip, user_agent, login_status, failure_reason)
    VALUES (?, ?, ?, ?, ?)
    "#,
    )
    .bind(user_id)
    .bind(&ip_value)
    .bind(&user_agent)
    .bind(1)
    .bind::<Option<String>>(None)
    .execute(&state.db)
    .await
    {
        tracing::warn!("[login] insert login log failed: {err}");
    }
}

fn should_fallback_login_log(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db_err) => {
            let code = db_err
                .code()
                .map(|value| value == "1054" || value == "1136")
                .unwrap_or(false);
            if code {
                return true;
            }
            let message = db_err.message();
            message.contains("Unknown column") || message.contains("column count")
        }
        _ => false,
    }
}

fn is_email_configured(state: &AppState) -> bool {
    let provider = state
        .env
        .mail_provider
        .as_deref()
        .unwrap_or("")
        .to_lowercase();
    if provider == "resend" {
        return state
            .env
            .resend_api_key
            .as_ref()
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
            || state
                .env
                .mail_resend_key
                .as_ref()
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false);
    }
    if provider == "smtp" {
        return state
            .env
            .mail_smtp_host
            .as_ref()
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
            || state
                .env
                .smtp_host
                .as_ref()
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false);
    }
    if provider == "sendgrid" {
        return state
            .env
            .sendgrid_api_key
            .as_ref()
            .map(|v| !v.trim().is_empty())
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

async fn handle_verification_code_request(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    body: &Value,
    purpose: &str,
    require_existing_user: bool,
    disallow_existing_user: bool,
) -> Response {
    let raw_email = body.get("email").and_then(Value::as_str).unwrap_or("");
    let email = raw_email.trim().to_lowercase();

    if email.is_empty() {
        return error(StatusCode::BAD_REQUEST, "请填写邮箱地址", None);
    }
    if !is_valid_email(&email) {
        return error(StatusCode::BAD_REQUEST, "请输入有效的邮箱地址", None);
    }
    if purpose == "register" && is_gmail_alias(&email) {
        return error(
            StatusCode::BAD_REQUEST,
            "暂不支持使用 Gmail 别名注册，请使用不含点和加号的原始邮箱地址",
            None,
        );
    }

    let flags = match resolve_verification_flags(state).await {
        Ok(value) => value,
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    };

    let verification_enabled = if purpose == "register" {
        flags.register_enabled && flags.email_verify_enabled && flags.email_provider_enabled
    } else {
        flags.email_verify_enabled && flags.email_provider_enabled
    };

    if !verification_enabled {
        let message = if purpose == "password_reset" {
            "当前未开启密码重置功能"
        } else {
            "当前未开启邮箱验证码功能"
        };
        return error(StatusCode::FORBIDDEN, message, None);
    }

    if purpose == "register" && flags.register_mode != "1" {
        return error(StatusCode::FORBIDDEN, "系统暂时关闭注册功能", None);
    }

    let existing_user = match get_user_by_email(state, &email).await {
        Ok(value) => value,
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
    };

    if require_existing_user && existing_user.is_none() {
        let message = if purpose == "password_reset" {
            "该邮箱未注册账户，请检查邮箱是否正确"
        } else {
            "该邮箱地址不存在，请先注册账号"
        };
        return error(StatusCode::BAD_REQUEST, message, None);
    }
    if disallow_existing_user && existing_user.is_some() {
        let message = if purpose == "register" {
            "该邮箱已被注册，请使用其他邮箱或直接登录"
        } else {
            "该邮箱已被注册"
        };
        return error(StatusCode::CONFLICT, message, None);
    }

    let _ = sqlx::query(
        r#"
    UPDATE email_verification_codes
    SET used_at = CURRENT_TIMESTAMP
    WHERE email = ? AND purpose = ? AND used_at IS NULL
    "#,
    )
    .bind(&email)
    .bind(purpose)
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
          AND purpose = ?
          AND created_at > DATE_SUB(CURRENT_TIMESTAMP, INTERVAL {} SECOND)
        "#,
            cooldown_seconds
        ))
        .bind(&email)
        .bind(purpose)
        .fetch_optional(&state.db)
        .await;
        if let Ok(Some(row)) = row {
            let count = row.try_get::<i64, _>("count").unwrap_or(0);
            if count > 0 {
                return error(
                    StatusCode::TOO_MANY_REQUESTS,
                    &format!("验证码发送频繁，请在 {} 秒后重试", cooldown_seconds),
                    None,
                );
            }
        }
    }

    if daily_limit > 0 {
        let row = sqlx::query(
            r#"
      SELECT COUNT(*) as count
      FROM email_verification_codes
      WHERE email = ?
        AND purpose = ?
        AND created_at > DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 1 DAY)
      "#,
        )
        .bind(&email)
        .bind(purpose)
        .fetch_optional(&state.db)
        .await;
        if let Ok(Some(row)) = row {
            let count = row.try_get::<i64, _>("count").unwrap_or(0);
            if count >= daily_limit {
                return error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "今日验证码发送次数已达上限，请24小时后再试",
                    None,
                );
            }
        }
    }

    if ip_hourly_limit > 0 && client_ip != "unknown" {
        let row = sqlx::query(
            r#"
      SELECT COUNT(*) as count
      FROM email_verification_codes
      WHERE request_ip = ?
        AND purpose = ?
        AND created_at > DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 1 HOUR)
      "#,
        )
        .bind(&client_ip)
        .bind(purpose)
        .fetch_optional(&state.db)
        .await;
        if let Ok(Some(row)) = row {
            let count = row.try_get::<i64, _>("count").unwrap_or(0);
            if count >= ip_hourly_limit {
                return error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "请求过于频繁，请稍后再试或更换网络",
                    None,
                );
            }
        }
    }

    let (code, expires_at) =
        match send_email_code(state, &email, purpose, &client_ip, &user_agent).await {
            Ok(value) => value,
            Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, &message, None),
        };

    let log_prefix = if purpose == "password_reset" {
        "password-reset"
    } else {
        "email-code"
    };
    println!(
        "[{}] purpose={} email={} code={}",
        log_prefix, purpose, email, code
    );
    success(
        json!({ "expires_at": expires_at }),
        "验证码已发送，请查收邮箱",
    )
    .into_response()
}

async fn send_email_code(
    state: &AppState,
    email: &str,
    purpose: &str,
    ip: &str,
    ua: &str,
) -> Result<(String, String), String> {
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
    "#
  )
  .bind(email)
  .bind(purpose)
  .bind(&hash)
  .bind(&expires_db)
  .bind(ip)
  .bind(ua)
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

    Ok((code, expires.to_rfc3339()))
}

async fn verify_email_code(
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
    if trimmed.len() != 6 || !trimmed.chars().all(|c| c.is_ascii_digit()) {
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
        Some(row) => row,
        None => return Err("验证码不存在或已过期".to_string()),
    };

    let id = row.try_get::<i64, _>("id").unwrap_or(0);
    let code_hash: String = row.try_get::<String, _>("code_hash").unwrap_or_default();
    let attempts = row.try_get::<i64, _>("attempts").unwrap_or(0);
    let hash = sha256_hex(trimmed);

    if hash != code_hash {
        let next_attempts = attempts + 1;
        let reach_limit = attempt_limit > 0 && next_attempts >= attempt_limit;
        let _ = sqlx::query(&format!(
            "UPDATE email_verification_codes SET attempts = ?, used_at = {} WHERE id = ?",
            if reach_limit {
                "CURRENT_TIMESTAMP"
            } else {
                "used_at"
            }
        ))
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

async fn reset_password_with_code(
    state: &AppState,
    email: &str,
    code: &str,
    new_password: &str,
) -> Result<bool, String> {
    verify_email_code(
        state,
        email,
        "password_reset",
        code,
        get_verification_attempt_limit(state),
    )
    .await?;

    let user = get_user_by_email(state, email).await?;
    let user = match user {
        Some(user) => user,
        None => return Err("用户不存在".to_string()),
    };

    let hash = hash_password(new_password);
    sqlx::query("UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(hash)
        .bind(user.id)
        .execute(&state.db)
        .await
        .map_err(|err| err.to_string())?;

    Ok(true)
}

async fn register_user(
    state: &AppState,
    email: &str,
    username: &str,
    password: &str,
    register_ip: Option<String>,
    invited_by: Option<i64>,
) -> Result<i64, String> {
    if let Some(_) = get_user_by_email(state, email).await? {
        return Err("邮箱已被注册".to_string());
    }
    if let Some(_) = get_user_by_username(state, username).await? {
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
    "#
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

fn get_verification_attempt_limit(state: &AppState) -> i64 {
    state
        .env
        .mail_verification_attempt_limit
        .as_ref()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(5)
}

async fn resolve_verification_flags(state: &AppState) -> Result<VerificationFlags, String> {
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

    Ok(VerificationFlags {
        configs,
        register_mode,
        register_enabled,
        email_verify_enabled,
        email_provider_enabled,
    })
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

fn verify_telegram_init_data(init_data: &str, bot_token: &str) -> Result<i64, String> {
    let normalized = init_data
        .trim()
        .trim_start_matches('?')
        .trim_start_matches('#');
    if normalized.is_empty() {
        return Err("缺少 Telegram initData".to_string());
    }

    let parsed: Vec<(String, String)> = serde_urlencoded::from_str(normalized)
        .map_err(|_| "Telegram initData 格式无效".to_string())?;
    if parsed.is_empty() {
        return Err("Telegram initData 为空".to_string());
    }

    let mut hash = String::new();
    let mut auth_date: i64 = 0;
    let mut user_raw = String::new();
    let mut receiver_raw = String::new();
    let mut data_check_parts: Vec<String> = Vec::new();
    for (key, value) in parsed {
        if key == "hash" {
            hash = value.to_lowercase();
            continue;
        }
        if key == "auth_date" {
            auth_date = value.parse::<i64>().unwrap_or(0);
        }
        if key == "user" {
            user_raw = value.clone();
        }
        if key == "receiver" {
            receiver_raw = value.clone();
        }
        data_check_parts.push(format!("{key}={value}"));
    }

    if hash.len() != 64 || !hash.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("Telegram hash 参数无效".to_string());
    }
    if auth_date <= 0 {
        return Err("Telegram auth_date 参数无效".to_string());
    }
    let now = Utc::now().timestamp();
    if (now - auth_date).abs() > TELEGRAM_INIT_DATA_MAX_AGE_SECONDS {
        return Err("Telegram 授权数据已过期，请重新打开 Mini App".to_string());
    }
    let user_payload = if user_raw.trim().is_empty() {
        receiver_raw
    } else {
        user_raw
    };
    if user_payload.trim().is_empty() {
        return Err("Telegram user 参数无效".to_string());
    }

    data_check_parts.sort();
    let data_check_string = data_check_parts.join("\n");

    type HmacSha256 = Hmac<Sha256>;
    let mut secret_mac = <HmacSha256 as Mac>::new_from_slice(b"WebAppData")
        .map_err(|_| "Telegram 签名校验失败".to_string())?;
    secret_mac.update(bot_token.as_bytes());
    let secret_key = secret_mac.finalize().into_bytes();

    let mut check_mac = <HmacSha256 as Mac>::new_from_slice(secret_key.as_slice())
        .map_err(|_| "Telegram 签名校验失败".to_string())?;
    check_mac.update(data_check_string.as_bytes());
    let expected_hash = hex::encode(check_mac.finalize().into_bytes());
    if !timing_safe_eq(&hash, &expected_hash) {
        return Err("Telegram 签名校验失败".to_string());
    }

    let user_json: Value =
        serde_json::from_str(&user_payload).map_err(|_| "Telegram user 参数无效".to_string())?;
    let user_id = user_json
        .get("id")
        .and_then(Value::as_i64)
        .or_else(|| {
            user_json
                .get("id")
                .and_then(Value::as_u64)
                .and_then(|value| i64::try_from(value).ok())
        })
        .or_else(|| {
            user_json
                .get("id")
                .and_then(Value::as_str)
                .and_then(|value| value.trim().parse::<i64>().ok())
        })
        .unwrap_or(0);
    if user_id <= 0 {
        return Err("Telegram user 参数无效".to_string());
    }

    Ok(user_id)
}

fn timing_safe_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (a, b) in left.bytes().zip(right.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
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

pub(super) fn encrypt_two_factor_secret(state: &AppState, secret: &str) -> Result<String, String> {
    let key = two_factor_key(state);
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce = Nonce::from_slice(&iv);
    let mut encrypted = cipher
        .encrypt(nonce, secret.as_bytes())
        .map_err(|_| "2FA 配置异常，请联系管理员".to_string())?;

    if encrypted.len() < 16 {
        return Err("2FA 配置异常，请联系管理员".to_string());
    }

    let tag = encrypted.split_off(encrypted.len() - 16);
    let mut output = Vec::with_capacity(iv.len() + tag.len() + encrypted.len());
    output.extend_from_slice(&iv);
    output.extend_from_slice(&tag);
    output.extend_from_slice(&encrypted);
    Ok(base64::engine::general_purpose::STANDARD.encode(output))
}

pub(super) fn decrypt_two_factor_secret(
    state: &AppState,
    encrypted: Option<&str>,
) -> Result<String, String> {
    let encrypted = encrypted.unwrap_or("");
    if encrypted.is_empty() {
        return Err("2FA 配置异常，请联系管理员".to_string());
    }

    let key = two_factor_key(state);
    let data = base64::engine::general_purpose::STANDARD
        .decode(encrypted.as_bytes())
        .map_err(|_| "2FA 配置异常，请联系管理员".to_string())?;
    if data.len() < 28 {
        return Err("2FA 配置异常，请联系管理员".to_string());
    }

    let iv = &data[0..12];
    let tag = &data[12..28];
    let cipher_text = &data[28..];
    let mut combined = Vec::with_capacity(cipher_text.len() + tag.len());
    combined.extend_from_slice(cipher_text);
    combined.extend_from_slice(tag);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce = Nonce::from_slice(iv);
    let decrypted = cipher
        .decrypt(nonce, combined.as_ref())
        .map_err(|_| "2FA 配置异常，请联系管理员".to_string())?;
    String::from_utf8(decrypted).map_err(|_| "2FA 配置异常，请联系管理员".to_string())
}

fn two_factor_key(state: &AppState) -> Vec<u8> {
    let env_key = state
        .env
        .two_factor_secret_key
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_string();
    let secret = if !env_key.is_empty() {
        env_key
    } else {
        let jwt = state
            .env
            .jwt_secret
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_string();
        if !jwt.is_empty() {
            jwt
        } else {
            "default-two-factor-secret".to_string()
        }
    };
    let digest = sha256_hex(&secret);
    hex::decode(digest).unwrap_or_else(|_| vec![0u8; 32])
}

pub(super) fn parse_backup_codes(raw: Option<&str>) -> Vec<String> {
    raw.and_then(|value| serde_json::from_str::<Vec<String>>(value).ok())
        .unwrap_or_default()
}

pub(super) fn normalize_backup_code(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase()
}

async fn update_two_factor_data(
    state: &AppState,
    user_id: i64,
    enabled: i32,
    secret: Option<&str>,
    backup_codes: &[String],
) -> Result<(), String> {
    let payload = if backup_codes.is_empty() {
        Value::Null
    } else {
        json!(backup_codes)
    };
    sqlx::query(
        r#"
    UPDATE users
    SET two_factor_enabled = ?,
        two_factor_secret = ?,
        two_factor_backup_codes = ?,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
    "#,
    )
    .bind(enabled)
    .bind(secret.unwrap_or(""))
    .bind(payload.to_string())
    .bind(user_id)
    .execute(&state.db)
    .await
    .map_err(|err| err.to_string())?;
    Ok(())
}

pub(super) async fn list_system_configs(
    state: &AppState,
) -> Result<std::collections::HashMap<String, String>, String> {
    let rows = sqlx::query("SELECT `key`, `value` FROM system_configs")
        .fetch_all(&state.db)
        .await
        .map_err(|err| err.to_string())?;
    let mut map = std::collections::HashMap::new();
    for row in rows {
        let key: String = row.try_get("key").unwrap_or_default();
        let value: Option<String> = row.try_get("value").ok();
        map.insert(key, value.unwrap_or_default());
    }
    Ok(map)
}

async fn get_user_by_email(state: &AppState, email: &str) -> Result<Option<UserRow>, String> {
    let row = sqlx::query(
        r#"
    SELECT id, email, username, is_admin, status, password_hash,
           two_factor_enabled, two_factor_secret, two_factor_backup_codes,
           google_sub, github_id
    FROM users WHERE email = ?
    "#,
    )
    .bind(email)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string())?;
    Ok(row.map(|r| UserRow::from_row(&r)))
}

async fn get_user_by_telegram_id(
    state: &AppState,
    telegram_id: &str,
) -> Result<Option<UserRow>, String> {
    let row = sqlx::query(
        r#"
    SELECT id, email, username, is_admin, status, password_hash,
           two_factor_enabled, two_factor_secret, two_factor_backup_codes,
           google_sub, github_id
    FROM users WHERE telegram_id = ?
    LIMIT 1
    "#,
    )
    .bind(telegram_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string())?;
    Ok(row.map(|r| UserRow::from_row(&r)))
}

async fn get_user_by_username(state: &AppState, username: &str) -> Result<Option<UserRow>, String> {
    let row = sqlx::query(
        r#"
    SELECT id, email, username, is_admin, status, password_hash,
           two_factor_enabled, two_factor_secret, two_factor_backup_codes,
           google_sub, github_id
    FROM users WHERE username = ?
    "#,
    )
    .bind(username)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string())?;
    Ok(row.map(|r| UserRow::from_row(&r)))
}

async fn get_user_by_id(state: &AppState, user_id: i64) -> Result<Option<UserRow>, String> {
    let row = sqlx::query(
        r#"
    SELECT id, email, username, is_admin, status, password_hash,
           two_factor_enabled, two_factor_secret, two_factor_backup_codes,
           google_sub, github_id
    FROM users WHERE id = ?
    "#,
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| err.to_string())?;
    Ok(row.map(|r| UserRow::from_row(&r)))
}

#[derive(Clone)]
pub(super) struct PasskeyRow {
    id: i64,
    user_id: i64,
    credential_id: String,
    public_key: String,
    alg: i64,
    user_handle: Option<String>,
    rp_id: Option<String>,
    transports: Option<String>,
    sign_count: i64,
    device_name: Option<String>,
    last_used_at: Option<NaiveDateTime>,
    created_at: Option<NaiveDateTime>,
    updated_at: Option<NaiveDateTime>,
}

impl PasskeyRow {
    fn from_row(row: &sqlx::mysql::MySqlRow) -> Self {
        Self {
            id: row.try_get::<i64, _>("id").unwrap_or(0),
            user_id: row.try_get::<i64, _>("user_id").unwrap_or(0),
            credential_id: row
                .try_get::<String, _>("credential_id")
                .unwrap_or_default(),
            public_key: row.try_get::<String, _>("public_key").unwrap_or_default(),
            alg: row.try_get::<i64, _>("alg").unwrap_or(-7),
            user_handle: row
                .try_get::<Option<String>, _>("user_handle")
                .ok()
                .flatten(),
            rp_id: row.try_get::<Option<String>, _>("rp_id").ok().flatten(),
            transports: row
                .try_get::<Option<String>, _>("transports")
                .ok()
                .flatten(),
            sign_count: row
                .try_get::<Option<i64>, _>("sign_count")
                .unwrap_or(Some(0))
                .unwrap_or(0),
            device_name: row
                .try_get::<Option<String>, _>("device_name")
                .ok()
                .flatten(),
            last_used_at: row
                .try_get::<Option<NaiveDateTime>, _>("last_used_at")
                .ok()
                .flatten(),
            created_at: row
                .try_get::<Option<NaiveDateTime>, _>("created_at")
                .ok()
                .flatten(),
            updated_at: row
                .try_get::<Option<NaiveDateTime>, _>("updated_at")
                .ok()
                .flatten(),
        }
    }

    pub(super) fn to_value(&self) -> Value {
        json!({
          "id": self.id,
          "user_id": self.user_id,
          "credential_id": self.credential_id,
          "public_key": self.public_key,
          "alg": self.alg,
          "user_handle": self.user_handle,
          "rp_id": self.rp_id,
          "transports": self.transports,
          "sign_count": self.sign_count,
          "device_name": self.device_name,
          "last_used_at": format_datetime(self.last_used_at),
          "created_at": format_datetime(self.created_at),
          "updated_at": format_datetime(self.updated_at)
        })
    }
}

struct PasskeyInsert {
    user_id: i64,
    credential_id: String,
    public_key: String,
    alg: i64,
    user_handle: Option<String>,
    rp_id: Option<String>,
    transports: Option<Vec<String>>,
    sign_count: i64,
    device_name: Option<String>,
}

fn format_datetime(value: Option<NaiveDateTime>) -> Option<String> {
    value.map(|dt| dt.format("%Y-%m-%dT%H:%M:%S").to_string())
}

pub(super) async fn list_passkeys(
    state: &AppState,
    user_id: i64,
) -> Result<Vec<PasskeyRow>, String> {
    let rows = sqlx::query("SELECT * FROM passkeys WHERE user_id = ?")
        .bind(user_id)
        .fetch_all(&state.db)
        .await
        .map_err(|err| err.to_string())?;
    Ok(rows.iter().map(PasskeyRow::from_row).collect())
}

async fn get_passkey_by_credential_id(
    state: &AppState,
    credential_id: &str,
) -> Result<Option<PasskeyRow>, String> {
    let row = sqlx::query("SELECT * FROM passkeys WHERE credential_id = ?")
        .bind(credential_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|err| err.to_string())?;
    Ok(row.map(|r| PasskeyRow::from_row(&r)))
}

async fn insert_passkey(state: &AppState, params: PasskeyInsert) -> Result<(), String> {
    let transports = params
        .transports
        .as_ref()
        .and_then(|value| serde_json::to_string(value).ok());
    sqlx::query(
        r#"
    INSERT INTO passkeys (
      user_id, credential_id, public_key, alg, user_handle, rp_id,
      transports, sign_count, device_name, created_at, updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    "#,
    )
    .bind(params.user_id)
    .bind(params.credential_id)
    .bind(params.public_key)
    .bind(params.alg)
    .bind(params.user_handle)
    .bind(params.rp_id)
    .bind(transports)
    .bind(params.sign_count)
    .bind(params.device_name)
    .execute(&state.db)
    .await
    .map_err(|err| err.to_string())?;
    Ok(())
}

async fn update_passkey_usage(
    state: &AppState,
    credential_id: &str,
    sign_count: i64,
) -> Result<(), String> {
    sqlx::query(
        r#"
    UPDATE passkeys
    SET sign_count = COALESCE(?, sign_count),
        last_used_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
    WHERE credential_id = ?
    "#,
    )
    .bind(sign_count)
    .bind(credential_id)
    .execute(&state.db)
    .await
    .map_err(|err| err.to_string())?;
    Ok(())
}

#[derive(Deserialize)]
struct TurnstileResponse {
    success: bool,
}

enum TurnstileError {
    RequestFailed,
    InvalidResponse,
}

async fn verify_turnstile(
    secret: &str,
    token: &str,
    ip: Option<String>,
) -> Result<bool, TurnstileError> {
    let client = reqwest::Client::new();
    let mut params = vec![
        ("secret", secret.to_string()),
        ("response", token.to_string()),
    ];
    if let Some(value) = ip {
        if !value.trim().is_empty() {
            params.push(("remoteip", value));
        }
    }

    let resp = client
        .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .form(&params)
        .send()
        .await
        .map_err(|_| TurnstileError::InvalidResponse)?;

    if !resp.status().is_success() {
        return Err(TurnstileError::RequestFailed);
    }

    let result = resp
        .json::<TurnstileResponse>()
        .await
        .map_err(|_| TurnstileError::InvalidResponse)?;

    Ok(result.success)
}

fn parse_auth_header(headers: &axum::http::HeaderMap) -> Option<String> {
    let header = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())?;
    let parts: Vec<&str> = header.split_whitespace().collect();
    if parts.len() == 2 && parts[0].eq_ignore_ascii_case("bearer") {
        return Some(parts[1].to_string());
    }
    None
}

async fn require_user(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    token_override: Option<String>,
) -> Result<UserRow, Response> {
    let token = token_override
        .and_then(|value| {
            let trimmed = value.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
        .or_else(|| parse_auth_header(headers));

    let token = match token {
        Some(value) => value,
        None => return Err(error(StatusCode::UNAUTHORIZED, "未登录", None)),
    };

    let session = cache_get(state, &format!("session_{token}")).await;
    let session = match session {
        Some(value) => value,
        None => return Err(error(StatusCode::UNAUTHORIZED, "登录已过期", None)),
    };

    let payload: SessionPayload = match serde_json::from_str(&session) {
        Ok(value) => value,
        Err(_) => return Err(error(StatusCode::UNAUTHORIZED, "会话无效", None)),
    };

    let user = match get_user_by_id(state, payload.id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            cache_delete(state, &format!("session_{token}")).await;
            return Err(error(StatusCode::UNAUTHORIZED, "账户已禁用或不存在", None));
        }
        Err(message) => return Err(error(StatusCode::INTERNAL_SERVER_ERROR, &message, None)),
    };

    if user.status != 1 {
        cache_delete(state, &format!("session_{token}")).await;
        return Err(error(StatusCode::UNAUTHORIZED, "账户已禁用或不存在", None));
    }

    Ok(user)
}

pub(super) async fn require_user_id(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    token_override: Option<String>,
) -> Result<i64, Response> {
    require_user(state, headers, token_override)
        .await
        .map(|user| user.id)
}

pub(super) async fn require_admin_user_id(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    token_override: Option<String>,
) -> Result<i64, Response> {
    let user = require_user(state, headers, token_override).await?;
    if user.is_admin != 1 {
        return Err(error(StatusCode::FORBIDDEN, "需要管理员权限", None));
    }
    Ok(user.id)
}

fn get_client_ip(headers: &axum::http::HeaderMap) -> Option<String> {
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

struct UserRow {
    id: i64,
    email: String,
    username: String,
    is_admin: i64,
    status: i64,
    password_hash: String,
    two_factor_enabled: i64,
    two_factor_secret: Option<String>,
    two_factor_backup_codes: Option<String>,
    google_sub: Option<String>,
    github_id: Option<String>,
}

impl UserRow {
    fn from_row(row: &sqlx::mysql::MySqlRow) -> Self {
        Self {
            id: row.try_get::<i64, _>("id").unwrap_or(0),
            email: row.try_get::<String, _>("email").unwrap_or_default(),
            username: row.try_get::<String, _>("username").unwrap_or_default(),
            is_admin: row
                .try_get::<Option<i64>, _>("is_admin")
                .unwrap_or(Some(0))
                .unwrap_or(0),
            status: row
                .try_get::<Option<i64>, _>("status")
                .unwrap_or(Some(0))
                .unwrap_or(0),
            password_hash: row
                .try_get::<String, _>("password_hash")
                .unwrap_or_default(),
            two_factor_enabled: row
                .try_get::<Option<i64>, _>("two_factor_enabled")
                .unwrap_or(Some(0))
                .unwrap_or(0),
            two_factor_secret: row
                .try_get::<Option<String>, _>("two_factor_secret")
                .ok()
                .flatten(),
            two_factor_backup_codes: row
                .try_get::<Option<String>, _>("two_factor_backup_codes")
                .ok()
                .flatten(),
            google_sub: row
                .try_get::<Option<String>, _>("google_sub")
                .ok()
                .flatten(),
            github_id: row.try_get::<Option<String>, _>("github_id").ok().flatten(),
        }
    }
}
