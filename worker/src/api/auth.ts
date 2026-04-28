// src/api/auth.js - 认证 API

import type { D1Database } from "@cloudflare/workers-types";
import type { Env } from "../types";
import { DatabaseService } from "../services/database";
import { CacheService } from "../services/cache";
import { successResponse, errorResponse } from "../utils/response";
import {
  generateToken,
  hashPassword,
  verifyPassword,
  generateUUID,
  generateRandomString,
  generateBase64Random,
  generateNumericCode,
  sha256Hex,
} from "../utils/crypto";
import {
  AuthenticationCredential,
  RegistrationCredential,
  base64UrlDecode,
  base64UrlEncode,
  randomChallenge,
  validateAuthenticationResponse,
  validateRegistrationResponse,
} from "../utils/passkey";
import { validateUserAuth } from "../middleware/auth";
import { EmailService } from "../services/email";
import {
  createSystemConfigManager,
  SystemConfigManager,
} from "../utils/systemConfig";
import { getLogger, Logger } from "../utils/logger";
import {
  defaultRegisterEmailSubject,
  defaultRegisterEmailTemplate,
  defaultPasswordResetEmailSubject,
  defaultPasswordResetEmailTemplate,
} from "./email/templates";
import {
  ensureNumber,
  ensureString,
  toRunResult,
  getChanges,
  getLastRowId,
} from "../utils/d1";
import { TwoFactorService } from "../services/twoFactor";
import { ReferralService } from "../services/referralService";

const GOOGLE_TOKENINFO_ENDPOINT = "https://oauth2.googleapis.com/tokeninfo";

type GoogleTokenInfo = {
  aud: string;
  sub: string;
  email?: string;
  email_verified?: string;
  iss?: string;
  name?: string;
  given_name?: string;
  picture?: string;
};

interface GithubTokenResponse {
  access_token?: string;
  token_type?: string;
  scope?: string;
  error?: string;
  error_description?: string;
}

interface GithubUserResponse {
  id?: number;
  email?: string;
  name?: string;
  login?: string;
  [key: string]: unknown;
}

interface GithubEmailEntry {
  email?: string;
  primary?: boolean;
  verified?: boolean;
  [key: string]: unknown;
}

type TwoFactorChallengePayload = {
  userId: number;
  remember: boolean;
  loginMethod: string;
  clientIP: string;
  userAgent: string;
  issuedAt: number;
  meta?: Record<string, unknown> | null;
};

type PasskeyChallengePayload = {
  type: "registration" | "authentication";
  userId: number;
  challenge: string;
  rpId: string;
  origin: string;
  remember?: boolean;
  createdAt: number;
};

type PendingOAuthRegistration = {
  provider: "google" | "github";
  email: string;
  providerId: string;
  usernameCandidates: string[];
  fallbackUsernameSeed: string;
  remember: boolean;
  clientIP: string;
  userAgent: string;
};

type TelegramMiniAppUser = {
  id: number;
  username?: string;
  first_name?: string;
  last_name?: string;
};

const EMAIL_REGEX =
  /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

const PURPOSE_REGISTER = "register";
const PURPOSE_PASSWORD_RESET = "password_reset";

const TWO_FACTOR_CHALLENGE_TTL = 300;
const TRUSTED_DEVICE_TTL_DAYS = 30;
const PASSKEY_CHALLENGE_TTL = 300;
const TELEGRAM_INIT_DATA_MAX_AGE_SECONDS = 86400;

interface AuthUserRow {
  id: number;
  email: string;
  password_hash: string;
  is_admin: number;
  expire_time?: string | null;
  status?: number | null;
  google_sub?: string | null;
  github_id?: string | null;
  username?: string | null;
  two_factor_enabled?: number;
  two_factor_secret?: string | null;
  two_factor_backup_codes?: string | null;
  two_factor_temp_secret?: string | null;
  [key: string]: unknown;
}

interface ConfigRow {
  key: string;
  value: string;
}

interface UserEmailUsernameRow {
  email?: string;
  username?: string;
}

type GetIntOptions = {
  allowZero?: boolean;
  min?: number;
};

export class AuthAPI {
  db: DatabaseService;
  cache: CacheService;
  env: Env;
  emailService: EmailService;
  configManager: SystemConfigManager;
  logger: Logger;
  private readonly dbRaw: D1Database;
  private readonly twoFactorService: TwoFactorService;
  private readonly referralService: ReferralService;

  constructor(env: Env) {
    this.dbRaw = env.DB as D1Database;
    this.db = new DatabaseService(this.dbRaw);
    this.cache = new CacheService(this.dbRaw);
    this.env = env;
    this.emailService = new EmailService(env);
    this.configManager = createSystemConfigManager(env);
    this.logger = getLogger(env);
    this.twoFactorService = new TwoFactorService(env);
    this.referralService = new ReferralService(this.db, this.configManager, this.logger);
  }

  getIntConfig(value: unknown, fallback: number, options: GetIntOptions = {}) {
    const { allowZero = false, min = 1 } = options;
    const raw =
      typeof value === "number"
        ? value
        : typeof value === "string"
        ? Number.parseInt(value, 10)
        : Number.NaN;
    if (!Number.isFinite(raw)) return fallback;
    const num = raw;
    if (allowZero && num === 0) return 0;
    if (num < min) return fallback;
    return num;
  }

  parseNumber(value, defaultValue = 0) {
    if (value === null || value === undefined) return defaultValue;
    if (typeof value === "number") return value;
    const num = Number(value);
    return Number.isFinite(num) ? num : defaultValue;
  }

  parseBoolean(value, defaultValue = false) {
    if (typeof value === "boolean") return value;
    if (typeof value === "number") return value !== 0;
    if (typeof value === "string") {
      const normalized = value.trim().toLowerCase();
      if (["true", "1", "yes", "y", "on"].includes(normalized)) {
        return true;
      }
      if (["false", "0", "no", "n", "off"].includes(normalized)) {
        return false;
      }
    }
    return defaultValue;
  }

  private bytesToHex(bytes: Uint8Array) {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  private timingSafeEqual(a: string, b: string) {
    if (a.length !== b.length) {
      return false;
    }
    let diff = 0;
    for (let i = 0; i < a.length; i += 1) {
      diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return diff === 0;
  }

  private async hmacSha256(
    key: string | Uint8Array,
    data: string
  ): Promise<Uint8Array> {
    const encoder = new TextEncoder();
    const keyData = typeof key === "string" ? encoder.encode(key) : key;
    const normalizedKey = new Uint8Array(keyData.byteLength);
    normalizedKey.set(keyData);
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      normalizedKey,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const signature = await crypto.subtle.sign(
      "HMAC",
      cryptoKey,
      encoder.encode(data)
    );
    return new Uint8Array(signature);
  }

  private parseTelegramMiniAppUser(rawUser: string): TelegramMiniAppUser | null {
    if (!rawUser) {
      return null;
    }

    try {
      const parsed = JSON.parse(rawUser) as Record<string, unknown>;
      const idRaw = parsed?.id;
      const id =
        typeof idRaw === "number"
          ? Math.trunc(idRaw)
          : Number.parseInt(String(idRaw ?? ""), 10);
      if (!Number.isSafeInteger(id) || id <= 0) {
        return null;
      }

      const user: TelegramMiniAppUser = { id };
      if (typeof parsed.username === "string") {
        user.username = parsed.username;
      }
      if (typeof parsed.first_name === "string") {
        user.first_name = parsed.first_name;
      }
      if (typeof parsed.last_name === "string") {
        user.last_name = parsed.last_name;
      }
      return user;
    } catch {
      return null;
    }
  }

  private async verifyTelegramInitData(rawInitData: string, botToken: string) {
    const initData = rawInitData.trim().replace(/^[?#]/, "");
    if (!initData) {
      return { ok: false, reason: "缺少 Telegram initData" };
    }

    const params = new URLSearchParams(initData);
    const hash = ensureString(params.get("hash"), "").trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(hash)) {
      return { ok: false, reason: "Telegram hash 参数无效" };
    }

    const authDate = Number.parseInt(
      ensureString(params.get("auth_date"), "").trim(),
      10
    );
    if (!Number.isFinite(authDate) || authDate <= 0) {
      return { ok: false, reason: "Telegram auth_date 参数无效" };
    }

    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - authDate) > TELEGRAM_INIT_DATA_MAX_AGE_SECONDS) {
      return { ok: false, reason: "Telegram 授权数据已过期，请重新打开 Mini App" };
    }

    const telegramUser = this.parseTelegramMiniAppUser(
      ensureString(params.get("user"), "")
    );
    if (!telegramUser) {
      return { ok: false, reason: "Telegram user 参数无效" };
    }

    const dataCheckItems: string[] = [];
    for (const [key, value] of params.entries()) {
      if (key === "hash") continue;
      dataCheckItems.push(`${key}=${value}`);
    }
    dataCheckItems.sort((a, b) => a.localeCompare(b));
    const dataCheckString = dataCheckItems.join("\n");

    const secretKey = await this.hmacSha256("WebAppData", botToken);
    const expectedHash = this.bytesToHex(
      await this.hmacSha256(secretKey, dataCheckString)
    );

    if (!this.timingSafeEqual(hash, expectedHash)) {
      return { ok: false, reason: "Telegram 签名校验失败" };
    }

    return {
      ok: true,
      user: telegramUser,
      authDate,
    };
  }

  private getExpectedOrigin(request: Request) {
    const override =
      typeof this.env.PASSKEY_ORIGIN === "string"
        ? this.env.PASSKEY_ORIGIN.trim()
        : "";
    if (override) {
      return override.replace(/\/+$/, "");
    }
    const url = new URL(request.url);
    return `${url.protocol}//${url.host}`;
  }

  private getRpId(request: Request) {
    const override =
      typeof this.env.PASSKEY_RP_ID === "string"
        ? this.env.PASSKEY_RP_ID.trim()
        : "";
    if (override) return override;
    const url = new URL(request.url);
    return url.hostname;
  }

  private getPasskeyCacheKey(challenge: string) {
    return `passkey_challenge_${challenge}`;
  }

  private async savePasskeyChallenge(payload: PasskeyChallengePayload) {
    await this.cache.set(
      this.getPasskeyCacheKey(payload.challenge),
      JSON.stringify(payload),
      PASSKEY_CHALLENGE_TTL
    );
  }

  private async loadPasskeyChallenge(
    challenge: string
  ): Promise<PasskeyChallengePayload | null> {
    const raw = await this.cache.get(this.getPasskeyCacheKey(challenge));
    if (!raw || typeof raw !== "string") return null;
    try {
      return JSON.parse(raw) as PasskeyChallengePayload;
    } catch {
      return null;
    }
  }

  private async clearPasskeyChallenge(challenge: string) {
    await this.cache.delete(this.getPasskeyCacheKey(challenge));
  }

  private parseTransports(raw?: string | null) {
    if (!raw) return undefined;
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        return parsed.map((t) => String(t));
      }
    } catch {
      // ignore
    }
    return undefined;
  }

  private extractClientChallenge(clientDataJSON: string) {
    try {
      const decoded = base64UrlDecode(clientDataJSON);
      const parsed = JSON.parse(
        new TextDecoder().decode(decoded)
      ) as Record<string, unknown>;
      return typeof parsed.challenge === "string" ? parsed.challenge : "";
    } catch {
      return "";
    }
  }

  private isTwoFactorEnabled(user: AuthUserRow): boolean {
    return Number(user.two_factor_enabled) === 1 && Boolean(user.two_factor_secret);
  }

  private async shouldRequireTwoFactor(
    user: AuthUserRow,
    trustToken: string
  ): Promise<boolean> {
    if (!this.isTwoFactorEnabled(user)) {
      return false;
    }
    if (trustToken && (await this.validateTrustedDevice(user.id, trustToken))) {
      return false;
    }
    return true;
  }

  private async validateTrustedDevice(userId: number, trustToken: string): Promise<boolean> {
    if (!trustToken) return false;
    const tokenHash = await sha256Hex(trustToken);
    const record = await this.db.db
      .prepare(
        `
        SELECT id FROM two_factor_trusted_devices
        WHERE user_id = ? AND token_hash = ? AND disabled = 0
          AND expires_at > datetime('now', '+8 hours')
      `
      )
      .bind(userId, tokenHash)
      .first<{ id: number }>();

    if (record) {
      await this.db.db
        .prepare(
          `
        UPDATE two_factor_trusted_devices
        SET last_used_at = datetime('now', '+8 hours')
        WHERE id = ?
      `
        )
        .bind(record.id)
        .run();
      return true;
    }
    return false;
  }

  private async createTwoFactorChallenge(
    payload: Omit<TwoFactorChallengePayload, "issuedAt">
  ) {
    const challengeId = generateRandomString(48);
    const data: TwoFactorChallengePayload = {
      ...payload,
      issuedAt: Date.now(),
      meta: payload.meta ?? null,
    };
    await this.cache.set(
      `twofa_challenge_${challengeId}`,
      JSON.stringify(data),
      TWO_FACTOR_CHALLENGE_TTL
    );
    return challengeId;
  }

  private async getTwoFactorChallenge(
    challengeId: string
  ): Promise<TwoFactorChallengePayload | null> {
    const cacheKey = `twofa_challenge_${challengeId}`;
    const raw = await this.cache.get(cacheKey);
    if (!raw) return null;
    try {
      if (typeof raw !== "string") {
        return null;
      }
      return JSON.parse(raw) as TwoFactorChallengePayload;
    } catch {
      return null;
    }
  }

  private async clearTwoFactorChallenge(challengeId: string) {
    await this.cache.delete(`twofa_challenge_${challengeId}`);
  }

  private async finalizeLogin(
    user: AuthUserRow,
    remember: boolean,
    loginMethod: string,
    clientIP: string,
    userAgent: string,
    extra: Record<string, unknown> = {}
  ) {
    const sessionTTL = remember ? 604800 : 172800;
    const token = await generateToken(
      {
        userId: user.id,
        email: user.email,
        isAdmin: user.is_admin === 1,
      },
      this.env.JWT_SECRET,
      sessionTTL
    );

    await this.cache.set(
      `session_${token}`,
      JSON.stringify(this.buildSessionPayload(user)),
      sessionTTL
    );

    await this.db.db
      .prepare(
        `
        UPDATE users 
        SET last_login_time = datetime('now', '+8 hours'), 
            last_login_ip = ?
        WHERE id = ?
      `
      )
      .bind(clientIP, user.id)
      .run();

    const loginNote = user.status === 0 ? "禁用用户登录" : null;
    await this.db.db
      .prepare(
        `
        INSERT INTO login_logs (user_id, login_ip, user_agent, login_status, failure_reason, login_method)
        VALUES (?, ?, ?, ?, ?, ?)
      `
      )
      .bind(user.id, clientIP, userAgent, 1, loginNote, loginMethod)
      .run();

    const userResponse = this.buildUserResponse(user);

    return successResponse({
      token,
      user: userResponse,
      remember,
      ...extra,
    });
  }

  private async verifyTwoFactorCode(
    user: AuthUserRow,
    code: string
  ): Promise<{ success: boolean; usedBackup: boolean }> {
    if (!code) return { success: false, usedBackup: false };
    const trimmed = code.trim();
    const secret = await this.twoFactorService.decryptSecret(user.two_factor_secret);
    if (!secret) return { success: false, usedBackup: false };

    if (await this.twoFactorService.verifyTotp(secret, trimmed)) {
      return { success: true, usedBackup: false };
    }

    const normalizedBackup = this.twoFactorService.normalizeBackupCodeInput(trimmed);
    if (!normalizedBackup || normalizedBackup.length < 6) {
      return { success: false, usedBackup: false };
    }

    const hashedInput = await this.twoFactorService.hashBackupCode(normalizedBackup);
    const storedCodes = this.twoFactorService.parseBackupCodes(user.two_factor_backup_codes);
    const index = storedCodes.findIndex((hash) => hash === hashedInput);
    if (index === -1) {
      return { success: false, usedBackup: false };
    }

    storedCodes.splice(index, 1);
    await this.db.db
      .prepare("UPDATE users SET two_factor_backup_codes = ? WHERE id = ?")
      .bind(JSON.stringify(storedCodes), user.id)
      .run();
    user.two_factor_backup_codes = JSON.stringify(storedCodes);

    return { success: true, usedBackup: true };
  }

  private async issueTrustedDeviceToken(
    userId: number,
    userAgent: string,
    deviceName?: string
  ): Promise<{ token: string; expires_at: string }> {
    const token = generateRandomString(64);
    const tokenHash = await sha256Hex(token);
    const expiresInExpression = `+${TRUSTED_DEVICE_TTL_DAYS} days`;

    await this.db.db
      .prepare(
        `
        INSERT INTO two_factor_trusted_devices (user_id, token_hash, device_name, user_agent, expires_at)
        VALUES (?, ?, ?, ?, datetime('now', '+8 hours', ?))
      `
      )
      .bind(userId, tokenHash, deviceName || null, userAgent || "", expiresInExpression)
      .run();

    const expiresAt = new Date(Date.now() + TRUSTED_DEVICE_TTL_DAYS * 24 * 60 * 60 * 1000);
    return {
      token,
      expires_at: expiresAt.toISOString(),
    };
  }

  private getGoogleClientIds(): string[] {
    const rawValue =
      typeof this.env.GOOGLE_CLIENT_ID === "string"
        ? this.env.GOOGLE_CLIENT_ID
        : typeof this.env.GOOGLE_CLIENT_IDS === "string"
        ? this.env.GOOGLE_CLIENT_IDS
        : "";

    if (!rawValue) {
      return [];
    }

    return rawValue
      .split(",")
      .map((item) => item.trim())
      .filter((item) => item.length > 0);
  }

  private isMailConfigured(): boolean {
    const fromEmail =
      typeof this.env.MAIL_FROM === "string" ? this.env.MAIL_FROM.trim() : "";
    const provider =
      typeof this.env.MAIL_PROVIDER === "string"
        ? this.env.MAIL_PROVIDER.trim().toLowerCase()
        : "";

    if (!fromEmail) return false;
    if (!provider || provider === "none") return false;
    return true;
  }

  private async verifyGoogleIdToken(
    idToken: string
  ): Promise<GoogleTokenInfo> {
    const url = `${GOOGLE_TOKENINFO_ENDPOINT}?id_token=${encodeURIComponent(
      idToken
    )}`;

    let response: Response;
    try {
      response = await fetch(url, { method: "GET" });
    } catch (error) {
      this.logger.error("Google token 验证请求失败", error);
      throw new Error("无法验证 Google 身份令牌，请稍后重试");
    }

    if (!response.ok) {
      const errorText = await response.text().catch(() => "");
      this.logger.warn("Google token 验证失败", {
        status: response.status,
        body: errorText,
      });
      throw new Error("Google 身份令牌无效或已过期");
    }

    const data = (await response.json()) as GoogleTokenInfo;
    if (!data || typeof data !== "object" || !data.aud || !data.sub) {
      throw new Error("Google 身份令牌返回数据异常");
    }

    return data;
  }

  private sanitizeUsername(value: string) {
    return value
      .toLowerCase()
      .replace(/[^a-z0-9_]/g, "")
      .replace(/^_+/, "")
      .replace(/_+$/, "")
      .slice(0, 30);
  }

  private async resolveUniqueUsername(base: string): Promise<string> {
    let sanitizedBase = this.sanitizeUsername(base);
    if (!sanitizedBase) {
      sanitizedBase = `user_${generateRandomString(6).toLowerCase()}`;
    }

    let candidate = sanitizedBase;
    let counter = 1;
    while (true) {
      const existing = await this.db.db
        .prepare("SELECT id FROM users WHERE username = ?")
        .bind(candidate)
        .first();
      if (!existing) {
        return candidate;
      }
      const suffix = String(counter);
      const maxBaseLength = Math.max(1, 30 - suffix.length);
      candidate = `${sanitizedBase.slice(0, maxBaseLength)}${suffix}`;
      counter += 1;
    }
  }

  private async generateUniqueUsername(
    preferredNames: string[],
    fallbackSeed: string
  ): Promise<string> {
    for (const name of preferredNames) {
      const sanitized = this.sanitizeUsername(name);
      if (!sanitized) continue;
      const unique = await this.resolveUniqueUsername(sanitized);
      if (unique) return unique;
    }

    const fallbackBase = this.sanitizeUsername(
      fallbackSeed ? `user_${fallbackSeed}` : ""
    );
    return this.resolveUniqueUsername(
      fallbackBase || `user_${generateRandomString(6).toLowerCase()}`
    );
  }

  private buildSessionPayload(user: any) {
    return {
      id: user.id,
      email: user.email,
      username: user.username,
      uuid: user.uuid,
      passwd: user.passwd,
      is_admin: user.is_admin,
      class: user.class,
      class_expire_time: user.class_expire_time,
      upload_traffic: user.upload_traffic,
      download_traffic: user.download_traffic,
      upload_today: user.upload_today,
      download_today: user.download_today,
      transfer_total: user.transfer_total,
      transfer_enable: user.transfer_enable,
      transfer_remain: Math.max(
        0,
        user.transfer_enable - user.transfer_total
      ),
      speed_limit: user.speed_limit,
      device_limit: user.device_limit,
      expire_time: user.expire_time,
      status: user.status,
      two_factor_enabled: Number(user.two_factor_enabled) === 1,
    };
  }

  private buildUserResponse(user: any) {
    return {
      id: user.id,
      email: user.email,
      username: user.username,
      uuid: user.uuid,
      passwd: user.passwd,
      is_admin: user.is_admin === 1,
      class: user.class,
      class_expire_time: user.class_expire_time,
      expire_time: user.expire_time,
      upload_traffic: user.upload_traffic,
      download_traffic: user.download_traffic,
      upload_today: user.upload_today,
      download_today: user.download_today,
      transfer_total: user.transfer_total,
      transfer_enable: user.transfer_enable,
      transfer_remain: Math.max(
        0,
        user.transfer_enable - user.transfer_total
      ),
      speed_limit: user.speed_limit,
      device_limit: user.device_limit,
      status: user.status,
      token: user.token,
      two_factor_enabled: Number(user.two_factor_enabled) === 1,
    };
  }

  private async sendOAuthWelcomeEmail(
    providerLabel: string,
    email: string,
    password: string,
    siteName: string,
    siteUrl?: string
  ): Promise<boolean> {
    if (!this.isMailConfigured()) {
      return false;
    }

    const subject = `${siteName} 账户已创建`;
    const safeSiteUrl = siteUrl || "";
    const html = `
      <p>您好，</p>
      <p>您已使用 ${this.escapeHtml(providerLabel)} 账号成功创建 ${this.escapeHtml(siteName)} 账户。</p>
      <p>我们为您生成了一组初始密码，请妥善保管：</p>
      <pre style="padding:12px;background:#f4f4f5;border-radius:6px;">${this.escapeHtml(
        password
      )}</pre>
      <p>建议您登录后尽快在个人资料页面修改密码。</p>
      ${
        safeSiteUrl
          ? `<p>立即访问：<a href="${this.escapeHtml(
              safeSiteUrl
            )}" target="_blank" rel="noopener">${this.escapeHtml(
              safeSiteUrl
            )}</a></p>`
          : ""
      }
      <p>祝您使用愉快！</p>
      `;

    const text = [
      "您好，",
      `您已使用 ${providerLabel} 账号成功创建 ${siteName} 账户。`,
      "我们为您生成了一组初始密码，请妥善保管：",
      password,
      "建议您登录后尽快在个人资料页面修改密码。",
      safeSiteUrl ? `立即访问：${safeSiteUrl}` : "",
      "祝您使用愉快！",
    ]
      .filter(Boolean)
      .join("\n");

    try {
      await this.emailService.sendEmail({
        to: email,
        subject,
        html,
        text,
      });
      return true;
    } catch (error) {
      this.logger.error("Google 注册欢迎邮件发送失败", error, { email });
      return false;
    }
  }

  private async cachePendingOAuthRegistration(
    data: PendingOAuthRegistration
  ): Promise<string> {
    const token = generateRandomString(48);
    const cacheKey = `oauth_pending_${token}`;
    await this.cache.set(cacheKey, JSON.stringify(data), 600);
    return token;
  }

  private async consumePendingOAuthRegistration(
    token: string
  ): Promise<PendingOAuthRegistration | null> {
    const cacheKey = `oauth_pending_${token}`;
    const raw = await this.cache.get(cacheKey);
    if (!raw || typeof raw !== "string") {
      return null;
    }
    await this.cache.delete(cacheKey);
    try {
      return JSON.parse(raw) as PendingOAuthRegistration;
    } catch (error) {
      this.logger.error("解析 OAuth 待注册数据失败", error, { token });
      return null;
    }
  }

  isGmailAlias(email: string) {
    const [local = "", domain = ""] = email.split("@");
    const normalizedDomain = domain.toLowerCase();
    if (
      normalizedDomain !== "gmail.com" &&
      normalizedDomain !== "googlemail.com"
    ) {
      return false;
    }
    const plusIndex = local.indexOf("+");
    if (plusIndex !== -1) {
      return true;
    }
    return local.includes(".");
  }

  private async getDefaultUserProvisioning() {
    const configRows = await this.db.db
      .prepare(
        "SELECT * FROM system_configs WHERE key IN ('default_traffic', 'default_expire_days', 'default_account_expire_days', 'default_class')"
      )
      .all<ConfigRow>();

    const config = new Map<string, string>();
    for (const item of configRows.results ?? []) {
      if (item?.key) {
        config.set(item.key, item.value ?? "");
      }
    }

    const toPositiveInt = (value: unknown, fallback: number) => {
      const parsed =
        typeof value === "number"
          ? value
          : typeof value === "string"
          ? Number.parseInt(value, 10)
          : Number.NaN;
      return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
    };

    const transferEnable = toPositiveInt(
      config.get("default_traffic"),
      10737418240
    );
    const accountExpireDays = toPositiveInt(
      config.get("default_account_expire_days"),
      3650
    );
    const classExpireDays = toPositiveInt(
      config.get("default_expire_days"),
      30
    );
    const defaultClass = toPositiveInt(config.get("default_class"), 1);

    const withOffset = (days: number) =>
      new Date(
        Date.now() + 8 * 60 * 60 * 1000 + days * 24 * 60 * 60 * 1000
      )
        .toISOString()
        .replace("Z", "+08:00");

    const accountExpireTime = withOffset(accountExpireDays);
    const classExpireTime = withOffset(classExpireDays);

    return {
      transferEnable,
      accountExpireTime,
      classExpireTime,
      defaultClass,
    };
  }

  private async createOAuthUserFromPending(
    pending: PendingOAuthRegistration,
    options: { invitedBy?: number; inviteCode?: string } = {}
  ): Promise<{
    user: AuthUserRow;
    tempPassword: string;
    passwordEmailSent: boolean;
  }> {
    await this.db.ensureUsersRegisterIpColumn();
    const tempPassword = generateRandomString(32);
    const hashedPassword = await hashPassword(tempPassword);
    const uuid = generateUUID();
    const proxyPassword = generateBase64Random(32);
    const subscriptionToken = generateRandomString(32);

    const defaults = await this.getDefaultUserProvisioning();

    const username = await this.generateUniqueUsername(
      pending.usernameCandidates,
      pending.fallbackUsernameSeed
    );

    const identifierColumn =
      pending.provider === "google" ? "google_sub" : "github_id";

    const invitedBy =
      options.invitedBy && options.invitedBy > 0
        ? ensureNumber(options.invitedBy)
        : 0;
    const inviteCodeOverride = this.referralService.normalizeInviteCode(
      options.inviteCode
    );

    const insertStmt = this.db.db.prepare(`
      INSERT INTO users (
        email, username, password_hash, uuid, passwd, token,
        invited_by,
        ${identifierColumn}, oauth_provider, first_oauth_login_at, last_oauth_login_at,
        transfer_enable, expire_time, class, class_expire_time, status, register_ip
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+8 hours'), datetime('now', '+8 hours'), ?, ?, ?, ?, 1, ?)
    `);

    const insertResult = await insertStmt
      .bind(
        pending.email,
        username,
        hashedPassword,
        uuid,
        proxyPassword,
        subscriptionToken,
        invitedBy,
        pending.providerId,
        pending.provider,
        defaults.transferEnable,
        defaults.accountExpireTime,
        defaults.defaultClass,
        defaults.classExpireTime,
        pending.clientIP || "unknown"
      )
      .run();

    const userId = insertResult.meta.last_row_id;
    const user = await this.db.db
      .prepare("SELECT * FROM users WHERE id = ?")
      .bind(userId)
      .first<AuthUserRow | null>();

    if (!user) {
      throw new Error("无法创建或加载用户信息");
    }

    const ensuredInviteCode = await this.referralService.ensureUserInviteCode(
      userId
    );
    await this.referralService.applyDefaultInviteLimit(userId);
    if (invitedBy > 0) {
      await this.referralService.saveReferralRelation({
        inviterId: invitedBy,
        inviteeId: userId,
        inviteCode: inviteCodeOverride || ensuredInviteCode,
        inviteIp: pending.clientIP,
      });
      await this.referralService.incrementInviteUsage(invitedBy);
    }

    const siteConfigs = await this.configManager.getSiteConfigs();
    const siteName = siteConfigs.site_name || "Soga Panel";
    const siteUrl = siteConfigs.site_url || "";

    const providerLabel = pending.provider === "google" ? "Google" : "GitHub";
    const passwordEmailSent = await this.sendOAuthWelcomeEmail(
      providerLabel,
      pending.email,
      tempPassword,
      siteName,
      siteUrl
    );

    await this.cache.deleteByPrefix("user_");

    return {
      user,
      tempPassword,
      passwordEmailSent,
    };
  }

  async getVerificationSettings(purpose = PURPOSE_REGISTER) {
    const isRegister = purpose === PURPOSE_REGISTER;
    const emailProviderEnabled = this.isMailConfigured();

    const envDefaults = {
      expire: this.getIntConfig(
        this.env.MAIL_VERIFICATION_EXPIRE_MINUTES,
        10,
        { min: 1 }
      ),
      cooldown: this.getIntConfig(
        this.env.MAIL_VERIFICATION_COOLDOWN_SECONDS,
        60,
        { allowZero: true, min: 1 }
      ),
      dailyLimit: this.getIntConfig(
        this.env.MAIL_VERIFICATION_DAILY_LIMIT,
        5,
        { allowZero: true, min: 1 }
      ),
      ipHourlyLimit: this.getIntConfig(
        this.env.MAIL_VERIFICATION_IP_HOURLY_LIMIT,
        10,
        { allowZero: true, min: 1 }
      ),
      attemptLimit: this.getIntConfig(
        this.env.MAIL_VERIFICATION_ATTEMPT_LIMIT,
        5,
        { min: 1 }
      ),
    };

    const siteConfigs = await this.configManager.getSiteConfigs();

    if (isRegister) {
      const registerEnabled = await this.configManager.getSystemConfig(
        "register_enabled",
        "1"
      );
      const verificationEnabled = await this.configManager.getSystemConfig(
        "register_email_verification_enabled",
        "1"
      );

      return {
        purpose,
        enabled:
          registerEnabled !== "0" &&
          verificationEnabled !== "0" &&
          emailProviderEnabled,
        subjectTemplate: defaultRegisterEmailSubject,
        bodyTemplate: defaultRegisterEmailTemplate,
        expireMinutes: envDefaults.expire,
        cooldownSeconds: envDefaults.cooldown,
        dailyLimit: envDefaults.dailyLimit,
        ipHourlyLimit: envDefaults.ipHourlyLimit,
        attemptLimit: envDefaults.attemptLimit,
        siteName: siteConfigs.site_name || "Soga Panel",
        siteUrl: siteConfigs.site_url || "",
      };
    }

    return {
      purpose,
      enabled: emailProviderEnabled,
      subjectTemplate: defaultPasswordResetEmailSubject,
      bodyTemplate: defaultPasswordResetEmailTemplate,
      expireMinutes: envDefaults.expire,
      cooldownSeconds: envDefaults.cooldown,
      dailyLimit: envDefaults.dailyLimit,
      ipHourlyLimit: envDefaults.ipHourlyLimit,
      attemptLimit: envDefaults.attemptLimit,
      siteName: siteConfigs.site_name || "Soga Panel",
      siteUrl: siteConfigs.site_url || "",
    };
  }

  async cleanupVerificationCodes(email = null, purpose = null) {
    const condition = `(
      expires_at <= datetime('now', '+8 hours')
      OR (used_at IS NOT NULL AND used_at < datetime('now', '+8 hours', '-1 day'))
    )`;

    let query = `DELETE FROM email_verification_codes WHERE ${condition}`;
    const bindings: any[] = [];

    if (email) {
      query += " AND email = ?";
      bindings.push(email);
    }

    if (purpose) {
      query += " AND purpose = ?";
      bindings.push(purpose);
    }

    await this.db.db.prepare(query).bind(...bindings).run();
  }

  renderTemplate(template, context) {
    if (!template) return "";
    return template.replace(/\{\{\s*(\w+)\s*\}\}/g, (match, key) => {
      const normalizedKey = key.trim().toLowerCase();
      return context[normalizedKey] ?? "";
    });
  }

  escapeHtml(str = "") {
    const value = str ?? "";
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  buildVerificationHtml({
    subject,
    siteName,
    siteUrl,
    code,
    textContent,
    expireMinutes,
    titleText,
  }) {
    const paragraphs = textContent
      .split(/\n+/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
      .map(
        (line) =>
          `<p style="margin:0 0 12px;">${this.escapeHtml(line)}</p>`
      )
      .join("");

    const footer = siteUrl
      ? `<p style="margin:0;color:#94a3b8;font-size:12px;text-align:center;">访问 <a href="${this.escapeHtml(
          siteUrl
        )}" style="color:#2563eb;text-decoration:none;">${this.escapeHtml(
          siteUrl
        )}</a> 获取更多信息。</p>`
      : "";

    return `
      <div style="background:#f1f5f9;padding:24px;">
        <div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:12px;padding:32px;box-shadow:0 16px 32px rgba(15,23,42,0.15);font-family:'Segoe UI',Helvetica,Arial,sans-serif;color:#0f172a;">
          <div style="text-align:center;margin-bottom:24px;">
            <div style="font-size:28px;font-weight:700;color:#2563eb;">${this.escapeHtml(
              siteName
            )}</div>
            <div style="font-size:14px;color:#64748b;margin-top:6px;">${this.escapeHtml(
              subject
            )}</div>
          </div>
          <div style="text-align:center;margin-bottom:24px;">
            <div style="font-size:14px;color:#475569;margin-bottom:8px;">${this.escapeHtml(
              titleText
            )}</div>
            <div style="display:inline-block;padding:16px 24px;border-radius:14px;background:#1d4ed8;color:#ffffff;font-size:36px;font-weight:700;letter-spacing:10px;">${this.escapeHtml(
              code
            )}</div>
            <div style="font-size:13px;color:#64748b;margin-top:12px;">验证码将在 ${expireMinutes} 分钟后失效</div>
          </div>
          <div style="font-size:14px;line-height:1.7;color:#334155;margin-bottom:24px;">
            ${paragraphs}
          </div>
          <div style="font-size:12px;color:#94a3b8;text-align:center;margin-top:32px;">
            如果这不是您的操作，请忽略此邮件。${footer}
          </div>
        </div>
      </div>
    `;
  }

  private buildUserResponsePayload(user: AuthUserRow) {
    const transferEnable = ensureNumber((user as any).transfer_enable);
    const transferTotal = ensureNumber((user as any).transfer_total);

    return {
      id: user.id,
      email: ensureString(user.email),
      username: ensureString(user.username),
      uuid: ensureString((user as any).uuid),
      passwd: ensureString((user as any).passwd),
      is_admin: ensureNumber(user.is_admin) === 1,
      class: ensureNumber((user as any).class),
      class_expire_time: ensureString((user as any).class_expire_time),
      expire_time: ensureString((user as any).expire_time),
      invite_code: ensureString((user as any).invite_code),
      invited_by: ensureNumber((user as any).invited_by),
      invite_limit: ensureNumber((user as any).invite_limit),
      invite_used: ensureNumber((user as any).invite_used),
      rebate_available: ensureNumber((user as any).rebate_available),
      rebate_total: ensureNumber((user as any).rebate_total),
      upload_traffic: ensureNumber((user as any).upload_traffic),
      download_traffic: ensureNumber((user as any).download_traffic),
      upload_today: ensureNumber((user as any).upload_today),
      download_today: ensureNumber((user as any).download_today),
      transfer_total: transferTotal,
      transfer_enable: transferEnable,
      transfer_remain: Math.max(0, transferEnable - transferTotal),
      speed_limit: ensureNumber((user as any).speed_limit),
      device_limit: ensureNumber((user as any).device_limit),
      status: ensureNumber(user.status),
    };
  }

  getPurposeMeta(purpose: string) {
    if (purpose === PURPOSE_PASSWORD_RESET) {
      return {
        label: "密码重置验证码",
        successMessage: "验证码已发送，请查收邮箱",
        disabledMessage: "当前未开启密码重置功能",
        existingUserMessage: "",
        missingUserMessage: "该邮箱未注册账户，请检查邮箱是否正确",
        titleText: "您的密码重置验证码",
        logPrefix: "密码重置",
      };
    }

    return {
      label: "注册验证码",
      successMessage: "验证码已发送，请查收邮箱",
      disabledMessage: "当前未开启邮箱验证码功能",
      existingUserMessage: "该邮箱已被注册，请使用其他邮箱或直接登录",
      missingUserMessage: "该邮箱地址不存在，请先注册账号",
      titleText: "您的注册验证码",
      logPrefix: "注册",
    };
  }

  async handleVerificationCodeRequest(
    request,
    {
      purpose = PURPOSE_REGISTER,
      requireExistingUser = false,
      disallowExistingUser = false,
    } = {}
  ) {
    let recordId = null;

    try {
      const requestBody = await request.json().catch(() => ({}));
      const rawEmail =
        typeof requestBody?.email === "string" ? requestBody.email : "";
      const email = rawEmail.trim().toLowerCase();

      if (!email) {
        return errorResponse("请填写邮箱地址", 400);
      }

      if (!EMAIL_REGEX.test(email)) {
        return errorResponse("请输入有效的邮箱地址", 400);
      }

      if (purpose === PURPOSE_REGISTER && this.isGmailAlias(email)) {
        return errorResponse(
          "暂不支持使用 Gmail 别名注册，请使用不含点和加号的原始邮箱地址",
          400
        );
      }

      const meta = this.getPurposeMeta(purpose);
      const settings = await this.getVerificationSettings(purpose);

      if (!settings.enabled) {
        return errorResponse(meta.disabledMessage, 403);
      }

      if (purpose === PURPOSE_REGISTER) {
        const registerEnabled = await this.configManager.getSystemConfig(
          "register_enabled",
          "1"
        );
        if (registerEnabled !== "1") {
          return errorResponse("系统暂时关闭注册功能", 403);
        }

        const existing = await this.db.db
          .prepare("SELECT id FROM users WHERE email = ?")
          .bind(email)
          .first();

        if (existing) {
          return errorResponse(
            "该邮箱已被注册，请直接登录或找回密码",
            409
          );
        }
      }

      let user = null;
      if (requireExistingUser || disallowExistingUser) {
        user = await this.db.db
          .prepare("SELECT id FROM users WHERE email = ?")
          .bind(email)
          .first();

        if (requireExistingUser && !user) {
          return errorResponse(meta.missingUserMessage, 400);
        }

        if (disallowExistingUser && user) {
          return errorResponse(meta.existingUserMessage, 409);
        }
      }

      await this.cleanupVerificationCodes(email, purpose);

      const clientIP =
        request.headers.get("CF-Connecting-IP") ||
        request.headers.get("X-Forwarded-For") ||
        request.headers.get("X-Real-IP") ||
        "unknown";
      const userAgent = request.headers.get("User-Agent") || "";

      if (settings.cooldownSeconds > 0) {
        const cooldownResult = await this.db.db
          .prepare(
            `
            SELECT COUNT(*) as count
            FROM email_verification_codes
            WHERE email = ?
              AND purpose = ?
              AND created_at > datetime('now', '+8 hours', ?)
          `
          )
          .bind(email, purpose, `-${settings.cooldownSeconds} seconds`)
          .first();

        if (this.parseNumber(cooldownResult?.count) > 0) {
          return errorResponse(
            `验证码发送频繁，请在 ${settings.cooldownSeconds} 秒后重试`,
            429
          );
        }
      }

      if (settings.dailyLimit > 0) {
        const dailyResult = await this.db.db
          .prepare(
            `
            SELECT COUNT(*) as count
            FROM email_verification_codes
            WHERE email = ?
              AND purpose = ?
              AND created_at > datetime('now', '+8 hours', '-1 day')
          `
          )
          .bind(email, purpose)
          .first();

        if (this.parseNumber(dailyResult?.count) >= settings.dailyLimit) {
          return errorResponse(
            "今日验证码发送次数已达上限，请24小时后再试",
            429
          );
        }
      }

      if (settings.ipHourlyLimit > 0 && clientIP !== "unknown") {
        const ipResult = await this.db.db
          .prepare(
            `
            SELECT COUNT(*) as count
            FROM email_verification_codes
            WHERE request_ip = ?
              AND purpose = ?
              AND created_at > datetime('now', '+8 hours', '-1 hour')
          `
          )
          .bind(clientIP, purpose)
          .first();

        if (this.parseNumber(ipResult?.count) >= settings.ipHourlyLimit) {
          return errorResponse(
            "请求过于频繁，请稍后再试或更换网络",
            429
          );
        }
      }

      await this.db.db
        .prepare(
          `
          UPDATE email_verification_codes
          SET used_at = datetime('now', '+8 hours')
          WHERE email = ? AND purpose = ? AND used_at IS NULL
        `
        )
        .bind(email, purpose)
        .run();

      const code = generateNumericCode(6);
      const codeHash = await hashPassword(code);

      const insertResult = await this.db.db
        .prepare(
          `
          INSERT INTO email_verification_codes (
            email, purpose, code_hash, expires_at, attempts, request_ip, user_agent
          )
          VALUES (?, ?, ?, datetime('now', '+8 hours', ?), 0, ?, ?)
        `
        )
        .bind(
          email,
          purpose,
          codeHash,
          `+${settings.expireMinutes} minutes`,
          clientIP,
          userAgent ? userAgent.slice(0, 500) : null
        )
        .run();

      recordId = insertResult?.meta?.last_row_id || null;

      const replacements = {
        code,
        email,
        purpose,
        site_name: settings.siteName,
        site_url: settings.siteUrl || "",
        expire_minutes: settings.expireMinutes.toString(),
        ip: clientIP,
      };

      const subject = this.renderTemplate(
        settings.subjectTemplate,
        replacements
      );
      const textContent = this.renderTemplate(
        settings.bodyTemplate,
        replacements
      );
      const htmlContent = this.buildVerificationHtml({
        subject,
        siteName: settings.siteName,
        siteUrl: settings.siteUrl,
        code,
        textContent,
        expireMinutes: settings.expireMinutes,
        titleText: meta.titleText,
      });

      await this.emailService.sendEmail({
        to: email,
        subject,
        html: htmlContent,
        text: textContent,
        fromName: settings.siteName,
      });

      this.logger.info(`发送${meta.label}成功`, {
        email,
        purpose,
        request_ip: clientIP,
        cooldown: settings.cooldownSeconds,
      });

      return successResponse({
        message: meta.successMessage,
        cooldown: settings.cooldownSeconds,
        expire_minutes: settings.expireMinutes,
      });
    } catch (error) {
      if (recordId) {
        await this.db.db
          .prepare("DELETE FROM email_verification_codes WHERE id = ?")
          .bind(recordId)
          .run();
      }

      this.logger.error(`发送验证码失败`, error, { purpose });
      return errorResponse("发送验证码失败，请稍后重试", 500);
    }
  }

  async validateVerificationCode(email, verificationCode, purpose, settings) {
    if (!verificationCode) {
      return {
        ok: false,
        response: errorResponse("请填写邮箱验证码", 400),
      };
    }

    if (!/^\d{6}$/.test(verificationCode)) {
      return {
        ok: false,
        response: errorResponse("验证码格式不正确，请输入6位数字验证码", 400),
      };
    }

    const meta = this.getPurposeMeta(purpose);

    const activeCode = await this.db.db
      .prepare(
        `
        SELECT id, code_hash, attempts
        FROM email_verification_codes
        WHERE email = ?
          AND purpose = ?
          AND used_at IS NULL
          AND expires_at > datetime('now', '+8 hours')
        ORDER BY created_at DESC
        LIMIT 1
      `
      )
      .bind(email, purpose)
      .first();

    if (!activeCode) {
      this.logger.warn(`${meta.logPrefix}验证码验证失败：未找到有效验证码`, { email });
      return {
        ok: false,
        response: errorResponse("验证码已过期或不存在，请重新获取", 400),
      };
    }

    const hashedInput = await hashPassword(verificationCode);
    if (hashedInput !== activeCode.code_hash) {
      const currentAttempts = this.parseNumber(activeCode.attempts);
      const nextAttempts = currentAttempts + 1;
      const reachLimit = nextAttempts >= settings.attemptLimit;

      if (reachLimit) {
        await this.db.db
          .prepare(
            `UPDATE email_verification_codes SET attempts = ?, used_at = datetime('now', '+8 hours') WHERE id = ?`
          )
          .bind(nextAttempts, activeCode.id)
          .run();
        this.logger.warn(`${meta.logPrefix}验证码错误次数达到上限`, {
          email,
          purpose,
          attempts: nextAttempts,
        });
        return {
          ok: false,
          response: errorResponse(
            "验证码错误次数过多，请重新获取验证码",
            429
          ),
        };
      }

      await this.db.db
        .prepare(
          `UPDATE email_verification_codes SET attempts = ? WHERE id = ?`
        )
        .bind(nextAttempts, activeCode.id)
        .run();

      this.logger.warn(`${meta.logPrefix}验证码校验失败`, {
        email,
        purpose,
        attempts: nextAttempts,
      });
      return {
        ok: false,
        response: errorResponse("验证码不正确，请检查后重试", 400),
      };
    }

    await this.db.db
      .prepare(
        `UPDATE email_verification_codes SET used_at = datetime('now', '+8 hours') WHERE id = ?`
      )
      .bind(activeCode.id)
      .run();

    this.logger.info(`${meta.logPrefix}验证码验证成功`, { email, purpose });

    return { ok: true, record: activeCode };
  }

  async sendEmailCode(request) {
    return this.handleVerificationCodeRequest(request, {
      purpose: PURPOSE_REGISTER,
      disallowExistingUser: true,
    });
  }

  async requestPasswordReset(request) {
    return this.handleVerificationCodeRequest(request, {
      purpose: PURPOSE_PASSWORD_RESET,
      requireExistingUser: true,
    });
  }

  async getRegisterConfig() {
    try {
      const emailProviderEnabled = this.isMailConfigured();
      const [registerEnabled, verificationEnabled] = await Promise.all([
        this.configManager.getSystemConfig("register_enabled", "1"),
        this.configManager.getSystemConfig(
          "register_email_verification_enabled",
          "1"
        ),
      ]);

      const registerMode = registerEnabled || "1";
      const registerEnabledFlag = registerMode !== "0";
      const inviteRequired = registerMode === "2";
      const verificationFlag =
        registerEnabledFlag &&
        verificationEnabled !== "0" &&
        emailProviderEnabled;
      const passwordResetEnabled =
        verificationEnabled !== "0" && emailProviderEnabled;

      return successResponse({
        registerEnabled: registerEnabledFlag,
        registerMode,
        inviteRequired,
        verificationEnabled: verificationFlag,
        passwordResetEnabled,
        emailProviderEnabled,
      });
    } catch (error) {
      this.logger.error("获取注册配置失败", error);
      return errorResponse(error.message, 500);
    }
  }

  async getSiteSettings() {
    try {
      const siteConfigs = await this.configManager.getSiteConfigs();
      const siteName = siteConfigs.site_name || (this.env.SITE_NAME as string) || "Soga Panel";
      const siteUrl = siteConfigs.site_url || (this.env.SITE_URL as string) || "";
      const docsUrl = siteConfigs.docs_url || "";

      return successResponse({
        siteName,
        siteUrl,
        docsUrl,
      });
    } catch (error) {
      this.logger.error("获取站点配置失败", error);
      const fallbackName = (this.env.SITE_NAME as string) || "Soga Panel";
      const fallbackUrl = (this.env.SITE_URL as string) || "";
      return successResponse({
        siteName: fallbackName,
        siteUrl: fallbackUrl,
        docsUrl: "",
      });
    }
  }

  async confirmPasswordReset(request) {
    try {
      const body = await request.json();
      const rawEmail =
        typeof body.email === "string" ? body.email.trim() : "";
      const email = rawEmail.toLowerCase();
      const verificationCode =
        typeof body.verificationCode === "string"
          ? body.verificationCode.trim()
          : typeof body.verification_code === "string"
          ? body.verification_code.trim()
          : "";
      const newPassword =
        typeof body.newPassword === "string"
          ? body.newPassword
          : typeof body.password === "string"
          ? body.password
          : "";
      const confirmPassword =
        typeof body.confirmPassword === "string"
          ? body.confirmPassword
          : typeof body.password_confirm === "string"
          ? body.password_confirm
          : "";

      if (!email || !verificationCode || !newPassword) {
        return errorResponse("请完整填写邮箱、验证码和新密码", 400);
      }

      if (!EMAIL_REGEX.test(email)) {
        return errorResponse("请输入有效的邮箱地址", 400);
      }

      if (newPassword.length < 6) {
        return errorResponse("新密码长度不能少于6位", 400);
      }

      if (confirmPassword && newPassword !== confirmPassword) {
        return errorResponse("两次输入的新密码不一致", 400);
      }

      const user = await this.db.db
        .prepare("SELECT id FROM users WHERE email = ?")
        .bind(email)
        .first();

      if (!user) {
        return errorResponse("该邮箱未注册账户，请检查邮箱是否正确", 404);
      }

      const settings = await this.getVerificationSettings(
        PURPOSE_PASSWORD_RESET
      );

      if (!settings.enabled) {
        return errorResponse("当前未开启密码重置功能", 403);
      }

      const validation = await this.validateVerificationCode(
        email,
        verificationCode,
        PURPOSE_PASSWORD_RESET,
        settings
      );

      if (!validation.ok) {
        return validation.response;
      }

      const hashedPassword = await hashPassword(newPassword);

      await this.db.db
        .prepare(
          `
        UPDATE users
        SET password_hash = ?, updated_at = datetime('now', '+8 hours')
        WHERE id = ?
      `
        )
        .bind(hashedPassword, user.id)
        .run();

      await this.cleanupVerificationCodes(email, PURPOSE_PASSWORD_RESET);
      await this.cache.deleteByPrefix(`user_${user.id}`);

      this.logger.info("密码重置成功", { email, user_id: user.id });

      return successResponse({
        message: "密码已重置，请使用新密码登录",
      });
    } catch (error) {
      this.logger.error("密码重置失败", error);
      return errorResponse(error.message, 500);
    }
  }

  async login(request) {
    try {
      const body = await request.json();
      const rawEmail =
        typeof body.email === "string" ? body.email.trim() : "";
      const email = rawEmail.toLowerCase();
      const password = typeof body.password === "string" ? body.password : "";
      const remember = this.parseBoolean(body.remember, false);
      const trustToken =
        typeof body.twoFactorTrustToken === "string"
          ? body.twoFactorTrustToken.trim()
          : "";
      const turnstileToken =
        typeof body.turnstileToken === "string"
          ? body.turnstileToken.trim()
          : typeof body["cf-turnstile-response"] === "string"
          ? body["cf-turnstile-response"].trim()
          : "";

      if (!email || !password) {
        return errorResponse("请填写邮箱和密码", 400);
      }

      // 获取客户端信息（在验证之前获取，用于失败日志记录）
      const clientIP = request.headers.get("CF-Connecting-IP") || 
                      request.headers.get("X-Forwarded-For") || 
                      request.headers.get("X-Real-IP") || 
                      "unknown";
      const userAgent = request.headers.get("User-Agent") || "";

      // Turnstile 人机验证（如已配置）
      const turnstileSecret =
        (this.env.TURNSTILE_SECRET_KEY as string | undefined) || "";
      const turnstileEnabled =
        typeof turnstileSecret === "string" && turnstileSecret.trim().length > 0;

      if (turnstileEnabled) {
        if (!turnstileToken) {
          return errorResponse("请完成人机验证后再登录", 400);
        }
        try {
          const formData = new FormData();
          formData.append("secret", turnstileSecret);
          formData.append("response", turnstileToken);
          if (clientIP && clientIP !== "unknown") {
            formData.append("remoteip", clientIP);
          }

          const resp = await fetch(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            {
              method: "POST",
              body: formData,
            }
          );

          if (!resp.ok) {
            this.logger.error("Turnstile 验证请求失败", {
              status: resp.status,
              statusText: resp.statusText,
            });
            return errorResponse("人机验证失败，请稍后重试", 400);
          }

          const verifyResult = (await resp.json()) as {
            success?: boolean;
            "error-codes"?: string[];
          };

          if (!verifyResult.success) {
            this.logger.warn("Turnstile 验证未通过", {
              errorCodes: verifyResult["error-codes"] || [],
              clientIP,
            });
            return errorResponse("人机验证未通过，请重试", 400);
          }
        } catch (error) {
          this.logger.error("Turnstile 验证异常", error);
          return errorResponse("人机验证异常，请稍后重试", 400);
        }
      }

      // 查找用户
      const user = await this.db.db
        .prepare("SELECT * FROM users WHERE email = ?")
        .bind(email)
        .first<AuthUserRow>();

      if (!user) {
        this.logger.warn("登录失败：邮箱不存在", {
          email,
          login_ip: clientIP,
        });
        return errorResponse("该邮箱地址不存在，请先注册账号", 400);
      }

      // 验证密码
      const isValidPassword = await verifyPassword(
        password,
        user.password_hash
      );
      if (!isValidPassword) {
        // 记录密码错误的失败登录
        await this.db.db
          .prepare(`INSERT INTO login_logs (user_id, login_ip, user_agent, login_status, failure_reason, login_method) VALUES (?, ?, ?, ?, ?, ?)`)
          .bind(user.id, clientIP, userAgent, 0, "密码错误", "password")
          .run();
        return errorResponse("密码错误，请检查您的密码", 401);
      }

      // 注释：允许禁用用户登录，但会在前端显示受限提示
      // 这里不检查用户状态，让禁用用户也能正常登录

      // 检查是否过期
      const expireTime = user.expire_time
        ? new Date(typeof user.expire_time === "string" ? user.expire_time : String(user.expire_time))
        : null;

      if (expireTime && expireTime < new Date()) {
        // 记录账户过期的失败登录
        await this.db.db
          .prepare(`INSERT INTO login_logs (user_id, login_ip, user_agent, login_status, failure_reason, login_method) VALUES (?, ?, ?, ?, ?, ?)`)
          .bind(user.id, clientIP, userAgent, 0, "账户过期", "password")
          .run();
        return errorResponse("账户已过期，请联系管理员续费", 403);
      }

      if (await this.shouldRequireTwoFactor(user, trustToken)) {
        const challengeId = await this.createTwoFactorChallenge({
          userId: user.id,
          remember,
          loginMethod: "password",
          clientIP,
          userAgent,
        });
        return successResponse({
          need_2fa: true,
          challenge_id: challengeId,
          two_factor_enabled: true,
        });
      }

      return this.finalizeLogin(user, remember, "password", clientIP, userAgent);
    } catch (error) {
      console.error("Login error:", error);
      return errorResponse(error.message, 500);
    }
  }

  async telegramMiniAppLogin(request) {
    let body: any;
    try {
      body = await request.json();
    } catch (error) {
      this.logger.warn("Telegram Mini App 登录失败：请求体解析失败", error);
      return errorResponse("请求格式不正确，请使用 JSON", 400);
    }

    const rawInitData =
      typeof body?.initData === "string"
        ? body.initData
        : typeof body?.init_data === "string"
        ? body.init_data
        : "";
    const initData = rawInitData.trim();
    const remember = this.parseBoolean(body?.remember, true);
    const trustToken =
      typeof body?.twoFactorTrustToken === "string"
        ? body.twoFactorTrustToken.trim()
        : "";

    if (!initData) {
      return errorResponse("缺少 Telegram initData", 400);
    }

    const botToken =
      (
        await this.configManager.getSystemConfig(
          "telegram_bot_token",
          ensureString(this.env.TELEGRAM_BOT_TOKEN, "")
        )
      )?.trim() || "";
    if (!botToken) {
      return errorResponse("未配置 telegram_bot_token，请联系管理员", 503);
    }

    const verifyResult = await this.verifyTelegramInitData(initData, botToken);
    if (!verifyResult.ok || !verifyResult.user) {
      this.logger.warn("Telegram Mini App 登录失败：initData 校验失败", {
        reason: verifyResult.reason,
      });
      return errorResponse(verifyResult.reason || "Telegram 数据校验失败", 401);
    }

    await this.db.ensureUsersTelegramColumns();

    const telegramId = String(verifyResult.user.id);
    const clientIP =
      request.headers.get("CF-Connecting-IP") ||
      request.headers.get("X-Forwarded-For") ||
      request.headers.get("X-Real-IP") ||
      "unknown";
    const userAgent = request.headers.get("User-Agent") || "";

    const user = await this.db.db
      .prepare("SELECT * FROM users WHERE telegram_id = ? LIMIT 1")
      .bind(telegramId)
      .first<AuthUserRow>();

    if (!user) {
      this.logger.warn("Telegram Mini App 登录失败：未绑定账号", {
        telegram_id: telegramId,
        login_ip: clientIP,
      });
      return errorResponse("当前 Telegram 未绑定账号，请先在面板完成绑定", 404);
    }

    const expireTime = user.expire_time
      ? new Date(
          typeof user.expire_time === "string"
            ? user.expire_time
            : String(user.expire_time)
        )
      : null;
    if (expireTime && expireTime < new Date()) {
      await this.db.db
        .prepare(
          `INSERT INTO login_logs (user_id, login_ip, user_agent, login_status, failure_reason, login_method) VALUES (?, ?, ?, ?, ?, ?)`
        )
        .bind(user.id, clientIP, userAgent, 0, "账户过期", "telegram_miniapp")
        .run();
      return errorResponse("账户已过期，请联系管理员续费", 403);
    }

    if (await this.shouldRequireTwoFactor(user, trustToken)) {
      const challengeId = await this.createTwoFactorChallenge({
        userId: user.id,
        remember,
        loginMethod: "telegram_miniapp",
        clientIP,
        userAgent,
        meta: {
          provider: "telegram",
          telegram_id: telegramId,
        },
      });
      return successResponse({
        need_2fa: true,
        challenge_id: challengeId,
        two_factor_enabled: true,
        provider: "telegram",
      });
    }

    return this.finalizeLogin(
      user,
      remember,
      "telegram_miniapp",
      clientIP,
      userAgent,
      {
        provider: "telegram",
      }
    );
  }

  async verifyTwoFactor(request) {
    try {
      const body = await request.json();
      const challengeId =
        typeof body.challenge_id === "string"
          ? body.challenge_id.trim()
          : typeof body.challengeId === "string"
          ? body.challengeId.trim()
          : "";
      const code = typeof body.code === "string" ? body.code.trim() : "";
      const rememberDevice = this.parseBoolean(body.rememberDevice, false);
      const deviceName =
        typeof body.deviceName === "string"
          ? body.deviceName.trim().slice(0, 64)
          : "";

      if (!challengeId) {
        return errorResponse("缺少验证会话，请重新登录", 400);
      }
      if (!code) {
        return errorResponse("请输入验证码", 400);
      }

      const challenge = await this.getTwoFactorChallenge(challengeId);
      if (!challenge) {
        return errorResponse("验证会话已过期，请重新登录", 400);
      }

      const user = await this.db.db
        .prepare("SELECT * FROM users WHERE id = ?")
        .bind(challenge.userId)
        .first<AuthUserRow>();

      if (!user || !this.isTwoFactorEnabled(user)) {
        await this.clearTwoFactorChallenge(challengeId);
        return errorResponse("用户未启用二步验证", 400);
      }

      const verification = await this.verifyTwoFactorCode(user, code);
      if (!verification.success) {
        await this.db.db
          .prepare(
            `
          INSERT INTO login_logs (user_id, login_ip, user_agent, login_status, failure_reason, login_method)
          VALUES (?, ?, ?, ?, ?, ?)
        `
          )
          .bind(
            user.id,
            challenge.clientIP,
            challenge.userAgent,
            0,
            "二步验证失败",
            challenge.loginMethod || "password"
          )
          .run();
        return errorResponse("二步验证码无效，请重试", 401);
      }

      await this.clearTwoFactorChallenge(challengeId);

      let trustInfo: Record<string, unknown> = {};
      if (rememberDevice) {
        const trusted = await this.issueTrustedDeviceToken(
          user.id,
          challenge.userAgent,
          deviceName || "Trusted device"
        );
        trustInfo = {
          trust_token: trusted.token,
          trust_token_expires_at: trusted.expires_at,
        };
      }

      const extra = {
        ...(challenge.meta || {}),
        ...trustInfo,
      };

      return this.finalizeLogin(
        user,
        challenge.remember,
        challenge.loginMethod || "password",
        challenge.clientIP,
        challenge.userAgent,
        extra
      );
    } catch (error) {
      this.logger.error("二步验证失败", error);
      return errorResponse(
        error instanceof Error ? error.message : "二步验证失败，请稍后重试",
        500
      );
    }
  }

  async generatePasskeyRegistrationOptions(request: Request) {
    const auth = await validateUserAuth(request, this.env);
    if (!auth.success) {
      return errorResponse(auth.message, 401);
    }

    const siteConfigs = await this.configManager.getSiteConfigs();
    const siteName =
      siteConfigs.site_name || (this.env.SITE_NAME as string) || "Soga Panel";
    const rpId = this.getRpId(request);
    const origin = this.getExpectedOrigin(request);
    const challenge = randomChallenge(32);

    const existing = await this.db.db
      .prepare("SELECT credential_id, transports FROM passkeys WHERE user_id = ?")
      .bind(auth.user.id)
      .all<{ credential_id: string; transports?: string | null }>();

    await this.savePasskeyChallenge({
      type: "registration",
      userId: auth.user.id,
      challenge,
      rpId,
      origin,
      createdAt: Date.now(),
    });

    const excludeCredentials =
      existing.results?.map((row) => ({
        id: row.credential_id,
        type: "public-key",
        transports: this.parseTransports(row.transports),
      })) || [];

    const userHandle = base64UrlEncode(String(auth.user.id));
    const displayName =
      (auth.user as any).username ||
      (auth.user as any).email ||
      `user_${auth.user.id}`;

    return successResponse({
      challenge,
      rp: { id: rpId, name: siteName },
      user: {
        id: userHandle,
        name: (auth.user as any).email || displayName,
        displayName,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      timeout: 120000,
      attestation: "none",
      authenticatorSelection: {
        userVerification: "preferred",
        residentKey: "preferred",
      },
      excludeCredentials,
    });
  }

  async verifyPasskeyRegistration(request: Request) {
    const auth = await validateUserAuth(request, this.env);
    if (!auth.success) {
      return errorResponse(auth.message, 401);
    }

    let body: any;
    try {
      body = await request.json();
    } catch {
      return errorResponse("请求格式不正确，请使用 JSON", 400);
    }

    const credential = body?.credential as RegistrationCredential | undefined;
    const deviceName =
      typeof body?.deviceName === "string"
        ? body.deviceName.trim().slice(0, 64)
        : "";

    if (
      !credential ||
      typeof credential.response?.clientDataJSON !== "string" ||
      typeof credential.response?.attestationObject !== "string"
    ) {
      return errorResponse("缺少 Passkey 凭证数据", 400);
    }

    const receivedChallenge = this.extractClientChallenge(
      credential.response.clientDataJSON
    );
    if (!receivedChallenge) {
      return errorResponse("挑战码无效，请重试", 400);
    }

    const challenge = await this.loadPasskeyChallenge(receivedChallenge);
    if (
      !challenge ||
      challenge.type !== "registration" ||
      challenge.userId !== auth.user.id
    ) {
      return errorResponse("Passkey 注册会话已过期，请重新开始", 400);
    }

    try {
      const validated = await validateRegistrationResponse({
        credential,
        expectedChallenge: challenge.challenge,
        expectedOrigin: challenge.origin,
        expectedRpId: challenge.rpId,
      });

      const existing = await this.db.db
        .prepare("SELECT user_id FROM passkeys WHERE credential_id = ?")
        .bind(validated.credentialId)
        .first<{ user_id: number }>();

      if (existing) {
        await this.clearPasskeyChallenge(receivedChallenge);
        return errorResponse("该 Passkey 已被绑定，请改用其它凭证", 400);
      }

      await this.db.db
        .prepare(
          `
          INSERT INTO passkeys (user_id, credential_id, public_key, alg, user_handle, rp_id, transports, sign_count, device_name, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+8 hours'), datetime('now', '+8 hours'))
        `
        )
        .bind(
          auth.user.id,
          validated.credentialId,
          validated.publicKey,
          validated.alg,
          validated.userHandle || base64UrlEncode(String(auth.user.id)),
          challenge.rpId,
          validated.transports ? JSON.stringify(validated.transports) : null,
          validated.signCount || 0,
          deviceName || null
        )
        .run();

      await this.clearPasskeyChallenge(receivedChallenge);
      return successResponse({
        credential_id: validated.credentialId,
        message: "Passkey 已绑定",
      });
    } catch (error) {
      await this.clearPasskeyChallenge(receivedChallenge);
      this.logger.error("Passkey 注册失败", error);
      const message =
        error instanceof Error ? error.message : "Passkey 注册失败，请重试";
      return errorResponse(message, 400);
    }
  }

  async generatePasskeyLoginOptions(request: Request) {
    let body: any;
    try {
      body = await request.json();
    } catch {
      return errorResponse("请求格式不正确，请使用 JSON", 400);
    }

    const email =
      typeof body?.email === "string" ? body.email.trim().toLowerCase() : "";
    const remember = this.parseBoolean(body?.remember, false);

    if (!email) {
      return errorResponse("请填写邮箱", 400);
    }
    if (!EMAIL_REGEX.test(email)) {
      return errorResponse("邮箱格式无效", 400);
    }

    const user = await this.db.db
      .prepare("SELECT * FROM users WHERE email = ?")
      .bind(email)
      .first<AuthUserRow>();

    if (!user) {
      return errorResponse("账户不存在", 404);
    }

    const passkeys = await this.db.db
      .prepare("SELECT credential_id, transports, rp_id FROM passkeys WHERE user_id = ?")
      .bind(user.id)
      .all<{ credential_id: string; transports?: string | null; rp_id?: string | null }>();

    const list = passkeys.results || [];
    if (!list.length) {
      return errorResponse("该账户未绑定 Passkey，请先使用密码登录绑定", 400);
    }

    const rpId = this.getRpId(request);
    const origin = this.getExpectedOrigin(request);
    const challenge = randomChallenge(32);

    await this.savePasskeyChallenge({
      type: "authentication",
      userId: user.id,
      challenge,
      rpId,
      origin,
      remember,
      createdAt: Date.now(),
    });

    return successResponse({
      challenge,
      rpId,
      timeout: 120000,
      allowCredentials: list.map((row) => ({
        id: row.credential_id,
        type: "public-key",
        transports: this.parseTransports(row.transports),
      })),
      userVerification: "required",
    });
  }

  async verifyPasskeyLogin(request: Request) {
    let body: any;
    try {
      body = await request.json();
    } catch {
      return errorResponse("请求格式不正确，请使用 JSON", 400);
    }

    const credential = body?.credential as AuthenticationCredential | undefined;
    if (
      !credential ||
      typeof credential.response?.clientDataJSON !== "string" ||
      typeof credential.response?.authenticatorData !== "string" ||
      typeof credential.response?.signature !== "string"
    ) {
      return errorResponse("缺少 Passkey 凭证数据", 400);
    }

    const clientIP =
      request.headers.get("CF-Connecting-IP") ||
      request.headers.get("X-Forwarded-For") ||
      request.headers.get("X-Real-IP") ||
      "unknown";
    const userAgent = request.headers.get("User-Agent") || "";

    const receivedChallenge = this.extractClientChallenge(
      credential.response.clientDataJSON
    );
    if (!receivedChallenge) {
      return errorResponse("挑战码无效，请重试", 400);
    }

    const challenge = await this.loadPasskeyChallenge(receivedChallenge);
    if (!challenge || challenge.type !== "authentication") {
      return errorResponse("登录会话已失效，请重试", 400);
    }

    const credentialId = typeof credential.id === "string" ? credential.id : "";
    const passkey = await this.db.db
      .prepare("SELECT * FROM passkeys WHERE credential_id = ?")
      .bind(credentialId)
      .first<any>();

    if (!passkey) {
      await this.clearPasskeyChallenge(receivedChallenge);
      return errorResponse("未找到匹配的 Passkey", 404);
    }

    if (Number(passkey.user_id) !== Number(challenge.userId)) {
      await this.clearPasskeyChallenge(receivedChallenge);
      return errorResponse("登录会话已失效，请重试", 400);
    }

    const user = await this.db.db
      .prepare("SELECT * FROM users WHERE id = ?")
      .bind(passkey.user_id)
      .first<AuthUserRow>();

    if (!user) {
      await this.clearPasskeyChallenge(receivedChallenge);
      return errorResponse("账户不存在", 404);
    }

    try {
      const validated = await validateAuthenticationResponse({
        credential,
        expectedChallenge: challenge.challenge,
        expectedOrigin: challenge.origin,
        expectedRpId: challenge.rpId || this.getRpId(request),
        storedPublicKey: passkey.public_key,
        alg: Number(passkey.alg ?? -7),
        prevSignCount: Number(passkey.sign_count ?? 0),
        expectedUserHandle:
          typeof passkey.user_handle === "string" ? passkey.user_handle : undefined,
      });

      const newCount =
        validated.newSignCount ?? Number(passkey.sign_count ?? 0);
      const finalCount =
        newCount > Number(passkey.sign_count ?? 0)
          ? newCount
          : Number(passkey.sign_count ?? 0);

      await this.db.db
        .prepare(
          `
          UPDATE passkeys
          SET sign_count = ?, last_used_at = datetime('now', '+8 hours'), updated_at = datetime('now', '+8 hours')
          WHERE credential_id = ?
        `
        )
        .bind(finalCount, credentialId)
        .run();

      await this.clearPasskeyChallenge(receivedChallenge);

      const expireTime = user.expire_time
        ? new Date(
            typeof user.expire_time === "string"
              ? user.expire_time
              : String(user.expire_time)
          )
        : null;

      if (expireTime && expireTime < new Date()) {
        await this.db.db
          .prepare(
            `
            INSERT INTO login_logs (user_id, login_ip, user_agent, login_status, failure_reason, login_method)
            VALUES (?, ?, ?, ?, ?, ?)
          `
          )
          .bind(user.id, clientIP, userAgent, 0, "账户过期", "passkey")
          .run();
        return errorResponse("账户已过期，请联系管理员续费", 403);
      }

      return this.finalizeLogin(
        user,
        Boolean(challenge.remember),
        "passkey",
        clientIP,
        userAgent
      );
    } catch (error) {
      await this.clearPasskeyChallenge(receivedChallenge);
      await this.db.db
        .prepare(
          `
          INSERT INTO login_logs (user_id, login_ip, user_agent, login_status, failure_reason, login_method)
          VALUES (?, ?, ?, ?, ?, ?)
        `
        )
        .bind(
          user.id,
          clientIP,
          userAgent,
          0,
          error instanceof Error ? error.message : "Passkey 校验失败",
          "passkey"
        )
        .run();
      this.logger.error("Passkey 登录失败", error);
      return errorResponse(
        error instanceof Error ? error.message : "Passkey 登录失败，请重试",
        400
      );
    }
  }

  async googleOAuthLogin(request) {
    let body: any;
    try {
      body = await request.json();
    } catch (error) {
      this.logger.warn("Google OAuth 登录失败：请求体解析失败", error);
      return errorResponse("请求格式不正确，请使用 JSON", 400);
    }

    const remember = this.parseBoolean(body?.remember, false);
    const trustToken =
      typeof body?.twoFactorTrustToken === "string"
        ? body.twoFactorTrustToken.trim()
        : "";

    const possibleToken =
      typeof body?.idToken === "string"
        ? body.idToken
        : typeof body?.credential === "string"
        ? body.credential
        : typeof body?.id_token === "string"
        ? body.id_token
        : typeof body?.token === "string"
        ? body.token
        : "";
    const idToken = possibleToken.trim();

    if (!idToken) {
      return errorResponse("缺少 Google 身份令牌", 400);
    }

    const clientIds = this.getGoogleClientIds();
    if (clientIds.length === 0) {
      this.logger.error("Google OAuth 登录失败：未配置 GOOGLE_CLIENT_ID");
      return errorResponse("未启用 Google 登录，请联系管理员", 503);
    }

    let tokenInfo: GoogleTokenInfo;
    try {
      tokenInfo = await this.verifyGoogleIdToken(idToken);
    } catch (error) {
      return errorResponse(
        error instanceof Error ? error.message : "Google 身份验证失败",
        401
      );
    }

    if (!clientIds.includes(tokenInfo.aud)) {
      this.logger.warn("Google OAuth 登录失败：aud 不匹配", {
        aud: tokenInfo.aud,
      });
      return errorResponse("Google 身份令牌无效，请重试", 401);
    }

    const issuer = tokenInfo.iss || "";
    if (
      issuer &&
      issuer !== "accounts.google.com" &&
      issuer !== "https://accounts.google.com"
    ) {
      this.logger.warn("Google OAuth 登录失败：issuer 不匹配", { issuer });
      return errorResponse("Google 身份令牌无效，请重试", 401);
    }

    const email = (tokenInfo.email || "").toLowerCase();
    if (!email || !EMAIL_REGEX.test(email)) {
      return errorResponse("未从 Google 获取到有效邮箱地址", 400);
    }

    const emailVerifiedRaw = tokenInfo.email_verified;
    const emailVerified = typeof emailVerifiedRaw === "string"
      ? ["true", "1", "yes"].includes(emailVerifiedRaw.trim().toLowerCase())
      : false;
    if (!emailVerified) {
      return errorResponse("您的 Google 邮箱尚未验证，无法登录", 403);
    }

    const googleSub = tokenInfo.sub;
    if (!googleSub) {
      return errorResponse("Google 身份令牌缺少唯一标识", 400);
    }

    const clientIP =
      request.headers.get("CF-Connecting-IP") ||
      request.headers.get("X-Forwarded-For") ||
      request.headers.get("X-Real-IP") ||
      "unknown";
    const userAgent = request.headers.get("User-Agent") || "";

    try {
      let user: AuthUserRow | null = await this.db.db
        .prepare("SELECT * FROM users WHERE google_sub = ?")
        .bind(googleSub)
        .first<AuthUserRow | null>();

      if (!user) {
        const existingByEmail = await this.db.db
          .prepare("SELECT * FROM users WHERE email = ?")
          .bind(email)
          .first<AuthUserRow | null>();

        if (existingByEmail) {
          if (
            existingByEmail.google_sub &&
            existingByEmail.google_sub !== googleSub
          ) {
            this.logger.warn("Google OAuth 登录失败：sub 与已绑定账号不匹配", {
              email,
              existingSub: existingByEmail.google_sub,
              incomingSub: googleSub,
            });
            return errorResponse(
              "该邮箱已绑定其它 Google 账号，请使用原账号登录",
              409
            );
          }
          user = existingByEmail;
        }
      }

      let isNewUser = false;
      let tempPassword: string | null = null;
      let passwordEmailSent = false;

      if (!user) {
        const emailLocal = email.split("@")[0] || "";
        const usernameCandidates = [
          tokenInfo.given_name,
          tokenInfo.name,
          emailLocal,
          `google_${googleSub.slice(-6)}`,
        ].filter(
          (name): name is string => !!name && name.trim().length > 0
        );

        const pendingToken = await this.cachePendingOAuthRegistration({
          provider: "google",
          email,
          providerId: googleSub,
          usernameCandidates,
          fallbackUsernameSeed: emailLocal || googleSub.slice(-6),
          remember,
          clientIP,
          userAgent,
        });

        return successResponse({
          need_terms_agreement: true,
          pending_terms_token: pendingToken,
          provider: "google",
          profile: {
            email,
            username:
              usernameCandidates[0] ||
              emailLocal ||
              `google_${googleSub.slice(-6)}`,
            avatar: tokenInfo.picture || "",
          },
        });
      } else {
        await this.cache.deleteByPrefix(`user_${user.id}`);
      }

      if (!user) {
        return errorResponse("无法创建或加载用户信息", 500);
      }

      await this.db.db
        .prepare(
          `
        UPDATE users
        SET google_sub = ?,
            oauth_provider = 'google',
            first_oauth_login_at = COALESCE(first_oauth_login_at, datetime('now', '+8 hours')),
            last_oauth_login_at = datetime('now', '+8 hours'),
            updated_at = datetime('now', '+8 hours')
        WHERE id = ?
      `
        )
        .bind(googleSub, user.id)
        .run();

      user = await this.db.db
        .prepare("SELECT * FROM users WHERE id = ?")
        .bind(user.id)
        .first<AuthUserRow>();

      if (!user) {
        return errorResponse("用户不存在", 404);
      }

      const refreshedExpire = user.expire_time
        ? new Date(typeof user.expire_time === "string" ? user.expire_time : String(user.expire_time))
        : null;

      if (refreshedExpire && refreshedExpire < new Date()) {
        await this.db.db
          .prepare(
            `INSERT INTO login_logs (user_id, login_ip, user_agent, login_status, failure_reason, login_method) VALUES (?, ?, ?, ?, ?, ?)`
          )
          .bind(user.id, clientIP, userAgent, 0, "账户过期", "google_oauth")
          .run();
        return errorResponse("账户已过期，请联系管理员续费", 403);
      }

      if (await this.shouldRequireTwoFactor(user, trustToken)) {
        const challengeId = await this.createTwoFactorChallenge({
          userId: user.id,
          remember,
          loginMethod: "google_oauth",
          clientIP,
          userAgent,
          meta: {
            isNewUser,
            tempPassword,
            passwordEmailSent,
            provider: "google",
          },
        });
        return successResponse({
          need_2fa: true,
          challenge_id: challengeId,
          two_factor_enabled: true,
          isNewUser,
          tempPassword,
          passwordEmailSent,
          provider: "google",
        });
      }

      return this.finalizeLogin(user, remember, "google_oauth", clientIP, userAgent, {
        isNewUser,
        tempPassword,
        passwordEmailSent,
        provider: "google",
      });
    } catch (error) {
      this.logger.error("Google OAuth 登录失败", error, { email });
      return errorResponse(
        error instanceof Error
          ? error.message
          : "Google 登录失败，请稍后重试",
        500
      );
    }
  }

  async githubOAuthLogin(request) {
    try {
      const clientId =
        typeof this.env.GITHUB_CLIENT_ID === "string"
          ? this.env.GITHUB_CLIENT_ID.trim()
          : "";
      const clientSecret =
        typeof this.env.GITHUB_CLIENT_SECRET === "string"
          ? this.env.GITHUB_CLIENT_SECRET.trim()
          : "";

      if (!clientId || !clientSecret) {
        return errorResponse("未配置 GitHub 登录，请联系管理员", 503);
      }

      let body: any = {};
      try {
        body = await request.json();
      } catch (err) {
        this.logger.warn("GitHub OAuth 登录：解析请求体失败", err);
      }

      const code =
        typeof body?.code === "string" ? body.code.trim() : "";
      const redirectUri =
        typeof body?.redirectUri === "string" ? body.redirectUri.trim() : "";
      const remember = this.parseBoolean(body?.remember, false);
      const trustToken =
        typeof body?.twoFactorTrustToken === "string"
          ? body.twoFactorTrustToken.trim()
          : "";

      if (!code) {
        return errorResponse("缺少 GitHub 授权码", 400);
      }

      const tokenRequestPayload: Record<string, string> = {
        client_id: clientId,
        client_secret: clientSecret,
        code,
      };

      if (redirectUri) {
        tokenRequestPayload.redirect_uri = redirectUri;
      }

      if (typeof body?.state === "string" && body.state.trim()) {
        tokenRequestPayload.state = body.state.trim();
      }

      const tokenResponse = await fetch(
        "https://github.com/login/oauth/access_token",
        {
          method: "POST",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
          },
          body: JSON.stringify(tokenRequestPayload),
        }
      );

      if (!tokenResponse.ok) {
        const errorText = await tokenResponse.text().catch(() => "");
        this.logger.error("GitHub token 交换失败", null, {
          status: tokenResponse.status,
          errorText,
        });
        return errorResponse("GitHub 授权失败，请重试", 502);
      }

      const tokenData = (await tokenResponse.json()) as GithubTokenResponse;
      if (tokenData.error) {
        return errorResponse(
          tokenData.error_description || "GitHub 授权失败",
          400
        );
      }

      const accessToken = ensureString(tokenData.access_token);
      if (!accessToken) {
        return errorResponse("未获取到 GitHub access token", 400);
      }

      const githubUserResponse = await fetch("https://api.github.com/user", {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/vnd.github+json",
          "User-Agent": "soga-panel",
        },
      });

      if (!githubUserResponse.ok) {
        const errorText = await githubUserResponse.text().catch(() => "");
        this.logger.error("GitHub 用户信息获取失败", null, {
          status: githubUserResponse.status,
          errorText,
        });
        return errorResponse("无法获取 GitHub 用户信息", 502);
      }

      const githubUser = (await githubUserResponse.json()) as GithubUserResponse;
      const githubId = githubUser?.id ? String(githubUser.id) : "";
      let email = typeof githubUser?.email === "string" ? githubUser.email : "";

      if (!email) {
        const emailsResponse = await fetch(
          "https://api.github.com/user/emails",
          {
            headers: {
              Authorization: `Bearer ${accessToken}`,
              Accept: "application/vnd.github+json",
              "User-Agent": "soga-panel",
            },
          }
        );

        if (emailsResponse.ok) {
          const emailsData = (await emailsResponse.json()) as GithubEmailEntry[];
          const primaryEmail = emailsData.find(
            (item) => item?.primary && item?.verified
          );
          const verifiedEmail = emailsData.find((item) => item?.verified);
          email = ensureString(primaryEmail?.email) || ensureString(verifiedEmail?.email);
        }
      }

      if (!githubId) {
        return errorResponse("无法获取 GitHub 用户标识", 400);
      }

      if (!email) {
        return errorResponse(
          "未能获取到 GitHub 邮箱，请在 GitHub 账户中公开邮箱或允许应用访问",
          400
        );
      }

      const normalizedEmail = email.toLowerCase();
      const clientIP =
        request.headers.get("CF-Connecting-IP") ||
        request.headers.get("X-Forwarded-For") ||
        request.headers.get("X-Real-IP") ||
        "unknown";
      const userAgent = request.headers.get("User-Agent") || "";

      let user: AuthUserRow | null = await this.db.db
        .prepare("SELECT * FROM users WHERE github_id = ?")
        .bind(githubId)
        .first<AuthUserRow | null>();

      if (!user) {
        const existingByEmail = await this.db.db
          .prepare("SELECT * FROM users WHERE email = ?")
          .bind(normalizedEmail)
          .first<AuthUserRow>();

        if (existingByEmail) {
          if (
            existingByEmail.github_id &&
            existingByEmail.github_id !== githubId
          ) {
            return errorResponse(
              "该邮箱已绑定其他 GitHub 账号，请使用原账号登录",
              409
            );
          }
          user = existingByEmail;
        }
      }

      let isNewUser = false;
      let tempPassword: string | null = null;
      let passwordEmailSent = false;

      if (!user) {
        const emailLocal = normalizedEmail.split("@")[0] || "";
        const usernameCandidates = [
          githubUser?.login,
          githubUser?.name,
          emailLocal,
          `github_${githubId.slice(-6)}`,
        ].filter((item): item is string => !!item && item.trim().length > 0);

        const pendingToken = await this.cachePendingOAuthRegistration({
          provider: "github",
          email: normalizedEmail,
          providerId: githubId,
          usernameCandidates,
          fallbackUsernameSeed: emailLocal || githubId.slice(-6),
          remember,
          clientIP,
          userAgent,
        });

        return successResponse({
          need_terms_agreement: true,
          pending_terms_token: pendingToken,
          provider: "github",
          profile: {
            email: normalizedEmail,
            username:
              usernameCandidates[0] ||
              emailLocal ||
              `github_${githubId.slice(-6)}`,
            avatar: githubUser?.avatar_url || "",
          },
        });
      } else {
        const now = "datetime('now', '+8 hours')";
        await this.db.db
          .prepare(
            `UPDATE users SET github_id = ?, oauth_provider = 'github', last_oauth_login_at = ${now}, first_oauth_login_at = COALESCE(first_oauth_login_at, ${now}) WHERE id = ?`
          )
          .bind(githubId, user.id)
          .run();

        await this.cache.deleteByPrefix(`user_${user.id}`);
      }

      if (!user) {
        return errorResponse("无法创建或加载用户信息", 500);
      }

      await this.db.db
        .prepare(
          `
        UPDATE users
        SET github_id = ?,
            oauth_provider = 'github',
            first_oauth_login_at = COALESCE(first_oauth_login_at, datetime('now', '+8 hours')),
            last_oauth_login_at = datetime('now', '+8 hours'),
            updated_at = datetime('now', '+8 hours')
        WHERE id = ?
      `
        )
        .bind(githubId, user.id)
        .run();

      user = await this.db.db
        .prepare("SELECT * FROM users WHERE id = ?")
        .bind(user.id)
        .first();

      if (await this.shouldRequireTwoFactor(user, trustToken)) {
        const challengeId = await this.createTwoFactorChallenge({
          userId: user.id,
          remember,
          loginMethod: "github_oauth",
          clientIP,
          userAgent,
          meta: {
            isNewUser,
            tempPassword,
            passwordEmailSent,
            provider: "github",
          },
        });
        return successResponse({
          need_2fa: true,
          challenge_id: challengeId,
          two_factor_enabled: true,
          isNewUser,
          tempPassword,
          passwordEmailSent,
          provider: "github",
        });
      }

      return this.finalizeLogin(user, remember, "github_oauth", clientIP, userAgent, {
        isNewUser,
        tempPassword,
        passwordEmailSent,
        provider: "github",
      });
    } catch (error) {
      this.logger.error("GitHub OAuth 登录失败", error);
      return errorResponse(
        error instanceof Error
          ? error.message
          : "GitHub 登录失败，请稍后重试",
        500
      );
    }
  }

  async register(request) {
    let createdUserId: number | null = null;
    try {
      const body = await request.json();
      const rawEmail =
        typeof body.email === "string" ? body.email.trim() : "";
      const email = rawEmail.toLowerCase();
      const username =
        typeof body.username === "string" ? body.username.trim() : "";
      const password =
        typeof body.password === "string" ? body.password : "";
      const verificationCode =
        typeof body.verificationCode === "string"
          ? body.verificationCode.trim()
          : typeof body.verification_code === "string"
          ? body.verification_code.trim()
          : "";
      const inviteCodeRaw =
        typeof body.inviteCode === "string"
          ? body.inviteCode
          : typeof body.invite_code === "string"
          ? body.invite_code
          : "";
      const inviteCode = this.referralService.normalizeInviteCode(inviteCodeRaw);

      if (!email || !username || !password) {
        return errorResponse("请填写邮箱、用户名和密码", 400);
      }

      if (!EMAIL_REGEX.test(email)) {
        return errorResponse("请输入有效的邮箱地址", 400);
      }

      if (this.isGmailAlias(email)) {
        return errorResponse(
          "暂不支持使用 Gmail 别名注册，请使用不含点和加号的原始邮箱地址",
          400
        );
      }

      // 获取系统配置
      const siteConfig = await this.db.db
        .prepare(
          "SELECT * FROM system_configs WHERE key IN ('register_enabled', 'default_traffic', 'default_expire_days', 'default_account_expire_days', 'default_class')"
        )
        .all<ConfigRow>();

      const config = new Map<string, string>();
      for (const item of siteConfig.results ?? []) {
        if (item?.key) {
          config.set(item.key, item.value ?? "");
        }
      }

      const registerMode = config.get("register_enabled") || "1";
      if (registerMode === "0") {
        return errorResponse("系统暂时关闭注册功能", 403);
      }

      let invitedBy = 0;
      if (inviteCode) {
        const inviterUser = await this.referralService.findInviterByCode(inviteCode);
        if (!inviterUser) {
          return errorResponse("邀请码无效或已失效，请确认后重试", 400);
        }
        invitedBy = ensureNumber(inviterUser.id);
        const canUseInvite = await this.referralService.isInviteAvailable(invitedBy);
        if (!canUseInvite) {
          return errorResponse("该邀请码使用次数已达上限，请联系邀请人", 400);
        }
      } else if (registerMode === "2") {
        return errorResponse("当前仅允许受邀注册，请填写有效邀请码", 403);
      }

      // 检查邮箱和用户名是否已存在
      const existingUser = await this.db.db
        .prepare("SELECT email, username FROM users WHERE email = ? OR username = ?")
        .bind(email, username)
        .first<UserEmailUsernameRow>();

      if (existingUser) {
        const existingEmail = ensureString(existingUser.email).toLowerCase();
        if (existingEmail === email) {
          return errorResponse("该邮箱已被注册，请使用其他邮箱或直接登录", 409);
        } else {
          return errorResponse("该用户名已被占用，请选择其他用户名", 409);
        }
      }

      const verificationSettings = await this.getVerificationSettings(
        PURPOSE_REGISTER
      );

      if (verificationSettings.enabled) {
        const validation = await this.validateVerificationCode(
          email,
          verificationCode,
          PURPOSE_REGISTER,
          verificationSettings
        );

        if (!validation.ok) {
          return validation.response;
        }
      }

      const registerIP =
        request.headers.get("CF-Connecting-IP") ||
        request.headers.get("X-Forwarded-For") ||
        request.headers.get("X-Real-IP") ||
        "unknown";

      await this.db.ensureUsersRegisterIpColumn();

      // 创建用户
      const hashedPassword = await hashPassword(password);
      const uuid = generateUUID();
      const proxyPassword = generateBase64Random(32);
      const subscriptionToken = generateRandomString(32);

      const stmt = this.db.db.prepare(`
        INSERT INTO users (
          email, username, password_hash, uuid, passwd, token,
          invited_by,
          transfer_enable, expire_time, class, class_expire_time, status, register_ip
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
      `);

      const transferEnableParsed = Number.parseInt(
        config.get("default_traffic") || "10737418240",
        10
      );
      const accountExpireDaysParsed = Number.parseInt(
        config.get("default_account_expire_days") || "3650",
        10
      );
      const classExpireDaysParsed = Number.parseInt(
        config.get("default_expire_days") || "30",
        10
      );
      const defaultClassParsed = Number.parseInt(
        config.get("default_class") || "1",
        10
      );

      const transferEnableValue = Number.isFinite(transferEnableParsed)
        ? transferEnableParsed
        : 10737418240;
      const accountExpireDays = Number.isFinite(accountExpireDaysParsed)
        ? accountExpireDaysParsed
        : 3650;
      const classExpireDays = Number.isFinite(classExpireDaysParsed)
        ? classExpireDaysParsed
        : 30;
      const defaultClassValue = Number.isFinite(defaultClassParsed)
        ? defaultClassParsed
        : 1;

      const accountExpireTime = new Date(
        Date.now() + 8 * 60 * 60 * 1000 + accountExpireDays * 24 * 60 * 60 * 1000
      )
        .toISOString()
        .replace("Z", "+08:00");
      const classExpireTime = new Date(
        Date.now() + 8 * 60 * 60 * 1000 + classExpireDays * 24 * 60 * 60 * 1000
      )
        .toISOString()
        .replace("Z", "+08:00");

      const insertResult = toRunResult(
        await stmt
        .bind(
          email,
          username,
          hashedPassword,
          uuid,
          proxyPassword,
          subscriptionToken,
          invitedBy,
          transferEnableValue,
          accountExpireTime,
          defaultClassValue,
          classExpireTime,
          registerIP
        )
        .run()
      );

      let userId = getLastRowId(insertResult);
      createdUserId = userId;

      if (userId === null) {
        const fallbackIdRow = await this.db.db
          .prepare("SELECT id FROM users WHERE email = ? ORDER BY id DESC LIMIT 1")
          .bind(email)
          .first<{ id: number } | null>();
        if (fallbackIdRow?.id) {
          userId = ensureNumber(fallbackIdRow.id, null);
          createdUserId = userId;
        }
      }

      if (userId === null) {
        return errorResponse("创建用户失败", 500);
      }

      const ensuredInviteCode = await this.referralService.ensureUserInviteCode(
        userId
      );
      await this.referralService.applyDefaultInviteLimit(userId);
      if (invitedBy > 0) {
        await this.referralService.saveReferralRelation({
          inviterId: invitedBy,
          inviteeId: userId,
          inviteCode: inviteCode || ensuredInviteCode,
          inviteIp: registerIP,
        });
        await this.referralService.incrementInviteUsage(invitedBy);
      }

      // 自动登录
      const token = await generateToken(
        { userId, email, isAdmin: false },
        this.env.JWT_SECRET
      );

      // 获取完整的用户数据用于会话
      const newUser = await this.db.db
        .prepare("SELECT * FROM users WHERE id = ?")
        .bind(userId)
        .first<AuthUserRow>();

      if (!newUser) {
        return errorResponse("获取用户信息失败", 500);
      }
      
      const sessionPayload = JSON.stringify({
        id: newUser.id,
        email: ensureString(newUser.email),
        username: ensureString(newUser.username),
        uuid: ensureString((newUser as any).uuid),
        passwd: ensureString((newUser as any).passwd),
        is_admin: ensureNumber(newUser.is_admin),
        class: ensureNumber((newUser as any).class),
        class_expire_time: ensureString(
          (newUser as Record<string, unknown>).class_expire_time as string | undefined
        ),
        upload_traffic: ensureNumber((newUser as any).upload_traffic),
        download_traffic: ensureNumber((newUser as any).download_traffic),
        upload_today: ensureNumber((newUser as any).upload_today),
        download_today: ensureNumber((newUser as any).download_today),
        transfer_total: ensureNumber((newUser as any).transfer_total),
        transfer_enable: ensureNumber((newUser as any).transfer_enable),
        expire_time: ensureString((newUser as any).expire_time),
        speed_limit: ensureNumber((newUser as any).speed_limit),
        device_limit: ensureNumber((newUser as any).device_limit),
        status: ensureNumber(newUser.status),
      });

      const defaultSessionTTL = 172800;
      try {
        await this.cache.set(`session_${token}`, sessionPayload, defaultSessionTTL);
      } catch (cacheError) {
        console.error("register session cache error:", cacheError);
      }

      try {
        await this.cache.deleteByPrefix("user_");
      } catch (cacheError) {
        console.error("register cache cleanup error:", cacheError);
      }

      try {
        await this.cleanupVerificationCodes(email, PURPOSE_REGISTER);
      } catch (cleanupError) {
        console.error("register cleanup verification code error:", cleanupError);
      }

      const newUserResponse = this.buildUserResponsePayload(newUser);

      return successResponse({
        message: "Registration successful",
        token,
        user: newUserResponse,
      });
    } catch (error) {
      console.error("Registration error:", error);
      if (createdUserId !== null) {
        try {
          const fallbackUser = await this.db.db
            .prepare("SELECT * FROM users WHERE id = ?")
            .bind(createdUserId)
            .first<AuthUserRow>();

          if (fallbackUser) {
            const fallbackToken = await generateToken(
              {
                userId: fallbackUser.id,
                email: ensureString(fallbackUser.email),
                isAdmin: false,
              },
              this.env.JWT_SECRET
            );
            const fallbackResponse = this.buildUserResponsePayload(
              fallbackUser
            );

            return successResponse({
              message: "Registration successful",
              token: fallbackToken,
              user: fallbackResponse,
              warnings: ["post_registration_noncritical_error"],
            });
          }
        } catch (fallbackError) {
          console.error("Registration fallback error:", fallbackError);
        }
      }
      return errorResponse(error.message, 500);
    }
  }

  async completePendingOAuthRegistration(request) {
    try {
      let body: any = {};
      try {
        body = await request.json();
      } catch (error) {
        this.logger.warn("解析 OAuth 完成请求失败", error);
      }

      const inviteCodeInput =
        typeof body.inviteCode === "string"
          ? body.inviteCode
          : typeof body.invite_code === "string"
          ? body.invite_code
          : "";
      const inviteCode = this.referralService.normalizeInviteCode(inviteCodeInput);
      const registerModeRaw = await this.configManager.getSystemConfig(
        "register_enabled",
        "1"
      );
      const registerMode = registerModeRaw || "1";

      const pendingToken = ensureString(
        body?.pendingToken || body?.pending_token
      );
      if (!pendingToken) {
        return errorResponse("缺少注册会话标识", 400);
      }

      const pending = await this.consumePendingOAuthRegistration(pendingToken);
      if (!pending) {
        return errorResponse("注册会话已过期，请重新登录并同意条款", 410);
      }

      const identifierField =
        pending.provider === "google" ? "google_sub" : "github_id";

      let user: AuthUserRow | null = await this.db.db
        .prepare(`SELECT * FROM users WHERE ${identifierField} = ?`)
        .bind(pending.providerId)
        .first<AuthUserRow | null>();

      if (!user) {
        const existingByEmail = await this.db.db
          .prepare("SELECT * FROM users WHERE email = ?")
          .bind(pending.email)
          .first<AuthUserRow | null>();

        if (
          existingByEmail &&
          existingByEmail[identifierField] &&
          ensureString(existingByEmail[identifierField]) !== pending.providerId
        ) {
          return errorResponse(
            "该邮箱已绑定其他第三方账号，请使用原账号登录",
            409
          );
        }

        user = existingByEmail;
      }

      let isNewUser = false;
      let tempPassword: string | null = null;
      let passwordEmailSent = false;

      let invitedBy = 0;
      let inviterUser: { id: number; invite_code: string } | null = null;

      if (!user) {
        if (registerMode === "0") {
          return errorResponse("系统暂时关闭注册功能", 403);
        }
        if (inviteCode) {
          inviterUser = await this.referralService.findInviterByCode(inviteCode);
          if (!inviterUser) {
            return errorResponse("邀请码无效或已失效，请联系邀请人", 400);
          }
          invitedBy = ensureNumber(inviterUser.id);
          const canUseInvite = await this.referralService.isInviteAvailable(invitedBy);
          if (!canUseInvite) {
            return errorResponse("该邀请码使用次数已达上限，请联系邀请人", 400);
          }
        } else if (registerMode === "2") {
          return errorResponse("当前仅允许受邀注册，请输入有效邀请码", 403);
        }

        const creationResult = await this.createOAuthUserFromPending(pending, {
          invitedBy,
          inviteCode: inviteCode || ensureString(inviterUser?.invite_code),
        });
        user = creationResult.user;
        tempPassword = creationResult.tempPassword;
        passwordEmailSent = creationResult.passwordEmailSent;
        isNewUser = true;
      } else {
        await this.cache.deleteByPrefix(`user_${user.id}`);
      }

      if (!user) {
        return errorResponse("无法创建或加载用户信息", 500);
      }

      await this.db.db
        .prepare(
          `
        UPDATE users
        SET ${identifierField} = ?,
            oauth_provider = ?,
            first_oauth_login_at = COALESCE(first_oauth_login_at, datetime('now', '+8 hours')),
            last_oauth_login_at = datetime('now', '+8 hours'),
            updated_at = datetime('now', '+8 hours')
        WHERE id = ?
      `
        )
        .bind(pending.providerId, pending.provider, user.id)
        .run();

      const refreshedUser = await this.db.db
        .prepare("SELECT * FROM users WHERE id = ?")
        .bind(user.id)
        .first<AuthUserRow | null>();

      if (!refreshedUser) {
        return errorResponse("无法加载用户信息", 500);
      }

      user = refreshedUser;

      if (await this.shouldRequireTwoFactor(user, "")) {
        const challengeId = await this.createTwoFactorChallenge({
          userId: user.id,
          remember: pending.remember,
          loginMethod: `${pending.provider}_oauth`,
          clientIP: pending.clientIP,
          userAgent: pending.userAgent,
          meta: {
            isNewUser,
            tempPassword,
            passwordEmailSent,
            provider: pending.provider,
          },
        });
        return successResponse({
          need_2fa: true,
          challenge_id: challengeId,
          two_factor_enabled: true,
          isNewUser,
          tempPassword,
          passwordEmailSent,
          provider: pending.provider,
        });
      }

      return this.finalizeLogin(
        user,
        pending.remember,
        `${pending.provider}_oauth`,
        pending.clientIP,
        pending.userAgent,
        {
          isNewUser,
          tempPassword,
          passwordEmailSent,
          provider: pending.provider,
        }
      );
    } catch (error) {
      this.logger.error("完成 OAuth 注册失败", error);
      return errorResponse(
        error instanceof Error ? error.message : "完成注册失败",
        500
      );
    }
  }

  async logout(request) {
    try {
      const authHeader = request.headers.get("Authorization");
      if (authHeader && authHeader.startsWith("Bearer ")) {
        const token = authHeader.substring(7);
        await this.cache.delete(`session_${token}`);
      }

      return successResponse({ message: "Logged out successfully" });
    } catch (error) {
      return errorResponse(error.message, 500);
    }
  }

}
