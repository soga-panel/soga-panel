import type { Env } from "../types";
import { DatabaseService } from "../services/database";
import { AuthAPI } from "./auth";
import {
  createSystemConfigManager,
  type SystemConfigManager,
} from "../utils/systemConfig";
import { errorResponse, successResponse } from "../utils/response";
import { ensureNumber, ensureString } from "../utils/d1";
import {
  generateRandomString,
  hashPassword,
  verifyPassword,
} from "../utils/crypto";

type DbRow = Record<string, unknown>;

type TelegramMessage = {
  text?: string;
  message_id?: string | number | bigint;
  message_thread_id?: string | number | bigint;
  from?: {
    id?: string | number | bigint;
    is_bot?: boolean;
  };
  chat?: {
    id?: string | number | bigint;
    type?: string;
  };
};

type TelegramCallbackQuery = {
  id?: string;
  data?: string;
  message?: TelegramMessage;
};

type TelegramUpdate = {
  message?: TelegramMessage;
  edited_message?: TelegramMessage;
  callback_query?: TelegramCallbackQuery;
};

type TelegramBotConfig = {
  token: string;
  apiBase: string;
  webhookSecret: string;
};

type SubscriptionType =
  | "v2ray"
  | "clash"
  | "quantumultx"
  | "singbox"
  | "shadowrocket"
  | "surge";

type BoundTelegramUser = {
  id: number;
  email: string;
  username: string;
  class_level: number;
  class_expire_time: string;
  expire_time: string;
  transfer_total: number;
  transfer_enable: number;
  upload_today: number;
  download_today: number;
  status: number;
  token: string;
  telegram_enabled: number;
};

type TicketTopicBindingRow = {
  ticket_id?: number;
  group_chat_id?: string;
  message_thread_id?: number;
};

type TicketBasicRow = {
  id?: number;
  user_id?: number;
  title?: string;
  status?: string;
};

type TicketOperatorRow = {
  id?: number;
  is_admin?: number;
  username?: string;
};

type TelegramCommand = {
  name: string;
  arg: string;
};

type RegisterStage =
  | "captcha_pending"
  | "email_pending"
  | "username_pending"
  | "invite_pending"
  | "email_code_pending";

type TelegramRegisterSession = {
  chat_id: string;
  stage: RegisterStage;
  human_code_hash: string;
  human_code_expires_at: number;
  human_code_attempts: number;
  email: string;
  username: string;
  invite_code: string;
  email_code_attempts: number;
  session_expires_at: number;
};

const TELEGRAM_START_CODE_PATTERN = /^[A-Za-z0-9_-]{8,64}$/;
const REGISTER_EMAIL_REGEX =
  /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
const REGISTER_USERNAME_REGEX = /^[A-Za-z0-9_]{3,20}$/;
const LINK_CALLBACK_PREFIX = "link:";
const NOTIFY_CALLBACK_PREFIX = "notify:";
const REGISTER_CAPTCHA_TTL_SECONDS = 10 * 60;
const REGISTER_SESSION_TTL_SECONDS = 30 * 60;
const REGISTER_COMMAND_COOLDOWN_SECONDS = 30;
const REGISTER_EMAIL_CODE_MAX_ATTEMPTS = 5;
const REGISTER_HUMAN_CODE_MAX_ATTEMPTS = 5;
const REGISTER_HUMAN_CODE_LENGTH = 8;
const REGISTER_HUMAN_CODE_DIGITS = "23456789";
const REGISTER_HUMAN_CODE_LETTERS = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const REGISTER_HUMAN_CODE_CHARSET =
  `${REGISTER_HUMAN_CODE_DIGITS}${REGISTER_HUMAN_CODE_LETTERS}`;
const REGISTER_HUMAN_CODE_REGEX = /^[2-9A-HJ-NP-Z]+$/;
const REGISTER_CAPTCHA_CALLBACK_PREFIX = "regcap:";
const REGISTER_INVITE_SKIP_INPUTS = ["skip", "none", "-", "无", "跳过"];
const TELEGRAM_CHAT_ID_REGEX = /^-?\d{5,20}$/;
const SUBSCRIPTION_TYPES: { type: SubscriptionType; label: string }[] = [
  { type: "v2ray", label: "V2Ray" },
  { type: "clash", label: "Clash" },
  { type: "quantumultx", label: "QuantumultX" },
  { type: "singbox", label: "SingBox" },
  { type: "shadowrocket", label: "Shadowrocket" },
  { type: "surge", label: "Surge" },
];

function randomIndex(maxExclusive: number): number {
  if (maxExclusive <= 0) {
    throw new Error("Invalid maxExclusive");
  }
  const randomValue = new Uint8Array(1);
  crypto.getRandomValues(randomValue);
  return randomValue[0] % maxExclusive;
}

function generateRegisterHumanCode(length = REGISTER_HUMAN_CODE_LENGTH): string {
  if (length < 2) {
    throw new Error("Invalid register human code length");
  }

  const chars: string[] = [];
  // 保证至少包含 1 个数字和 1 个字母
  chars.push(
    REGISTER_HUMAN_CODE_DIGITS[randomIndex(REGISTER_HUMAN_CODE_DIGITS.length)]
  );
  chars.push(
    REGISTER_HUMAN_CODE_LETTERS[randomIndex(REGISTER_HUMAN_CODE_LETTERS.length)]
  );

  for (let i = 2; i < length; i += 1) {
    chars.push(
      REGISTER_HUMAN_CODE_CHARSET[randomIndex(REGISTER_HUMAN_CODE_CHARSET.length)]
    );
  }

  // Fisher-Yates 洗牌，避免前两位模式固定
  for (let i = chars.length - 1; i > 0; i -= 1) {
    const j = randomIndex(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.join("");
}

export class TelegramAPI {
  private readonly env: Env;
  private readonly db: DatabaseService;
  private readonly configManager: SystemConfigManager;
  private readonly authAPI: AuthAPI;

  constructor(env: Env) {
    this.env = env;
    this.db = new DatabaseService(env.DB);
    this.configManager = createSystemConfigManager(env);
    this.authAPI = new AuthAPI(env);
  }

  async handleWebhook(request: Request) {
    if (request.method === "GET") {
      return successResponse({ ok: true, message: "telegram webhook ready" });
    }

    if (request.method !== "POST") {
      return errorResponse("Method not allowed", 405);
    }

    try {
      await this.db.ensureUsersTelegramColumns();
      await this.db.ensureTelegramRegisterSessionTable();
      await this.db.ensureTelegramTicketTopicsTable();
      await this.db.cleanupExpiredTelegramRegisterSessions();

      const botConfig = await this.loadBotConfig();
      const providedSecret =
        request.headers.get("X-Telegram-Bot-Api-Secret-Token")?.trim() || "";
      if (
        botConfig.webhookSecret &&
        botConfig.webhookSecret !== providedSecret
      ) {
        return errorResponse("Unauthorized webhook request", 403);
      }

      const payload = (await request.json().catch(() => null)) as
        | TelegramUpdate
        | null;
      if (!payload) {
        return successResponse({ ok: true, skipped: "invalid_json" });
      }

      if (payload.callback_query) {
        return await this.handleCallbackQuery(payload.callback_query, botConfig, request);
      }

      const message = this.extractMessage(payload);
      if (!message) {
        return successResponse({ ok: true, skipped: "no_message" });
      }

      const chatId = this.normalizeChatId(message.chat?.id);
      if (!chatId) {
        return successResponse({ ok: true, skipped: "no_chat_id" });
      }

      const topicReplyHandled = await this.handleTicketTopicReply(
        message,
        chatId,
        botConfig
      );
      if (topicReplyHandled) {
        return topicReplyHandled;
      }

      if (!message.text) {
        return successResponse({ ok: true, skipped: "no_text_message" });
      }

      const command = this.parseCommand(message.text);
      if (!command) {
        const handled = await this.handleRegisterTextInput(
          chatId,
          message.text,
          botConfig,
          request
        );
        if (handled) return handled;
        return successResponse({ ok: true, skipped: "not_command" });
      }

      if (command.name === "start") {
        return await this.handleStartCommand(chatId, command.arg, botConfig);
      }

      if (command.name === "register") {
        return await this.handleRegisterCommand(chatId, command.arg, botConfig);
      }

      if (command.name === "info") {
        return await this.handleInfoCommand(chatId, botConfig);
      }

      if (command.name === "link") {
        return await this.handleSublinkCommand(chatId, botConfig, request);
      }
      if (command.name === "panel") {
        return await this.handlePanelCommand(chatId, botConfig, request);
      }
      if (command.name === "notify") {
        return await this.handleNotifyCommand(chatId, command.arg, botConfig);
      }
      if (command.name === "help") {
        return await this.handleHelpCommand(chatId, botConfig);
      }

      return successResponse({ ok: true, skipped: "unsupported_command" });
    } catch (error) {
      console.error("Telegram webhook error:", error);
      return errorResponse("Webhook 处理失败", 500);
    }
  }

  private async handleStartCommand(
    chatId: string,
    startPayload: string,
    botConfig: TelegramBotConfig
  ) {
    if (!startPayload) {
      const boundUser = await this.getBoundUserByChatId(chatId);
      if (boundUser) {
        const accountName =
          ensureString(boundUser.username, "").trim() || `#${boundUser.id}`;
        await this.sendMessageIfEnabled(
          botConfig,
          chatId,
          [
            `当前 Telegram 已绑定账号：${accountName}。`,
            "可发送 /info 查看账号信息，/panel 打开面板，/notify 管理通知。",
            "更多命令请发送 /help。",
          ].join("\n")
        );
        return successResponse({
          ok: true,
          skipped: "missing_bind_code_already_bound",
          user_id: boundUser.id,
        });
      }

        await this.sendMessageIfEnabled(
          botConfig,
          chatId,
          [
            "未检测到绑定码。",
            "如果你已有面板账号：请先在面板中点击 Telegram 绑定，并复制 /start 绑定码后再发送。",
            "如果你还没有账号：可发送 /register 进行注册。",
            "更多命令请发送 /help。",
          ].join("\n")
        );
      return successResponse({ ok: true, skipped: "missing_bind_code" });
    }

    if (!TELEGRAM_START_CODE_PATTERN.test(startPayload)) {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "绑定码格式无效，请回到面板重新获取绑定码。"
      );
      return successResponse({ ok: true, skipped: "invalid_bind_code" });
    }

    const now = Math.floor(Date.now() / 1000);
    const user = await this.db.db
      .prepare(
        `
          SELECT id, username, telegram_bind_code_expires_at
          FROM users
          WHERE telegram_bind_code = ?
          LIMIT 1
        `
      )
      .bind(startPayload)
      .first<DbRow | null>();

    if (!user) {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "绑定码无效或已失效，请回到面板刷新后重试。"
      );
      return successResponse({ ok: true, skipped: "bind_code_not_found" });
    }

    const userId = ensureNumber(user.id);
    const username = ensureString(user.username, "");
    const expiresAt = ensureNumber(user.telegram_bind_code_expires_at, 0);
    if (expiresAt <= now) {
      await this.db.db
        .prepare(
          `
            UPDATE users
            SET telegram_bind_code = NULL,
                telegram_bind_code_expires_at = NULL,
                updated_at = datetime('now', '+8 hours')
            WHERE id = ?
          `
        )
        .bind(userId)
        .run();

      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "绑定码已过期，请回到面板点击刷新绑定码后重试。"
      );
      return successResponse({ ok: true, skipped: "bind_code_expired" });
    }

    await this.db.db
      .prepare(
        `
          UPDATE users
          SET telegram_id = NULL,
              telegram_enabled = 0,
              updated_at = datetime('now', '+8 hours')
          WHERE telegram_id = ?
            AND id != ?
        `
      )
      .bind(chatId, userId)
      .run();

    await this.db.db
      .prepare(
        `
          UPDATE users
          SET telegram_id = ?,
              telegram_enabled = 1,
              telegram_bind_code = NULL,
              telegram_bind_code_expires_at = NULL,
              updated_at = datetime('now', '+8 hours')
          WHERE id = ?
        `
      )
      .bind(chatId, userId)
      .run();

    await this.sendMessageIfEnabled(
      botConfig,
      chatId,
      `绑定成功，账号 ${username || `#${userId}`} 已关联当前 Telegram。\n后续公告和每日流量提醒会通过机器人发送。`
    );

    return successResponse({ ok: true, bound_user_id: userId });
  }

  private async handleRegisterCommand(
    chatId: string,
    argText: string,
    botConfig: TelegramBotConfig
  ) {
    const boundUser = await this.getBoundUserByChatId(chatId);
    if (boundUser) {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "当前 Telegram 已绑定账号，如需新注册请先解绑或更换 Telegram 账号。"
      );
      return successResponse({ ok: true, skipped: "already_bound" });
    }

    const args = argText
      .trim()
      .split(/\s+/)
      .map((item) => item.trim())
      .filter(Boolean);

    if (args.length === 0) {
      const currentSession = await this.getRegisterSession(chatId);
      if (currentSession?.stage === "captcha_pending") {
        const now = Math.floor(Date.now() / 1000);
        const cooldownWindowEnd =
          ensureNumber(currentSession.human_code_expires_at, 0) -
          (REGISTER_CAPTCHA_TTL_SECONDS - REGISTER_COMMAND_COOLDOWN_SECONDS);
        if (cooldownWindowEnd > now) {
          const remaining = cooldownWindowEnd - now;
          await this.sendMessageIfEnabled(
            botConfig,
            chatId,
            `操作过于频繁，请 ${remaining} 秒后再试。\n你也可以直接点击上一条消息里的验证码按钮。`
          );
          return successResponse({ ok: true, skipped: "register_command_cooldown" });
        }
      }
      return this.startRegisterFlow(chatId, botConfig);
    }

    await this.sendMessageIfEnabled(
      botConfig,
      chatId,
      [
        "当前仅支持交互式注册，不需要在 /register 后附加参数。",
        "请直接发送 /register，然后按提示点击验证码按钮并继续下一步。",
      ].join("\n")
    );
    return successResponse({ ok: true, skipped: "register_args_not_supported" });
  }

  private async handleRegisterTextInput(
    chatId: string,
    messageText: string,
    botConfig: TelegramBotConfig,
    request: Request
  ): Promise<Response | null> {
    const session = await this.getRegisterSession(chatId);
    if (!session) {
      return null;
    }

    const text = messageText.trim();
    if (!text) {
      return successResponse({ ok: true, skipped: "empty_register_input" });
    }

    if (session.stage === "captcha_pending") {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "请点击验证码按钮完成人机验证；如按钮失效请发送 /register 重新开始。"
      );
      return successResponse({ ok: true, skipped: "awaiting_captcha_button" });
    }

    if (session.stage === "email_pending") {
      return this.handleRegisterEmailInput(chatId, text, botConfig);
    }

    if (session.stage === "username_pending") {
      return this.handleRegisterUsernameInput(chatId, text, botConfig);
    }

    if (session.stage === "invite_pending") {
      return this.handleRegisterInviteInput(chatId, text, botConfig, request);
    }

    if (session.stage === "email_code_pending") {
      if (/^\d{6}$/.test(text)) {
        return this.completeRegisterByEmailCode(chatId, text, botConfig, request);
      }

      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "请发送 6 位邮箱验证码。"
      );
      return successResponse({ ok: true, skipped: "awaiting_email_code" });
    }

    await this.sendMessageIfEnabled(botConfig, chatId, "注册会话状态异常，请重新发送 /register。");
    await this.clearRegisterSession(chatId);
    return successResponse({ ok: true, skipped: "invalid_register_stage" });
  }

  private async startRegisterFlow(chatId: string, botConfig: TelegramBotConfig) {
    const humanCode = generateRegisterHumanCode();
    const humanCodeHash = await hashPassword(humanCode);
    const now = Math.floor(Date.now() / 1000);

    await this.upsertRegisterSession(chatId, {
      stage: "captcha_pending",
      human_code_hash: humanCodeHash,
      human_code_expires_at: now + REGISTER_CAPTCHA_TTL_SECONDS,
      human_code_attempts: 0,
      email: "",
      username: "",
      invite_code: "",
      email_code_attempts: 0,
      session_expires_at: now + REGISTER_SESSION_TTL_SECONDS,
    });

    const captchaKeyboard = this.buildRegisterCaptchaKeyboard(humanCode);
    await this.sendMessageIfEnabled(
      botConfig,
      chatId,
      [
        `注册人机验证码：${humanCode}`,
        `请在 ${Math.floor(REGISTER_CAPTCHA_TTL_SECONDS / 60)} 分钟内点击下方正确验证码按钮。`,
        "",
        "发送 /register 可重新开始。",
      ].join("\n"),
      {
        inline_keyboard: captchaKeyboard,
      }
    );

    return successResponse({ ok: true, command: "register_init" });
  }

  private async verifyRegisterHumanCode(
    chatId: string,
    humanCodeRaw: string,
    botConfig: TelegramBotConfig
  ) {
    const session = await this.getRegisterSession(chatId);
    if (!session || session.stage !== "captcha_pending") {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "当前不在人机验证码步骤，请发送 /register 重新开始。"
      );
      return successResponse({ ok: true, skipped: "missing_register_session" });
    }

    const now = Math.floor(Date.now() / 1000);
    if (session.human_code_expires_at <= now) {
      await this.clearRegisterSession(chatId);
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "人机验证码已过期，请重新发送 /register 获取新验证码。"
      );
      return successResponse({ ok: true, skipped: "register_human_code_expired" });
    }

    const humanCode = humanCodeRaw.trim().toUpperCase();
    if (
      humanCode.length !== REGISTER_HUMAN_CODE_LENGTH ||
      !REGISTER_HUMAN_CODE_REGEX.test(humanCode)
    ) {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        `验证码格式无效，请输入 ${REGISTER_HUMAN_CODE_LENGTH} 位字母数字验证码。`
      );
      return successResponse({ ok: true, skipped: "register_human_code_format_invalid" });
    }
    const isHumanCodeValid = await verifyPassword(
      humanCode,
      ensureString(session.human_code_hash, "")
    );
    if (!isHumanCodeValid) {
      const nextAttempts = ensureNumber(session.human_code_attempts, 0) + 1;
      if (nextAttempts >= REGISTER_HUMAN_CODE_MAX_ATTEMPTS) {
        await this.clearRegisterSession(chatId);
        await this.sendMessageIfEnabled(
          botConfig,
          chatId,
          "人机验证码错误次数过多，已取消本次注册，请重新发送 /register。"
        );
        return successResponse({ ok: true, skipped: "register_human_code_locked" });
      }

      await this.upsertRegisterSession(chatId, {
        ...session,
        human_code_attempts: nextAttempts,
        session_expires_at: now + REGISTER_SESSION_TTL_SECONDS,
      });
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        `人机验证码错误，请重试（剩余 ${REGISTER_HUMAN_CODE_MAX_ATTEMPTS - nextAttempts} 次）。`
      );
      return successResponse({ ok: true, skipped: "register_human_code_invalid" });
    }

    await this.upsertRegisterSession(chatId, {
      ...session,
      stage: "email_pending",
      human_code_attempts: 0,
      session_expires_at: now + REGISTER_SESSION_TTL_SECONDS,
    });

    await this.sendMessageIfEnabled(botConfig, chatId, "人机验证通过，请输入注册邮箱：");
    return successResponse({ ok: true, command: "register_captcha_ok" });
  }

  private async handleRegisterEmailInput(
    chatId: string,
    emailRaw: string,
    botConfig: TelegramBotConfig
  ) {
    const session = await this.getRegisterSession(chatId);
    if (!session || session.stage !== "email_pending") {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "当前不在邮箱输入步骤，请发送 /register 重新开始。"
      );
      return successResponse({ ok: true, skipped: "missing_email_pending_session" });
    }

    const email = emailRaw.trim().toLowerCase();
    if (!REGISTER_EMAIL_REGEX.test(email)) {
      await this.sendMessageIfEnabled(botConfig, chatId, "邮箱格式无效，请重新输入邮箱。");
      return successResponse({ ok: true, skipped: "register_invalid_email" });
    }

    const now = Math.floor(Date.now() / 1000);
    await this.upsertRegisterSession(chatId, {
      ...session,
      stage: "username_pending",
      email,
      session_expires_at: now + REGISTER_SESSION_TTL_SECONDS,
    });
    await this.sendMessageIfEnabled(
      botConfig,
      chatId,
      "邮箱已记录，请输入用户名（3-20 位字母、数字、下划线）："
    );
    return successResponse({ ok: true, command: "register_email_ok", email });
  }

  private async handleRegisterUsernameInput(
    chatId: string,
    usernameRaw: string,
    botConfig: TelegramBotConfig
  ) {
    const session = await this.getRegisterSession(chatId);
    if (!session || session.stage !== "username_pending") {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "当前不在用户名输入步骤，请发送 /register 重新开始。"
      );
      return successResponse({ ok: true, skipped: "missing_username_pending_session" });
    }

    const username = usernameRaw.trim();
    if (!REGISTER_USERNAME_REGEX.test(username)) {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "用户名格式无效，仅支持 3-20 位字母、数字、下划线，请重新输入。"
      );
      return successResponse({ ok: true, skipped: "register_invalid_username" });
    }

    const now = Math.floor(Date.now() / 1000);
    await this.upsertRegisterSession(chatId, {
      ...session,
      stage: "invite_pending",
      username,
      session_expires_at: now + REGISTER_SESSION_TTL_SECONDS,
    });
    await this.sendMessageIfEnabled(
      botConfig,
      chatId,
      "如有邀请码请直接输入；没有可发送 `skip` / `无` 跳过。"
    );
    return successResponse({ ok: true, command: "register_username_ok", username });
  }

  private async handleRegisterInviteInput(
    chatId: string,
    inviteInputRaw: string,
    botConfig: TelegramBotConfig,
    request: Request
  ) {
    const session = await this.getRegisterSession(chatId);
    if (!session || session.stage !== "invite_pending") {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "当前不在邀请码输入步骤，请发送 /register 重新开始。"
      );
      return successResponse({ ok: true, skipped: "missing_invite_pending_session" });
    }

    const inviteInput = inviteInputRaw.trim();
    const inviteCode = REGISTER_INVITE_SKIP_INPUTS.includes(inviteInput.toLowerCase())
      ? ""
      : inviteInput;

    const email = ensureString(session.email, "").trim().toLowerCase();
    const username = ensureString(session.username, "").trim();
    if (!email || !username) {
      await this.clearRegisterSession(chatId);
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "注册会话信息不完整，请重新发送 /register。"
      );
      return successResponse({ ok: true, skipped: "register_profile_incomplete" });
    }

    const emailCodeResult = await this.sendRegisterEmailCodeByAuth(email, request);
    if (!emailCodeResult.ok) {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        `发送邮箱验证码失败：${emailCodeResult.message || "请稍后重试"}`
      );
      return successResponse({ ok: true, skipped: "register_email_code_send_failed" });
    }

    const now = Math.floor(Date.now() / 1000);
    const expireMinutes = ensureNumber(
      (emailCodeResult.data as { expire_minutes?: number } | undefined)?.expire_minutes,
      10
    );
    await this.upsertRegisterSession(chatId, {
      ...session,
      stage: "email_code_pending",
      invite_code: inviteCode,
      email_code_attempts: 0,
      session_expires_at: now + REGISTER_SESSION_TTL_SECONDS,
    });

    await this.sendMessageIfEnabled(
      botConfig,
      chatId,
      [
        `已向 ${email} 发送邮箱验证码（有效期约 ${expireMinutes} 分钟）。`,
        "请直接发送 6 位验证码完成注册。",
      ].join("\n")
    );
    return successResponse({
      ok: true,
      command: "register_email_code_sent",
      email,
      username,
    });
  }

  private async completeRegisterByEmailCode(
    chatId: string,
    emailCodeRaw: string,
    botConfig: TelegramBotConfig,
    request: Request
  ) {
    const session = await this.getRegisterSession(chatId);
    if (!session || session.stage !== "email_code_pending") {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "当前没有待完成的注册流程，请先发送 /register。"
      );
      return successResponse({ ok: true, skipped: "missing_email_code_session" });
    }

    const emailCode = emailCodeRaw.trim();
    if (!/^\d{6}$/.test(emailCode)) {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "邮箱验证码格式无效，请发送 6 位数字验证码。"
      );
      return successResponse({ ok: true, skipped: "invalid_email_code_format" });
    }

    const password = generateRandomString(16);
    const registerResult = await this.registerByAuth({
      request,
      email: ensureString(session.email, "").trim().toLowerCase(),
      username: ensureString(session.username, "").trim(),
      inviteCode: ensureString(session.invite_code, "").trim(),
      emailCode,
      password,
    });

    if (!registerResult.ok) {
      const nextAttempts = ensureNumber(session.email_code_attempts, 0) + 1;
      if (nextAttempts >= REGISTER_EMAIL_CODE_MAX_ATTEMPTS) {
        await this.clearRegisterSession(chatId);
        await this.sendMessageIfEnabled(
          botConfig,
          chatId,
          `注册失败：${registerResult.message || "邮箱验证码校验失败"}\n错误次数过多，已取消本次注册，请重新发送 /register。`
        );
        return successResponse({ ok: true, skipped: "register_email_code_locked" });
      }

      await this.upsertRegisterSession(chatId, {
        ...session,
        email_code_attempts: nextAttempts,
      });
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        `注册失败：${registerResult.message || "邮箱验证码校验失败"}\n请检查后重试（剩余 ${REGISTER_EMAIL_CODE_MAX_ATTEMPTS - nextAttempts} 次）。`
      );
      return successResponse({ ok: true, skipped: "register_email_code_invalid" });
    }

    await this.clearRegisterSession(chatId);
    await this.bindTelegramAfterRegister(chatId, registerResult.userId);

    await this.sendMessageIfEnabled(
      botConfig,
      chatId,
      [
        "注册成功，已自动绑定当前 Telegram。",
        `邮箱：${ensureString(session.email, "-")}`,
        `用户名：${ensureString(session.username, "-")}`,
        `初始密码：${password}`,
        "",
        "请立即登录面板并在个人资料中修改登录密码。",
      ].join("\n")
    );

    return successResponse({
      ok: true,
      command: "register_success",
      user_id: registerResult.userId,
    });
  }

  private async sendRegisterEmailCodeByAuth(email: string, request: Request) {
    const headers = new Headers();
    headers.set("Content-Type", "application/json");

    const forwardedHeaders = [
      "CF-Connecting-IP",
      "X-Forwarded-For",
      "X-Real-IP",
      "User-Agent",
    ];
    for (const key of forwardedHeaders) {
      const value = request.headers.get(key);
      if (value) {
        headers.set(key, value);
      }
    }

    const registerRequest = new Request(request.url, {
      method: "POST",
      headers,
      body: JSON.stringify({ email }),
    });

    const response = await this.authAPI.handleVerificationCodeRequest(
      registerRequest,
      {
        purpose: "register",
        disallowExistingUser: true,
      }
    );
    const payload = await this.readApiPayload(response);
    return {
      ok: payload.code === 0,
      message: payload.message,
      data: payload.data,
    };
  }

  private async registerByAuth(options: {
    request: Request;
    email: string;
    username: string;
    inviteCode: string;
    emailCode: string;
    password: string;
  }) {
    const headers = new Headers();
    headers.set("Content-Type", "application/json");

    const forwardedHeaders = [
      "CF-Connecting-IP",
      "X-Forwarded-For",
      "X-Real-IP",
      "User-Agent",
    ];
    for (const key of forwardedHeaders) {
      const value = options.request.headers.get(key);
      if (value) {
        headers.set(key, value);
      }
    }

    const registerBody: Record<string, unknown> = {
      email: options.email,
      username: options.username,
      password: options.password,
      verificationCode: options.emailCode,
    };
    if (options.inviteCode) {
      registerBody.inviteCode = options.inviteCode;
    }

    const registerRequest = new Request(options.request.url, {
      method: "POST",
      headers,
      body: JSON.stringify(registerBody),
    });

    const response = await this.authAPI.register(registerRequest);
    const payload = await this.readApiPayload(response);
    return {
      ok: payload.code === 0,
      message: payload.message,
      userId: ensureNumber(
        (payload.data as { user?: { id?: number } } | undefined)?.user?.id,
        0
      ),
    };
  }

  private async readApiPayload(response: Response): Promise<{
    code: number;
    message: string;
    data?: unknown;
  }> {
    const fallback = {
      code: response.status || 500,
      message: "请求失败",
      data: null,
    };
    try {
      const data = (await response.json().catch(() => null)) as {
        code?: number;
        message?: string;
        data?: unknown;
      } | null;
      if (!data || typeof data !== "object") {
        return fallback;
      }
      return {
        code: ensureNumber(data.code, response.ok ? 0 : response.status || 500),
        message: ensureString(data.message, response.ok ? "Success" : "请求失败"),
        data: data.data,
      };
    } catch {
      return fallback;
    }
  }

  private async bindTelegramAfterRegister(chatId: string, userId: number) {
    await this.db.db
      .prepare(
        `
          UPDATE users
          SET telegram_id = NULL,
              telegram_enabled = 0,
              updated_at = datetime('now', '+8 hours')
          WHERE telegram_id = ?
            AND id != ?
        `
      )
      .bind(chatId, userId)
      .run();

    await this.db.db
      .prepare(
        `
          UPDATE users
          SET telegram_id = ?,
              telegram_enabled = 1,
              telegram_bind_code = NULL,
              telegram_bind_code_expires_at = NULL,
              updated_at = datetime('now', '+8 hours')
          WHERE id = ?
        `
      )
      .bind(chatId, userId)
      .run();
  }

  private async getRegisterSession(
    chatId: string
  ): Promise<TelegramRegisterSession | null> {
    const row = await this.db.db
      .prepare(
        `
          SELECT chat_id, stage, human_code_hash, human_code_expires_at, human_code_attempts,
                 email, username, invite_code, email_code_attempts, session_expires_at
          FROM telegram_register_sessions
          WHERE chat_id = ?
          LIMIT 1
        `
      )
      .bind(chatId)
      .first<DbRow | null>();

    if (!row) {
      return null;
    }

    const session: TelegramRegisterSession = {
      chat_id: ensureString(row.chat_id, chatId),
      stage: (() => {
        const stage = ensureString(row.stage, "");
        if (
          stage === "captcha_pending" ||
          stage === "email_pending" ||
          stage === "username_pending" ||
          stage === "invite_pending" ||
          stage === "email_code_pending"
        ) {
          return stage;
        }
        return "captcha_pending";
      })(),
      human_code_hash: ensureString(row.human_code_hash, ""),
      human_code_expires_at: ensureNumber(row.human_code_expires_at, 0),
      human_code_attempts: ensureNumber(row.human_code_attempts, 0),
      email: ensureString(row.email, ""),
      username: ensureString(row.username, ""),
      invite_code: ensureString(row.invite_code, ""),
      email_code_attempts: ensureNumber(row.email_code_attempts, 0),
      session_expires_at: ensureNumber(row.session_expires_at, 0),
    };

    const now = Math.floor(Date.now() / 1000);
    if (session.session_expires_at <= now) {
      await this.clearRegisterSession(chatId);
      return null;
    }

    return session;
  }

  private async upsertRegisterSession(
    chatId: string,
    session: Omit<TelegramRegisterSession, "chat_id">
  ) {
    await this.db.db
      .prepare(
        `
          INSERT INTO telegram_register_sessions (
            chat_id, stage, human_code_hash, human_code_expires_at, human_code_attempts,
            email, username, invite_code, email_code_attempts, session_expires_at,
            created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+8 hours'), datetime('now', '+8 hours'))
          ON CONFLICT(chat_id) DO UPDATE SET
            stage = excluded.stage,
            human_code_hash = excluded.human_code_hash,
            human_code_expires_at = excluded.human_code_expires_at,
            human_code_attempts = excluded.human_code_attempts,
            email = excluded.email,
            username = excluded.username,
            invite_code = excluded.invite_code,
            email_code_attempts = excluded.email_code_attempts,
            session_expires_at = excluded.session_expires_at,
            updated_at = datetime('now', '+8 hours')
        `
      )
      .bind(
        chatId,
        session.stage,
        session.human_code_hash,
        session.human_code_expires_at,
        session.human_code_attempts,
        session.email,
        session.username,
        session.invite_code,
        session.email_code_attempts,
        session.session_expires_at
      )
      .run();
  }

  private async clearRegisterSession(chatId: string) {
    await this.db.db
      .prepare("DELETE FROM telegram_register_sessions WHERE chat_id = ?")
      .bind(chatId)
      .run();
  }

  private async handleInfoCommand(chatId: string, botConfig: TelegramBotConfig) {
    const user = await this.getBoundUserByChatId(chatId);
    if (!user) {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "当前 Telegram 未绑定账号，请先在面板点击绑定并发送 /start 绑定码。"
      );
      return successResponse({ ok: true, skipped: "not_bound" });
    }

    const total = Math.max(0, user.transfer_enable);
    const used = Math.max(0, user.transfer_total);
    const remain = total > 0 ? Math.max(0, total - used) : 0;
    const text = [
      "账号信息",
      `邮箱：${user.email || "-"}`,
      `用户名：${user.username || "-"}`,
      `会员等级：Lv.${user.class_level}`,
      `等级到期：${this.formatDateTime(user.class_expire_time)}`,
      `账户到期：${this.formatDateTime(user.expire_time)}`,
      "",
      "流量信息",
      `总额度：${total > 0 ? this.formatBytes(total) : "不限"}`,
      `已使用：${this.formatBytes(used)}`,
      `剩余流量：${total > 0 ? this.formatBytes(remain) : "不限"}`,
      `今日上行：${this.formatBytes(Math.max(0, user.upload_today))}`,
      `今日下行：${this.formatBytes(Math.max(0, user.download_today))}`,
    ].join("\n");

    await this.sendMessageIfEnabled(botConfig, chatId, text);
    return successResponse({ ok: true, command: "info", user_id: user.id });
  }

  private async handleSublinkCommand(
    chatId: string,
    botConfig: TelegramBotConfig,
    _request: Request
  ) {
    const user = await this.getBoundUserByChatId(chatId);
    if (!user) {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "当前 Telegram 未绑定账号，请先在面板点击绑定并发送 /start 绑定码。"
      );
      return successResponse({ ok: true, skipped: "not_bound" });
    }
    if (user.status !== 1) {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "当前账号不可用，请联系管理员。"
      );
      return successResponse({ ok: true, skipped: "user_disabled" });
    }
    if (!user.token) {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "未获取到订阅 token，请在面板中重置订阅后重试。"
      );
      return successResponse({ ok: true, skipped: "missing_token" });
    }

    const inlineKeyboard = this.buildSubscriptionKeyboard();
    await this.sendMessageIfEnabled(
      botConfig,
      chatId,
      "请选择订阅类型，点击按钮后会返回对应订阅链接：",
      {
        inline_keyboard: inlineKeyboard,
      }
    );
    return successResponse({ ok: true, command: "link", user_id: user.id });
  }

  private async handlePanelCommand(
    chatId: string,
    botConfig: TelegramBotConfig,
    request: Request
  ) {
    const user = await this.getBoundUserByChatId(chatId);
    if (!user) {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "当前 Telegram 未绑定账号，请先在面板点击绑定并发送 /start 绑定码。"
      );
      return successResponse({ ok: true, skipped: "not_bound" });
    }
    if (user.status !== 1) {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "当前账号不可用，请联系管理员。"
      );
      return successResponse({ ok: true, skipped: "user_disabled" });
    }

    const panelUrl = await this.resolveMiniAppUrl(request);
    const inlineKeyboard = [
      [
        {
          text: "打开面板",
          web_app: { url: panelUrl },
        },
      ],
    ];

    await this.sendMessageIfEnabled(
      botConfig,
      chatId,
      "点击下方按钮在 Telegram 内打开面板：",
      {
        inline_keyboard: inlineKeyboard,
      }
    );
    return successResponse({
      ok: true,
      command: "panel",
      user_id: user.id,
      panel_url: panelUrl,
    });
  }

  private async handleHelpCommand(chatId: string, botConfig: TelegramBotConfig) {
    await this.sendMessageIfEnabled(botConfig, chatId, this.buildHelpText());
    return successResponse({ ok: true, command: "help" });
  }

  private async handleNotifyCommand(
    chatId: string,
    argText: string,
    botConfig: TelegramBotConfig
  ) {
    const user = await this.getBoundUserByChatId(chatId);
    if (!user) {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "当前 Telegram 未绑定账号，请先在面板点击绑定并发送 /start 绑定码。"
      );
      return successResponse({ ok: true, skipped: "not_bound" });
    }

    const arg = argText.trim();
    const currentEnabled = user.telegram_enabled === 1;
    if (!arg) {
      await this.sendNotifyStatusMessage(chatId, currentEnabled, botConfig);
      return successResponse({
        ok: true,
        command: "notify_status",
        telegram_enabled: currentEnabled,
      });
    }

    const targetEnabled = this.parseNotifyCommandArg(arg);
    if (targetEnabled === null) {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "参数无效。请发送 /notify on 开启通知，或发送 /notify off 关闭通知。"
      );
      return successResponse({ ok: true, skipped: "notify_invalid_arg" });
    }

    if (targetEnabled === currentEnabled) {
      await this.sendNotifyStatusMessage(chatId, currentEnabled, botConfig);
      return successResponse({
        ok: true,
        command: "notify_no_change",
        telegram_enabled: currentEnabled,
      });
    }

    await this.updateTelegramNotifySetting(user.id, targetEnabled);
    await this.sendNotifyStatusMessage(chatId, targetEnabled, botConfig);

    return successResponse({
      ok: true,
      command: "notify_updated",
      telegram_enabled: targetEnabled,
      user_id: user.id,
    });
  }

  private async handleCallbackQuery(
    callbackQuery: TelegramCallbackQuery,
    botConfig: TelegramBotConfig,
    request: Request
  ) {
    const callbackId = ensureString(callbackQuery.id, "").trim();
    const data = ensureString(callbackQuery.data, "").trim();
    const chatId = this.normalizeChatId(callbackQuery.message?.chat?.id);
    const callbackMessageId = this.normalizeTelegramMessageId(
      callbackQuery.message?.message_id
    );

    if (!chatId) {
      if (callbackId) {
        await this.answerCallbackQuery(botConfig, callbackId, "未获取到聊天信息");
      }
      return successResponse({ ok: true, skipped: "callback_no_chat_id" });
    }

    if (data.startsWith(REGISTER_CAPTCHA_CALLBACK_PREFIX)) {
      return this.handleRegisterCaptchaCallback(chatId, data, callbackId, botConfig);
    }
    if (data.startsWith(NOTIFY_CALLBACK_PREFIX)) {
      return this.handleNotifyCallback(
        chatId,
        data,
        callbackId,
        callbackMessageId,
        botConfig
      );
    }

    if (!data.startsWith(LINK_CALLBACK_PREFIX)) {
      if (callbackId) {
        await this.answerCallbackQuery(botConfig, callbackId, "不支持的操作");
      }
      return successResponse({ ok: true, skipped: "unsupported_callback" });
    }

    const subType = data.slice(LINK_CALLBACK_PREFIX.length) as SubscriptionType;
    const target = SUBSCRIPTION_TYPES.find((item) => item.type === subType);
    if (!target) {
      if (callbackId) {
        await this.answerCallbackQuery(botConfig, callbackId, "不支持的订阅类型");
      }
      return successResponse({ ok: true, skipped: "invalid_subscription_type" });
    }

    const user = await this.getBoundUserByChatId(chatId);
    if (!user || !user.token) {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "当前 Telegram 未绑定可用账号，请先绑定后重试。"
      );
      if (callbackId) {
        await this.answerCallbackQuery(botConfig, callbackId, "当前未绑定可用账号");
      }
      return successResponse({ ok: true, skipped: "not_bound_or_missing_token" });
    }
    if (user.status !== 1) {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "当前账号不可用，请联系管理员。"
      );
      if (callbackId) {
        await this.answerCallbackQuery(botConfig, callbackId, "账号不可用");
      }
      return successResponse({ ok: true, skipped: "user_disabled" });
    }

    const baseUrl = await this.resolveSubscriptionBaseUrl(request);
    const link = this.buildSubscriptionLink(baseUrl, target.type, user.token);
    await this.sendMessageIfEnabled(
      botConfig,
      chatId,
      `${target.label} 订阅链接：\n${link}`
    );
    if (callbackId) {
      await this.answerCallbackQuery(botConfig, callbackId, `已返回 ${target.label} 链接`);
    }
    return successResponse({
      ok: true,
      command: "link_callback",
      type: target.type,
      user_id: user.id,
    });
  }

  private async handleNotifyCallback(
    chatId: string,
    callbackData: string,
    callbackId: string,
    callbackMessageId: number | null,
    botConfig: TelegramBotConfig
  ) {
    const raw = callbackData.slice(NOTIFY_CALLBACK_PREFIX.length).trim();
    const targetEnabled = this.parseNotifyCommandArg(raw);
    if (targetEnabled === null) {
      if (callbackId) {
        await this.answerCallbackQuery(botConfig, callbackId, "按钮参数无效");
      }
      return successResponse({ ok: true, skipped: "notify_invalid_callback_arg" });
    }

    const user = await this.getBoundUserByChatId(chatId);
    if (!user) {
      await this.sendMessageIfEnabled(
        botConfig,
        chatId,
        "当前 Telegram 未绑定账号，请先在面板点击绑定并发送 /start 绑定码。"
      );
      if (callbackId) {
        await this.answerCallbackQuery(botConfig, callbackId, "当前未绑定账号");
      }
      return successResponse({ ok: true, skipped: "not_bound" });
    }

    const currentEnabled = user.telegram_enabled === 1;
    if (targetEnabled !== currentEnabled) {
      await this.updateTelegramNotifySetting(user.id, targetEnabled);
    }
    if (callbackMessageId && callbackMessageId > 0) {
      await this.deleteMessageIfEnabled(botConfig, chatId, callbackMessageId);
    }
    await this.sendNotifyStatusMessage(chatId, targetEnabled, botConfig);

    if (callbackId) {
      await this.answerCallbackQuery(
        botConfig,
        callbackId,
        targetEnabled ? "已开启通知" : "已关闭通知"
      );
    }
    return successResponse({
      ok: true,
      command: "notify_callback",
      telegram_enabled: targetEnabled,
      user_id: user.id,
    });
  }

  private async handleRegisterCaptchaCallback(
    chatId: string,
    callbackData: string,
    callbackId: string,
    botConfig: TelegramBotConfig
  ) {
    const selectedCode = callbackData
      .slice(REGISTER_CAPTCHA_CALLBACK_PREFIX.length)
      .trim()
      .toUpperCase();

    if (
      selectedCode.length !== REGISTER_HUMAN_CODE_LENGTH ||
      !REGISTER_HUMAN_CODE_REGEX.test(selectedCode)
    ) {
      if (callbackId) {
        await this.answerCallbackQuery(botConfig, callbackId, "验证码按钮无效");
      }
      return successResponse({ ok: true, skipped: "invalid_captcha_callback_data" });
    }

    const response = await this.verifyRegisterHumanCode(
      chatId,
      selectedCode,
      botConfig
    );

    if (callbackId) {
      await this.answerCallbackQuery(botConfig, callbackId, "已提交验证");
    }
    return response;
  }

  private extractMessage(update: TelegramUpdate): TelegramMessage | null {
    if (update.message) return update.message;
    if (update.edited_message) return update.edited_message;
    return null;
  }

  private parseCommand(text: string): TelegramCommand | null {
    const trimmed = text.trim();
    const matched = trimmed.match(
      /^\/([A-Za-z0-9_]+)(?:@[A-Za-z0-9_]+)?(?:\s+(.+))?$/i
    );
    if (!matched) {
      return null;
    }

    const name = ensureString(matched[1], "").trim().toLowerCase();
    const arg = ensureString(matched[2], "").trim();
    if (!name) return null;
    return { name, arg };
  }

  private normalizeChatId(raw: unknown): string {
    if (typeof raw === "string") {
      return raw.trim();
    }
    if (typeof raw === "number" && Number.isFinite(raw)) {
      return Math.trunc(raw).toString();
    }
    if (typeof raw === "bigint") {
      return raw.toString();
    }
    return "";
  }

  private normalizeThreadId(raw: unknown): number {
    if (typeof raw === "number" && Number.isFinite(raw) && raw > 0) {
      return Math.trunc(raw);
    }
    if (typeof raw === "string") {
      const parsed = Number.parseInt(raw.trim(), 10);
      if (Number.isFinite(parsed) && parsed > 0) {
        return parsed;
      }
    }
    if (typeof raw === "bigint" && raw > 0n && raw <= BigInt(Number.MAX_SAFE_INTEGER)) {
      return Number(raw);
    }
    return 0;
  }

  private async loadTicketGroupChatId(): Promise<string> {
    const value = (
      await this.configManager.getSystemConfig("telegram_ticket_group_id", "")
    )?.trim() || "";
    if (!TELEGRAM_CHAT_ID_REGEX.test(value)) {
      return "";
    }
    return value;
  }

  private async handleTicketTopicReply(
    message: TelegramMessage,
    chatId: string,
    botConfig: TelegramBotConfig
  ): Promise<Response | null> {
    const ticketGroupChatId = await this.loadTicketGroupChatId();
    if (!ticketGroupChatId || chatId !== ticketGroupChatId) {
      return null;
    }

    const threadId = this.normalizeThreadId(message.message_thread_id);
    if (threadId <= 0) {
      return successResponse({ ok: true, skipped: "ticket_topic_missing_thread_id" });
    }

    if (message.from?.is_bot) {
      return successResponse({ ok: true, skipped: "ticket_topic_sender_is_bot" });
    }

    const replyText = ensureString(message.text, "").trim();
    if (!replyText) {
      return successResponse({ ok: true, skipped: "ticket_topic_empty_text" });
    }

    const operatorTelegramId = this.normalizeChatId(message.from?.id);
    if (!operatorTelegramId) {
      return successResponse({ ok: true, skipped: "ticket_topic_missing_sender_id" });
    }

    const operator = await this.db.db
      .prepare(
        `
          SELECT id, is_admin, username
          FROM users
          WHERE telegram_id = ?
          LIMIT 1
        `
      )
      .bind(operatorTelegramId)
      .first<TicketOperatorRow | null>();
    if (!operator || ensureNumber(operator.is_admin, 0) !== 1) {
      return successResponse({ ok: true, skipped: "ticket_topic_sender_not_admin" });
    }
    const operatorId = ensureNumber(operator.id, 0);
    if (operatorId <= 0) {
      return successResponse({ ok: true, skipped: "ticket_topic_invalid_admin_id" });
    }

    const topicBinding = await this.db.db
      .prepare(
        `
          SELECT ticket_id, group_chat_id, message_thread_id
          FROM ticket_telegram_topics
          WHERE group_chat_id = ? AND message_thread_id = ?
          LIMIT 1
        `
      )
      .bind(ticketGroupChatId, threadId)
      .first<TicketTopicBindingRow | null>();
    const ticketId = ensureNumber(topicBinding?.ticket_id, 0);
    if (ticketId <= 0) {
      return successResponse({ ok: true, skipped: "ticket_topic_not_mapped" });
    }

    const ticket = await this.db.db
      .prepare(
        `
          SELECT id, user_id, title, status
          FROM tickets
          WHERE id = ?
          LIMIT 1
        `
      )
      .bind(ticketId)
      .first<TicketBasicRow | null>();
    if (!ticket) {
      return successResponse({ ok: true, skipped: "ticket_topic_ticket_missing" });
    }

    await this.db.db
      .prepare(
        `
          INSERT INTO ticket_replies (ticket_id, author_id, author_role, content, created_at)
          VALUES (?, ?, 'admin', ?, datetime('now', '+8 hours'))
        `
      )
      .bind(ticketId, operatorId, replyText)
      .run();

    await this.db.db
      .prepare(
        `
          UPDATE tickets
          SET status = 'answered',
              last_reply_by_admin_id = ?,
              last_reply_at = datetime('now', '+8 hours'),
              updated_at = datetime('now', '+8 hours')
          WHERE id = ?
        `
      )
      .bind(operatorId, ticketId)
      .run();

    const ticketUserId = ensureNumber(ticket.user_id, 0);
    if (ticketUserId > 0) {
      const ticketOwner = await this.db.db
        .prepare("SELECT telegram_id FROM users WHERE id = ? LIMIT 1")
        .bind(ticketUserId)
        .first<{ telegram_id?: string | null } | null>();
      const ownerChatId = this.normalizeChatId(ticketOwner?.telegram_id);
      if (ownerChatId) {
        const operatorName =
          ensureString(operator.username, "").trim() || `#${operatorId}`;
        const ticketTitle = ensureString(ticket.title, "").trim();
        await this.sendMessageIfEnabled(
          botConfig,
          ownerChatId,
          [
            `你的工单 #${ticketId} 已收到客服回复。`,
            ticketTitle ? `标题：${ticketTitle}` : "",
            `回复人：${operatorName}`,
            "",
            replyText,
          ]
            .filter(Boolean)
            .join("\n")
        );
      }
    }

    return successResponse({
      ok: true,
      command: "ticket_topic_reply_forwarded",
      ticket_id: ticketId,
      operator_id: operatorId,
      thread_id: threadId,
    });
  }

  private async loadBotConfig(): Promise<TelegramBotConfig> {
    const token =
      (
        await this.configManager.getSystemConfig(
          "telegram_bot_token",
          ensureString(this.env.TELEGRAM_BOT_TOKEN, "")
        )
      )?.trim() || "";
    const apiBase =
      (
        await this.configManager.getSystemConfig(
          "telegram_bot_api_base",
          "https://api.telegram.org"
        )
      )?.trim() || "https://api.telegram.org";
    const webhookSecret =
      (
        await this.configManager.getSystemConfig(
          "telegram_webhook_secret",
          ensureString(this.env.TELEGRAM_WEBHOOK_SECRET, "")
        )
      )?.trim() || "";

    return {
      token,
      apiBase,
      webhookSecret,
    };
  }

  private async getBoundUserByChatId(chatId: string): Promise<BoundTelegramUser | null> {
    const user = await this.db.db
      .prepare(
        `
        SELECT id, email, username, class AS class_level, class_expire_time, expire_time,
               transfer_total, transfer_enable, upload_today, download_today, status, token, telegram_enabled
        FROM users
        WHERE telegram_id = ?
        LIMIT 1
      `
      )
      .bind(chatId)
      .first<DbRow | null>();
    if (!user) return null;

    return {
      id: ensureNumber(user.id, 0),
      email: ensureString(user.email, ""),
      username: ensureString(user.username, ""),
      class_level: ensureNumber(user.class_level, 0),
      class_expire_time: ensureString(user.class_expire_time, ""),
      expire_time: ensureString(user.expire_time, ""),
      transfer_total: ensureNumber(user.transfer_total, 0),
      transfer_enable: ensureNumber(user.transfer_enable, 0),
      upload_today: ensureNumber(user.upload_today, 0),
      download_today: ensureNumber(user.download_today, 0),
      status: ensureNumber(user.status, 0),
      token: ensureString(user.token, ""),
      telegram_enabled: ensureNumber(user.telegram_enabled, 0),
    };
  }

  private parseNotifyCommandArg(raw: string): boolean | null {
    const normalized = raw.trim().toLowerCase();
    if (
      normalized === "on" ||
      normalized === "enable" ||
      normalized === "enabled" ||
      normalized === "1" ||
      normalized === "true" ||
      normalized === "开" ||
      normalized === "开启"
    ) {
      return true;
    }
    if (
      normalized === "off" ||
      normalized === "disable" ||
      normalized === "disabled" ||
      normalized === "0" ||
      normalized === "false" ||
      normalized === "关" ||
      normalized === "关闭"
    ) {
      return false;
    }
    return null;
  }

  private normalizeTelegramMessageId(raw: unknown): number | null {
    if (typeof raw === "number" && Number.isFinite(raw) && raw > 0) {
      return Math.trunc(raw);
    }
    if (typeof raw === "string") {
      const parsed = Number.parseInt(raw.trim(), 10);
      if (Number.isFinite(parsed) && parsed > 0) {
        return parsed;
      }
    }
    if (typeof raw === "bigint" && raw > 0n && raw <= BigInt(Number.MAX_SAFE_INTEGER)) {
      return Number(raw);
    }
    return null;
  }

  private buildSubscriptionKeyboard() {
    const rows: { text: string; callback_data: string }[][] = [];
    for (let i = 0; i < SUBSCRIPTION_TYPES.length; i += 2) {
      const left = SUBSCRIPTION_TYPES[i];
      const right = SUBSCRIPTION_TYPES[i + 1];
      const row: { text: string; callback_data: string }[] = [
        {
          text: left.label,
          callback_data: `${LINK_CALLBACK_PREFIX}${left.type}`,
        },
      ];
      if (right) {
        row.push({
          text: right.label,
          callback_data: `${LINK_CALLBACK_PREFIX}${right.type}`,
        });
      }
      rows.push(row);
    }
    return rows;
  }

  private buildRegisterCaptchaKeyboard(correctCode: string) {
    const options = new Set<string>([correctCode]);
    while (options.size < 4) {
      const candidate = generateRegisterHumanCode();
      options.add(candidate);
    }

    const items = Array.from(options);
    for (let i = items.length - 1; i > 0; i -= 1) {
      const j = randomIndex(i + 1);
      [items[i], items[j]] = [items[j], items[i]];
    }

    return [
      items.slice(0, 2).map((code) => ({
        text: code,
        callback_data: `${REGISTER_CAPTCHA_CALLBACK_PREFIX}${code}`,
      })),
      items.slice(2, 4).map((code) => ({
        text: code,
        callback_data: `${REGISTER_CAPTCHA_CALLBACK_PREFIX}${code}`,
      })),
    ];
  }

  private buildNotifyToggleKeyboard(enabled: boolean) {
    return [
      [
        {
          text: `${enabled ? "✅ " : ""}开启通知`,
          callback_data: `${NOTIFY_CALLBACK_PREFIX}on`,
        },
        {
          text: `${!enabled ? "✅ " : ""}关闭通知`,
          callback_data: `${NOTIFY_CALLBACK_PREFIX}off`,
        },
      ],
    ];
  }

  private async sendNotifyStatusMessage(
    chatId: string,
    enabled: boolean,
    botConfig: TelegramBotConfig
  ) {
    await this.sendMessageIfEnabled(
      botConfig,
      chatId,
      [
        `当前 Telegram 通知：${enabled ? "已开启" : "已关闭"}。`,
        enabled
          ? "你将通过当前 Bot 接收公告和每日流量推送。"
          : "你将不会收到公告和每日流量推送。",
        "可直接点击下方按钮切换。",
      ].join("\n"),
      {
        inline_keyboard: this.buildNotifyToggleKeyboard(enabled),
      }
    );
  }

  private async updateTelegramNotifySetting(userId: number, enabled: boolean) {
    await this.db.db
      .prepare(
        `
          UPDATE users
          SET telegram_enabled = ?,
              updated_at = datetime('now', '+8 hours')
          WHERE id = ?
        `
      )
      .bind(enabled ? 1 : 0, userId)
      .run();
  }

  private buildHelpText(): string {
    return [
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
    ].join("\n");
  }

  private async resolveMiniAppUrl(request: Request): Promise<string> {
    const miniAppUrl = (
      await this.configManager.getSystemConfig(
        "telegram_miniapp_url",
        ensureString(this.env.TELEGRAM_MINIAPP_URL, "")
      )
    ).trim();
    if (miniAppUrl) {
      return this.normalizeMiniAppUrl(miniAppUrl);
    }

    const siteUrl = (
      await this.configManager.getSystemConfig(
        "site_url",
        ensureString(this.env.SITE_URL, "")
      )
    ).trim();
    if (siteUrl) {
      return this.normalizeMiniAppUrl(siteUrl);
    }

    return this.normalizeMiniAppUrl(new URL(request.url).origin);
  }

  private normalizeMiniAppUrl(rawUrl: string): string {
    const trimmed = rawUrl.trim();
    if (!trimmed) {
      return "";
    }

    try {
      const url = new URL(trimmed);
      if (!url.pathname || url.pathname === "/") {
        url.pathname = "/auth/login";
      }
      url.searchParams.set("tgMiniApp", "1");
      url.hash = "";
      return url.toString();
    } catch {
      const normalized = trimmed.replace(/\/+$/, "");
      if (/\/auth\/login(?:\?|$)/.test(normalized)) {
        return normalized.includes("?")
          ? `${normalized}&tgMiniApp=1`
          : `${normalized}?tgMiniApp=1`;
      }
      return `${normalized}/auth/login?tgMiniApp=1`;
    }
  }

  private async resolveSubscriptionBaseUrl(request: Request): Promise<string> {
    const subscriptionUrl = (
      await this.configManager.getSystemConfig("subscription_url", "")
    )
      .trim();
    if (subscriptionUrl) {
      return subscriptionUrl.replace(/\/+$/, "");
    }

    const siteUrl = (
      await this.configManager.getSystemConfig(
        "site_url",
        ensureString(this.env.SITE_URL, "")
      )
    ).trim();
    if (siteUrl) {
      return siteUrl.replace(/\/+$/, "");
    }

    return new URL(request.url).origin.replace(/\/+$/, "");
  }

  private buildSubscriptionLink(baseUrl: string, type: SubscriptionType, token: string): string {
    return `${baseUrl}/api/subscription/${type}?token=${encodeURIComponent(token)}`;
  }

  private formatDateTime(value: string): string {
    const trimmed = value.trim();
    if (!trimmed) return "永久";
    const date = new Date(trimmed);
    if (Number.isNaN(date.getTime())) return trimmed;
    return date.toLocaleString("zh-CN", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  }

  private formatBytes(bytes: number): string {
    if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB", "PB"];
    let value = bytes;
    let unitIndex = 0;
    while (value >= 1024 && unitIndex < units.length - 1) {
      value /= 1024;
      unitIndex++;
    }
    const precision = value >= 100 ? 0 : value >= 10 ? 1 : 2;
    return `${value.toFixed(precision)} ${units[unitIndex]}`;
  }

  private async sendMessageIfEnabled(
    botConfig: TelegramBotConfig,
    chatId: string,
    text: string,
    replyMarkup?: Record<string, unknown>
  ) {
    if (!botConfig.token) {
      return;
    }

    try {
      const endpoint = `${botConfig.apiBase.replace(/\/+$/, "")}/bot${botConfig.token}/sendMessage`;
      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "User-Agent": "Soga-Panel/1.0",
        },
        body: JSON.stringify({
          chat_id: chatId,
          text,
          disable_web_page_preview: true,
          ...(replyMarkup ? { reply_markup: replyMarkup } : {}),
        }),
      });
      if (!response.ok) {
        console.error(
          "Telegram webhook reply failed:",
          response.status,
          await response.text().catch(() => "")
        );
      }
    } catch (error) {
      console.error("Telegram webhook reply error:", error);
    }
  }

  private async deleteMessageIfEnabled(
    botConfig: TelegramBotConfig,
    chatId: string,
    messageId: number
  ) {
    if (!botConfig.token || !chatId || !Number.isFinite(messageId) || messageId <= 0) {
      return;
    }

    try {
      const endpoint = `${botConfig.apiBase.replace(/\/+$/, "")}/bot${botConfig.token}/deleteMessage`;
      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "User-Agent": "Soga-Panel/1.0",
        },
        body: JSON.stringify({
          chat_id: chatId,
          message_id: messageId,
        }),
      });
      if (!response.ok) {
        console.warn(
          "Telegram deleteMessage failed:",
          response.status,
          await response.text().catch(() => "")
        );
      }
    } catch (error) {
      console.warn("Telegram deleteMessage error:", error);
    }
  }

  private async answerCallbackQuery(
    botConfig: TelegramBotConfig,
    callbackQueryId: string,
    text?: string
  ) {
    if (!botConfig.token || !callbackQueryId) {
      return;
    }

    try {
      const endpoint = `${botConfig.apiBase.replace(/\/+$/, "")}/bot${botConfig.token}/answerCallbackQuery`;
      await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "User-Agent": "Soga-Panel/1.0",
        },
        body: JSON.stringify({
          callback_query_id: callbackQueryId,
          text: text || "",
          show_alert: false,
        }),
      });
    } catch (error) {
      console.error("Telegram answerCallbackQuery error:", error);
    }
  }
}
