import type { Env } from "../types";
import { DatabaseService } from "../services/database";
import { validateUserAuth, validateAdminAuth } from "../middleware/auth";
import { successResponse, errorResponse } from "../utils/response";

type AuthSuccess = {
  success: true;
  user: { id: number; username?: string; email?: string; is_admin?: boolean };
};

type AuthFailure = { success: false; message: string };

type AuthResult = AuthSuccess | AuthFailure;

type TicketStatus = "open" | "answered" | "closed";

type TicketRow = {
  id: number;
  user_id: number;
  title: string;
  content: string;
  status: TicketStatus;
  last_reply_by_admin_id?: number | null;
  last_reply_at?: string | null;
  created_at: string;
  updated_at: string;
};

type TicketReplyRow = {
  id: number;
  ticket_id: number;
  author_id: number;
  author_role: "user" | "admin";
  content: string;
  created_at: string;
  author_username?: string | null;
  author_email?: string | null;
};

type TelegramTicketDispatchConfig = {
  token: string;
  apiBase: string;
  groupChatId: string;
};

type TelegramTicketTopicRow = {
  ticket_id?: number;
  group_chat_id?: string;
  message_thread_id?: number;
};

type TelegramUserRow = {
  username?: string | null;
  email?: string | null;
};

const MAX_TITLE_LENGTH = 120;
const MAX_CONTENT_LENGTH = 8000;
const TICKET_STATUSES: TicketStatus[] = ["open", "answered", "closed"];
const TELEGRAM_TOPIC_MAX_LEN = 128;
const TELEGRAM_GROUP_ID_REGEX = /^-?\d{5,20}$/;

const isAuthFailure = (result: AuthResult): result is AuthFailure => result.success === false;

export class TicketAPI {
  private readonly db: DatabaseService;
  private readonly env: Env;

  constructor(env: Env) {
    this.env = env;
    this.db = new DatabaseService(env.DB);
  }

  private async requireUser(request: Request): Promise<AuthResult> {
    return (await validateUserAuth(request, this.env)) as AuthResult;
  }

  private async requireAdmin(request: Request): Promise<AuthResult> {
    return (await validateAdminAuth(request, this.env)) as AuthResult;
  }

  private parseStatus(input: unknown): TicketStatus | null {
    if (!input || typeof input !== "string") {
      return null;
    }
    const normalized = input.trim().toLowerCase();
    return TICKET_STATUSES.includes(normalized as TicketStatus)
      ? (normalized as TicketStatus)
      : null;
  }

  private getPagination(url: URL) {
    const page = Math.max(1, Number.parseInt(url.searchParams.get("page") || "1", 10) || 1);
    const pageSize = Math.min(
      50,
      Math.max(5, Number.parseInt(url.searchParams.get("pageSize") || "10", 10) || 10)
    );
    const offset = (page - 1) * pageSize;
    return { page, pageSize, offset };
  }

  private extractTicketId(request: Request): number | null {
    const url = new URL(request.url);
    const match = url.pathname.match(/\/tickets\/(\d+)/);
    if (!match) {
      return null;
    }
    const ticketId = Number.parseInt(match[1], 10);
    return Number.isNaN(ticketId) ? null : ticketId;
  }

  private sanitizeText(input: unknown, maxLength: number) {
    if (!input || typeof input !== "string") {
      return "";
    }
    return input.trim().slice(0, maxLength);
  }

  private async getReplies(ticketId: number) {
    const replyResult = await this.db.db
      .prepare(
        `
          SELECT tr.id, tr.ticket_id, tr.author_id, tr.author_role, tr.content, tr.created_at,
                 u.username AS author_username, u.email AS author_email
          FROM ticket_replies tr
          LEFT JOIN users u ON tr.author_id = u.id
          WHERE tr.ticket_id = ?
          ORDER BY tr.created_at ASC
        `
      )
      .bind(ticketId)
      .all<TicketReplyRow>();

    const replies = replyResult.results ?? [];
    return replies.map((reply) => ({
      id: reply.id,
      content: reply.content,
      created_at: reply.created_at,
      author: {
        id: reply.author_id,
        role: reply.author_role,
        username: reply.author_username,
        email: reply.author_email,
      },
    }));
  }

  private buildTicketResponse(row: TicketRow, includeContent = false) {
    const base = {
      id: row.id,
      title: row.title,
      status: row.status,
      last_reply_at: row.last_reply_at,
      created_at: row.created_at,
      updated_at: row.updated_at,
    };

    if (includeContent) {
      return { ...base, content: row.content };
    }
    return base;
  }

  private normalizeTelegramGroupId(raw: unknown): string {
    if (typeof raw === "string") {
      const trimmed = raw.trim();
      return TELEGRAM_GROUP_ID_REGEX.test(trimmed) ? trimmed : "";
    }
    if (typeof raw === "number" && Number.isFinite(raw)) {
      const value = Math.trunc(raw).toString();
      return TELEGRAM_GROUP_ID_REGEX.test(value) ? value : "";
    }
    return "";
  }

  private normalizeTelegramThreadId(raw: unknown): number {
    if (typeof raw === "number" && Number.isFinite(raw) && raw > 0) {
      return Math.trunc(raw);
    }
    if (typeof raw === "string") {
      const parsed = Number.parseInt(raw.trim(), 10);
      if (Number.isFinite(parsed) && parsed > 0) {
        return parsed;
      }
    }
    return 0;
  }

  private limitText(value: string, maxLength: number): string {
    const trimmed = value.trim();
    if (!trimmed) return "";
    if (trimmed.length <= maxLength) return trimmed;
    return `${trimmed.slice(0, Math.max(1, maxLength - 3))}...`;
  }

  private buildTicketTopicName(ticketId: number, title: string): string {
    const prefix = `工单 #${ticketId}`;
    const compactTitle = title.replace(/\s+/g, " ").trim();
    if (!compactTitle) {
      return prefix;
    }
    const remain = TELEGRAM_TOPIC_MAX_LEN - prefix.length - 1;
    if (remain <= 0) {
      return prefix.slice(0, TELEGRAM_TOPIC_MAX_LEN);
    }
    return `${prefix} ${this.limitText(compactTitle, remain)}`.slice(0, TELEGRAM_TOPIC_MAX_LEN);
  }

  private async loadTelegramTicketDispatchConfig(): Promise<TelegramTicketDispatchConfig | null> {
    const rows = await this.db.db
      .prepare(
        `
          SELECT key, value
          FROM system_configs
          WHERE key IN ('telegram_bot_token', 'telegram_bot_api_base', 'telegram_ticket_group_id')
        `
      )
      .all<{ key?: string; value?: string }>();

    let token = "";
    let apiBase = "https://api.telegram.org";
    let groupChatId = "";
    for (const row of rows.results ?? []) {
      const key = typeof row?.key === "string" ? row.key.trim() : "";
      const value = typeof row?.value === "string" ? row.value.trim() : "";
      if (!key) continue;
      if (key === "telegram_bot_token" && value) {
        token = value;
      } else if (key === "telegram_bot_api_base" && value) {
        apiBase = value;
      } else if (key === "telegram_ticket_group_id" && value) {
        groupChatId = this.normalizeTelegramGroupId(value);
      }
    }

    if (!token || !groupChatId) {
      return null;
    }

    return { token, apiBase, groupChatId };
  }

  private async callTelegramApi<T>(
    config: TelegramTicketDispatchConfig,
    method: string,
    payload: Record<string, unknown>
  ): Promise<T | null> {
    const endpoint = `${config.apiBase.replace(/\/+$/, "")}/bot${config.token}/${method}`;
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "User-Agent": "Soga-Panel/1.0",
        },
        body: JSON.stringify(payload),
      });
      const body = (await response.json().catch(() => ({}))) as {
        ok?: boolean;
        result?: T;
        description?: string;
      };
      if (!response.ok || body.ok === false) {
        console.warn(
          `Telegram ${method} failed:`,
          response.status,
          body?.description || "unknown"
        );
        return null;
      }
      return (body.result as T | undefined) ?? null;
    } catch (error) {
      console.warn(`Telegram ${method} error:`, error);
      return null;
    }
  }

  private async getOrCreateTelegramTicketThread(
    config: TelegramTicketDispatchConfig,
    ticketId: number,
    ticketTitle: string
  ): Promise<number | null> {
    await this.db.ensureTelegramTicketTopicsTable();

    const existing = await this.db.db
      .prepare(
        `
          SELECT ticket_id, group_chat_id, message_thread_id
          FROM ticket_telegram_topics
          WHERE ticket_id = ? AND group_chat_id = ?
          LIMIT 1
        `
      )
      .bind(ticketId, config.groupChatId)
      .first<TelegramTicketTopicRow | null>();
    const existingThreadId = this.normalizeTelegramThreadId(existing?.message_thread_id);
    if (existingThreadId > 0) {
      return existingThreadId;
    }

    const topic = await this.callTelegramApi<{ message_thread_id?: number }>(
      config,
      "createForumTopic",
      {
        chat_id: config.groupChatId,
        name: this.buildTicketTopicName(ticketId, ticketTitle),
      }
    );
    const threadId = this.normalizeTelegramThreadId(topic?.message_thread_id);
    if (threadId <= 0) {
      return null;
    }

    await this.db.db
      .prepare(
        `
          INSERT INTO ticket_telegram_topics (
            ticket_id, group_chat_id, message_thread_id, created_at, updated_at
          )
          VALUES (?, ?, ?, datetime('now', '+8 hours'), datetime('now', '+8 hours'))
          ON CONFLICT(ticket_id) DO UPDATE SET
            group_chat_id = excluded.group_chat_id,
            message_thread_id = excluded.message_thread_id,
            updated_at = datetime('now', '+8 hours')
        `
      )
      .bind(ticketId, config.groupChatId, threadId)
      .run();

    return threadId;
  }

  private async resolveUserDisplay(userId: number, fallbackUsername?: string, fallbackEmail?: string) {
    if (fallbackUsername || fallbackEmail) {
      return {
        username: fallbackUsername?.trim() || `#${userId}`,
        email: fallbackEmail?.trim() || "-",
      };
    }
    const row = await this.db.db
      .prepare("SELECT username, email FROM users WHERE id = ? LIMIT 1")
      .bind(userId)
      .first<TelegramUserRow | null>();
    return {
      username: row?.username?.trim() || `#${userId}`,
      email: row?.email?.trim() || "-",
    };
  }

  private async sendTicketMessageToTelegramTopic(
    config: TelegramTicketDispatchConfig,
    ticketId: number,
    ticketTitle: string,
    text: string
  ) {
    const threadId = await this.getOrCreateTelegramTicketThread(config, ticketId, ticketTitle);
    if (!threadId) {
      return;
    }
    const messageText = this.limitText(text, 3800);
    const markdownResult = await this.callTelegramApi(
      config,
      "sendMessage",
      {
        chat_id: config.groupChatId,
        message_thread_id: threadId,
        text: messageText,
        parse_mode: "Markdown",
        disable_web_page_preview: true,
      }
    );
    if (markdownResult) {
      return;
    }
    await this.callTelegramApi(
      config,
      "sendMessage",
      {
        chat_id: config.groupChatId,
        message_thread_id: threadId,
        text: messageText,
        disable_web_page_preview: true,
      }
    );
  }

  private async forwardTicketCreatedToTelegram(
    ticketId: number,
    userId: number,
    title: string,
    content: string,
    fallbackUsername?: string,
    fallbackEmail?: string
  ) {
    const config = await this.loadTelegramTicketDispatchConfig();
    if (!config) {
      return;
    }
    const user = await this.resolveUserDisplay(userId, fallbackUsername, fallbackEmail);
    const text = [
      `📩 新工单 #${ticketId}`,
      `用户：${user.username} (ID: ${userId})`,
      `邮箱：${user.email}`,
      `标题：${title}`,
      "",
      "内容：",
      content,
    ].join("\n");
    await this.sendTicketMessageToTelegramTopic(config, ticketId, title, text);
  }

  private async forwardUserReplyToTelegram(
    ticketId: number,
    userId: number,
    title: string,
    content: string,
    fallbackUsername?: string
  ) {
    const config = await this.loadTelegramTicketDispatchConfig();
    if (!config) {
      return;
    }
    const user = await this.resolveUserDisplay(userId, fallbackUsername, undefined);
    const text = [
      `💬 用户回复工单 #${ticketId}`,
      `用户：${user.username} (ID: ${userId})`,
      "",
      content,
    ].join("\n");
    await this.sendTicketMessageToTelegramTopic(config, ticketId, title, text);
  }

  async createTicket(request: Request) {
    try {
      const auth = await this.requireUser(request);
      if (isAuthFailure(auth)) {
        return errorResponse(auth.message, 401);
      }

      let payload: Record<string, unknown> = {};
      try {
        payload = await request.json();
      } catch {
        return errorResponse("Invalid JSON payload", 400);
      }

      const title = this.sanitizeText(payload.title, MAX_TITLE_LENGTH);
      const content = this.sanitizeText(payload.content, MAX_CONTENT_LENGTH);

      if (!title) {
        return errorResponse("请填写工单标题", 400);
      }

      if (!content) {
        return errorResponse("请填写工单内容", 400);
      }

      const stmt = this.db.db.prepare(
        `
          INSERT INTO tickets (user_id, title, content, status, created_at, updated_at)
          VALUES (?, ?, ?, 'open', datetime('now', '+8 hours'), datetime('now', '+8 hours'))
        `
      );
      const result = await stmt.bind(auth.user.id, title, content).run();

      const ticket = await this.db.db
        .prepare(
          `
            SELECT id, user_id, title, content, status, last_reply_at, created_at, updated_at
            FROM tickets
            WHERE id = ?
          `
        )
        .bind(result.meta.last_row_id)
        .first<TicketRow | null>();

      const fallbackNow = new Date().toISOString();
      const responseTicket = ticket
        ? this.buildTicketResponse(ticket, true)
        : {
            id: Number(result.meta.last_row_id),
            title,
            content,
            status: "open" as TicketStatus,
            last_reply_at: null,
            created_at: fallbackNow,
            updated_at: fallbackNow,
          };

      const createdTicketId = Number(responseTicket.id || result.meta.last_row_id || 0);
      if (createdTicketId > 0) {
        try {
          await this.forwardTicketCreatedToTelegram(
            createdTicketId,
            auth.user.id,
            title,
            content,
            auth.user.username,
            auth.user.email
          );
        } catch (error) {
          console.warn("forwardTicketCreatedToTelegram error:", error);
        }
      }

      return successResponse(responseTicket, "工单创建成功");
    } catch (error: unknown) {
      console.error("createTicket error", error);
      return errorResponse("创建工单失败", 500);
    }
  }

  async listUserTickets(request: Request) {
    try {
      const auth = await this.requireUser(request);
      if (isAuthFailure(auth)) {
        return errorResponse(auth.message, 401);
      }

      const url = new URL(request.url);
      const { page, pageSize, offset } = this.getPagination(url);
      const filters = ["user_id = ?"];
      const bindings: Array<string | number> = [auth.user.id];

      const statusParam = this.parseStatus(url.searchParams.get("status"));
      if (statusParam) {
        filters.push("status = ?");
        bindings.push(statusParam);
      }

      const whereClause = filters.length ? `WHERE ${filters.join(" AND ")}` : "";

      const totalRow = await this.db.db
        .prepare(`SELECT COUNT(1) AS total FROM tickets ${whereClause}`)
        .bind(...bindings)
        .first<{ total: number } | null>();

      const listResult = await this.db.db
        .prepare(
          `
            SELECT id, user_id, title, content, status, last_reply_at, created_at, updated_at
            FROM tickets
            ${whereClause}
            ORDER BY updated_at DESC
            LIMIT ? OFFSET ?
          `
        )
        .bind(...bindings, pageSize, offset)
        .all<TicketRow>();

      const items = (listResult.results ?? []).map((row) => this.buildTicketResponse(row));

      return successResponse({
        items,
        pagination: {
          page,
          pageSize,
          total: totalRow?.total ?? 0,
        },
      });
    } catch (error: unknown) {
      console.error("listUserTickets error", error);
      return errorResponse("获取工单列表失败", 500);
    }
  }

  async getUserTicketDetail(request: Request) {
    try {
      const auth = await this.requireUser(request);
      if (isAuthFailure(auth)) {
        return errorResponse(auth.message, 401);
      }

      const ticketId = this.extractTicketId(request);
      if (!ticketId) {
        return errorResponse("无效的工单ID", 400);
      }

      const ticket = await this.db.db
        .prepare(
          `
            SELECT id, user_id, title, content, status, last_reply_at, created_at, updated_at
            FROM tickets
            WHERE id = ? AND user_id = ?
          `
        )
        .bind(ticketId, auth.user.id)
        .first<TicketRow | null>();

      if (!ticket) {
        return errorResponse("工单不存在或已删除", 404);
      }

      const replies = await this.getReplies(ticketId);
      return successResponse({
        ticket: this.buildTicketResponse(ticket, true),
        replies,
      });
    } catch (error: unknown) {
      console.error("getUserTicketDetail error", error);
      return errorResponse("获取工单详情失败", 500);
    }
  }

  async listAdminTickets(request: Request) {
    try {
      const auth = await this.requireAdmin(request);
      if (isAuthFailure(auth)) {
        return errorResponse(auth.message, 401);
      }

      const url = new URL(request.url);
      const { page, pageSize, offset } = this.getPagination(url);
      const filters: string[] = [];
      const bindings: Array<string | number> = [];

      const statusParam = this.parseStatus(url.searchParams.get("status"));
      if (statusParam) {
        filters.push("t.status = ?");
        bindings.push(statusParam);
      }

      const whereClause = filters.length ? `WHERE ${filters.join(" AND ")}` : "";

      const totalRow = await this.db.db
        .prepare(`SELECT COUNT(1) AS total FROM tickets t ${whereClause}`)
        .bind(...bindings)
        .first<{ total: number } | null>();

      const listResult = await this.db.db
        .prepare(
          `
            SELECT t.id, t.user_id, t.title, t.content, t.status, t.last_reply_at,
                   t.created_at, t.updated_at, u.username, u.email
            FROM tickets t
            LEFT JOIN users u ON t.user_id = u.id
            ${whereClause}
            ORDER BY t.updated_at DESC
            LIMIT ? OFFSET ?
          `
        )
        .bind(...bindings, pageSize, offset)
        .all<TicketRow & { username?: string | null; email?: string | null }>();

      const items =
        listResult.results?.map((row) => ({
          ...this.buildTicketResponse(row),
          user: {
            id: row.user_id,
            username: row.username,
            email: row.email,
          },
        })) ?? [];

      return successResponse({
        items,
        pagination: {
          page,
          pageSize,
          total: totalRow?.total ?? 0,
        },
      });
    } catch (error: unknown) {
      console.error("listAdminTickets error", error);
      return errorResponse("获取工单列表失败", 500);
    }
  }

  async getAdminTicketDetail(request: Request) {
    try {
      const auth = await this.requireAdmin(request);
      if (isAuthFailure(auth)) {
        return errorResponse(auth.message, 401);
      }

      const ticketId = this.extractTicketId(request);
      if (!ticketId) {
        return errorResponse("无效的工单ID", 400);
      }

      const ticket = await this.db.db
        .prepare(
          `
            SELECT t.id, t.user_id, t.title, t.content, t.status, t.last_reply_at,
                   t.created_at, t.updated_at, u.username, u.email
            FROM tickets t
            LEFT JOIN users u ON t.user_id = u.id
            WHERE t.id = ?
          `
        )
        .bind(ticketId)
        .first<(TicketRow & { username?: string | null; email?: string | null }) | null>();

      if (!ticket) {
        return errorResponse("工单不存在或已删除", 404);
      }

      const replies = await this.getReplies(ticketId);
      return successResponse({
        ticket: {
          ...this.buildTicketResponse(ticket, true),
          user: {
            id: ticket.user_id,
            username: ticket.username,
            email: ticket.email,
          },
        },
        replies,
      });
    } catch (error: unknown) {
      console.error("getAdminTicketDetail error", error);
      return errorResponse("获取工单详情失败", 500);
    }
  }

  async replyTicketAsAdmin(request: Request) {
    try {
      const auth = await this.requireAdmin(request);
      if (isAuthFailure(auth)) {
        return errorResponse(auth.message, 401);
      }

      const ticketId = this.extractTicketId(request);
      if (!ticketId) {
        return errorResponse("无效的工单ID", 400);
      }

      const ticket = await this.db.db
        .prepare("SELECT id FROM tickets WHERE id = ?")
        .bind(ticketId)
        .first<{ id: number } | null>();

      if (!ticket) {
        return errorResponse("工单不存在或已删除", 404);
      }

      let payload: Record<string, unknown> = {};
      try {
        payload = await request.json();
      } catch {
        return errorResponse("Invalid JSON payload", 400);
      }

      const content = this.sanitizeText(payload.content, MAX_CONTENT_LENGTH);
      if (!content) {
        return errorResponse("请填写回复内容", 400);
      }

      const nextStatus = this.parseStatus(payload.status) ?? "answered";

      await this.db.db
        .prepare(
          `
            INSERT INTO ticket_replies (ticket_id, author_id, author_role, content, created_at)
            VALUES (?, ?, 'admin', ?, datetime('now', '+8 hours'))
          `
        )
        .bind(ticketId, auth.user.id, content)
        .run();

      await this.db.db
        .prepare(
          `
            UPDATE tickets
            SET status = ?, last_reply_by_admin_id = ?, last_reply_at = datetime('now', '+8 hours'),
                updated_at = datetime('now', '+8 hours')
            WHERE id = ?
          `
        )
        .bind(nextStatus, auth.user.id, ticketId)
        .run();

      const replies = await this.getReplies(ticketId);
      return successResponse(
        {
          replies,
          status: nextStatus,
        },
        "回复已发送"
      );
    } catch (error: unknown) {
      console.error("replyTicket error", error);
      return errorResponse("回复工单失败", 500);
    }
  }

  async replyTicketAsUser(request: Request) {
    try {
      const auth = await this.requireUser(request);
      if (isAuthFailure(auth)) {
        return errorResponse(auth.message, 401);
      }

      const ticketId = this.extractTicketId(request);
      if (!ticketId) {
        return errorResponse("无效的工单ID", 400);
      }

      const ticket = await this.db.db
        .prepare("SELECT id, user_id, status, title FROM tickets WHERE id = ?")
        .bind(ticketId)
        .first<{ id: number; user_id: number; status: TicketStatus; title?: string } | null>();

      if (!ticket || ticket.user_id !== auth.user.id) {
        return errorResponse("工单不存在或无权访问", 404);
      }

      if (ticket.status === "closed") {
        return errorResponse("工单已关闭，无法继续回复", 400);
      }

      let payload: Record<string, unknown> = {};
      try {
        payload = await request.json();
      } catch {
        return errorResponse("Invalid JSON payload", 400);
      }

      const content = this.sanitizeText(payload.content, MAX_CONTENT_LENGTH);
      if (!content) {
        return errorResponse("请填写回复内容", 400);
      }

      await this.db.db
        .prepare(
          `
            INSERT INTO ticket_replies (ticket_id, author_id, author_role, content, created_at)
            VALUES (?, ?, 'user', ?, datetime('now', '+8 hours'))
          `
        )
        .bind(ticketId, auth.user.id, content)
        .run();

      await this.db.db
        .prepare(
          `
            UPDATE tickets
            SET status = 'open',
                updated_at = datetime('now', '+8 hours')
            WHERE id = ?
          `
        )
        .bind(ticketId)
        .run();

      try {
        await this.forwardUserReplyToTelegram(
          ticketId,
          auth.user.id,
          ticket.title || `工单 #${ticketId}`,
          content,
          auth.user.username
        );
      } catch (error) {
        console.warn("forwardUserReplyToTelegram error:", error);
      }

      const replies = await this.getReplies(ticketId);
      return successResponse({ replies, status: "open" as TicketStatus }, "回复已发送");
    } catch (error: unknown) {
      console.error("replyTicketAsUser error", error);
      return errorResponse("回复工单失败", 500);
    }
  }

  async updateTicketStatus(request: Request) {
    try {
      const auth = await this.requireAdmin(request);
      if (isAuthFailure(auth)) {
        return errorResponse(auth.message, 401);
      }

      const ticketId = this.extractTicketId(request);
      if (!ticketId) {
        return errorResponse("无效的工单ID", 400);
      }

      const ticket = await this.db.db
        .prepare("SELECT id FROM tickets WHERE id = ?")
        .bind(ticketId)
        .first<{ id: number } | null>();

      if (!ticket) {
        return errorResponse("工单不存在或已删除", 404);
      }

      let payload: Record<string, unknown> = {};
      try {
        payload = await request.json();
      } catch {
        return errorResponse("Invalid JSON payload", 400);
      }

      const status = this.parseStatus(payload.status);
      if (!status) {
        return errorResponse("状态不合法", 400);
      }

      await this.db.db
        .prepare(
          `
            UPDATE tickets
            SET status = ?, updated_at = datetime('now', '+8 hours')
            WHERE id = ?
          `
        )
        .bind(status, ticketId)
        .run();

      return successResponse({ status }, "工单状态已更新");
    } catch (error: unknown) {
      console.error("updateTicketStatus error", error);
      return errorResponse("更新工单状态失败", 500);
    }
  }

  async getUserUnreadCount(request: Request) {
    try {
      const auth = await this.requireUser(request);
      if (isAuthFailure(auth)) {
        return errorResponse(auth.message, 401);
      }

      const row = await this.db.db
        .prepare("SELECT COUNT(1) AS total FROM tickets WHERE user_id = ? AND status = 'answered'")
        .bind(auth.user.id)
        .first<{ total: number } | null>();

      return successResponse({ count: row?.total ?? 0 });
    } catch (error) {
      console.error("getUserUnreadCount error", error);
      return errorResponse("获取未读工单数量失败", 500);
    }
  }

  async getAdminPendingCount(request: Request) {
    try {
      const auth = await this.requireAdmin(request);
      if (isAuthFailure(auth)) {
        return errorResponse(auth.message, 401);
      }

      const row = await this.db.db
        .prepare("SELECT COUNT(1) AS total FROM tickets WHERE status = 'open'")
        .first<{ total: number } | null>();

      return successResponse({ count: row?.total ?? 0 });
    } catch (error) {
      console.error("getAdminPendingCount error", error);
      return errorResponse("获取待回复工单数量失败", 500);
    }
  }

  async closeTicketByUser(request: Request) {
    try {
      const auth = await this.requireUser(request);
      if (isAuthFailure(auth)) {
        return errorResponse(auth.message, 401);
      }

      const ticketId = this.extractTicketId(request);
      if (!ticketId) {
        return errorResponse("无效的工单ID", 400);
      }

      const ticket = await this.db.db
        .prepare("SELECT id, status FROM tickets WHERE id = ? AND user_id = ?")
        .bind(ticketId, auth.user.id)
        .first<{ id: number; status: TicketStatus } | null>();

      if (!ticket) {
        return errorResponse("工单不存在或无权操作", 404);
      }

      if (ticket.status === "closed") {
        return successResponse({ status: ticket.status }, "工单已关闭");
      }

      await this.db.db
        .prepare(
          `
            UPDATE tickets
            SET status = 'closed', updated_at = datetime('now', '+8 hours')
            WHERE id = ?
          `
        )
        .bind(ticketId)
        .run();

      return successResponse({ status: "closed" }, "工单已关闭");
    } catch (error: unknown) {
      console.error("closeTicketByUser error", error);
      return errorResponse("关闭工单失败", 500);
    }
  }
}
