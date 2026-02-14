import { Router, type Request, type Response } from "express";
import type { AppContext } from "../../types";
import { createAuthMiddleware } from "../../middleware/auth";
import { errorResponse, successResponse } from "../../utils/response";
import { generateRandomString } from "../../utils/crypto";
import { hashPassword, verifyPassword } from "../../utils/crypto";
import { ReferralService } from "../../services/referral";
import { TrafficService } from "../../services/traffic";
import { TicketService } from "../../services/ticket";
import { UserAuditService } from "../../services/userAudit";
import { TwoFactorService } from "../../services/twoFactor";
import { ensureNumber, ensureString } from "../../utils/d1";
import {
  formatRemoteAccountIdForResponse,
  parseRemoteAccountIdList,
} from "../../utils/sharedIds";

export function createUserRouter(ctx: AppContext) {
  const router = Router();
  router.use(createAuthMiddleware(ctx));
  const referralService = new ReferralService(ctx.dbService);
  const trafficService = new TrafficService(ctx.dbService);
  const ticketService = new TicketService(ctx.dbService);
  const auditService = new UserAuditService(ctx.dbService);
  const twoFactorService = new TwoFactorService(ctx.env);

  const toNumber = (value: unknown, fallback = 0): number => ensureNumber(value, fallback);
  const toText = (value: unknown, fallback = ""): string => ensureString(value, fallback);

  const verifyUserTwoFactorCode = async (userRow: any, code: string) => {
    if (!code) return { success: false, usedBackup: false };
    const trimmed = code.trim();
    const secret = await twoFactorService.decryptSecret(userRow.two_factor_secret);
    if (secret) {
      const ok = await twoFactorService.verifyTotp(secret, trimmed);
      if (ok) return { success: true, usedBackup: false };
    }
    const normalized = twoFactorService.normalizeBackupCodeInput(trimmed);
    if (!normalized || normalized.length < 6) return { success: false, usedBackup: false };
    const hashedInput = await twoFactorService.hashBackupCode(normalized);
    const stored = twoFactorService.parseBackupCodes(userRow.two_factor_backup_codes);
    const idx = stored.findIndex((h) => h === hashedInput);
    if (idx === -1) return { success: false, usedBackup: false };
    stored.splice(idx, 1);
    await ctx.dbService.db
      .prepare("UPDATE users SET two_factor_backup_codes = ? WHERE id = ?")
      .bind(JSON.stringify(stored), userRow.id)
      .run();
    userRow.two_factor_backup_codes = JSON.stringify(stored);
    return { success: true, usedBackup: true };
  };

  router.get("/profile", async (req: Request, res: Response) => {
    const user = (req as any).user;
    if (!user?.id) {
      return errorResponse(res, "未登录", 401);
    }
    const dbUser = await ctx.dbService.getUserById(Number(user.id));
    if (!dbUser) {
      return errorResponse(res, "用户不存在", 404);
    }

    const transferEnable = Number(dbUser.transfer_enable ?? 0);
    const transferUsed = Number(dbUser.transfer_total ?? 0);
    const transferRemain = Math.max(0, transferEnable - transferUsed);
    const trafficPercentage = transferEnable > 0 ? Math.round((transferUsed / transferEnable) * 100) : 0;
    const isExpired = dbUser.expire_time ? new Date(dbUser.expire_time).getTime() < Date.now() : false;
    const daysRemaining =
      dbUser.expire_time && !Number.isNaN(new Date(dbUser.expire_time).getTime())
        ? Math.max(0, Math.ceil((new Date(dbUser.expire_time).getTime() - Date.now()) / (1000 * 60 * 60 * 24)))
        : null;

    const configs = await ctx.dbService.listSystemConfigsMap();
    const trafficResetDay = Number(configs["traffic_reset_day"] ?? 0);
    let subscriptionUrl = configs["subscription_url"] || configs["site_url"] || ctx.env.SITE_URL || "";

    // 补全订阅 URL
    if (!subscriptionUrl && ctx.env.SITE_URL) {
      subscriptionUrl = ctx.env.SITE_URL;
    }

    return successResponse(res, {
      id: dbUser.id,
      email: dbUser.email,
      username: dbUser.username,
      uuid: dbUser.uuid,
      passwd: dbUser.passwd,
      token: dbUser.token,
      is_admin: Boolean(dbUser.is_admin),
      class: dbUser.class,
      class_expire_time: dbUser.class_expire_time,
      expire_time: dbUser.expire_time,
      is_expired: isExpired,
      days_remaining: daysRemaining,
      speed_limit: dbUser.speed_limit,
      device_limit: dbUser.device_limit,
      tcp_limit: dbUser.tcp_limit,
      upload_traffic: Number(dbUser.upload_traffic ?? 0),
      download_traffic: Number(dbUser.download_traffic ?? 0),
      upload_today: Number(dbUser.upload_today ?? 0),
      download_today: Number(dbUser.download_today ?? 0),
      transfer_total: transferUsed,
      transfer_enable: transferEnable,
      transfer_remain: transferRemain,
      traffic_percentage: trafficPercentage,
      reg_date: dbUser.reg_date,
      last_login_time: dbUser.last_login_time,
      last_login_ip: dbUser.last_login_ip,
      status: dbUser.status,
      traffic_reset_day: trafficResetDay,
      subscription_url: subscriptionUrl,
      two_factor_enabled: Number(dbUser.two_factor_enabled) === 1,
      has_two_factor_backup_codes: Boolean(dbUser.two_factor_backup_codes)
    });
  });

  router.get("/passkeys", async (req: Request, res: Response) => {
    const user = (req as any).user;
    if (!user?.id) return errorResponse(res, "未登录", 401);
    const list = await ctx.dbService.listPasskeys(Number(user.id));
    return successResponse(res, { items: list });
  });

  router.delete("/passkeys/:id", async (req: Request, res: Response) => {
    const user = (req as any).user;
    if (!user?.id) return errorResponse(res, "未登录", 401);
    const id = ensureString(req.params?.id);
    if (!id) return errorResponse(res, "缺少凭证ID", 400);

    const del = await ctx.dbService.db
      .prepare("DELETE FROM passkeys WHERE user_id = ? AND credential_id = ?")
      .bind(user.id, id)
      .run();
    const changes = (del.meta as any)?.changes ?? (del as any)?.changes;
    if (!changes) return errorResponse(res, "未找到要删除的通行密钥", 404);
    return successResponse(res, { removed: id });
  });

  router.put("/profile", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const { username, email } = req.body || {};

    const current = await ctx.dbService.getUserById(Number(user.id));
    if (!current) {
      return errorResponse(res, "用户不存在", 404);
    }

    const currentUsername = ensureString(current.username);
    const currentEmail = ensureString(current.email);

    const hasUsernameInput = typeof username === "string";
    const hasEmailInput = typeof email === "string";

    const nextUsername = hasUsernameInput ? ensureString(username).trim() : currentUsername;
    const nextEmailRaw = hasEmailInput ? ensureString(email).trim() : currentEmail;
    const nextEmail = nextEmailRaw ? nextEmailRaw.toLowerCase() : nextEmailRaw;

    const isUsernameChanged = hasUsernameInput && nextUsername !== currentUsername;
    const isEmailChanged = hasEmailInput && nextEmail !== currentEmail.toLowerCase();

    if (isUsernameChanged && isEmailChanged) {
      return errorResponse(res, "不能同时修改用户名和邮箱，请分别修改", 400);
    }

    const updates: { username?: string; email?: string } = {};

    if (isUsernameChanged) {
      if (!nextUsername) {
        return errorResponse(res, "用户名不能为空", 400);
      }
      const exists = await ctx.dbService.getUserByUsername(nextUsername);
      if (exists && Number(exists.id) !== Number(user.id)) {
        return errorResponse(res, "用户名已被占用", 400);
      }
      updates.username = nextUsername;
    }

    if (isEmailChanged) {
      if (!nextEmail) {
        return errorResponse(res, "邮箱不能为空", 400);
      }
      const existsEmail = await ctx.dbService.getUserByEmail(nextEmail);
      if (existsEmail && Number(existsEmail.id) !== Number(user.id)) {
        return errorResponse(res, "该邮箱已被使用，请选择其他邮箱", 400);
      }
      updates.email = nextEmail;
    }

    if (!updates.username && !updates.email) {
      return errorResponse(res, "没有需要更新的字段", 400);
    }

    await ctx.dbService.updateUserProfile(Number(user.id), updates);
    return successResponse(res, null, "资料已更新");
  });

  router.get("/nodes", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const page = Number(req.query.page ?? 1) || 1;
    const limit = Math.min(Number(req.query.limit ?? 10) || 10, 200);
    const typeFilter = typeof req.query.type === "string" ? req.query.type.toLowerCase() : "";
    const statusFilterRaw = req.query.status;
    const statusFilter =
      statusFilterRaw === undefined || statusFilterRaw === null || statusFilterRaw === ""
        ? null
        : String(statusFilterRaw) === "1";

    const userRow = await ctx.dbService.getUserById(Number(user.id));
    if (!userRow) return errorResponse(res, "用户不存在", 404);
    const userClass = Number(userRow?.class ?? 0);

    const filters: string[] = ["status = 1"];
    const values: any[] = [];
    if (typeFilter) {
      filters.push("LOWER(type) = ?");
      values.push(typeFilter);
    }
    const where = `WHERE ${filters.join(" AND ")}`;
    const offset = (page - 1) * limit;

    const totalRow = await ctx.db
      .prepare("SELECT COUNT(*) as total FROM nodes WHERE status = 1")
      .first<{ total?: number }>();
    const filteredTotalRow = await ctx.db
      .prepare(`SELECT COUNT(*) as total FROM nodes ${where}`)
      .bind(...values)
      .first<{ total?: number }>();
    const accessibleRow = await ctx.db
      .prepare("SELECT COUNT(*) as total FROM nodes WHERE status = 1 AND node_class <= ?")
      .bind(userClass)
      .first<{ total?: number }>();
    const onlineRow = await ctx.db
      .prepare(
        `
        SELECT COUNT(DISTINCT ns.node_id) as total
        FROM node_status ns
        INNER JOIN nodes n ON ns.node_id = n.id
        WHERE ns.created_at >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)
          AND n.status = 1
      `
      )
      .first<{ total?: number }>();

    const rows = await ctx.db
      .prepare(
        `
        SELECT * FROM nodes
        ${where}
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
      `
      )
      .bind(...values, limit, offset)
      .all();

    const parseNodeConfig = (raw: any) => {
      try {
        return typeof raw === "string" ? JSON.parse(raw || "{}") : raw || {};
      } catch (error) {
        console.warn("parse node_config failed", error);
        return {};
      }
    };

    const nodes =
      (rows.results || []).map((node: any) => {
        const parsed = parseNodeConfig(node.node_config);
        const cfg = (parsed as any)?.config || parsed || {};
        const client = (parsed as any)?.client || {};
        const server = client.server || "";
        const port = Number(client.port || cfg.port || 0) || 0;
        const tlsHost = client.tls_host || cfg.host || server;
        return {
          ...node,
          server,
          server_port: port || 443,
          tls_host: tlsHost,
          config: parsed
        };
      }) || [];

    // 填充在线状态与用户在节点的流量
    const enriched = await Promise.all(
      nodes.map(async (node: any) => {
        const traffic = await ctx.db
          .prepare(
            `
            SELECT 
              COALESCE(SUM(upload_traffic), 0) as upload_traffic,
              COALESCE(SUM(download_traffic), 0) as download_traffic,
              COALESCE(SUM(upload_traffic + download_traffic), 0) as total_traffic,
              COALESCE(SUM(actual_upload_traffic), 0) as actual_upload_traffic,
              COALESCE(SUM(actual_download_traffic), 0) as actual_download_traffic,
              COALESCE(SUM(actual_traffic), 0) as actual_total_traffic
            FROM traffic_logs
            WHERE user_id = ? AND node_id = ?
          `
          )
          .bind(user.id, node.id)
          .first<{
            upload_traffic?: number;
            download_traffic?: number;
            total_traffic?: number;
            actual_upload_traffic?: number;
            actual_download_traffic?: number;
            actual_total_traffic?: number;
          }>();

        const onlineRow = await ctx.db
          .prepare(
            `
            SELECT COUNT(*) as total FROM node_status 
            WHERE node_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)
          `
          )
          .bind(node.id)
          .first<{ total?: number }>();

        return {
          ...node,
          user_upload_traffic: Number(traffic?.upload_traffic ?? 0),
          user_download_traffic: Number(traffic?.download_traffic ?? 0),
          user_total_traffic: Number(traffic?.actual_total_traffic ?? traffic?.total_traffic ?? 0),
          user_raw_total_traffic: Number(traffic?.total_traffic ?? 0),
          user_actual_upload_traffic: Number(traffic?.actual_upload_traffic ?? 0),
          user_actual_download_traffic: Number(traffic?.actual_download_traffic ?? 0),
          user_actual_total_traffic: Number(traffic?.actual_total_traffic ?? 0),
          tags: ["等级" + node.node_class],
          is_online: Number(onlineRow?.total ?? 0) > 0
        };
      })
    );

    let filtered = enriched;
    if (statusFilter !== null) {
      filtered = filtered.filter((n) => (statusFilter ? n.is_online : !n.is_online));
    }

    const totalEnabled = Number(totalRow?.total ?? 0);
    const filteredTotal = Number(filteredTotalRow?.total ?? 0);
    const totalOnline = Number(onlineRow?.total ?? 0);
    const accessibleTotal = Number(accessibleRow?.total ?? 0);
    const offlineCount = Math.max(0, totalEnabled - totalOnline);
    const total = statusFilter !== null ? filtered.length : filteredTotal;
    return successResponse(res, {
      nodes: filtered,
      statistics: {
        total: totalEnabled,
        online: totalOnline,
        offline: offlineCount,
        accessible: accessibleTotal
      },
      pagination: {
        total,
        page,
        limit
      }
    });
  });

  router.post("/reset-subscription-token", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const newToken = generateRandomString(32);
    await ctx.dbService.resetSubscriptionToken(Number(user.id), newToken);
    return successResponse(res, { token: newToken }, "订阅 Token 已重置");
  });

  router.get("/login-logs", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const limit = Number(req.query.limit ?? 20) || 20;
    const logs = await ctx.dbService.listLoginLogs(Number(user.id), Math.min(limit, 100));
    return successResponse(res, logs);
  });

  router.post("/change-password", async (req: Request, res: Response) => {
    const user = (req as any).user;
    // 前端传 current_password/new_password
    const { old_password, new_password, current_password } = req.body || {};
    const current = old_password || current_password;
    if (!current || !new_password) return errorResponse(res, "参数缺失", 400);

    const dbUser = await ctx.dbService.getUserById(Number(user.id));
    if (!dbUser) return errorResponse(res, "用户不存在", 404);

    const ok = verifyPassword(current, String(dbUser.password_hash || ""));
    if (!ok) return errorResponse(res, "原密码错误", 400);

    await ctx.dbService.updateUserPassword(Number(user.id), hashPassword(new_password));
    return successResponse(res, null, "密码已更新");
  });

  // 2FA: 获取密钥/二维码
  router.post("/two-factor/setup", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const userRow = await ctx.dbService.getUserById(Number(user.id));
    if (!userRow) return errorResponse(res, "用户不存在", 404);
    if (Number(userRow.two_factor_enabled) === 1 && userRow.two_factor_secret) {
      return errorResponse(res, "二步验证已启用", 400);
    }

    const secret = twoFactorService.generateSecret(32);
    const encryptedSecret = await twoFactorService.encryptSecret(secret);
    await ctx.dbService.db
      .prepare("UPDATE users SET two_factor_temp_secret = ? WHERE id = ?")
      .bind(encryptedSecret, userRow.id)
      .run();

    const account = ensureString(userRow.email) || ensureString(userRow.username) || `user_${userRow.id}`;
    const issuer = ctx.env.SITE_NAME || "Soga Panel";
    const otpAuthUrl = twoFactorService.createOtpAuthUrl(secret, account, issuer);
    return successResponse(res, {
      secret,
      otp_auth_url: otpAuthUrl,
      provisioning_uri: otpAuthUrl
    });
  });

  // 2FA: 启用
  router.post("/two-factor/enable", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const { code } = req.body || {};
    if (!code) return errorResponse(res, "请输入验证码", 400);

    const userRow = await ctx.dbService.getUserById(Number(user.id));
    if (!userRow) return errorResponse(res, "用户不存在", 404);
    if (!userRow.two_factor_temp_secret) return errorResponse(res, "请先获取新的密钥", 400);

    const tempSecret = await twoFactorService.decryptSecret(userRow.two_factor_temp_secret);
    if (!tempSecret) return errorResponse(res, "临时密钥无效，请重新生成", 400);

    const ok = await twoFactorService.verifyTotp(tempSecret, String(code));
    if (!ok) return errorResponse(res, "验证码无效，请重试", 401);

    const backupCodes = twoFactorService.generateBackupCodes();
    const hashed = await twoFactorService.hashBackupCodes(backupCodes);

    await ctx.dbService.db
      .prepare(
        `
        UPDATE users
        SET two_factor_enabled = 1,
            two_factor_secret = two_factor_temp_secret,
            two_factor_backup_codes = ?,
            two_factor_temp_secret = NULL,
            two_factor_confirmed_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `
      )
      .bind(JSON.stringify(hashed), user.id)
      .run();

    return successResponse(res, { backup_codes: backupCodes }, "二步验证已启用");
  });

  // 2FA: 重新生成备用码
  router.post("/two-factor/backup-codes", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const { code } = req.body || {};
    if (!code) return errorResponse(res, "请输入验证码", 400);
    const userRow = await ctx.dbService.getUserById(Number(user.id));
    if (!userRow || Number(userRow.two_factor_enabled) !== 1) {
      return errorResponse(res, "尚未启用二步验证", 400);
    }
    const verification = await verifyUserTwoFactorCode(userRow, String(code));
    if (!verification.success) return errorResponse(res, "验证码无效，请重试", 401);

    const backupCodes = twoFactorService.generateBackupCodes();
    const hashed = await twoFactorService.hashBackupCodes(backupCodes);
    await ctx.dbService.db
      .prepare("UPDATE users SET two_factor_backup_codes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
      .bind(JSON.stringify(hashed), user.id)
      .run();

    return successResponse(res, { backup_codes: backupCodes }, "已生成新的备用验证码");
  });

  // 2FA: 关闭
  router.post("/two-factor/disable", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const { password, code } = req.body || {};
    if (!password || !code) return errorResponse(res, "请输入密码和验证码", 400);

    const userRow = await ctx.dbService.getUserById(Number(user.id));
    if (!userRow || Number(userRow.two_factor_enabled) !== 1) {
      return errorResponse(res, "尚未启用二步验证", 400);
    }
    const passwordOk = verifyPassword(String(password), String(userRow.password_hash || ""));
    if (!passwordOk) return errorResponse(res, "密码错误", 401);

    const verification = await verifyUserTwoFactorCode(userRow, String(code));
    if (!verification.success) return errorResponse(res, "验证码无效，请重试", 401);

    await ctx.dbService.db
      .prepare(
        `
        UPDATE users
        SET two_factor_enabled = 0,
            two_factor_secret = NULL,
            two_factor_backup_codes = NULL,
            two_factor_temp_secret = NULL,
            two_factor_confirmed_at = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `
      )
      .bind(user.id)
      .run();

    return successResponse(res, null, "二步验证已关闭");
  });

  router.get("/subscription-logs", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const page = Number(req.query.page ?? 1) || 1;
    const limit = Math.min(Number(req.query.limit ?? 20) || 20, 200);
    const type = typeof req.query.type === "string" ? req.query.type : undefined;
    const offset = (page - 1) * limit;
    const filters: string[] = ["user_id = ?"];
    const values: any[] = [user.id];
    if (type) {
      filters.push("type = ?");
      values.push(type);
    }
    const where = `WHERE ${filters.join(" AND ")}`;
    const rows = await ctx.dbService.db
      .prepare(
        `
        SELECT id, user_id, type, request_ip, request_time, request_user_agent
        FROM subscriptions
        ${where}
        ORDER BY request_time DESC
        LIMIT ? OFFSET ?
      `
      )
      .bind(...values, limit, offset)
      .all();
    const totalRow = await ctx.dbService.db
      .prepare(`SELECT COUNT(*) as total FROM subscriptions ${where}`)
      .bind(...values)
      .first<{ total?: number }>();
    const total = Number(totalRow?.total ?? 0);
    return successResponse(res, {
      data: rows.results || [],
      total,
      page,
      limit,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.max(1, Math.ceil(total / limit))
      }
    });
  });

  router.get("/traffic-records", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const page = Math.max(1, Number(req.query.page ?? 1) || 1);
    const limit = Math.min(Math.max(1, Number(req.query.limit ?? 20) || 20), 200);
    const offset = (page - 1) * limit;
    const startDate = typeof req.query.start_date === "string" ? req.query.start_date.trim() : "";
    const endDate = typeof req.query.end_date === "string" ? req.query.end_date.trim() : "";
    const normalizeTime = (value: string) => value.replace(/\+/g, " ").trim();
    const startTime =
      typeof req.query.start_time === "string" ? normalizeTime(req.query.start_time) : "";
    const endTime =
      typeof req.query.end_time === "string" ? normalizeTime(req.query.end_time) : "";
    const nodeName = typeof req.query.node_name === "string" ? req.query.node_name.trim() : "";
    const nodeIdRaw = typeof req.query.node_id === "string" ? Number(req.query.node_id) : NaN;
    const nodeId = Number.isFinite(nodeIdRaw) ? nodeIdRaw : 0;
    const hasTimeRange = Boolean(startTime || endTime);
    const hasNodeFilter = Boolean(nodeName || nodeId);

    const filters: string[] = ["tl.user_id = ?"];
    const values: any[] = [Number(user.id)];
    if (startDate) {
      filters.push("tl.date >= ?");
      values.push(startDate);
    }
    if (endDate) {
      filters.push("tl.date <= ?");
      values.push(endDate);
    }
    if (startTime) {
      filters.push("tl.created_at >= ?");
      values.push(startTime);
    }
    if (endTime) {
      filters.push("tl.created_at <= ?");
      values.push(endTime);
    }
    if (nodeId) {
      filters.push("tl.node_id = ?");
      values.push(nodeId);
    }
    if (nodeName) {
      filters.push("n.name LIKE ?");
      values.push(`%${nodeName}%`);
    }
    const whereClause = `WHERE ${filters.join(" AND ")}`;
    const countJoinClause = nodeName ? "LEFT JOIN nodes n ON n.id = tl.node_id" : "";

    const totalRow = await ctx.dbService.db
      .prepare(`SELECT COUNT(*) as total FROM traffic_logs tl ${countJoinClause} ${whereClause}`)
      .bind(...values)
      .first<{ total?: number | string | null }>();
    const trafficTotal = Number(totalRow?.total ?? 0);

    if (trafficTotal === 0 && !hasTimeRange && !hasNodeFilter) {
      const dailyFilters: string[] = ["dt.user_id = ?"];
      const dailyValues: any[] = [Number(user.id)];
      if (startDate) {
        dailyFilters.push("dt.record_date >= ?");
        dailyValues.push(startDate);
      }
      if (endDate) {
        dailyFilters.push("dt.record_date <= ?");
        dailyValues.push(endDate);
      }
      const dailyWhere = `WHERE ${dailyFilters.join(" AND ")}`;
      const dailyRows = await ctx.dbService.db
        .prepare(
          `
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
          FROM daily_traffic
          ${dailyWhere}
          ORDER BY record_date DESC
          LIMIT ? OFFSET ?
        `
        )
        .bind(...dailyValues, limit, offset)
        .all();

      const dailyTotalRow = await ctx.dbService.db
        .prepare(`SELECT COUNT(*) as total FROM daily_traffic dt ${dailyWhere}`)
        .bind(...dailyValues)
        .first<{ total?: number | string | null }>();
      const dailyTotal = Number(dailyTotalRow?.total ?? 0);

      return successResponse(res, {
        data: dailyRows.results || [],
        total: dailyTotal,
        page,
        limit,
        pages: limit > 0 ? Math.max(1, Math.ceil(dailyTotal / limit)) : 1
      });
    }

    const rows = await ctx.dbService.db
      .prepare(
        `
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
        ${whereClause}
        ORDER BY tl.date DESC, tl.created_at DESC
        LIMIT ? OFFSET ?
      `
      )
      .bind(...values, limit, offset)
      .all();

    return successResponse(res, {
      data: rows.results || [],
      total: trafficTotal,
      page,
      limit,
      pages: limit > 0 ? Math.max(1, Math.ceil(trafficTotal / limit)) : 1
    });
  });

  router.get("/online-ips", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const limit = Number(req.query.limit ?? 50) || 50;
    const rows = await ctx.dbService.listOnlineIps(Number(user.id), Math.min(limit, 200), 5);
    return successResponse(res, rows);
  });

  // 兼容前端个人资料页所需的详情格式
  router.get("/online-ips-detail", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const limit = Math.min(Number(req.query.limit ?? 50) || 50, 200);
    const userId = Number(user.id);
    const rows = await ctx.dbService.listOnlineIps(userId, limit, 5);
    const data =
      rows?.map((row: any) => ({
        id: row.id,
        node_id: row.node_id,
        node_name: row.node_name,
        ip: row.ip,
        last_seen: row.last_seen
      })) || [];
    return successResponse(res, {
      data,
      count: data.length,
      user_id: userId,
      check_time: new Date().toISOString()
    });
  });

  router.get("/online-devices", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const userId = Number(user.id);
    const rows = await ctx.dbService.listOnlineDevices(userId, 2);
    return successResponse(res, {
      count: rows.length,
      user_id: userId,
      check_time: new Date().toISOString(),
      devices: rows
    });
  });

  router.get("/bark-settings", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const dbUser = await ctx.dbService.getUserById(Number(user.id));
    if (!dbUser) return errorResponse(res, "用户不存在", 404);
    return successResponse(res, {
      bark_key: dbUser.bark_key || "",
      bark_enabled: Number(dbUser.bark_enabled) === 1
    });
  });

  router.put("/bark-settings", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const { bark_key, bark_enabled } = req.body || {};
    await ctx.dbService.updateUserBarkSettings(Number(user.id), bark_key ?? null, Boolean(bark_enabled));
    return successResponse(res, null, "Bark 设置已更新");
  });

  // Bark 通知测试（对齐 Worker 版 /api/user/bark-test）
  router.post("/bark-test", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const userId = Number(user.id);
    if (!userId) return errorResponse(res, "未登录", 401);

    let testBarkKey: string | undefined;
    const body = req.body || {};
    if (typeof body.bark_key === "string") {
      testBarkKey = body.bark_key.trim();
    }

    try {
      if (!testBarkKey) {
        const row = await ctx.dbService.db
          .prepare("SELECT bark_key FROM users WHERE id = ?")
          .bind(userId)
          .first<{ bark_key?: string | null } | null>();
        if (row?.bark_key) {
          testBarkKey = String(row.bark_key);
        }
      }

      if (!testBarkKey) {
        return errorResponse(res, "请先设置 Bark Key", 400);
      }

      const title = encodeURIComponent("Bark通知测试");
      const content = encodeURIComponent("如果您收到这条消息，说明Bark配置正确！");

      let testUrl: string;
      if (testBarkKey.startsWith("http://") || testBarkKey.startsWith("https://")) {
        const base = testBarkKey.endsWith("/") ? testBarkKey.slice(0, -1) : testBarkKey;
        testUrl = `${base}/${title}/${content}`;
      } else {
        testUrl = `https://api.day.app/${testBarkKey}/${title}/${content}`;
      }

      const response = await fetch(testUrl, {
        method: "GET",
        headers: {
          "User-Agent": "Soga-Panel-Server/1.0"
        }
      });

      if (!response.ok) {
        // 测试失败，自动禁用 Bark
        await ctx.dbService.updateUserBarkSettings(userId, testBarkKey, false);
        return errorResponse(res, `测试失败，HTTP 状态码: ${response.status}，已自动禁用 Bark 通知`, 400);
      }

      let result: any = null;
      try {
        result = await response.json();
      } catch {
        // 部分 Bark 服务可能不返回 JSON，忽略解析错误
      }

      const okCode = result && (result.code === 200 || result.message === "success");
      if (!okCode && result) {
        await ctx.dbService.updateUserBarkSettings(userId, testBarkKey, false);
        return errorResponse(
          res,
          `Bark 服务器返回错误: ${String(result.message || "未知错误")}，已自动禁用 Bark 通知`,
          400
        );
      }

      return successResponse(res, {
        message: "Bark 通知测试成功，请检查您的设备是否收到测试消息",
        success: true,
        bark_response: result ?? null
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await ctx.dbService.updateUserBarkSettings(userId, testBarkKey ?? null, false);
      return errorResponse(res, `网络请求失败: ${message}，已自动禁用 Bark 通知`, 400);
    }
  });

  router.get("/invite", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const stats = await ctx.dbService.getUserInviteStats(Number(user.id));
    const code =
      stats.invite_code ||
      (await ctx.dbService.ensureUserInviteCode(Number(user.id), () => referralService.normalizeInviteCode(generateRandomString(8))));
    const base = ctx.env.SITE_URL || "";
    const link = base ? `${base.replace(/\/$/, "")}/register?invite=${code}` : null;
    const configMap = await ctx.dbService.listSystemConfigsMap();
    const rebateRate = Number(configMap["rebate_rate"] ?? 0);
    const rebateMode = (configMap["rebate_mode"] ?? "every_order").toString();
    const inviteLimitDefault = Number(configMap["invite_default_limit"] ?? stats.invite_limit ?? 0);
    return successResponse(res, {
      invite_code: code,
      invite_link: link,
      invited_by: stats.invited_by,
      invite_used: stats.invite_used,
      invite_limit: stats.invite_limit,
      total_invitees: stats.total_invitees,
      confirmed_invitees: stats.confirmed_invitees,
      rebate_available: stats.rebate_available,
      rebate_total: stats.rebate_total,
      rebate_rate: rebateRate,
      rebate_mode: rebateMode,
      invite_default_limit: inviteLimitDefault
    });
  });

  router.post("/invite/regenerate", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const code = await referralService.regenerateInviteCode(Number(user.id));
    const base = ctx.env.SITE_URL || "";
    const link = base ? `${base.replace(/\/$/, "")}/register?invite=${code}` : null;
    return successResponse(res, { invite_code: code, invite_link: link }, "邀请码已重置");
  });

  router.get("/invite/referrals", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const page = Number(req.query.page ?? 1) || 1;
    const pageSize = Math.min(Number(req.query.pageSize ?? 20) || 20, 200);
    const data = await ctx.dbService.listReferrals(Number(user.id), page, pageSize);
    return successResponse(res, data);
  });

  // 邀请/返利概览（对齐 Worker）
  router.get("/referrals", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const page = Number(req.query.page ?? 1) || 1;
    const limit = Math.min(Number(req.query.limit ?? 10) || 10, 200);
    const offsetPageSize = limit;
    const referrals = await ctx.dbService.listReferrals(Number(user.id), page, offsetPageSize);
    const statsRow = await ctx.dbService.db
      .prepare(
        `
        SELECT 
          COUNT(*) AS total,
          SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active_total
        FROM referral_relations
        WHERE inviter_id = ?
      `
      )
      .bind(user.id)
      .first<{ total?: number; active_total?: number }>();
    const userRow = await ctx.dbService.db
      .prepare(
        `
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
      `
      )
      .bind(user.id)
      .first<{
        invite_code?: string;
        invited_by?: number;
        rebate_available?: number;
        rebate_total?: number;
        invite_limit?: number;
        invite_used?: number;
        rebate_eligible?: number;
      }>();
    const configs = await ctx.dbService.listSystemConfigsMap();
    const inviteBaseUrl = configs["site_url"] || ctx.env.SITE_URL || "";
    const rebateSettings = {
      mode: configs["rebate_mode"] || "every_order",
      rate: Number(configs["rebate_rate"] ?? 0)
    };
    const withdrawSettings = {
      feeRate: Number(configs["rebate_withdraw_fee_rate"] ?? 0.05),
      minAmount: Number(configs["rebate_withdraw_min_amount"] ?? 200)
    };
    return successResponse(res, {
      inviteCode: userRow?.invite_code || null,
      invitedBy: userRow?.invited_by ?? null,
      rebateAvailable: Number(userRow?.rebate_available ?? 0),
      rebateTotal: Number(userRow?.rebate_total ?? 0),
      inviteLimit: Number(userRow?.invite_limit ?? 0),
      inviteUsed: Number(userRow?.invite_used ?? 0),
      rebateEligible: Boolean(userRow?.rebate_eligible ?? 0),
      stats: {
        totalInvited: Number(statsRow?.total ?? 0),
        activeInvited: Number(statsRow?.active_total ?? 0)
      },
      referrals: (referrals.data || []).map((row: any) => ({
        id: row.id,
        inviteeId: row.invitee_id,
        email: row.invitee_email,
        username: row.invitee_username,
        status: row.status,
        registeredAt: row.created_at,
        firstPaidAt: row.first_paid_at,
        totalRebate: Number(row.total_rebate ?? 0)
      })),
      pagination: {
        page,
        limit,
        total: referrals.total,
        totalPages: Math.max(1, Math.ceil(referrals.total / limit))
      },
      rebateSettings,
      withdrawSettings,
      inviteBaseUrl
    });
  });

  router.get("/tickets/unread-count", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const unread = await ticketService.countUserUnread(Number(user.id));
    return successResponse(res, { count: unread });
  });

  // 工单列表
  router.get("/tickets", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const page = Number(req.query.page ?? 1) || 1;
    const pageSize = Number(req.query.pageSize ?? 10) || 10;
    const status = typeof req.query.status === "string" ? (req.query.status as any) : undefined;
    const data = await ticketService.listUserTickets(Number(user.id), page, Math.min(pageSize, 50), status);
    return successResponse(res, data);
  });

  // 创建工单
  router.post("/tickets", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const { title, content } = req.body || {};
    if (!title || !content) return errorResponse(res, "标题和内容不能为空", 400);
    const ticket = await ticketService.createTicket(Number(user.id), title, content);
    return successResponse(res, ticket, "工单已提交");
  });

  // 工单详情
  router.get("/tickets/:id", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const id = Number(req.params.id);
    const ticket = await ticketService.getTicketForUser(id, Number(user.id));
    if (!ticket) return errorResponse(res, "未找到工单", 404);
    const replies = await ticketService.listReplies(id);
    return successResponse(res, { ticket, replies });
  });

  // 工单回复
  router.post("/tickets/:id/replies", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const id = Number(req.params.id);
    const { content } = req.body || {};
    if (!content) return errorResponse(res, "回复内容不能为空", 400);
    const ticket = await ticketService.getTicketDetail(id);
    if (!ticket || Number(ticket.user_id) !== Number(user.id)) return errorResponse(res, "未找到工单", 404);
    const status = await ticketService.replyTicket(id, Number(user.id), "user", content);
    const replies = await ticketService.listReplies(id);
    return successResponse(res, { replies, status }, "回复成功");
  });

  // 关闭工单
  router.post("/tickets/:id/close", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const id = Number(req.params.id);
    const result = await ticketService.closeTicketByUser(id, Number(user.id));
    if (!result.success) return errorResponse(res, result.message || "关闭失败", 400);
    return successResponse(res, { status: result.status }, "工单已关闭");
  });

  // 用户流量趋势
  router.get("/traffic/trends", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const period = String(req.query.period || "today");
    const daysCount = period === "3days" ? 3 : period === "7days" ? 7 : 1;

    const now = new Date();
    const beijingTime = new Date(now.getTime() + 8 * 60 * 60 * 1000);

    const dayNames = ["周日", "周一", "周二", "周三", "周四", "周五", "周六"];
    const dateList: Array<{ date: string; label: string }> = [];
    for (let i = daysCount - 1; i >= 0; i -= 1) {
      const targetDate = new Date(beijingTime.getTime() - i * 24 * 60 * 60 * 1000);
      const dateStr = targetDate.toISOString().split("T")[0];
      const dayName = dayNames[targetDate.getUTCDay()];
      dateList.push({
        date: dateStr,
        label: i === 0 ? "今天" : dayName
      });
    }

    const startDate = dateList[0]?.date || beijingTime.toISOString().split("T")[0];
    const dailyRows = await ctx.dbService.db
      .prepare(
        `
        SELECT 
          DATE_FORMAT(date, '%Y-%m-%d') as date,
          COALESCE(SUM(actual_upload_traffic), 0) as upload_traffic,
          COALESCE(SUM(actual_download_traffic), 0) as download_traffic,
          COALESCE(SUM(actual_traffic), 0) as total_traffic
        FROM traffic_logs
        WHERE user_id = ?
          AND date >= ?
        GROUP BY date
        ORDER BY date ASC
      `
      )
      .bind(Number(user.id), startDate)
      .all<{ date?: string; upload_traffic?: any; download_traffic?: any; total_traffic?: any }>();

    const dataMap: Record<
      string,
      { upload_traffic: number; download_traffic: number; total_traffic: number }
    > = {};
    for (const row of dailyRows.results || []) {
      if (!row?.date) continue;
      dataMap[row.date] = {
        upload_traffic: ensureNumber(row.upload_traffic),
        download_traffic: ensureNumber(row.download_traffic),
        total_traffic: ensureNumber(row.total_traffic)
      };
    }

    const trends = dateList.map((item) => {
      const data = dataMap[item.date] || { upload_traffic: 0, download_traffic: 0, total_traffic: 0 };
      return {
        date: item.date,
        label: item.label,
        upload_traffic: data.upload_traffic,
        download_traffic: data.download_traffic,
        total_traffic: data.total_traffic
      };
    });

    const hasAny = trends.some(
      (item) =>
        ensureNumber(item.total_traffic) > 0 ||
        ensureNumber(item.upload_traffic) > 0 ||
        ensureNumber(item.download_traffic) > 0
    );

    // 没有任何记录时返回空数组，前端会回退到用户表的 upload_today/download_today
    return successResponse(res, hasAny ? trends : []);
  });

  // 用户流量汇总
  router.get("/traffic/summary", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const data = await trafficService.getUserTrafficSummary(Number(user.id));
    return successResponse(res, data);
  });

  // 用户流量统计（兼容旧版 API）
  router.get("/traffic-stats", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const days = Number(req.query.days ?? 30) || 30;
    const data = await trafficService.getUserTrafficStats(Number(user.id), Math.min(days, 180));
    if (!data) return errorResponse(res, "用户不存在", 404);
    return successResponse(res, data);
  });

  // 手动触发流量更新（同步当日 traffic_logs 到 daily_traffic / system_traffic_summary）
  router.post("/traffic/manual-update", async (req: Request, res: Response) => {
    try {
      const now = new Date(Date.now() + 8 * 60 * 60 * 1000);
      const recordDate = now.toISOString().slice(0, 10);
      await ctx.dbService.aggregateTrafficForDate(recordDate);
      return successResponse(res, null, "已触发手动同步");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return errorResponse(res, message || "手动同步失败", 500);
    }
  });

  // 审计：规则列表
  router.get("/audit-rules", async (req: Request, res: Response) => {
    const page = Number(req.query.page ?? 1) || 1;
    const limit = Number(req.query.limit ?? 20) || 20;
    const data = await auditService.listRules(page, Math.min(limit, 100));
    return successResponse(res, data);
  });

  // 审计：日志列表
  router.get("/audit-logs", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const page = Number(req.query.page ?? 1) || 1;
    const limit = Number(req.query.limit ?? 20) || 20;
    const data = await auditService.listLogs(Number(user.id), page, Math.min(limit, 100));
    return successResponse(res, data);
  });

  // 审计：概览
  router.get("/audit-overview", async (req: Request, res: Response) => {
    const user = (req as any).user;
    const data = await auditService.overview(Number(user.id));
    return successResponse(res, data);
  });

  // 用户共享账号（苹果账号等）
  router.get("/shared-ids", async (_req: Request, res: Response) => {
    type SharedIdRow = {
      id: number;
      name: string | null;
      fetch_url: string | null;
      remote_account_id: unknown;
      status: number | null;
    };

    type SharedIdPayload = {
      id: number;
      name: string;
      remote_account_id: number | number[];
      status: "ok" | "missing" | "error";
      account: unknown;
      accounts?: unknown[];
      missing_ids?: number[];
      fetched_at?: string;
      message?: string | null;
      error?: string;
    };

    const rows = await ctx.dbService.db
      .prepare(
        `
        SELECT id, name, fetch_url, remote_account_id, status
        FROM shared_ids
        WHERE status = 1
        ORDER BY id DESC
      `
      )
      .all<SharedIdRow>();

    const list = rows.results ?? [];

    const fetchAccount = async (record: SharedIdRow): Promise<SharedIdPayload> => {
      const id = toNumber(record.id);
      const remoteAccountIds = parseRemoteAccountIdList(record.remote_account_id);
      const base: SharedIdPayload = {
        id,
        name: toText(record.name),
        remote_account_id: formatRemoteAccountIdForResponse(record.remote_account_id),
        status: "error",
        account: null,
        accounts: [],
        error: undefined
      };

      if (remoteAccountIds.length === 0) {
        return {
          ...base,
          status: "error",
          fetched_at: new Date().toISOString(),
          account: null,
          accounts: [],
          error: "未配置远程账号 ID"
        };
      }

      if (!record.fetch_url) {
        return {
          ...base,
          status: "error",
          fetched_at: new Date().toISOString(),
          message: "未配置拉取地址",
          error: "苹果账号未配置拉取地址"
        };
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);

      try {
        const response = await fetch(record.fetch_url, {
          method: "GET",
          headers: { Accept: "application/json" },
          signal: controller.signal
        });

        if (!response.ok) {
          throw new Error(`远程接口返回状态 ${response.status}`);
        }

        const payload = (await response.json()) as Record<string, unknown>;
        const rawAccounts = (payload as { accounts?: unknown }).accounts;
        const accounts = Array.isArray(rawAccounts) ? rawAccounts : [];

        const matchedAccounts: unknown[] = [];
        const missingIds: number[] = [];

        for (const remoteId of remoteAccountIds) {
          const matched =
            accounts.find((item) => {
              const rowObj = item as Record<string, unknown>;
              return Number(rowObj?.id) === remoteId;
            }) ?? null;
          if (matched) {
            matchedAccounts.push(matched);
          } else {
            missingIds.push(remoteId);
          }
        }

        const isMatched = matchedAccounts.length > 0;
        const message =
          toText((payload as { msg?: unknown }).msg) ||
          toText((payload as { message?: unknown }).message);

        return {
          ...base,
          status: isMatched ? "ok" : "missing",
          fetched_at: new Date().toISOString(),
          account: matchedAccounts[0] ?? null,
          accounts: matchedAccounts,
          missing_ids: missingIds.length ? missingIds : undefined,
          message,
          error: isMatched ? undefined : "未找到匹配的ID"
        };
      } catch (error) {
        const message =
          error instanceof Error ? error.message : "远程拉取失败";
        return {
          ...base,
          status: "error",
          fetched_at: new Date().toISOString(),
          account: null,
          error: message
        };
      } finally {
        clearTimeout(timeoutId);
      }
    };

    const items = await Promise.all(list.map((row) => fetchAccount(row)));
    return successResponse(res, { items, count: items.length });
  });

  return router;
}
