// src/api/user.js - 用户 API

import type { Env } from "../types";
import { DatabaseService } from "../services/database";
import { CacheService } from "../services/cache";
import { validateUserAuth } from "../middleware/auth";
import { successResponse, errorResponse } from "../utils/response";
import { hashPassword, verifyPassword } from "../utils/crypto";
import { createSystemConfigManager, type SystemConfigManager } from "../utils/systemConfig";
import { ensureNumber, ensureString } from "../utils/d1";
import { TwoFactorService } from "../services/twoFactor";
import { ReferralService } from "../services/referralService";
import { getLogger, type Logger } from "../utils/logger";
import { formatRemoteAccountIdForResponse, parseRemoteAccountIdList } from "../utils/sharedIds";

type AuthenticatedUser = {
  id: number;
  email?: string | null;
  username?: string | null;
  class?: number;
  is_admin?: boolean;
  bark_enabled?: number;
  bark_key?: string | null;
  [key: string]: unknown;
};

type AuthResultSuccess = { success: true; user: AuthenticatedUser; message?: string };
type AuthResultFailure = { success: false; message: string };
type AuthResult = AuthResultSuccess | AuthResultFailure;

type DbRow = Record<string, any>;

type SharedIdRow = {
  id: number;
  name: string | null;
  fetch_url: string | null;
  remote_account_id: unknown;
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

const toNumber = (value: unknown, fallback = 0): number => ensureNumber(value, fallback);
const toString = (value: unknown, fallback = ""): string => ensureString(value, fallback);
const toErrorMessage = (error: unknown, fallback = "Internal Server Error"): string =>
  error instanceof Error ? error.message : fallback ?? String(error);

export class UserAPI {
  private readonly db: DatabaseService;
  private readonly cache: CacheService;
  private readonly env: Env;
  private readonly configManager: SystemConfigManager;
  private readonly twoFactorService: TwoFactorService;
  private readonly logger: Logger;
  private readonly referralService: ReferralService;

  constructor(env: Env) {
    this.db = new DatabaseService(env.DB);
    this.cache = new CacheService(env.DB);
    this.env = env;
    this.configManager = createSystemConfigManager(env);
    this.twoFactorService = new TwoFactorService(env);
    this.logger = getLogger(env);
    this.referralService = new ReferralService(this.db, this.configManager, this.logger);
  }

  private async validateUser(request: Request): Promise<AuthResult> {
    return (await validateUserAuth(request, this.env)) as AuthResult;
  }

  async listPasskeys(request: Request) {
    const auth = await this.validateUser(request);
    if (!auth.success) return errorResponse(auth.message, 401);

    const result = await this.db.db
      .prepare(
        `
        SELECT credential_id, device_name, sign_count, created_at, last_used_at
        FROM passkeys
        WHERE user_id = ?
        ORDER BY created_at DESC
      `
      )
      .bind(auth.user.id)
      .all<{
        credential_id: string;
        device_name?: string | null;
        sign_count?: number | string | null;
        created_at?: string | null;
        last_used_at?: string | null;
      }>();

    return successResponse({ items: result.results || [] });
  }

  async deletePasskey(request: Request, credentialId: string) {
    const auth = await this.validateUser(request);
    if (!auth.success) return errorResponse(auth.message, 401);
    if (!credentialId) return errorResponse("缺少凭证ID", 400);

    const del = await this.db.db
      .prepare("DELETE FROM passkeys WHERE user_id = ? AND credential_id = ?")
      .bind(auth.user.id, credentialId)
      .run();

    const changes = (del.meta as any)?.changes ?? (del as any)?.changes;
    if (!changes) {
      return errorResponse("未找到要删除的通行密钥", 404);
    }

    return successResponse({ removed: credentialId });
  }

  private async verifyUserTwoFactorCode(userRow: DbRow, code: string) {
    if (!code) {
      return { success: false, usedBackup: false };
    }
    const trimmed = code.trim();
    const secret = await this.twoFactorService.decryptSecret(userRow.two_factor_secret);
    if (!secret) {
      return { success: false, usedBackup: false };
    }
    if (await this.twoFactorService.verifyTotp(secret, trimmed)) {
      return { success: true, usedBackup: false };
    }

    const normalized = this.twoFactorService.normalizeBackupCodeInput(trimmed);
    if (!normalized || normalized.length < 6) {
      return { success: false, usedBackup: false };
    }
    const hashedInput = await this.twoFactorService.hashBackupCode(normalized);
    const stored = this.twoFactorService.parseBackupCodes(userRow.two_factor_backup_codes);
    const index = stored.findIndex((hash) => hash === hashedInput);
    if (index === -1) {
      return { success: false, usedBackup: false };
    }
    stored.splice(index, 1);
    await this.db.db
      .prepare("UPDATE users SET two_factor_backup_codes = ? WHERE id = ?")
      .bind(JSON.stringify(stored), userRow.id)
      .run();
    userRow.two_factor_backup_codes = JSON.stringify(stored);
    return { success: true, usedBackup: true };
  }

  private async revokeTrustedDevices(userId: number) {
    await this.db.db
      .prepare("DELETE FROM two_factor_trusted_devices WHERE user_id = ?")
      .bind(userId)
      .run();
  }

  async getProfile(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }

      const authUser = authResult.user;
      const userId = authUser.id;

      const user = await this.db.db
        .prepare("SELECT * FROM users WHERE id = ?")
        .bind(userId)
        .first<DbRow | null>();

      if (!user) {
        return errorResponse("User not found", 404);
      }

      // 获取系统配置中的流量重置日设置
      const trafficResetConfig = await this.db.db
        .prepare("SELECT value FROM system_configs WHERE key = 'traffic_reset_day'")
        .first<DbRow | null>();
      const trafficResetDay = Number.parseInt(toString(trafficResetConfig?.value, "0"), 10) || 0;

      // 获取订阅链接URL配置
      let subscriptionUrl = await this.configManager.getSystemConfig("subscription_url");
      if (!subscriptionUrl) {
        subscriptionUrl = await this.configManager.getSystemConfig(
          "site_url",
          toString(this.env.SITE_URL) || ""
        );
      }
      if (!subscriptionUrl) {
        subscriptionUrl = toString(this.env.SITE_URL) || "";
      }

      // 计算流量信息
      const transferEnable = toNumber(user.transfer_enable);
      const usedTraffic = toNumber(user.transfer_total);
      const remainTraffic = Math.max(0, transferEnable - usedTraffic);
      const trafficPercentage =
        transferEnable > 0
          ? Math.round((usedTraffic / transferEnable) * 100)
          : 0;

      return successResponse({
        id: user.id,
        email: user.email,
        username: user.username,
        uuid: user.uuid,
        passwd: user.passwd,
        token: user.token,
        class: user.class,
        class_expire_time: user.class_expire_time,
        is_admin: user.is_admin === 1,
        speed_limit: user.speed_limit,
        device_limit: user.device_limit,
        tcp_limit: user.tcp_limit,
        upload_traffic: toNumber(user.upload_traffic),
        download_traffic: toNumber(user.download_traffic),
        upload_today: toNumber(user.upload_today),
        download_today: toNumber(user.download_today),
        transfer_total: usedTraffic,
        transfer_enable: transferEnable,
        transfer_remain: remainTraffic,
        traffic_percentage: trafficPercentage,
        expire_time: user.expire_time,
        is_expired: Boolean(user.expire_time && new Date(user.expire_time) < new Date()),
        days_remaining: user.expire_time
          ? Math.max(
              0,
              Math.ceil(
                (new Date(user.expire_time).getTime() - Date.now()) /
                  (1000 * 60 * 60 * 24)
              )
            )
          : null,
        reg_date: user.reg_date,
        last_login_time: user.last_login_time,
        last_login_ip: user.last_login_ip,
        status: user.status,
        traffic_reset_day: trafficResetDay,
        subscription_url: subscriptionUrl,
        two_factor_enabled: Number(user.two_factor_enabled) === 1,
        has_two_factor_backup_codes: Boolean(user.two_factor_backup_codes),
      });
    } catch (error: unknown) {
      return errorResponse(toErrorMessage(error), 500);
    }
  }

  async updateProfile(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }

      const authUser = authResult.user;
      const userId = authUser.id;
      const updateData = (await request.json()) as Record<string, unknown>;
      
      // 获取当前用户信息
      const currentUser = await this.db.db
        .prepare("SELECT username, email FROM users WHERE id = ?")
        .bind(userId)
        .first<DbRow | null>();

      if (!currentUser) {
        return errorResponse("用户不存在", 404);
      }

      // 检查是否同时修改用户名和邮箱
      const newUsername = toString(updateData.username ?? currentUser.username ?? "");
      const newEmail = toString(updateData.email ?? currentUser.email ?? "");
      const isUsernameChanged = updateData.username !== undefined && newUsername !== currentUser.username;
      const isEmailChanged = updateData.email !== undefined && newEmail !== currentUser.email;
      
      if (isUsernameChanged && isEmailChanged) {
        return errorResponse("不能同时修改用户名和邮箱，请分别修改", 400);
      }

      const updates = [];
      const values = [];

      // 只处理实际发生变化的字段
      if (isUsernameChanged) {
        // 检查用户名是否已存在
        const existingUsername = await this.db.db
          .prepare("SELECT id FROM users WHERE username = ? AND id != ?")
          .bind(newUsername, userId)
          .first<DbRow | null>();
        
        if (existingUsername) {
          return errorResponse("该用户名已被使用，请选择其他用户名", 400);
        }
        
        updates.push("username = ?");
        values.push(newUsername);
      }

      if (isEmailChanged) {
        // 检查邮箱是否已存在
        const existingEmail = await this.db.db
          .prepare("SELECT id FROM users WHERE email = ? AND id != ?")
          .bind(newEmail, userId)
          .first<DbRow | null>();
        
        if (existingEmail) {
          return errorResponse("该邮箱已被使用，请选择其他邮箱", 400);
        }
        
        updates.push("email = ?");
        values.push(newEmail);
      }

      if (updates.length === 0) {
        return errorResponse("没有需要更新的字段", 400);
      }

      values.push(userId);
      const stmt = this.db.db.prepare(`
        UPDATE users 
        SET ${updates.join(", ")}, updated_at = datetime('now', '+8 hours')
        WHERE id = ?
      `);

      await stmt.bind(...values).run();

      return successResponse({ message: "个人信息更新成功" });
    } catch (error: unknown) {
      const message = toErrorMessage(error);
      if (message.includes('UNIQUE constraint failed')) {
        if (message.includes('username')) {
          return errorResponse("该用户名已被使用，请选择其他用户名", 400);
        } else if (message.includes('email')) {
          return errorResponse("该邮箱已被使用，请选择其他邮箱", 400);
        }
      }
      return errorResponse(message, 500);
    }
  }

  async changePassword(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }

      const authUser = authResult.user;
      const { current_password, new_password } = (await request.json()) as {
        current_password?: string;
        new_password?: string;
      };

      if (!current_password || !new_password) {
        return errorResponse("Current password and new password are required", 400);
      }

      // 验证当前密码
      const user = await this.db.db
        .prepare("SELECT password_hash FROM users WHERE id = ?")
        .bind(authUser.id)
        .first<DbRow | null>();

      const isValidPassword = await verifyPassword(current_password, user.password_hash);
      if (!isValidPassword) {
        return errorResponse("Current password is incorrect", 400);
      }

      // 更新密码
      const hashedPassword = await hashPassword(new_password);
      await this.db.db
        .prepare("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(hashedPassword, authUser.id)
        .run();

      return successResponse({ message: "Password changed successfully" });
    } catch (error: unknown) {
      return errorResponse(toErrorMessage(error), 500);
    }
  }

  async getAccessibleNodes(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }

      const authUser = authResult.user;
      const userClass = toNumber(authUser.class);
      const userId = authUser.id;
      const url = new URL(request.url);
      const pageParam = parseInt(url.searchParams.get("page") || "1", 10);
      const limitParam = parseInt(url.searchParams.get("limit") || "20", 10);
      const page = Number.isFinite(pageParam) && pageParam > 0 ? pageParam : 1;
      const limitCandidate = Number.isFinite(limitParam) && limitParam > 0 ? limitParam : 20;
      const limit = Math.min(limitCandidate, 100);
      const offset = (page - 1) * limit;
      const typeFilterParam = url.searchParams.get("type");
      const statusParam = url.searchParams.get("status");
      const normalizedTypeFilter = typeFilterParam ? typeFilterParam.trim().toLowerCase() : "";
      const statusFilter =
        statusParam === null || statusParam === ""
          ? null
          : statusParam === "1";

      // 获取所有启用节点（不限制用户等级）
      const nodesStmt = this.db.db.prepare(`
        SELECT * FROM nodes 
        WHERE status = 1
        ORDER BY node_class ASC, id ASC
      `);
      
      const nodesResult = await nodesStmt.all<DbRow>();
      const nodes = nodesResult.results || [];

      // 获取节点统计信息
      const nodeStats = await this.getNodeStatistics(userClass);

      const processedNodes = await Promise.all(nodes.map(async (node) => {
        const parsedConfig = this.safeParseNodeConfig(node.node_config);
        const cfg = (parsedConfig as any)?.config || parsedConfig || {};
        const client = (parsedConfig as any)?.client || {};
        const resolvedServer = client.server || '';
        const resolvedPort = client.port || cfg.port || 443;
        const resolvedTlsHost = client.tls_host || cfg.host || '';
        const configForClient = parsedConfig || {};

        // 检查节点是否在线（5分钟内有状态更新）
        const isOnline = await this.checkNodeOnlineStatus(node.id);

        // 获取用户在该节点的流量使用情况
        const userTrafficStmt = this.db.db.prepare(`
          SELECT 
            COALESCE(SUM(upload_traffic), 0) as upload_traffic,
            COALESCE(SUM(download_traffic), 0) as download_traffic,
            COALESCE(SUM(upload_traffic + download_traffic), 0) as total_traffic,
            COALESCE(SUM(actual_upload_traffic), 0) as actual_upload_traffic,
            COALESCE(SUM(actual_download_traffic), 0) as actual_download_traffic,
            COALESCE(SUM(actual_traffic), 0) as actual_total_traffic
          FROM traffic_logs 
          WHERE user_id = ? AND node_id = ?
        `);
        const userTraffic = await userTrafficStmt.bind(userId, node.id).first<DbRow | null>();
        const rawUpload = toNumber(userTraffic?.upload_traffic);
        const rawDownload = toNumber(userTraffic?.download_traffic);
        const rawTotal = toNumber(userTraffic?.total_traffic);
        const actualUpload = toNumber(userTraffic?.actual_upload_traffic);
        const actualDownload = toNumber(userTraffic?.actual_download_traffic);
        const actualTotal = toNumber(userTraffic?.actual_total_traffic);

        return {
          id: node.id,
          name: node.name,
          type: node.type,
          server: resolvedServer,
          server_port: resolvedPort,
          tls_host: resolvedTlsHost,
          node_class: node.node_class,
          node_bandwidth: node.node_bandwidth,
          node_bandwidth_limit: node.node_bandwidth_limit,
          traffic_multiplier: node.traffic_multiplier ?? 1,
          status: node.status,
          node_config: node.node_config,
          config: configForClient,
          created_at: node.created_at,
          updated_at: node.updated_at,
          // 用户在该节点的流量使用情况
          user_upload_traffic: rawUpload,
          user_download_traffic: rawDownload,
          user_total_traffic: actualTotal || rawTotal,
          user_raw_total_traffic: rawTotal,
          user_actual_upload_traffic: actualUpload,
          user_actual_download_traffic: actualDownload,
          user_actual_total_traffic: actualTotal,
          // 添加一些用户友好的标签
          tags: this.getNodeTags(node.node_class),
          // 在线状态（基于最近5分钟的状态更新）
          is_online: isOnline
        };
      }));

      const typeOrderMap: Record<string, number> = {
        ss: 1,
        shadowsocks: 1,
        ssr: 2,
        shadowsocksr: 2,
        v2ray: 3,
        vmess: 3,
        vless: 4,
        trojan: 5,
        hysteria: 6,
        hysteria2: 6,
        anytls: 7
      };
      const sortedNodes = [...processedNodes].sort((a, b) => {
        const classA = toNumber(a.node_class);
        const classB = toNumber(b.node_class);
        if (classA !== classB) return classA - classB;
        const typeA = (a.type || "").toLowerCase();
        const typeB = (b.type || "").toLowerCase();
        const orderA = typeOrderMap[typeA] ?? 99;
        const orderB = typeOrderMap[typeB] ?? 99;
        if (orderA !== orderB) return orderA - orderB;
        const nameA = String(a.name || "");
        const nameB = String(b.name || "");
        return nameA.localeCompare(nameB, "zh-CN", { numeric: true, sensitivity: "base" });
      });

      let filteredNodes = sortedNodes;

      if (normalizedTypeFilter) {
        filteredNodes = filteredNodes.filter(
          (node) => (node.type || "").toLowerCase() === normalizedTypeFilter
        );
      }

      if (statusFilter !== null) {
        const shouldBeOnline = statusFilter === true;
        filteredNodes = filteredNodes.filter((node) =>
          shouldBeOnline ? Boolean(node.is_online) : !node.is_online
        );
      }

      const total = filteredNodes.length;
      const pagedNodes = filteredNodes.slice(offset, offset + limit);

      return successResponse({
        nodes: pagedNodes,
        statistics: nodeStats,
        pagination: {
          total,
          page,
          limit
        }
      });
    } catch (error: unknown) {
      return errorResponse(toErrorMessage(error), 500);
    }
  }

  /**
   * 获取节点统计信息
   */
  async getNodeStatistics(userClass: number) {
    try {
      const totalNodesStmt = this.db.db.prepare(`
        SELECT COUNT(*) as count 
        FROM nodes 
        WHERE status = 1
      `);
      const totalNodes = await totalNodesStmt.first<DbRow | null>();

      // 用户可访问的节点（启用且等级满足）
      const accessibleNodesStmt = this.db.db.prepare(`
        SELECT COUNT(*) as count 
        FROM nodes 
        WHERE status = 1 AND node_class <= ?
      `);
      const accessibleNodes = await accessibleNodesStmt.bind(userClass).first<DbRow | null>();

      // 在线节点数（统计所有启用节点）
      const onlineNodesStmt = this.db.db.prepare(`
        SELECT COUNT(DISTINCT ns.node_id) as count
        FROM node_status ns
        INNER JOIN nodes n ON ns.node_id = n.id
        WHERE ns.created_at >= datetime('now', '+8 hours', '-5 minutes')
          AND n.status = 1
      `);
      const onlineNodes = await onlineNodesStmt.first<DbRow | null>();

      const totalEnabled = toNumber(totalNodes?.count);
      const accessibleTotal = toNumber(accessibleNodes?.count);
      const totalOnline = toNumber(onlineNodes?.count);
      const totalOffline = Math.max(0, totalEnabled - totalOnline);

      return {
        total: totalEnabled,
        online: totalOnline,
        offline: totalOffline,
        accessible: accessibleTotal
      };
    } catch (error: unknown) {
      console.error('获取节点统计失败:', error);
      return {
        total: 0,
        online: 0,
        offline: 0,
        accessible: 0
      };
    }
  }

  private safeParseNodeConfig(raw: unknown) {
    try {
      const parsed = typeof raw === "string" ? JSON.parse(raw || "{}") : (raw || {});
      return parsed;
    } catch (error) {
      console.warn("parse node_config failed, using empty config:", error);
      return {};
    }
  }

  /**
   * 检查节点在线状态（简化版，实际应该查询node_status表）
   */
  async checkNodeOnlineStatus(nodeId: number) {
    try {
      const stmt = this.db.db.prepare(`
        SELECT COUNT(DISTINCT node_id) as count
        FROM node_status
        WHERE node_id = ?
          AND created_at >= datetime('now', '+8 hours', '-5 minutes')
      `);
      const result = await stmt.bind(nodeId).first<DbRow | null>();
      return Boolean(result && toNumber(result.count));
    } catch (error) {
      return false; // 默认为离线
    }
  }

  async getTrafficStats(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }

      const authUser = authResult.user;
      const userId = authUser.id;
      const url = new URL(request.url);
      const days = Number.parseInt(url.searchParams.get("days") ?? "", 10) || 30;

      // 获取用户基本流量信息
      const user = await this.db.db
        .prepare("SELECT * FROM users WHERE id = ?")
        .bind(userId)
        .first<DbRow | null>();

      if (!user) {
        return errorResponse("用户不存在", 404);
      }

      // 计算流量相关数据
      const uploadTraffic = toNumber(user.upload_traffic);
      const downloadTraffic = toNumber(user.download_traffic);
      const transferTotal = toNumber(user.transfer_total);
      const transferToday = toNumber(user.transfer_today);
      const transferEnable = toNumber(user.transfer_enable);
      const remainTraffic = Math.max(0, transferEnable - transferTotal);
      const trafficPercentage = transferEnable > 0 
        ? Math.round((transferTotal / transferEnable) * 100) 
        : 0;

      // 获取流量历史统计 - 优先从daily_traffic_stats获取，如果没有数据则从traffic_logs获取
      const dailyStatsStmt = this.db.db.prepare(`
        SELECT date, upload_traffic as upload, download_traffic as download, total_traffic
        FROM daily_traffic_stats 
        WHERE user_id = ? AND date >= date('now', '-${days} days')
        ORDER BY date ASC
      `);

      let trafficHistory = await dailyStatsStmt.bind(userId).all<DbRow>();
      
      // 如果daily_traffic_stats没有数据，从traffic_logs获取
      if (!trafficHistory.results || trafficHistory.results.length === 0) {
        const trafficLogsStmt = this.db.db.prepare(`
          SELECT date, SUM(upload_traffic) as upload, SUM(download_traffic) as download
          FROM traffic_logs 
          WHERE user_id = ? AND date >= date('now', '-${days} days')
          GROUP BY date
          ORDER BY date ASC
        `);
        trafficHistory = await trafficLogsStmt.bind(userId).all<DbRow>();
      }

      return successResponse({
        // 基本流量信息
        transfer_enable: transferEnable,
        transfer_total: transferTotal,
        transfer_today: transferToday,
        remain_traffic: remainTraffic,
        traffic_percentage: trafficPercentage,
        upload_traffic: uploadTraffic,
        download_traffic: downloadTraffic,
        
        // 今日流量（从transfer_today拆分，简化处理）
        today_upload: Math.round(transferToday * 0.3), // 假设上传占30%
        today_download: Math.round(transferToday * 0.7), // 假设下载占70%
        
        // 历史流量数据
        traffic_stats: trafficHistory.results || [],
        total_days: days,
        
        // 其他信息
        last_checkin_time: user.last_login_time,
      });
    } catch (error: unknown) {
      return errorResponse(toErrorMessage(error), 500);
    }
  }

  async resetSubscriptionToken(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }

      const authUser = authResult.user;
      // 生成新的UUID、passwd和token
      const { generateRandomString, generateUUID, generateBase64Random } = await import("../utils/crypto");
      const newUUID = generateUUID();
      const newPassword = generateBase64Random(32);
      const newToken = generateRandomString(32);

      // 更新用户的UUID、passwd和token
      const stmt = this.db.db.prepare(`
        UPDATE users 
        SET uuid = ?, passwd = ?, token = ?, updated_at = datetime('now', '+8 hours')
        WHERE id = ?
      `);

      await stmt.bind(newUUID, newPassword, newToken, authUser.id).run();

      // 返回更新后的用户信息
      const updatedUser = await this.db.db
        .prepare("SELECT * FROM users WHERE id = ?")
        .bind(authUser.id)
        .first<DbRow | null>();

      return successResponse({
        message: "订阅信息重置成功，UUID、密码和令牌已更新",
        token: newToken,
        uuid: newUUID,
        passwd: newPassword,
        user: {
          id: updatedUser?.id,
          email: updatedUser?.email,
          username: updatedUser?.username,
          token: updatedUser?.token,
          uuid: updatedUser?.uuid,
          passwd: updatedUser?.passwd,
          class: updatedUser?.class,
          is_admin: updatedUser ? updatedUser.is_admin === 1 : false
        }
      });
    } catch (error: unknown) {
      return errorResponse(toErrorMessage(error), 500);
    }
  }

  getNodeTags(nodeClass) {
    const tags = [];
    switch (nodeClass) {
      case 1:
        tags.push("基础", "稳定");
        break;
      case 2:
        tags.push("高级", "高速");
        break;
      case 3:
        tags.push("专线", "低延迟");
        break;
      default:
        tags.push("特殊");
    }
    return tags;
  }

  // 获取用户订阅记录
  async getSubscriptionLogs(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }

      const authUser = authResult.user;
      const url = new URL(request.url);
      const page = Number.parseInt(url.searchParams.get('page') ?? '', 10) || 1;
      const limit = Number.parseInt(url.searchParams.get('limit') ?? '', 10) || 20;
      const type = url.searchParams.get('type') || '';
      const offset = (page - 1) * limit;

      // 构建查询条件
      let whereClause = 'WHERE user_id = ?';
      const params: Array<number | string> = [authUser.id];
      
      if (type) {
        whereClause += ' AND type = ?';
        params.push(type);
      }

      // 获取总记录数
      const countQuery = `SELECT COUNT(*) as total FROM subscriptions ${whereClause}`;
      const countResult = await this.db.db.prepare(countQuery).bind(...params).first<DbRow | null>();
      const total = toNumber(countResult?.total);

      // 获取订阅记录
      const logsQuery = `
        SELECT 
          id,
          user_id,
          type,
          request_ip,
          request_time,
          request_user_agent
        FROM subscriptions 
        ${whereClause}
        ORDER BY request_time DESC
        LIMIT ? OFFSET ?
      `;
      
      const logsResult = await this.db.db
        .prepare(logsQuery)
        .bind(...params, limit, offset)
        .all<DbRow>();

      const logs = logsResult.results || [];

      return successResponse({
        data: logs,
        total: total,
        page: page,
        limit: limit,
        pages: Math.ceil(total / limit)
      });

    } catch (error: unknown) {
      console.error('Get subscription logs error:', error);
      return errorResponse('获取订阅记录失败', 500);
    }
  }

  // 获取用户Bark设置
  async getBarkSettings(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }

      const authUser = authResult.user;
      const user = await this.db.db
        .prepare("SELECT bark_key, bark_enabled FROM users WHERE id = ?")
        .bind(authUser.id)
        .first<DbRow | null>();

      return successResponse({
        bark_key: toString(user?.bark_key, ''),
        bark_enabled: user?.bark_enabled === 1
      });

    } catch (error: unknown) {
      console.error('Get bark settings error:', error);
      return errorResponse('获取Bark设置失败', 500);
    }
  }

  // 更新用户Bark设置
  async updateBarkSettings(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }

      const authUser = authResult.user;
      const { bark_key, bark_enabled } = (await request.json()) as {
        bark_key?: string;
        bark_enabled?: boolean;
      };

      // 验证bark_key格式（如果提供）
      if (bark_key && !this.isValidBarkKey(bark_key)) {
        return errorResponse('Bark Key格式无效', 400);
      }

      await this.db.db
        .prepare("UPDATE users SET bark_key = ?, bark_enabled = ?, updated_at = datetime('now', '+8 hours') WHERE id = ?")
        .bind(bark_key || null, bark_enabled ? 1 : 0, authUser.id)
        .run();

      return successResponse({ message: 'Bark设置更新成功' });

    } catch (error: unknown) {
      console.error('Update bark settings error:', error);
      return errorResponse('更新Bark设置失败', 500);
    }
  }

  // 获取用户登录记录
  async getLoginLogs(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }

      const url = new URL(request.url);
      const limit = Number.parseInt(url.searchParams.get('limit') ?? '', 10) || 10;

      const logs = await this.db.db
        .prepare(`
          SELECT 
            id,
            login_ip,
            login_time,
            user_agent,
            login_status,
            failure_reason
          FROM login_logs 
          WHERE user_id = ?
          ORDER BY login_time DESC
          LIMIT ?
        `)
        .bind(authResult.user.id, limit)
        .all<DbRow>();

      return successResponse({
        data: logs.results || []
      });

    } catch (error: unknown) {
      console.error('Get login logs error:', error);
      return errorResponse('获取登录记录失败', 500);
    }
  }

  // ===== 苹果账号功能 =====

  private async fetchSharedIdAccount(record: SharedIdRow): Promise<SharedIdPayload> {
    const id = toNumber(record.id);
    const cacheKey = `shared_id_payload_${id}`;
    const cached = this.cache.memoryCache.get<SharedIdPayload>(cacheKey);
    if (cached) {
      return cached;
    }

    const remoteAccountIds = parseRemoteAccountIdList(record.remote_account_id);
    const baseInfo: SharedIdPayload = {
      id,
      name: toString(record.name),
      remote_account_id: formatRemoteAccountIdForResponse(record.remote_account_id),
      status: "error",
      account: null,
      accounts: [],
      error: undefined,
    };

    if (remoteAccountIds.length === 0) {
      const result: SharedIdPayload = {
        ...baseInfo,
        status: "error",
        error: "未配置远程账号 ID",
      };
      this.cache.memoryCache.set(cacheKey, result, 30);
      return result;
    }

    if (!record.fetch_url) {
      const result: SharedIdPayload = {
        ...baseInfo,
        error: "苹果账号未配置拉取地址",
      };
      this.cache.memoryCache.set(cacheKey, result, 30);
      return result;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    try {
      const response = await fetch(record.fetch_url, {
        method: "GET",
        headers: {
          Accept: "application/json",
        },
        signal: controller.signal,
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
          accounts.find((item) => Number((item as Record<string, unknown>)?.id) === remoteId) ?? null;
        if (matched) {
          matchedAccounts.push(matched);
        } else {
          missingIds.push(remoteId);
        }
      }

      const isMatched = matchedAccounts.length > 0;
      const result: SharedIdPayload = {
        ...baseInfo,
        status: isMatched ? "ok" : "missing",
        fetched_at: new Date().toISOString(),
        account: matchedAccounts[0] ?? null,
        accounts: matchedAccounts,
        missing_ids: missingIds.length ? missingIds : undefined,
        message:
          toString((payload as { msg?: unknown }).msg) ||
          toString((payload as { message?: unknown }).message),
        error: isMatched ? undefined : "未找到匹配的ID",
      };
      this.cache.memoryCache.set(cacheKey, result, 60);
      return result;
    } catch (error) {
      const message = error instanceof Error ? error.message : "远程拉取失败";
      const result: SharedIdPayload = {
        ...baseInfo,
        status: "error",
        account: null,
        error: message,
      };
      this.cache.memoryCache.set(cacheKey, result, 30);
      return result;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async getSharedIds(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }

      const rows = await this.db.db
        .prepare(
          `
          SELECT id, name, fetch_url, remote_account_id
          FROM shared_ids
          WHERE status = 1
          ORDER BY id DESC
        `
        )
        .all<SharedIdRow>();

      const list = rows.results ?? [];
      const items = await Promise.all(list.map((row) => this.fetchSharedIdAccount(row)));

      return successResponse({
        items,
        count: items.length,
      });
    } catch (error) {
      return errorResponse(toErrorMessage(error), 500);
    }
  }

  async startTwoFactorSetup(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }
      const userId = authResult.user.id;
      const user = await this.db.db
        .prepare(
          "SELECT id, email, username, two_factor_enabled, two_factor_secret FROM users WHERE id = ?"
        )
        .bind(userId)
        .first<DbRow | null>();

      if (!user) {
        return errorResponse("用户不存在", 404);
      }
      if (Number(user.two_factor_enabled) === 1 && user.two_factor_secret) {
        return errorResponse("二步验证已启用", 400);
      }

      const secret = this.twoFactorService.generateSecret(32);
      const encryptedSecret = await this.twoFactorService.encryptSecret(secret);

      await this.db.db
        .prepare(
          `
        UPDATE users
        SET two_factor_temp_secret = ?
        WHERE id = ?
      `
        )
        .bind(encryptedSecret, userId)
        .run();

      const siteConfigs = await this.configManager.getSiteConfigs();
      const issuer = siteConfigs.site_name || "Soga Panel";
      const accountName =
        ensureString(user.email) ||
        ensureString(user.username) ||
        `user_${user.id}`;
      const otpAuthUrl = this.twoFactorService.createOtpAuthUrl(
        secret,
        accountName,
        issuer
      );

      return successResponse({
        secret,
        otp_auth_url: otpAuthUrl,
        provisioning_uri: otpAuthUrl,
      });
    } catch (error: unknown) {
      return errorResponse(toErrorMessage(error), 500);
    }
  }

  async enableTwoFactor(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }
      const userId = authResult.user.id;
      const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
      const code =
        typeof body.code === "string" ? body.code.trim() : "";
      if (!code) {
        return errorResponse("请输入验证码", 400);
      }

      const user = await this.db.db
        .prepare(
          "SELECT * FROM users WHERE id = ?"
        )
        .bind(userId)
        .first<DbRow | null>();

      if (!user) {
        return errorResponse("用户不存在", 404);
      }
      if (!user.two_factor_temp_secret) {
        return errorResponse("请先获取新的密钥", 400);
      }

      const tempSecret = await this.twoFactorService.decryptSecret(
        user.two_factor_temp_secret
      );
      if (!tempSecret) {
        return errorResponse("临时密钥无效，请重新生成", 400);
      }

      const verified = await this.twoFactorService.verifyTotp(
        tempSecret,
        code
      );
      if (!verified) {
        return errorResponse("验证码无效，请重试", 401);
      }

      const backupCodes = this.twoFactorService.generateBackupCodes();
      const hashedCodes = await this.twoFactorService.hashBackupCodes(
        backupCodes
      );

      await this.db.db
        .prepare(
          `
        UPDATE users
        SET two_factor_enabled = 1,
            two_factor_secret = two_factor_temp_secret,
            two_factor_backup_codes = ?,
            two_factor_temp_secret = NULL,
            two_factor_confirmed_at = datetime('now', '+8 hours')
        WHERE id = ?
      `
        )
        .bind(JSON.stringify(hashedCodes), userId)
        .run();

      await this.revokeTrustedDevices(userId);
      await this.cache.deleteByPrefix(`user_${userId}`);

      return successResponse({
        message: "二步验证已启用",
        backup_codes: backupCodes,
      });
    } catch (error: unknown) {
      return errorResponse(toErrorMessage(error), 500);
    }
  }

  async regenerateTwoFactorBackupCodes(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }
      const userId = authResult.user.id;
      const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
      const code =
        typeof body.code === "string" ? body.code.trim() : "";
      if (!code) {
        return errorResponse("请输入验证码", 400);
      }

      const user = await this.db.db
        .prepare("SELECT * FROM users WHERE id = ?")
        .bind(userId)
        .first<DbRow | null>();

      if (!user || Number(user.two_factor_enabled) !== 1) {
        return errorResponse("尚未启用二步验证", 400);
      }

      const verification = await this.verifyUserTwoFactorCode(user, code);
      if (!verification.success) {
        return errorResponse("验证码无效，请重试", 401);
      }

      const backupCodes = this.twoFactorService.generateBackupCodes();
      const hashedCodes = await this.twoFactorService.hashBackupCodes(
        backupCodes
      );

      await this.db.db
        .prepare(
          "UPDATE users SET two_factor_backup_codes = ? WHERE id = ?"
        )
        .bind(JSON.stringify(hashedCodes), userId)
        .run();

      return successResponse({
        message: "已生成新的备用验证码",
        backup_codes: backupCodes,
      });
    } catch (error: unknown) {
      return errorResponse(toErrorMessage(error), 500);
    }
  }

  async disableTwoFactor(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }
      const userId = authResult.user.id;
      const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
      const password =
        typeof body.password === "string" ? body.password : "";
      const code =
        typeof body.code === "string" ? body.code.trim() : "";

      if (!password || !code) {
        return errorResponse("请输入密码和验证码", 400);
      }

      const user = await this.db.db
        .prepare("SELECT * FROM users WHERE id = ?")
        .bind(userId)
        .first<DbRow | null>();

      if (!user || Number(user.two_factor_enabled) !== 1) {
        return errorResponse("尚未启用二步验证", 400);
      }

      const validPassword = await verifyPassword(
        password,
        ensureString(user.password_hash)
      );
      if (!validPassword) {
        return errorResponse("密码错误", 401);
      }

      const verification = await this.verifyUserTwoFactorCode(user, code);
      if (!verification.success) {
        return errorResponse("验证码无效，请重试", 401);
      }

      await this.db.db
        .prepare(
          `
        UPDATE users
        SET two_factor_enabled = 0,
            two_factor_secret = NULL,
            two_factor_backup_codes = NULL,
            two_factor_temp_secret = NULL,
            two_factor_confirmed_at = NULL
        WHERE id = ?
      `
        )
        .bind(userId)
        .run();

      await this.revokeTrustedDevices(userId);
      await this.cache.deleteByPrefix(`user_${userId}`);

      return successResponse({
        message: "二步验证已关闭",
      });
    } catch (error: unknown) {
      return errorResponse(toErrorMessage(error), 500);
    }
  }

  // 测试Bark通知
  async testBarkNotification(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }

      const authUser = authResult.user;

      // 从请求体中获取测试用的Bark Key，如果没有则使用已保存的
      let testBarkKey;
      if (request.method === 'POST') {
        try {
          const body = (await request.json()) as { bark_key?: string };
          testBarkKey = body.bark_key;
        } catch {
          // 如果解析失败，使用已保存的key
        }
      }

      if (!testBarkKey) {
        const user = await this.db.db
          .prepare("SELECT bark_key FROM users WHERE id = ?")
          .bind(authUser.id)
          .first<DbRow | null>();
        
        testBarkKey = toString(user?.bark_key, "");
      }
      
      if (!testBarkKey) {
        return errorResponse('请先设置Bark Key', 400);
      }

      // 构建测试消息URL - 发送真实的测试消息
      let testUrl;
      const testTitle = encodeURIComponent('Bark通知测试');
      const testContent = encodeURIComponent('如果您收到这条消息，说明Bark配置正确！');
      
      if (testBarkKey.startsWith('http')) {
        // 完整URL格式 (支持自建服务器)
        // 确保URL以/结尾，然后添加测试消息
        const baseUrl = testBarkKey.endsWith('/') ? testBarkKey.slice(0, -1) : testBarkKey;
        testUrl = `${baseUrl}/${testTitle}/${testContent}`;
      } else {
        // 简单key格式，使用官方服务器
        testUrl = `https://api.day.app/${testBarkKey}/${testTitle}/${testContent}`;
      }
      
      try {
        console.log('发送Bark测试消息到:', testUrl);
        const response = await fetch(testUrl, {
          method: 'GET',
          headers: {
            'User-Agent': 'Soga-Panel/1.0'
          }
        });

        if (!response.ok) {
          console.log('Bark测试请求失败，状态码:', response.status);
          // 测试失败，禁用Bark通知
          await this.disableBarkNotification(authUser.id);
          return errorResponse(`测试失败，HTTP状态码: ${response.status}。请检查Bark Key设置。已自动禁用Bark通知。`, 400);
        }

        const result = await response.json() as { code?: number; message?: string };
        console.log('Bark测试响应:', result);
        
        if (result.code === 200 || result.message === 'success') {
          return successResponse({ 
            message: 'Bark通知测试成功！请检查您的设备是否收到测试消息。',
            success: true,
            bark_response: result
          });
        } else {
          // 测试失败，禁用Bark通知
          await this.disableBarkNotification(authUser.id);
          return errorResponse(`Bark服务器返回错误: ${result.message || '未知错误'}。已自动禁用Bark通知。`, 400);
        }
      } catch (fetchError: unknown) {
        console.error('Bark测试请求失败:', fetchError);
        // 测试失败，禁用Bark通知
        await this.disableBarkNotification(authUser.id);
        return errorResponse(`网络请求失败: ${toErrorMessage(fetchError)}。请检查Bark Key设置。已自动禁用Bark通知。`, 400);
      }
    } catch (error: unknown) {
      console.error('测试Bark通知失败:', error);
      return errorResponse(toErrorMessage(error), 500);
    }
  }

  // 禁用用户的Bark通知
  async disableBarkNotification(userId: number) {
    try {
      await this.db.db
        .prepare("UPDATE users SET bark_enabled = 0, updated_at = datetime('now', '+8 hours') WHERE id = ?")
        .bind(userId)
        .run();
      console.log(`已禁用用户 ${userId} 的Bark通知`);
    } catch (error: unknown) {
      console.error(`禁用用户 ${userId} Bark通知失败:`, error);
    }
  }

  // 验证Bark Key格式
  isValidBarkKey(barkKey: string) {
    // 简单的格式验证：应该是一个URL或者包含有效字符的字符串
    if (!barkKey || barkKey.length < 3) return false;
    
    // 支持完整URL格式：https://your-bark-server.com/your_key/ 或 http://...
    if (barkKey.startsWith('http://') || barkKey.startsWith('https://')) {
      try {
        new URL(barkKey);
        return true;
      } catch {
        return false;
      }
    }
    
    // 支持简单的key格式：只包含字母数字和基本符号
    return /^[a-zA-Z0-9_-]+$/.test(barkKey);
  }

  // 获取用户审计规则
  async getAuditRules(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }

      const url = new URL(request.url);
      const page = Number.parseInt(url.searchParams.get('page') ?? '', 10) || 1;
      const limit = Number.parseInt(url.searchParams.get('limit') ?? '', 10) || 20;
      const action = url.searchParams.get('action') || '';
      const search = url.searchParams.get('search') || '';

      const { getUserAuditRules } = await import('./user-audit');
      const result = await getUserAuditRules(this.env, authResult.user.id, {
        page, limit, action, search
      });

      if (result.success) {
        return successResponse(result.data);
      } else {
        return errorResponse(result.message, 500);
      }
    } catch (error: unknown) {
      return errorResponse(toErrorMessage(error), 500);
    }
  }

  // 获取用户审计记录
  async getAuditLogs(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }

      const url = new URL(request.url);
      const page = Number.parseInt(url.searchParams.get('page') ?? '', 10) || 1;
      const limit = Number.parseInt(url.searchParams.get('limit') ?? '', 10) || 20;
      const action = url.searchParams.get('action') || '';
      const date_start = url.searchParams.get('date_start') || '';
      const date_end = url.searchParams.get('date_end') || '';
      const search = url.searchParams.get('search') || '';

      const { getUserAuditLogs } = await import('./user-audit');
      const result = await getUserAuditLogs(this.env, authResult.user.id, {
        page, limit, action, date_start, date_end, search
      });

      if (result.success) {
        return successResponse(result.data);
      } else {
        return errorResponse(result.message, 500);
      }
    } catch (error: unknown) {
      return errorResponse(toErrorMessage(error), 500);
    }
  }

  // 获取用户审计概览
  async getAuditOverview(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }

      const { getUserAuditOverview } = await import('./user-audit');
      const result = await getUserAuditOverview(this.env, authResult.user.id);

      if (result.success) {
        return successResponse(result.data);
      } else {
        return errorResponse(result.message, 500);
      }
    } catch (error: unknown) {
      return errorResponse(toErrorMessage(error), 500);
    }
  }

  // 获取用户在线设备数量
  async getOnlineDevices(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }

      // 查询该用户最近2分钟内的在线IP记录
      const stmt = this.db.db.prepare(`
        SELECT DISTINCT ip 
        FROM online_ips 
        WHERE user_id = ? 
        AND last_seen >= datetime('now', '+8 hours', '-2 minutes')
      `);

      const result = await stmt.bind(authResult.user.id).all<DbRow>();
      const onlineDeviceCount = result.results ? result.results.length : 0;

      return successResponse({
        count: onlineDeviceCount,
        user_id: authResult.user.id,
        check_time: new Date().toISOString()
      });
    } catch (error: unknown) {
      console.error('获取在线设备数量失败:', error);
      return errorResponse(toErrorMessage(error), 500);
    }
  }

  // 获取用户在线IP详细信息
  async getOnlineIpsDetail(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }

      // 查询该用户最近5分钟内的在线IP详细记录
      const stmt = this.db.db.prepare(`
        SELECT 
          oi.ip,
          oi.node_id,
          oi.last_seen,
          n.name as node_name
        FROM online_ips oi
        LEFT JOIN nodes n ON oi.node_id = n.id
        WHERE oi.user_id = ? 
        AND oi.last_seen >= datetime('now', '+8 hours', '-5 minutes')
        ORDER BY oi.last_seen DESC
      `);

      const result = await stmt.bind(authResult.user.id).all<DbRow>();
      const onlineIps = result.results || [];

      return successResponse({
        data: onlineIps,
        count: onlineIps.length,
        user_id: authResult.user.id,
        check_time: new Date().toISOString()
      });
    } catch (error: unknown) {
      console.error('获取在线IP详细信息失败:', error);
      return errorResponse(toErrorMessage(error), 500);
    }
  }

  async getReferralOverview(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }

      const userId = ensureNumber(authResult.user.id);
      const url = new URL(request.url);
      const page = Math.max(1, Number.parseInt(url.searchParams.get("page") ?? "1", 10) || 1);
      const limit = Math.max(1, Number.parseInt(url.searchParams.get("limit") ?? "10", 10) || 10);
      const offset = (page - 1) * limit;

      const userRow = await this.db.db
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
                AND (class_expire_time IS NULL OR class_expire_time > datetime('now', '+8 hours'))
              THEN 1
              ELSE 0
            END AS rebate_eligible
          FROM users
          WHERE id = ?
        `
        )
        .bind(userId)
        .first<DbRow | null>();
      if (!userRow) {
        return errorResponse("用户不存在", 404);
      }

      const statsRow = await this.db.db
        .prepare(`
          SELECT 
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active_total
          FROM referral_relations
          WHERE inviter_id = ?
        `)
        .bind(userId)
        .first<{ total?: number | string | null; active_total?: number | string | null } | null>();

      const referrals = await this.db.db
        .prepare(
          `
          SELECT 
            rr.id,
            rr.invitee_id,
            rr.status,
            rr.registered_at,
            rr.first_paid_at,
            u.email,
            u.username,
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
        `
        )
        .bind(userId, limit, offset)
        .all();

      const rows = (referrals.results ?? []) as DbRow[];
      const total = ensureNumber(statsRow?.total);
      const [settings, withdrawSettings, siteConfigs] = await Promise.all([
        this.referralService.getRebateSettings(),
        this.referralService.getWithdrawalSettings(),
        this.configManager.getSiteConfigs()
      ]);

      return successResponse({
        inviteCode: toString(userRow.invite_code),
        invitedBy: toNumber(userRow.invited_by),
        rebateAvailable: toNumber(userRow.rebate_available),
        rebateTotal: toNumber(userRow.rebate_total),
        inviteLimit: toNumber(userRow.invite_limit),
        inviteUsed: toNumber(userRow.invite_used),
        rebateEligible: Boolean(toNumber(userRow.rebate_eligible)),
        stats: {
          totalInvited: total,
          activeInvited: ensureNumber(statsRow?.active_total),
        },
        referrals: rows.map((row) => ({
          id: ensureNumber(row.id),
          inviteeId: ensureNumber(row.invitee_id),
          email: toString(row.email),
          username: toString(row.username),
          status: toString(row.status, "pending"),
          registeredAt: toString(row.registered_at),
          firstPaidAt: toString(row.first_paid_at),
          totalRebate: toNumber(row.total_rebate),
        })),
        pagination: {
          page,
          limit,
          total,
          totalPages: Math.max(1, Math.ceil(total / limit)),
        },
        rebateSettings: settings,
        withdrawSettings,
        inviteBaseUrl: siteConfigs.site_url || "",
      });
    } catch (error) {
      this.logger.error("获取邀请数据失败", error);
      return errorResponse(toErrorMessage(error, "获取邀请数据失败"), 500);
    }
  }

  async getRebateLedger(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }
      const userId = ensureNumber(authResult.user.id);
      const url = new URL(request.url);
      const page = Math.max(1, Number.parseInt(url.searchParams.get("page") ?? "1", 10) || 1);
      const limit = Math.max(1, Number.parseInt(url.searchParams.get("limit") ?? "20", 10) || 20);
      const offset = (page - 1) * limit;
      const eventType = url.searchParams.get("event_type");

      let whereClause = "WHERE inviter_id = ?";
      let ledgerWhereClause = "WHERE rt.inviter_id = ?";
      const bindings: Array<number | string> = [userId];
      const ledgerBindings: Array<number | string> = [userId];
      if (eventType) {
        whereClause += " AND event_type = ?";
        ledgerWhereClause += " AND rt.event_type = ?";
        bindings.push(eventType);
        ledgerBindings.push(eventType);
      }

      const totalRow = await this.db.db
        .prepare(`SELECT COUNT(*) AS total FROM rebate_transactions ${whereClause}`)
        .bind(...bindings)
        .first<{ total?: number | string | null } | null>();

      const ledger = await this.db.db
        .prepare(
          `
          SELECT 
            rt.id,
            rt.event_type,
            rt.amount,
            rt.source_type,
            rt.source_id,
            rt.trade_no,
            rt.status,
            rt.created_at,
            rt.invitee_id,
            u.email AS invitee_email
          FROM rebate_transactions rt
          LEFT JOIN users u ON rt.invitee_id = u.id
          ${ledgerWhereClause}
          ORDER BY rt.created_at DESC
          LIMIT ? OFFSET ?
        `
        )
        .bind(...ledgerBindings, limit, offset)
        .all();

      const rows = (ledger.results ?? []) as DbRow[];
      const total = ensureNumber(totalRow?.total);

      return successResponse({
        records: rows.map((row) => ({
          id: ensureNumber(row.id),
          eventType: toString(row.event_type),
          amount: toNumber(row.amount),
          sourceType: toString(row.source_type),
          sourceId: row.source_id ?? null,
          tradeNo: toString(row.trade_no),
          status: toString(row.status),
          createdAt: toString(row.created_at),
          inviteeEmail: toString(row.invitee_email),
        })),
        pagination: {
          page,
          limit,
          total,
          totalPages: Math.max(1, Math.ceil(total / limit)),
        },
      });
    } catch (error) {
      this.logger.error("获取返利流水失败", error);
      return errorResponse(toErrorMessage(error, "获取返利流水失败"), 500);
    }
  }

  async transferRebateToBalance(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }
      const userId = ensureNumber(authResult.user.id);
      const body = (await request.json().catch(() => ({}))) as {
        amount?: number | string;
      };
      const amount = ensureNumber(body?.amount);
      if (!Number.isFinite(amount) || amount <= 0) {
        return errorResponse("请输入有效的划转金额", 400);
      }

      await this.referralService.transferRebateToBalance(userId, amount);
      const userRow = await this.db.db
        .prepare("SELECT money, rebate_available FROM users WHERE id = ?")
        .bind(userId)
        .first<{ money?: number | string | null; rebate_available?: number | string | null } | null>();

      return successResponse(
        {
          money: toNumber(userRow?.money),
          rebateAvailable: toNumber(userRow?.rebate_available),
        },
        "返利已划转至余额"
      );
    } catch (error) {
      this.logger.error("返利划转失败", error);
      return errorResponse(toErrorMessage(error, "划转失败，请稍后再试"), 400);
    }
  }

  async createRebateWithdrawal(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }
      const userId = ensureNumber(authResult.user.id);
      const body = (await request.json().catch(() => ({}))) as {
        amount?: number | string;
        method?: string;
        accountPayload?: Record<string, unknown> | null;
      };
      const amount = ensureNumber(body?.amount);
      if (!Number.isFinite(amount) || amount <= 0) {
        return errorResponse("请输入有效的提现金额", 400);
      }
      const method = toString(body?.method || "manual");
      const payload =
        body?.accountPayload && typeof body.accountPayload === "object"
          ? body.accountPayload
          : null;

      const withdrawalId = await this.referralService.createWithdrawal({
        userId,
        amount,
        method,
        accountPayload: payload,
      });

      return successResponse(
        {
          id: withdrawalId,
        },
        "提现申请已提交，请等待审核"
      );
    } catch (error) {
      this.logger.error("提交提现申请失败", error);
      return errorResponse(toErrorMessage(error, "提现申请失败"), 400);
    }
  }

  async getRebateWithdrawals(request: Request) {
    try {
      const authResult = await this.validateUser(request);
      if (!authResult.success) {
        return errorResponse(authResult.message, 401);
      }
      const userId = ensureNumber(authResult.user.id);
      const url = new URL(request.url);
      const page = Math.max(1, Number.parseInt(url.searchParams.get("page") ?? "1", 10) || 1);
      const limit = Math.max(1, Number.parseInt(url.searchParams.get("limit") ?? "10", 10) || 10);
      const offset = (page - 1) * limit;

      const totalRow = await this.db.db
        .prepare("SELECT COUNT(*) as total FROM rebate_withdrawals WHERE user_id = ?")
        .bind(userId)
        .first<{ total?: number | string | null } | null>();

      const records = await this.db.db
        .prepare(
          `
          SELECT id, amount, method, status, account_payload, review_note, fee_rate, fee_amount, created_at, updated_at, processed_at
          FROM rebate_withdrawals
          WHERE user_id = ?
          ORDER BY id DESC
          LIMIT ? OFFSET ?
        `
        )
        .bind(userId, limit, offset)
        .all();

      const rows = (records.results ?? []) as DbRow[];
      const total = ensureNumber(totalRow?.total);

      return successResponse({
        records: rows.map((row) => ({
          id: ensureNumber(row.id),
          amount: toNumber(row.amount),
          method: toString(row.method),
          status: toString(row.status),
          accountPayload: row.account_payload ? JSON.parse(toString(row.account_payload)) : null,
          reviewNote: toString(row.review_note),
          feeRate: toNumber(row.fee_rate),
          feeAmount: toNumber(row.fee_amount),
          createdAt: toString(row.created_at),
          updatedAt: toString(row.updated_at),
          processedAt: toString(row.processed_at),
        })),
        pagination: {
          page,
          limit,
          total,
          totalPages: Math.max(1, Math.ceil(total / limit)),
        },
      });
    } catch (error) {
      this.logger.error("获取提现记录失败", error);
      return errorResponse(toErrorMessage(error, "获取提现记录失败"), 500);
    }
  }

}
