// src/services/database.ts - 数据库服务（更新版）

import type { D1Database } from "@cloudflare/workers-types";
import { ensureNumber, getChanges, toRunResult } from "../utils/d1";

export class DatabaseService {
  public readonly db: D1Database;
  private registerIpColumnChecked = false;
  private registerIpColumnExists = false;
  private telegramColumnsChecked = false;
  private telegramColumnsReady = false;
  private telegramRegisterSessionChecked = false;
  private telegramRegisterSessionReady = false;
  private xraySchemaChecked = false;
  private xraySchemaReady = false;

  constructor(db: D1Database) {
    this.db = db;
  }

  async ensureUsersRegisterIpColumn() {
    if (this.registerIpColumnChecked && this.registerIpColumnExists) {
      return true;
    }
    try {
      const info = await this.db
        .prepare("PRAGMA table_info(users)")
        .all<{ name?: string }>();
      const exists =
        info.results?.some((col) => {
          const name =
            typeof col?.name === "string"
              ? col.name
              : col?.name !== undefined && col?.name !== null
              ? String(col.name)
              : "";
          return name === "register_ip";
        }) ?? false;
      if (!exists) {
        await this.db
          .prepare("ALTER TABLE users ADD COLUMN register_ip TEXT")
          .run();
      }
      this.registerIpColumnExists = true;
      this.registerIpColumnChecked = true;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes("duplicate column name")) {
        this.registerIpColumnExists = true;
      } else {
        console.error("ensureUsersRegisterIpColumn error:", error);
        this.registerIpColumnExists = false;
      }
      if (this.registerIpColumnExists) {
        this.registerIpColumnChecked = true;
      }
    }
    return this.registerIpColumnExists;
  }

  async ensureUsersTelegramColumns() {
    if (this.telegramColumnsChecked && this.telegramColumnsReady) {
      return true;
    }

    try {
      const info = await this.db
        .prepare("PRAGMA table_info(users)")
        .all<{ name?: string }>();

      const columnNames = new Set(
        (info.results ?? []).map((col) => {
          if (typeof col?.name === "string") return col.name;
          if (col?.name !== undefined && col?.name !== null) return String(col.name);
          return "";
        })
      );

      if (!columnNames.has("telegram_id")) {
        await this.db.prepare("ALTER TABLE users ADD COLUMN telegram_id TEXT").run();
      }
      if (!columnNames.has("telegram_enabled")) {
        await this.db
          .prepare("ALTER TABLE users ADD COLUMN telegram_enabled INTEGER DEFAULT 0")
          .run();
      }
      if (!columnNames.has("telegram_bind_code")) {
        await this.db
          .prepare("ALTER TABLE users ADD COLUMN telegram_bind_code TEXT")
          .run();
      }
      if (!columnNames.has("telegram_bind_code_expires_at")) {
        await this.db
          .prepare("ALTER TABLE users ADD COLUMN telegram_bind_code_expires_at INTEGER")
          .run();
      }

      await this.db
        .prepare(
          `
          UPDATE users
          SET telegram_enabled = COALESCE(telegram_enabled, 0)
          WHERE telegram_enabled IS NULL
        `
        )
        .run();

      this.telegramColumnsReady = true;
      this.telegramColumnsChecked = true;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes("duplicate column name")) {
        this.telegramColumnsReady = true;
        this.telegramColumnsChecked = true;
      } else {
        console.error("ensureUsersTelegramColumns error:", error);
        this.telegramColumnsReady = false;
      }
    }

    return this.telegramColumnsReady;
  }

  async ensureTelegramRegisterSessionTable() {
    if (
      this.telegramRegisterSessionChecked &&
      this.telegramRegisterSessionReady
    ) {
      return true;
    }

    try {
      await this.db
        .prepare(
          `
          CREATE TABLE IF NOT EXISTS telegram_register_sessions (
            chat_id TEXT PRIMARY KEY,
            stage TEXT NOT NULL,
            human_code_hash TEXT,
            human_code_expires_at INTEGER,
            human_code_attempts INTEGER NOT NULL DEFAULT 0,
            email TEXT,
            username TEXT,
            invite_code TEXT,
            email_code_attempts INTEGER NOT NULL DEFAULT 0,
            session_expires_at INTEGER NOT NULL,
            created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
            updated_at DATETIME DEFAULT (datetime('now', '+8 hours'))
          )
        `
        )
        .run();

      await this.db
        .prepare(
          `
          CREATE INDEX IF NOT EXISTS idx_tg_register_session_expires
          ON telegram_register_sessions (session_expires_at)
        `
        )
        .run();

      await this.db
        .prepare(
          `
          CREATE INDEX IF NOT EXISTS idx_tg_register_session_stage
          ON telegram_register_sessions (stage)
        `
        )
        .run();

      this.telegramRegisterSessionReady = true;
      this.telegramRegisterSessionChecked = true;
    } catch (error) {
      console.error("ensureTelegramRegisterSessionTable error:", error);
      this.telegramRegisterSessionReady = false;
    }

    return this.telegramRegisterSessionReady;
  }

  async cleanupExpiredTelegramRegisterSessions(nowUnix = Math.floor(Date.now() / 1000)) {
    await this.ensureTelegramRegisterSessionTable();
    await this.db
      .prepare(
        `
        DELETE FROM telegram_register_sessions
        WHERE session_expires_at <= ?
      `
      )
      .bind(nowUnix)
      .run();
  }

  private normalizeIdList(value: unknown): number[] {
    let list: number[] = [];

    if (Array.isArray(value)) {
      list = value.map((item) => Number(item));
    } else if (typeof value === "string") {
      const trimmed = value.trim();
      if (!trimmed) {
        return [];
      }
      try {
        const parsed = JSON.parse(trimmed);
        if (Array.isArray(parsed)) {
          list = parsed.map((item) => Number(item));
        } else {
          list = trimmed.split(",").map((item) => Number(item.trim()));
        }
      } catch {
        list = trimmed.split(",").map((item) => Number(item.trim()));
      }
    }

    const unique = new Set<number>();
    for (const item of list) {
      const id = Number(item);
      if (Number.isFinite(id) && id > 0) {
        unique.add(id);
      }
    }
    return Array.from(unique);
  }

  async ensureXrayRuleSchema() {
    if (this.xraySchemaChecked && this.xraySchemaReady) {
      return true;
    }

    try {
      await this.db
        .prepare(
          `
          CREATE TABLE IF NOT EXISTS xray_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            rule_type TEXT NOT NULL CHECK (rule_type IN ('dns', 'routing', 'outbounds')),
            rule_format TEXT NOT NULL CHECK (rule_format IN ('json', 'yaml')),
            rule_content TEXT NOT NULL,
            rule_json TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
            updated_at DATETIME DEFAULT (datetime('now', '+8 hours'))
          )
        `
        )
        .run();

      const info = await this.db
        .prepare("PRAGMA table_info(nodes)")
        .all<{ name?: string }>();
      const hasXrayRuleIds =
        info.results?.some((col) => {
          const name =
            typeof col?.name === "string"
              ? col.name
              : col?.name !== undefined && col?.name !== null
              ? String(col.name)
              : "";
          return name === "xray_rule_ids";
        }) ?? false;

      if (!hasXrayRuleIds) {
        await this.db
          .prepare("ALTER TABLE nodes ADD COLUMN xray_rule_ids TEXT NOT NULL DEFAULT '[]'")
          .run();
      }

      await this.db
        .prepare(
          `
          UPDATE nodes
          SET xray_rule_ids = '[]'
          WHERE xray_rule_ids IS NULL OR TRIM(xray_rule_ids) = ''
        `
        )
        .run();

      this.xraySchemaReady = true;
      this.xraySchemaChecked = true;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (
        message.includes("duplicate column name") ||
        message.includes("already exists")
      ) {
        this.xraySchemaReady = true;
        this.xraySchemaChecked = true;
      } else {
        console.error("ensureXrayRuleSchema error:", error);
        this.xraySchemaReady = false;
      }
    }

    return this.xraySchemaReady;
  }

  // 获取节点信息
  async getNode(nodeId) {
    const stmt = this.db.prepare("SELECT * FROM nodes WHERE id = ?");
    return await stmt.bind(nodeId).first();
  }

  // 获取审计规则
  async getAuditRules() {
    const stmt = this.db.prepare("SELECT * FROM audit_rules WHERE enabled = 1");
    const result = await stmt.all();
    return result.results || [];
  }

  // 获取 Xray 规则（按节点）
  async getXrayRulesByNodeId(nodeId) {
    await this.ensureXrayRuleSchema();

    const node = await this.db
      .prepare("SELECT xray_rule_ids FROM nodes WHERE id = ?")
      .bind(nodeId)
      .first<{ xray_rule_ids?: string } | null>();
    const ruleIds = this.normalizeIdList(node?.xray_rule_ids ?? "[]");
    if (ruleIds.length === 0) {
      return [];
    }

    const placeholders = ruleIds.map(() => "?").join(", ");
    const stmt = this.db.prepare(
      `
      SELECT id, name, rule_type, rule_format, rule_content, rule_json, enabled, created_at, updated_at
      FROM xray_rules
      WHERE enabled = 1 AND id IN (${placeholders})
      ORDER BY id ASC
    `
    );
    const result = await stmt.bind(...ruleIds).all();
    return result.results || [];
  }

  // 获取白名单
  async getWhiteList() {
    const stmt = this.db.prepare("SELECT * FROM white_list WHERE status = 1");
    const result = await stmt.all();
    return result.results || [];
  }

  // 更新用户在线IP
  async updateUserAliveIPs(aliveData, nodeId) {
    for (const userRecord of aliveData) {
      const userId = userRecord.id;
      const ips = userRecord.ips || [];
      
      // 为每个用户的每个IP创建一条记录
      for (const ip of ips) {
        await this.db
          .prepare(
            `
          INSERT OR REPLACE INTO online_ips 
          (user_id, node_id, ip, last_seen)
          VALUES (?, ?, ?, datetime('now', '+8 hours'))
        `
          )
          .bind(userId, nodeId, ip)
          .run();
      }
    }
  }

  // 插入审计日志
  async insertAuditLogs(auditData, nodeId) {
    for (const log of auditData) {
      await this.db
        .prepare(
          `
        INSERT INTO audit_logs 
        (user_id, node_id, audit_rule_id, ip_address, created_at)
        VALUES (?, ?, ?, ?, datetime('now', '+8 hours'))
      `
        )
        .bind(log.user_id, nodeId, log.audit_id, log.ip_address || null)
        .run();
    }
  }

  // 插入节点状态
  async insertNodeStatus(statusData, nodeId) {
    await this.db
      .prepare(
        `
      INSERT INTO node_status 
      (node_id, cpu_usage, memory_total, memory_used, swap_total, swap_used, 
       disk_total, disk_used, uptime, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+8 hours'))
    `
      )
      .bind(
        nodeId,
        statusData.cpu || 0,
        statusData.mem?.total || 0,
        statusData.mem?.used || 0,
        statusData.swap?.total || 0,
        statusData.swap?.used || 0,
        statusData.disk?.total || 0,
        statusData.disk?.used || 0,
        statusData.uptime || 0
      )
      .run();
  }

  // 获取用户可访问的节点（基于等级）
  async getUserAccessibleNodes(userId) {
    const stmt = this.db.prepare(`
      SELECT n.*
      FROM nodes n, users u
      WHERE u.id = ? 
        AND u.status = 1
        AND (u.expire_time IS NULL OR u.expire_time > datetime('now', '+8 hours'))
        AND (u.class_expire_time IS NULL OR u.class_expire_time > datetime('now', '+8 hours'))
        AND n.status = 1
        AND n.node_class <= u.class
      ORDER BY n.node_class ASC, n.id ASC
    `);
    const result = await stmt.bind(userId).all();
    return result.results || [];
  }

  // 获取节点用户（用于 Soga API）
  async getNodeUsers(nodeId) {
    const stmt = this.db.prepare(`
      SELECT u.id, u.uuid, u.passwd as password, 
             u.speed_limit, u.device_limit, u.tcp_limit
      FROM users u, nodes n
      WHERE n.id = ? 
        AND u.status = 1 
        AND (u.expire_time IS NULL OR u.expire_time > datetime('now', '+8 hours'))
        AND (u.class_expire_time IS NULL OR u.class_expire_time > datetime('now', '+8 hours'))
        AND u.transfer_enable > u.transfer_total
        AND u.class >= n.node_class
    `);
    const result = await stmt.bind(nodeId).all();
    return result.results || [];
  }

  // 更新用户流量
  async updateUserTraffic(trafficData, nodeId) {
    const nodeRow = await this.db
      .prepare("SELECT traffic_multiplier FROM nodes WHERE id = ?")
      .bind(nodeId)
      .first<{ traffic_multiplier?: number | string | null } | null>();
    const rawMultiplier = ensureNumber(nodeRow?.traffic_multiplier, 1);
    const trafficMultiplier = rawMultiplier > 0 ? rawMultiplier : 1;
    const now = new Date(Date.now() + 8 * 60 * 60 * 1000);
    const date = now.toISOString().split("T")[0];

    for (const traffic of trafficData) {
      const userId = ensureNumber(traffic.id);
      if (userId <= 0) {
        continue;
      }
      const upload = Math.max(0, ensureNumber(traffic.u));
      const download = Math.max(0, ensureNumber(traffic.d));
      const total = upload + download;
      const actualUpload = Math.max(
        0,
        Math.round(upload * trafficMultiplier)
      );
      const actualDownload = Math.max(
        0,
        Math.round(download * trafficMultiplier)
      );
      const deductedTotal = Math.max(0, actualUpload + actualDownload);

      // 更新用户总流量和今日流量（分别记录上传和下载）
      await this.db
        .prepare(
          `
        UPDATE users 
        SET upload_traffic = upload_traffic + ?, 
            download_traffic = download_traffic + ?,
            upload_today = upload_today + ?,
            download_today = download_today + ?,
            transfer_total = transfer_total + ?,
            updated_at = datetime('now', '+8 hours')
        WHERE id = ?
      `
        )
        .bind(
          upload,
          download,
          upload,
          download,
          deductedTotal,
          userId
        )
        .run();

      // 记录流量日志 - 每次提交都记录新条目（已移除UNIQUE约束）
      await this.db
        .prepare(
          `
        INSERT INTO traffic_logs 
        (user_id, node_id, upload_traffic, download_traffic, actual_upload_traffic, actual_download_traffic, actual_traffic, deduction_multiplier, date, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+8 hours'))
      `
        )
        .bind(
          userId,
          nodeId,
          upload,
          download,
          actualUpload,
          actualDownload,
          deductedTotal,
          trafficMultiplier,
          date
        )
        .run();
    }

    // 更新节点流量
    const totalTraffic = trafficData.reduce(
      (sum, t) => sum + ensureNumber(t.u) + ensureNumber(t.d),
      0
    );
    await this.db
      .prepare(
        `
      UPDATE nodes 
      SET node_bandwidth = node_bandwidth + ?,
          updated_at = datetime('now', '+8 hours')
      WHERE id = ?
    `
      )
      .bind(totalTraffic, nodeId)
      .run();
  }

  // ===== 新增：用户等级过期检测相关方法 =====

  /**
   * 获取等级过期的用户列表
   * @returns {Promise<Array>} 过期用户列表
   */
  async getExpiredLevelUsers() {
    const stmt = this.db.prepare(`
      SELECT id, email, username, class, class_expire_time,
             upload_traffic, download_traffic, transfer_today, 
             transfer_total, transfer_enable
      FROM users 
      WHERE class_expire_time IS NOT NULL 
        AND class_expire_time < datetime('now', '+8 hours')
        AND class > 0
        AND status = 1
    `);
    const result = await stmt.all();
    return result.results || [];
  }

  /**
   * 批量重置过期用户的等级和流量
   * @param {Array} userIds 用户ID数组
   * @returns {Promise<void>}
   */
  async resetExpiredUsersLevel(userIds) {
    if (!userIds || userIds.length === 0) return;

    // 验证userIds都是数字类型，防止注入
    const validIds = userIds.filter(id => Number.isInteger(Number(id)) && Number(id) > 0);
    if (validIds.length === 0) return;

    // 构建批量更新语句
    const placeholders = validIds.map(() => "?").join(",");
    const stmt = this.db.prepare(`
      UPDATE users 
      SET class = 0,
          class_expire_time = NULL,
          upload_traffic = 0,
          download_traffic = 0,
          transfer_today = 0,
          transfer_total = 0,
          transfer_enable = 0,
          updated_at = datetime('now', '+8 hours')
      WHERE id IN (${placeholders})
    `);

    await stmt.bind(...validIds).run();
  }

  /**
   * 单个用户等级重置（带详细日志）
   * @param {number} userId 用户ID
   * @param {Object} userInfo 用户信息（用于日志）
   * @returns {Promise<Object>} 重置结果
   */
  async resetUserLevel(userId, userInfo = {}) {
    try {
      // 获取重置前的数据
      const beforeData = await this.db
        .prepare(
          `
        SELECT class, upload_traffic, download_traffic, 
               transfer_today, transfer_total, transfer_enable
        FROM users WHERE id = ?
      `
        )
        .bind(userId)
        .first();

      // 执行重置
    const result = toRunResult(
      await this.db
        .prepare(
          `
        UPDATE users 
        SET class = 0,
            class_expire_time = NULL,
            upload_traffic = 0,
            download_traffic = 0,
            transfer_today = 0,
            transfer_total = 0,
            transfer_enable = 0,
            updated_at = datetime('now', '+8 hours')
        WHERE id = ?
      `
        )
        .bind(userId)
        .run()
    );

    return {
      success: true,
      userId: userId,
      beforeData: beforeData,
      resetTime: new Date().toISOString(),
      changesCount: getChanges(result),
    };
  } catch (error) {
      console.error(`Error resetting user ${userId} level:`, error);
      return {
        success: false,
        userId: userId,
        error: error.message,
      };
    }
  }

  /**
   * 记录用户等级重置日志
   * @param {Array} resetResults 重置结果数组
   * @returns {Promise<void>}
   */
  async logLevelResets(resetResults) {
    try {
      for (const result of resetResults) {
        if (result.success) {
          console.log(`User ${result.userId} level reset successful:`, {
            before: result.beforeData,
            resetTime: result.resetTime,
            changes: result.changesCount,
          });
        } else {
          console.error(
            `User ${result.userId} level reset failed:`,
            result.error
          );
        }
      }
    } catch (error) {
      console.error("Error logging level resets:", error);
    }
  }

  /**
   * 获取系统统计信息（包含过期用户统计）
   * @returns {Promise<Object>} 统计信息
   */
  async getSystemStats() {
    const stats = await this.db
      .prepare(
        `
      SELECT 
        (SELECT COUNT(*) FROM users WHERE status = 1) as active_users,
        (SELECT COUNT(*) FROM users WHERE class_expire_time IS NOT NULL 
         AND class_expire_time < datetime('now', '+8 hours') AND class > 0) as expired_level_users,
        (SELECT COUNT(*) FROM users WHERE expire_time < datetime('now', '+8 hours')) as expired_account_users,
        (SELECT COUNT(*) FROM users WHERE transfer_total >= transfer_enable) as exhausted_users,
        (SELECT COUNT(*) FROM nodes WHERE status = 1) as active_nodes
    `
      )
      .first();

    return stats || {};
  }
}
