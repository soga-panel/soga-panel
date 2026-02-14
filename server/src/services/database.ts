import { MariaD1Database } from "../db/d1-adapter";
import { ensureNumber, getChanges, getLastRowId, toRunResult } from "../utils/d1";

// MariaDB 版数据库服务，尽量复用 Worker 逻辑
export class DatabaseService {
  public readonly db: MariaD1Database;
  private registerIpColumnChecked = false;
  private registerIpColumnExists = false;

  constructor(db: MariaD1Database) {
    this.db = db;
  }

  async ensureUsersRegisterIpColumn() {
    if (this.registerIpColumnChecked && this.registerIpColumnExists) {
      return true;
    }
    try {
      await this.db
        .prepare(
          "ALTER TABLE users ADD COLUMN IF NOT EXISTS register_ip VARCHAR(255)"
        )
        .run();
      this.registerIpColumnExists = true;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes("Duplicate column")) {
        this.registerIpColumnExists = true;
      } else {
        console.error("ensureUsersRegisterIpColumn error:", error);
        this.registerIpColumnExists = false;
      }
    }
    this.registerIpColumnChecked = true;
    return this.registerIpColumnExists;
  }

  async getNode(nodeId: number) {
    return await this.db.prepare("SELECT * FROM nodes WHERE id = ?").bind(nodeId).first();
  }

  async getAuditRules() {
    const result = await this.db.prepare("SELECT * FROM audit_rules WHERE enabled = 1").all();
    return result.results || [];
  }

  async getDnsRulesByNodeId(nodeId: number) {
    const result = await this.db
      .prepare(
        `
        SELECT id, rule_json
        FROM dns_rules
        WHERE enabled = 1
          AND JSON_CONTAINS(node_ids, JSON_ARRAY(?))
        ORDER BY id ASC
        LIMIT 2
      `
      )
      .bind(nodeId)
      .all();
    return result.results || [];
  }

  async getWhiteList() {
    const result = await this.db.prepare("SELECT * FROM white_list WHERE status = 1").all();
    return result.results || [];
  }

  async updateUserAliveIPs(aliveData: Array<{ id: number; ips?: string[] }>, nodeId: number) {
    for (const userRecord of aliveData) {
      const userId = userRecord.id;
      const ips = userRecord.ips || [];
      for (const ip of ips) {
        await this.db
          .prepare(
            `
            INSERT INTO online_ips (user_id, node_id, ip, last_seen)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON DUPLICATE KEY UPDATE last_seen = VALUES(last_seen)
          `
          )
          .bind(userId, nodeId, ip)
          .run();
      }
    }
  }

  async insertAuditLogs(
    auditData: Array<{ user_id: number; audit_id: number; ip_address?: string }>,
    nodeId: number
  ) {
    for (const log of auditData) {
      await this.db
        .prepare(
          `
          INSERT INTO audit_logs (user_id, node_id, audit_rule_id, ip_address, created_at)
          VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        `
        )
        .bind(log.user_id, nodeId, log.audit_id, log.ip_address || null)
        .run();
    }
  }

  async insertNodeStatus(
    statusData: {
      cpu?: number;
      mem?: { total?: number; used?: number };
      swap?: { total?: number; used?: number };
      disk?: { total?: number; used?: number };
      uptime?: number;
    },
    nodeId: number
  ) {
    await this.db
      .prepare(
        `
        INSERT INTO node_status 
        (node_id, cpu_usage, memory_total, memory_used, swap_total, swap_used, 
         disk_total, disk_used, uptime, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
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

  async getUserAccessibleNodes(userId: number) {
    const result = await this.db
      .prepare(
        `
        SELECT n.*
        FROM nodes n, users u
        WHERE u.id = ? 
          AND u.status = 1
          AND (u.expire_time IS NULL OR u.expire_time > CURRENT_TIMESTAMP)
          AND (u.class_expire_time IS NULL OR u.class_expire_time > CURRENT_TIMESTAMP)
          AND n.status = 1
          AND n.node_class <= u.class
        ORDER BY n.node_class ASC, n.id ASC
      `
      )
      .bind(userId)
      .all();
    return result.results || [];
  }

  async getNodeUsers(nodeId: number) {
    const result = await this.db
      .prepare(
        `
        SELECT u.id, u.uuid, u.passwd as password, 
               u.speed_limit, u.device_limit, u.tcp_limit
        FROM users u, nodes n
        WHERE n.id = ? 
          AND u.status = 1 
          AND (u.expire_time IS NULL OR u.expire_time > CURRENT_TIMESTAMP)
          AND (u.class_expire_time IS NULL OR u.class_expire_time > CURRENT_TIMESTAMP)
          AND u.transfer_enable > u.transfer_total
          AND u.class >= n.node_class
      `
      )
      .bind(nodeId)
      .all();
    return result.results || [];
  }

  async getUserByEmail(email: string) {
    return await this.db
      .prepare(
        `
        SELECT * FROM users WHERE email = ?
      `
      )
      .bind(email)
      .first();
  }

  async getUserByInviteCode(code: string) {
    return await this.db
      .prepare(
        `
        SELECT * FROM users WHERE LOWER(invite_code) = LOWER(?) LIMIT 1
      `
      )
      .bind(code)
      .first();
  }

  async getUserInviteStats(userId: number) {
    const user = await this.db
      .prepare("SELECT invite_code, invited_by, invite_used, invite_limit, rebate_available, rebate_total FROM users WHERE id = ?")
      .bind(userId)
      .first<{
        invite_code?: string | null;
        invited_by?: number | null;
        invite_used?: number | string | null;
        invite_limit?: number | string | null;
        rebate_available?: number | string | null;
        rebate_total?: number | string | null;
      }>();
    const totalRows = await this.db
      .prepare("SELECT COUNT(*) as total, SUM(CASE WHEN status = 'confirmed' THEN 1 ELSE 0 END) as confirmed FROM referral_relations WHERE inviter_id = ?")
      .bind(userId)
      .first<{ total?: number | string | null; confirmed?: number | string | null }>();
    return {
      invite_code: user?.invite_code ?? null,
      invited_by: user?.invited_by ?? null,
      invite_used: Number(user?.invite_used ?? 0),
      invite_limit: Number(user?.invite_limit ?? 0),
      rebate_available: Number(user?.rebate_available ?? 0),
      rebate_total: Number(user?.rebate_total ?? 0),
      total_invitees: Number(totalRows?.total ?? 0),
      confirmed_invitees: Number(totalRows?.confirmed ?? 0)
    };
  }

  async ensureUserInviteCode(userId: number, generate: () => string) {
    const row = await this.db
      .prepare("SELECT invite_code FROM users WHERE id = ?")
      .bind(userId)
      .first<{ invite_code?: string | null }>();
    if (row?.invite_code) return row.invite_code;
    const code = generate();
    await this.db
      .prepare("UPDATE users SET invite_code = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
      .bind(code, userId)
      .run();
    return code;
  }

  async getUserByUsername(username: string) {
    return await this.db
      .prepare(
        `
        SELECT * FROM users WHERE username = ?
      `
      )
      .bind(username)
      .first();
  }

  async createUser(payload: {
    email: string;
    username: string;
    password_hash: string;
    uuid: string;
    passwd: string;
    token: string;
    register_ip?: string | null;
    invited_by?: number | null;
    invite_limit?: number | null;
  }) {
    const result = await this.db
      .prepare(
        `
        INSERT INTO users (email, username, password_hash, uuid, passwd, token, register_ip, invited_by, invite_limit, reg_date, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      `
      )
      .bind(
        payload.email,
        payload.username,
        payload.password_hash,
        payload.uuid,
        payload.passwd,
        payload.token,
        payload.register_ip ?? null,
        payload.invited_by ?? 0,
        payload.invite_limit ?? 0
      )
      .run();

    return getLastRowId(toRunResult(result));
  }

  async updateLoginInfo(userId: number, ip?: string | null) {
    await this.db
      .prepare(
        `
        UPDATE users 
        SET last_login_time = CURRENT_TIMESTAMP,
            last_login_ip = COALESCE(?, last_login_ip),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `
      )
      .bind(ip ?? null, userId)
      .run();
  }

  async updateUserPassword(userId: number, passwordHash: string) {
    await this.db
      .prepare(
        `
        UPDATE users 
        SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `
      )
      .bind(passwordHash, userId)
      .run();
  }

  async listPasskeys(userId: number) {
    const result = await this.db
      .prepare(
        `
        SELECT * FROM passkeys WHERE user_id = ?
      `
      )
      .bind(userId)
      .all();
    return result.results || [];
  }

  async getPasskeyByCredentialId(credentialId: string) {
    return await this.db
      .prepare(
        `
        SELECT * FROM passkeys WHERE credential_id = ?
      `
      )
      .bind(credentialId)
      .first();
  }

  async insertPasskey(params: {
    userId: number;
    credentialId: string;
    publicKey: string;
    alg: number;
    userHandle?: string | null;
    rpId?: string | null;
    transports?: string[] | null;
    signCount?: number | null;
    deviceName?: string | null;
  }) {
    await this.db
      .prepare(
        `
        INSERT INTO passkeys (user_id, credential_id, public_key, alg, user_handle, rp_id, transports, sign_count, device_name, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      `
      )
      .bind(
        params.userId,
        params.credentialId,
        params.publicKey,
        params.alg,
        params.userHandle ?? null,
        params.rpId ?? null,
        params.transports ? JSON.stringify(params.transports) : null,
        params.signCount ?? 0,
        params.deviceName ?? null
      )
      .run();
  }

  async updatePasskeyUsage(credentialId: string, signCount?: number | null) {
    await this.db
      .prepare(
        `
        UPDATE passkeys
        SET sign_count = COALESCE(?, sign_count),
            last_used_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE credential_id = ?
      `
      )
      .bind(signCount ?? null, credentialId)
      .run();
  }

  async updateUserBarkSettings(userId: number, barkKey: string | null, enabled: boolean) {
    await this.db
      .prepare(
        `
        UPDATE users 
        SET bark_key = ?, bark_enabled = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `
      )
      .bind(barkKey, enabled ? 1 : 0, userId)
      .run();
  }

  async listSubscriptionLogs(userId: number, limit = 50) {
    const result = await this.db
      .prepare(
        `
        SELECT id, type, request_ip, request_time, request_user_agent
        FROM subscriptions
        WHERE user_id = ?
        ORDER BY request_time DESC
        LIMIT ?
      `
      )
      .bind(userId, limit)
      .all();
    return result.results || [];
  }

  async listTrafficLogs(userId: number, limit = 50) {
    const result = await this.db
      .prepare(
        `
        SELECT id, node_id, upload_traffic, download_traffic, actual_traffic, date, created_at
        FROM traffic_logs
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ?
      `
      )
      .bind(userId, limit)
      .all();
    return result.results || [];
  }

  async listOnlineIps(userId: number, limit = 50, recentMinutes = 5) {
    const safeLimit = Math.max(1, Math.min(limit, 200));
    const minutes =
      Number.isFinite(recentMinutes) && recentMinutes
        ? Math.min(Math.max(Math.floor(Number(recentMinutes)), 1), 24 * 60)
        : 5;

    const result = await this.db.db
      .prepare(
        `
        SELECT oi.id, oi.node_id, oi.ip, oi.last_seen, n.name as node_name
        FROM online_ips oi
        LEFT JOIN nodes n ON oi.node_id = n.id
        WHERE oi.user_id = ?
          AND oi.last_seen >= DATE_SUB(NOW(), INTERVAL ${minutes} MINUTE)
        ORDER BY oi.last_seen DESC
        LIMIT ?
      `
      )
      .bind(userId, safeLimit)
      .all();
    return result.results || [];
  }

  async listUsers(params: {
    page: number;
    pageSize: number;
    search?: string;
    class?: number;
    status?: number;
  }) {
    const page = params.page > 0 ? params.page : 1;
    const pageSize = params.pageSize > 0 ? params.pageSize : 20;
    const offset = (page - 1) * pageSize;

    const conditions: string[] = [];
    const values: any[] = [];

    if (params.search && params.search.trim()) {
      const keyword = `%${params.search.trim()}%`;
      conditions.push("(email LIKE ? OR username LIKE ?)");
      values.push(keyword, keyword);
    }

    if (typeof params.class === "number" && !Number.isNaN(params.class)) {
      conditions.push("class = ?");
      values.push(params.class);
    }

    if (typeof params.status === "number" && !Number.isNaN(params.status)) {
      conditions.push("status = ?");
      values.push(params.status);
    }

    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

    const rows = await this.db.db
      .prepare(
        `
        SELECT 
          id,
          email,
          username,
          uuid,
          class,
          class_expire_time,
          upload_traffic,
          download_traffic,
          (upload_today + download_today) AS transfer_today,
          transfer_enable,
          transfer_total,
          expire_time,
          status,
          is_admin,
          reg_date,
          last_login_time,
          created_at,
          bark_key,
          bark_enabled,
          speed_limit,
          device_limit,
          money,
          register_ip,
          invite_code,
          invite_limit,
          invite_used
        FROM users
        ${where}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
      `
      )
      .bind(...values, pageSize, offset)
      .all();
    const count = await this.db.db
      .prepare(`SELECT COUNT(*) as total FROM users ${where}`)
      .bind(...values)
      .first<{ total?: number }>();
    return {
      data: rows.results || [],
      total: Number(count?.total ?? 0)
    };
  }

  async updateUserStatus(userId: number, status: number) {
    await this.db.db
      .prepare(
        `
        UPDATE users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
      `
      )
      .bind(status, userId)
      .run();
  }

  async listPackages() {
    const result = await this.db.db
      .prepare(
        `
        SELECT id, name, price, traffic_quota, validity_days, speed_limit, device_limit, level, status, is_recommended, sort_weight
        FROM packages
        WHERE status = 1
        ORDER BY sort_weight DESC, id DESC
      `
      )
      .all();
    return result.results || [];
  }

  async getPackageById(id: number) {
    return await this.db.db
      .prepare(
        `
        SELECT * FROM packages WHERE id = ? AND status = 1
      `
      )
      .bind(id)
      .first();
  }

  async getPackageByIdAny(id: number) {
    return await this.db.db
      .prepare(
        `
        SELECT * FROM packages WHERE id = ?
      `
      )
      .bind(id)
      .first();
  }

  async createPurchaseRecord(params: {
    userId: number;
    packageId: number;
    price: number;
    tradeNo: string;
    status?: number;
    purchaseType?: string | null;
    couponId?: number | null;
    couponCode?: string | null;
    discountAmount?: number | null;
    packagePrice?: number | null;
  }) {
    await this.db.db
      .prepare(
        `
        INSERT INTO package_purchase_records (
          user_id, package_id, price, package_price, coupon_id, coupon_code, discount_amount, trade_no, status, purchase_type, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      `
      )
      .bind(
        params.userId,
        params.packageId,
        params.price,
        params.packagePrice ?? params.price,
        params.couponId ?? null,
        params.couponCode ?? null,
        params.discountAmount ?? 0,
        params.tradeNo,
        params.status ?? 0,
        params.purchaseType ?? "online"
      )
      .run();
  }

  async listPurchaseRecords(userId: number, limit = 20, offset = 0) {
    const rows = await this.db.db
      .prepare(
        `
        SELECT id, package_id, price, trade_no, status, created_at, paid_at, expires_at
        FROM package_purchase_records
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
      `
      )
      .bind(userId, limit, offset)
      .all();
    return rows.results || [];
  }

  async getCouponByCode(code: string) {
    return await this.db.db
      .prepare(
        `
        SELECT * FROM coupons WHERE code = ? AND status = 1
      `
      )
      .bind(code)
      .first();
  }

  async updateCoupon(
    id: number,
    payload: Partial<{
      name: string;
      code: string;
      discount_type: string;
      discount_value: number;
      start_at: number;
      end_at: number;
      max_usage: number | null;
      per_user_limit: number | null;
      status: number;
      description: string | null;
    }>
  ) {
    const fields: string[] = [];
    const values: any[] = [];

    if (payload.name !== undefined) {
      fields.push("name = ?");
      values.push(payload.name);
    }
    if (payload.code !== undefined) {
      fields.push("code = ?");
      values.push(payload.code);
    }
    if (payload.discount_type !== undefined) {
      fields.push("discount_type = ?");
      values.push(payload.discount_type);
    }
    if (payload.discount_value !== undefined) {
      fields.push("discount_value = ?");
      values.push(Number(payload.discount_value));
    }
    if (payload.start_at !== undefined) {
      fields.push("start_at = ?");
      values.push(Number(payload.start_at));
    }
    if (payload.end_at !== undefined) {
      fields.push("end_at = ?");
      values.push(Number(payload.end_at));
    }
    if (payload.max_usage !== undefined) {
      fields.push("max_usage = ?");
      values.push(payload.max_usage === null ? null : Number(payload.max_usage));
    }
    if (payload.per_user_limit !== undefined) {
      fields.push("per_user_limit = ?");
      values.push(payload.per_user_limit === null ? null : Number(payload.per_user_limit));
    }
    if (payload.status !== undefined) {
      fields.push("status = ?");
      values.push(Number(payload.status));
    }
    if (payload.description !== undefined) {
      fields.push("description = ?");
      values.push(payload.description);
    }

    if (!fields.length) return;
    values.push(id);
    await this.db.db
      .prepare(
        `
        UPDATE coupons 
        SET ${fields.join(", ")}, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `
      )
      .bind(...values)
      .run();
  }

  async countCouponUsage(couponId: number, userId: number) {
    const total = await this.db.db
      .prepare("SELECT COUNT(*) as total FROM coupon_usages WHERE coupon_id = ?")
      .bind(couponId)
      .first<{ total?: number }>();
    const byUser = await this.db.db
      .prepare("SELECT COUNT(*) as total FROM coupon_usages WHERE coupon_id = ? AND user_id = ?")
      .bind(couponId, userId)
      .first<{ total?: number }>();
    return {
      total: Number(total?.total ?? 0),
      byUser: Number(byUser?.total ?? 0)
    };
  }

  async recordCouponUsage(params: { couponId: number; userId: number; tradeNo?: string | null }) {
    await this.db.db
      .prepare(
        `
        INSERT INTO coupon_usages (coupon_id, user_id, order_trade_no, used_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
      `
      )
      .bind(params.couponId, params.userId, params.tradeNo ?? null)
      .run();
    await this.db.db
      .prepare(
        `
        UPDATE coupons SET total_used = total_used + 1 WHERE id = ?
      `
      )
      .bind(params.couponId)
      .run();
  }

  async updateUserProfile(userId: number, payload: { username?: string; email?: string }) {
    const fields: string[] = [];
    const values: any[] = [];
    if (payload.username !== undefined) {
      fields.push("username = ?");
      values.push(payload.username);
    }
    if (payload.email !== undefined) {
      fields.push("email = ?");
      values.push(payload.email);
    }
    if (!fields.length) return;
    values.push(userId);
    await this.db.db
      .prepare(
        `
        UPDATE users 
        SET ${fields.join(", ")}, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `
      )
      .bind(...values)
      .run();
  }

  async listOnlineDevices(userId: number, recentMinutes = 2) {
    const minutes =
      Number.isFinite(recentMinutes) && recentMinutes
        ? Math.min(Math.max(Math.floor(Number(recentMinutes)), 1), 24 * 60)
        : 2;

    const result = await this.db.db
      .prepare(
        `
        SELECT 
          ip,
          MIN(node_id) as node_id,
          MAX(last_seen) as last_seen
        FROM online_ips 
        WHERE user_id = ?
          AND last_seen >= DATE_SUB(NOW(), INTERVAL ${minutes} MINUTE)
        GROUP BY ip
        ORDER BY last_seen DESC
      `
      )
      .bind(userId)
      .all();
    return result.results || [];
  }

  async getUserBalance(userId: number) {
    const row = await this.db.db
      .prepare("SELECT money FROM users WHERE id = ?")
      .bind(userId)
      .first<{ money?: number }>();
    return Number(row?.money ?? 0);
  }

  async createRechargeRecord(userId: number, amount: number, tradeNo: string, method?: string | null) {
    await this.db.db
      .prepare(
        `
        INSERT INTO recharge_records (user_id, amount, payment_method, trade_no, status, created_at)
        VALUES (?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
      `
      )
      .bind(userId, amount, method ?? "manual", tradeNo)
      .run();
  }

  async markRechargePaid(tradeNo: string) {
    const record = await this.db.db
      .prepare("SELECT * FROM recharge_records WHERE trade_no = ?")
      .bind(tradeNo)
      .first<{ id: number; user_id: number; amount: number; status: number }>();
    if (!record) return null;

    const updateResult = toRunResult(
      await this.db.db
        .prepare(
          `
          UPDATE recharge_records 
          SET status = 1, paid_at = CURRENT_TIMESTAMP
          WHERE trade_no = ? AND status = 0
        `
        )
        .bind(tradeNo)
        .run()
    );

    if (getChanges(updateResult) === 0) {
      const latest = await this.db.db
        .prepare("SELECT status FROM recharge_records WHERE trade_no = ?")
        .bind(tradeNo)
        .first<{ status?: number | string | null }>();
      const isPaid = ensureNumber(latest?.status ?? record.status, 0) === 1;
      return { record, applied: false, alreadyPaid: isPaid };
    }

    await this.db.db
      .prepare(
        `
        UPDATE users 
        SET money = money + ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `
      )
      .bind(Number(record.amount), Number(record.user_id))
      .run();

    return { record, applied: true, alreadyPaid: false };
  }

  async markPurchasePaid(tradeNo: string) {
    const record = await this.db.db
      .prepare("SELECT * FROM package_purchase_records WHERE trade_no = ?")
      .bind(tradeNo)
      .first<{
        id: number;
        user_id: number;
        package_id: number;
        status: number;
        price?: number | null;
        package_price?: number | null;
        discount_amount?: number | null;
        coupon_id?: number | null;
        coupon_code?: string | null;
        purchase_type?: string | null;
      }>();
    if (!record) return null;

    const pkg = await this.getPackageByIdAny(Number(record.package_id));
    if (!pkg) throw new Error("套餐不存在或已下架");

    const updateResult = toRunResult(
      await this.db.db
        .prepare(
          `
          UPDATE package_purchase_records 
          SET status = 1, paid_at = CURRENT_TIMESTAMP
          WHERE trade_no = ? AND status = 0
        `
        )
        .bind(tradeNo)
        .run()
    );

    if (getChanges(updateResult) === 0) {
      const latest = await this.db.db
        .prepare("SELECT status, paid_at, expires_at FROM package_purchase_records WHERE trade_no = ?")
        .bind(tradeNo)
        .first<{ status?: number | string | null; paid_at?: string | null; expires_at?: string | null }>();
      const isPaid = ensureNumber(latest?.status ?? record.status, 0) === 1;
      return {
        record: {
          ...record,
          status: ensureNumber(latest?.status ?? record.status, 0),
          paid_at: latest?.paid_at ?? (record as any).paid_at,
          expires_at: latest?.expires_at ?? (record as any).expires_at
        },
        applied: false,
        alreadyPaid: isPaid
      };
    }

    // 补差额场景：支付完成后扣除余额部分（在线支付补差额）
    const purchaseType = String(record.purchase_type || "").toLowerCase();
    if (purchaseType.startsWith("balance_")) {
      const basePrice = Number(record.package_price ?? record.price ?? 0);
      const discount = Number(record.discount_amount ?? 0);
      const onlinePaid = Number(record.price ?? 0);
      const balanceNeed = Math.max(basePrice - discount - onlinePaid, 0);
      if (balanceNeed > 0) {
        const ok = await this.deductUserBalance(Number(record.user_id), balanceNeed);
        if (!ok) {
          await this.db.db
            .prepare(
              `
              UPDATE package_purchase_records
              SET status = 0, paid_at = NULL
              WHERE trade_no = ? AND status = 1
            `
            )
            .bind(tradeNo)
            .run();
          throw new Error("余额扣除失败，请联系管理员");
        }
      }
    }

    if (record.coupon_id) {
      await this.recordCouponUsage({
        couponId: Number(record.coupon_id),
        userId: Number(record.user_id),
        tradeNo
      });
    }

    const applyResult = await this.updateUserAfterPackagePurchase(Number(record.user_id), pkg);
    if (applyResult.success && applyResult.newExpireTime) {
      await this.db.db
        .prepare(
          `
          UPDATE package_purchase_records
          SET expires_at = ?
          WHERE trade_no = ?
        `
        )
        .bind(applyResult.newExpireTime, tradeNo)
        .run();
    }

    return {
      record: { ...record, status: 1, paid_at: new Date().toISOString(), expires_at: applyResult.newExpireTime ?? null },
      applied: true,
      alreadyPaid: false
    };
  }

  async deductUserBalance(userId: number, amount: number) {
    const result = toRunResult(
      await this.db.db
        .prepare(
          `
          UPDATE users
          SET money = money - ?, updated_at = CURRENT_TIMESTAMP
          WHERE id = ? AND money >= ?
        `
        )
        .bind(amount, userId, amount)
        .run()
    );
    return getChanges(result) > 0;
  }

  async listRechargeRecords(userId: number, limit = 20, offset = 0) {
    const rows = await this.db.db
      .prepare(
        `
        SELECT 
          rr.id,
          rr.amount,
          rr.payment_method,
          rr.trade_no,
          rr.status,
          rr.created_at,
          rr.paid_at,
          gcr.code AS gift_card_code
        FROM recharge_records rr
        LEFT JOIN gift_card_redemptions gcr ON gcr.recharge_record_id = rr.id
        WHERE rr.user_id = ?
        ORDER BY rr.created_at DESC
        LIMIT ? OFFSET ?
      `
      )
      .bind(userId, limit, offset)
      .all();
    return rows.results || [];
  }

  async listAllLoginLogs(page: number, pageSize: number) {
    const offset = (page - 1) * pageSize;
    const rows = await this.db.db
      .prepare(
        `
        SELECT l.*, u.email, u.username
        FROM login_logs l
        LEFT JOIN users u ON l.user_id = u.id
        ORDER BY l.created_at DESC
        LIMIT ? OFFSET ?
      `
      )
      .bind(pageSize, offset)
      .all();
    const total = await this.db.db.prepare("SELECT COUNT(*) as total FROM login_logs").first<{ total?: number }>();
    return {
      data: rows.results || [],
      total: Number(total?.total ?? 0)
    };
  }

  async listAllSubscriptionLogs(page: number, pageSize: number) {
    const offset = (page - 1) * pageSize;
    const rows = await this.db.db
      .prepare(
        `
        SELECT s.*, u.email, u.username
        FROM subscriptions s
        LEFT JOIN users u ON s.user_id = u.id
        ORDER BY s.request_time DESC
        LIMIT ? OFFSET ?
      `
      )
      .bind(pageSize, offset)
      .all();
    const total = await this.db.db.prepare("SELECT COUNT(*) as total FROM subscriptions").first<{ total?: number }>();
    return {
      data: rows.results || [],
      total: Number(total?.total ?? 0)
    };
  }

  async listSystemTrafficSummary(days = 30) {
    const rows = await this.db.db
      .prepare(
        `
        SELECT record_date, total_users, total_upload, total_download, total_traffic
        FROM system_traffic_summary
        WHERE record_date >= DATE_SUB(CURRENT_DATE, INTERVAL ? DAY)
        ORDER BY record_date DESC
      `
      )
      .bind(days)
      .all();
    return rows.results || [];
  }

  async resetTodayBandwidth() {
    await this.db.db.prepare("UPDATE users SET upload_today = 0, download_today = 0").run();
  }

  async listUsersWithBalance(page: number, pageSize: number) {
    const offset = (page - 1) * pageSize;
    const rows = await this.db.db
      .prepare(
        `
        SELECT id, email, username, money, rebate_available, rebate_total, created_at
        FROM users
        ORDER BY id DESC
        LIMIT ? OFFSET ?
      `
      )
      .bind(pageSize, offset)
      .all();
    const total = await this.db.db.prepare("SELECT COUNT(*) as total FROM users").first<{ total?: number }>();
    return { data: rows.results || [], total: Number(total?.total ?? 0) };
  }

  async transferRebateToBalance(userId: number, amount: number) {
    const user = await this.db.db
      .prepare("SELECT rebate_available FROM users WHERE id = ?")
      .bind(userId)
      .first<{ rebate_available?: number }>();
    const available = Number(user?.rebate_available ?? 0);
    if (amount > available) throw new Error("返利余额不足");

    await this.db.db
      .prepare(
        `
        UPDATE users 
        SET rebate_available = rebate_available - ?, money = money + ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `
      )
      .bind(amount, amount, userId)
      .run();
  }

  async listSharedIds() {
    const rows = await this.db.db
      .prepare(
        `
        SELECT id, name, fetch_url, remote_account_id, status, created_at, updated_at
        FROM shared_ids
        ORDER BY id DESC
      `
      )
      .all();
    return rows.results || [];
  }

  async createSharedId(params: { name: string; fetchUrl: string; remoteAccountId: string; status?: number }) {
    await this.db.db
      .prepare(
        `
        INSERT INTO shared_ids (name, fetch_url, remote_account_id, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      `
      )
      .bind(params.name, params.fetchUrl, params.remoteAccountId, params.status ?? 1)
      .run();
  }

  async updateSharedId(id: number, params: Partial<{ name: string; fetchUrl: string; remoteAccountId: string; status: number }>) {
    const fields: string[] = [];
    const values: any[] = [];
    if (params.name !== undefined) {
      fields.push("name = ?");
      values.push(params.name);
    }
    if (params.fetchUrl !== undefined) {
      fields.push("fetch_url = ?");
      values.push(params.fetchUrl);
    }
    if (params.remoteAccountId !== undefined) {
      fields.push("remote_account_id = ?");
      values.push(params.remoteAccountId);
    }
    if (params.status !== undefined) {
      fields.push("status = ?");
      values.push(params.status);
    }
    if (!fields.length) return;
    values.push(id);
    await this.db.db
      .prepare(
        `
        UPDATE shared_ids SET ${fields.join(", ")}, updated_at = CURRENT_TIMESTAMP WHERE id = ?
      `
      )
      .bind(...values)
      .run();
  }

  async deleteSharedId(id: number) {
    await this.db.db.prepare("DELETE FROM shared_ids WHERE id = ?").bind(id).run();
  }

  async listSystemConfigsMap() {
    const rows = await this.listSystemConfigs();
    const map: Record<string, string> = {};
    for (const row of rows) {
      if (row && typeof row.key === "string") {
        map[row.key] = row.value as unknown as string;
      }
    }
    return map;
  }

  async listTrafficResetTasks() {
    const users = await this.db.db
      .prepare(
        `
        SELECT id, email, username, upload_today, download_today,
               (upload_today + download_today) AS transfer_today,
               transfer_total, transfer_enable
        FROM users
        WHERE upload_today > 0 OR download_today > 0
      `
      )
      .all();
    return users.results || [];
  }

  async aggregateDailyTraffic(recordDate: string) {
    const rows = await this.db.db
      .prepare(
        `
        SELECT user_id,
               COALESCE(SUM(actual_upload_traffic), 0) as upload,
               COALESCE(SUM(actual_download_traffic), 0) as download,
               COALESCE(SUM(actual_traffic), 0) as total
        FROM traffic_logs
        WHERE date = ?
        GROUP BY user_id
      `
      )
      .bind(recordDate)
      .all();

    const list = rows.results || [];
    for (const row of list) {
      await this.db.db
        .prepare(
          `
          INSERT INTO daily_traffic (user_id, record_date, upload_traffic, download_traffic, total_traffic, created_at)
          VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
          ON DUPLICATE KEY UPDATE 
            upload_traffic = VALUES(upload_traffic),
            download_traffic = VALUES(download_traffic),
            total_traffic = VALUES(total_traffic)
        `
        )
        .bind(row.user_id, recordDate, row.upload, row.download, row.total)
        .run();
    }
    return list.length;
  }

  async aggregateSystemTraffic(recordDate: string) {
    const stats = await this.db.db
      .prepare(
        `
        SELECT 
          COUNT(DISTINCT user_id) as users,
          COALESCE(SUM(actual_upload_traffic), 0) as total_upload,
          COALESCE(SUM(actual_download_traffic), 0) as total_download,
          COALESCE(SUM(actual_traffic), 0) as total_traffic
        FROM traffic_logs
        WHERE date = ?
      `
      )
      .bind(recordDate)
      .first<{
        users?: number | string | null;
        total_upload?: number | string | null;
        total_download?: number | string | null;
        total_traffic?: number | string | null;
      }>();

    await this.db.db
      .prepare(
        `
        INSERT INTO system_traffic_summary (record_date, total_users, total_upload, total_download, total_traffic, created_at)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON DUPLICATE KEY UPDATE 
          total_users = VALUES(total_users),
          total_upload = VALUES(total_upload),
          total_download = VALUES(total_download),
          total_traffic = VALUES(total_traffic)
      `
      )
      .bind(
        recordDate,
        Number(stats?.users ?? 0),
        Number(stats?.total_upload ?? 0),
        Number(stats?.total_download ?? 0),
        Number(stats?.total_traffic ?? 0)
      )
      .run();

    return {
      total_users: Number(stats?.users ?? 0),
      total_upload: Number(stats?.total_upload ?? 0),
      total_download: Number(stats?.total_download ?? 0),
      total_traffic: Number(stats?.total_traffic ?? 0)
    };
  }

  async aggregateTrafficForDate(recordDate: string) {
    const userCount = await this.aggregateDailyTraffic(recordDate);
    const systemStats = await this.aggregateSystemTraffic(recordDate);
    return { userCount, systemStats };
  }

  async listDailyTraffic(params: { date?: string | null; page: number; pageSize: number }) {
    const offset = (params.page - 1) * params.pageSize;
    const values: any[] = [];
    let where = "";
    if (params.date) {
      where = "WHERE dt.record_date = ?";
      values.push(params.date);
    }
    const rows = await this.db.db
      .prepare(
        `
        SELECT dt.*, u.email, u.username
        FROM daily_traffic dt
        LEFT JOIN users u ON dt.user_id = u.id
        ${where}
        ORDER BY dt.record_date DESC, dt.user_id ASC
        LIMIT ? OFFSET ?
      `
      )
      .bind(...values, params.pageSize, offset)
      .all();
    const totalRow = await this.db.db
      .prepare(`SELECT COUNT(*) as total FROM daily_traffic ${where}`)
      .bind(...values)
      .first<{ total?: number }>();
    return { data: rows.results || [], total: Number(totalRow?.total ?? 0) };
  }

  async listSystemTrafficSummaryPaged(params: { days?: number; page?: number; pageSize?: number }) {
    const page = params.page ?? 1;
    const pageSize = params.pageSize ?? 30;
    const offset = (page - 1) * pageSize;
    const days = params.days ?? null;
    const values: any[] = [];
    let where = "";
    if (days != null) {
      where = "WHERE record_date >= DATE_SUB(CURRENT_DATE, INTERVAL ? DAY)";
      values.push(days);
    }
    const rows = await this.db.db
      .prepare(
        `
        SELECT * FROM system_traffic_summary
        ${where}
        ORDER BY record_date DESC
        LIMIT ? OFFSET ?
      `
      )
      .bind(...values, pageSize, offset)
      .all();
    const totalRow = await this.db.db
      .prepare(`SELECT COUNT(*) as total FROM system_traffic_summary ${where}`)
      .bind(...values)
      .first<{ total?: number }>();
    return { data: rows.results || [], total: Number(totalRow?.total ?? 0) };
  }

  async getGiftCardByCode(code: string) {
    return await this.db.db
      .prepare(
        `
        SELECT * FROM gift_cards WHERE code = ? AND status = 1
      `
      )
      .bind(code)
      .first();
  }

  async markGiftCardUsed(cardId: number, usedCount: number, maxUsage: number | null) {
    const nextCount = usedCount + 1;
    const nextStatus = maxUsage !== null && maxUsage !== undefined && nextCount >= maxUsage ? 2 : 1;
    await this.db.db
      .prepare(
        `
        UPDATE gift_cards 
        SET used_count = ?, status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `
      )
      .bind(nextCount, nextStatus, cardId)
      .run();
  }

  async insertGiftCardRedemption(params: {
    cardId: number;
    userId: number;
    code: string;
    cardType: string;
    changeAmount?: number | null;
    durationDays?: number | null;
    trafficValueGb?: number | null;
    resetTrafficGb?: number | null;
    packageId?: number | null;
    rechargeRecordId?: number | null;
    purchaseRecordId?: number | null;
    tradeNo?: string | null;
    resultStatus?: string | null;
    message?: string | null;
  }) {
    await this.db.db
      .prepare(
        `
        INSERT INTO gift_card_redemptions (
          card_id, user_id, code, card_type, change_amount, duration_days, traffic_value_gb, reset_traffic_gb,
          package_id, recharge_record_id, purchase_record_id, trade_no, result_status, message, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      `
      )
      .bind(
        params.cardId,
        params.userId,
        params.code,
        params.cardType,
        params.changeAmount ?? null,
        params.durationDays ?? null,
        params.trafficValueGb ?? null,
        params.resetTrafficGb ?? null,
        params.packageId ?? null,
        params.rechargeRecordId ?? null,
        params.purchaseRecordId ?? null,
        params.tradeNo ?? params.code,
        params.resultStatus ?? "success",
        params.message ?? null
      )
      .run();
  }

  async listGiftCards(page: number, pageSize: number) {
    const offset = (page - 1) * pageSize;
    const rows = await this.db.db
      .prepare(
        `
        SELECT * FROM gift_cards
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
      `
      )
      .bind(pageSize, offset)
      .all();
    const total = await this.db.db.prepare("SELECT COUNT(*) as total FROM gift_cards").first<{ total?: number }>();
    return {
      data: rows.results || [],
      total: Number(total?.total ?? 0)
    };
  }

  async createGiftCard(params: {
    name: string;
    code: string;
    cardType: string;
    balanceAmount?: number | null;
    durationDays?: number | null;
    trafficValueGb?: number | null;
    resetTrafficGb?: number | null;
    packageId?: number | null;
    maxUsage?: number | null;
    perUserLimit?: number | null;
    startAt?: Date | null;
    endAt?: Date | null;
  }) {
    await this.db.db
      .prepare(
        `
        INSERT INTO gift_cards (
          name, code, card_type, balance_amount, duration_days, traffic_value_gb, reset_traffic_gb, package_id,
          max_usage, per_user_limit, used_count, status, start_at, end_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      `
      )
      .bind(
        params.name,
        params.code,
        params.cardType,
        params.balanceAmount ?? null,
        params.durationDays ?? null,
        params.trafficValueGb ?? null,
        params.resetTrafficGb ?? null,
        params.packageId ?? null,
        params.maxUsage ?? null,
        params.perUserLimit ?? null,
        params.startAt ?? null,
        params.endAt ?? null
      )
      .run();
  }

  async countGiftCardUserRedemptions(cardId: number, userId: number) {
    const row = await this.db.db
      .prepare(
        `
        SELECT COUNT(*) as total
        FROM gift_card_redemptions
        WHERE card_id = ? AND user_id = ? AND result_status = 'success'
      `
      )
      .bind(cardId, userId)
      .first<{ total?: number | string | null }>();
    return Number(row?.total ?? 0);
  }

  async listSystemConfigs() {
    const rows = await this.db.db.prepare("SELECT id, `key`, value, description FROM system_configs").all();
    return rows.results || [];
  }

  async updateSystemConfig(key: string, value: string) {
    await this.db.db
      .prepare(
        `
        INSERT INTO system_configs (\`key\`, value, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON DUPLICATE KEY UPDATE value = VALUES(value), updated_at = CURRENT_TIMESTAMP
      `
      )
      .bind(key, value)
      .run();
  }

  async deleteSystemConfig(key: string) {
    await this.db.db.prepare("DELETE FROM system_configs WHERE `key` = ?").bind(key).run();
  }

  async listNodes(params: {
    page: number;
    pageSize: number;
    keyword?: string;
    status?: number | null;
  }) {
    const page = params.page > 0 ? params.page : 1;
    const pageSize = params.pageSize > 0 ? params.pageSize : 20;
    const offset = (page - 1) * pageSize;

    const conditions: string[] = [];
    const values: any[] = [];

    if (params.keyword && params.keyword.trim()) {
      conditions.push("name LIKE ?");
      values.push(`%${params.keyword.trim()}%`);
    }

    if (typeof params.status === "number" && !Number.isNaN(params.status)) {
      conditions.push("status = ?");
      values.push(params.status);
    }

    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

    const rows = await this.db.db
      .prepare(
        `
        SELECT 
          id,
          name,
          type,
          node_class,
          node_bandwidth,
          node_bandwidth_limit,
          traffic_multiplier,
          bandwidthlimit_resetday,
          node_config,
          status,
          created_at,
          updated_at
        FROM nodes
        ${where}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
      `
      )
      .bind(...values, pageSize, offset)
      .all();
    const total = await this.db.db
      .prepare(`SELECT COUNT(*) as total FROM nodes ${where}`)
      .bind(...values)
      .first<{ total?: number }>();
    return { data: rows.results || [], total: Number(total?.total ?? 0) };
  }

  async updateNodeStatus(nodeId: number, status: number) {
    await this.db.db
      .prepare("UPDATE nodes SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
      .bind(status, nodeId)
      .run();
  }

  async listAuditLogs(page: number, pageSize: number) {
    const offset = (page - 1) * pageSize;
    const rows = await this.db.db
      .prepare(
        `
        SELECT al.*, u.email, u.username, n.name as node_name, ar.name as rule_name
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        LEFT JOIN nodes n ON al.node_id = n.id
        LEFT JOIN audit_rules ar ON al.audit_rule_id = ar.id
        ORDER BY al.created_at DESC
        LIMIT ? OFFSET ?
      `
      )
      .bind(pageSize, offset)
      .all();
    const total = await this.db.db.prepare("SELECT COUNT(*) as total FROM audit_logs").first<{ total?: number }>();
    return {
      data: rows.results || [],
      total: Number(total?.total ?? 0)
    };
  }

  async listPackageStats() {
    const rows = await this.db.db
      .prepare(
        `
        SELECT p.id, p.name, p.price,
          COUNT(r.id) as total_orders,
          SUM(CASE WHEN r.status = 1 THEN 1 ELSE 0 END) as paid_orders,
          SUM(CASE WHEN r.status = 1 THEN r.price ELSE 0 END) as paid_amount
        FROM packages p
        LEFT JOIN package_purchase_records r ON r.package_id = p.id
        GROUP BY p.id, p.name, p.price
        ORDER BY p.id ASC
      `
      )
      .all();
    return rows.results || [];
  }

  async listPendingWithdrawals(limit = 100) {
    const rows = await this.db.db
      .prepare(
        `
        SELECT rw.*, u.email, u.username
        FROM rebate_withdrawals rw
        LEFT JOIN users u ON rw.user_id = u.id
        WHERE rw.status = 'pending'
        ORDER BY rw.created_at ASC
        LIMIT ?
      `
      )
      .bind(limit)
      .all();
    return rows.results || [];
  }

  async createWithdrawalRequest(params: {
    userId: number;
    amount: number;
    method: string;
    accountPayload?: Record<string, unknown>;
    feeRate?: number;
    feeAmount?: number;
  }): Promise<number> {
    const now = new Date();
    const feeRate = typeof params.feeRate === "number" ? params.feeRate : 0;
    const feeAmount = typeof params.feeAmount === "number" ? params.feeAmount : 0;
    const result = toRunResult(
      await this.db.db
      .prepare(
        `
        INSERT INTO rebate_withdrawals (
          user_id, amount, method, account_payload, fee_rate, fee_amount, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
      `
      )
      .bind(
        params.userId,
        params.amount,
        params.method,
        params.accountPayload ? JSON.stringify(params.accountPayload) : null,
        feeRate,
        feeAmount,
        now,
        now
      )
      .run()
    );
    const id = getLastRowId(result);
    return id ?? 0;
  }

  async listWithdrawals(params: { page: number; pageSize: number; status?: string }) {
    const offset = (params.page - 1) * params.pageSize;
    const filters: string[] = [];
    const values: any[] = [];
    if (params.status) {
      filters.push("rw.status = ?");
      values.push(params.status);
    }
    const where = filters.length ? `WHERE ${filters.join(" AND ")}` : "";
    const rows = await this.db.db
      .prepare(
        `
        SELECT rw.*, u.email, u.username
        FROM rebate_withdrawals rw
        LEFT JOIN users u ON rw.user_id = u.id
        ${where}
        ORDER BY rw.created_at DESC
        LIMIT ? OFFSET ?
      `
      )
      .bind(...values, params.pageSize, offset)
      .all();
    const totalRow = await this.db.db
      .prepare(
        `
        SELECT COUNT(*) as total
        FROM rebate_withdrawals rw
        ${where}
      `
      )
      .bind(...values)
      .first<{ total?: number }>();
    return { data: rows.results || [], total: Number(totalRow?.total ?? 0) };
  }

  async updateWithdrawalStatus(id: number, status: string, note?: string | null, reviewerId?: number | null) {
    await this.db.db
      .prepare(
        `
        UPDATE rebate_withdrawals
        SET status = ?, review_note = ?, reviewer_id = ?, updated_at = CURRENT_TIMESTAMP, processed_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `
      )
      .bind(status, note ?? null, reviewerId ?? null, id)
      .run();
  }

  async reduceRebateOnWithdrawal(userId: number, amount: number) {
    const user = await this.db.db
      .prepare("SELECT rebate_available FROM users WHERE id = ?")
      .bind(userId)
      .first<{ rebate_available?: number }>();
    const available = Number(user?.rebate_available ?? 0);
    if (amount > available) throw new Error("返利余额不足");
    await this.db.db
      .prepare(
        `
        UPDATE users 
        SET rebate_available = rebate_available - ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `
      )
      .bind(amount, userId)
      .run();
  }

  async listPendingRecharge(limit = 100) {
    const rows = await this.db.db
      .prepare(
        `
        SELECT rr.*, u.email, u.username
        FROM recharge_records rr
        LEFT JOIN users u ON rr.user_id = u.id
        WHERE rr.status = 0
        ORDER BY rr.created_at ASC
        LIMIT ?
      `
      )
      .bind(limit)
      .all();
    return rows.results || [];
  }

  async listAllRechargeRecords(page: number, pageSize: number) {
    const offset = (page - 1) * pageSize;
    const rows = await this.db.db
      .prepare(
        `
        SELECT rr.*, u.email, u.username
        FROM recharge_records rr
        LEFT JOIN users u ON rr.user_id = u.id
        ORDER BY rr.created_at DESC
        LIMIT ? OFFSET ?
      `
      )
      .bind(pageSize, offset)
      .all();
    const total = await this.db.db.prepare("SELECT COUNT(*) as total FROM recharge_records").first<{ total?: number }>();
    return { data: rows.results || [], total: Number(total?.total ?? 0) };
  }

  async listAllPurchaseRecords(page: number, pageSize: number) {
    const offset = (page - 1) * pageSize;
    const rows = await this.db.db
      .prepare(
        `
        SELECT pr.*, u.email, u.username, p.name as package_name
        FROM package_purchase_records pr
        LEFT JOIN users u ON pr.user_id = u.id
        LEFT JOIN packages p ON pr.package_id = p.id
        ORDER BY pr.created_at DESC
        LIMIT ? OFFSET ?
      `
      )
      .bind(pageSize, offset)
      .all();
    const total = await this.db.db
      .prepare("SELECT COUNT(*) as total FROM package_purchase_records")
      .first<{ total?: number }>();
    return { data: rows.results || [], total: Number(total?.total ?? 0) };
  }

  async listCoupons(page: number, pageSize: number) {
    const offset = (page - 1) * pageSize;
    const rows = await this.db.db
      .prepare(
        `
        SELECT * FROM coupons
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
      `
      )
      .bind(pageSize, offset)
      .all();
    const total = await this.db.db.prepare("SELECT COUNT(*) as total FROM coupons").first<{ total?: number }>();
    return { data: rows.results || [], total: Number(total?.total ?? 0) };
  }

  async deleteCoupon(id: number) {
    await this.db.db.prepare("DELETE FROM coupons WHERE id = ?").bind(id).run();
  }

  async listGiftCardRedemptions(page: number, pageSize: number) {
    const offset = (page - 1) * pageSize;
    const rows = await this.db.db
      .prepare(
        `
        SELECT r.*, u.email, u.username, g.name as card_name
        FROM gift_card_redemptions r
        LEFT JOIN users u ON r.user_id = u.id
        LEFT JOIN gift_cards g ON r.card_id = g.id
        ORDER BY r.created_at DESC
        LIMIT ? OFFSET ?
      `
      )
      .bind(pageSize, offset)
      .all();
    const total = await this.db.db
      .prepare("SELECT COUNT(*) as total FROM gift_card_redemptions")
      .first<{ total?: number }>();
    return { data: rows.results || [], total: Number(total?.total ?? 0) };
  }

  async listPackagesAll() {
    const rows = await this.db.db
      .prepare(
        `
        SELECT * FROM packages ORDER BY sort_weight DESC, id DESC
      `
      )
      .all();
    return rows.results || [];
  }

  async createPackage(params: {
    name: string;
    price: number;
    trafficQuota: number;
    validityDays: number;
    speedLimit?: number | null;
    deviceLimit?: number | null;
    level?: number | null;
    status?: number | null;
    isRecommended?: number | null;
    sortWeight?: number | null;
  }) {
    await this.db.db
      .prepare(
        `
        INSERT INTO packages (name, price, traffic_quota, validity_days, speed_limit, device_limit, level, status, is_recommended, sort_weight, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      `
      )
      .bind(
        params.name,
        params.price,
        params.trafficQuota,
        params.validityDays,
        params.speedLimit ?? 0,
        params.deviceLimit ?? 0,
        params.level ?? 1,
        params.status ?? 1,
        params.isRecommended ?? 0,
        params.sortWeight ?? 0
      )
      .run();
  }

  async updatePackage(id: number, payload: Partial<{
    name: string;
    price: number;
    trafficQuota: number;
    validityDays: number;
    speedLimit: number;
    deviceLimit: number;
    level: number;
    status: number;
    isRecommended: number;
    sortWeight: number;
  }>) {
    const fields: string[] = [];
    const values: any[] = [];
    if (payload.name !== undefined) { fields.push("name = ?"); values.push(payload.name); }
    if (payload.price !== undefined) { fields.push("price = ?"); values.push(payload.price); }
    if (payload.trafficQuota !== undefined) { fields.push("traffic_quota = ?"); values.push(payload.trafficQuota); }
    if (payload.validityDays !== undefined) { fields.push("validity_days = ?"); values.push(payload.validityDays); }
    if (payload.speedLimit !== undefined) { fields.push("speed_limit = ?"); values.push(payload.speedLimit); }
    if (payload.deviceLimit !== undefined) { fields.push("device_limit = ?"); values.push(payload.deviceLimit); }
    if (payload.level !== undefined) { fields.push("level = ?"); values.push(payload.level); }
    if (payload.status !== undefined) { fields.push("status = ?"); values.push(payload.status); }
    if (payload.isRecommended !== undefined) { fields.push("is_recommended = ?"); values.push(payload.isRecommended); }
    if (payload.sortWeight !== undefined) { fields.push("sort_weight = ?"); values.push(payload.sortWeight); }
    if (!fields.length) return;
    values.push(id);
    await this.db.db
      .prepare(
        `
        UPDATE packages SET ${fields.join(", ")}, updated_at = CURRENT_TIMESTAMP WHERE id = ?
      `
      )
      .bind(...values)
      .run();
  }

  async deletePackage(id: number) {
    await this.db.db.prepare("DELETE FROM packages WHERE id = ?").bind(id).run();
  }

  async createCoupon(params: {
    name: string;
    code: string;
    discountType: "amount" | "percentage";
    discountValue: number;
    startAt: number;
    endAt: number;
    maxUsage?: number | null;
    perUserLimit?: number | null;
    status?: number;
    description?: string | null;
  }) {
    await this.db.db
      .prepare(
        `
        INSERT INTO coupons (
          name, code, discount_type, discount_value, start_at, end_at, max_usage, per_user_limit, total_used, status, description, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      `
      )
      .bind(
        params.name,
        params.code,
        params.discountType,
        params.discountValue,
        params.startAt,
        params.endAt,
        params.maxUsage ?? null,
        params.perUserLimit ?? null,
        params.status ?? 1,
        params.description ?? null
      )
      .run();
  }

  async updateCouponStatus(id: number, status: number) {
    await this.db.db
      .prepare(
        `
        UPDATE coupons SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
      `
      )
      .bind(status, id)
      .run();
  }

  async listUserWithdrawals(userId: number, limit = 50) {
    const rows = await this.db.db
      .prepare(
        `
        SELECT id, amount, method, status, created_at, updated_at, processed_at
        FROM rebate_withdrawals
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ?
      `
      )
      .bind(userId, limit)
      .all();
    return rows.results || [];
  }

  async listReferrals(inviterId: number, page: number, pageSize: number) {
    const offset = (page - 1) * pageSize;
    const rows = await this.db.db
      .prepare(
        `
        SELECT 
          rr.*,
          u.email as invitee_email,
          u.username as invitee_username,
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
      .bind(inviterId, pageSize, offset)
      .all();
    const total = await this.db.db
      .prepare("SELECT COUNT(*) as total FROM referral_relations WHERE inviter_id = ?")
      .bind(inviterId)
      .first<{ total?: number }>();
    return { data: rows.results || [], total: Number(total?.total ?? 0) };
  }

  async listRebateTransactions(page: number, pageSize: number, inviterId?: number | null) {
    const offset = (page - 1) * pageSize;
    const filters: string[] = [];
    const values: any[] = [];
    if (inviterId) {
      filters.push("rt.inviter_id = ?");
      values.push(inviterId);
    }
    const where = filters.length ? `WHERE ${filters.join(" AND ")}` : "";
    const rows = await this.db.db
      .prepare(
        `
        SELECT rt.*, u.email as inviter_email, u.username as inviter_username, iu.email as invitee_email, iu.username as invitee_username
        FROM rebate_transactions rt
        LEFT JOIN users u ON rt.inviter_id = u.id
        LEFT JOIN users iu ON rt.invitee_id = iu.id
        ${where}
        ORDER BY rt.created_at DESC
        LIMIT ? OFFSET ?
      `
      )
      .bind(...values, pageSize, offset)
      .all();
    const total = await this.db.db
      .prepare(`SELECT COUNT(*) as total FROM rebate_transactions rt ${where}`)
      .bind(...values)
      .first<{ total?: number }>();
    return { data: rows.results || [], total: Number(total?.total ?? 0) };
  }

  async listUsersForExport() {
    const rows = await this.db.db
      .prepare(
        `
        SELECT id, email, username, status, class, expire_time, transfer_total, transfer_enable, money, rebate_available, created_at
        FROM users
        ORDER BY id ASC
      `
      )
      .all();
    return rows.results || [];
  }

  async listRebateTransfers(userId: number, limit = 20) {
    const rows = await this.db.db
      .prepare(
        `
        SELECT amount, balance_before, balance_after, rebate_before, rebate_after, created_at
        FROM rebate_transfers
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ?
      `
      )
      .bind(userId, limit)
      .all();
    return rows.results || [];
  }

  async insertRebateTransfer(params: {
    userId: number;
    amount: number;
    balanceBefore: number;
    balanceAfter: number;
    rebateBefore: number;
    rebateAfter: number;
  }) {
    await this.db.db
      .prepare(
        `
        INSERT INTO rebate_transfers (
          user_id, amount, balance_before, balance_after, rebate_before, rebate_after, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      `
      )
      .bind(
        params.userId,
        params.amount,
        params.balanceBefore,
        params.balanceAfter,
        params.rebateBefore,
        params.rebateAfter
      )
      .run();
  }

  async updateTwoFactorData(params: {
    userId: number;
    enabled: number;
    secret?: string | null;
    backupCodes?: string[] | null;
  }) {
    await this.db
      .prepare(
        `
        UPDATE users 
        SET two_factor_enabled = ?,
            two_factor_secret = ?,
            two_factor_backup_codes = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `
      )
      .bind(
        params.enabled,
        params.secret ?? null,
        params.backupCodes ? JSON.stringify(params.backupCodes) : null,
        params.userId
      )
      .run();
  }

  async upsertEmailCode(params: {
    email: string;
    purpose: string;
    code_hash: string;
    expires_at: Date;
    request_ip?: string | null;
    user_agent?: string | null;
  }) {
    await this.db
      .prepare(
        `
        INSERT INTO email_verification_codes (email, purpose, code_hash, expires_at, attempts, request_ip, user_agent, created_at)
        VALUES (?, ?, ?, ?, 0, ?, ?, CURRENT_TIMESTAMP)
      `
      )
      .bind(
        params.email,
        params.purpose,
        params.code_hash,
        params.expires_at.toISOString().slice(0, 19).replace("T", " "),
        params.request_ip ?? null,
        params.user_agent ?? null
      )
      .run();
  }

  async getValidEmailCode(email: string, purpose: string) {
    return await this.db
      .prepare(
        `
        SELECT * FROM email_verification_codes
        WHERE email = ?
          AND purpose = ?
          AND expires_at > CURRENT_TIMESTAMP
          AND used_at IS NULL
        ORDER BY id DESC
        LIMIT 1
      `
      )
      .bind(email, purpose)
      .first();
  }

  async markEmailCodeUsed(id: number) {
    await this.db
      .prepare(
        `
        UPDATE email_verification_codes
        SET used_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `
      )
      .bind(id)
      .run();
  }

  async getUserById(id: number) {
    return await this.db
      .prepare(
        `
        SELECT * FROM users WHERE id = ?
      `
      )
      .bind(id)
      .first();
  }

  async resetSubscriptionToken(userId: number, newToken: string) {
    await this.db
      .prepare(
        `
        UPDATE users 
        SET token = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `
      )
      .bind(newToken, userId)
      .run();
  }

  async deleteUser(userId: number) {
    await this.db.prepare("DELETE FROM users WHERE id = ?").bind(userId).run();
  }


  async insertLoginLog(params: {
    userId: number;
    ip: string;
    userAgent?: string | null;
    status?: number;
    failureReason?: string | null;
    loginMethod?: string | null;
  }) {
    await this.db
      .prepare(
        `
        INSERT INTO login_logs (user_id, login_ip, user_agent, login_status, failure_reason, login_method, created_at)
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      `
      )
      .bind(
        params.userId,
        params.ip,
        params.userAgent ?? null,
        params.status ?? 1,
        params.failureReason ?? null,
        params.loginMethod ?? "password"
      )
      .run();
  }

  async listLoginLogs(userId: number, limit = 20) {
    const result = await this.db
      .prepare(
        `
        SELECT id, login_ip, login_time, user_agent, login_status, failure_reason, login_method, created_at
        FROM login_logs 
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ?
      `
      )
      .bind(userId, limit)
      .all();
    return result.results || [];
  }

  async updateUserTraffic(
    trafficData: Array<{ id: number; u: number; d: number }>,
    nodeId: number
  ) {
    const nodeRow = await this.db
      .prepare("SELECT traffic_multiplier FROM nodes WHERE id = ?")
      .bind(nodeId)
      .first<{ traffic_multiplier?: number | string | null } | null>();
    const rawMultiplier = ensureNumber(nodeRow?.traffic_multiplier, 1);
    const trafficMultiplier = rawMultiplier > 0 ? rawMultiplier : 1;
    const now = new Date();
    const date = new Date(now.getTime() + 8 * 60 * 60 * 1000)
      .toISOString()
      .split("T")[0];

    for (const traffic of trafficData) {
      const userId = ensureNumber(traffic.id);
      if (userId <= 0) continue;

      const upload = Math.max(0, ensureNumber(traffic.u));
      const download = Math.max(0, ensureNumber(traffic.d));
      const total = upload + download;
      const actualUpload = Math.max(0, Math.round(upload * trafficMultiplier));
      const actualDownload = Math.max(0, Math.round(download * trafficMultiplier));
      const deductedTotal = Math.max(0, actualUpload + actualDownload);

      await this.db
        .prepare(
          `
          UPDATE users 
          SET upload_traffic = upload_traffic + ?, 
              download_traffic = download_traffic + ?,
              upload_today = upload_today + ?,
              download_today = download_today + ?,
              transfer_total = transfer_total + ?,
              updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `
        )
        .bind(upload, download, upload, download, deductedTotal, userId)
        .run();

      await this.db
        .prepare(
          `
          INSERT INTO traffic_logs 
          (user_id, node_id, upload_traffic, download_traffic, actual_upload_traffic, actual_download_traffic, actual_traffic, deduction_multiplier, date, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
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

    const totalTraffic = trafficData.reduce(
      (sum, t) => sum + ensureNumber(t.u) + ensureNumber(t.d),
      0
    );
    await this.db
      .prepare(
        `
        UPDATE nodes 
        SET node_bandwidth = node_bandwidth + ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `
      )
      .bind(totalTraffic, nodeId)
      .run();
  }

  async getExpiredLevelUsers(useLocalTime = false) {
    if (!useLocalTime) {
      const result = await this.db
        .prepare(
          `
          SELECT id, email, username, class, class_expire_time,
                 upload_traffic, download_traffic,
                 transfer_total, transfer_enable
          FROM users 
          WHERE class_expire_time IS NOT NULL 
            AND class_expire_time <= CURRENT_TIMESTAMP
            AND class > 0
            AND status = 1
        `
        )
        .all();
      return result.results || [];
    }

    // 本地时间判断（JS 时区），避免数据库时区配置与业务期望不一致
    const rows = await this.db
      .prepare(
        `
        SELECT id, email, username, class, class_expire_time,
               upload_traffic, download_traffic,
               transfer_total, transfer_enable
        FROM users 
        WHERE class_expire_time IS NOT NULL 
          AND class > 0
          AND status = 1
      `
      )
      .all<any>();

    const now = Date.now();
    return (rows.results || []).filter((row) => {
      if (!row?.class_expire_time) return false;
      const ts = new Date(row.class_expire_time).getTime();
      return Number.isFinite(ts) && ts <= now;
    });
  }

  async resetExpiredUsersLevel(userIds: Array<number | string>) {
    if (!userIds || userIds.length === 0) return;
    const validIds = userIds
      .map((id) => Number(id))
      .filter((id) => Number.isInteger(id) && id > 0);
    if (validIds.length === 0) return;

    const placeholders = validIds.map(() => "?").join(",");
    await this.db
      .prepare(
        `
        UPDATE users 
        SET class = 0,
            class_expire_time = NULL,
            upload_traffic = 0,
            download_traffic = 0,
            upload_today = 0,
            download_today = 0,
            transfer_total = 0,
            transfer_enable = 0,
            updated_at = CURRENT_TIMESTAMP
        WHERE id IN (${placeholders})
      `
      )
      .bind(...validIds)
      .run();
  }

  async resetUserLevel(userId: number, userInfo: Record<string, unknown> = {}) {
    try {
      const beforeData = await this.db
        .prepare(
          `
          SELECT class, upload_traffic, download_traffic, 
                 transfer_total, transfer_enable
          FROM users WHERE id = ?
        `
        )
        .bind(userId)
        .first();

      const result = toRunResult(
        await this.db
          .prepare(
            `
            UPDATE users 
            SET class = 0,
                class_expire_time = NULL,
                upload_traffic = 0,
                download_traffic = 0,
                upload_today = 0,
                download_today = 0,
                transfer_total = 0,
                transfer_enable = 0,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
          `
          )
          .bind(userId)
          .run()
      );

      return {
        success: true,
        userId,
        beforeData,
        resetTime: new Date().toISOString(),
        changesCount: getChanges(result),
        userInfo
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`Error resetting user ${userId} level:`, error);
      return {
        success: false,
        userId,
        error: message
      };
    }
  }

  async logLevelResets(resetResults: Array<Record<string, unknown>>) {
    try {
      for (const result of resetResults) {
        if (result.success) {
          console.log(`User ${result.userId} level reset successful:`, {
            before: result.beforeData,
            resetTime: result.resetTime,
            changes: result.changesCount
          });
        } else {
          console.error(`User ${result.userId} level reset failed:`, result.error);
        }
      }
    } catch (error) {
      console.error("Error logging level resets:", error);
    }
  }

  async updateUserAfterPackagePurchase(userId: number, packageInfo: any) {
    const userInfo = await this.db.db
      .prepare(
        `
        SELECT class, class_expire_time, transfer_enable, transfer_total, speed_limit, device_limit
        FROM users
        WHERE id = ?
      `
      )
      .bind(userId)
      .first<{
        class?: number | string;
        class_expire_time?: string | null;
        transfer_enable?: number | string;
        transfer_total?: number | string;
        speed_limit?: number | string | null;
        device_limit?: number | string | null;
      }>();

    if (!userInfo) {
      throw new Error("用户不存在");
    }

    const currentTime = new Date();
    const currentLevel = ensureNumber(userInfo.class, 0);
    const packageLevel = ensureNumber(packageInfo.level, 0);
    const classExpireRaw = userInfo.class_expire_time;
    const currentTransferEnable = ensureNumber(userInfo.transfer_enable, 0);
    const packageTrafficBytes = ensureNumber(packageInfo.traffic_quota, 0) * 1024 * 1024 * 1024;
    const validityDays = ensureNumber(packageInfo.validity_days, 30);
    const newSpeedLimit = ensureNumber(packageInfo.speed_limit, 0);
    const newDeviceLimit = ensureNumber(packageInfo.device_limit, 0);

    let newExpireTime: string;
    let newTrafficQuota: number;
    let shouldResetUsedTraffic = false;

    if (classExpireRaw && new Date(classExpireRaw) > currentTime && currentLevel === packageLevel) {
      const currentExpire = new Date(classExpireRaw);
      currentExpire.setDate(currentExpire.getDate() + validityDays);
      newExpireTime = currentExpire.toISOString().slice(0, 19).replace("T", " ");
      newTrafficQuota = currentTransferEnable + packageTrafficBytes;
    } else if (currentLevel === packageLevel) {
      const expire = new Date(currentTime.getTime() + 8 * 60 * 60 * 1000);
      expire.setDate(expire.getDate() + validityDays);
      newExpireTime = expire.toISOString().slice(0, 19).replace("T", " ");
      newTrafficQuota = currentTransferEnable + packageTrafficBytes;
    } else {
      const expire = new Date(currentTime.getTime() + 8 * 60 * 60 * 1000);
      expire.setDate(expire.getDate() + validityDays);
      newExpireTime = expire.toISOString().slice(0, 19).replace("T", " ");
      newTrafficQuota = packageTrafficBytes;
      shouldResetUsedTraffic = true;
    }

    const params: any[] = [
      packageLevel,
      newExpireTime,
      newTrafficQuota,
      newSpeedLimit,
      newDeviceLimit,
      userId
    ];

    if (shouldResetUsedTraffic) {
      await this.db.db
        .prepare(
          `
          UPDATE users
          SET class = ?, class_expire_time = ?, transfer_enable = ?, transfer_total = 0,
              upload_traffic = 0, download_traffic = 0, upload_today = 0, download_today = 0,
              speed_limit = ?, device_limit = ?, updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `
        )
        .bind(...params)
        .run();
    } else {
      await this.db.db
        .prepare(
          `
          UPDATE users
          SET class = ?, class_expire_time = ?, transfer_enable = ?,
              speed_limit = ?, device_limit = ?, updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `
        )
        .bind(...params)
        .run();
    }

    return {
      success: true,
      newExpireTime,
      newTrafficQuota,
      resetUsed: shouldResetUsedTraffic
    };
  }

  async getSystemStats() {
    const usersRow = await this.db
      .prepare(
        `
        SELECT 
          COUNT(*)                                   AS total_users,
          SUM(CASE WHEN transfer_total > 0 THEN 1 ELSE 0 END) AS active_users,
          SUM(CASE WHEN status = 0 THEN 1 ELSE 0 END)         AS disabled_users,
          SUM(CASE WHEN is_admin = 1 THEN 1 ELSE 0 END)       AS admin_users
        FROM users
      `
      )
      .first<{
        total_users?: number;
        active_users?: number;
        disabled_users?: number;
        admin_users?: number;
      }>();

    const nodesRow = await this.db
      .prepare(
        `
        SELECT 
          COUNT(*)                                   AS total_nodes,
          SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) AS active_nodes
        FROM nodes
      `
      )
      .first<{
        total_nodes?: number;
        active_nodes?: number;
      }>();

    const onlineNodesRow = await this.db
      .prepare(
        `
        SELECT COUNT(DISTINCT node_id) AS online_nodes
        FROM node_status
        WHERE created_at >= DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 5 MINUTE)
      `
      )
      .first<{ online_nodes?: number }>();

    const trafficRow = await this.db
      .prepare(
        `
        SELECT 
          COALESCE(SUM(transfer_enable), 0)                 AS total_traffic,
          COALESCE(SUM(upload_today + download_today), 0)   AS today_traffic,
          COALESCE(AVG(transfer_enable), 0)                 AS average_quota
        FROM users
      `
      )
      .first<{
        total_traffic?: number;
        today_traffic?: number;
        average_quota?: number;
      }>();

    return {
      users: {
        total: Number(usersRow?.total_users ?? 0),
        active: Number(usersRow?.active_users ?? 0),
        disabled: Number(usersRow?.disabled_users ?? 0),
        admins: Number(usersRow?.admin_users ?? 0)
      },
      nodes: {
        total: Number(nodesRow?.total_nodes ?? 0),
        active: Number(nodesRow?.active_nodes ?? 0),
        online: Number(onlineNodesRow?.online_nodes ?? 0),
        offline:
          Number(nodesRow?.active_nodes ?? 0) - Number(onlineNodesRow?.online_nodes ?? 0)
      },
      traffic: {
        total: Number(trafficRow?.total_traffic ?? 0),
        today: Number(trafficRow?.today_traffic ?? 0),
        average_quota: Number(trafficRow?.average_quota ?? 0)
      }
    };
  }
}
