-- =============================================
-- Soga 代理面板 D1 数据库设计
-- =============================================
-- 用户表
-- 字段说明：
-- id: 用户唯一标识ID（主键）
-- email: 用户邮箱地址（唯一，不能为空）
-- username: 用户名（唯一，不能为空）
-- password_hash: 密码哈希值（SHA-256加密，不能为空）
-- uuid: 用户UUID（唯一标识，用于代理配置）
-- passwd: 代理密码（明文，用于代理认证）
-- token: 订阅令牌（唯一，用于订阅链接）
-- invite_code: 用户的唯一邀请码（用于邀请注册）
-- invited_by: 上级邀请人ID（0表示无上级）
-- invite_limit: 邀请码可使用次数（0表示无限制）
-- invite_used: 邀请码已使用次数
-- google_sub: Google OAuth 唯一标识（第三方登录时记录）
-- oauth_provider: OAuth 提供商标识（如 google、github 等）
-- first_oauth_login_at: 首次通过 OAuth 登录的时间（UTC+8时区）
-- last_oauth_login_at: 最近一次通过 OAuth 登录的时间（UTC+8时区）
-- github_id: GitHub OAuth 唯一标识
-- is_admin: 管理员标志（0-普通用户，1-管理员）
-- speed_limit: 速度限制（Mbps，0表示无限制）
-- device_limit: 设备数量限制（0表示无限制）
-- tcp_limit: TCP连接数限制（0表示无限制）
-- upload_traffic: 上传流量统计（字节）
-- download_traffic: 下载流量统计（字节）
-- upload_today: 今日上传流量使用（字节）
-- download_today: 今日下载流量使用（字节）
-- transfer_total: 历史已使用总流量（字节）
-- transfer_enable: 总流量额度（字节，默认10GB）
-- status: 账户状态（0-禁用，1-启用）
-- reg_date: 注册时间（UTC+8时区）
-- expire_time: 账户过期时间（UTC+8时区）
-- last_login_time: 最后登录时间（UTC+8时区）
-- last_login_ip: 最后登录IP地址
-- class: 用户等级（数字越大权限越高，999为最高管理员级别）
-- class_expire_time: 等级过期时间（UTC+8时区）
-- bark_key: 用户的Bark通知Key，格式如 https://api.day.app/your_key/
-- bark_enabled: 是否启用Bark通知 (0-禁用，1-启用)
-- register_ip: 用户注册时记录的IP地址
-- created_at: 创建时间（UTC+8时区）
-- updated_at: 更新时间（UTC+8时区）
CREATE TABLE
    IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        uuid TEXT UNIQUE NOT NULL,
        passwd TEXT NOT NULL,
        token TEXT UNIQUE NOT NULL,
        invite_code TEXT UNIQUE,
        invited_by INTEGER NOT NULL DEFAULT 0,
        invite_used INTEGER DEFAULT 0,
        invite_limit INTEGER DEFAULT 0,
        google_sub TEXT,
        oauth_provider TEXT,
        first_oauth_login_at DATETIME,
        last_oauth_login_at DATETIME,
        github_id TEXT,
        is_admin INTEGER DEFAULT 0,
        speed_limit INTEGER DEFAULT 0,
        device_limit INTEGER DEFAULT 0,
        tcp_limit INTEGER DEFAULT 0,
        upload_traffic INTEGER DEFAULT 0,
        download_traffic INTEGER DEFAULT 0,
        upload_today INTEGER DEFAULT 0,
        download_today INTEGER DEFAULT 0,
        transfer_total INTEGER DEFAULT 0,
        transfer_enable INTEGER DEFAULT 10737418240, -- 默认10GB
        status INTEGER DEFAULT 1,
        reg_date DATETIME DEFAULT (datetime('now', '+8 hours')),
        expire_time DATETIME,
        last_login_time DATETIME,
        last_login_ip TEXT,
        class INTEGER DEFAULT 1,
        class_expire_time DATETIME,
        bark_key TEXT,
        bark_enabled INTEGER DEFAULT 0,
        two_factor_enabled INTEGER DEFAULT 0,
        two_factor_secret TEXT,
        two_factor_backup_codes TEXT,
        two_factor_temp_secret TEXT,
        two_factor_confirmed_at DATETIME,
        money DECIMAL(10,2) DEFAULT 0.00,
        rebate_available DECIMAL(10,2) DEFAULT 0.00,
        rebate_total DECIMAL(10,2) DEFAULT 0.00,
        register_ip TEXT,
        created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
        updated_at DATETIME DEFAULT (datetime('now', '+8 hours'))
    );

-- 节点表
-- 字段说明：
-- id: 节点唯一标识ID（主键）
-- name: 节点名称（不能为空）
-- type: 节点类型（如：v2ray, trojan, vless, hysteria等）
-- node_class: 节点等级（决定哪些用户等级可以访问此节点）
-- node_bandwidth: 节点已用流量（字节）
-- node_bandwidth_limit: 节点流量限制（字节，0表示无限制）
-- traffic_multiplier: 节点流量倍率（扣费时使用，默认 1）
-- bandwidthlimit_resetday: 节点流量重置日期（每月几号重置）
-- node_config: 节点配置JSON（包含协议相关配置）
-- status: 节点状态（0-禁用，1-启用）
-- created_at: 创建时间（UTC+8时区）
-- updated_at: 更新时间（UTC+8时区）
CREATE TABLE
    IF NOT EXISTS nodes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        node_class INTEGER DEFAULT 1,
        node_bandwidth INTEGER DEFAULT 0,
        node_bandwidth_limit INTEGER DEFAULT 0,
        traffic_multiplier REAL DEFAULT 1,
        bandwidthlimit_resetday INTEGER DEFAULT 1,
        node_config TEXT NOT NULL DEFAULT '{}',
        status INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
        updated_at DATETIME DEFAULT (datetime('now', '+8 hours'))
    );

-- 审计规则表
-- 字段说明：
-- id: 审计规则唯一标识ID（主键）
-- name: 规则名称（不能为空）
-- description: 规则描述
-- rule: 规则表达式（正则表达式或关键字）
-- enabled: 规则启用状态（0-禁用，1-启用）
-- created_at: 创建时间（UTC+8时区）
-- updated_at: 更新时间（UTC+8时区）
CREATE TABLE
    IF NOT EXISTS audit_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        rule TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
        updated_at DATETIME DEFAULT (datetime('now', '+8 hours'))
    );

-- DNS 规则表
-- 字段说明：
-- id: DNS 规则唯一标识ID（主键）
-- name: 规则名称（不能为空）
-- description: 规则描述
-- rule_json: 规则 JSON 内容
-- enabled: 规则启用状态（0-禁用，1-启用）
-- node_ids: 绑定节点ID列表（JSON 数组）
-- created_at: 创建时间（UTC+8时区）
-- updated_at: 更新时间（UTC+8时区）
CREATE TABLE
    IF NOT EXISTS dns_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        rule_json TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        node_ids TEXT NOT NULL,
        created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
        updated_at DATETIME DEFAULT (datetime('now', '+8 hours'))
    );

-- 审计白名单表
-- 字段说明：
-- id: 白名单规则唯一标识ID（主键）
-- rule: 白名单规则（域名、IP段、端口等）
-- description: 规则描述
-- status: 规则状态（0-禁用，1-启用）
-- created_at: 创建时间（UTC+8时区）
CREATE TABLE
    IF NOT EXISTS white_list (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule TEXT NOT NULL,
        description TEXT,
        status INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT (datetime('now', '+8 hours'))
    );

-- 订阅记录表
-- 字段说明：
-- id: 订阅记录唯一标识ID（主键）
-- user_id: 用户ID（外键关联users表）
-- type: 订阅类型（v2ray、clash、quantumultx等）
-- request_ip: 请求来源IP地址
-- request_time: 请求时间（UTC+8时区）
-- request_user_agent: 请求用户代理字符串
CREATE TABLE
    IF NOT EXISTS subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        request_ip TEXT,
        request_time DATETIME DEFAULT (datetime('now', '+8 hours')),
        request_user_agent TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    );

-- 用户在线IP记录表
-- 字段说明：
-- id: 在线IP记录唯一标识ID（主键）
-- user_id: 用户ID（外键关联users表）
-- node_id: 节点ID（外键关联nodes表）
-- ip: 用户在线IP地址
-- last_seen: 最后一次看到在线时间（UTC+8时区）
CREATE TABLE
    IF NOT EXISTS online_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        node_id INTEGER NOT NULL,
        ip TEXT NOT NULL,
        last_seen DATETIME DEFAULT (datetime('now', '+8 hours')),
        UNIQUE (user_id, node_id, ip),
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE
    );

-- 审计日志表
-- 字段说明：
-- id: 审计日志唯一标识ID（主键）
-- user_id: 用户ID（外键关联users表）
-- node_id: 节点ID（外键关联nodes表）
-- audit_rule_id: 审计规则ID（外键关联audit_rules表）
-- ip_address: 触发审计的IP地址
-- created_at: 审计日志创建时间（UTC+8时区）
CREATE TABLE
    IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        node_id INTEGER NOT NULL,
        audit_rule_id INTEGER NOT NULL,
        ip_address TEXT,
        created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE,
        FOREIGN KEY (audit_rule_id) REFERENCES audit_rules (id) ON DELETE CASCADE
    );

-- 节点状态记录表
-- 字段说明：
-- id: 节点状态记录唯一标识ID（主键）
-- node_id: 节点ID（外键关联nodes表）
-- cpu_usage: CPU使用率（百分比）
-- memory_total: 内存总量（字节）
-- memory_used: 内存已用（字节）
-- swap_total: 交换区总量（字节）
-- swap_used: 交换区已用（字节）
-- disk_total: 磁盘总量（字节）
-- disk_used: 磁盘已用（字节）
-- uptime: 系统运行时间（秒）
-- created_at: 状态记录时间（UTC+8时区）
CREATE TABLE
    IF NOT EXISTS node_status (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_id INTEGER NOT NULL,
        cpu_usage REAL,
        memory_total INTEGER,
        memory_used INTEGER,
        swap_total INTEGER,
        swap_used INTEGER,
        disk_total INTEGER,
        disk_used INTEGER,
        uptime INTEGER,
        created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
        FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE
    );

-- 流量日志表（简化版）
-- 字段说明：
-- id: 流量日志唯一标识ID（主键）
-- user_id: 用户ID（外键关联users表）
-- node_id: 节点ID（外键关联nodes表）
-- upload_traffic: 上传流量（字节）
-- download_traffic: 下载流量（字节）
-- actual_upload_traffic: 扣费倍率后折算的上传流量（字节）
-- actual_download_traffic: 扣费倍率后折算的下载流量（字节）
-- actual_traffic: 实际扣费流量（字节，含上传+下载）
-- deduction_multiplier: 当次扣费倍率
-- date: 统计日期（YYYY-MM-DD格式）
-- created_at: 记录创建时间（UTC+8时区）
CREATE TABLE
    IF NOT EXISTS traffic_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        node_id INTEGER NOT NULL,
        upload_traffic INTEGER DEFAULT 0,
        download_traffic INTEGER DEFAULT 0,
        actual_upload_traffic INTEGER DEFAULT 0,
        actual_download_traffic INTEGER DEFAULT 0,
        actual_traffic INTEGER DEFAULT 0,
        deduction_multiplier REAL DEFAULT 1,
        date DATE NOT NULL,
        created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE
    );

-- 用户每日流量统计表
-- 字段说明：
-- user_id: 用户ID
-- record_date: 记录日期 (YYYY-MM-DD)
-- upload_traffic: 当日上传流量(字节)
-- download_traffic: 当日下载流量(字节)
-- total_traffic: 当日总流量(字节)
-- node_usage: 各节点使用情况JSON
-- created_at: 记录创建时间（UTC+8时区）
CREATE TABLE IF NOT EXISTS daily_traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    record_date DATE NOT NULL,
    upload_traffic BIGINT DEFAULT 0,
    download_traffic BIGINT DEFAULT 0,
    total_traffic BIGINT DEFAULT 0,
    node_usage TEXT,
    created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, record_date)
);

-- 公告表
-- 字段说明：
-- title: 公告标题
-- content: 公告内容(Markdown格式)
-- content_html: 公告HTML内容
-- type: 公告类型(info, warning, success, danger)
-- is_active: 是否启用(0-禁用, 1-启用)
-- is_pinned: 是否置顶(0-否, 1-是)
-- priority: 优先级，数字越大优先级越高
-- created_by: 创建者用户ID
-- created_at: 创建时间戳
-- updated_at: 更新时间戳
-- expires_at: 过期时间戳
CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    content_html TEXT,
    type VARCHAR(50) DEFAULT 'info',
    is_active INTEGER DEFAULT 1,
    is_pinned INTEGER DEFAULT 0,
    priority INTEGER DEFAULT 0,
    created_by INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER,
    expires_at INTEGER,
    
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- 系统配置表
-- 字段说明：
-- id: 系统配置唯一标识ID（主键）
-- key: 配置项键名（唯一，不能为空）
-- value: 配置项值
-- description: 配置项描述
-- created_at: 创建时间（UTC+8时区）
-- updated_at: 更新时间（UTC+8时区）
CREATE TABLE
    IF NOT EXISTS system_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        value TEXT,
        description TEXT,
        created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
        updated_at DATETIME DEFAULT (datetime('now', '+8 hours'))
    );

-- 用户登录记录表
-- 字段说明：
-- id: 登录记录唯一标识ID（主键）
-- user_id: 用户ID（外键关联users表）
-- login_ip: 登录IP地址
-- login_time: 登录时间（UTC+8时区）
-- user_agent: 用户代理字符串（浏览器信息）
-- login_status: 登录状态（1-成功，0-失败）
-- failure_reason: 失败原因（登录失败时记录）
-- login_method: 登录方式（如 password、google_oauth）
-- created_at: 记录创建时间（UTC+8时区）
CREATE TABLE IF NOT EXISTS login_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    login_ip TEXT NOT NULL,
    login_time DATETIME DEFAULT (datetime('now', '+8 hours')),
    user_agent TEXT,
    login_status INTEGER DEFAULT 1,
    failure_reason TEXT,
    login_method TEXT DEFAULT 'password',
    created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 邮箱验证码表
-- 字段说明：
-- id: 主键
-- email: 接收验证码的邮箱地址
-- code_hash: 验证码的哈希值（SHA-256）
-- purpose: 验证码用途（如 register、password_reset）
-- expires_at: 验证码过期时间（UTC+8时区）
-- attempts: 已尝试验证的次数
-- request_ip: 请求发送验证码的 IP
-- user_agent: 请求发送验证码时的 UA
-- created_at: 记录创建时间（发送时间）
-- used_at: 验证码成功使用时间
CREATE TABLE IF NOT EXISTS email_verification_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    purpose TEXT NOT NULL DEFAULT 'register',
    code_hash TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    request_ip TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    used_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_email_verification_email ON email_verification_codes (email);
CREATE INDEX IF NOT EXISTS idx_email_verification_email_purpose ON email_verification_codes (email, purpose);
CREATE INDEX IF NOT EXISTS idx_email_verification_expires_at ON email_verification_codes (expires_at);
CREATE INDEX IF NOT EXISTS idx_email_verification_used_at ON email_verification_codes (used_at);

-- 用户会话表（替代KV存储）
-- 字段说明：
-- id: 会话记录唯一标识ID（主键）
-- token: 会话令牌（唯一，不能为空）
-- user_id: 用户ID（外键关联users表）
-- user_data: 用户会话数据JSON格式
-- expires_at: 会话过期时间（UTC+8时区）
-- created_at: 会话创建时间（UTC+8时区）
CREATE TABLE
    IF NOT EXISTS user_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        user_data TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    );

-- 二步验证可信设备表
-- 字段说明：
-- id: 唯一标识
-- user_id: 用户ID
-- token_hash: 记住设备令牌哈希
-- device_name: 设备名称
-- user_agent: UA
-- expires_at: 过期时间
-- last_used_at: 最后使用时间
-- created_at: 创建时间
-- disabled: 是否禁用
CREATE TABLE IF NOT EXISTS two_factor_trusted_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,
    device_name TEXT,
    user_agent TEXT,
    expires_at DATETIME NOT NULL,
    last_used_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    disabled INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    UNIQUE (user_id, token_hash)
);

-- Passkey 表（WebAuthn）
-- 字段说明：
-- id: 主键
-- user_id: 用户ID（外键）
-- credential_id: 凭证ID（base64url，唯一）
-- public_key: COSE 公钥（base64url）
-- alg: COSE alg（如 -7 表示 ES256）
-- user_handle: 注册时的 user.id（base64url）
-- rp_id: 绑定的 rpId（域名）
-- transports: 认证器传输方式 JSON
-- sign_count: 签名计数
-- device_name: 设备备注
-- last_used_at/created_at/updated_at: 时间字段
CREATE TABLE IF NOT EXISTS passkeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    alg INTEGER NOT NULL,
    user_handle TEXT,
    rp_id TEXT,
    transports TEXT,
    sign_count INTEGER DEFAULT 0,
    device_name TEXT,
    last_used_at DATETIME,
    created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    updated_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- 苹果账号共享ID配置表
-- 字段说明：
-- id: 主键
-- name: 共享ID名称，展示给用户
-- fetch_url: 需要代理获取的远程JSON地址
-- remote_account_id: 远程JSON中的账户ID（支持单个ID或ID数组：JSON/逗号分隔）
-- status: 状态（1启用，0禁用）
-- created_at/updated_at: 记录创建与更新时间（UTC+8）
CREATE TABLE IF NOT EXISTS shared_ids (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    fetch_url TEXT NOT NULL,
    remote_account_id TEXT NOT NULL,
    status INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    updated_at DATETIME DEFAULT (datetime('now', '+8 hours'))
);

-- 套餐表
-- 字段说明：
-- id: 套餐唯一标识ID（主键）
-- name: 套餐名称（不能为空）
-- price: 套餐价格（元）
-- traffic_quota: 流量配额（GB）
-- validity_days: 有效期天数（购买后增加多少天的等级有效期）
-- speed_limit: 速度限制（Mbps，0表示无限制）
-- device_limit: 设备数量限制（0表示无限制）
-- level: 套餐对应的用户等级
-- status: 套餐状态（0-禁用，1-启用）
-- is_recommended: 是否推荐套餐（0-否，1-是）
-- sort_weight: 排序权重（数字越大排序越靠前）
-- created_at: 创建时间（UTC+8时区）
-- updated_at: 更新时间（UTC+8时区）
CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    traffic_quota INTEGER NOT NULL DEFAULT 0, -- 单位GB
    validity_days INTEGER NOT NULL DEFAULT 30,
    speed_limit INTEGER DEFAULT 0,
    device_limit INTEGER DEFAULT 0,
    level INTEGER DEFAULT 1,
    status INTEGER DEFAULT 1,
    is_recommended INTEGER DEFAULT 0,
    sort_weight INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    updated_at DATETIME DEFAULT (datetime('now', '+8 hours'))
);

-- 优惠券表
-- 字段说明：
-- code: 唯一优惠码
-- discount_type: off_amount/ off_percentage
-- discount_value: 优惠值（金额或百分比，百分比传 1-100）
-- start_at / end_at: Unix 时间戳（秒）
-- max_usage / per_user_limit: NULL 表示不限制
-- total_used: 已使用次数，配合 max_usage 控制剩余名额
CREATE TABLE IF NOT EXISTS coupons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    code TEXT NOT NULL UNIQUE,
    discount_type TEXT NOT NULL CHECK(discount_type IN ('amount', 'percentage')),
    discount_value DECIMAL(10,2) NOT NULL,
    start_at INTEGER NOT NULL,
    end_at INTEGER NOT NULL,
    max_usage INTEGER,
    per_user_limit INTEGER,
    total_used INTEGER NOT NULL DEFAULT 0,
    status INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    updated_at DATETIME DEFAULT (datetime('now', '+8 hours'))
);

-- 优惠券适用套餐表
CREATE TABLE IF NOT EXISTS coupon_packages (
    coupon_id INTEGER NOT NULL,
    package_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    PRIMARY KEY (coupon_id, package_id),
    FOREIGN KEY (coupon_id) REFERENCES coupons (id) ON DELETE CASCADE,
    FOREIGN KEY (package_id) REFERENCES packages (id) ON DELETE CASCADE
);

-- 优惠券使用记录表
CREATE TABLE IF NOT EXISTS coupon_usages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    coupon_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    order_id INTEGER,
    order_trade_no TEXT,
    used_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    FOREIGN KEY (coupon_id) REFERENCES coupons (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_coupon_usages_coupon ON coupon_usages (coupon_id);
CREATE INDEX IF NOT EXISTS idx_coupon_usages_coupon_user ON coupon_usages (coupon_id, user_id);

-- 礼品卡批次表
-- 字段说明：
-- id: 批次主键
-- name: 批次名称（用于在后台区分不同发放场景）
-- description: 批次备注说明
-- card_type: 批次内礼品卡的类型（balance/duration/traffic/reset_traffic/package）
-- quantity: 本批次计划生成的卡片数量
-- code_prefix: 批量生成卡号时使用的前缀
-- balance_amount/duration_days/traffic_value_gb/reset_traffic_gb: 针对不同类型的默认面值
-- package_id: 若为兑换套餐类型，对应的套餐ID
-- max_usage: 单张礼品卡最大可被使用次数（null 表示不限制）
-- start_at/end_at: 批次有效期（卡片默认继承）
-- created_by: 创建该批次的管理员ID
-- created_at: 记录创建时间（UTC+8）
CREATE TABLE IF NOT EXISTS gift_card_batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    card_type TEXT NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    code_prefix TEXT,
    balance_amount DECIMAL(10,2),
    duration_days INTEGER,
    traffic_value_gb INTEGER,
    reset_traffic_gb INTEGER,
    package_id INTEGER,
    max_usage INTEGER,
    per_user_limit INTEGER,
    start_at DATETIME,
    end_at DATETIME,
    created_by INTEGER,
    created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    FOREIGN KEY (package_id) REFERENCES packages (id) ON DELETE SET NULL,
    FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL
);

-- 礼品卡表
-- 字段说明：
-- id: 礼品卡主键
-- batch_id: 所属批次ID（可为空表示单独创建）
-- name: 礼品卡名称/标题
-- code: 唯一卡密（用户兑换凭证）
-- card_type: 类型（balance/duration/traffic/reset_traffic/package）
-- status: 状态（1-启用，0-禁用，2-已用完）
-- balance_amount/duration_days/traffic_value_gb/reset_traffic_gb: 按类型对应的面值
-- package_id: 若为套餐兑换类型，指定的套餐
-- max_usage: 最大使用次数（null 表示不限制）
-- per_user_limit: 每个用户最多可使用次数（null 表示不限制）
-- used_count: 已使用次数
-- start_at/end_at: 单张卡的生效/失效时间
-- created_by: 创建人ID
-- created_at/updated_at: 创建与更新时间（UTC+8）
CREATE TABLE IF NOT EXISTS gift_cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id INTEGER,
    name TEXT NOT NULL,
    code TEXT UNIQUE NOT NULL,
    card_type TEXT NOT NULL,
    status INTEGER NOT NULL DEFAULT 1,
    balance_amount DECIMAL(10,2),
    duration_days INTEGER,
    traffic_value_gb INTEGER,
    reset_traffic_gb INTEGER,
    package_id INTEGER,
    max_usage INTEGER DEFAULT 1,
    per_user_limit INTEGER,
    used_count INTEGER DEFAULT 0,
    start_at DATETIME,
    end_at DATETIME,
    created_by INTEGER,
    created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    updated_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    FOREIGN KEY (batch_id) REFERENCES gift_card_batches (id) ON DELETE SET NULL,
    FOREIGN KEY (package_id) REFERENCES packages (id) ON DELETE SET NULL,
    FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL
);

-- 礼品卡兑换记录表
-- 字段说明：
-- id: 兑换记录主键
-- card_id: 对应的礼品卡ID
-- user_id: 兑换该卡的用户ID
-- code: 兑换时使用的礼品卡卡密
-- card_type: 兑换卡的类型
-- change_amount/duration_days/traffic_value_gb/reset_traffic_gb: 兑换产生的实际变动值
-- package_id: 若兑换套餐时记录的套餐ID
-- recharge_record_id/purchase_record_id: 关联的充值或套餐购买记录ID（根据类型为空）
-- trade_no: 关联的交易号（默认为卡密）
-- result_status: 兑换状态（success/failed）
-- message: 兑换结果描述
-- created_at: 兑换时间（UTC+8）
CREATE TABLE IF NOT EXISTS gift_card_redemptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    code TEXT NOT NULL,
    card_type TEXT NOT NULL,
    change_amount DECIMAL(10,2),
    duration_days INTEGER,
    traffic_value_gb INTEGER,
    reset_traffic_gb INTEGER,
    package_id INTEGER,
    recharge_record_id INTEGER,
    purchase_record_id INTEGER,
    trade_no TEXT,
    result_status TEXT NOT NULL DEFAULT 'success',
    message TEXT,
    created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    FOREIGN KEY (card_id) REFERENCES gift_cards (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (recharge_record_id) REFERENCES recharge_records (id) ON DELETE SET NULL,
    FOREIGN KEY (purchase_record_id) REFERENCES package_purchase_records (id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_gift_cards_status ON gift_cards (status);
CREATE INDEX IF NOT EXISTS idx_gift_cards_type ON gift_cards (card_type);
CREATE INDEX IF NOT EXISTS idx_gift_cards_code ON gift_cards (code);
CREATE INDEX IF NOT EXISTS idx_gift_card_redemptions_card_id ON gift_card_redemptions (card_id);
CREATE INDEX IF NOT EXISTS idx_gift_card_redemptions_user_id ON gift_card_redemptions (user_id);

-- 邀请关系表
-- 字段说明：
-- id: 关联ID
-- inviter_id: 邀请人用户ID
-- invitee_id: 被邀请人用户ID
-- invite_code: 使用的邀请码
-- invite_ip: 注册时的IP地址
-- registered_at: 注册时间
-- first_payment_type: 首次付费类型（recharge/purchase）
-- first_payment_id: 首次付费记录ID
-- first_paid_at: 首次付费时间
-- status: 状态（pending/active/blocked）
-- created_at: 创建时间
-- updated_at: 更新时间
CREATE TABLE IF NOT EXISTS referral_relations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    inviter_id INTEGER NOT NULL,
    invitee_id INTEGER NOT NULL UNIQUE,
    invite_code TEXT NOT NULL,
    invite_ip TEXT,
    registered_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    first_payment_type TEXT,
    first_payment_id INTEGER,
    first_paid_at DATETIME,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    updated_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    FOREIGN KEY (inviter_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_referral_relations_inviter ON referral_relations (inviter_id, created_at);
CREATE INDEX IF NOT EXISTS idx_referral_relations_status ON referral_relations (status);

-- 返利流水表
-- 字段说明：
-- id: 流水ID
-- inviter_id: 获得返利的用户ID
-- referral_id: 对应的邀请关系ID
-- invitee_id: 受邀人ID
-- source_type: 来源类型（recharge/purchase/withdraw/transfer等）
-- source_id: 来源记录ID
-- trade_no: 关联交易号
-- event_type: 事件类型（order_rebate/cancel/withdraw等）
-- amount: 变动金额（正为增加，负为扣减）
-- status: 流水状态（confirmed/canceled）
-- remark: 备注信息
-- created_at: 创建时间
CREATE TABLE IF NOT EXISTS rebate_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    inviter_id INTEGER NOT NULL,
    referral_id INTEGER,
    invitee_id INTEGER,
    source_type TEXT NOT NULL,
    source_id INTEGER,
    trade_no TEXT,
    event_type TEXT NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    status TEXT NOT NULL DEFAULT 'confirmed',
    remark TEXT,
    created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    FOREIGN KEY (inviter_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (referral_id) REFERENCES referral_relations (id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_rebate_transactions_user ON rebate_transactions (inviter_id, created_at);
CREATE INDEX IF NOT EXISTS idx_rebate_transactions_source ON rebate_transactions (source_type, source_id);

-- 返利划转记录
-- 字段说明：
-- id: 记录ID
-- user_id: 用户ID
-- amount: 划转金额
-- balance_before/balance_after: 划转前后余额
-- rebate_before/rebate_after: 划转前后返利余额
-- created_at: 创建时间
CREATE TABLE IF NOT EXISTS rebate_transfers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    balance_before DECIMAL(10,2) NOT NULL,
    balance_after DECIMAL(10,2) NOT NULL,
    rebate_before DECIMAL(10,2) NOT NULL,
    rebate_after DECIMAL(10,2) NOT NULL,
    created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_rebate_transfers_user ON rebate_transfers (user_id, created_at);

-- 返利提现申请表
-- 字段说明：
-- id: 提现申请ID
-- user_id: 用户ID
-- amount: 申请金额
-- method: 提现方式
-- account_payload: 收款信息JSON
-- status: 状态（pending/approved/rejected/paid）
-- reviewer_id: 审核管理员ID
-- review_note: 审核备注
-- created_at: 申请时间
-- updated_at: 更新时间
-- processed_at: 处理完成时间
CREATE TABLE IF NOT EXISTS rebate_withdrawals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    method TEXT NOT NULL DEFAULT 'manual',
    account_payload TEXT,
    fee_rate DECIMAL(6,4) NOT NULL DEFAULT 0,
    fee_amount DECIMAL(10,2) NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    reviewer_id INTEGER,
    review_note TEXT,
    created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    updated_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    processed_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (reviewer_id) REFERENCES users (id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_rebate_withdrawals_user ON rebate_withdrawals (user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_rebate_withdrawals_status ON rebate_withdrawals (status);

-- 充值记录表
-- 字段说明：
-- id: 充值记录唯一标识ID（主键）
-- user_id: 用户ID（外键关联users表）
-- amount: 充值金额（元）
-- payment_method: 支付方式（alipay、wechat、balance等）
-- trade_no: 交易号（支付平台的订单号）
-- status: 充值状态（0-待支付，1-已支付，2-已取消，3-支付失败）
-- created_at: 创建时间（UTC+8时区）
-- paid_at: 支付完成时间（UTC+8时区）
CREATE TABLE IF NOT EXISTS recharge_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    payment_method TEXT NOT NULL DEFAULT 'alipay',
    trade_no TEXT UNIQUE NOT NULL,
    status INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    paid_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- 套餐购买记录表
-- 字段说明：
-- id: 购买记录唯一标识ID（主键）
-- user_id: 用户ID（外键关联users表）
-- package_id: 套餐ID（外键关联packages表）
-- price: 购买时的价格（元）
-- package_price: 套餐原价（元），用于智能补差额购买功能
-- purchase_type: 购买类型（balance-余额购买，direct-直接支付）
-- trade_no: 交易号
-- status: 购买状态（0-待支付，1-已支付，2-已取消，3-支付失败）
-- created_at: 创建时间（UTC+8时区）
-- paid_at: 支付完成时间（UTC+8时区）
-- expires_at: 到期时间（UTC+8时区）
CREATE TABLE IF NOT EXISTS package_purchase_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    package_id INTEGER NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    package_price DECIMAL(10,2),
    coupon_id INTEGER,
    coupon_code TEXT,
    discount_amount DECIMAL(10,2) NOT NULL DEFAULT 0,
    purchase_type TEXT NOT NULL DEFAULT 'balance',
    trade_no TEXT UNIQUE NOT NULL,
    status INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    paid_at DATETIME,
    expires_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (package_id) REFERENCES packages (id) ON DELETE CASCADE,
    FOREIGN KEY (coupon_id) REFERENCES coupons (id) ON DELETE SET NULL
);

-- =============================================
-- 工单系统
-- =============================================
-- 工单表
-- 字段说明：
-- id: 工单ID
-- user_id: 提交工单的用户ID
-- title: 工单标题
-- content: 工单正文（Markdown）
-- status: 工单状态（open/answered/closed）
-- last_reply_by_admin_id: 最后回复的管理员ID
-- last_reply_at: 最后回复时间
-- created_at / updated_at: 记录创建与更新时间
CREATE TABLE
    IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        last_reply_by_admin_id INTEGER,
        last_reply_at DATETIME,
        created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
        updated_at DATETIME DEFAULT (datetime('now', '+8 hours')),
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        FOREIGN KEY (last_reply_by_admin_id) REFERENCES users (id) ON DELETE SET NULL
    );

-- 工单回复表
-- 仅允许管理员回复，记录 Markdown 正文内容
CREATE TABLE
    IF NOT EXISTS ticket_replies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id INTEGER NOT NULL,
        author_id INTEGER NOT NULL,
        author_role TEXT NOT NULL CHECK(author_role IN ('user', 'admin')),
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
        FOREIGN KEY (ticket_id) REFERENCES tickets (id) ON DELETE CASCADE,
        FOREIGN KEY (author_id) REFERENCES users (id) ON DELETE CASCADE
    );


-- =============================================
-- 创建索引以优化查询性能
-- =============================================
-- 用户表索引
CREATE INDEX IF NOT EXISTS idx_users_uuid ON users (uuid);

CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

CREATE INDEX IF NOT EXISTS idx_users_token ON users (token);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_invite_code ON users (invite_code);
CREATE INDEX IF NOT EXISTS idx_users_invited_by ON users (invited_by);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub ON users (google_sub);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_github_id ON users (github_id);
CREATE INDEX IF NOT EXISTS idx_users_oauth_provider ON users (oauth_provider);

CREATE INDEX IF NOT EXISTS idx_users_status ON users (status);

CREATE INDEX IF NOT EXISTS idx_users_expire_time ON users (expire_time);

CREATE INDEX IF NOT EXISTS idx_users_class ON users (class);

CREATE INDEX IF NOT EXISTS idx_users_money ON users (money);

-- 节点表索引
CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes (type);

CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes (status);

CREATE INDEX IF NOT EXISTS idx_nodes_class ON nodes (node_class);

-- 流量日志索引
CREATE INDEX IF NOT EXISTS idx_traffic_logs_user_date ON traffic_logs (user_id, date);

CREATE INDEX IF NOT EXISTS idx_traffic_logs_node_date ON traffic_logs (node_id, date);

-- 每日流量统计索引
CREATE INDEX IF NOT EXISTS idx_daily_traffic_user_date ON daily_traffic (user_id, record_date);
CREATE INDEX IF NOT EXISTS idx_daily_traffic_date ON daily_traffic (record_date);
CREATE INDEX IF NOT EXISTS idx_daily_traffic_created ON daily_traffic (created_at);



-- 在线IP索引
CREATE INDEX IF NOT EXISTS idx_online_ips_user ON online_ips (user_id);

CREATE INDEX IF NOT EXISTS idx_online_ips_last_seen ON online_ips (last_seen);

-- 审计日志索引
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs (user_id);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at);

-- 节点状态索引
CREATE INDEX IF NOT EXISTS idx_node_status_node_time ON node_status (node_id, created_at);

-- 会话索引
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions (token);

CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions (expires_at);

CREATE INDEX IF NOT EXISTS idx_two_factor_trusted_devices_user ON two_factor_trusted_devices (user_id);

CREATE INDEX IF NOT EXISTS idx_two_factor_trusted_devices_expires ON two_factor_trusted_devices (expires_at);

CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys (user_id);

CREATE INDEX IF NOT EXISTS idx_passkeys_rp ON passkeys (rp_id);

CREATE INDEX IF NOT EXISTS idx_shared_ids_status ON shared_ids (status);
CREATE INDEX IF NOT EXISTS idx_shared_ids_remote_id ON shared_ids (remote_account_id);

-- 登录记录索引
CREATE INDEX IF NOT EXISTS idx_login_logs_user_id ON login_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_login_logs_login_time ON login_logs(login_time);
CREATE INDEX IF NOT EXISTS idx_login_logs_login_ip ON login_logs(login_ip);
CREATE INDEX IF NOT EXISTS idx_login_logs_status ON login_logs(login_status);

-- 公告表索引
CREATE INDEX IF NOT EXISTS idx_announcements_active ON announcements(is_active);
CREATE INDEX IF NOT EXISTS idx_announcements_pinned ON announcements(is_pinned);
CREATE INDEX IF NOT EXISTS idx_announcements_created_at ON announcements(created_at);
CREATE INDEX IF NOT EXISTS idx_announcements_expires_at ON announcements(expires_at);

-- 套餐相关索引
CREATE INDEX IF NOT EXISTS idx_packages_status ON packages (status);
CREATE INDEX IF NOT EXISTS idx_packages_level ON packages (level);
CREATE INDEX IF NOT EXISTS idx_packages_price ON packages (price);

-- 充值记录索引
CREATE INDEX IF NOT EXISTS idx_recharge_records_user_id ON recharge_records (user_id);
CREATE INDEX IF NOT EXISTS idx_recharge_records_trade_no ON recharge_records (trade_no);
CREATE INDEX IF NOT EXISTS idx_recharge_records_status ON recharge_records (status);
CREATE INDEX IF NOT EXISTS idx_recharge_records_created_at ON recharge_records (created_at);

-- 套餐购买记录索引
CREATE INDEX IF NOT EXISTS idx_package_purchase_records_user_id ON package_purchase_records (user_id);
CREATE INDEX IF NOT EXISTS idx_package_purchase_records_package_id ON package_purchase_records (package_id);
CREATE INDEX IF NOT EXISTS idx_package_purchase_records_trade_no ON package_purchase_records (trade_no);
CREATE INDEX IF NOT EXISTS idx_package_purchase_records_status ON package_purchase_records (status);
CREATE INDEX IF NOT EXISTS idx_package_purchase_records_created_at ON package_purchase_records (created_at);
CREATE INDEX IF NOT EXISTS idx_package_purchase_records_paid_at ON package_purchase_records (paid_at);
CREATE INDEX IF NOT EXISTS idx_package_purchase_records_expires_at ON package_purchase_records (expires_at);

-- 工单常用索引
CREATE INDEX IF NOT EXISTS idx_tickets_user_id ON tickets (user_id);
CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets (status);
CREATE INDEX IF NOT EXISTS idx_tickets_last_reply_at ON tickets (last_reply_at);
CREATE INDEX IF NOT EXISTS idx_ticket_replies_ticket_id ON ticket_replies (ticket_id);
CREATE INDEX IF NOT EXISTS idx_ticket_replies_author_role ON ticket_replies (author_role);
