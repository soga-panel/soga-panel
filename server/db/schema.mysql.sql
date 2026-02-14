-- MariaDB 版 Schema（迁移自 worker/db/db.sql）
-- 说明：默认时区建议设置为 +08:00；时间字段使用 CURRENT_TIMESTAMP，并在更新时自动更新时间。

CREATE TABLE IF NOT EXISTS users (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '用户ID',
  email VARCHAR(255) NOT NULL UNIQUE COMMENT '邮箱（唯一）',
  username VARCHAR(255) NOT NULL UNIQUE COMMENT '用户名（唯一）',
  password_hash VARCHAR(255) NOT NULL COMMENT '登录密码哈希',
  uuid VARCHAR(255) NOT NULL UNIQUE COMMENT '代理 UUID',
  passwd VARCHAR(255) NOT NULL COMMENT '代理连接密码',
  token VARCHAR(255) NOT NULL UNIQUE COMMENT '订阅令牌',
  invite_code VARCHAR(255) UNIQUE COMMENT '用户邀请码',
  invited_by BIGINT NOT NULL DEFAULT 0 COMMENT '邀请人用户 ID（0 表示无）',
  invite_used INT DEFAULT 0 COMMENT '邀请码已使用次数',
  invite_limit INT DEFAULT 0 COMMENT '邀请码可使用次数（0 表示不限）',
  google_sub VARCHAR(255) COMMENT 'Google OAuth 唯一标识',
  oauth_provider VARCHAR(50) COMMENT 'OAuth 提供商（google/github 等）',
  first_oauth_login_at DATETIME COMMENT '首次 OAuth 登录时间',
  last_oauth_login_at DATETIME COMMENT '最近 OAuth 登录时间',
  github_id VARCHAR(255) COMMENT 'GitHub OAuth 唯一标识',
  is_admin TINYINT DEFAULT 0 COMMENT '是否管理员（1 为管理员）',
  speed_limit INT DEFAULT 0 COMMENT '速度限制 Mbps（0 表示不限）',
  device_limit INT DEFAULT 0 COMMENT '设备数量限制（0 表示不限）',
  tcp_limit INT DEFAULT 0 COMMENT 'TCP 连接数限制（0 表示不限）',
  upload_traffic BIGINT DEFAULT 0 COMMENT '历史上传流量（字节）',
  download_traffic BIGINT DEFAULT 0 COMMENT '历史下载流量（字节）',
  upload_today BIGINT DEFAULT 0 COMMENT '今日上传流量（字节）',
  download_today BIGINT DEFAULT 0 COMMENT '今日下载流量（字节）',
  transfer_total BIGINT DEFAULT 0 COMMENT '历史已用总流量（字节）',
  transfer_enable BIGINT DEFAULT 10737418240 COMMENT '总流量额度（字节）',
  status TINYINT DEFAULT 1 COMMENT '账户状态（0 禁用，1 启用）',
  reg_date DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '注册时间',
  expire_time DATETIME COMMENT '账户过期时间',
  last_login_time DATETIME COMMENT '最后登录时间',
  last_login_ip VARCHAR(255) COMMENT '最后登录 IP',
  class INT DEFAULT 1 COMMENT '用户等级',
  class_expire_time DATETIME COMMENT '等级过期时间',
  bark_key VARCHAR(255) COMMENT 'Bark 推送 Key',
  bark_enabled TINYINT DEFAULT 0 COMMENT '是否启用 Bark 推送',
  two_factor_enabled TINYINT DEFAULT 0 COMMENT '是否开启二步验证',
  two_factor_secret TEXT COMMENT '二步验证密钥',
  two_factor_backup_codes TEXT COMMENT '二步验证备用验证码',
  two_factor_temp_secret TEXT COMMENT '二步验证临时密钥',
  two_factor_confirmed_at DATETIME COMMENT '二步验证启用确认时间',
  money DECIMAL(10,2) DEFAULT 0.00 COMMENT '余额',
  rebate_available DECIMAL(10,2) DEFAULT 0.00 COMMENT '可用返利余额',
  rebate_total DECIMAL(10,2) DEFAULT 0.00 COMMENT '累计返利总额',
  register_ip VARCHAR(255) COMMENT '注册 IP',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_invite_code ON users (invite_code);

CREATE TABLE IF NOT EXISTS nodes (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '节点 ID',
  name VARCHAR(255) NOT NULL COMMENT '节点名称',
  type VARCHAR(50) NOT NULL COMMENT '节点类型（v2ray/vless/trojan 等）',
  node_class INT DEFAULT 1 COMMENT '节点等级（可访问的最低用户等级）',
  node_bandwidth BIGINT DEFAULT 0 COMMENT '节点已用流量（字节）',
  node_bandwidth_limit BIGINT DEFAULT 0 COMMENT '节点流量上限（字节，0 表示不限）',
  traffic_multiplier DECIMAL(10,4) DEFAULT 1 COMMENT '流量倍率（扣费时的倍数）',
  bandwidthlimit_resetday INT DEFAULT 1 COMMENT '每月流量重置日（1-31）',
  node_config JSON NOT NULL COMMENT '节点配置 JSON',
  status TINYINT DEFAULT 1 COMMENT '节点状态（0 禁用，1 启用）',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS audit_rules (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '审计规则 ID',
  name VARCHAR(255) NOT NULL COMMENT '规则名称',
  description TEXT COMMENT '规则描述',
  rule TEXT NOT NULL COMMENT '规则表达式',
  enabled TINYINT DEFAULT 1 COMMENT '是否启用（1 启用）',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS dns_rules (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT 'DNS 规则 ID',
  name VARCHAR(255) NOT NULL COMMENT '规则名称',
  description TEXT COMMENT '规则描述',
  rule_json JSON NOT NULL COMMENT '规则 JSON',
  enabled TINYINT DEFAULT 1 COMMENT '是否启用（1 启用）',
  node_ids JSON NOT NULL COMMENT '绑定节点 ID 列表',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS white_list (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '白名单 ID',
  rule TEXT NOT NULL COMMENT '白名单规则（域名/IP 等）',
  description TEXT COMMENT '规则描述',
  status TINYINT DEFAULT 1 COMMENT '状态（1 启用）',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS subscriptions (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '订阅记录 ID',
  user_id BIGINT NOT NULL COMMENT '用户 ID',
  type VARCHAR(50) NOT NULL COMMENT '订阅类型（clash/v2ray 等）',
  request_ip VARCHAR(255) COMMENT '请求 IP',
  request_time DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '请求时间',
  request_user_agent TEXT COMMENT 'User-Agent',
  CONSTRAINT fk_subscriptions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS online_ips (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '在线 IP 记录 ID',
  user_id BIGINT NOT NULL COMMENT '用户 ID',
  node_id BIGINT NOT NULL COMMENT '节点 ID',
  ip VARCHAR(255) NOT NULL COMMENT '在线 IP 地址',
  last_seen DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '最后在线时间',
  UNIQUE KEY uniq_online_ips (user_id, node_id, ip),
  CONSTRAINT fk_online_ips_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_online_ips_node FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '审计日志 ID',
  user_id BIGINT NOT NULL COMMENT '用户 ID',
  node_id BIGINT NOT NULL COMMENT '节点 ID',
  audit_rule_id BIGINT NOT NULL COMMENT '触发的审计规则 ID',
  ip_address VARCHAR(255) COMMENT '命中时的 IP 地址',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  CONSTRAINT fk_audit_logs_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_audit_logs_node FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE,
  CONSTRAINT fk_audit_logs_rule FOREIGN KEY (audit_rule_id) REFERENCES audit_rules (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS node_status (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '节点状态记录 ID',
  node_id BIGINT NOT NULL COMMENT '节点 ID',
  cpu_usage DECIMAL(6,3) COMMENT 'CPU 使用率',
  memory_total BIGINT COMMENT '内存总量（字节）',
  memory_used BIGINT COMMENT '内存已用（字节）',
  swap_total BIGINT COMMENT '交换区总量（字节）',
  swap_used BIGINT COMMENT '交换区已用（字节）',
  disk_total BIGINT COMMENT '磁盘总量（字节）',
  disk_used BIGINT COMMENT '磁盘已用（字节）',
  uptime BIGINT COMMENT '系统运行时间（秒）',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '记录时间',
  CONSTRAINT fk_node_status_node FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS traffic_logs (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '流量日志 ID',
  user_id BIGINT NOT NULL COMMENT '用户 ID',
  node_id BIGINT NOT NULL COMMENT '节点 ID',
  upload_traffic BIGINT DEFAULT 0 COMMENT '上传流量（字节）',
  download_traffic BIGINT DEFAULT 0 COMMENT '下载流量（字节）',
  actual_upload_traffic BIGINT DEFAULT 0 COMMENT '折算后上传流量（字节）',
  actual_download_traffic BIGINT DEFAULT 0 COMMENT '折算后下载流量（字节）',
  actual_traffic BIGINT DEFAULT 0 COMMENT '实际扣费流量（字节）',
  deduction_multiplier DECIMAL(10,4) DEFAULT 1 COMMENT '扣费倍率',
  date DATE NOT NULL COMMENT '统计日期',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '记录创建时间',
  CONSTRAINT fk_traffic_logs_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_traffic_logs_node FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS daily_traffic (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '日流量统计 ID',
  user_id BIGINT NOT NULL COMMENT '用户 ID',
  record_date DATE NOT NULL COMMENT '统计日期',
  upload_traffic BIGINT DEFAULT 0 COMMENT '当日上传流量',
  download_traffic BIGINT DEFAULT 0 COMMENT '当日下载流量',
  total_traffic BIGINT DEFAULT 0 COMMENT '当日总流量',
  node_usage JSON COMMENT '按节点统计的使用情况 JSON',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  UNIQUE KEY uniq_daily_traffic_user_date (user_id, record_date),
  CONSTRAINT fk_daily_traffic_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_traffic_summary (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '系统流量汇总 ID',
  record_date DATE NOT NULL UNIQUE COMMENT '统计日期',
  total_users BIGINT DEFAULT 0 COMMENT '当天统计的用户总数',
  total_upload BIGINT DEFAULT 0 COMMENT '总上传流量',
  total_download BIGINT DEFAULT 0 COMMENT '总下载流量',
  total_traffic BIGINT DEFAULT 0 COMMENT '总流量',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS announcements (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '公告 ID',
  title VARCHAR(255) NOT NULL COMMENT '公告标题',
  content TEXT NOT NULL COMMENT '公告内容（Markdown/文本）',
  content_html TEXT COMMENT '渲染后的 HTML 内容',
  type VARCHAR(50) DEFAULT 'info' COMMENT '公告类型（info/warning 等）',
  is_active TINYINT DEFAULT 1 COMMENT '是否启用',
  is_pinned TINYINT DEFAULT 0 COMMENT '是否置顶',
  priority INT DEFAULT 0 COMMENT '排序权重',
  created_by BIGINT NOT NULL COMMENT '创建人用户 ID',
  created_at BIGINT NOT NULL COMMENT '创建时间（时间戳）',
  updated_at BIGINT COMMENT '更新时间（时间戳）',
  expires_at BIGINT COMMENT '过期时间（时间戳）',
  CONSTRAINT fk_announcements_user FOREIGN KEY (created_by) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_configs (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '配置项 ID',
  `key` VARCHAR(255) NOT NULL UNIQUE COMMENT '配置键',
  value TEXT COMMENT '配置值',
  description TEXT COMMENT '配置说明',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS login_logs (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '登录日志 ID',
  user_id BIGINT NOT NULL COMMENT '用户 ID',
  login_ip VARCHAR(255) NOT NULL COMMENT '登录 IP',
  login_time DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '登录时间',
  user_agent TEXT COMMENT 'User-Agent',
  login_status TINYINT DEFAULT 1 COMMENT '登录状态（1 成功，0 失败）',
  failure_reason TEXT COMMENT '失败原因',
  login_method VARCHAR(50) DEFAULT 'password' COMMENT '登录方式（密码/验证码等）',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  CONSTRAINT fk_login_logs_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS email_verification_codes (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '邮箱验证码记录 ID',
  email VARCHAR(255) NOT NULL COMMENT '邮箱地址',
  purpose VARCHAR(50) NOT NULL DEFAULT 'register' COMMENT '用途（注册/重置密码等）',
  code_hash VARCHAR(255) NOT NULL COMMENT '验证码哈希',
  expires_at DATETIME NOT NULL COMMENT '过期时间',
  attempts INT NOT NULL DEFAULT 0 COMMENT '验证尝试次数',
  request_ip VARCHAR(255) COMMENT '请求 IP',
  user_agent TEXT COMMENT 'User-Agent',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  used_at DATETIME COMMENT '使用时间',
  INDEX idx_email_verification_email (email),
  INDEX idx_email_verification_email_purpose (email, purpose),
  INDEX idx_email_verification_expires_at (expires_at),
  INDEX idx_email_verification_used_at (used_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS user_sessions (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '用户会话 ID',
  token VARCHAR(255) NOT NULL UNIQUE COMMENT '会话 Token',
  user_id BIGINT NOT NULL COMMENT '用户 ID',
  user_data JSON NOT NULL COMMENT '会话内缓存的用户数据',
  expires_at DATETIME NOT NULL COMMENT '过期时间',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  CONSTRAINT fk_user_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS two_factor_trusted_devices (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '二步验证信任设备 ID',
  user_id BIGINT NOT NULL COMMENT '用户 ID',
  token_hash VARCHAR(255) NOT NULL COMMENT '信任 Token 哈希',
  device_name VARCHAR(255) COMMENT '设备名称',
  user_agent TEXT COMMENT 'User-Agent',
  expires_at DATETIME NOT NULL COMMENT '过期时间',
  last_used_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '最后使用时间',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  disabled TINYINT DEFAULT 0 COMMENT '是否禁用',
  UNIQUE KEY uniq_two_factor_token (user_id, token_hash),
  CONSTRAINT fk_two_factor_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  INDEX idx_two_factor_user (user_id),
  INDEX idx_two_factor_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS passkeys (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT 'Passkey ID',
  user_id BIGINT NOT NULL COMMENT '用户 ID',
  credential_id VARCHAR(255) NOT NULL UNIQUE COMMENT '凭证 ID（base64url）',
  public_key TEXT NOT NULL COMMENT 'COSE 公钥（base64url）',
  alg INT NOT NULL COMMENT 'COSE 算法',
  user_handle VARCHAR(255) COMMENT 'user_handle（base64url）',
  rp_id VARCHAR(255) COMMENT '绑定 rpId',
  transports TEXT COMMENT '认证器传输方式',
  sign_count BIGINT DEFAULT 0 COMMENT '签名计数',
  device_name VARCHAR(255) COMMENT '设备备注',
  last_used_at DATETIME COMMENT '最后使用时间',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  CONSTRAINT fk_passkeys_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  INDEX idx_passkeys_user (user_id),
  INDEX idx_passkeys_rp (rp_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS shared_ids (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '共享账号 ID',
  name VARCHAR(255) NOT NULL COMMENT '共享账号名称',
  fetch_url TEXT NOT NULL COMMENT '远程拉取地址',
  remote_account_id TEXT NOT NULL COMMENT '远程账号 ID（支持单个ID或ID数组：JSON/CSV）',
  status TINYINT DEFAULT 1 COMMENT '状态（1 可用）',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  INDEX idx_shared_ids_status (status),
  INDEX idx_shared_ids_remote_id (remote_account_id(255))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS packages (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '套餐 ID',
  name VARCHAR(255) NOT NULL COMMENT '套餐名称',
  price DECIMAL(10,2) NOT NULL COMMENT '售价',
  traffic_quota BIGINT NOT NULL DEFAULT 0 COMMENT '流量额度（字节）',
  validity_days INT NOT NULL DEFAULT 30 COMMENT '有效期天数',
  speed_limit INT DEFAULT 0 COMMENT '速度限制 Mbps（0 不限）',
  device_limit INT DEFAULT 0 COMMENT '设备数量限制（0 不限）',
  level INT DEFAULT 1 COMMENT '购买后提升到的用户等级',
  status TINYINT DEFAULT 1 COMMENT '状态（1 上架）',
  is_recommended TINYINT DEFAULT 0 COMMENT '是否推荐套餐',
  sort_weight INT DEFAULT 0 COMMENT '排序权重',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS coupons (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '优惠券 ID',
  name VARCHAR(255) NOT NULL COMMENT '优惠券名称',
  code VARCHAR(255) NOT NULL UNIQUE COMMENT '优惠码',
  discount_type ENUM('amount','percentage') NOT NULL COMMENT '优惠类型（金额/百分比）',
  discount_value DECIMAL(10,2) NOT NULL COMMENT '优惠数值',
  start_at BIGINT NOT NULL COMMENT '生效时间戳',
  end_at BIGINT NOT NULL COMMENT '失效时间戳',
  max_usage INT COMMENT '总可用次数',
  per_user_limit INT COMMENT '单用户可用次数',
  total_used INT NOT NULL DEFAULT 0 COMMENT '已使用次数',
  status TINYINT NOT NULL DEFAULT 1 COMMENT '状态（1 启用）',
  description TEXT COMMENT '描述',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS coupon_packages (
  coupon_id BIGINT NOT NULL COMMENT '优惠券 ID',
  package_id BIGINT NOT NULL COMMENT '套餐 ID',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (coupon_id, package_id),
  CONSTRAINT fk_coupon_packages_coupon FOREIGN KEY (coupon_id) REFERENCES coupons (id) ON DELETE CASCADE,
  CONSTRAINT fk_coupon_packages_package FOREIGN KEY (package_id) REFERENCES packages (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS coupon_usages (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '优惠券使用记录 ID',
  coupon_id BIGINT NOT NULL COMMENT '优惠券 ID',
  user_id BIGINT NOT NULL COMMENT '用户 ID',
  order_id BIGINT COMMENT '关联订单 ID',
  order_trade_no VARCHAR(255) COMMENT '关联订单交易号',
  used_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '使用时间',
  CONSTRAINT fk_coupon_usages_coupon FOREIGN KEY (coupon_id) REFERENCES coupons (id) ON DELETE CASCADE,
  CONSTRAINT fk_coupon_usages_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  INDEX idx_coupon_usages_coupon (coupon_id),
  INDEX idx_coupon_usages_coupon_user (coupon_id, user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS gift_card_batches (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '礼品卡批次 ID',
  name VARCHAR(255) NOT NULL COMMENT '批次名称',
  description TEXT COMMENT '批次描述',
  card_type VARCHAR(50) NOT NULL COMMENT '礼品卡类型',
  quantity INT NOT NULL DEFAULT 1 COMMENT '生成数量',
  code_prefix VARCHAR(100) COMMENT '卡密前缀',
  balance_amount DECIMAL(10,2) COMMENT '余额面值',
  duration_days INT COMMENT '套餐时长（天）',
  traffic_value_gb INT COMMENT '流量值（GB）',
  reset_traffic_gb INT COMMENT '每次重置流量（GB）',
  package_id BIGINT COMMENT '绑定套餐 ID',
  max_usage INT COMMENT '每张卡可使用次数',
  per_user_limit INT COMMENT '单个用户最多可使用次数',
  start_at DATETIME COMMENT '生效时间',
  end_at DATETIME COMMENT '失效时间',
  created_by BIGINT COMMENT '创建人 ID',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  CONSTRAINT fk_gift_card_batches_package FOREIGN KEY (package_id) REFERENCES packages (id) ON DELETE SET NULL,
  CONSTRAINT fk_gift_card_batches_user FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS gift_cards (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '礼品卡 ID',
  batch_id BIGINT COMMENT '所属批次 ID',
  name VARCHAR(255) NOT NULL COMMENT '礼品卡名称',
  code VARCHAR(255) NOT NULL UNIQUE COMMENT '礼品卡卡密',
  card_type VARCHAR(50) NOT NULL COMMENT '礼品卡类型',
  status TINYINT NOT NULL DEFAULT 1 COMMENT '状态（1 可用）',
  balance_amount DECIMAL(10,2) COMMENT '余额面值',
  duration_days INT COMMENT '套餐时长（天）',
  traffic_value_gb INT COMMENT '流量值（GB）',
  reset_traffic_gb INT COMMENT '每次重置流量（GB）',
  package_id BIGINT COMMENT '绑定套餐 ID',
  max_usage INT DEFAULT 1 COMMENT '最大使用次数',
  per_user_limit INT COMMENT '单用户最大使用次数',
  used_count INT DEFAULT 0 COMMENT '已使用次数',
  start_at DATETIME COMMENT '生效时间',
  end_at DATETIME COMMENT '失效时间',
  created_by BIGINT COMMENT '创建人 ID',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  CONSTRAINT fk_gift_cards_batch FOREIGN KEY (batch_id) REFERENCES gift_card_batches (id) ON DELETE SET NULL,
  CONSTRAINT fk_gift_cards_package FOREIGN KEY (package_id) REFERENCES packages (id) ON DELETE SET NULL,
  CONSTRAINT fk_gift_cards_user FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL,
  INDEX idx_gift_cards_status (status),
  INDEX idx_gift_cards_type (card_type),
  INDEX idx_gift_cards_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS referral_relations (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '邀请关系 ID',
  inviter_id BIGINT NOT NULL COMMENT '邀请人用户 ID',
  invitee_id BIGINT NOT NULL UNIQUE COMMENT '被邀请用户 ID',
  invite_code VARCHAR(255) NOT NULL COMMENT '使用的邀请码',
  invite_ip VARCHAR(255) COMMENT '注册时 IP',
  registered_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '注册时间',
  first_payment_type VARCHAR(50) COMMENT '首付类型（充值/套餐）',
  first_payment_id BIGINT COMMENT '首付记录 ID',
  first_paid_at DATETIME COMMENT '首付时间',
  status VARCHAR(50) NOT NULL DEFAULT 'pending' COMMENT '状态（pending/confirmed 等）',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  CONSTRAINT fk_referral_relations_inviter FOREIGN KEY (inviter_id) REFERENCES users (id) ON DELETE CASCADE,
  INDEX idx_referral_relations_inviter (inviter_id, created_at),
  INDEX idx_referral_relations_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS rebate_transactions (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '返利流水 ID',
  inviter_id BIGINT NOT NULL COMMENT '邀请人用户 ID',
  referral_id BIGINT COMMENT '关联的邀请关系 ID',
  invitee_id BIGINT COMMENT '被邀请用户 ID',
  source_type VARCHAR(50) NOT NULL COMMENT '来源类型（recharge/purchase/withdraw 等）',
  source_id BIGINT COMMENT '来源记录 ID',
  trade_no VARCHAR(255) COMMENT '关联订单号',
  event_type VARCHAR(50) NOT NULL COMMENT '事件类型',
  amount DECIMAL(10,2) NOT NULL COMMENT '金额（正为增加，负为减少）',
  status VARCHAR(50) NOT NULL DEFAULT 'confirmed' COMMENT '状态',
  remark TEXT COMMENT '备注',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  CONSTRAINT fk_rebate_transactions_user FOREIGN KEY (inviter_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_rebate_transactions_referral FOREIGN KEY (referral_id) REFERENCES referral_relations (id) ON DELETE SET NULL,
  INDEX idx_rebate_transactions_user (inviter_id, created_at),
  INDEX idx_rebate_transactions_source (source_type, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS rebate_transfers (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '返利划转记录 ID',
  user_id BIGINT NOT NULL COMMENT '用户 ID',
  amount DECIMAL(10,2) NOT NULL COMMENT '划转金额（返利 → 余额）',
  balance_before DECIMAL(10,2) NOT NULL COMMENT '划转前余额',
  balance_after DECIMAL(10,2) NOT NULL COMMENT '划转后余额',
  rebate_before DECIMAL(10,2) NOT NULL COMMENT '划转前返利余额',
  rebate_after DECIMAL(10,2) NOT NULL COMMENT '划转后返利余额',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  CONSTRAINT fk_rebate_transfers_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  INDEX idx_rebate_transfers_user (user_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS rebate_withdrawals (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '返利提现申请 ID',
  user_id BIGINT NOT NULL COMMENT '用户 ID',
  amount DECIMAL(10,2) NOT NULL COMMENT '提现金额',
  method VARCHAR(50) NOT NULL DEFAULT 'manual' COMMENT '提现方式',
  account_payload JSON COMMENT '提现账户信息 JSON',
  fee_rate DECIMAL(6,4) NOT NULL DEFAULT 0 COMMENT '手续费比例',
  fee_amount DECIMAL(10,2) NOT NULL DEFAULT 0 COMMENT '手续费金额',
  status VARCHAR(50) NOT NULL DEFAULT 'pending' COMMENT '状态（pending/approved/rejected）',
  reviewer_id BIGINT COMMENT '审核管理员 ID',
  review_note TEXT COMMENT '审核备注',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  processed_at DATETIME COMMENT '处理时间',
  CONSTRAINT fk_rebate_withdrawals_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_rebate_withdrawals_reviewer FOREIGN KEY (reviewer_id) REFERENCES users (id) ON DELETE SET NULL,
  INDEX idx_rebate_withdrawals_user (user_id, created_at),
  INDEX idx_rebate_withdrawals_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS recharge_records (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '余额充值记录 ID',
  user_id BIGINT NOT NULL COMMENT '用户 ID',
  amount DECIMAL(10,2) NOT NULL COMMENT '充值金额',
  payment_method VARCHAR(50) NOT NULL DEFAULT 'alipay' COMMENT '支付方式',
  trade_no VARCHAR(255) NOT NULL UNIQUE COMMENT '支付订单号',
  status TINYINT DEFAULT 0 COMMENT '支付状态（0 未支付，1 已支付）',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  paid_at DATETIME COMMENT '支付时间',
  CONSTRAINT fk_recharge_records_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  INDEX idx_recharge_records_user_id (user_id),
  INDEX idx_recharge_records_trade_no (trade_no),
  INDEX idx_recharge_records_status (status),
  INDEX idx_recharge_records_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS package_purchase_records (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '套餐购买记录 ID',
  user_id BIGINT NOT NULL COMMENT '用户 ID',
  package_id BIGINT NOT NULL COMMENT '套餐 ID',
  price DECIMAL(10,2) NOT NULL COMMENT '成交金额',
  package_price DECIMAL(10,2) COMMENT '套餐原价',
  coupon_id BIGINT COMMENT '使用的优惠券 ID',
  coupon_code VARCHAR(255) COMMENT '优惠码',
  discount_amount DECIMAL(10,2) NOT NULL DEFAULT 0 COMMENT '优惠金额',
  purchase_type VARCHAR(50) NOT NULL DEFAULT 'balance' COMMENT '购买方式（余额/礼品卡等）',
  trade_no VARCHAR(255) NOT NULL UNIQUE COMMENT '订单号',
  status TINYINT DEFAULT 0 COMMENT '状态（0 未支付，1 已支付）',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  paid_at DATETIME COMMENT '支付时间',
  expires_at DATETIME COMMENT '套餐到期时间',
  CONSTRAINT fk_package_purchase_records_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_package_purchase_records_package FOREIGN KEY (package_id) REFERENCES packages (id) ON DELETE CASCADE,
  CONSTRAINT fk_package_purchase_records_coupon FOREIGN KEY (coupon_id) REFERENCES coupons (id) ON DELETE SET NULL,
  INDEX idx_package_purchase_records_user_id (user_id),
  INDEX idx_package_purchase_records_package_id (package_id),
  INDEX idx_package_purchase_records_trade_no (trade_no),
  INDEX idx_package_purchase_records_status (status),
  INDEX idx_package_purchase_records_created_at (created_at),
  INDEX idx_package_purchase_records_paid_at (paid_at),
  INDEX idx_package_purchase_records_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS gift_card_redemptions (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '礼品卡兑换记录 ID',
  card_id BIGINT NOT NULL COMMENT '礼品卡 ID',
  user_id BIGINT NOT NULL COMMENT '用户 ID',
  code VARCHAR(255) NOT NULL COMMENT '兑换时输入的卡密',
  card_type VARCHAR(50) NOT NULL COMMENT '礼品卡类型',
  change_amount DECIMAL(10,2) COMMENT '变动金额（余额或优惠金额）',
  duration_days INT COMMENT '增加的时长（天）',
  traffic_value_gb INT COMMENT '增加的流量（GB）',
  reset_traffic_gb INT COMMENT '重置后的流量（GB）',
  package_id BIGINT COMMENT '关联套餐 ID',
  recharge_record_id BIGINT COMMENT '关联充值记录 ID',
  purchase_record_id BIGINT COMMENT '关联套餐购买记录 ID',
  trade_no VARCHAR(255) COMMENT '生成的交易号',
  result_status VARCHAR(50) NOT NULL DEFAULT 'success' COMMENT '兑换结果状态',
  message TEXT COMMENT '结果说明',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  CONSTRAINT fk_gift_card_redemptions_card FOREIGN KEY (card_id) REFERENCES gift_cards (id) ON DELETE CASCADE,
  CONSTRAINT fk_gift_card_redemptions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_gift_card_redemptions_recharge FOREIGN KEY (recharge_record_id) REFERENCES recharge_records (id) ON DELETE SET NULL,
  CONSTRAINT fk_gift_card_redemptions_purchase FOREIGN KEY (purchase_record_id) REFERENCES package_purchase_records (id) ON DELETE SET NULL,
  INDEX idx_gift_card_redemptions_card_id (card_id),
  INDEX idx_gift_card_redemptions_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tickets (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '工单 ID',
  user_id BIGINT NOT NULL COMMENT '提交工单的用户 ID',
  title TEXT NOT NULL COMMENT '工单标题',
  content TEXT NOT NULL COMMENT '工单内容',
  status VARCHAR(50) NOT NULL DEFAULT 'open' COMMENT '工单状态（open/closed 等）',
  last_reply_by_admin_id BIGINT COMMENT '最后回复的管理员 ID',
  last_reply_at DATETIME COMMENT '最后回复时间',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  CONSTRAINT fk_tickets_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_tickets_admin FOREIGN KEY (last_reply_by_admin_id) REFERENCES users (id) ON DELETE SET NULL,
  INDEX idx_tickets_user_id (user_id),
  INDEX idx_tickets_status (status),
  INDEX idx_tickets_last_reply_at (last_reply_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ticket_replies (
  id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '工单回复 ID',
  ticket_id BIGINT NOT NULL COMMENT '工单 ID',
  author_id BIGINT NOT NULL COMMENT '回复人用户 ID',
  author_role VARCHAR(10) NOT NULL COMMENT '回复人角色（user/admin）',
  content TEXT NOT NULL COMMENT '回复内容',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  CONSTRAINT fk_ticket_replies_ticket FOREIGN KEY (ticket_id) REFERENCES tickets (id) ON DELETE CASCADE,
  CONSTRAINT fk_ticket_replies_author FOREIGN KEY (author_id) REFERENCES users (id) ON DELETE CASCADE,
  INDEX idx_ticket_replies_ticket_id (ticket_id),
  INDEX idx_ticket_replies_author_role (author_role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 额外索引（若已在表定义中创建则可忽略重复）
CREATE INDEX IF NOT EXISTS idx_users_uuid ON users (uuid);
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

CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes (type);
CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes (status);
CREATE INDEX IF NOT EXISTS idx_nodes_class ON nodes (node_class);

CREATE INDEX IF NOT EXISTS idx_traffic_logs_user_date ON traffic_logs (user_id, date);
CREATE INDEX IF NOT EXISTS idx_traffic_logs_node_date ON traffic_logs (node_id, date);

CREATE INDEX IF NOT EXISTS idx_daily_traffic_user_date ON daily_traffic (user_id, record_date);
CREATE INDEX IF NOT EXISTS idx_daily_traffic_date ON daily_traffic (record_date);
CREATE INDEX IF NOT EXISTS idx_daily_traffic_created ON daily_traffic (created_at);

CREATE INDEX IF NOT EXISTS idx_online_ips_user ON online_ips (user_id);
CREATE INDEX IF NOT EXISTS idx_online_ips_last_seen ON online_ips (last_seen);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at);

CREATE INDEX IF NOT EXISTS idx_node_status_node_time ON node_status (node_id, created_at);

CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions (token);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions (expires_at);

CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys (user_id);
CREATE INDEX IF NOT EXISTS idx_passkeys_rp ON passkeys (rp_id);

CREATE INDEX IF NOT EXISTS idx_announcements_active ON announcements (is_active);
CREATE INDEX IF NOT EXISTS idx_announcements_pinned ON announcements (is_pinned);
CREATE INDEX IF NOT EXISTS idx_announcements_created_at ON announcements (created_at);
CREATE INDEX IF NOT EXISTS idx_announcements_expires_at ON announcements (expires_at);

CREATE INDEX IF NOT EXISTS idx_packages_status ON packages (status);
CREATE INDEX IF NOT EXISTS idx_packages_level ON packages (level);
CREATE INDEX IF NOT EXISTS idx_packages_price ON packages (price);
