-- Telegram Bot 注册会话状态表（交互式 /register）
CREATE TABLE IF NOT EXISTS telegram_register_sessions (
  chat_id VARCHAR(64) PRIMARY KEY COMMENT 'Telegram Chat ID',
  stage VARCHAR(32) NOT NULL COMMENT '注册阶段',
  human_code_hash VARCHAR(255) NOT NULL DEFAULT '' COMMENT '人机验证码哈希',
  human_code_expires_at BIGINT NOT NULL DEFAULT 0 COMMENT '人机验证码过期时间戳（秒）',
  human_code_attempts INT NOT NULL DEFAULT 0 COMMENT '人机验证码错误次数',
  email VARCHAR(255) NOT NULL DEFAULT '' COMMENT '待注册邮箱',
  username VARCHAR(255) NOT NULL DEFAULT '' COMMENT '待注册用户名',
  invite_code VARCHAR(255) NOT NULL DEFAULT '' COMMENT '邀请码',
  email_code_attempts INT NOT NULL DEFAULT 0 COMMENT '邮箱验证码错误次数',
  session_expires_at BIGINT NOT NULL COMMENT '会话过期时间戳（秒）',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_tg_register_session_expires
ON telegram_register_sessions (session_expires_at);

CREATE INDEX idx_tg_register_session_stage
ON telegram_register_sessions (stage);
