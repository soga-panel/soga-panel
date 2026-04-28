-- Telegram Bot 注册会话状态表
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
);

CREATE INDEX IF NOT EXISTS idx_tg_register_session_expires
ON telegram_register_sessions (session_expires_at);

CREATE INDEX IF NOT EXISTS idx_tg_register_session_stage
ON telegram_register_sessions (stage);
