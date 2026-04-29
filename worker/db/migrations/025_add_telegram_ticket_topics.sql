-- Telegram 工单转发：工单与论坛话题映射
CREATE TABLE IF NOT EXISTS ticket_telegram_topics (
  ticket_id INTEGER PRIMARY KEY,
  group_chat_id TEXT NOT NULL,
  message_thread_id INTEGER NOT NULL,
  topic_message_id INTEGER,
  created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
  updated_at DATETIME DEFAULT (datetime('now', '+8 hours')),
  FOREIGN KEY (ticket_id) REFERENCES tickets (id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ticket_tg_topics_group_thread
ON ticket_telegram_topics (group_chat_id, message_thread_id);

INSERT OR IGNORE INTO system_configs (key, value, description)
VALUES ('telegram_ticket_group_id', '', 'Telegram 工单转发群组 ID（需开启论坛话题）');
