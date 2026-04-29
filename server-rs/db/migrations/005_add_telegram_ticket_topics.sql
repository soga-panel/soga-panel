-- Telegram 工单转发：工单与论坛话题映射
CREATE TABLE IF NOT EXISTS ticket_telegram_topics (
  ticket_id BIGINT NOT NULL COMMENT '工单 ID',
  group_chat_id VARCHAR(64) NOT NULL COMMENT 'Telegram 论坛群组 Chat ID',
  message_thread_id BIGINT NOT NULL COMMENT 'Telegram 论坛话题 Thread ID',
  topic_message_id BIGINT COMMENT '创建话题时的消息 ID（可选）',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  CONSTRAINT fk_ticket_tg_topics_ticket FOREIGN KEY (ticket_id) REFERENCES tickets (id) ON DELETE CASCADE,
  UNIQUE KEY uk_ticket_tg_topics_ticket (ticket_id),
  UNIQUE KEY uk_ticket_tg_topics_group_thread (group_chat_id, message_thread_id),
  INDEX idx_ticket_tg_topics_thread (message_thread_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO system_configs (`key`, value, description) VALUES
('telegram_ticket_group_id', '', 'Telegram 工单转发群组 ID（需开启论坛话题）');
