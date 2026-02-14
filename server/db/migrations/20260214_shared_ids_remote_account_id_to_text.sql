-- 20260214_shared_ids_remote_account_id_to_text.sql
-- 将 shared_ids.remote_account_id 从 BIGINT 改为 TEXT，以支持单个 ID 或 ID 数组（JSON/CSV）
-- 说明：
-- 1) 先删除旧索引（BIGINT 索引），否则修改为 TEXT 会报 “BLOB/TEXT column used in key specification without a key length”
-- 2) TEXT 索引需使用前缀长度，这里取 255

-- 可选：执行前确认当前字段类型/索引
-- SHOW COLUMNS FROM shared_ids LIKE 'remote_account_id';
-- SHOW INDEX FROM shared_ids WHERE Key_name IN ('idx_shared_ids_remote_id');

ALTER TABLE shared_ids
  DROP INDEX idx_shared_ids_remote_id;

ALTER TABLE shared_ids
  MODIFY COLUMN remote_account_id TEXT NOT NULL COMMENT '远程账号 ID（支持单个ID或ID数组：JSON/CSV）';

CREATE INDEX idx_shared_ids_remote_id ON shared_ids (remote_account_id(255));

