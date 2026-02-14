-- 018_update_shared_ids_remote_account_id_to_text.sql
-- 将 shared_ids.remote_account_id 从 INTEGER 改为 TEXT，以支持单个 ID 或 ID 数组（JSON/CSV）

PRAGMA foreign_keys=off;

ALTER TABLE shared_ids RENAME TO shared_ids_old;

CREATE TABLE shared_ids (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    fetch_url TEXT NOT NULL,
    remote_account_id TEXT NOT NULL,
    status INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT (datetime('now', '+8 hours')),
    updated_at DATETIME DEFAULT (datetime('now', '+8 hours'))
);

INSERT INTO shared_ids (id, name, fetch_url, remote_account_id, status, created_at, updated_at)
SELECT id, name, fetch_url, CAST(remote_account_id AS TEXT), status, created_at, updated_at
FROM shared_ids_old;

DROP TABLE shared_ids_old;

DROP INDEX IF EXISTS idx_shared_ids_status;
DROP INDEX IF EXISTS idx_shared_ids_remote_id;

CREATE INDEX IF NOT EXISTS idx_shared_ids_status ON shared_ids (status);
CREATE INDEX IF NOT EXISTS idx_shared_ids_remote_id ON shared_ids (remote_account_id);

PRAGMA foreign_keys=on;
