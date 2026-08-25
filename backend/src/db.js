import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(__dirname, '..', 'data');
fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'openvpn-manager.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT UNIQUE NOT NULL,
  static_ip     TEXT UNIQUE,
  status        TEXT NOT NULL DEFAULT 'active',   -- active | expired | revoked
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at    TEXT,                             -- ISO timestamp, NULL = never
  note          TEXT
);

CREATE TABLE IF NOT EXISTS acl_rules (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  action   TEXT NOT NULL,          -- allow | deny
  dst      TEXT NOT NULL,          -- CIDR or IP, e.g. 10.10.10.0/24 or 0.0.0.0/0
  proto    TEXT NOT NULL DEFAULT 'all',  -- tcp | udp | icmp | all
  port     TEXT,                   -- single port or range, NULL for any/icmp/all
  applied  INTEGER NOT NULL DEFAULT 0    -- 0 = not yet pushed to host, 1 = pushed
);

CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         TEXT NOT NULL DEFAULT (datetime('now')),
  actor      TEXT,
  action     TEXT NOT NULL,
  target     TEXT,
  detail     TEXT,
  ok         INTEGER NOT NULL DEFAULT 1
);
`);

export function audit(actor, action, target, detail, ok = true) {
  db.prepare(
    'INSERT INTO audit_log (actor, action, target, detail, ok) VALUES (?, ?, ?, ?, ?)'
  ).run(actor || 'system', action, target || null, detail || null, ok ? 1 : 0);
}

export default db;
