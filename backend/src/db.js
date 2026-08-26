import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';
import cfg from './config.js';
import { hashPassword } from './password.js';

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

-- Reusable ACL rule groups (templates applied to many users, kept live)
CREATE TABLE IF NOT EXISTS acl_groups (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT UNIQUE NOT NULL,
  description TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS acl_group_rules (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id INTEGER NOT NULL REFERENCES acl_groups(id) ON DELETE CASCADE,
  action   TEXT NOT NULL,
  dst      TEXT NOT NULL,
  proto    TEXT NOT NULL DEFAULT 'all',
  port     TEXT
);

-- Which groups are assigned to which users (many-to-many)
CREATE TABLE IF NOT EXISTS user_acl_groups (
  user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  group_id INTEGER NOT NULL REFERENCES acl_groups(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, group_id)
);

-- Port-forward (DNAT) rules managed on the Proxmox host
CREATE TABLE IF NOT EXISTS port_forwards (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  label       TEXT,
  proto       TEXT NOT NULL DEFAULT 'tcp',    -- tcp | udp
  public_port INTEGER NOT NULL,
  dest_ip     TEXT NOT NULL,
  dest_port   INTEGER NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (proto, public_port)
);

-- Dashboard user accounts (IAM) — separate from VPN users
CREATE TABLE IF NOT EXISTS dashboard_users (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  username   TEXT UNIQUE NOT NULL,
  pass_hash  TEXT NOT NULL,
  role         TEXT NOT NULL DEFAULT 'operator',  -- admin | operator | viewer
  disabled     INTEGER NOT NULL DEFAULT 0,
  is_owner     INTEGER NOT NULL DEFAULT 0,         -- protected superadmin (only one)
  totp_secret  TEXT,
  totp_enabled INTEGER NOT NULL DEFAULT 0,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

// Migrations for DBs created before these columns existed.
for (const stmt of [
  'ALTER TABLE dashboard_users ADD COLUMN is_owner INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE dashboard_users ADD COLUMN totp_secret TEXT',
  'ALTER TABLE dashboard_users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0',
]) {
  try { db.exec(stmt); } catch { /* column already exists */ }
}

// Seed the first admin from env on a fresh DB (marked as the owner).
const haveUsers = db.prepare('SELECT COUNT(*) AS n FROM dashboard_users').get().n;
if (haveUsers === 0 && cfg.adminUser && cfg.adminPassword) {
  db.prepare('INSERT INTO dashboard_users (username, pass_hash, role, is_owner) VALUES (?, ?, ?, 1)')
    .run(cfg.adminUser, hashPassword(cfg.adminPassword), 'admin');
  console.log(`[db] seeded owner "${cfg.adminUser}" from env`);
}

// Backfill: ensure exactly one owner exists (for DBs seeded before this change).
if (db.prepare('SELECT COUNT(*) AS n FROM dashboard_users WHERE is_owner = 1').get().n === 0) {
  const target =
    db.prepare('SELECT id FROM dashboard_users WHERE username = ?').get(cfg.adminUser) ||
    db.prepare("SELECT id FROM dashboard_users WHERE role = 'admin' ORDER BY id LIMIT 1").get();
  if (target) {
    db.prepare('UPDATE dashboard_users SET is_owner = 1, role = ? WHERE id = ?').run('admin', target.id);
    console.log(`[db] backfilled owner flag on user id ${target.id}`);
  }
}

// --- migrations (idempotent) ---
// Store the generated .ovpn so the admin can re-download it later. The file
// contains the client private key, so the DB now holds secrets — protect the
// DB file / VM accordingly (it's already an admin-only tool).
try {
  db.exec('ALTER TABLE users ADD COLUMN ovpn TEXT');
} catch {
  /* column already exists */
}

export function audit(actor, action, target, detail, ok = true) {
  db.prepare(
    'INSERT INTO audit_log (actor, action, target, detail, ok) VALUES (?, ?, ?, ?, ?)'
  ).run(actor || 'system', action, target || null, detail || null, ok ? 1 : 0);
}

export default db;
