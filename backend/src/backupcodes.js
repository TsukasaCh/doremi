import crypto from 'crypto';
import db from './db.js';

const COUNT = 10;

// Backup codes are high-entropy random, so a fast hash (sha256) is fine.
function norm(code) {
  return String(code || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}
function hash(code) {
  return crypto.createHash('sha256').update(norm(code)).digest('hex');
}

// Generate a fresh set, replacing any existing codes for the user.
// Returns the plaintext codes (shown once).
export function regenerate(userId) {
  db.prepare('DELETE FROM backup_codes WHERE user_id = ?').run(userId);
  const codes = [];
  const insert = db.prepare('INSERT INTO backup_codes (user_id, code_hash) VALUES (?, ?)');
  for (let i = 0; i < COUNT; i++) {
    const raw = crypto.randomBytes(5).toString('hex'); // 10 hex chars
    const code = `${raw.slice(0, 5)}-${raw.slice(5)}`;
    codes.push(code);
    insert.run(userId, hash(code));
  }
  return codes;
}

export function remaining(userId) {
  return db.prepare('SELECT COUNT(*) AS n FROM backup_codes WHERE user_id = ? AND used_at IS NULL')
    .get(userId).n;
}

// Consume one matching unused code; returns true if a code was used.
export function consume(userId, input) {
  const row = db.prepare('SELECT id FROM backup_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL')
    .get(userId, hash(input));
  if (!row) return false;
  db.prepare("UPDATE backup_codes SET used_at = datetime('now') WHERE id = ?").run(row.id);
  return true;
}

export function clear(userId) {
  db.prepare('DELETE FROM backup_codes WHERE user_id = ?').run(userId);
}
