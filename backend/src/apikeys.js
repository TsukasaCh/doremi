import crypto from 'crypto';
import db from './db.js';

const PREFIX = 'ovpnk_';

function sha256(s) {
  return crypto.createHash('sha256').update(String(s)).digest('hex');
}

// Create a new key. The raw value is returned ONCE and never stored in clear.
export function generateKey(name) {
  const raw = PREFIX + crypto.randomBytes(24).toString('base64url');
  const keyPrefix = raw.slice(0, 12);
  const info = db
    .prepare('INSERT INTO api_keys (name, key_prefix, key_hash) VALUES (?, ?, ?)')
    .run(name, keyPrefix, sha256(raw));
  return { id: info.lastInsertRowid, raw, prefix: keyPrefix };
}

export function listKeys() {
  return db
    .prepare('SELECT id, name, key_prefix, disabled, created_at, last_used FROM api_keys ORDER BY id DESC')
    .all()
    .map((k) => ({ ...k, disabled: !!k.disabled }));
}

export function setDisabled(id, disabled) {
  db.prepare('UPDATE api_keys SET disabled = ? WHERE id = ?').run(disabled ? 1 : 0, id);
}

export function deleteKey(id) {
  db.prepare('DELETE FROM api_keys WHERE id = ?').run(id);
}

// Express middleware: authenticate a request by API key (Bearer or X-API-Key).
export function requireApiKey(req, res, next) {
  const hdr = req.headers.authorization || '';
  const key = hdr.startsWith('Bearer ') ? hdr.slice(7) : (req.headers['x-api-key'] || '');
  const row = db.prepare('SELECT * FROM api_keys WHERE key_hash = ? AND disabled = 0').get(sha256(key));
  if (!row) return res.status(401).json({ error: 'Invalid or missing API key' });
  db.prepare("UPDATE api_keys SET last_used = datetime('now') WHERE id = ?").run(row.id);
  req.apiKey = { id: row.id, name: row.name };
  next();
}
