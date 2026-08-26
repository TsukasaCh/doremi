import { Router } from 'express';
import db, { audit } from '../db.js';
import { hashPassword } from '../password.js';

const router = Router();

const ROLES = new Set(['admin', 'operator', 'viewer']);
const NAME_RE = /^[a-zA-Z0-9_.-]{2,32}$/;

function serialize(u) {
  return { id: u.id, username: u.username, role: u.role, disabled: !!u.disabled, is_owner: !!u.is_owner, created_at: u.created_at };
}
function adminCount() {
  return db.prepare("SELECT COUNT(*) AS n FROM dashboard_users WHERE role = 'admin' AND disabled = 0").get().n;
}

// GET /api/admins — list dashboard users (no hashes)
router.get('/', (req, res) => {
  const rows = db.prepare('SELECT * FROM dashboard_users ORDER BY username').all();
  res.json(rows.map(serialize));
});

// POST /api/admins — create { username, password, role }
router.post('/', (req, res) => {
  const { username, password, role = 'operator' } = req.body || {};
  if (!NAME_RE.test(username || '')) return res.status(400).json({ error: 'Username tidak valid (2-32: huruf, angka, . _ -)' });
  if (!password || String(password).length < 6) return res.status(400).json({ error: 'Password minimal 6 karakter' });
  if (!ROLES.has(role)) return res.status(400).json({ error: 'Role harus admin|operator|viewer' });
  if (db.prepare('SELECT 1 FROM dashboard_users WHERE username = ?').get(username))
    return res.status(409).json({ error: 'Username sudah ada' });

  const info = db.prepare('INSERT INTO dashboard_users (username, pass_hash, role) VALUES (?, ?, ?)')
    .run(username, hashPassword(password), role);
  audit(req.user, 'iam_create', username, `role=${role}`);
  res.status(201).json(serialize(db.prepare('SELECT * FROM dashboard_users WHERE id = ?').get(info.lastInsertRowid)));
});

// PATCH /api/admins/:id — { role?, password?, disabled? }
router.patch('/:id', (req, res) => {
  const u = db.prepare('SELECT * FROM dashboard_users WHERE id = ?').get(req.params.id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  const { role, password, disabled } = req.body || {};

  // Owner protection: only the owner may touch the owner account, and even then
  // their role/enabled status is locked (owner stays admin & active).
  if (u.is_owner) {
    if (req.userId !== u.id)
      return res.status(403).json({ error: 'Akun owner tidak bisa diubah oleh admin lain' });
    if ((role !== undefined && role !== 'admin') || disabled === true)
      return res.status(400).json({ error: 'Owner tidak bisa diturunkan atau dinonaktifkan' });
  }

  // Guard against locking everyone out of admin.
  const losingAdmin = u.role === 'admin' && !u.disabled &&
    ((role && role !== 'admin') || disabled === true);
  if (losingAdmin && adminCount() <= 1)
    return res.status(400).json({ error: 'Tidak bisa menonaktifkan/menurunkan admin terakhir' });

  if (role !== undefined) {
    if (!ROLES.has(role)) return res.status(400).json({ error: 'Role tidak valid' });
    db.prepare('UPDATE dashboard_users SET role = ? WHERE id = ?').run(role, u.id);
  }
  if (password !== undefined) {
    if (String(password).length < 6) return res.status(400).json({ error: 'Password minimal 6 karakter' });
    db.prepare('UPDATE dashboard_users SET pass_hash = ? WHERE id = ?').run(hashPassword(password), u.id);
  }
  if (disabled !== undefined) {
    db.prepare('UPDATE dashboard_users SET disabled = ? WHERE id = ?').run(disabled ? 1 : 0, u.id);
  }
  audit(req.user, 'iam_update', u.username,
    [role && `role=${role}`, password !== undefined && 'password reset', disabled !== undefined && `disabled=${!!disabled}`].filter(Boolean).join(', '));
  res.json(serialize(db.prepare('SELECT * FROM dashboard_users WHERE id = ?').get(u.id)));
});

// DELETE /api/admins/:id
router.delete('/:id', (req, res) => {
  const u = db.prepare('SELECT * FROM dashboard_users WHERE id = ?').get(req.params.id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  if (u.is_owner) return res.status(403).json({ error: 'Akun owner tidak bisa dihapus' });
  if (u.id === req.userId) return res.status(400).json({ error: 'Tidak bisa menghapus akun sendiri' });
  if (u.role === 'admin' && !u.disabled && adminCount() <= 1)
    return res.status(400).json({ error: 'Tidak bisa menghapus admin terakhir' });
  db.prepare('DELETE FROM dashboard_users WHERE id = ?').run(u.id);
  audit(req.user, 'iam_delete', u.username);
  res.json({ ok: true });
});

export default router;
