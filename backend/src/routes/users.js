import { Router } from 'express';
import db, { audit } from '../db.js';
import { openvpnAgent, proxmoxAgent } from '../agentClient.js';
import { allocateStaticIp } from '../ipalloc.js';
import { applyUserAcl } from './acl.js';

const router = Router();

const NAME_RE = /^[a-zA-Z0-9_.-]{2,40}$/;

function serializeUser(u) {
  const rules = db
    .prepare('SELECT id, action, dst, proto, port, applied FROM acl_rules WHERE user_id = ?')
    .all(u.id);
  const groups = db
    .prepare(
      `SELECT g.id, g.name FROM user_acl_groups uag
         JOIN acl_groups g ON g.id = uag.group_id
        WHERE uag.user_id = ? ORDER BY g.name`
    )
    .all(u.id);
  // Never send the raw .ovpn (contains the private key) in list/detail payloads;
  // expose only whether one is stored. It's fetched on demand via /:id/ovpn.
  const { ovpn, ...rest } = u;
  return { ...rest, acl: rules, groups, has_ovpn: !!ovpn };
}

// GET /api/users  — list all users with their ACL
router.get('/', (req, res) => {
  const users = db.prepare('SELECT * FROM users ORDER BY created_at DESC').all();
  res.json(users.map(serializeUser));
});

// POST /api/users  — create a new OpenVPN user
// body: { name, expiryDays?, note? }
router.post('/', async (req, res) => {
  const { name, expiryDays, note } = req.body || {};
  if (!NAME_RE.test(name || '')) {
    return res.status(400).json({ error: 'Invalid name (2-40 chars: letters, digits, . _ -)' });
  }
  const exists = db.prepare('SELECT 1 FROM users WHERE name = ?').get(name);
  if (exists) return res.status(409).json({ error: 'User already exists' });

  const days = expiryDays ? parseInt(expiryDays, 10) : null;
  let staticIp;
  try {
    staticIp = allocateStaticIp();
  } catch (e) {
    return res.status(507).json({ error: e.message });
  }

  let ovpn;
  try {
    // 1) generate cert/key + .ovpn on the OpenVPN host
    const r = await openvpnAgent.createUser(name, days);
    ovpn = r.ovpn;
    // 2) pin a static IP for this user via client-config-dir
    await openvpnAgent.setCcd(name, staticIp);
  } catch (e) {
    audit(req.user, 'create_user', name, e.message, false);
    return res.status(502).json({ error: `OpenVPN agent: ${e.message}` });
  }

  const expiresAt = days
    ? new Date(Date.now() + days * 86400000).toISOString()
    : null;

  const info = db
    .prepare(
      'INSERT INTO users (name, static_ip, expires_at, note, ovpn) VALUES (?, ?, ?, ?, ?)'
    )
    .run(name, staticIp, expiresAt, note || null, ovpn || null);

  audit(req.user, 'create_user', name, `ip=${staticIp} expires=${expiresAt || 'never'}`);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
  // .ovpn is returned once here so the admin can download/hand it to the user
  res.status(201).json({ user: serializeUser(user), ovpn });
});

// GET /api/users/:id/ovpn  — re-download the stored .ovpn config
router.get('/:id/ovpn', (req, res) => {
  const u = db.prepare('SELECT name, ovpn FROM users WHERE id = ?').get(req.params.id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  if (!u.ovpn) {
    return res.status(404).json({
      error: 'Config tidak tersimpan untuk user ini (dibuat sebelum fitur ini). Buat ulang user untuk config yang bisa diunduh.',
    });
  }
  res.json({ name: u.name, ovpn: u.ovpn });
});

router.get('/:id', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  res.json(serializeUser(u));
});

// PATCH /api/users/:id  — renew / change expiry or note
// body: { expiryDays? (from now), note? }
router.patch('/:id', async (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!u) return res.status(404).json({ error: 'Not found' });

  const { expiryDays, note } = req.body || {};
  let expiresAt = u.expires_at;
  if (expiryDays !== undefined) {
    const days = expiryDays === null ? null : parseInt(expiryDays, 10);
    expiresAt = days ? new Date(Date.now() + days * 86400000).toISOString() : null;
  }
  const newStatus = u.status === 'expired' && expiresAt && new Date(expiresAt) > new Date()
    ? 'active'
    : u.status;

  db.prepare('UPDATE users SET expires_at = ?, note = ?, status = ? WHERE id = ?')
    .run(expiresAt, note ?? u.note, newStatus, u.id);

  // If user was expired and is being re-activated, re-apply ACL & CCD
  if (u.status === 'expired' && newStatus === 'active') {
    try {
      await openvpnAgent.setCcd(u.name, u.static_ip);
      await applyUserAcl(u.id);
    } catch (e) {
      return res.status(502).json({ error: `Re-activate failed: ${e.message}` });
    }
  }

  audit(req.user, 'update_user', u.name, `expires=${expiresAt || 'never'} status=${newStatus}`);
  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(u.id);
  res.json(serializeUser(updated));
});

// DELETE /api/users/:id  — revoke cert, drop CCD + iptables ACL, remove record
router.delete('/:id', async (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!u) return res.status(404).json({ error: 'Not found' });

  const errors = [];
  try { await openvpnAgent.revokeUser(u.name); } catch (e) { errors.push(`revoke: ${e.message}`); }
  try { await openvpnAgent.removeCcd(u.name); } catch (e) { errors.push(`ccd: ${e.message}`); }
  if (u.static_ip) {
    try { await proxmoxAgent.removeAcl(u.static_ip); } catch (e) { errors.push(`iptables: ${e.message}`); }
  }

  db.prepare('DELETE FROM users WHERE id = ?').run(u.id); // cascades to acl_rules
  audit(req.user, 'delete_user', u.name, errors.length ? errors.join('; ') : 'ok', errors.length === 0);

  if (errors.length) {
    return res.status(207).json({ ok: true, warning: 'Removed from DB but agent steps had errors', errors });
  }
  res.json({ ok: true });
});

export default router;
