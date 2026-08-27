import crypto from 'crypto';
import { Router } from 'express';
import db from '../db.js';
import { createVpnUser, removeVpnUser } from '../userService.js';
import { validateRule, applyUserAcl } from './acl.js';

const router = Router();

/**
 * Public provisioning API (API-key auth). Designed for a CTF/SOC-lab platform
 * to mint temporary VPN profiles on demand.
 */

// POST /api/v1/vpn — create a (temporary) VPN profile
// body: { name?, ttl_minutes? | expiry_days?, note?, acl?: [{action,dst,proto?,port?}] }
router.post('/vpn', async (req, res) => {
  let { name, ttl_minutes, expiry_days, note, acl } = req.body || {};

  let expiresAt = null, certDays = null;
  if (ttl_minutes != null) {
    const m = parseInt(ttl_minutes, 10);
    if (!(m > 0)) return res.status(400).json({ error: 'ttl_minutes harus > 0' });
    expiresAt = new Date(Date.now() + m * 60000).toISOString();
    certDays = Math.max(1, Math.ceil(m / 1440));
  } else if (expiry_days != null) {
    const d = parseInt(expiry_days, 10);
    if (!(d > 0)) return res.status(400).json({ error: 'expiry_days harus > 0' });
    expiresAt = new Date(Date.now() + d * 86400000).toISOString();
    certDays = d;
  }

  if (!name) name = 'ctf-' + crypto.randomBytes(4).toString('hex');

  // Validate ACL up-front so we don't create a user then fail on a bad rule.
  let rules = [];
  if (acl !== undefined) {
    if (!Array.isArray(acl)) return res.status(400).json({ error: 'acl harus array' });
    try { rules = acl.map((r) => validateRule(r)); }
    catch (e) { return res.status(400).json({ error: `acl: ${e.message}` }); }
  }

  try {
    const actor = 'api:' + req.apiKey.name;
    const { user, ovpn } = await createVpnUser({
      name, expiresAt, note: note || actor, certDays, actor,
    });

    let aclWarning;
    if (rules.length) {
      const ins = db.prepare('INSERT INTO acl_rules (user_id, action, dst, proto, port) VALUES (?, ?, ?, ?, ?)');
      for (const r of rules) ins.run(user.id, r.action, r.dst, r.proto, r.port);
      try { await applyUserAcl(user.id); }
      catch (e) { aclWarning = `ACL stored but not pushed: ${e.message}`; }
    }

    res.status(201).json({
      name: user.name,
      common_name: user.name,
      static_ip: user.static_ip,
      expires_at: user.expires_at,
      ovpn,
      ...(aclWarning ? { warning: aclWarning } : {}),
    });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

// GET /api/v1/vpn — list profiles (metadata only, no key material)
router.get('/vpn', (req, res) => {
  res.json(db.prepare(
    'SELECT id, name, static_ip, status, created_at, expires_at FROM users ORDER BY created_at DESC'
  ).all());
});

// GET /api/v1/vpn/:name — status of one profile
router.get('/vpn/:name', (req, res) => {
  const u = db.prepare(
    'SELECT id, name, static_ip, status, created_at, expires_at FROM users WHERE name = ?'
  ).get(req.params.name);
  if (!u) return res.status(404).json({ error: 'Not found' });
  res.json(u);
});

// GET /api/v1/vpn/:name/config — fetch the .ovpn again
router.get('/vpn/:name/config', (req, res) => {
  const u = db.prepare('SELECT name, ovpn FROM users WHERE name = ?').get(req.params.name);
  if (!u || !u.ovpn) return res.status(404).json({ error: 'Not found' });
  res.json({ name: u.name, ovpn: u.ovpn });
});

// Revoke + remove a profile by name. DELETE is canonical; POST /revoke is an
// alias for clients that prefer it.
async function revokeByName(req, res) {
  const u = db.prepare('SELECT * FROM users WHERE name = ?').get(req.params.name);
  if (!u) return res.status(404).json({ error: 'Not found' });
  const errors = await removeVpnUser(u, 'api:' + req.apiKey.name);
  res.json({ ok: true, revoked: u.name, ...(errors.length ? { warnings: errors } : {}) });
}
router.delete('/vpn/:name', revokeByName);
router.post('/vpn/:name/revoke', revokeByName);

export default router;
