import db, { audit } from './db.js';
import { openvpnAgent, proxmoxAgent } from './agentClient.js';
import { allocateStaticIp } from './ipalloc.js';

export const NAME_RE = /^[a-zA-Z0-9_.-]{2,40}$/;

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

/**
 * Create an OpenVPN user end-to-end: allocate a static IP, mint the cert/.ovpn
 * on the OpenVPN host, pin the IP via CCD, and persist. Shared by the dashboard
 * route and the public API. Throws httpError(status, message) on failure.
 *
 * @returns {Promise<{user: object, ovpn: string}>}
 */
export async function createVpnUser({ name, expiresAt = null, note = null, certDays = null, actor = 'system' }) {
  if (!NAME_RE.test(name || '')) {
    throw httpError(400, 'Invalid name (2-40 chars: letters, digits, . _ -)');
  }
  if (db.prepare('SELECT 1 FROM users WHERE name = ?').get(name)) {
    throw httpError(409, 'User already exists');
  }

  let staticIp;
  try {
    staticIp = allocateStaticIp();
  } catch (e) {
    throw httpError(507, e.message);
  }

  let ovpn;
  try {
    const r = await openvpnAgent.createUser(name, certDays);
    ovpn = r.ovpn;
    await openvpnAgent.setCcd(name, staticIp);
  } catch (e) {
    audit(actor, 'create_user', name, e.message, false);
    throw httpError(502, `OpenVPN agent: ${e.message}`);
  }

  const info = db
    .prepare('INSERT INTO users (name, static_ip, expires_at, note, ovpn) VALUES (?, ?, ?, ?, ?)')
    .run(name, staticIp, expiresAt, note, ovpn || null);
  audit(actor, 'create_user', name, `ip=${staticIp} expires=${expiresAt || 'never'}`);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
  return { user, ovpn };
}

/**
 * Revoke a user's cert, drop their CCD + iptables ACL, and delete the record.
 * Agent errors are collected, not thrown (so a partial teardown still removes
 * the DB row). @returns {Promise<string[]>} list of non-fatal errors.
 */
export async function removeVpnUser(user, actor = 'system') {
  const errors = [];
  try { await openvpnAgent.revokeUser(user.name); } catch (e) { errors.push(`revoke: ${e.message}`); }
  try { await openvpnAgent.removeCcd(user.name); } catch (e) { errors.push(`ccd: ${e.message}`); }
  if (user.static_ip) {
    try { await proxmoxAgent.removeAcl(user.static_ip); } catch (e) { errors.push(`iptables: ${e.message}`); }
  }
  db.prepare('DELETE FROM users WHERE id = ?').run(user.id); // cascades to acl_rules
  audit(actor, 'delete_user', user.name, errors.length ? errors.join('; ') : 'ok', errors.length === 0);
  return errors;
}
