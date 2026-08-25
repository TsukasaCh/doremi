import db, { audit } from './db.js';
import { openvpnAgent, proxmoxAgent } from './agentClient.js';
import cfg from './config.js';

/**
 * Periodically finds users whose expires_at has passed and are still active,
 * then revokes their cert and tears down their iptables ACL — automatic expiry.
 */
async function expireUser(u) {
  const errors = [];
  try { await openvpnAgent.revokeUser(u.name); } catch (e) { errors.push(`revoke: ${e.message}`); }
  try { await openvpnAgent.removeCcd(u.name); } catch (e) { errors.push(`ccd: ${e.message}`); }
  if (u.static_ip) {
    try { await proxmoxAgent.removeAcl(u.static_ip); } catch (e) { errors.push(`iptables: ${e.message}`); }
  }
  db.prepare("UPDATE users SET status = 'expired' WHERE id = ?").run(u.id);
  audit('scheduler', 'auto_expire', u.name, errors.length ? errors.join('; ') : 'ok', errors.length === 0);
}

async function tick() {
  const now = new Date().toISOString();
  const due = db
    .prepare("SELECT * FROM users WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= ?")
    .all(now);
  for (const u of due) {
    try {
      await expireUser(u);
      console.log(`[scheduler] expired user ${u.name}`);
    } catch (e) {
      console.error(`[scheduler] failed to expire ${u.name}: ${e.message}`);
    }
  }
}

export function startScheduler() {
  const intervalMs = Math.max(1, cfg.expiryCheckIntervalMin) * 60 * 1000;
  tick().catch(() => {});
  setInterval(() => tick().catch(() => {}), intervalMs);
  console.log(`[scheduler] expiry check every ${cfg.expiryCheckIntervalMin} min`);
}
