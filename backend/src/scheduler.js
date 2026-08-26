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

// ---- host bandwidth sampler ----
let lastNet = null; // { ts, rx, tx, iface }

async function sampleBandwidth() {
  const agent = cfg.bandwidth.agent === 'openvpn' ? openvpnAgent : proxmoxAgent;
  let s;
  try {
    s = await agent.netStats();
  } catch {
    return; // agent offline; skip this sample
  }
  const iface = cfg.bandwidth.iface || s.default_iface;
  const stat = iface && s.interfaces ? s.interfaces[iface] : null;
  if (!stat) { lastNet = null; return; }

  const cur = { ts: s.time, rx: stat.rx, tx: stat.tx, iface };
  if (lastNet && lastNet.iface === iface && cur.ts > lastNet.ts) {
    const dt = (cur.ts - lastNet.ts) / 1000; // seconds
    // bits per second; guard against counter resets
    const rxBps = Math.max(0, (cur.rx - lastNet.rx)) * 8 / dt;
    const txBps = Math.max(0, (cur.tx - lastNet.tx)) * 8 / dt;
    if (cur.rx >= lastNet.rx && cur.tx >= lastNet.tx) {
      db.prepare('INSERT OR REPLACE INTO bandwidth_samples (ts, rx_bps, tx_bps) VALUES (?, ?, ?)')
        .run(cur.ts, rxBps, txBps);
      const cutoff = Date.now() - cfg.bandwidth.retainHours * 3600 * 1000;
      db.prepare('DELETE FROM bandwidth_samples WHERE ts < ?').run(cutoff);
    }
  }
  lastNet = cur;
}

export function startScheduler() {
  const intervalMs = Math.max(1, cfg.expiryCheckIntervalMin) * 60 * 1000;
  tick().catch(() => {});
  setInterval(() => tick().catch(() => {}), intervalMs);
  console.log(`[scheduler] expiry check every ${cfg.expiryCheckIntervalMin} min`);

  const bwMs = Math.max(5, cfg.bandwidth.sampleSec) * 1000;
  sampleBandwidth().catch(() => {});
  setInterval(() => sampleBandwidth().catch(() => {}), bwMs);
  console.log(`[scheduler] bandwidth sampling every ${cfg.bandwidth.sampleSec}s on ${cfg.bandwidth.agent}`);
}
