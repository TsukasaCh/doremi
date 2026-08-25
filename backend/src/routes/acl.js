import { Router } from 'express';
import db, { audit } from '../db.js';
import { proxmoxAgent } from '../agentClient.js';

const router = Router();

const ACTIONS = new Set(['allow', 'deny']);
const PROTOS = new Set(['tcp', 'udp', 'icmp', 'all']);
const CIDR_RE = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;

/**
 * Push the full ACL for one user to the Proxmox iptables agent.
 * The agent replaces the whole per-user chain atomically, so we always
 * send the complete current rule set.
 */
export async function applyUserAcl(userId) {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user || !user.static_ip) throw new Error('User has no static IP');

  const rules = db
    .prepare('SELECT action, dst, proto, port FROM acl_rules WHERE user_id = ? ORDER BY id')
    .all(userId);

  await proxmoxAgent.applyAcl(user.static_ip, rules);
  db.prepare('UPDATE acl_rules SET applied = 1 WHERE user_id = ?').run(userId);
  return rules;
}

// POST /api/users/:id/acl  — add a rule then push to host
// body: { action, dst, proto?, port? }
router.post('/:id/acl', async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  let { action, dst, proto = 'all', port = null } = req.body || {};
  action = (action || '').toLowerCase();
  proto = (proto || 'all').toLowerCase();

  if (!ACTIONS.has(action)) return res.status(400).json({ error: 'action must be allow|deny' });
  if (!CIDR_RE.test(dst || '')) return res.status(400).json({ error: 'dst must be IP or CIDR' });
  if (!PROTOS.has(proto)) return res.status(400).json({ error: 'proto must be tcp|udp|icmp|all' });
  if (port && !/^\d{1,5}(:\d{1,5})?$/.test(String(port))) {
    return res.status(400).json({ error: 'port must be a number or range n:m' });
  }
  if (port && (proto === 'icmp' || proto === 'all')) port = null; // ports only for tcp/udp

  db.prepare(
    'INSERT INTO acl_rules (user_id, action, dst, proto, port) VALUES (?, ?, ?, ?, ?)'
  ).run(user.id, action, dst, proto, port ? String(port) : null);

  try {
    await applyUserAcl(user.id);
  } catch (e) {
    return res.status(502).json({ error: `iptables agent: ${e.message}` });
  }
  audit(req.user, 'add_acl', user.name, `${action} ${dst} ${proto}${port ? ':' + port : ''}`);
  const rules = db.prepare('SELECT * FROM acl_rules WHERE user_id = ?').all(user.id);
  res.status(201).json({ acl: rules });
});

// DELETE /api/users/:id/acl/:ruleId  — remove a rule then re-push
router.delete('/:id/acl/:ruleId', async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const rule = db
    .prepare('SELECT * FROM acl_rules WHERE id = ? AND user_id = ?')
    .get(req.params.ruleId, user.id);
  if (!rule) return res.status(404).json({ error: 'Rule not found' });

  db.prepare('DELETE FROM acl_rules WHERE id = ?').run(rule.id);
  try {
    await applyUserAcl(user.id);
  } catch (e) {
    return res.status(502).json({ error: `iptables agent: ${e.message}` });
  }
  audit(req.user, 'del_acl', user.name, `${rule.action} ${rule.dst}`);
  res.json({ ok: true });
});

export default router;
