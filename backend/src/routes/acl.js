import { Router } from 'express';
import db, { audit } from '../db.js';
import { proxmoxAgent } from '../agentClient.js';

const router = Router();

const ACTIONS = new Set(['allow', 'deny']);
const PROTOS = new Set(['tcp', 'udp', 'icmp', 'all']);
const CIDR_RE = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;

/**
 * Validate + normalize a rule object. Returns { action, dst, proto, port }
 * or throws Error with a message. Shared by per-user and group rules.
 */
export function validateRule(input) {
  let { action, dst, proto = 'all', port = null } = input || {};
  action = (action || '').toLowerCase();
  proto = (proto || 'all').toLowerCase();
  if (!ACTIONS.has(action)) throw new Error('action must be allow|deny');
  if (!CIDR_RE.test(dst || '')) throw new Error('dst must be IP or CIDR');
  if (!PROTOS.has(proto)) throw new Error('proto must be tcp|udp|icmp|all');
  if (port && !/^\d{1,5}(:\d{1,5})?$/.test(String(port))) {
    throw new Error('port must be a number or range n:m');
  }
  if (port && (proto === 'icmp' || proto === 'all')) port = null; // ports only for tcp/udp
  return { action, dst, proto, port: port ? String(port) : null };
}

/**
 * The effective rule set for a user = their manual rules first, then the rules
 * of every ACL group assigned to them. Manual rules come first so per-user
 * exceptions take precedence (iptables is first-match).
 */
export function effectiveRules(userId) {
  const manual = db
    .prepare('SELECT action, dst, proto, port FROM acl_rules WHERE user_id = ? ORDER BY id')
    .all(userId);
  const groupRules = db
    .prepare(
      `SELECT gr.action, gr.dst, gr.proto, gr.port
         FROM user_acl_groups uag
         JOIN acl_group_rules gr ON gr.group_id = uag.group_id
        WHERE uag.user_id = ?
        ORDER BY uag.group_id, gr.id`
    )
    .all(userId);
  return [...manual, ...groupRules];
}

/**
 * Push the full ACL (manual + groups) for one user to the Proxmox iptables
 * agent. The agent replaces the whole per-user chain atomically.
 */
export async function applyUserAcl(userId) {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user || !user.static_ip) throw new Error('User has no static IP');

  const rules = effectiveRules(userId);
  await proxmoxAgent.applyAcl(user.static_ip, rules);
  db.prepare('UPDATE acl_rules SET applied = 1 WHERE user_id = ?').run(userId);
  return rules;
}

/**
 * Re-push every active user that is assigned a given group. Used when the
 * group's rules change so the change goes live everywhere. Errors per user
 * are collected, not thrown, so one offline host doesn't block the rest.
 */
export async function repushGroupMembers(groupId) {
  const members = db
    .prepare(
      `SELECT u.id FROM user_acl_groups uag
         JOIN users u ON u.id = uag.user_id
        WHERE uag.group_id = ? AND u.status = 'active' AND u.static_ip IS NOT NULL`
    )
    .all(groupId);
  const errors = [];
  for (const m of members) {
    try {
      await applyUserAcl(m.id);
    } catch (e) {
      errors.push(`user ${m.id}: ${e.message}`);
    }
  }
  return errors;
}

// POST /api/users/:id/acl  — add a manual rule then push to host
router.post('/:id/acl', async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  let rule;
  try {
    rule = validateRule(req.body);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  db.prepare(
    'INSERT INTO acl_rules (user_id, action, dst, proto, port) VALUES (?, ?, ?, ?, ?)'
  ).run(user.id, rule.action, rule.dst, rule.proto, rule.port);

  try {
    await applyUserAcl(user.id);
  } catch (e) {
    return res.status(502).json({ error: `iptables agent: ${e.message}` });
  }
  audit(req.user, 'add_acl', user.name, `${rule.action} ${rule.dst} ${rule.proto}${rule.port ? ':' + rule.port : ''}`);
  const rules = db.prepare('SELECT * FROM acl_rules WHERE user_id = ?').all(user.id);
  res.status(201).json({ acl: rules });
});

// DELETE /api/users/:id/acl/:ruleId  — remove a manual rule then re-push
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

// POST /api/users/:id/groups  — assign a group to the user then push
// body: { groupId }
router.post('/:id/groups', async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const groupId = parseInt(req.body?.groupId, 10);
  const group = db.prepare('SELECT * FROM acl_groups WHERE id = ?').get(groupId);
  if (!group) return res.status(404).json({ error: 'Group not found' });

  db.prepare('INSERT OR IGNORE INTO user_acl_groups (user_id, group_id) VALUES (?, ?)')
    .run(user.id, groupId);
  try {
    await applyUserAcl(user.id);
  } catch (e) {
    return res.status(502).json({ error: `iptables agent: ${e.message}` });
  }
  audit(req.user, 'assign_group', user.name, group.name);
  res.status(201).json({ ok: true });
});

// DELETE /api/users/:id/groups/:groupId  — unassign a group then re-push
router.delete('/:id/groups/:groupId', async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  db.prepare('DELETE FROM user_acl_groups WHERE user_id = ? AND group_id = ?')
    .run(user.id, req.params.groupId);
  try {
    await applyUserAcl(user.id);
  } catch (e) {
    return res.status(502).json({ error: `iptables agent: ${e.message}` });
  }
  audit(req.user, 'unassign_group', user.name, `group ${req.params.groupId}`);
  res.json({ ok: true });
});

export default router;
