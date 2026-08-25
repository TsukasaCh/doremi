import { Router } from 'express';
import db, { audit } from '../db.js';
import { validateRule, repushGroupMembers, applyUserAcl } from './acl.js';

const router = Router();

const NAME_RE = /^[a-zA-Z0-9 _.-]{2,40}$/;

function serializeGroup(g) {
  const rules = db
    .prepare('SELECT id, action, dst, proto, port FROM acl_group_rules WHERE group_id = ? ORDER BY id')
    .all(g.id);
  const members = db
    .prepare('SELECT COUNT(*) AS n FROM user_acl_groups WHERE group_id = ?')
    .get(g.id).n;
  return { ...g, rules, members };
}

// GET /api/groups  — list all groups with rules + member count
router.get('/', (req, res) => {
  const groups = db.prepare('SELECT * FROM acl_groups ORDER BY name').all();
  res.json(groups.map(serializeGroup));
});

// POST /api/groups  — create a group  { name, description? }
router.post('/', (req, res) => {
  const { name, description } = req.body || {};
  if (!NAME_RE.test(name || '')) {
    return res.status(400).json({ error: 'Invalid name (2-40 chars)' });
  }
  if (db.prepare('SELECT 1 FROM acl_groups WHERE name = ?').get(name)) {
    return res.status(409).json({ error: 'Group already exists' });
  }
  const info = db
    .prepare('INSERT INTO acl_groups (name, description) VALUES (?, ?)')
    .run(name, description || null);
  audit(req.user, 'create_group', name);
  const g = db.prepare('SELECT * FROM acl_groups WHERE id = ?').get(info.lastInsertRowid);
  res.status(201).json(serializeGroup(g));
});

// DELETE /api/groups/:id  — delete group; memberships cascade; re-push ex-members
router.delete('/:id', async (req, res) => {
  const g = db.prepare('SELECT * FROM acl_groups WHERE id = ?').get(req.params.id);
  if (!g) return res.status(404).json({ error: 'Not found' });

  // capture members before the cascade removes the links
  const members = db
    .prepare(
      `SELECT u.id FROM user_acl_groups uag JOIN users u ON u.id = uag.user_id
        WHERE uag.group_id = ? AND u.status = 'active' AND u.static_ip IS NOT NULL`
    )
    .all(g.id);

  db.prepare('DELETE FROM acl_groups WHERE id = ?').run(g.id); // cascades

  const errors = [];
  for (const m of members) {
    try { await applyUserAcl(m.id); } catch (e) { errors.push(`user ${m.id}: ${e.message}`); }
  }
  audit(req.user, 'delete_group', g.name, errors.join('; ') || 'ok', errors.length === 0);
  res.json({ ok: true, errors });
});

// POST /api/groups/:id/rules  — add a rule to the group; re-push all members
router.post('/:id/rules', async (req, res) => {
  const g = db.prepare('SELECT * FROM acl_groups WHERE id = ?').get(req.params.id);
  if (!g) return res.status(404).json({ error: 'Not found' });

  let rule;
  try {
    rule = validateRule(req.body);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  db.prepare(
    'INSERT INTO acl_group_rules (group_id, action, dst, proto, port) VALUES (?, ?, ?, ?, ?)'
  ).run(g.id, rule.action, rule.dst, rule.proto, rule.port);

  const errors = await repushGroupMembers(g.id);
  audit(req.user, 'add_group_rule', g.name, `${rule.action} ${rule.dst} ${rule.proto}${rule.port ? ':' + rule.port : ''}`);
  const rules = db.prepare('SELECT * FROM acl_group_rules WHERE group_id = ?').all(g.id);
  res.status(201).json({ rules, warning: errors.length ? errors : undefined });
});

// DELETE /api/groups/:id/rules/:ruleId  — remove a rule; re-push all members
router.delete('/:id/rules/:ruleId', async (req, res) => {
  const g = db.prepare('SELECT * FROM acl_groups WHERE id = ?').get(req.params.id);
  if (!g) return res.status(404).json({ error: 'Not found' });
  const rule = db
    .prepare('SELECT * FROM acl_group_rules WHERE id = ? AND group_id = ?')
    .get(req.params.ruleId, g.id);
  if (!rule) return res.status(404).json({ error: 'Rule not found' });

  db.prepare('DELETE FROM acl_group_rules WHERE id = ?').run(rule.id);
  const errors = await repushGroupMembers(g.id);
  audit(req.user, 'del_group_rule', g.name, `${rule.action} ${rule.dst}`);
  res.json({ ok: true, warning: errors.length ? errors : undefined });
});

export default router;
