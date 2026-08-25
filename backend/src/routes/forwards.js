import { Router } from 'express';
import db, { audit } from '../db.js';
import { proxmoxAgent } from '../agentClient.js';

const router = Router();
const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

function allForwards() {
  return db.prepare('SELECT * FROM port_forwards ORDER BY public_port').all();
}

// Push the full managed forward set to the Proxmox agent (atomic replace).
export async function applyForwards() {
  await proxmoxAgent.applyForwards(allForwards());
}

// GET /api/forwards
router.get('/', (req, res) => res.json(allForwards()));

// POST /api/forwards  { label?, proto, public_port, dest_ip, dest_port }
router.post('/', async (req, res) => {
  let { label, proto = 'tcp', public_port, dest_ip, dest_port } = req.body || {};
  proto = (proto || 'tcp').toLowerCase();
  const pub = parseInt(public_port, 10);
  const dp = parseInt(dest_port, 10);
  if (!['tcp', 'udp'].includes(proto)) return res.status(400).json({ error: 'proto must be tcp|udp' });
  if (!(pub >= 1 && pub <= 65535)) return res.status(400).json({ error: 'public_port harus 1-65535' });
  if (!(dp >= 1 && dp <= 65535)) return res.status(400).json({ error: 'dest_port harus 1-65535' });
  if (!IP_RE.test(dest_ip || '')) return res.status(400).json({ error: 'dest_ip tidak valid' });
  if (db.prepare('SELECT 1 FROM port_forwards WHERE proto = ? AND public_port = ?').get(proto, pub)) {
    return res.status(409).json({ error: `Port publik ${proto}/${pub} sudah dipakai` });
  }

  db.prepare(
    'INSERT INTO port_forwards (label, proto, public_port, dest_ip, dest_port) VALUES (?, ?, ?, ?, ?)'
  ).run(label || null, proto, pub, dest_ip, dp);

  try {
    await applyForwards();
  } catch (e) {
    // roll back the row so DB stays consistent with the host
    db.prepare('DELETE FROM port_forwards WHERE proto = ? AND public_port = ?').run(proto, pub);
    return res.status(502).json({ error: `iptables agent: ${e.message}` });
  }
  audit(req.user, 'add_forward', `${proto}/${pub}`, `→ ${dest_ip}:${dp}`);
  res.status(201).json(allForwards());
});

// DELETE /api/forwards/:id
router.delete('/:id', async (req, res) => {
  const f = db.prepare('SELECT * FROM port_forwards WHERE id = ?').get(req.params.id);
  if (!f) return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM port_forwards WHERE id = ?').run(f.id);
  try {
    await applyForwards();
  } catch (e) {
    return res.status(502).json({ error: `iptables agent: ${e.message}` });
  }
  audit(req.user, 'del_forward', `${f.proto}/${f.public_port}`, `→ ${f.dest_ip}:${f.dest_port}`);
  res.json({ ok: true });
});

export default router;
