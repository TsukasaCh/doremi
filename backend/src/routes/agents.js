import { Router } from 'express';
import db from '../db.js';
import { openvpnAgent, proxmoxAgent } from '../agentClient.js';

const router = Router();

// GET /api/agents/status — health of both agents
router.get('/status', async (req, res) => {
  const out = {};
  for (const [key, agent] of [['openvpn', openvpnAgent], ['proxmox', proxmoxAgent]]) {
    try {
      const r = await agent.ping();
      out[key] = { online: true, ...r };
    } catch (e) {
      out[key] = { online: false, error: e.message };
    }
  }
  res.json(out);
});

// GET /api/agents/iptables — raw iptables ACL view from the Proxmox host
router.get('/iptables', async (req, res) => {
  try {
    const r = await proxmoxAgent.listAcl();
    res.json(r);
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// GET /api/audit — recent audit log
router.get('/audit', (req, res) => {
  const rows = db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 200').all();
  res.json(rows);
});

export default router;
