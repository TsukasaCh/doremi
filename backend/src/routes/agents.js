import { Router } from 'express';
import db from '../db.js';
import cfg from '../config.js';
import { openvpnAgent, proxmoxAgent } from '../agentClient.js';

const router = Router();

// GET /api/agents/status — health of both agents
router.get('/status', async (req, res) => {
  const out = {};
  for (const [key, agent] of [['openvpn', openvpnAgent], ['proxmox', proxmoxAgent]]) {
    const url = cfg.agents[key].url;
    try {
      const r = await agent.ping();
      out[key] = { online: true, url, ...r };
    } catch (e) {
      out[key] = { online: false, url, error: e.message };
    }
  }
  res.json(out);
});

// GET /api/agents/connected — clients currently connected to OpenVPN
router.get('/connected', async (req, res) => {
  try {
    res.json(await openvpnAgent.connected());
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// GET /api/agents/iptables[?full=1] — iptables view from the Proxmox host
router.get('/iptables', async (req, res) => {
  try {
    const r = await proxmoxAgent.listAcl(req.query.full === '1');
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
