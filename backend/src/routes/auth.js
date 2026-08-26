import crypto from 'crypto';
import { Router } from 'express';
import { issueCookie, clearCookie, requireAuth } from '../auth.js';
import db, { audit } from '../db.js';
import { verifyPassword } from '../password.js';
import cfg from '../config.js';

const router = Router();

// Public: does the UI show the decoy sign-in? (no secret leaked)
router.get('/config', (req, res) => {
  res.json({ decoy: !!cfg.unlockCode });
});

// Public: check the decoy unlock code server-side. Reveals nothing on failure.
router.post('/unlock', (req, res) => {
  const code = req.body?.code;
  const expected = cfg.unlockCode;
  const ok =
    expected &&
    typeof code === 'string' &&
    code.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(code), Buffer.from(expected));
  if (!ok) return res.status(401).json({ error: 'invalid' });
  res.json({ ok: true });
});

router.post('/login', (req, res) => {
  const { user, password } = req.body || {};
  if (!user || !password) return res.status(400).json({ error: 'Missing credentials' });
  const row = db
    .prepare('SELECT username, pass_hash, role, disabled FROM dashboard_users WHERE username = ?')
    .get(user);
  if (!row || row.disabled || !verifyPassword(password, row.pass_hash)) {
    audit(user, 'login', null, 'failed', false);
    return res.status(401).json({ error: 'Username atau password salah' });
  }
  issueCookie(res, row.username);
  audit(row.username, 'login', null, 'success');
  res.json({ ok: true, user: row.username, role: row.role });
});

router.post('/logout', (req, res) => {
  clearCookie(res);
  res.json({ ok: true });
});

router.get('/me', requireAuth, (req, res) => {
  res.json({ user: req.user, role: req.userRole });
});

export default router;
