import { Router } from 'express';
import { checkLogin, issueCookie, clearCookie, requireAuth } from '../auth.js';
import { audit } from '../db.js';

const router = Router();

router.post('/login', (req, res) => {
  const { user, password } = req.body || {};
  if (!user || !password) return res.status(400).json({ error: 'Missing credentials' });
  if (!checkLogin(user, password)) {
    audit(user, 'login', null, 'failed', false);
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  issueCookie(res, user);
  audit(user, 'login', null, 'success');
  res.json({ ok: true, user });
});

router.post('/logout', (req, res) => {
  clearCookie(res);
  res.json({ ok: true });
});

router.get('/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

export default router;
