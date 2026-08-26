import crypto from 'crypto';
import { Router } from 'express';
import { issueCookie, clearCookie, requireAuth } from '../auth.js';
import db, { audit } from '../db.js';
import QRCode from 'qrcode';
import { verifyPassword, hashPassword } from '../password.js';
import { generateSecret, verifyTOTP, otpauthURI } from '../totp.js';
import * as backup from '../backupcodes.js';
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
  const { user, password, code } = req.body || {};
  if (!user || !password) return res.status(400).json({ error: 'Missing credentials' });
  const row = db
    .prepare('SELECT id, username, pass_hash, role, disabled, totp_secret, totp_enabled FROM dashboard_users WHERE username = ?')
    .get(user);
  if (!row || row.disabled || !verifyPassword(password, row.pass_hash)) {
    audit(user, 'login', null, 'failed', false);
    return res.status(401).json({ error: 'Username atau password salah' });
  }
  // Second factor: accept a TOTP code OR a one-time backup code.
  if (row.totp_enabled) {
    if (!code) return res.json({ twofa: true }); // password ok, ask for the code
    const okTotp = verifyTOTP(code, row.totp_secret);
    const okBackup = !okTotp && backup.consume(row.id, code);
    if (!okTotp && !okBackup) {
      audit(user, 'login', null, '2fa failed', false);
      return res.status(401).json({ twofa: true, error: 'Kode 2FA / backup salah' });
    }
    if (okBackup) audit(row.username, 'login', null, 'via backup code');
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
  const row = db.prepare('SELECT totp_enabled FROM dashboard_users WHERE id = ?').get(req.userId);
  const twofa = !!row?.totp_enabled;
  res.json({ user: req.user, role: req.userRole, twofa, backupCount: twofa ? backup.remaining(req.userId) : 0 });
});

// --- Own account settings (any signed-in user) ---

// Change own password
router.post('/password', requireAuth, (req, res) => {
  const { current, next } = req.body || {};
  const row = db.prepare('SELECT pass_hash FROM dashboard_users WHERE id = ?').get(req.userId);
  if (!row || !verifyPassword(current, row.pass_hash))
    return res.status(400).json({ error: 'Password saat ini salah' });
  if (!next || String(next).length < 6)
    return res.status(400).json({ error: 'Password baru minimal 6 karakter' });
  db.prepare('UPDATE dashboard_users SET pass_hash = ? WHERE id = ?').run(hashPassword(next), req.userId);
  audit(req.user, 'change_password', req.user);
  res.json({ ok: true });
});

// Begin 2FA enrollment: returns a fresh secret + otpauth URI + QR (SVG)
router.post('/2fa/setup', requireAuth, async (req, res) => {
  const secret = generateSecret();
  const uri = otpauthURI(req.user, secret);
  const qr = await QRCode.toString(uri, { type: 'svg', margin: 1 });
  res.json({ secret, uri, qr });
});

// Enable 2FA after the user proves they can generate a valid code; returns
// one-time backup codes (shown once).
router.post('/2fa/enable', requireAuth, (req, res) => {
  const { secret, code } = req.body || {};
  if (!secret || !verifyTOTP(code, secret))
    return res.status(400).json({ error: 'Kode salah — coba lagi dengan kode terbaru' });
  db.prepare('UPDATE dashboard_users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?').run(secret, req.userId);
  const codes = backup.regenerate(req.userId);
  audit(req.user, '2fa_enable', req.user);
  res.json({ ok: true, backupCodes: codes });
});

// Regenerate backup codes (invalidates old ones). Requires a valid 2FA code.
router.post('/2fa/backup/regenerate', requireAuth, (req, res) => {
  const row = db.prepare('SELECT totp_secret, totp_enabled FROM dashboard_users WHERE id = ?').get(req.userId);
  if (!row?.totp_enabled) return res.status(400).json({ error: '2FA belum aktif' });
  const code = req.body?.code;
  if (!verifyTOTP(code, row.totp_secret) && !backup.consume(req.userId, code))
    return res.status(400).json({ error: 'Kode 2FA / backup salah' });
  const codes = backup.regenerate(req.userId);
  audit(req.user, '2fa_backup_regen', req.user);
  res.json({ ok: true, backupCodes: codes });
});

// Disable 2FA (requires a current code or backup code)
router.post('/2fa/disable', requireAuth, (req, res) => {
  const row = db.prepare('SELECT totp_secret, totp_enabled FROM dashboard_users WHERE id = ?').get(req.userId);
  if (!row?.totp_enabled) return res.json({ ok: true });
  const code = req.body?.code;
  if (!verifyTOTP(code, row.totp_secret) && !backup.consume(req.userId, code))
    return res.status(400).json({ error: 'Kode 2FA / backup salah' });
  db.prepare('UPDATE dashboard_users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?').run(req.userId);
  backup.clear(req.userId);
  audit(req.user, '2fa_disable', req.user);
  res.json({ ok: true });
});

export default router;
