import crypto from 'crypto';
import cfg from './config.js';

const COOKIE = 'ovpn_session';
const MAX_AGE_MS = 8 * 60 * 60 * 1000; // 8 hours

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', cfg.sessionSecret).update(body).digest('base64url');
  return `${body}.${mac}`;
}

function verify(token) {
  if (!token || !token.includes('.')) return null;
  const [body, mac] = token.split('.');
  const expected = crypto.createHmac('sha256', cfg.sessionSecret).update(body).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected))) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

export function checkLogin(user, password) {
  // Constant-time-ish comparison
  const uOk = user === cfg.adminUser;
  const pOk =
    password.length === cfg.adminPassword.length &&
    crypto.timingSafeEqual(
      Buffer.from(password.padEnd(64)),
      Buffer.from(cfg.adminPassword.padEnd(64))
    );
  return uOk && pOk;
}

export function issueCookie(res, user) {
  const token = sign({ user, exp: Date.now() + MAX_AGE_MS });
  res.cookie(COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: MAX_AGE_MS,
  });
}

export function clearCookie(res) {
  res.clearCookie(COOKIE);
}

export function requireAuth(req, res, next) {
  const payload = verify(req.cookies?.[COOKIE]);
  if (!payload) return res.status(401).json({ error: 'Not authenticated' });
  req.user = payload.user;
  next();
}
