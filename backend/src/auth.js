import crypto from 'crypto';
import cfg from './config.js';
import db from './db.js';

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
  if (mac.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected))) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

export function issueCookie(res, user) {
  const token = sign({ user, exp: Date.now() + MAX_AGE_MS });
  res.cookie(COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: cfg.cookieSecure,
    maxAge: MAX_AGE_MS,
  });
}

export function clearCookie(res) {
  res.clearCookie(COOKIE);
}

// Loads the current dashboard user from the signed cookie; rejects if the
// account was removed or disabled since the cookie was issued.
export function requireAuth(req, res, next) {
  const payload = verify(req.cookies?.[COOKIE]);
  if (!payload) return res.status(401).json({ error: 'Not authenticated' });
  const u = db
    .prepare('SELECT id, username, role, disabled FROM dashboard_users WHERE username = ?')
    .get(payload.user);
  if (!u || u.disabled) return res.status(401).json({ error: 'Not authenticated' });
  req.user = u.username;   // string, kept for audit()
  req.userId = u.id;
  req.userRole = u.role;
  next();
}

// Restrict a route to specific roles.
export function requireRole(...roles) {
  return (req, res, next) =>
    roles.includes(req.userRole) ? next() : res.status(403).json({ error: 'Akses ditolak (role tidak cukup)' });
}

// Read for everyone; writes (non-GET) only for admin/operator. Viewers are read-only.
export function writeGuard(req, res, next) {
  if (req.method === 'GET') return next();
  if (req.userRole === 'admin' || req.userRole === 'operator') return next();
  return res.status(403).json({ error: 'Akses ditolak (read-only)' });
}
