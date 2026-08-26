import crypto from 'crypto';

// scrypt password hashing (stdlib only). Format: scrypt$<saltHex>$<hashHex>
export function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const dk = crypto.scryptSync(String(pw), salt, 32);
  return `scrypt$${salt.toString('hex')}$${dk.toString('hex')}`;
}

export function verifyPassword(pw, stored) {
  if (!stored || typeof stored !== 'string') return false;
  const [algo, saltHex, hashHex] = stored.split('$');
  if (algo !== 'scrypt' || !saltHex || !hashHex) return false;
  const dk = crypto.scryptSync(String(pw), Buffer.from(saltHex, 'hex'), 32);
  const expected = Buffer.from(hashHex, 'hex');
  return dk.length === expected.length && crypto.timingSafeEqual(dk, expected);
}
