import crypto from 'crypto';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function generateSecret(bytes = 20) {
  const buf = crypto.randomBytes(bytes);
  let bits = '';
  for (const b of buf) bits += b.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i + 5 <= bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5), 2)];
  return out;
}

function base32Decode(s) {
  const clean = s.replace(/=+$/, '').toUpperCase().replace(/\s/g, '');
  let bits = '';
  for (const c of clean) {
    const v = B32.indexOf(c);
    if (v < 0) continue;
    bits += v.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

function hotp(secretBytes, counter) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', secretBytes).update(buf).digest();
  const off = h[h.length - 1] & 0xf;
  const code = ((h[off] & 0x7f) << 24) | ((h[off + 1] & 0xff) << 16) |
               ((h[off + 2] & 0xff) << 8) | (h[off + 3] & 0xff);
  return (code % 1_000_000).toString().padStart(6, '0');
}

// Verify a 6-digit token against a base32 secret, allowing ±window steps of drift.
export function verifyTOTP(token, secretB32, window = 1) {
  const t = String(token || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(t) || !secretB32) return false;
  const secret = base32Decode(secretB32);
  const counter = Math.floor(Date.now() / 1000 / 30);
  for (let e = -window; e <= window; e++) {
    const expected = hotp(secret, counter + e);
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(t))) return true;
  }
  return false;
}

export function otpauthURI(user, secretB32, issuer = 'OpenVPN Manager') {
  const label = encodeURIComponent(`${issuer}:${user}`);
  const params = new URLSearchParams({ secret: secretB32, issuer, digits: '6', period: '30' });
  return `otpauth://totp/${label}?${params.toString()}`;
}
