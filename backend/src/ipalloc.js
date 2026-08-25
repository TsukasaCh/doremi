import db from './db.js';
import cfg from './config.js';

function ipToInt(ip) {
  return ip.split('.').reduce((acc, o) => (acc << 8) + parseInt(o, 10), 0) >>> 0;
}
function intToIp(n) {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/**
 * Allocate the next free static IP inside VPN_SUBNET, starting at poolStart.
 * Uses the users table to know what's already taken.
 */
export function allocateStaticIp() {
  const base = ipToInt(cfg.vpn.subnet);
  // number of addresses in the subnet
  const size = 2 ** (32 - maskBitCount(cfg.vpn.netmask));

  const taken = new Set(
    db.prepare('SELECT static_ip FROM users WHERE static_ip IS NOT NULL')
      .all()
      .map((r) => r.static_ip)
  );

  for (let host = cfg.vpn.poolStart; host < size - 1; host++) {
    const candidate = intToIp(base + host);
    if (!taken.has(candidate)) return candidate;
  }
  throw new Error('No free IP in VPN pool');
}

function maskBitCount(netmask) {
  return netmask
    .split('.')
    .map(Number)
    .reduce((bits, o) => bits + o.toString(2).split('1').length - 1, 0);
}
