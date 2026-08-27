import dotenv from 'dotenv';
dotenv.config();

const cfg = {
  port: parseInt(process.env.PORT || '8080', 10),
  adminUser: process.env.ADMIN_USER || 'admin',
  adminPassword: process.env.ADMIN_PASSWORD || 'changeme',
  sessionSecret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  // Optional decoy unlock code. If set, the UI shows a neutral decoy sign-in
  // and only reveals the real login when this exact code is submitted. Checked
  // server-side, so it never ships to the browser. Empty = decoy disabled.
  unlockCode: process.env.UNLOCK_CODE || '',
  // Set true once served over HTTPS (behind a TLS reverse proxy) so session
  // cookies get the Secure flag. Keep false while testing over plain HTTP.
  cookieSecure: /^(1|true|yes)$/i.test(process.env.COOKIE_SECURE || ''),

  agents: {
    openvpn: {
      url: process.env.OPENVPN_AGENT_URL || 'http://10.10.10.101:9000',
      token: process.env.OPENVPN_AGENT_TOKEN || '',
    },
    proxmox: {
      url: process.env.PROXMOX_AGENT_URL || 'http://10.10.10.1:9000',
      token: process.env.PROXMOX_AGENT_TOKEN || '',
    },
  },

  vpn: {
    subnet: process.env.VPN_SUBNET || '10.8.0.0',
    netmask: process.env.VPN_NETMASK || '255.255.255.0',
    poolStart: parseInt(process.env.VPN_POOL_START || '10', 10),
  },

  expiryCheckIntervalMin: parseInt(process.env.EXPIRY_CHECK_INTERVAL_MIN || '15', 10),

  bandwidth: {
    agent: process.env.BANDWIDTH_AGENT || 'proxmox', // which agent's host to measure
    iface: process.env.BANDWIDTH_IFACE || '',        // '' = default-route interface
    sampleSec: parseInt(process.env.BANDWIDTH_SAMPLE_SEC || '20', 10),
    retainHours: parseInt(process.env.BANDWIDTH_RETAIN_HOURS || '6', 10),
  },
};

export default cfg;
