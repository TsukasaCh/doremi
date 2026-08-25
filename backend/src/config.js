import dotenv from 'dotenv';
dotenv.config();

const cfg = {
  port: parseInt(process.env.PORT || '8080', 10),
  adminUser: process.env.ADMIN_USER || 'admin',
  adminPassword: process.env.ADMIN_PASSWORD || 'changeme',
  sessionSecret: process.env.SESSION_SECRET || 'dev-secret-change-me',

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
};

export default cfg;
