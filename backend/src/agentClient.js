import cfg from './config.js';

/**
 * Minimal JSON-RPC style client for talking to the remote agents.
 * The agent exposes POST /rpc with body { method, params } and returns
 * { ok, result } or { ok:false, error }. Auth via Bearer token.
 */
async function callAgent(agent, method, params = {}) {
  const { url, token } = agent;
  if (!url) throw new Error('Agent URL not configured');

  let res;
  try {
    res = await fetch(`${url.replace(/\/$/, '')}/rpc`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ method, params }),
      signal: AbortSignal.timeout(30000),
    });
  } catch (e) {
    throw new Error(`Cannot reach agent at ${url}: ${e.message}`);
  }

  let data;
  const text = await res.text();
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`Agent returned non-JSON (HTTP ${res.status}): ${text.slice(0, 200)}`);
  }

  if (!res.ok || data.ok === false) {
    throw new Error(data.error || `Agent error (HTTP ${res.status})`);
  }
  return data.result;
}

export const openvpnAgent = {
  ping: () => callAgent(cfg.agents.openvpn, 'ping'),
  createUser: (name, expiryDays) =>
    callAgent(cfg.agents.openvpn, 'openvpn.create_user', { name, expiry_days: expiryDays }),
  revokeUser: (name) =>
    callAgent(cfg.agents.openvpn, 'openvpn.revoke_user', { name }),
  setCcd: (name, staticIp, netmask = cfg.vpn.netmask) =>
    callAgent(cfg.agents.openvpn, 'openvpn.set_ccd', {
      name,
      static_ip: staticIp,
      netmask,
    }),
  removeCcd: (name) =>
    callAgent(cfg.agents.openvpn, 'openvpn.remove_ccd', { name }),
  listCerts: () =>
    callAgent(cfg.agents.openvpn, 'openvpn.list_certs'),
  connected: () =>
    callAgent(cfg.agents.openvpn, 'openvpn.connected'),
};

export const proxmoxAgent = {
  ping: () => callAgent(cfg.agents.proxmox, 'ping'),
  // rules: [{ action, dst, proto, port }]
  applyAcl: (vpnIp, rules) =>
    callAgent(cfg.agents.proxmox, 'iptables.apply_acl', { vpn_ip: vpnIp, rules }),
  removeAcl: (vpnIp) =>
    callAgent(cfg.agents.proxmox, 'iptables.remove_acl', { vpn_ip: vpnIp }),
  listAcl: (full = false) =>
    callAgent(cfg.agents.proxmox, 'iptables.list', { full }),
  applyForwards: (forwards) =>
    callAgent(cfg.agents.proxmox, 'iptables.apply_forwards', { forwards }),
  listForwards: () =>
    callAgent(cfg.agents.proxmox, 'iptables.list_forwards'),
};

export { callAgent };
