#!/usr/bin/env python3
"""
OpenVPN Manager - Host Agent
============================
A single-file, stdlib-only agent that the dashboard backend talks to over
HTTP (POST /rpc, Bearer-token auth). One binary runs on both hosts; the
ROLE env var decides which method families are enabled:

  ROLE=openvpn   -> openvpn.*  (cert lifecycle + client-config-dir)  [10.10.10.101]
  ROLE=proxmox   -> iptables.* (per-user ACL chains)                 [10.10.10.1]
  ROLE=both      -> everything

Configuration is read from environment variables (see config.example.env).
Run as root (needs easy-rsa / iptables). Deploy with the systemd unit in deploy/.
"""

import json
import os
import platform
import re
import shlex
import ssl
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.0.0"
STARTED_AT = time.time()

# ---------------------------------------------------------------- config
def env(key, default=None):
    return os.environ.get(key, default)

CONF = {
    "listen_host": env("AGENT_LISTEN", "0.0.0.0"),
    "listen_port": int(env("AGENT_PORT", "9000")),
    "token": env("AGENT_TOKEN", ""),
    "role": env("ROLE", "both"),
    "hostname": env("AGENT_HOSTNAME", os.uname().nodename if hasattr(os, "uname") else "host"),

    # --- OpenVPN ---
    # How the agent creates/revokes clients:
    #   script  -> drive an existing openvpn-install.sh (recommended if you used one)
    #   easyrsa -> call easy-rsa directly
    "openvpn_backend": env("OPENVPN_BACKEND", "easyrsa"),
    "openvpn_install_sh": env("OPENVPN_INSTALL_SH", "/root/openvpn-install.sh"),

    # --- easy-rsa (used only when OPENVPN_BACKEND=easyrsa) ---
    "easyrsa_dir": env("EASYRSA_DIR", "/etc/openvpn/easy-rsa"),
    # PKI location; defaults to <EASYRSA_DIR>/pki but can be pointed elsewhere
    "easyrsa_pki": env("EASYRSA_PKI") or
    os.path.join(env("EASYRSA_DIR", "/etc/openvpn/easy-rsa"), "pki"),
    "openvpn_dir": env("OPENVPN_DIR", "/etc/openvpn"),
    "ccd_dir": env("CCD_DIR", "/etc/openvpn/ccd"),
    "ta_key": env("TA_KEY", "/etc/openvpn/ta.key"),
    "crl_dest": env("CRL_DEST", "/etc/openvpn/crl.pem"),
    "tls_mode": env("TLS_MODE", "tls-crypt"),  # tls-crypt | tls-auth | none
    # .ovpn client template values
    "vpn_remote": env("VPN_REMOTE", "vpn.example.com"),
    "vpn_port": env("VPN_PORT", "1194"),
    "vpn_proto": env("VPN_PROTO", "udp"),
    "vpn_cipher": env("VPN_CIPHER", "AES-256-GCM"),

    # --- iptables ---
    "iptables_bin": env("IPTABLES_BIN", "iptables"),
    "vpn_iface": env("VPN_IFACE", "tun0"),
    "parent_chain": env("PARENT_CHAIN", "VPN_ACL"),
    # where the per-user jump lives: FORWARD (routed traffic through the box)
    "hook_chain": env("HOOK_CHAIN", "FORWARD"),
}

NAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{2,40}$")
IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
CIDR_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")


class RpcError(Exception):
    pass


# ---------------------------------------------------------------- shell
def run(cmd, check=True, input_text=None, cwd=None, extra_env=None):
    """Run a command (list form) and return stdout. Raise RpcError on failure."""
    env = None
    if extra_env:
        env = os.environ.copy()
        env.update(extra_env)
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, input=input_text, timeout=120,
            cwd=cwd, env=env,
        )
    except FileNotFoundError:
        raise RpcError(f"command not found: {cmd[0]}")
    except subprocess.TimeoutExpired:
        raise RpcError(f"command timed out: {' '.join(cmd)}")
    if check and p.returncode != 0:
        raise RpcError(f"`{' '.join(shlex.quote(c) for c in cmd)}` failed: "
                       f"{(p.stderr or p.stdout).strip()[:400]}")
    return p.stdout


def read_file(path):
    with open(path, "r") as f:
        return f.read()


# ================================================================ OpenVPN
def ovpn_easyrsa(*args, days=None):
    ers = os.path.join(CONF["easyrsa_dir"], "easyrsa")
    if not os.path.exists(ers):
        raise RpcError(
            f"easyrsa not found at {ers}. Set EASYRSA_DIR in "
            f"/etc/openvpn-agent.env to the dir holding the 'easyrsa' script and 'pki/'.")
    cmd = [ers, "--batch"]
    if days:
        cmd.append(f"--days={int(days)}")
    cmd += list(args)
    # Run from EASYRSA_DIR and pin the PKI explicitly so easyrsa reads/writes
    # the right pki regardless of the agent's working directory.
    return run(cmd, cwd=CONF["easyrsa_dir"],
               extra_env={"EASYRSA_PKI": CONF["easyrsa_pki"],
                          "EASYRSA_BATCH": "1"})


# ---- backend dispatchers -------------------------------------------------
def _install_sh():
    p = CONF["openvpn_install_sh"]
    if not os.path.exists(p):
        raise RpcError(f"openvpn-install.sh not found at {p}. "
                       f"Set OPENVPN_INSTALL_SH in /etc/openvpn-agent.env.")
    return p


def openvpn_create_user(params):
    if CONF["openvpn_backend"] == "script":
        return _create_user_script(params)
    return _create_user_easyrsa(params)


def openvpn_revoke_user(params):
    if CONF["openvpn_backend"] == "script":
        return _revoke_user_script(params)
    return _revoke_user_easyrsa(params)


def openvpn_list_certs(params):
    if CONF["openvpn_backend"] == "script":
        return _list_certs_script(params)
    return _list_certs_easyrsa(params)


# ---- backend: openvpn-install.sh ----------------------------------------
def _create_user_script(params):
    name = params.get("name", "")
    if not NAME_RE.match(name):
        raise RpcError("invalid name")
    days = params.get("expiry_days")

    out = os.path.join("/tmp", f"{name}.ovpn")
    cmd = [_install_sh(), "client", "add", name, "--output", out]
    if days:
        cmd += ["--cert-days", str(int(days))]
    run(cmd)  # no --password -> nopass client, as the dashboard expects
    if not os.path.exists(out):
        raise RpcError("client added but .ovpn not found at expected path")
    ovpn = read_file(out)
    try:
        os.remove(out)
    except OSError:
        pass
    return {"ovpn": ovpn}


def _revoke_user_script(params):
    name = params.get("name", "")
    if not NAME_RE.match(name):
        raise RpcError("invalid name")
    run([_install_sh(), "client", "revoke", name])
    return {"revoked": name}


def _list_certs_script(_params):
    out = run([_install_sh(), "client", "list"], check=False)
    return {"raw": out}


# ---- backend: easy-rsa ---------------------------------------------------
def _create_user_easyrsa(params):
    name = params.get("name", "")
    if not NAME_RE.match(name):
        raise RpcError("invalid name")
    days = params.get("expiry_days")

    pki = CONF["easyrsa_pki"]
    crt = os.path.join(pki, "issued", f"{name}.crt")
    if os.path.exists(crt):
        raise RpcError("certificate already exists on host")

    # Generate client cert + key without password
    ovpn_easyrsa("build-client-full", name, "nopass", days=days)

    # Assemble inline .ovpn
    ca = read_file(os.path.join(pki, "ca.crt"))
    cert = read_file(crt)
    # extract just the certificate block (easy-rsa .crt has a text header)
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                  cert, re.S)
    cert = m.group(0) if m else cert
    key = read_file(os.path.join(pki, "private", f"{name}.key"))

    tls_block = ""
    if CONF["tls_mode"] in ("tls-crypt", "tls-auth"):
        ta = read_file(CONF["ta_key"])
        tag = "tls-crypt" if CONF["tls_mode"] == "tls-crypt" else "tls-auth"
        tls_block = f"<{tag}>\n{ta.strip()}\n</{tag}>\n"
        if tag == "tls-auth":
            tls_block = "key-direction 1\n" + tls_block

    ovpn = f"""client
dev tun
proto {CONF['vpn_proto']}
remote {CONF['vpn_remote']} {CONF['vpn_port']}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
data-ciphers {CONF['vpn_cipher']}
cipher {CONF['vpn_cipher']}
verb 3
<ca>
{ca.strip()}
</ca>
<cert>
{cert.strip()}
</cert>
<key>
{key.strip()}
</key>
{tls_block}"""
    return {"ovpn": ovpn}


def _revoke_user_easyrsa(params):
    name = params.get("name", "")
    if not NAME_RE.match(name):
        raise RpcError("invalid name")
    ovpn_easyrsa("revoke", name)
    ovpn_easyrsa("gen-crl")
    # publish the fresh CRL where the server reads it
    src = os.path.join(CONF["easyrsa_pki"], "crl.pem")
    if os.path.exists(src):
        run(["install", "-m", "644", src, CONF["crl_dest"]])
    return {"revoked": name}


def _ccd_path(name):
    return os.path.join(CONF["ccd_dir"], name)


def openvpn_set_ccd(params):
    name = params.get("name", "")
    ip = params.get("static_ip", "")
    # netmask follows the VPN subnet (sent by the backend); fall back to /24
    netmask = params.get("netmask") or "255.255.255.0"
    if not NAME_RE.match(name):
        raise RpcError("invalid name")
    if not IP_RE.match(ip):
        raise RpcError("invalid static_ip")
    if not IP_RE.match(netmask):
        raise RpcError("invalid netmask")
    os.makedirs(CONF["ccd_dir"], exist_ok=True)
    with open(_ccd_path(name), "w") as f:
        f.write(f"ifconfig-push {ip} {netmask}\n")
    return {"name": name, "static_ip": ip, "netmask": netmask}


def openvpn_remove_ccd(params):
    name = params.get("name", "")
    if not NAME_RE.match(name):
        raise RpcError("invalid name")
    p = _ccd_path(name)
    if os.path.exists(p):
        os.remove(p)
    return {"removed": name}


def _list_certs_easyrsa(_params):
    idx = os.path.join(CONF["easyrsa_pki"], "index.txt")
    out = []
    if os.path.exists(idx):
        for line in read_file(idx).splitlines():
            parts = line.split("\t")
            if len(parts) >= 6:
                cn = re.search(r"CN=([^/]+)", parts[5])
                out.append({"status": parts[0], "cn": cn.group(1) if cn else parts[5]})
    return {"certs": out}


# ================================================================ iptables
def _chain_for(ip):
    # iptables chain names must be <=29 chars; encode the IP
    return "VACL_" + ip.replace(".", "_")


def _ipt(*args, check=True):
    return run([CONF["iptables_bin"]] + list(args), check=check)


def _ensure_parent():
    parent = CONF["parent_chain"]
    hook = CONF["hook_chain"]
    # create parent chain if it does not exist yet
    exists = subprocess.run([CONF["iptables_bin"], "-nL", parent],
                            capture_output=True)
    if exists.returncode != 0:
        _ipt("-N", parent)
    # make sure the hook chain jumps into it exactly once
    jump = subprocess.run(
        [CONF["iptables_bin"], "-C", hook, "-i", CONF["vpn_iface"], "-j", parent],
        capture_output=True)
    if jump.returncode != 0:
        _ipt("-I", hook, "-i", CONF["vpn_iface"], "-j", parent)


def iptables_apply_acl(params):
    ip = params.get("vpn_ip", "")
    rules = params.get("rules", [])
    if not IP_RE.match(ip):
        raise RpcError("invalid vpn_ip")

    _ensure_parent()
    parent = CONF["parent_chain"]
    chain = _chain_for(ip)

    # (re)create the per-user chain, fresh
    subprocess.run([CONF["iptables_bin"], "-N", chain], capture_output=True)
    _ipt("-F", chain)

    # ensure the parent jumps to this user's chain for its source IP
    exists = subprocess.run(
        [CONF["iptables_bin"], "-C", parent, "-s", ip, "-j", chain],
        capture_output=True)
    if exists.returncode != 0:
        _ipt("-A", parent, "-s", ip, "-j", chain)

    # translate each rule into an iptables append
    for r in rules:
        action = (r.get("action") or "").lower()
        dst = r.get("dst") or ""
        proto = (r.get("proto") or "all").lower()
        port = r.get("port")
        if action not in ("allow", "deny"):
            raise RpcError(f"bad action: {action}")
        if not CIDR_RE.match(dst):
            raise RpcError(f"bad dst: {dst}")
        target = "ACCEPT" if action == "allow" else "DROP"
        cmd = ["-A", chain, "-d", dst]
        if proto in ("tcp", "udp"):
            cmd += ["-p", proto]
            if port:
                if not re.match(r"^\d{1,5}(:\d{1,5})?$", str(port)):
                    raise RpcError(f"bad port: {port}")
                cmd += ["--dport", str(port)]
        elif proto == "icmp":
            cmd += ["-p", "icmp"]
        cmd += ["-j", target]
        _ipt(*cmd)

    # unmatched traffic returns to parent (default policy decided upstream)
    _ipt("-A", chain, "-j", "RETURN")
    _persist()
    return {"vpn_ip": ip, "chain": chain, "rules_applied": len(rules)}


def iptables_remove_acl(params):
    ip = params.get("vpn_ip", "")
    if not IP_RE.match(ip):
        raise RpcError("invalid vpn_ip")
    parent = CONF["parent_chain"]
    chain = _chain_for(ip)
    # remove the jump, then flush + delete the chain
    subprocess.run([CONF["iptables_bin"], "-D", parent, "-s", ip, "-j", chain],
                   capture_output=True)
    subprocess.run([CONF["iptables_bin"], "-F", chain], capture_output=True)
    subprocess.run([CONF["iptables_bin"], "-X", chain], capture_output=True)
    _persist()
    return {"removed": ip}


def _parse_iptables_text(text):
    """Parse `iptables -L -n -v --line-numbers` output into a list of chains,
    each: {name, policy, info, rules:[{num,pkts,bytes,target,prot,opt,in,out,
    source,destination,extra}]}."""
    chains = []
    cur = None
    for line in (text or "").splitlines():
        if line.startswith("Chain "):
            m = re.match(r"^Chain (\S+) \((.*)\)\s*$", line)
            name = m.group(1) if m else line[6:].strip()
            meta = m.group(2) if m else ""
            policy, info = None, meta
            pm = re.match(r"policy (\S+)\s*(.*)", meta)
            if pm:
                policy, info = pm.group(1), pm.group(2)
            cur = {"name": name, "policy": policy, "info": info, "rules": []}
            chains.append(cur)
            continue
        s = line.strip()
        if not s or s.startswith("num ") or s.startswith("pkts ") or s.startswith("target "):
            continue  # header / blank
        if cur is None:
            continue
        parts = line.split(None, 10)
        if len(parts) < 10:
            continue
        cur["rules"].append({
            "num": parts[0], "pkts": parts[1], "bytes": parts[2],
            "target": parts[3], "prot": parts[4], "opt": parts[5],
            "in": parts[6], "out": parts[7],
            "source": parts[8], "destination": parts[9],
            "extra": parts[10] if len(parts) > 10 else "",
        })
    return chains


def _parse_table(table):
    out = _ipt("-t", table, "-L", "-n", "-v", "--line-numbers", check=False)
    return _parse_iptables_text(out)


def iptables_list(params):
    """Return structured chains grouped by table.
      full=False (default): filter (FORWARD + VPN_ACL + per-user) + full nat.
      full=True: every table (filter, nat, mangle, raw), all chains.
    """
    full = bool((params or {}).get("full"))
    names = ["filter", "nat", "mangle", "raw"] if full else ["filter", "nat"]
    tables = []
    for t in names:
        chains = _parse_table(t)
        if not full and t == "filter":
            keep = (CONF["hook_chain"], CONF["parent_chain"])
            chains = [c for c in chains
                      if c["name"] in keep or c["name"].startswith("VACL_")]
        tables.append({"table": t, "chains": chains})
    return {"tables": tables, "full": full}


def _persist():
    """Best-effort persistence so ACLs survive reboot."""
    if os.path.exists("/etc/iptables/rules.v4"):
        try:
            out = run(["iptables-save"])
            with open("/etc/iptables/rules.v4", "w") as f:
                f.write(out)
        except RpcError:
            pass


# ================================================================ dispatch
METHODS_OPENVPN = {
    "openvpn.create_user": openvpn_create_user,
    "openvpn.revoke_user": openvpn_revoke_user,
    "openvpn.set_ccd": openvpn_set_ccd,
    "openvpn.remove_ccd": openvpn_remove_ccd,
    "openvpn.list_certs": openvpn_list_certs,
}
METHODS_IPTABLES = {
    "iptables.apply_acl": iptables_apply_acl,
    "iptables.remove_acl": iptables_remove_acl,
    "iptables.list": iptables_list,
}


def enabled_methods():
    m = {}
    role = CONF["role"]
    if role in ("openvpn", "both"):
        m.update(METHODS_OPENVPN)
    if role in ("proxmox", "both"):
        m.update(METHODS_IPTABLES)
    return m


def dispatch(method, params):
    if method == "ping":
        return {
            "host": CONF["hostname"], "role": CONF["role"], "version": VERSION,
            "methods": sorted(enabled_methods()),
            "uptime_seconds": int(time.time() - STARTED_AT),
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(STARTED_AT)),
            "pid": os.getpid(),
            "python": platform.python_version(),
            "listen": f"{CONF['listen_host']}:{CONF['listen_port']}",
        }
    handler = enabled_methods().get(method)
    if not handler:
        raise RpcError(f"unknown or disabled method: {method}")
    return handler(params or {})


# ---------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        auth = self.headers.get("Authorization", "")
        return CONF["token"] and auth == f"Bearer {CONF['token']}"

    def do_POST(self):
        if self.path != "/rpc":
            return self._send(404, {"ok": False, "error": "not found"})
        if not self._authed():
            return self._send(401, {"ok": False, "error": "unauthorized"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length) or "{}")
            result = dispatch(data.get("method"), data.get("params"))
            self._send(200, {"ok": True, "result": result})
        except RpcError as e:
            self._send(400, {"ok": False, "error": str(e)})
        except Exception as e:  # noqa: BLE001
            self._send(500, {"ok": False, "error": f"internal: {e}"})

    def log_message(self, fmt, *args):
        sys.stderr.write("[agent] " + (fmt % args) + "\n")


def main():
    if not CONF["token"]:
        print("FATAL: AGENT_TOKEN is not set", file=sys.stderr)
        sys.exit(1)
    srv = ThreadingHTTPServer((CONF["listen_host"], CONF["listen_port"]), Handler)
    print(f"[agent] role={CONF['role']} listening on "
          f"{CONF['listen_host']}:{CONF['listen_port']}", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
