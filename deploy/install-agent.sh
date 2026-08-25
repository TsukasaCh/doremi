#!/usr/bin/env bash
# Install the host agent on a Linux host (OpenVPN server or Proxmox host).
#
# Works two ways:
#   1) From a cloned repo:   sudo bash deploy/install-agent.sh
#   2) Standalone one-liner:  curl -fsSL <raw>/deploy/install-agent.sh | sudo bash
#      (missing files are downloaded from GitHub automatically)
set -euo pipefail

RAW="https://raw.githubusercontent.com/TsukasaCh/doremi/main"
DEST=/opt/openvpn-agent
ENV_FILE=/etc/openvpn-agent.env
SERVICE=/etc/systemd/system/openvpn-agent.service

# Repo root, if we are running from inside a checkout. May be empty/invalid
# when the script was copied out on its own — that's fine, we fall back to RAW.
SELF="$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)"
REPO="$(cd "$SELF/.." 2>/dev/null && pwd || true)"

# get_file <repo-relative-path> <destination> <mode>
# Uses the local repo copy if present, otherwise downloads from GitHub.
get_file() {
  local rel="$1" dst="$2" mode="$3"
  if [[ -n "$REPO" && -f "$REPO/$rel" ]]; then
    install -m "$mode" "$REPO/$rel" "$dst"
  else
    echo "   downloading $rel"
    local tmp; tmp="$(mktemp)"
    curl -fsSL "$RAW/$rel" -o "$tmp"
    install -m "$mode" "$tmp" "$dst"
    rm -f "$tmp"
  fi
}

echo ">> Installing agent to $DEST"
install -d "$DEST"
get_file "agent/agent.py" "$DEST/agent.py" 755

if [[ ! -f "$ENV_FILE" ]]; then
  echo ">> Creating $ENV_FILE from example (EDIT IT before starting!)"
  get_file "agent/config.example.env" "$ENV_FILE" 600
else
  echo ">> $ENV_FILE already exists, leaving it untouched"
fi

echo ">> Installing systemd unit"
get_file "deploy/openvpn-agent.service" "$SERVICE" 644

systemctl daemon-reload
echo
echo "Done. Next steps:"
echo "  1. Edit $ENV_FILE  (set AGENT_TOKEN, ROLE, and the paths for this host)"
echo "  2. systemctl enable --now openvpn-agent"
echo "  3. systemctl status openvpn-agent   # verify it is listening"
