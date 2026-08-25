#!/usr/bin/env bash
# Install the host agent on a Linux host (OpenVPN server or Proxmox host).
# Usage:  sudo ./install-agent.sh
# Run this ON the target host, from the repo's agent/ + deploy/ files.
set -euo pipefail

DEST=/opt/openvpn-agent
ENV_FILE=/etc/openvpn-agent.env
SERVICE=/etc/systemd/system/openvpn-agent.service
HERE="$(cd "$(dirname "$0")/.." && pwd)"

echo ">> Installing agent to $DEST"
install -d "$DEST"
install -m 755 "$HERE/agent/agent.py" "$DEST/agent.py"

if [[ ! -f "$ENV_FILE" ]]; then
  echo ">> Creating $ENV_FILE from example (EDIT IT before starting!)"
  install -m 600 "$HERE/agent/config.example.env" "$ENV_FILE"
else
  echo ">> $ENV_FILE already exists, leaving it untouched"
fi

echo ">> Installing systemd unit"
install -m 644 "$HERE/deploy/openvpn-agent.service" "$SERVICE"

systemctl daemon-reload
echo
echo "Done. Next steps:"
echo "  1. Edit $ENV_FILE  (set AGENT_TOKEN, ROLE, and the paths for this host)"
echo "  2. systemctl enable --now openvpn-agent"
echo "  3. systemctl status openvpn-agent   # verify it is listening"
