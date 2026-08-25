#!/usr/bin/env bash
# One-shot deploy of the dashboard on a fresh VM (e.g. 10.10.10.110) using Docker.
# Run this ON the VM:
#     curl -fsSL https://raw.githubusercontent.com/TsukasaCh/doremi/main/deploy/deploy-vm.sh | bash
# ...or clone the repo first and run  bash deploy/deploy-vm.sh
set -euo pipefail

REPO="https://github.com/TsukasaCh/doremi.git"
DIR="${DEPLOY_DIR:-$HOME/doremi}"

echo "==> OpenVPN Manager :: VM deploy"

# 1) Docker present?
if ! command -v docker >/dev/null 2>&1; then
  echo "==> Docker not found. Installing via official script..."
  curl -fsSL https://get.docker.com | sh
  sudo usermod -aG docker "$USER" || true
  echo "   (log out/in later so your user can run docker without sudo)"
fi
DC="docker compose"
docker compose version >/dev/null 2>&1 || DC="sudo docker compose"

# 2) Get / update the code
if [ -d "$DIR/.git" ]; then
  echo "==> Updating existing checkout in $DIR"
  git -C "$DIR" pull --ff-only
else
  echo "==> Cloning into $DIR"
  git clone "$REPO" "$DIR"
fi
cd "$DIR"

# 3) Environment file — on first run we stop so you can edit it.
#    (No interactive editor here: this script is often run via `curl | bash`,
#    where stdin is the pipe, so a prompt/nano cannot read the keyboard.)
if [ ! -f backend/.env ]; then
  cp backend/.env.example backend/.env
  echo
  echo "!!  Created backend/.env from the example. EDIT IT before starting:"
  echo "      - ADMIN_PASSWORD, SESSION_SECRET"
  echo "      - OPENVPN_AGENT_URL/TOKEN  (http://10.10.10.101:9000)"
  echo "      - PROXMOX_AGENT_URL/TOKEN  (http://10.10.10.1:9000)"
  echo "      - keep PORT=8080"
  echo
  echo "    Next:"
  echo "      nano $DIR/backend/.env"
  echo "      cd $DIR && $DC up -d --build"
  echo
  echo "==> Stopping here so you can edit the config first."
  exit 0
fi

# 4) Build & run
echo "==> Building and starting the container"
$DC up -d --build

echo
echo "==> Done. Dashboard: http://$(hostname -I | awk '{print $1}'):8080"
echo "    Logs:   $DC logs -f"
echo "    Update: git pull && $DC up -d --build"
