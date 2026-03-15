#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${1:-/opt/phantom}"

echo "[*] Ensuring service user/groups"
if ! getent group phantom >/dev/null 2>&1; then
  sudo groupadd --system phantom
fi
if ! getent group phantom-admin >/dev/null 2>&1; then
  sudo groupadd --system phantom-admin
fi
if ! getent group phantom-user >/dev/null 2>&1; then
  sudo groupadd --system phantom-user
fi
if ! id phantom >/dev/null 2>&1; then
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin --gid phantom phantom
fi

echo "[*] Preparing runtime directories"
sudo install -d -m 0750 -o phantom -g phantom /var/lib/phantom/traps
sudo install -d -m 0750 -o phantom -g phantom /var/lib/phantom/evidence
sudo install -d -m 0750 -o phantom -g phantom /var/log/phantom
sudo install -d -m 0750 -o root -g phantom /etc/phantom/templates
sudo install -d -m 0750 -o root -g phantom /etc/phantom/keys

if [ ! -f /etc/phantom/secrets.env ]; then
  echo "[*] Creating /etc/phantom/secrets.env template"
  sudo sh -c "cat > /etc/phantom/secrets.env" <<'EOF'
PHANTOM_SIGNING_PASSPHRASE=change-me
PHANTOM_API_KEY_ADMIN=change-me
PHANTOM_API_KEY_EDITOR=change-me
PHANTOM_API_KEY_VIEWER=change-me
EOF
  sudo chown root:root /etc/phantom/secrets.env
  sudo chmod 0400 /etc/phantom/secrets.env
fi

echo "[*] Installing Python package"
cd "$PROJECT_DIR"
sudo -u phantom PYTHONPATH=src python3 -m pip install -e .

echo "[*] Installing service unit"
sudo cp deploy/phantom.service /etc/systemd/system/phantom.service
sudo systemctl daemon-reload
sudo systemctl enable phantom.service

echo "[+] Setup completed. Start with: sudo systemctl start phantom"
