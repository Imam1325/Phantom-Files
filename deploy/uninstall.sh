#!/usr/bin/env bash
set -euo pipefail

echo "[*] Stopping phantom service"
sudo systemctl stop phantom.service || true
sudo systemctl disable phantom.service || true

echo "[*] Removing service unit"
sudo rm -f /etc/systemd/system/phantom.service
sudo systemctl daemon-reload

echo "[*] Keeping runtime data by default"
echo "[+] Uninstall complete"

