#!/usr/bin/env bash
# enable_bpf_lsm.sh — Enable BPF LSM in GRUB and reboot.
#
# BPF LSM allows Phantom to block file access in-kernel via
# LSM_PROBE(file_open) — the core blocking mechanism.
#
# Requirements:
#   - Kernel >= 5.7 with CONFIG_BPF_LSM=y
#   - Root privileges
#
# Usage:
#   sudo ./deploy/scripts/enable_bpf_lsm.sh
#   sudo ./deploy/scripts/enable_bpf_lsm.sh --no-reboot   # just configure
#   sudo ./deploy/scripts/enable_bpf_lsm.sh --check        # check status only

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*"; }

check_status() {
    echo "=== BPF LSM Status ==="

    # Kernel version
    local kver
    kver=$(uname -r)
    echo "Kernel: $kver"

    local major minor
    major=$(echo "$kver" | cut -d. -f1)
    minor=$(echo "$kver" | cut -d. -f2)
    if [ "$major" -gt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -ge 7 ]; }; then
        info "Kernel version OK (>= 5.7)"
    else
        error "Kernel version too old (need >= 5.7)"
    fi

    # CONFIG_BPF_LSM
    local config_file="/boot/config-$kver"
    if [ -f "$config_file" ]; then
        if grep -q "CONFIG_BPF_LSM=y" "$config_file"; then
            info "CONFIG_BPF_LSM=y (compiled in)"
        else
            error "CONFIG_BPF_LSM not enabled in kernel config"
        fi
    else
        warn "Cannot check kernel config ($config_file not found)"
    fi

    # Current LSM list
    local lsm_file="/sys/kernel/security/lsm"
    if [ -f "$lsm_file" ]; then
        local current_lsm
        current_lsm=$(cat "$lsm_file")
        echo "Current LSM: $current_lsm"
        if echo "$current_lsm" | grep -q "bpf"; then
            info "BPF LSM is ACTIVE"
        else
            warn "BPF LSM is NOT in the active LSM list"
            echo "    Need to add 'bpf' to kernel cmdline: lsm=${current_lsm},bpf"
        fi
    else
        error "securityfs not mounted"
    fi

    # BCC
    if python3 -c "import bcc" 2>/dev/null; then
        info "BCC (python3-bpfcc) is installed"
    else
        warn "BCC not found. Install: sudo apt install python3-bpfcc"
    fi

    echo "=== End ==="
}

enable_bpf_lsm() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This script must be run as root (sudo)"
        exit 1
    fi

    local grub_file="/etc/default/grub"
    if [ ! -f "$grub_file" ]; then
        error "GRUB config not found: $grub_file"
        exit 1
    fi

    # Read current LSM list
    local current_lsm=""
    if [ -f "/sys/kernel/security/lsm" ]; then
        current_lsm=$(cat /sys/kernel/security/lsm)
    fi

    if echo "$current_lsm" | grep -q "bpf"; then
        info "BPF LSM is already active. Nothing to do."
        exit 0
    fi

    # Build new LSM string
    local new_lsm
    if [ -n "$current_lsm" ]; then
        new_lsm="${current_lsm},bpf"
    else
        new_lsm="lockdown,capability,landlock,yama,apparmor,bpf"
    fi

    info "Adding lsm=${new_lsm} to GRUB config..."

    # Backup
    cp "$grub_file" "${grub_file}.bak.$(date +%s)"
    info "Backup saved: ${grub_file}.bak.*"

    # Check if lsm= already in cmdline
    if grep -q 'lsm=' "$grub_file"; then
        # Replace existing lsm= parameter
        sed -i "s/lsm=[^ \"']*/lsm=${new_lsm}/" "$grub_file"
    else
        # Append lsm= to GRUB_CMDLINE_LINUX_DEFAULT
        sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT=\"\(.*\)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\1 lsm=${new_lsm}\"/" "$grub_file"
    fi

    info "Running update-grub..."
    update-grub 2>&1

    info "GRUB updated. New LSM list: ${new_lsm}"

    if [ "${1:-}" = "--no-reboot" ]; then
        warn "Reboot required to activate BPF LSM."
        warn "Run: sudo reboot"
    else
        warn "Rebooting in 5 seconds to activate BPF LSM..."
        warn "Press Ctrl+C to cancel."
        sleep 5
        reboot
    fi
}

# Install BCC if needed
install_bcc() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This script must be run as root (sudo)"
        exit 1
    fi

    if python3 -c "import bcc" 2>/dev/null; then
        info "BCC already installed"
        return
    fi

    info "Installing BCC (python3-bpfcc)..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get install -y python3-bpfcc bpfcc-tools linux-headers-"$(uname -r)"
    elif command -v dnf &>/dev/null; then
        dnf install -y python3-bcc bcc-tools kernel-devel-"$(uname -r)"
    elif command -v pacman &>/dev/null; then
        pacman -S --noconfirm python-bcc bcc linux-headers
    else
        error "Unknown package manager. Install BCC manually."
        exit 1
    fi
    info "BCC installed successfully"
}

case "${1:-}" in
    --check)
        check_status
        ;;
    --install-bcc)
        install_bcc
        ;;
    --no-reboot)
        enable_bpf_lsm --no-reboot
        ;;
    --help|-h)
        echo "Usage: sudo $0 [--check|--no-reboot|--install-bcc|--help]"
        echo ""
        echo "  (no args)     Enable BPF LSM and reboot"
        echo "  --no-reboot   Enable BPF LSM without reboot"
        echo "  --check       Check BPF LSM status"
        echo "  --install-bcc Install BCC (python3-bpfcc)"
        echo "  --help        Show this help"
        ;;
    *)
        enable_bpf_lsm
        ;;
esac
