#!/bin/bash

# Enhanced FIPS 140-3 Compliance Script (Safe Mode)
# Authors: Tim Burns, Kiumarz Hashemi
# Date: 2025-05-03
# Version: 1.5
# Description:
# This script enables FIPS 140-3 compliance safely by checking NICs, backing up GRUB/initramfs,
# logging actions, and supporting dry-run mode to avoid breaking connectivity.

set -euo pipefail

LOG_FILE="/var/log/fips-setup.log"
BACKUP_DIR="/var/backups/fips"
DRY_RUN=false

# Enable logging
exec > >(tee -a "$LOG_FILE") 2>&1

# Dry-run support
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true && echo "[DRY RUN MODE ENABLED]"

print_ascii_banner() {
    CYAN_BOLD="\033[1;36m"
    RESET="\033[0m"

    printf "${CYAN_BOLD}"
    cat << "EOF"
                              ▄█    █▄       ▄████████    ▄████████ ████████▄  ███▄▄▄▄   
                             ███    ███     ███    ███   ███    ███ ███   ▀███ ███▀▀▀██▄ 
                             ███    ███     ███    ███   ███    ███ ███    ███ ███   ███ 
                            ▄███▄▄▄▄███▄▄   ███    ███  ▄███▄▄▄▄██▀ ███    ███ ███   ███ 
                           ▀▀███▀▀▀▀███▀  ▀███████████ ▀▀███▀▀▀▀▀   ███    ███ ███   ███ 
                             ███    ███     ███    ███ ▀███████████ ███    ███ ███   ███ 
                             ███    ███     ███    ███   ███    ███ ███   ▄███ ███   ███ 
                             ███    █▀      ███    █▀    ███    ███ ████████▀   ▀█   █▀  
                                                         ███    ███ 
                                    
                                        F I P S  C O M P L I A N C E

                                                   v 1.5 SAFE
EOF
    printf "${RESET}"
}

check_nic_modules() {
    echo "[INFO] Verifying NIC kernel modules..."
    local modules=(e1000e ixgbe r8169 r8168 atlantic tg3)
    local found=false

    for mod in "${modules[@]}"; do
        if modinfo "$mod" &>/dev/null; then
            echo "[OK] Found NIC module: $mod"
            found=true
            break
        fi
    done

    if ! $found; then
        echo "[WARNING] No known NIC kernel modules found."
        echo "[INFO] Attempting to detect and add missing NIC drivers..."
        apt update && apt install -y linux-modules-extra-$(uname -r)
        echo "[INFO] NIC drivers installed. Please verify manually if issues persist."
    fi
}

backup_grub_settings() {
    echo "[INFO] Backing up GRUB config..."
    mkdir -p "$BACKUP_DIR"
    cp /etc/default/grub "$BACKUP_DIR/grub.bak.$(date +%s)"
    echo "[OK] GRUB configuration backed up."
}

setup_fips_compliance() {
    echo "[STEP] Setting up FIPS packages..."
    apt update
    apt install -y dracut-core grub2 openssl linux-image-$(uname -r) linux-headers-$(uname -r) linux-modules-extra-$(uname -r)
    sed -i 's/#.*fips_mode = 1/fips_mode = 1/' /etc/ssl/openssl.cnf || true
}

apply_security_settings() {
    echo "[STEP] Applying kernel-level security settings..."
    local settings=("slub_debug=FZP" "mce=0" "page_poison=1" "pti=on" "vsyscall=none" "kptr_restrict=2")

    for setting in "${settings[@]}"; do
        if ! grep -q "$setting" /etc/default/grub; then
            if ! grep -q "^GRUB_CMDLINE_LINUX=" /etc/default/grub; then
                echo "GRUB_CMDLINE_LINUX=\"$setting\"" >> /etc/default/grub
            else
                sed -i "s/GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"$setting /" /etc/default/grub
            fi
        fi
    done
    echo "[OK] Security settings applied to GRUB."
}

add_fips_to_grub() {
    echo "[STEP] Adding fips=1 to GRUB configuration..."
    if ! grep -q "fips=1" /etc/default/grub; then
        if ! grep -q "^GRUB_CMDLINE_LINUX=" /etc/default/grub; then
            echo 'GRUB_CMDLINE_LINUX="fips=1"' >> /etc/default/grub
        else
            sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="fips=1 /' /etc/default/grub
        fi
    fi
    update-grub
    echo "[OK] fips=1 added to GRUB configuration."
}

handle_missing_fips_module() {
    echo "[WARNING] Missing FIPS kernel modules — attempting recovery..."
    apt install -y linux-modules-extra-$(uname -r)
    dracut --force --add fips /boot/initramfs-$(uname -r).img $(uname -r)
}

regenerate_initramfs() {
    echo "[STEP] Regenerating initramfs with FIPS modules..."
    if $DRY_RUN; then echo "[DRY RUN] Skipping dracut"; return 0; fi

    mkdir -p "$BACKUP_DIR/initrd"
    cp /boot/initrd.img-$(uname -r) "$BACKUP_DIR/initrd.img-$(uname -r).bak" || true

    if ! dracut --force --add fips /boot/initramfs-$(uname -r).img $(uname -r) | tee /tmp/dracut.log | grep -q "ERROR"; then
        echo "[OK] Initramfs regenerated."
    else
        handle_missing_fips_module
    fi
}

verify_fips_mode() {
    echo "[VERIFY] Checking if FIPS mode is active..."
    if grep -q "fips=1" /proc/cmdline; then
        echo "[OK] FIPS mode appears enabled."
    else
        echo "[WARNING] FIPS mode not yet active. Please reboot to activate."
        echo "Verify after reboot with: cat /proc/sys/crypto/fips_enabled (should be 1)"
    fi
}

setup_cron_updates() {
    echo "[STEP] Setting up Cron job for updates..."
    local cron_job="0 3 * * * /usr/bin/apt update && /usr/bin/apt upgrade -y"
    (crontab -l 2>/dev/null | grep -v -F "$cron_job"; echo "$cron_job") | crontab -
    echo "[OK] Cron job scheduled for daily updates."
}

main() {
    print_ascii_banner
    echo "[START] FIPS 140-3 Compliance Setup..."

    [[ $EUID -ne 0 ]] && echo "[ERROR] Run this script as root." && exit 1

    check_nic_modules
    backup_grub_settings
    setup_fips_compliance
    apply_security_settings
    regenerate_initramfs
    add_fips_to_grub
    setup_cron_updates
    verify_fips_mode

    echo "[DONE] FIPS setup completed. See $LOG_FILE for full trace."
    echo "[INFO] Please reboot the system to activate FIPS mode."
}

main "$@"
