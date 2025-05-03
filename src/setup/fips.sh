#!/bin/bash

# Enhanced Debian FIPS 140-2 Compliance Script (Safe Mode)
# Authors: Tim Burns, Kiumarz Hashemi
# Date: 2025-05-03
# Version: 1.6
# Description:
# This script enables FIPS 140-2 compliance safely by checking NICs, backing up GRUB/initramfs,
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
        if apt show linux-modules-extra-$(uname -r) &>/dev/null; then
            apt update && apt install -y linux-modules-extra-$(uname -r)
            echo "[INFO] NIC drivers installed. Please verify manually if issues persist."
        else
            echo "[ERROR] linux-modules-extra-$(uname -r) not found. Skipping NIC driver installation."
        fi
    fi
}

fips_compatible() {
    echo "[INFO] Checking for FIPS-compatible kernels in the repository..."

   
    local available_kernels
    available_kernels=$(apt-cache search linux-image | grep -E "fips|hardened|generic" | awk '{print $1}')

    if [[ -z "$available_kernels" ]]; then
        echo "[ERROR] No FIPS-compatible kernels found in the repository. Please check your sources.list."
        return 1
    fi

    echo "[INFO] Available FIPS-compatible kernels:"
    echo "$available_kernels"

    local current_kernel
    current_kernel=$(uname -r)

    if [[ "$available_kernels" == *"$current_kernel"* ]]; then
        echo "[OK] Current kernel ($current_kernel) is FIPS-compatible."
    else
        echo "[WARNING] Current kernel ($current_kernel) is not FIPS-compatible."
        echo "[ACTION] Consider installing one of the following FIPS-compatible kernels:"
        echo "$available_kernels"
        echo "[INFO] To install a new kernel, run the following command:"
        echo "sudo apt install <kernel-package-name>"
    fi
}

backup_grub_settings() {
    echo "[INFO] Backing up GRUB config..."
    mkdir -p "$BACKUP_DIR"
    cp /etc/default/grub "$BACKUP_DIR/grub.bak.$(date +%s)"
    echo "[OK] GRUB configuration backed up."
}






setup_fips_compliance() {
    echo "[STEP] Setting up FIPS packages and dependencies..."
    if ! apt update; then
        echo "[ERROR] Failed to update package lists. Please check your network and repository configuration."
        return 1
    fi






    local packages=("linux-image-cloud-amd64" "initramfs-tools" "grub2" "openssl" "libssl3" "fipscheck" "fipscheck-lib")
    for pkg in "${packages[@]}"; do
        if ! apt install -y "$pkg"; then
            echo "[ERROR] Failed to install package: $pkg. Ensure the package is available in your repository."
            return 1
        fi
    done





  
    if ! update-initramfs -u -k "$(uname -r)"; then
        echo "[ERROR] Failed to update initramfs. Verify your kernel and initramfs tools."
        return 1
    fi





    if [ -f /etc/ssl/openssl.cnf ]; then
        sed -i 's/#.*fips_mode = 1/fips_mode = 1/' /etc/ssl/openssl.cnf
        echo "[INFO] FIPS mode enabled in OpenSSL configuration."
    else
        echo "[WARNING] OpenSSL configuration file not found. Skipping FIPS mode setup for OpenSSL."
    fi




    echo "[OK] FIPS compliance setup completed successfully."
    echo "[INFO] Please reboot the system to activate FIPS mode."
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
    echo "[OK] Security settings applied to GRUB. Please validate manually before rebooting."
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
    echo "[INFO] Updating GRUB configuration..."
    update-grub || echo "[ERROR] GRUB update failed. Please verify manually."
 

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

    if dracut --force --add fips /boot/initramfs-$(uname -r).img $(uname -r); then
        echo "[OK] Initramfs regenerated successfully."
    else
        echo "[ERROR] Failed to regenerate initramfs. Restoring backup..."
        cp "$BACKUP_DIR/initrd.img-$(uname -r).bak" /boot/initrd.img-$(uname -r)
        echo "[INFO] Backup restored. Please troubleshoot dracut errors."
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

add_backend_sources() {
    echo "[INFO] Adding backend sources to /etc/apt/sources.list..."

    # Define the backend sources
    local backend_sources=(
        "deb http://deb.debian.org/debian stable main contrib non-free"
        "deb-src http://deb.debian.org/debian stable main contrib non-free"
        "deb http://security.debian.org/debian-security stable-security main contrib non-free"
        "deb-src http://security.debian.org/debian-security stable-security main contrib non-free"
    )

    # Backup the current sources.list
    local backup_file="/etc/apt/sources.list.bak.$(date +%s)"
    echo "[INFO] Backing up /etc/apt/sources.list to $backup_file..."
    cp /etc/apt/sources.list "$backup_file"

    # Add the backend sources if they are not already present
    for source in "${backend_sources[@]}"; do
        if ! grep -Fq "$source" /etc/apt/sources.list; then
            echo "$source" >> /etc/apt/sources.list
            echo "[INFO] Added source: $source"
        else
            echo "[INFO] Source already present: $source"
        fi
    done

    echo "[INFO] Updating the package list..."
    apt update || (echo "[ERROR] Failed to update package list. Please check sources." && return 1)

    echo "[OK] Backend sources added successfully."
}

setup_cron_updates() {
    echo "[STEP] Setting up Cron job for updates..."
    local cron_job="0 3 * * * /usr/bin/apt update && /usr/bin/apt upgrade -y"
    (crontab -l 2>/dev/null | grep -v -F "$cron_job"; echo "$cron_job") | crontab -
    echo "[OK] Cron job scheduled for daily updates."
}

main() {
    print_ascii_banner
    echo "[START] FIPS 140-2 Compliance Setup..."

    [[ $EUID -ne 0 ]] && echo "[ERROR] Run this script as root." && exit 1
    
    add_backend_sources
    fips_compatible
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
