#!/bin/bash
source /usr/lib/hardn-xdr/src/setup/hardn-common.sh
set -e

HARDN_STATUS "info" "Initializing AppArmor security module..."

# Check if AppArmor is installed
if ! command -v aa-status &>/dev/null; then
    HARDN_STATUS "info" "AppArmor not found. Installing..."
    apt update -y && apt install -y apparmor apparmor-utils || {
        HARDN_STATUS "warning" "Failed to install AppArmor packages."
        return 0
    }
fi

# Ensure AppArmor is enabled at kernel boot
if ! grep -q "apparmor=1" /proc/cmdline; then
    HARDN_STATUS "warning" "AppArmor not enabled at boot. Updating GRUB..."

    if grep -q '^GRUB_CMDLINE_LINUX="' /etc/default/grub; then
        sed -i 's/^GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor /' /etc/default/grub
        update-grub
        HARDN_STATUS "info" "GRUB updated. Reboot required to activate AppArmor."
    else
        HARDN_STATUS "error" "Could not modify GRUB boot config."
    fi
fi

# Load AppArmor kernel module if not already
if ! lsmod | grep -q apparmor; then
    modprobe apparmor && HARDN_STATUS "info" "AppArmor kernel module loaded."
fi

# List and enforce all profiles
if command -v aa-status &>/dev/null; then
    HARDN_STATUS "info" "Current AppArmor profile status:"
    aa-status
fi

HARDN_STATUS "info" "Enforcing all AppArmor profiles..."
aa-enforce /etc/apparmor.d/* 2>/dev/null || {
    HARDN_STATUS "warning" "Some profiles could not be enforced or are in complain mode."
}

# Restart and enable AppArmor service
systemctl restart apparmor.service
systemctl enable apparmor.service

HARDN_STATUS "pass" "AppArmor module completed successfully."

# Allow execution of next modules
return 0
