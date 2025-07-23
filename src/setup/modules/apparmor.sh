#!/bin/bash
source /usr/lib/hardn-xdr/src/setup/hardn-common.sh
set -e

# Cross-architecture 
is_installed() {
    if command -v apt >/dev/null 2>&1; then
        dpkg -s "$1" >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        dnf list installed "$1" >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        yum list installed "$1" >/dev/null 2>&1
    elif command -v rpm >/dev/null 2>&1; then
        rpm -q "$1" >/dev/null 2>&1
    else
        return 1
    fi
}

HARDN_STATUS "info" "Initializing AppArmor security module..."


if ! is_installed apparmor || ! is_installed apparmor-utils; then
    HARDN_STATUS "info" "AppArmor packages not found. Installing..."
    if command -v apt >/dev/null 2>&1; then
        apt update -y && apt install -y apparmor apparmor-utils || {
            HARDN_STATUS "warning" "Failed to install AppArmor packages with apt."
            return 0
        }
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y apparmor apparmor-utils || {
            HARDN_STATUS "warning" "Failed to install AppArmor packages with dnf."
            return 0
        }
    elif command -v yum >/dev/null 2>&1; then
        yum install -y apparmor apparmor-utils || {
            HARDN_STATUS "warning" "Failed to install AppArmor packages with yum."
            return 0
        }
    fi
fi

# Ensure AppArmor is enabled at boot
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

# Load AppArmor kernel module if not loaded
if ! lsmod | grep -q apparmor; then
    modprobe apparmor && HARDN_STATUS "info" "AppArmor kernel module loaded."
fi

# Enforce all profiles
HARDN_STATUS "info" "Enforcing all AppArmor profiles..."
aa-enforce /etc/apparmor.d/* 2>/dev/null || {
    HARDN_STATUS "warning" "Some profiles could not be enforced or are in complain mode."
}

# Restart and enable AppArmor service
systemctl restart apparmor.service
systemctl enable apparmor.service

# Status check
if command -v aa-status &>/dev/null; then
    HARDN_STATUS "info" "Current AppArmor profile status:"
    aa-status
fi

HARDN_STATUS "pass" "AppArmor module completed successfully."

# Allow main script to continue
return 0