#!/bin/sh
set -e # Exit on errors
set -x # Debug mode
set -u # Treat unset variables as an error
set -o pipefail # Fail if any command in a pipeline fails

########################################
#            HARDN - Setup             #
#  Please have repo cloned beforehand  #
#       Installs + Pre-config          #
#    Must have python-3 loaded already #
#             Author(s):               #
#         - Chris Bingham              #
#           - Tim Burns                #
#        Date: 4/5-12/2025             #
########################################

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Use: sudo ./setup.sh"
    exit 1
fi

# Update system packages
update_system_packages() {
    printf "\033[1;31m[+] Updating system packages...\033[0m\n"
    apt update -y && apt upgrade -y
}

# Setup Python virtual environment
setup_python_venv() {
    printf "\033[1;31m[+] Setting up Python virtual environment...\033[0m\n"
    python3 -m venv /opt/hardn/venv
    source /opt/hardn/venv/bin/activate
    pip install --upgrade pip
}

# Install Python dependencies
install_python_deps() {
    printf "\033[1;31m[+] Installing Python dependencies...\033[0m\n"
    apt install -y python3 python3-pip python3-venv
    setup_python_venv
    pip install PyQt6
    deactivate
    printf "\033[1;31m[+] Python dependencies installed and virtual environment deactivated.\033[0m\n"
}

# Install package dependencies
install_pkgdeps() {
    printf "\033[1;31m[+] Installing package dependencies...\033[0m\n"
    apt install -y wget curl git gawk mariadb-common mysql-common policycoreutils \
        python-matplotlib-data unixodbc-common
}

# Install and configure SELinux
install_selinux() {
    printf "\033[1;31m[+] Installing and configuring SELinux...\033[0m\n"
    apt update
    apt install -y selinux-utils selinux-basics policycoreutils policycoreutils-python-utils selinux-policy-default
    if ! command -v getenforce > /dev/null 2>&1; then
        printf "\033[1;31m[-] SELinux installation failed. Please check system logs.\033[0m\n"
        return 1
    fi
    if getenforce | grep -q "Disabled"; then
        printf "\033[1;31m[-] SELinux is disabled. Configuring it to enforcing mode at boot...\033[0m\n"
        if [ -f /etc/selinux/config ]; then
            sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config
            sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config
            printf "\033[1;31m[+] SELinux configured to enforcing mode at boot.\033[0m\n"
        fi
    else
        setenforce 1 || printf "\033[1;31m[-] Could not set SELinux to enforcing mode immediately. Please reboot to apply changes.\033[0m\n"
    fi
    printf "\033[1;31m[+] SELinux installation and configuration completed.\033[0m\n"
}

# Install security tools
install_security_tools() {
    printf "\033[1;31m[+] Installing required system security tools...\033[0m\n"
    apt install -y ufw fail2ban apparmor apparmor-profiles apparmor-utils firejail tcpd lynis debsums \
        libpam-pwquality libvirt-daemon-system libvirt-clients qemu-system-x86 openssh-server openssh-client
}

# Configure UFW
configure_ufw() {
    printf "\033[1;31m[+] Configuring UFW...\033[0m\n"
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable || printf "\033[1;31m[-] Warning: Could not enable UFW.\033[0m\n"
    ufw reload || printf "\033[1;31m[-] Warning: Could not reload UFW.\033[0m\n"
    printf "\033[1;31m[+] UFW configuration completed.\033[0m\n"
}

# Enable and configure Fail2Ban and AppArmor
enable_services() {
    printf "\033[1;31m[+] Enabling and starting Fail2Ban and AppArmor services...\033[0m\n"
    systemctl enable --now fail2ban
    systemctl enable --now apparmor

    printf "\033[1;31m[+] Configuring Fail2Ban...\033[0m\n"
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 24h
findtime = 10m
maxretry = 3
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 2
EOF

    systemctl restart fail2ban
    printf "\033[1;31m[+] Fail2Ban configured and restarted.\033[0m\n"
}

# Install additional tools
install_additional_tools() {
    printf "\033[1;31m[+] Installing chkrootkit and LMD...\033[0m\n"
    apt install -y chkrootkit
    printf "\033[1;31m[+] Installing Linux Malware Detect...\033[0m\n"
    temp_dir=$(mktemp -d)
    cd "$temp_dir" || { printf "\033[1;31m[-] Failed to create temporary directory\033[0m\n"; return 1; }
    if git clone https://github.com/rfxn/linux-malware-detect.git; then
        cd linux-malware-detect || { printf "\033[1;31m[-] Failed to change to maldetect directory\033[0m\n"; return 1; }
        chmod +x install.sh
        ./install.sh
    else
        printf "\033[1;31m[-] Failed to clone maldetect repository\033[0m\n"
    fi
    cd /tmp || true
    rm -rf "$temp_dir"
}

# Reload AppArmor profiles
reload_apparmor() {
    printf "\033[1;31m[+] Reloading AppArmor profiles...\033[0m\n"
    systemctl reload apparmor || systemctl start apparmor
    if command -v aa-status >/dev/null 2>&1 && aa-status >/dev/null 2>&1; then
        printf "\033[1;31m[+] AppArmor is running properly.\033[0m\n"
    else
        printf "\033[1;31m[-] Warning: AppArmor may not be running correctly.\033[0m\n"
    fi
}

# Configure cron jobs
configure_cron() {
    printf "\033[1;31m[+] Configuring cron jobs...\033[0m\n"
    crontab -l 2>/dev/null | grep -v -E "lynis audit system --cronjob|apt update && apt upgrade -y|chkrootkit|maldet --update|maldet --scan-all|setenforce 1" > mycron || true
    cat >> mycron << 'EOFCRON'
0 1 * * * lynis audit system --cronjob >> /var/log/lynis_cron.log 2>&1
0 4 * * * chkrootkit
0 5 * * * maldet --update
0 6 * * * maldet --scan-all / >> /var/log/maldet_scan.log 2>&1
EOFCRON
    crontab mycron
    rm mycron
    printf "\033[1;31m[+] Cron jobs configured.\033[0m\n"
}

# Disable USB storage
disable_usb_storage() {
    printf "\033[1;31m[+] Disabling USB storage devices while allowing HID devices...\033[0m\n"
    if echo 'install usb-storage /bin/false' > /etc/modprobe.d/usb-storage.conf; then
        modprobe -r usb-storage || printf "\033[1;31m[-] Warning: USB storage module in use, cannot unload.\033[0m\n"
        printf "\033[1;31m[+] USB storage devices blocked successfully.\033[0m\n"
    else
        printf "\033[1;31m[-] Error: Could not write to /etc/modprobe.d/usb-storage.conf. Check permissions.\033[0m\n"
    fi
}

# Disable guest accounts
disable_guest_account() {
    printf "\033[1;31m[+] Disabling guest accounts...\033[0m\n"
    if id "guest" >/dev/null 2>&1; then
        usermod -L guest || printf "\033[1;31m[-] Warning: Could not disable guest account.\033[0m\n"
        printf "\033[1;31m[+] Guest account disabled.\033[0m\n"
    else
        printf "\033[1;31m[-] Guest account does not exist. Skipping...\033[0m\n"
    fi
}

# Configure auditd
configure_auditd() {
    printf "\033[1;31m[+] Configuring auditd for STIG compliance...\033[0m\n"
    apt install -y auditd audispd-plugins
    cat > /etc/audit/audit.rules <<EOF
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins
EOF
    systemctl restart auditd
    printf "\033[1;31m[+] auditd configured and restarted.\033[0m\n"
}

# Final message
setup_complete() {
    echo "======================================================="
    echo "             [+] HARDN - Setup Complete                "
    echo "  [+] Please reboot your system to apply changes       "
    echo "======================================================="
}

# Main function
main() {
    update_system_packages
    install_python_deps
    install_pkgdeps
    install_selinux
    install_security_tools
    configure_ufw
    enable_services
    install_additional_tools
    reload_apparmor
    configure_cron
    disable_usb_storage
    disable_guest_account
    configure_auditd
    setup_complete
}

main