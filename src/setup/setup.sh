#!/bin/sh
set -e # Exit on errors
set -x # Debug mode

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

update_system_packages() {
    printf "\033[1;31m[+] Updating system packages...\033[0m\n"
    apt update -y && apt upgrade -y
}

install_pkgdeps() {
    printf "\033[1;31m[+] Installing package dependencies...\033[0m\n"
    apt install -y wget curl git gawk mariadb-common mysql-common policycoreutils \
        python3-matplotlib unixodbc-common firejail python3-pyqt6
}

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

install_security_tools() {
    printf "\033[1;31m[+] Installing required system security tools...\033[0m\n"
    apt install -y ufw fail2ban apparmor apparmor-profiles apparmor-utils firejail tcpd lynis debsums \
        libpam-pwquality libvirt-daemon-system libvirt-clients qemu-system-x86 openssh-server openssh-client
}

configure_ufw() {
    printf "\033[1;31m[+] Configuring UFW firewall...\033[0m\n"
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow 443/tcp
    ufw enable
    ufw reload
    printf "\033[1;31m[+] UFW firewall configured and enabled.\033[0m\n"
}

enable_services() {
    printf "\033[1;31m[+] Enabling and starting Fail2Ban and AppArmor services...\033[0m\n"
    systemctl enable --now fail2ban
    systemctl enable --now apparmor
    printf "\033[1;31m[+] Applying stricter AppArmor profiles...\033[0m\n"
    for profile in /etc/apparmor.d/*; do
        aa-enforce "$profile" || printf "\033[1;31m[-] Warning: Failed to enforce profile: %s\033[0m\n" "$profile"
    done
    systemctl restart fail2ban
}

install_additional_tools() {
    printf "\033[1;31m[+] Installing chkrootkit and LMD...\033[0m\n"
    apt install -y chkrootkit
    temp_dir=$(mktemp -d)
    cd "$temp_dir" || { printf "\033[1;31m[-] Failed to create temp directory\033[0m\n"; return 1; }
    if git clone https://github.com/rfxn/linux-malware-detect.git; then
        cd linux-malware-detect || { printf "\033[1;31m[-] Could not enter maldetect dir\033[0m\n"; return 1; }
        chmod +x install.sh
        ./install.sh
    else
        printf "\033[1;31m[-] Failed to clone maldetect repo\033[0m\n"
    fi
    cd /tmp || true
    rm -rf "$temp_dir"
}

install_rust() {
    printf "\033[1;31m[+] Installing Rust...\033[0m\n"
    if command -v rustc > /dev/null 2>&1; then
        printf "\033[1;32m[+] Rust is already installed. Skipping installation.\033[0m\n"
        return 0
    fi
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    export PATH="$HOME/.cargo/bin:$PATH"
    if command -v rustc > /dev/null 2>&1; then
        printf "\033[1;32m[+] Rust installed successfully.\033[0m\n"
        rustc --version
    else
        printf "\033[1;31m[-] Rust installation failed. Please check the logs.\033[0m\n"
        return 1
    fi
}

randomize_nic_mac() {
    printf "\033[1;31m[+] Randomizing NIC MAC addresses...\033[0m\n"
    for nic in $(ls /sys/class/net | grep -v lo); do
        ip link set dev "$nic" down
        mac=$(hexdump -n6 -e '/1 ":%02X"' /dev/urandom | sed 's/^://')
        ip link set dev "$nic" address "$mac"
        ip link set dev "$nic" up
        printf "\033[1;32m[+] Randomized MAC for %s: %s\033[0m\n" "$nic" "$mac"
    done
}

# the CRON train 
setup_cron_jobs() {
printf "\033[1;31m[+] Setting up cron jobs for security packages and updates...\033[0m\n"
echo "0 3 * * * root apt update -y && apt upgrade -y" > /etc/cron.d/system_updates_3am
echo "0 5 * * * root apt update -y && apt upgrade -y" > /etc/cron.d/system_updates_5am
echo "0 3 * * * root fail2ban-client reload" > /etc/cron.d/fail2ban_reload
echo "0 3 * * * root lynis audit system --quick" > /etc/cron.d/lynis_audit
echo "0 3 * * * root /usr/local/sbin/maldet --update" > /etc/cron.d/maldet_update
echo "0 3 * * 0 root update-grub" > /etc/cron.d/grub_update
echo "0 6 * * * root /sbin/reboot" > /etc/cron.d/daily_reboot
chmod 644 /etc/cron.d/system_updates_3am /etc/cron.d/system_updates_5am /etc/cron.d/fail2ban_reload /etc/cron.d/lynis_audit /etc/cron.d/maldet_update /etc/cron.d/grub_update /etc/cron.d/daily_reboot
printf "\033[1;32m[+] Cron jobs for security packages, updates, GRUB updates, and daily reboot have been set up.\033[0m\n"
}



apply_stig_hardening() {
    stig_password_policy
    stig_lock_inactive_accounts
    stig_login_banners
    stig_secure_filesystem
    stig_audit_rules
    stig_disable_usb
    stig_disable_core_dumps
    stig_disable_ctrl_alt_del
    stig_disable_ipv6
    randomize_nic_mac
}

setup_complete() {
    echo "======================================================="
    echo "             [+] HARDN - Setup Complete                "
    echo "  [+] Please reboot your system to apply changes       "
    echo "======================================================="
}

main() {
    update_system_packages
    install_pkgdeps
    install_selinux
    install_security_tools
    configure_ufw
    enable_services
    install_additional_tools
    install_rust
    apply_stig_hardening
    setup_complete


    # Make packages.sh executable and call it
    chmod +x "$(dirname "$0")/packages.sh"
    "$(dirname "$0")/packages.sh"
}

main