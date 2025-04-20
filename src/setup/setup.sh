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

# Update system packages
update_system_packages() {
    printf "\033[1;31m[+] Updating system packages...\033[0m\n"
    apt update -y && apt upgrade -y
}

# Install package dependencies
install_pkgdeps() {
    printf "\033[1;31m[+] Installing package dependencies...\033[0m\n"
    apt install -y wget curl git gawk mariadb-common mysql-common policycoreutils \
        python3-matplotlib-data unixodbc-common firejail python3-pyqt6
}
}

echo "========================================================"
echo "             [+] HARDN - Security Features              "
echo "       [+] Installing required Security Services        "
echo "========================================================"

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

    printf "\033[1;31m[+] Applying stricter AppArmor profiles...\033[0m\n"
    aa-enforce /etc/apparmor.d/* || printf "\033[1;31m[-] Warning: Failed to enforce some AppArmor profiles.\033[0m\n"
    printf "\033[1;31m[+] AppArmor profiles enforced.\033[0m\n"

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
    setup_complete
}

main