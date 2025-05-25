#!/bin/bash

# HARDN-XDR - The Linux Security Hardening Sentinel
# Developed and built by Christopher Bingham and Tim Burns


# Resources & Global Variables
repo="https://github.com/OpenSource-For-Freedom/HARDN-XDR/"
progsfile="https://raw.githubusercontent.com/OpenSource-For-Freedom/HARDN-XDR/main/progs.csv"
repobranch="main"
name=$(whoami)


# MENU


print_ascii_banner() {
    cat << "EOF"

   ▄█    █▄            ▄████████         ▄████████      ████████▄       ███▄▄▄▄   
  ███    ███          ███    ███        ███    ███      ███   ▀███      ███▀▀▀██▄ 
  ███    ███          ███    ███        ███    ███      ███    ███      ███   ███ 
 ▄███▄▄▄▄███▄▄        ███    ███       ▄███▄▄▄▄██▀      ███    ███      ███   ███ 
▀▀███▀▀▀▀███▀       ▀███████████      ▀▀███▀▀▀▀▀        ███    ███      ███   ███ 
  ███    ███          ███    ███      ▀███████████      ███    ███      ███   ███ 
  ███    ███          ███    ███        ███    ███      ███   ▄███      ███   ███ 
  ███    █▀           ███    █▀         ███    ███      ████████▀        ▀█   █▀  
                                        ███    ███ 
                           
                            Extended Detection and Response
                            by Security International Group
                                   Version 1.2.1
EOF
}

# Check for root privileges
[ "$(id -u)" -ne 0 ] && echo "This script must be run as root." && exit 1

installpkg() {
    dpkg -s "$1" >/dev/null 2>&1 || sudo apt install -y "$1" >/dev/null 2>&1
}

error() {
    
    printf "%s\n" "$1" >&2
    exit 1
}

welcomemsg() {
    printf "\\n\\n Welcome to HARDN-XDR a Debian Security tool for System Hardening\\n"
    printf "\\nThis installer will update your system first...\\n"
    # Original yes/no whiptail did not have an explicit exit path for "no"
}

preinstallmsg() {
    printf "\\nWelcome to HARDN-XDR. A Linux Security Hardening program.\\n"
    printf "The system will be configured to ensure STIG and Security compliance.\\n"
    # Removed: || { clear; exit 1; }
}

update_system_packages() {
    printf "\033[1;31m[+] Updating system packages...\033[0m\n"
    apt update && apt upgrade -y
    apt update -y
}

install_package_dependencies() {
    printf "\\033[1;31m[+] Installing package dependencies from progs.csv...\\033[0m\\n"
    progsfile="$1"
    
    # If progsfile is a URL, download it first
    if [[ "$progsfile" == http* ]]; then
        temp_csv=$(mktemp)
        curl -fsSL "$progsfile" -o "$temp_csv" || {
            printf "Failed to download %s\\n" "$progsfile"
            return 1
        }
        progsfile="$temp_csv"
    fi
    
    # Check if the CSV file exists
    if [[ ! -f "$progsfile" ]]; then
        printf "Package list file not found: %s\\n" "$progsfile"
        return 1
    fi
    
    # Read and install packages from CSV
    while IFS=, read -r tag name desc || [[ -n "$tag" ]]; do
        # Skip empty lines and comments
        [[ -z "$tag" || "$tag" =~ ^[[:space:]]*# ]] && continue
        
        # Remove any quotes and whitespace from name
        name=$(echo "$name" | tr -d '"' | xargs)
        
        if [[ -n "$name" ]]; then
            if ! dpkg -s "$name" >/dev/null 2>&1; then
                printf "Installing %s (%s)...\\n" "$name" "${desc:-$name}"
                apt install -y "$name" >/dev/null 2>&1 || {
                    printf "Warning: Failed to install %s\\n" "$name"
                }
            else
                printf "%s is already installed.\\n" "$name"
            fi
        fi
    done < "$progsfile"
    
    # Clean up temp file if we downloaded it
    [[ "$1" == http* ]] && rm -f "$temp_csv"
}

# Function to install packages with visual feedback
aptinstall() {
    package="$1"
    comment="$2"
    printf "Installing \`%s\` from the repository. %s\\n" "$package" "$comment"
    echo "$aptinstalled" | grep -q "^$package$" && return 1
    apt-get install -y "$package" >/dev/null 2>&1
    # Add to installed packages list
    aptinstalled="$aptinstalled\n$package"
}

maininstall() {
    # Installs all needed programs from main repo.
    printf "Installing \`%s\` - %s\\n" "$1" "$2"
    installpkg "$1"
}

# Function to build and install from Git repo
gitdpkgbuild() {
    repo_url="$1"
    description="$2"
    dir="/tmp/$(basename "$repo_url" .git)"

    printf "Cloning %s... (%s)\\n" "$repo_url" "$description"
    git clone --depth=1 "$repo_url" "$dir" >/dev/null 2>&1 || {
        printf "Failed to clone %s\\n" "$repo_url"
        return 1
    }
    cd "$dir" || { printf "Failed to enter %s\\n" "$dir"; return 1; }
    printf "Building and installing %s...\\n" "$description"

    # Check and install build dependencies
    printf "Checking build dependencies for %s...\\n" "$description"
    build_deps=$(dpkg-checkbuilddeps 2>&1 | grep -oP 'Unmet build dependencies: \\K.*')
    if [[ "$build_deps" ]]; then
        printf "Installing build dependencies: %s\\n" "$build_deps"
        apt-get install -y "$build_deps" >/dev/null 2>&1
    fi

    # Run dpkg-source before building (if debian/source/format exists)
    if [[ -f debian/source/format ]]; then
        dpkg-source --before-build . >/dev/null 2>&1
    fi

    # Build and install the package
    if dpkg-buildpackage -us -uc >/dev/null 2>&1; then
        debfile=$(find .. -name '*.deb' -print -quit)
        if [[ "$debfile" ]]; then
            dpkg -i "$debfile"
        else
            printf "No .deb file found after build.\\n"
            return 1
        fi
    else
        printf "%s failed to build. Installing common build dependencies and retrying...\\n" "$description"
        apt install -y build-essential debhelper libpam-tmpdir apt-listbugs devscripts git-buildpackage >/dev/null 2>&1
        if dpkg-buildpackage -us -uc >/dev/null 2>&1; then
            debfile=$(find .. -name '*.deb' -print -quit)
            if [[ "$debfile" ]]; then
                dpkg -i "$debfile"
            else
                printf "No .deb file found after retry.\\n"
                return 1
            fi
        else
            printf "%s failed to build after retry. Please check build dependencies.\\n" "$description"
            return 1
        fi
    fi
}

build_hardn_package() {
        set -e
        printf "Building HARDN Debian package...\\n"

        temp_dir=$(mktemp -d)
        cd "$temp_dir"
        git clone --depth=1 -b "$repobranch" "$repo"
        cd HARDN-XDR

        printf "Running dpkg-buildpackage...\\n"
        dpkg-buildpackage -us -uc

        cd ..
        printf "Installing HARDN package...\\n"
        dpkg -i hardn_*.deb || true
        apt install -f -y

        cd /
        rm -rf "$temp_dir"

        printf "HARDN package installed successfully\\n"
}


# setup basic configs for security tools:

setup_security(){
    printf "\\033[1;31m[+] Setting up security tools and configurations...\\033[0m\\n"
    
    # UFW (Uncomplicated Firewall)
    printf "Configuring UFW...\\n"
    ufw --force reset >/dev/null 2>&1
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow essential services
    ufw allow ssh
    ufw allow out 53/udp comment 'DNS'
    ufw allow out 80/tcp comment 'HTTP'
    ufw allow out 443/tcp comment 'HTTPS'
    ufw allow out 123/udp comment 'NTP'
    
    # Security-specific rules
    ufw deny out 23/tcp comment 'Block Telnet'
    ufw deny out 135/tcp comment 'Block RPC'
    ufw deny out 139/tcp comment 'Block NetBIOS'
    ufw deny out 445/tcp comment 'Block SMB'
    ufw deny in 1433/tcp comment 'Block MSSQL'
    ufw deny in 3389/tcp comment 'Block RDP'
    
    # Rate limiting for SSH
    ufw limit ssh/tcp comment 'Rate limit SSH'
    
    # Log denied connections
    ufw logging on
    
    ufw --force enable
    
    # Fail2Ban
    printf "Configuring Fail2Ban...\\n"
    systemctl enable fail2ban
    systemctl start fail2ban
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    sed -i 's/bantime  = 10m/bantime  = 1h/' /etc/fail2ban/jail.local
    sed -i 's/findtime  = 10m/findtime  = 10m/' /etc/fail2ban/jail.local
    sed -i 's/maxretry = 5/maxretry = 3/' /etc/fail2ban/jail.local
    systemctl restart fail2ban

    # kernel hardening
    # Check if system is UEFI VM and skip kernel hardening if so
    if [ -d /sys/firmware/efi ] && systemd-detect-virt -q; then
        printf "UEFI VM detected, skipping kernel hardening...\\n"
    else
        printf "Configuring kernel hardening...\\n"
        {
            echo "kernel.kptr_restrict = 2"
            echo "kernel.randomize_va_space = 2"
            echo "kernel.yama.ptrace_scope = 1"
            echo "fs.protected_hardlinks = 1"
            echo "fs.protected_symlinks = 1"
            echo "fs.suid_dumpable = 0"
            echo "kernel.dmesg_restrict = 1"
            echo "kernel.unprivileged_bpf_disabled = 1"
            echo "kernel.unprivileged_userns_clone = 1"
            echo "kernel.kexec_load_disabled = 1"
            echo "kernel.modules_disabled = 1"
            echo "kernel.sysrq = 0"
            echo "kernel.core_pattern = |/bin/false"
            echo "kernel.core_uses_pid = 1"
            echo "kernel.panic = 10"
        } >> /etc/sysctl.conf
    fi

    # grub
    # Check if system is UEFI and not using GRUB
    if [ -d /sys/firmware/efi ] && ! command -v grub-install >/dev/null 2>&1; then
        printf "UEFI system detected without GRUB, skipping GRUB configuration...\\n"
    elif [ ! -f /etc/default/grub ]; then
        printf "GRUB configuration file not found, skipping GRUB configuration...\\n"
    else
        printf "Configuring GRUB...\\n"
        # Backup original GRUB config
        cp /etc/default/grub "/etc/default/grub.bak.$(date +%F-%T)" 2>/dev/null || true
        
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=""/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash mitigations=auto"/' /etc/default/grub 2>/dev/null || true
        sed -i 's/GRUB_TIMEOUT=5/GRUB_TIMEOUT=0/' /etc/default/grub 2>/dev/null || true
        sed -i 's/GRUB_HIDDEN_TIMEOUT=0/GRUB_HIDDEN_TIMEOUT=5/' /etc/default/grub 2>/dev/null || true
        sed -i 's/GRUB_HIDDEN_TIMEOUT_QUIET=true/GRUB_HIDDEN_TIMEOUT_QUIET=false/' /etc/default/grub 2>/dev/null || true
        sed -i 's/GRUB_TERMINAL=console/GRUB_TERMINAL=console/' /etc/default/grub 2>/dev/null || true
        sed -i 's/GRUB_DISABLE_OS_PROBER=true/GRUB_DISABLE_OS_PROBER=false/' /etc/default/grub 2>/dev/null || true
        
        if update-grub >/dev/null 2>&1; then
            printf "GRUB configuration updated.\\n"
        else
            printf "Warning: Failed to update GRUB configuration.\\n"
        fi
    fi
    
    # AppArmor
    printf "Configuring AppArmor...\\n"
    if [ -d /sys/kernel/security/apparmor ]; then
        systemctl enable apparmor >/dev/null 2>&1
        systemctl start apparmor >/dev/null 2>&1
        # Check if AppArmor is actually running before enforcing profiles
        if systemctl is-active --quiet apparmor && [ -f /sys/kernel/security/apparmor/profiles ]; then
            aa-enforce /etc/apparmor.d/* >/dev/null 2>&1 || {
                printf "Warning: Failed to enforce some AppArmor profiles.\\n"
            }
        else
            printf "Warning: AppArmor not properly initialized, skipping profile enforcement.\\n"
        fi
    else
        printf "Warning: AppArmor not supported on this system, skipping configuration.\\n"
    fi
    
    # Firejail
    printf "Configuring Firejail...\\n"
    firecfg >/dev/null 2>&1 || true
    
    # Configure Firejail for specific browsers
    browsers=("firefox" "google-chrome" "tor" "brave")
    for browser in "${browsers[@]}"; do
        if command -v "$browser" >/dev/null 2>&1; then
            printf "Configuring Firejail for %s...\\n" "$browser"
            firejail --apparmor --seccomp --private-tmp --noroot --caps.drop=all "$browser" >/dev/null 2>&1 || true
        fi
    done
    
    # TCP Wrappers (tcpd)
    printf "Configuring TCP Wrappers...\\n"
    
    echo "ALL: LOCAL, 127.0.0.1" >> /etc/hosts.allow
    echo "sshd: ALL" >> /etc/hosts.allow
    echo "ALL: ALL" >> /etc/hosts.deny

  
  
    # USB storage
    echo 'blacklist usb-storage' > /etc/modprobe.d/usb-storage.conf
    if modprobe -r usb-storage 2>/dev/null; then
        printf "\033[1;31m[+] USB storage successfully disabled.\033[0m\n"
    else
        printf "\033[1;31m[-] Warning: USB storage module in use, cannot unload.\033[0m\n"
    fi
    
    # Disable unnecessary network protocols
    printf "Disabling unnecessary network protocols...\\n"
    {
        echo "install dccp /bin/true"
        echo "install sctp /bin/true"
        echo "install rds /bin/true"
        echo "install tipc /bin/true"
    } >> /etc/modprobe.d/blacklist-rare-network.conf
    
    # Secure shared memory
    printf "Securing shared memory...\\n"
    if ! grep -q "tmpfs /run/shm" /etc/fstab; then
        echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    fi
    
    # Set secure file permissions
    printf "Setting secure file permissions...\\n"
    chmod 700 /root
    chmod 644 /etc/passwd
    chmod 600 /etc/shadow
    chmod 644 /etc/group
    chmod 600 /etc/gshadow
    chmod 600 /etc/ssh/sshd_config
    
    # Disable core dumps for security
    printf "Disabling core dumps...\\n"
    echo "* hard core 0" >> /etc/security/limits.conf
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
    
    # Configure automatic security updates
    printf "Configuring automatic security updates...\\n"
    # shellcheck disable=SC2016
    echo 'Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}-security";
        "${distro_id}ESMApps:${distro_codename}-apps-security";
        "${distro_id}ESM:${distro_codename}-infra-security";
    };' > /etc/apt/apt.conf.d/50unattended-upgrades
    
    # Secure network parameters
    printf "Configuring secure network parameters...\\n"
    {
        echo "net.ipv4.ip_forward = 0"
        echo "net.ipv4.conf.all.send_redirects = 0"
        echo "net.ipv4.conf.default.send_redirects = 0"
        echo "net.ipv4.conf.all.accept_redirects = 0"
        echo "net.ipv4.conf.default.accept_redirects = 0"
        echo "net.ipv4.conf.all.secure_redirects = 0"
        echo "net.ipv4.conf.default.secure_redirects = 0"
        echo "net.ipv4.conf.all.log_martians = 1"
        echo "net.ipv4.conf.default.log_martians = 1"
        echo "net.ipv4.icmp_echo_ignore_broadcasts = 1"
        echo "net.ipv4.icmp_ignore_bogus_error_responses = 1"
        echo "net.ipv4.tcp_syncookies = 1"
        echo "net.ipv6.conf.all.disable_ipv6 = 1"
        echo "net.ipv6.conf.default.disable_ipv6 = 1"
    } >> /etc/sysctl.conf


    # debsums
    printf "Configuring debsums...\\n"
    if command -v debsums >/dev/null 2>&1; then
        if debsums_init >/dev/null 2>&1; then
            printf "\\033[1;32m[+] debsums initialized successfully\\033[0m\\n"
        else
            printf "\\033[1;31m[-] Failed to initialize debsums\\033[0m\\n"
        fi
        
        # Add debsums check to daily cron
        if ! grep -q "debsums" /etc/crontab; then
            echo "0 4 * * * root /usr/bin/debsums -s 2>&1 | logger -t debsums" >> /etc/crontab
            printf "\\033[1;32m[+] debsums daily check added to crontab\\033[0m\\n"
        else
            printf "\\033[1;33m[!] debsums already in crontab\\033[0m\\n"
        fi
        
        # Run initial check
        printf "Running initial debsums check...\\n"
        if debsums -s >/dev/null 2>&1; then
            printf "\\033[1;32m[+] Initial debsums check completed successfully\\033[0m\\n"
        else
            printf "\\033[1;33m[!] Warning: Some packages failed debsums verification\\033[0m\\n"
        fi
    else
        printf "\\033[1;31m[-] debsums command not found, skipping configuration\\033[0m\\n"
    fi
    
    # rkhunter
    printf "Configuring rkhunter...\\n"
    if command -v rkhunter >/dev/null 2>&1; then
        # Configure rkhunter first
        sed -i 's/#CRON_DAILY_RUN=""/CRON_DAILY_RUN="true"/' /etc/default/rkhunter 2>/dev/null || true
        
        # Update the configuration and database
        rkhunter --configcheck >/dev/null 2>&1 || true
        rkhunter --update --nocolors >/dev/null 2>&1 || {
            printf "Warning: Failed to update rkhunter database.\\n"
        }
        rkhunter --propupd --nocolors >/dev/null 2>&1 || {
            printf "Warning: Failed to update rkhunter properties.\\n"
        }
    else
        printf "Warning: rkhunter not found, skipping configuration.\\n"
    fi
    
    # PAM Password Quality
    printf "Configuring PAM password quality...\\n"
    if [ -f /etc/pam.d/common-password ]; then
        if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
            echo "password requisite pam_pwquality.so retry=3 minlen=8 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1" >> /etc/pam.d/common-password
        fi
    else
        printf "Warning: /etc/pam.d/common-password not found, skipping PAM configuration...\\n"
    fi
    
    # libvirt and KVM
    printf "Configuring libvirt...\\n"
    systemctl enable libvirtd
    systemctl start libvirtd
    usermod -a -G libvirt "$name" >/dev/null 2>&1 || true
    
    # OpenSSH Server
    printf "Configuring OpenSSH...\\n"
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/#Protocol 2/Protocol 2/' /etc/ssh/sshd_config
    sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
    systemctl restart ssh || systemctl restart sshd
    
    # chkrootkit
    printf "Configuring chkrootkit...\\n"
    if ! grep -q "chkrootkit" /etc/crontab; then
        echo "0 3 * * * root /usr/sbin/chkrootkit" >> /etc/crontab
    fi
    
    # auditd
    printf "Configuring auditd...\\n"
    if dpkg -s auditd >/dev/null 2>&1; then
        if systemctl enable auditd >/dev/null 2>&1; then
            printf "\\033[1;32m[+] auditd service enabled successfully\\033[0m\\n"
        else
            printf "\\033[1;31m[-] Failed to enable auditd service\\033[0m\\n"
        fi
        
        if systemctl start auditd >/dev/null 2>&1; then
            printf "\\033[1;32m[+] auditd service started successfully\\033[0m\\n"
        else
            printf "\\033[1;31m[-] Failed to start auditd service\\033[0m\\n"
        fi
        
        if command -v auditctl >/dev/null 2>&1; then
            if auditctl -e 1 >/dev/null 2>&1; then
                printf "\\033[1;32m[+] auditd enabled successfully\\033[0m\\n"
            else
                printf "\\033[1;31m[-] Failed to enable auditd\\033[0m\\n"
            fi
        else
            printf "\\033[1;33m[!] Warning: auditctl command not found\\033[0m\\n"
        fi
    else
        printf "\\033[1;33m[!] Warning: auditd not installed, skipping configuration...\\033[0m\\n"
    fi
    
    # Suricata
    printf "Configuring Suricata...\\n"
    if systemctl enable suricata; then
        printf "\\033[1;32m[+] Suricata service enabled successfully\\033[0m\\n"
    else
        printf "\\033[1;31m[-] Failed to enable Suricata service\\033[0m\\n"
    fi
    
    if suricata-update >/dev/null 2>&1; then
        printf "\\033[1;32m[+] Suricata rules updated successfully\\033[0m\\n"
    else
        printf "\\033[1;33m[!] Warning: Suricata rules update failed\\033[0m\\n"
    fi
    
    if systemctl start suricata; then
        printf "\\033[1;32m[+] Suricata service started successfully\\033[0m\\n"
    else
        printf "\\033[1;31m[-] Failed to start Suricata service\\033[0m\\n"
    fi
    
    # AIDE (Advanced Intrusion Detection Environment)
    if ! dpkg -s aide >/dev/null 2>&1; then
        printf "Installing and configuring AIDE...\\n"
        apt install -y aide >/dev/null 2>&1
        aideinit >/dev/null 2>&1 || true
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db >/dev/null 2>&1 || true
        echo "0 5 * * * root /usr/bin/aide --check" >> /etc/crontab
        printf "\\033[1;32m[+] AIDE installed and configured successfully\\033[0m\\n"
    else
        printf "\\033[1;33m[!] AIDE already installed, skipping configuration...\\033[0m\\n"
    fi
    # libpam-tmpdir
    printf "Configuring PAM tmpdir...\\n"
    if [ -f /etc/pam.d/common-session ]; then
        if ! grep -q "pam_tmpdir.so" /etc/pam.d/common-session; then
            echo "session optional pam_tmpdir.so" >> /etc/pam.d/common-session
        fi
    else
        printf "Warning: /etc/pam.d/common-session not found, skipping PAM tmpdir configuration...\\n"
    fi
    
    # YARA
    printf "YARA installed and ready for custom rules...\\n"
    mkdir -p /etc/yara/rules
    
    # apt-listbugs
    printf "apt-listbugs configured for security updates...\\n"
    
    # SELinux
    printf "Configuring SELinux...\\n"
    if selinux-activate >/dev/null 2>&1; then
        printf "\\033[1;32m[+] SELinux activated successfully\\033[0m\\n"
    else
        printf "\\033[1;33m[!] Warning: Failed to activate SELinux\\033[0m\\n"
    fi
    
    if echo "SELINUX=enforcing" > /etc/selinux/config && echo "SELINUXTYPE=default" >> /etc/selinux/config; then
        printf "\\033[1;32m[+] SELinux configuration written successfully\\033[0m\\n"
    else
        printf "\\033[1;31m[-] Error: Failed to write SELinux configuration\\033[0m\\n"
    fi
    
    # Lynis
    printf "Configuring Lynis...\\n"
    lynis update info >/dev/null 2>&1 || true
    echo "0 2 * * 0 root /usr/bin/lynis audit system --cronjob" >> /etc/crontab
    
    printf "\\033[1;32m[+] Security tools configuration completed!\\033[0m\\n"
    printf "\\033[1;33m[!] Note: Some changes require a reboot to take full effect.\\033[0m\\n"
}

restrict_compilers() {
    printf "\033[1;31m[+] Restricting compiler access to root only (HRDN-7222)...\033[0m\n"

    local compilers
	compilers="/usr/bin/gcc /usr/bin/g++ /usr/bin/make /usr/bin/cc /usr/bin/c++ /usr/bin/as /usr/bin/ld"
    for bin in $compilers; do
        if [[ -f "$bin" ]]; then
            chmod 700 "$bin"
            chown root:root "$bin"
            printf "\033[1;32m[+] Restricted %s to root only.\\033[0m\\n" "$bin"
        fi
    done
}

disable_binfmt_misc() {
    printf "\\033[1;31m[+] Checking/Disabling non-native binary format support (binfmt_misc)...\\033[0m\\n"
    if mount | grep -q 'binfmt_misc'; then
        printf "\\033[1;33m[*] binfmt_misc is mounted. Attempting to unmount...\033[0m\\n"
        if umount /proc/sys/fs/binfmt_misc; then
            printf "\\033[1;32m[+] binfmt_misc unmounted successfully.\033[0m\\n"
        else
            printf "\\033[1;31m[-] Failed to unmount binfmt_misc. It might be busy or not a separate mount.\033[0m\\n"
        fi
    fi

    if lsmod | grep -q "^binfmt_misc"; then
        printf "\\033[1;33m[*] binfmt_misc module is loaded. Attempting to unload...\033[0m\\n"
        if rmmod binfmt_misc; then
            printf "\\033[1;32m[+] binfmt_misc module unloaded successfully.\033[0m\\n"
        else
            printf "\\033[1;31m[-] Failed to unload binfmt_misc module. It might be in use or built-in.\033[0m\\n"
        fi
    else
        printf "\\033[1;32m[+] binfmt_misc module is not currently loaded.\033[0m\\n"
    fi

    # Prevent module from loading on boot
    local modprobe_conf="/etc/modprobe.d/disable-binfmt_misc.conf"
    if [[ ! -f "$modprobe_conf" ]]; then
        echo "install binfmt_misc /bin/true" > "$modprobe_conf"
        printf "\\033[1;32m[+] Added modprobe rule to prevent binfmt_misc from loading on boot: %s\033[0m\\n" "$modprobe_conf"
    else
        if ! grep -q "install binfmt_misc /bin/true" "$modprobe_conf"; then
            echo "install binfmt_misc /bin/true" >> "$modprobe_conf"
            printf "\\033[1;32m[+] Appended modprobe rule to prevent binfmt_misc from loading to %s\033[0m\\n" "$modprobe_conf"
        else
            printf "\\033[1;34m[*] Modprobe rule to disable binfmt_misc already exists in %s.\033[0m\\n" "$modprobe_conf"
        fi
    fi
    whiptail --infobox "Non-native binary format support (binfmt_misc) checked/disabled." 7 70
}

disable_firewire_drivers() {
    printf "\\033[1;31m[+] Checking/Disabling FireWire (IEEE 1394) drivers...\033[0m\\n"
    local firewire_modules changed blacklist_file
	firewire_modules="firewire_core firewire_ohci firewire_sbp2"
    changed=0

    for module_name in $firewire_modules; do
        if lsmod | grep -q "^${module_name}"; then
            printf "\\033[1;33m[*] FireWire module %s is loaded. Attempting to unload...\033[0m\\n" "$module_name"
            if rmmod "$module_name"; then
                printf "\\033[1;32m[+] FireWire module %s unloaded successfully.\033[0m\\n" "$module_name"
                changed=1
            else
                printf "\\033[1;31m[-] Failed to unload FireWire module %s. It might be in use or built-in.\033[0m\\n" "$module_name"
            fi
        else
            printf "\\033[1;34m[*] FireWire module %s is not currently loaded.\033[0m\\n" "$module_name"
        fi
    done

    blacklist_file="/etc/modprobe.d/blacklist-firewire.conf"
    if [[ ! -f "$blacklist_file" ]]; then
        touch "$blacklist_file"
        printf "\\033[1;32m[+] Created FireWire blacklist file: %s\033[0m\\n" "$blacklist_file"
    fi

    for module_name in $firewire_modules; do
        if ! grep -q "blacklist $module_name" "$blacklist_file"; then
            echo "blacklist $module_name" >> "$blacklist_file"
            printf "\\033[1;32m[+] Blacklisted FireWire module %s in %s\033[0m\\n" "$module_name" "$blacklist_file"
            changed=1
        else
            printf "\\033[1;34m[*] FireWire module %s already blacklisted in %s.\033[0m\\n" "$module_name" "$blacklist_file"
        fi
    done

    if [[ "$changed" -eq 1 ]]; then
        whiptail --infobox "FireWire drivers checked. Unloaded and/or blacklisted where applicable." 7 70
    else
        whiptail --infobox "FireWire drivers checked. No changes made (likely already disabled/not present)." 8 70
    fi
}

purge_old_packages() {
    printf "\\033[1;31m[+] Purging configuration files of old/removed packages...\033[0m\\n"
    local packages_to_purge
    packages_to_purge=$(dpkg -l | grep '^rc' | awk '{print $2}')

    if [[ "$packages_to_purge" ]]; then
        printf "\\033[1;33m[*] Found the following packages with leftover configuration files to purge:\033[0m\\n"
        echo "$packages_to_purge"
       
        if command -v whiptail >/dev/null; then
            whiptail --title "Packages to Purge" --msgbox "The following packages have leftover configuration files that will be purged:\n\n$packages_to_purge" 15 70
        fi

        for pkg in $packages_to_purge; do
            printf "\\033[1;31m[+] Purging %s...\\033[0m\\n" "$pkg"
            if apt-get purge -y "$pkg"; then
                printf "\\033[1;32m[+] Successfully purged %s.\\033[0m\\n" "$pkg"
            else
                printf "\\033[1;31m[-] Failed to purge %s. Trying dpkg --purge...\\033[0m\\n" "$pkg"
                if dpkg --purge "$pkg"; then
                    printf "\\033[1;32m[+] Successfully purged %s with dpkg.\\033[0m\\n" "$pkg"
                else
                    printf "\\033[1;31m[-] Failed to purge %s with dpkg as well.\\033[0m\\n" "$pkg"
                fi
            fi
        done
        whiptail --infobox "Purged configuration files for removed packages." 7 70
    else
        printf "\\033[1;32m[+] No old/removed packages with leftover configuration files found to purge.\033[0m\\n"
        whiptail --infobox "No leftover package configurations to purge." 7 70
    fi
   
    printf "\\033[1;31m[+] Running apt-get autoremove and clean to free up space...\033[0m\\n"
    apt-get autoremove -y
    apt-get clean
    whiptail --infobox "Apt cache cleaned." 7 70
}

enable_nameservers() {
    printf "\\033[1;31m[+] Checking and configuring DNS nameservers (Quad9 primary, Google secondary)...\033[0m\\n"
    local resolv_conf quad9_ns google_ns nameserver_count configured_persistently changes_made
	resolv_conf="/etc/resolv.conf"
    quad9_ns="9.9.9.9"
    google_ns="8.8.8.8"
    nameserver_count=0
    configured_persistently=false
    changes_made=false

    if [[ -f "$resolv_conf" ]]; then
        nameserver_count=$(grep -E "^\s*nameserver\s+" "$resolv_conf" | grep -Ev "127\.0\.0\.1|::1" | awk '{print $2}' | sort -u | wc -l)
    fi

    printf "\\033[1;34m[*] Found %s non-localhost nameserver(s) in %s.\033[0m\\n" "$nameserver_count" "$resolv_conf"

    # Always attempt to set Quad9 as primary and Google as secondary
    # Check for systemd-resolved
    if systemctl is-active --quiet systemd-resolved && \
       [[ -L "$resolv_conf" ]] && \
       (readlink "$resolv_conf" | grep -qE "systemd/resolve/(stub-resolv.conf|resolv.conf)"); then
        
        printf "\\033[1;34m[*] systemd-resolved is active and manages %s.\033[0m\\n" "$resolv_conf"
        local resolved_conf_systemd temp_resolved_conf
		resolved_conf_systemd="/etc/systemd/resolved.conf"
        temp_resolved_conf=$(mktemp)

        if [[ ! -f "$resolved_conf_systemd" ]]; then
            printf "\\033[1;33m[*] Creating %s as it does not exist.\033[0m\\n" "$resolved_conf_systemd"
            echo "[Resolve]" > "$resolved_conf_systemd"
            chmod 644 "$resolved_conf_systemd"
        fi
        
        cp "$resolved_conf_systemd" "$temp_resolved_conf"

        # Set DNS= and FallbackDNS= explicitly
        if grep -qE "^\s*DNS=" "$temp_resolved_conf"; then
            sed -i -E "s/^\s*DNS=.*/DNS=$quad9_ns $google_ns/" "$temp_resolved_conf"
        else
            if grep -q "\[Resolve\]" "$temp_resolved_conf"; then
                sed -i "/\[Resolve\]/a DNS=$quad9_ns $google_ns" "$temp_resolved_conf"
            else
                echo -e "\n[Resolve]\nDNS=$quad9_ns $google_ns" >> "$temp_resolved_conf"
            fi
        fi

        # Set FallbackDNS as well (optional, for redundancy)
        if grep -qE "^\s*FallbackDNS=" "$temp_resolved_conf"; then
            sed -i -E "s/^\s*FallbackDNS=.*/FallbackDNS=$google_ns $quad9_ns/" "$temp_resolved_conf"
        else
            if grep -q "\[Resolve\]" "$temp_resolved_conf"; then
                sed -i "/\[Resolve\]/a FallbackDNS=$google_ns $quad9_ns" "$temp_resolved_conf"
            else
                echo -e "\n[Resolve]\nFallbackDNS=$google_ns $quad9_ns" >> "$temp_resolved_conf"
            fi
        fi

        if ! cmp -s "$temp_resolved_conf" "$resolved_conf_systemd"; then
            cp "$temp_resolved_conf" "$resolved_conf_systemd"
            printf "\\033[1;32m[+] Updated %s. Restarting systemd-resolved...\033[0m\\n" "$resolved_conf_systemd"
            if systemctl restart systemd-resolved; then
                printf "\\033[1;32m[+] systemd-resolved restarted successfully.\033[0m\\n"
                configured_persistently=true
                changes_made=true
            else
                printf "\\033[1;31m[-] Failed to restart systemd-resolved. Manual check required.\033[0m\\n"
            fi
        else
            printf "\\033[1;34m[*] No effective changes to %s were needed.\033[0m\\n" "$resolved_conf_systemd"
        fi
        rm -f "$temp_resolved_conf"
    fi

    # If not using systemd-resolved, try to set directly in /etc/resolv.conf
    if [[ "$configured_persistently" = false ]]; then
        printf "\\033[1;34m[*] Attempting direct modification of %s.\033[0m\\n" "$resolv_conf"
        if [[ -f "$resolv_conf" ]] && [[ -w "$resolv_conf" ]]; then
            # Remove existing Quad9/Google entries and add them at the top
            grep -vE "^\s*nameserver\s+($quad9_ns|$google_ns)" "$resolv_conf" > "${resolv_conf}.tmp"
            {
                echo "nameserver $quad9_ns"
                echo "nameserver $google_ns"
                cat "${resolv_conf}.tmp"
            } > "$resolv_conf"
            rm -f "${resolv_conf}.tmp"
            printf "\\033[1;32m[+] Set Quad9 as primary and Google as secondary in %s.\033[0m\\n" "$resolv_conf"
            printf "\\033[1;33m[!] Warning: Direct changes to %s might be overwritten by network management tools.\033[0m\\n" "$resolv_conf"
            changes_made=true
        else
            printf "\\033[1;31m[-] Could not modify %s (file not found or not writable).\033[0m\\n" "$resolv_conf"
        fi
    fi

    if [[ "$changes_made" = true ]]; then
        whiptail --infobox "DNS configured: Quad9 primary, Google secondary." 7 70
    else
        whiptail --infobox "DNS configuration checked. No changes made or needed." 8 70
    fi
}

enable_process_accounting_and_sysstat() {
    printf "\\033[1;31m[+] Enabling process accounting (acct) and system statistics (sysstat)...\033[0m\\n"
    local changed_acct changed_sysstat
	changed_acct=false
    changed_sysstat=false

    # Enable Process Accounting (acct/psacct)
    printf "\\033[1;34m[*] Checking and installing acct (process accounting)...\033[0m\\n"
    if ! dpkg -s acct >/dev/null 2>&1 && ! dpkg -s psacct >/dev/null 2>&1; then
        whiptail --infobox "Installing acct (process accounting)..." 7 60
        if apt-get install -y acct; then
            printf "\\033[1;32m[+] acct installed successfully.\033[0m\\n"
            changed_acct=true
        else
            printf "\\033[1;31m[-] Failed to install acct. Please check manually.\033[0m\\n"
        fi
    else
        printf "\\033[1;34m[*] acct/psacct is already installed.\033[0m\\n"
    fi

    if dpkg -s acct >/dev/null 2>&1 || dpkg -s psacct >/dev/null 2>&1; then
        if ! systemctl is-active --quiet acct && ! systemctl is-active --quiet psacct; then
            printf "\\033[1;33m[*] Attempting to enable and start acct/psacct service...\033[0m\\n"
            if systemctl enable --now acct 2>/dev/null || systemctl enable --now psacct 2>/dev/null; then
                printf "\\033[1;32m[+] acct/psacct service enabled and started.\033[0m\\n"
                changed_acct=true
            else
                printf "\\033[1;31m[-] Failed to enable/start acct/psacct service. It might need manual configuration or a reboot.\033[0m\\n"
            fi
        else
            printf "\\033[1;32m[+] acct/psacct service is already active.\033[0m\\n"
        fi
    fi

    # Enable Sysstat
    printf "\\033[1;34m[*] Checking and installing sysstat...\033[0m\\n"
    if ! dpkg -s sysstat >/dev/null 2>&1; then
        whiptail --infobox "Installing sysstat..." 7 60
        if apt-get install -y sysstat; then
            printf "\\033[1;32m[+] sysstat installed successfully.\033[0m\\n"
            changed_sysstat=true
        else
            printf "\\033[1;31m[-] Failed to install sysstat. Please check manually.\033[0m\\n"
        fi
    else
        printf "\\033[1;34m[*] sysstat is already installed.\033[0m\\n"
    fi

    if dpkg -s sysstat >/dev/null 2>&1; then
        local sysstat_conf
		sysstat_conf="/etc/default/sysstat"
        if [[ -f "$sysstat_conf" ]]; then
            if ! grep -qE '^\s*ENABLED="true"' "$sysstat_conf"; then
                printf "\\033[1;33m[*] Enabling sysstat data collection in %s...\033[0m\\n" "$sysstat_conf"
                sed -i 's/^\s*ENABLED="false"/ENABLED="true"/' "$sysstat_conf"
          
                if ! grep -qE '^\s*ENABLED=' "$sysstat_conf"; then
                    echo 'ENABLED="true"' >> "$sysstat_conf"
                fi
                changed_sysstat=true
                printf "\\033[1;32m[+] sysstat data collection enabled.\033[0m\\n"
            else
                printf "\\033[1;32m[+] sysstat data collection is already enabled in %s.\033[0m\\n" "$sysstat_conf"
            fi
        else
            # Fallback for systems where config might be /etc/sysstat/sysstat (e.g. RHEL based, but this is Debian focused)
            # For Debian, /etc/default/sysstat is standard.
            printf "\\033[1;33m[!] sysstat configuration file %s not found. Manual check might be needed.\033[0m\\n" "$sysstat_conf"
        fi

        if ! systemctl is-active --quiet sysstat; then
            printf "\\033[1;33m[*] Attempting to enable and start sysstat service...\033[0m\\n"
            if systemctl enable --now sysstat; then
                printf "\\033[1;32m[+] sysstat service enabled and started.\033[0m\\n"
                changed_sysstat=true
            else
                printf "\\033[1;31m[-] Failed to enable/start sysstat service.\033[0m\\n"
            fi
        else
            printf "\\033[1;32m[+] sysstat service is already active.\033[0m\\n"
        fi
    fi

    if [[ "$changed_acct" = true || "$changed_sysstat" = true ]]; then
        printf "\\033[1;32m[+] Process accounting (acct) and sysstat configured successfully.\033[0m\\n"
    else
        printf "\\033[1;32m[+] Process accounting (acct) and sysstat already configured or no changes needed.\033[0m\\n"
    fi
}

# Central logging
setup_central_logging() {
    {
        echo 10
        sleep 0.2
        printf "\033[1;31m[+] Setting up central logging for security tools...\033[0m\n"

        # Create necessary directories
        mkdir -p /var/log/suricata
        mkdir -p /usr/local/var/log/suricata
        touch /usr/local/var/log/suricata/hardn-xdr.log
        chmod 640 /usr/local/var/log/suricata/hardn-xdr.log
        chown root:adm /usr/local/var/log/suricata/hardn-xdr.log

        echo 20
        sleep 0.2

        # Create rsyslog configuration for centralized logging
        cat > /etc/rsyslog.d/30-hardn-xdr.conf << 'EOF'
# HARDN-XDR Central Logging Configuration

# Create a template for security logs
$template HARDNFormat,"%TIMESTAMP% %HOSTNAME% %syslogtag%%msg%\n"

# Suricata logs
if $programname == 'suricata' then /usr/local/var/log/suricata/hardn-xdr.log;HARDNFormat
& stop

# AIDE logs
if $programname == 'aide' then /usr/local/var/log/suricata/hardn-xdr.log;HARDNFormat
& stop

# Maldet logs
if $programname == 'maldet' or $syslogtag contains 'maldet' then /usr/local/var/log/suricata/hardn-xdr.log;HARDNFormat
& stop

# SELinux logs
if $programname == 'setroubleshoot' or $programname == 'audit' or $msg contains 'selinux' then /usr/local/var/log/suricata/hardn-xdr.log;HARDNFormat
& stop

# AppArmor logs
if $programname == 'apparmor' or $msg contains 'apparmor' then /usr/local/var/log/suricata/hardn-xdr.log;HARDNFormat
& stop

# Fail2Ban logs
if $programname == 'fail2ban' then /usr/local/var/log/suricata/hardn-xdr.log;HARDNFormat
& stop

# RKHunter logs
if $programname == 'rkhunter' or $syslogtag contains 'rkhunter' then /usr/local/var/log/suricata/hardn-xdr.log;HARDNFormat
& stop

# Debsums logs
if $programname == 'debsums' or $syslogtag contains 'debsums' then /usr/local/var/log/suricata/hardn-xdr.log;HARDNFormat
& stop
EOF

        echo 40
        sleep 0.2

        # Create logrotate configuration for the central log
        cat > /etc/logrotate.d/hardn-xdr << 'EOF'
/usr/local/var/log/suricata/hardn-xdr.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF

        echo 60
        sleep 0.2

        # Configure each tool to use syslog where possible

        # Configure Suricata to use syslog
        if [ -f /etc/suricata/suricata.yaml ]; then
            if ! grep -q "syslog:" /etc/suricata/suricata.yaml; then
                # Backup the original config
                cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak

                # Add syslog output configuration
                sed -i '/outputs:/a \
  - syslog:\n      enabled: yes\n      facility: local5\n      level: Info\n      format: "[%i] <%d> -- "' /etc/suricata/suricata.yaml
            fi
        fi

        # Configure AIDE to use syslog
        if [ -f /etc/aide/aide.conf ]; then
            if ! grep -q "report_syslog" /etc/aide/aide.conf; then
                echo "report_syslog=yes" >> /etc/aide/aide.conf
            fi
        fi

        # Configure RKHunter to use syslog
        if [ -f /etc/rkhunter.conf ]; then
            sed -i 's/^#\?USE_SYSLOG=.*/USE_SYSLOG=1/' /etc/rkhunter.conf
        fi

        echo 80
        sleep 0.2

        # Create a script to periodically check and consolidate logs that don't use syslog
        cat > /usr/local/bin/hardn-log-collector.sh << 'EOF'
#!/bin/bash

# HARDN-XDR Log Collector
# This script collects logs from various security tools and adds them to the central log

CENTRAL_LOG="/usr/local/var/log/suricata/hardn-xdr.log"
HOSTNAME=$(hostname)
DATE=$(date "+%b %d %H:%M:%S")

# Function to append logs with proper formatting
append_log() {
    local source="$1"
    local log_file="$2"

    if [ -f "$log_file" ]; then
        while IFS= read -r line; do
            echo "$DATE $HOSTNAME $source: $line" >> "$CENTRAL_LOG"
        done < <(tail -n 100 "$log_file" 2>/dev/null)
    fi
}

# Collect logs from tools that don't use syslog
append_log "maldet" "/var/log/maldet_scan.log"
append_log "debsums" "/var/log/debsums_cron.log"
append_log "aide" "/var/log/aide_check.log"
append_log "rkhunter" "/var/log/rkhunter_cron.log"
append_log "lynis" "/var/log/lynis_cron.log"
append_log "yara" "/var/log/yara_scan.log"

# Set proper permissions
chmod 640 "$CENTRAL_LOG"
chown root:adm "$CENTRAL_LOG"
EOF

        chmod +x /usr/local/bin/hardn-log-collector.sh

        # Add the log collector to crontab
        (crontab -l 2>/dev/null || true) > mycron
        if ! grep -q "hardn-log-collector.sh" mycron; then
            echo "*/30 * * * * /usr/local/bin/hardn-log-collector.sh" >> mycron
            crontab mycron
        fi
        rm mycron

        echo 90
        sleep 0.2

        # Restart rsyslog to apply changes
        systemctl restart rsyslog

        # Create a symlink in /var/log for easier access
        ln -sf /usr/local/var/log/suricata/hardn-xdr.log /var/log/hardn-xdr.log

        echo 100
        sleep 0.2
    } 

    printf "\033[1;32m[+] Central logging setup complete. All security logs will be collected in /usr/local/var/log/suricata/hardn-xdr.log\033[0m\n"
    printf "\033[1;32m[+] A symlink has been created at /var/log/hardn-xdr.log for easier access\033[0m\n"
}

disable_service_if_active() {
    local service_name
    service_name="$1"
    if systemctl is-active --quiet "$service_name"; then
        printf "\033[1;31m[+] Disabling active service: %s...\033[0m\n" "$service_name"
        systemctl disable --now "$service_name" || printf "\033[1;33m[!] Failed to disable service: %s (may not be installed or already disabled).\033[0m\n" "$service_name"
    elif systemctl list-unit-files --type=service | grep -qw "^$service_name.service"; then
        printf "\033[1;31m[+] Service %s is not active, ensuring it is disabled...\033[0m\n" "$service_name"
        systemctl disable "$service_name" || printf "\033[1;33m[!] Failed to disable service: %s (may not be installed or already disabled).\033[0m\n" "$service_name"
    else
        printf "\033[1;34m[*] Service %s not found or not installed. Skipping.\033[0m\n" "$service_name"
    fi
}

remove_unnecessary_services() {
    printf "\033[1;32m[+] Disabling unnecessary services...\033[0m\n"
    
    disable_service_if_active avahi-daemon
    disable_service_if_active cups
    disable_service_if_active rpcbind
    disable_service_if_active nfs-server
        disable_service_if_active smbd
    disable_service_if_active snmpd
    disable_service_if_active apache2
    disable_service_if_active mysql
    disable_service_if_active bind9

    # Remove packages if they exist
    packages_to_remove="telnet vsftpd proftpd tftpd postfix exim4"
    for pkg in $packages_to_remove; do
        if dpkg -s "$pkg" >/dev/null 2>&1; then
            printf "\033[1;31m[+] Removing package: %s...\033[0m\n" "$pkg"
            apt remove -y "$pkg"
        else
            printf "\033[1;34m[*] Package %s not installed. Skipping removal.\033[0m\n" "$pkg"
        fi
    done

    printf "\033[1;32m[+] Unnecessary services checked and disabled/removed where applicable.\033[0m\n"
}

pen_test() {
    printf "\\033[1;31m[+] Running penetration tests...\\033[0m\\n"
    if ! lynis audit system --pentest --quick 2>/dev/null; then
        printf "\\033[1;31m[-] Lynis audit failed. Please check your Lynis installation.\\033[0m\\n"
        return 1
    fi
    printf "\\033[1;32m[+] Penetration tests completed!\\033[0m\\n"
}


cleanup(){
    printf "\\033[1;31m[+] Cleaning up temporary files...\\033[0m\\n"
    rm -rf /tmp/* >/dev/null 2>&1
    apt autoremove -y >/dev/null 2>&1
    apt clean >/dev/null 2>&1
    apt update -y >/dev/null 2>&1
    printf "\\033[1;32m[+] Cleanup completed!\\033[0m\\n"

}



main() {
    print_ascii_banner
    welcomemsg
    update_system_packages
    install_package_dependencies "$progsfile"
    maininstall "hardn" "HARDN-XDR Main Program"
    build_hardn_package
    setup_security
    enable_process_accounting_and_sysstat
    enable_nameservers
    purge_old_packages
    disable_firewire_drivers
    restrict_compilers
    disable_binfmt_misc
    remove_unnecessary_services
    setup_central_logging
    pen_test
    cleanup

    printf "\\n\\033[1;32mHARDN-XDR installation completed, Please reboot your System.\\033[0m\\n"
}

main
