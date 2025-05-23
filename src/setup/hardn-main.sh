#!/bin/bash

# HARDN-XDR - The Linux Security Hardening Sentinel
# Developed and built by chris Bingham and Tim Burns
# credit due: larbs.xyz

repo="https://github.com/OpenSource-For-Freedom/HARDN/"
progsfile="https://github.com/OpenSource-For-Freedom/HARDN/progs.csv"
repobranch="main-patch"
name=$(whoami)


############# ADD MENU HERE #############



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
                                   Version 1.1.8
EOF
}


# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
        echo ""
        echo "This script must be run as root."
        exit 1
fi

installpkg() {
      
       dpkg -s "$1" >/dev/null 2>&1 || sudo apt install -y "$1" # Removed >/dev/null 2>&1 for install for better feedback if whiptail is not used
}

error() {
        printf "%s\n" "$1" >&2
        exit 1
}

welcomemsg() {
        whiptail --title "HARDN-XDR" --backtitle "HARDN OS Security" --fb \
            --msgbox "\n\n Welcome to HARDN-XDR a Debian Security tool for System Hardening" 15 60

        whiptail --title "HARDN-XDR" --backtitle "HARDN OS Security" --fb \
            --yes-button "HARDN" \
            --no-button "RETURN..." \
            --yesno "\n\n\nThis installer will update your system first..\n\n" 12 70
}

preinstallmsg() {
        whiptail --title "Welcome to HARDN. A Linux Security Hardening program." --yes-button "HARDN" \
            --no-button "RETURN" \
            --yesno "\n\n\nThe Building the Debian System to ensure STIG and Security compliance\n\n" 13 60 || {
            clear
            exit 1
    }
}

update_system_packages() {
    printf "\033[1;31m[+] Updating system packages...\033[0m\n"
    apt update && apt upgrade -y
    apt-get update -y
}

install_package_dependencies() {
        printf "\\033[1;31m[+] Installing package: %s...\\033[0m\\n" "$1" # Corrected color code and message
        local package_name="$1" 
            if ! dpkg -s "$package_name" >/dev/null 2>&1; then
                whiptail --infobox "Installing $package_name... ($2)" 7 60
                sudo apt update -qq # Corrected command
                sudo apt install -y "$package_name"
            else
                whiptail --infobox "$package_name is already installed." 7 60
            fi
}


aptinstall() {
    package="$1"
    comment="$2"
    whiptail --title "HARDN Installation" \\
        --infobox "Installing \`$package\` ($n of $total) from the repository. $comment" 9 70
    echo "$aptinstalled" | grep -q "^$package$" && return 1
    apt-get install -y "$package" >/dev/null 2>&1
    # Add to installed packages list
    aptinstalled="$aptinstalled\\n$package"
}

maininstall() {
  
    whiptail --title "HARDN Installation" --infobox "Installing \`$1\` ($n of $total). $1 $2" 9 70
    installpkg "$1"
}


gitdpkgbuild() {
        repo_url="$1"
        description="$2"
        dir="/tmp/$(basename "$repo_url" .git)"

        whiptail --infobox "Cloning $repo_url... ($description)" 7 70
        git clone --depth=1 "$repo_url" "$dir" >/dev/null 2>&1 || {
            whiptail --msgbox "Failed to clone $repo_url" 8 60
            return 1
        }
        cd "$dir" || { whiptail --msgbox "Failed to enter $dir" 8 60; return 1; }
        whiptail --infobox "Building and installing $description..." 7 70

  
        whiptail --infobox "Checking build dependencies for $description..." 7 70
        build_deps=$(dpkg-checkbuilddeps 2>&1 | grep -oP 'Unmet build dependencies: \K.*')
        if [ -n "$build_deps" ]; then
          whiptail --infobox "Installing build dependencies: $build_deps" 7 70
          apt-get install -y $build_deps >/dev/null 2>&1
        fi

        if [ -f debian/source/format ]; then
            dpkg-source --before-build . >/dev/null 2>&1
        fi

        if dpkg-buildpackage -us -uc >/dev/null 2>&1; then
          debfile=$(ls ../*.deb | head -n1)
          if [ -n "$debfile" ]; then
            dpkg -i "$debfile"
          else
            whiptail --msgbox "No .deb file found after build." 8 60
            return 1
          fi
        else
          whiptail --infobox "$description failed to build. Installing common build dependencies and retrying..." 10 60
          apt-get install -y build-essential debhelper libpam-tmpdir apt-listbugs devscripts git-buildpackage >/dev/null 2>&1
          if dpkg-buildpackage -us -uc >/dev/null 2>&1; then
            debfile=$(ls ../*.deb | head -n1)
            if [ -n "$debfile" ]; then
              dpkg -i "$debfile"
            else
              whiptail --msgbox "No .deb file found after retry." 8 60
              return 1
            fi
          else
            whiptail --msgbox "$description failed to build after retry. Please check build dependencies." 10 60
            return 1
          fi
        fi
}

build_hardn_package() {
    set -e  
    build_deps="debhelper-compat devscripts git-buildpackage"
    whiptail --infobox "Installing build dependencies: $build_deps" 7 60
    for pkg in $build_deps; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        echo "[+] Installing missing dependencies: $pkg" 
            apt-get install -y "$pkg" >/dev/null 2>&1
        fi
    done 

    whiptail --infobox "Building HARDN Debian package..." 7 60

    temp_dir=$(mktemp -d)
    cd "$temp_dir"

    git clone --depth=1 -b "$repobranch" "$repo"
    cd HARDN

    whiptail --infobox "Running dpkg-buildpackage..." 7 60
    dpkg-buildpackage -us -uc

    cd ..
    whiptail --infobox "Installing HARDN package..." 7 60
    dpkg -i hardn_*.deb || true  

    apt-get install -f -y

    cd /
    rm -rf "$temp_dir"

    whiptail --infobox "HARDN package installed successfully" 7 60
}



installationloop() {
       
        if [[ "$progsfile" == http* ]]; then
            curl -Ls "$progsfile" | sed '/^#/d' > /tmp/progs.csv
        elif [ -f "$progsfile" ]; then
            sed '/^#/d' < "$progsfile" > /tmp/progs.csv
        else
            whiptail --title "Error" --msgbox "progs.csv file not found at $progsfile and not a valid URL." 8 70
            return 1
        fi

        total=$(wc -l </tmp/progs.csv)
        echo "[INFO] Found $total entries to process."
        aptinstalled=$(apt-mark showmanual)
        while IFS=, read -r tag program comment; do
            n=$((n + 1))
            echo "➤ Processing: $program [$tag]"

      
            echo "$comment" | grep -q "^\".*\"$" &&
                comment="$(echo "$comment" | sed -E "s/(^\"|\"$)//g")"

            case "$tag" in
                a) aptinstall "$program" "$comment" ;;
                G) gitdpkgbuild "$program" "$comment" ;;
                *) 
                   if [ -z "$program" ]; then
                       whiptail --title "Warning" --msgbox "Skipping empty program entry (Tag: $tag, Line: $n)" 8 70
                   else
                       maininstall "$program" "$comment"
                   fi
                   ;;
            esac
        done </tmp/progs.csv
}

putgitrepo() {
        printf "\\033[1;32m[+] Downloading and installing files...\\033[0m\\n"
        local branch
      
        
        [ -z "$3" ] && branch="master" || branch="$repobranch"
        
        local dir
        dir=$(mktemp -d)

        if [ -z "$2" ]; then
            whiptail --title "Error" --msgbox "Target directory for git repository is not specified." 8 70
            rm -rf "$dir" # Clean up temp dir
            return 1
        fi
   
        mkdir -p "$2"

       
        chown "$name":"$(id -gn "$name")" "$dir" # Ownership for temp dir
        chown "$name":"$(id -gn "$name")" "$2" # Ownership for target dir

        if [ -z "$1" ]; then
            whiptail --title "Error" --msgbox "Git repository URL is not specified." 8 70
            rm -rf "$dir" # Clean up temp dir
            return 1
        fi


        if ! sudo -u "$name" git clone --depth 1 \\
            --single-branch --no-tags -q --recursive -b "$branch" \\
            --recurse-submodules "$1" "$dir"; then
            whiptail --title "Error" --msgbox "Failed to clone repository: $1" 8 70
            rm -rf "$dir" # Clean up temp dir
            return 1
        fi
        
      
        if ! sudo -u "$name" cp -rfT "$dir" "$2"; then
            whiptail --title "Error" --msgbox "Failed to copy files from $dir to $2" 8 70
            rm -rf "$dir" # Clean up temp dir
            return 1
        fi
        
        rm -rf "$dir" # Clean up temp dir
}

enable_selinux() {
        printf "\033[1;31m[+] Installing and configuring SELinux...\033[0m\n"

        setenforce 1 2>/dev/null || whiptail --msgbox "Could not set SELinux to enforcing mode immediately" 8 60

        if [ -f /etc/selinux/config ]; then
            sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config
            sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config
            whiptail --infobox "SELinux configured to enforcing mode at boot" 7 60
        else
            whiptail --msgbox "SELinux config file not found" 8 60
        fi

        whiptail --infobox "SELinux installation and configuration completed" 7 60
}


check_security_tools() {
  printf "\033[1;31m[+] Checking for security packages are installed...\033[0m\n"
        for pkg in ufw fail2ban apparmor apparmor-profiles apparmor-utils firejail tcpd lynis debsums rkhunter libpam-pwquality libvirt-daemon-system libvirt-clients qemu-kvm docker.io docker-compose openssh-server ; do
            if ! dpkg -s "$pkg" >/dev/null 2>&1; then
                whiptail --infobox "Installing $pkg..." 7 60
                apt install -y "$pkg"
            else
                whiptail --infobox "$pkg is already installed." 7 60
            fi
        done
}

enable_suricata() {
    {
        echo 10
        sleep 0.2
        printf "\033[1;31m[+] Enabling Suricata...\033[0m\n"
        if ! dpkg -s suricata >/dev/null 2>&1; then
            echo 30
            sleep 0.2
            printf "\033[1;31m[+] Installing Suricata...\033[0m\n"
            apt install -y suricata >/dev/null 2>&1
        else
            echo 30
            sleep 0.2
            printf "\033[1;31m[+] Suricata is already installed.\033[0m\n"
        fi
        echo 70
        sleep 0.2
        systemctl enable --now suricata >/dev/null 2>&1
        echo 100
        sleep 0.2
    } | whiptail --gauge "Installing and enabling Suricata..." 8 60 0
}


enable_rkhunter() {
    {
        echo 10
        sleep 0.2
        printf "\033[1;31m[+] Enabling rkhunter...\033[0m\n"
        if ! dpkg -s rkhunter >/dev/null 2>&1; then
            whiptail --infobox "Installing rkhunter..." 7 60
            apt install -y rkhunter
        else
            whiptail --infobox "rkhunter is already installed." 7 60
        fi
        echo 40
        sleep 0.2

        
        sed -i 's/^#\?ENABLE_TESTS=.*/ENABLE_TESTS=all/' /etc/rkhunter.conf
        sed -i 's/^#\?MAIL-ON-WARNING=.*/MAIL-ON-WARNING="root"/' /etc/rkhunter.conf
        sed -i 's/^#\?MAIL-ON-ERROR=.*/MAIL-ON-ERROR="root"/' /etc/rkhunter.conf
        echo 60
        sleep 0.2

        
        rkhunter --update --quiet
        rkhunter --propupd --quiet
        echo 100
        sleep 0.2
    } | whiptail --gauge "Installing and configuring rkhunter..." 8 60 0

    printf "\033[1;32m[+] rkhunter installed and configured.\033[0m\n"
}

configure_firejail() {
    {
        echo 10
        sleep 0.2
        printf "\033[1;31m[+] Configuring Firejail for Firefox, Chrome, Brave, and Tor Browser...\033[0m\n"

        if ! command -v firejail > /dev/null 2>&1; then
            printf "\033[1;31m[-] Firejail is not installed. Please install it first.\033[0m\n"
            echo 100
            sleep 0.2
            return 1
        fi
        echo 20
        sleep 0.2

        if command -v firefox > /dev/null 2>&1; then
            printf "\033[1;31m[+] Setting up Firejail for Firefox...\033[0m\n"
            ln -sf /usr/bin/firejail /usr/local/bin/firefox
        else
            printf "\033[1;31m[-] Firefox is not installed. Skipping Firejail setup for Firefox.\033[0m\n"
        fi
        echo 40
        sleep 0.2

        if command -v google-chrome > /dev/null 2>&1; then
            printf "\033[1;31m[+] Setting up Firejail for Google Chrome...\033[0m\n"
            ln -sf /usr/bin/firejail /usr/local/bin/google-chrome
        else
            printf "\033[1;31m[-] Google Chrome is not installed. Skipping Firejail setup for Chrome.\033[0m\n"
        fi
        echo 60
        sleep 0.2

        if command -v brave-browser > /dev/null 2>&1; then
            printf "\033[1;31m[+] Setting up Firejail for Brave Browser...\033[0m\n"
            ln -sf /usr/bin/firejail /usr/local/bin/brave-browser
        else
            printf "\033[1;31m[-] Brave Browser is not installed. Skipping Firejail setup for Brave.\033[0m\n"
        fi
        echo 80
        sleep 0.2

        if command -v torbrowser-launcher > /dev/null 2>&1; then
            printf "\033[1;31m[+] Setting up Firejail for Tor Browser...\033[0m\n"
            ln -sf /usr/bin/firejail /usr/local/bin/torbrowser-launcher
        else
            printf "\033[1;31m[-] Tor Browser is not installed. Skipping Firejail setup for Tor Browser.\033[0m\n"
        fi
        echo 100
        sleep 0.2

        printf "\033[1;31m[+] Firejail configuration completed.\033[0m\n"
    } | whiptail --gauge "Configuring Firejail for browsers..." 8 60 0
}

configure_ufw() {
        printf "\\033[1;31m[+] Configuring UFW...\\033[0m\\n" # Corrected printf
        
      
        if ! ufw status | grep -qw active; then
            printf "\\033[1;33m[*] UFW is not active. Enabling...\\033[0m\\n" # Corrected printf
            yes | ufw enable 
        fi

        ufw default deny incoming
        ufw default allow outgoing
        
        
        ufw allow ssh 
        
        
        ufw allow out to any port 53 proto tcp
        ufw allow out to any port 80 proto tcp
        ufw allow out to any port 443 proto tcp
        
        
        ufw allow out to any port 53 proto udp
        ufw allow out to any port 123 proto udp
        
        
        ufw allow out to any port 67 proto udp
        ufw allow out to any port 68 proto udp

       
        if ufw status | grep -qw active; then
            printf "\\033[1;31m[+] Reloading UFW rules...\\033[0m\\n" # Corrected printf
            ufw reload
        else
            printf "\\033[1;31m[-] UFW is not active, cannot reload. Please check UFW status manually.\\033[0m\\n" # Corrected printf
        fi
}

enable_yara() {
    printf "\\033[1;31m[+] Configuring YARA rules...\\033[0m\\n"
    whiptail --title "YARA Notice" --msgbox "The 'YARA' tool will be configured to scan for malware and suspicious files. You can review the logs in /var/log/yara_scan.log." 12 70

    {
        echo 5
        sleep 0.2

        if ! command -v yara >/dev/null 2>&1; then
            printf "\\033[1;31m[+] Configuring YARA...\\033[0m\\n"
            DEBIAN_FRONTEND=noninteractive apt-get -y install yara || {
                printf "\\033[1;31m[-] Failed to install YARA.\\033[0m\\n"
                echo 100
                sleep 0.2
                return 1
            }
        fi
        echo 15
        sleep 0.2

        yara_rules_dir="/etc/yara/rules"
        mkdir -p "$yara_rules_dir"
        echo 20
        sleep 0.2

        printf "\\033[1;31m[+] Downloading YARA rules...\\033[0m\\n"
        yara_rules_zip="/tmp/yara-rules.zip"
        if ! wget -q "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip" -O "$yara_rules_zip"; then
            printf "\\033[1;31m[-] Failed to download YARA rules.\\033[0m\\n"
            echo 100
            sleep 0.2
            return 1
        fi
        echo 30
        sleep 0.2

        tmp_extract_dir="/tmp/yara-rules-extract"
        mkdir -p "$tmp_extract_dir"

        printf "\\033[1;31m[+] Extracting YARA rules...\\033[0m\\n"
        if ! unzip -q -o "$yara_rules_zip" -d "$tmp_extract_dir"; then
            printf "\\033[1;31m[-] Failed to extract YARA rules.\\033[0m\\n"
            rm -f "$yara_rules_zip"
            rm -rf "$tmp_extract_dir"
            echo 100
            sleep 0.2
            return 1
        fi
        echo 40
        sleep 0.2

        rules_dir=$(find "$tmp_extract_dir" -type d -name "rules-*" | head -n 1)
        if [ -z "$rules_dir" ]; then
            printf "\\033[1;31m[-] Failed to find extracted YARA rules directory.\\033[0m\\n"
            rm -f "$yara_rules_zip"
            rm -rf "$tmp_extract_dir"
            echo 100
            sleep 0.2
            return 1
        fi
        echo 50
        sleep 0.2

        printf "\\033[1;31m[+] Copying YARA rules to $yara_rules_dir...\\033[0m\\n"
        cp -rf "$rules_dir"/* "$yara_rules_dir/" || {
            printf "\\033[1;31m[-] Failed to copy YARA rules.\\033[0m\\n"
            rm -f "$yara_rules_zip"
            rm -rf "$tmp_extract_dir"
            echo 100
            sleep 0.2
            return 1
        }
        echo 60
        sleep 0.2

        printf "\\033[1;31m[+] Setting proper permissions on YARA rules...\\033[0m\\n"
        chown -R root:root "$yara_rules_dir"
        chmod -R 644 "$yara_rules_dir"
        find "$yara_rules_dir" -type d -exec chmod 755 {} \\;
        echo 65
        sleep 0.2

        if [ ! -f "$yara_rules_dir/index.yar" ]; then
            printf "\\033[1;31m[+] Creating index.yar file for YARA rules...\\033[0m\\n"
            find "$yara_rules_dir" -name "*.yar" -not -name "index.yar" | while read -r rule_file; do
                echo "include \\"${rule_file#$yara_rules_dir/}\\"" >> "$yara_rules_dir/index.yar"
            done
        fi
        echo 70
        sleep 0.2

        printf "\\033[1;31m[+] Testing YARA functionality...\\033[0m\\n"
        if ! yara -r "$yara_rules_dir/index.yar" /tmp >/dev/null 2>&1; then
            printf "\\033[1;33m[!] YARA test failed. Rules might need adjustment.\\033[0m\\n"
            echo 'rule test_rule {strings: $test = "test" condition: $test}' > "$yara_rules_dir/test.yar"
            # You might want to add a re-test here or specific error handling
        else
            printf "\\033[1;32m[+] YARA rules successfully installed and tested.\\033[0m\\n"
        fi
        echo 80
        sleep 0.2

        printf "\\033[1;31m[+] Setting up YARA scanning in crontab...\\033[0m\\n"
        touch /var/log/yara_scan.log
        chmod 640 /var/log/yara_scan.log
        chown root:adm /var/log/yara_scan.log
        
        (crontab -l 2>/dev/null | grep -v "/usr/bin/yara.*$yara_rules_dir/index.yar" ; \
         echo "0 2 * * * /usr/bin/yara -r $yara_rules_dir/index.yar /home /var /tmp >> /var/log/yara_scan.log 2>&1") | crontab -
        
        echo 90
        sleep 0.2

        printf "\\033[1;31m[+] Cleaning up temporary YARA files...\\033[0m\\n"
        rm -f "$yara_rules_zip"
        rm -rf "$tmp_extract_dir"
        echo 100
        sleep 0.2
    } | whiptail --gauge "Installing and configuring YARA..." 8 60 0

    printf "\\033[1;32m[+] YARA configuration completed successfully.\\033[0m\n"
}

check_promiscuous_mode() {
    printf "\\033[1;31m[+] Checking for network interfaces in promiscuous mode...\\033[0m\\n"
    local promiscuous_interfaces
    promiscuous_interfaces=$(ip -d link show | grep -B1 'PROMISC' | grep '^[0-9]' | awk -F':' '{print $2}' | awk '{print $1}')

    if [ -z "$promiscuous_interfaces" ]; then
        whiptail --infobox "No network interfaces found in promiscuous mode." 7 60
        return 0
    fi

    for iface in $promiscuous_interfaces; do
        if (whiptail --title "Promiscuous Mode Detected" --yesno "Interface '$iface' is in promiscuous mode. This might be a security risk if not intentional.\n\nIs promiscuous mode REQUIRED for this interface (e.g., for a network sensor)?" 12 78); then
            whiptail --infobox "Promiscuous mode for '$iface' will be kept enabled as per user confirmation." 7 70
        else
            printf "\\033[1;33m[*] Attempting to disable promiscuous mode for interface '$iface'...\\033[0m\\n"
            if ip link set dev "$iface" promisc off; then
                whiptail --infobox "Promiscuous mode disabled for '$iface'. This change might be temporary. You may need to adjust your network configuration files to make it permanent." 10 78
            else
                whiptail --msgbox "Failed to disable promiscuous mode for '$iface'. Please check manually." 8 70
            fi
        fi
    done
    printf "\\033[1;32m[+] Promiscuous mode check completed.\\033[0m\\n"
}

disable_usb_storage() {
    printf "\\033[1;31m[+] Disabling USB storage (modprobe)...\\033[0m\\n"
    if ! grep -q "install usb-storage /bin/true" /etc/modprobe.d/disable-usb-storage.conf; then
        echo "install usb-storage /bin/true" > /etc/modprobe.d/disable-usb-storage.conf
        whiptail --infobox "USB storage has been disabled. A reboot may be required." 7 60
    else
        whiptail --infobox "USB storage is already configured to be disabled." 7 60
    fi
    modprobe -r usb-storage 2>/dev/null || true
}

enhance_fail2ban() {
    printf "\\033[1;31m[+] Enhancing Fail2Ban configuration...\\033[0m\\n"
    if [ ! -f /etc/fail2ban/jail.local ]; then
        cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    fi

    if ! grep -q "^\\[sshd\\]" /etc/fail2ban/jail.local; then
        printf "\\n[sshd]\\nenabled = true\\nport = ssh\\nlogpath = %%(sshd_log)s\\nbackend = %%(sshd_backend)s\\n" >> /etc/fail2ban/jail.local
    elif ! grep -q "^\\[sshd\\]\\nenabled = true" /etc/fail2ban/jail.local && grep -q "^\\[sshd\\]" /etc/fail2ban/jail.local; then
        sed -i '/^\[sshd\]/a enabled = true' /etc/fail2ban/jail.local
    fi
   #  more aggressive ban time:
    # sed -i 's/bantime  = 10m/bantime  = 1h/g' /etc/fail2ban/jail.local
    # sed -i 's/findtime  = 10m/findtime  = 10m/g' /etc/fail2ban/jail.local
    # sed -i 's/maxretry = 5/maxretry = 3/g' /etc/fail2ban/jail.local
    
    systemctl restart fail2ban || whiptail --msgbox "Failed to restart Fail2Ban. Check configuration." 8 60
    whiptail --infobox "Fail2Ban configuration enhanced and restarted." 7 60
}

finalize() {
    whiptail --title "HARDN-XDR Hardening Complete" --msgbox \
        "All selected hardening tasks have been applied.\\n\\n\
It is highly recommended to REBOOT your system for all changes to take full effect.\\n\\n\
Please review all logs and check system functionality." 15 70
    printf "\\033[1;32m[+] HARDN-XDR hardening tasks complete. Please reboot.\\033[0m\\n"
}

grub_security() {
    printf \"\\\\\\\\033[1;31m[+] Securing GRUB bootloader...\\\\\\\\033[0m\\\\\\\\n\"

    if ! command -v grub-mkpasswd-pbkdf2 >/dev/null 2>&1; then
        whiptail --title "GRUB Utility Missing" --yesno "The 'grub-mkpasswd-pbkdf2' command was not found. This is needed to set a GRUB password. \\\\\\\\n\\\\\\\\nAttempt to install 'grub2-common' package which should provide this utility?" 12 78
        if [ $? -eq 0 ]; then
            whiptail --infobox "Installing grub2-common..." 7 60
            if apt-get update -qq && apt-get install -y grub2-common; then
                whiptail --infobox "'grub2-common' installed successfully." 7 60
                if ! command -v grub-mkpasswd-pbkdf2 >/dev/null 2>&1; then
                    whiptail --msgbox "Installation of 'grub2-common' complete, but 'grub-mkpasswd-pbkdf2' is still not found. Skipping GRUB password setup." 10 78
                    return 1
                fi
            else
                whiptail --msgbox "Failed to install 'grub2-common'. Skipping GRUB password setup." 10 78
                return 1
            fi
        else
            whiptail --infobox "Skipping GRUB password setup as 'grub-mkpasswd-pbkdf2' is not available." 7 78
            return 1
        fi
    fi

    if [ ! -d /etc/grub.d ] || [ ! -f /etc/grub.d/00_header ] || [ ! -f /etc/grub.d/10_linux ]; then
        whiptail --msgbox "GRUB configuration files (e.g., /etc/grub.d/00_header, /etc/grub.d/10_linux) not found. GRUB might not be installed or configured in a standard way. Skipping GRUB password setup." 12 78
        return 1
    fi

    if command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt --quiet; then
        if ! (whiptail --title "Virtual Machine Detected" --yesno \\
            "This script appears to be running in a virtual machine. GRUB password protection might be ineffective or managed by the hypervisor (e.g., console access might bypass GRUB password, or boot order is managed externally).\\\\\\\\n\\\\\\\\nGRUB hardening is generally less critical or might not function as expected in VMs.\\\\\\\\n\\\\\\\\nDo you still want to proceed with GRUB password setup for this VM?" 18 78); then
            whiptail --infobox "GRUB password setup skipped as this is a virtual machine and user chose not to proceed." 8 78
            return 0
        fi
    fi

    local grub_user="root"
    local grub_password_hash

    if ! grub_password_hash=$(whiptail --passwordbox "Enter a strong password for GRUB user '$grub_user':" 10 78 3>&1 1>&2 2>&3); then
        whiptail --infobox "GRUB password entry cancelled. Skipping GRUB password setup." 8 78
        return 1
    fi
    if [ -z "$grub_password_hash" ]; then
        whiptail --infobox "No GRUB password entered. Skipping GRUB password setup." 8 78
        return 1
    fi

    local hashed_password
    hashed_password=$(echo -e "$grub_password_hash\\\\n$grub_password_hash" | grub-mkpasswd-pbkdf2 | awk '/grub.pbkdf2/{print $NF}')

    if [ -z "$hashed_password" ]; then
        whiptail --msgbox "Failed to generate GRUB password hash. Skipping GRUB password setup." 10 78
        return 1
    fi

    whiptail --infobox "Setting GRUB password. This will modify GRUB configuration files." 8 78
    
    cp /etc/grub.d/00_header /etc/grub.d/00_header.bak_$(date +%F-%T) || printf "Warning: Failed to backup /etc/grub.d/00_header\\\\\\\\n"
    cp /etc/default/grub /etc/default/grub.bak_$(date +%F-%T) || printf "Warning: Failed to backup /etc/default/grub\\\\\\\\n"

    cat << 'EOF_GRUB_HEADER' | tee -a /etc/grub.d/00_header > /dev/null
cat << EOF
set superusers="${grub_user}"
password_pbkdf2 ${grub_user} ${hashed_password}
EOF
EOF_GRUB_HEADER

    sed -i '/GRUB_CMDLINE_LINUX_DEFAULT/s/unrestricted//g' /etc/default/grub
    
    sed -i 's/ --unrestricted/ /g' /etc/grub.d/10_linux

    if update-grub; then
        whiptail --msgbox "GRUB configuration updated and password set for user '$grub_user'.\\\\\\\\nIMPORTANT: Test this configuration thoroughly, especially console access and boot process, before relying on it in a production environment." 12 78
    else
        whiptail --msgbox "Failed to update GRUB configuration (update-grub). Review any errors. GRUB password may not be set correctly. Consider restoring backups: /etc/grub.d/00_header.bak_... and /etc/default/grub.bak_..." 12 78
        return 1
    fi
    printf \"\\\\\\\\033[1;32m[+] GRUB secured.\\\\\\\\033[0m\\\\\\\\n\"
    return 0
}

reload_apparmor() {
    printf "\\033[1;31m[+] Reloading AppArmor profiles...\\033[0m\\n"
    if command -v aa-enforce > /dev/null && [ -d /etc/apparmor.d ]; then
        aa-enforce /etc/apparmor.d/* || systemctl reload apparmor || whiptail --msgbox "Failed to reload AppArmor profiles." 8 60
        whiptail --infobox "AppArmor profiles reloaded." 7 60
    else
        whiptail --infobox "AppArmor not found or no profiles to load." 7 60
    fi
}

restrict_compilers() {
    printf "\\033[1;31m[+] Restricting access to compilers...\\033[0m\\n"
    local compilers=("gcc" "g++" "cc" "c++" "clang" "clang++") 
    local restricted_group="devs" 

    if ! getent group "$restricted_group" >/dev/null; then
        groupadd "$restricted_group"
        whiptail --infobox "Created group '$restricted_group' for compiler access." 7 60
    fi
    
    chown root:"$restricted_group" /usr/bin/dpkg-statoverride
    chmod 0750 /usr/bin/dpkg-statoverride

    for compiler_path in $(command -v "${compilers[@]}" 2>/dev/null); do
        if [ -x "$compiler_path" ]; then
            # dpkg-statoverride --update --add root "$restricted_group" 0750 "$compiler_path"
            chown root:"$restricted_group" "$compiler_path"
            chmod 0750 "$compiler_path"
            printf "  Restricted: %s\\n" "$compiler_path"
        fi
    done
    whiptail --infobox "Compiler access restricted to root and group '$restricted_group'. Add users to this group as needed." 10 70
}

stig_disable_core_dumps() {
    printf "\\033[1;31m[+] Disabling system-wide core dumps...\\033[0m\\n"
    local limits_conf="/etc/security/limits.d/disable-core-dumps.conf"
    if ! grep -q "^\* hard core 0" "$limits_conf" 2>/dev/null; then
        echo "* hard core 0" > "$limits_conf"
        whiptail --infobox "Core dumps disabled via limits.conf. Kernel setting fs.suid_dumpable=0 also applied." 8 70
    else
        whiptail --infobox "Core dump disabling rule already exists in limits.conf." 7 60
    fi
}

stig_enable_auditd() {
    printf "\\033[1;31m[+] Installing and configuring auditd...\\033[0m\\n"
    if ! dpkg -s auditd audispd-plugins >/dev/null 2>&1; then
        whiptail --infobox "Installing auditd and audispd-plugins..." 7 60
        apt-get update -qq
        apt-get install -y auditd audispd-plugins || {
            whiptail --msgbox "Failed to install auditd." 8 60
            return 1
        }
    fi

    # Basic audit rules (example, can be expanded from STIG checklist)
    audit_rules_file="/etc/audit/rules.d/stig.rules"
    cat <<EOFAUDIT > "$audit_rules_file"
# Audit rule for STIG compliance 
# Monitor changes to time and timezone
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change
-w /etc/localtime -p wa -k time-change

# Monitor module loading/unloading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Monitor login/logout events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Monitor changes to user/group information
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor changes to network configuration
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale

# Make the audit configuration immutable (optional, requires reboot to change)
# -e 2
EOFAUDIT

    augenrules --load || whiptail --msgbox "Failed to load auditd rules. Check $audit_rules_file" 8 60
    systemctl enable auditd >/dev/null 2>&1
    systemctl restart auditd || whiptail --msgbox "Failed to start/restart auditd." 8 60
    whiptail --infobox "auditd installed, configured with basic STIG rules, and enabled." 8 70
}

stig_file_permissions() {
    printf "\\033[1;31m[+] Setting restrictive file permissions (umask)...\\033[0m\\n"
    # Set umask to 027 for users, 077 for root (more restrictive)
    echo "umask 027" >> /etc/profile
    echo "umask 027" >> /etc/bash.bashrc
    # For root specifically, can be set in /root/.bashrc or /etc/login.defs
    sed -i 's/^UMASK.*/UMASK           077/' /etc/login.defs
    umask 077
    whiptail --infobox "Default umask set to 027 (users) and 077 (root). New files will have restricted permissions." 9 70
}

stig_password_policy() {
    printf "\\033[1;31m[+] Configuring password hashing rounds in /etc/login.defs...\\033[0m\\n"
    local login_defs="/etc/login.defs"

    sed -i '/^SHA_CRYPT_MIN_ROUNDS/d' "$login_defs"
    sed -i '/^SHA_CRYPT_MAX_ROUNDS/d' "$login_defs"

    echo "SHA_CRYPT_MIN_ROUNDS 5000" >> "$login_defs"
    echo "SHA_CRYPT_MAX_ROUNDS 10000" >> "$login_defs"

    if grep -q "^SHA_CRYPT_MIN_ROUNDS 5000" "$login_defs" && grep -q "^SHA_CRYPT_MAX_ROUNDS 10000" "$login_defs"; then
        whiptail --infobox "Password hashing rounds (SHA_CRYPT_MIN_ROUNDS, SHA_CRYPT_MAX_ROUNDS) set in $login_defs." 8 78
    else
        whiptail --msgbox "Failed to set password hashing rounds in $login_defs. Please check manually." 8 78
    fi
}

disable_uncommon_network_protocols() {
    printf "\\033[1;31m[+] Disabling uncommon network protocols (dccp, sctp, rds, tipc)...\\033[0m\\n"
    local conf_file="/etc/modprobe.d/blacklist-uncommon-network.conf"
    local protocols_disabled=0

  
    cat << EOF > "$conf_file"
# Disable uncommon network protocols as per security recommendations (NETW-3200)
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF

    if [ -f "$conf_file" ] && grep -q "install dccp /bin/true" "$conf_file"; then
        modprobe -r dccp 2>/dev/null || true
        modprobe -r sctp 2>/dev/null || true
        modprobe -r rds 2>/dev/null || true
        modprobe -r tipc 2>/dev/null || true
        whiptail --infobox "Uncommon network protocols (dccp, sctp, rds, tipc) blacklisted. A reboot may be required for changes to fully apply." 10 78
        protocols_disabled=1
    else
        whiptail --msgbox "Failed to create or write to $conf_file. Please check permissions and try again." 8 78
    fi

    if [ "$protocols_disabled" -eq 1 ]; then
        printf "\\033[1;32m[+] Uncommon network protocols successfully configured for disabling.\\033[0m\\n"
    else
        printf "\\033[1;31m[-] Failed to disable uncommon network protocols.\\033[0m\\n"
    fi
}

set_legal_banners() {
    printf "\\033[1;31m[+] Setting legal banners for /etc/issue and /etc/issue.net...\\033[0m\\n"
    
    local banner_text
    banner_text="*******************************************************************************
*                                                                             *
*   ATTENTION: This is a Security International Group (SIG) Information System.   *
*   Authorized use only. All activity is subject to monitoring and auditing.   *
*   Unauthorized access or use may result in civil and criminal penalties.      *
*                                                                             *
*******************************************************************************"

    
    echo -e "$banner_text\\n" > /etc/issue
    echo "Kernel \\r on an \\m" >> /etc/issue
    
    echo -e "$banner_text\\n" > /etc/issue.net

    if grep -q "WARNING: This system is for authorized use only." /etc/issue && \
       grep -q "WARNING: This system is for authorized use only." /etc/issue.net; then
        whiptail --infobox "Legal banners set for /etc/issue and /etc/issue.net." 8 78
        printf "\\033[1;32m[+] Legal banners successfully set.\\033[0m\\n"
    else
        whiptail --msgbox "Failed to set legal banners. Please check /etc/issue and /etc/issue.net manually." 8 78
        printf "\\033[1;31m[-] Failed to set legal banners.\\033[0m\\n"
    fi
}

stig_hardn_services() {
    printf "\\033[1;31m[+] Hardening system services (disabling unnecessary ones)...\\033[0m\\n"
.
    local services_to_disable=(
        "telnet.socket" "rsh.socket" "rlogin.socket" "rexec.socket" # Insecure legacy services
        "avahi-daemon" # Zeroconf networking, often not needed on servers
        "cups" # Printing service, if not a print server
        # "nfs-server" "rpcbind" # If not an NFS server
        # "smbd" "nmbd" # If not a Samba server
        # "apache2" "nginx" # If not a web server (or manage them specifically)
        # "vsftpd" # If not an FTP server
    )
    local disabled_count=0
    local not_found_count=0

    for service in "${services_to_disable[@]}"; do
        if systemctl list-unit-files --type=service,socket | grep -q "^${service}\\s"; then
            if systemctl is-enabled "$service" &>/dev/null; then
                systemctl stop "$service" &>/dev/null
                systemctl disable "$service" &>/dev/null
                printf "  Disabled: %s\\n" "$service"
                disabled_count=$((disabled_count + 1))
            else
                printf "  Already disabled or inactive: %s\\n" "$service"
            fi
        else
            printf "  Service not found: %s\\n" "$service"
            not_found_count=$((not_found_count + 1))
        fi
    done
    whiptail --infobox "Checked services. Disabled $disabled_count services. $not_found_count services not found." 8 70
}

stig_lock_inactive_accounts() {
    printf "\\033[1;31m[+] Configuring automatic locking of inactive accounts...\\033[0m\\n"
    local inactive_days=35 # STIG requirement often suggests 35 days

    # Configure in /etc/default/useradd
    if grep -q "^INACTIVE=" /etc/default/useradd; then
        sed -i "s/^INACTIVE=.*/INACTIVE=${inactive_days}/" /etc/default/useradd
    else
        echo "INACTIVE=${inactive_days}" >> /etc/default/useradd
    fi
    whiptail --infobox "New users will be locked after $inactive_days days of inactivity. Existing users need manual check." 9 70
    
    if (whiptail --title "Lock Existing Inactive Accounts" --yesno "Scan and lock existing user accounts inactive for more than $inactive_days days?\\n(Review carefully, system accounts might be affected if not excluded)" 12 78); then
        local excluded_users="root,daemon,bin,sys,sync,games,man,lp,mail,news,uucp,proxy,www-data,backup,list,irc,gnats,nobody,_apt,systemd-network,systemd-resolve,systemd-timesync,messagebus,sshd,landscape,pollinate,usbmux,dnsmasq,tcpdump"
        local users_locked_or_to_remove=()

        lastlog -b "$inactive_days" | tail -n +2 | while IFS= read -r line; do
            user=$(echo "$line" | awk '{print $1}')
            # Check if user is in excluded list
            if ! echo ",$excluded_users," | grep -q ",$user,"; then
                # Check if user has a valid shell (likely a real user)
                if grep -q "^$user:.*:/bin/.*sh$" /etc/passwd; then
                     if (whiptail --title "Confirm Lock" --yesno "Lock user \'$user\' (last login: $(echo "$line" | awk '{for (i=4;i<=NF;i++) printf $i " "; print ""}'))?" 10 70); then
                        usermod -L "$user"
                        passwd -l "$user" # Also lock password
                        printf "  Locked user: %s\\n" "$user"
                        users_locked_or_to_remove+=("$user")
                     fi
                fi
            fi
        done
        whiptail --infobox "Checked and potentially locked existing inactive user accounts." 7 70

        if [ ${#users_locked_or_to_remove[@]} -gt 0 ]; then
            if (whiptail --title "Remove Locked Inactive Accounts" --yesno "ATTENTION: You have locked ${#users_locked_or_to_remove[@]} inactive account(s). \\n\\nDo you want to PERMANENTLY REMOVE these accounts now? This action is irreversible and includes home directories." 15 78); then
                for user_to_remove in "${users_locked_or_to_remove[@]}"; do
                    if (whiptail --title "Confirm Removal" --yesno "Really remove user \'$user_to_remove\' and their home directory?" 10 70); then
                        userdel -r "$user_to_remove"
                        printf "  Removed user: %s\\n" "$user_to_remove"
                    else
                        printf "  Skipped removal of user: %s\\n" "$user_to_remove"
                    fi
                done
                whiptail --infobox "Finished processing removal of locked inactive accounts." 7 70
            else
                whiptail --infobox "Skipped removal of locked inactive accounts. They remain locked." 7 70
            fi
        fi
    fi
}

enforce_password_expiry_existing_users() {
    printf "\\\\033[1;31m[+] Enforcing password expiry policies for existing users...\\\\033[0m\\\\n"
    local pass_max_days=60
    local pass_min_days=1
    local pass_warn_age=7
    local changed_count=0
    local min_uid_to_check=1000 

    local excluded_users_expiry="root,daemon,bin,sys,sync,games,man,lp,mail,news,uucp,proxy,www-data,backup,list,irc,gnats,nobody,_apt,systemd-network,systemd-resolve,systemd-timesync,messagebus,sshd,landscape,pollinate,usbmux,dnsmasq,tcpdump,postgres,mysql,vagrant,docker"

    whiptail --title "Password Expiry for Existing Users" --infobox "Applying password expiry: MAX_DAYS=$pass_max_days, MIN_DAYS=$pass_min_days, WARN_AGE=$pass_warn_age to non-system users." 10 78
    
    getent passwd | while IFS=: read -r name password uid gid gecos home shell; do
        if [ "$uid" -ge "$min_uid_to_check" ] && [[ ! "$shell" =~ /nologin$|/false$ ]] && ! echo ",$excluded_users_expiry," | grep -q ",$name,"; then
            if (whiptail --title "Confirm Password Policy" --yesno "Apply password expiry policy (Max: $pass_max_days, Min: $pass_min_days, Warn: $pass_warn_age days) to user \'$name\' (UID: $uid)?" 12 78); then
                chage -M "$pass_max_days" -m "$pass_min_days" -W "$pass_warn_age" "$name"
                if [ $? -eq 0 ]; then
                    printf "  Applied password expiry to user: %s\\n" "$name"
                    changed_count=$((changed_count + 1))
                else
                    printf "  Failed to apply password expiry to user: %s\\n" "$name"
                    whiptail --msgbox "Failed to apply password policy to user \'$name\'. Check manually." 8 60
                fi
            else
                printf "  Skipped password expiry for user: %s\\n" "$name"
            fi
        fi
    done

    if [ "$changed_count" -gt 0 ]; then
        whiptail --infobox "Password expiry policies applied to $changed_count user(s)." 8 60
    else
        whiptail --infobox "No changes made to existing user password expiry policies, or no eligible users found/selected." 8 70
    fi
    printf "\\\\033[1;32m[+] Password expiry enforcement for existing users complete.\\\\033[0m\\\\n"
}

stig_kernel_setup() {
     
    printf "\033[1;31m[+] Setting up STIG-compliant kernel parameters (login-safe)...\033[0m\n"
    tee /etc/sysctl.d/stig-kernel-safe.conf > /dev/null <<EOF

# Address Space Layout Randomization (ASLR)
kernel.randomize_va_space = 2

# Restrict kernel pointers in /proc
kernel.kptr_restrict = 2

# Restrict dmesg to root
kernel.dmesg_restrict = 1

# Protect hardlinks and symlinks
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# Disable core dumps for SUID programs
fs.suid_dumpable = 0

# Disable magic SysRq key
kernel.sysrq = 0

# Use PID in core dump filenames
kernel.core_uses_pid = 1

# Restrict ptrace
kernel.yama.ptrace_scope = 1

# IPv4 network hardening
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF

    sysctl --system || printf "\033[1;31m[-] Failed to reload sysctl settings.\033[0m\n"
    sysctl -w kernel.randomize_va_space=2 || printf "\033[1;31m[-] Failed to set kernel Security Parameters.\033[0m\n"
}



stig_harden_ssh() {
    {
        echo 10
        sleep 0.2
        printf "\033[1;31m[+] Hardening SSH configuration...\033[0m\n"

        sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        echo 15
        sleep 0.2

        sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
        echo 20
        sleep 0.2

        sed -i 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
        echo 25
        sleep 0.2

        sed -i 's/^#\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config
        echo 30
        sleep 0.2

        # Harden SSH options as per SSH-7408
        sed -i '/^AllowTcpForwarding /d' /etc/ssh/sshd_config
        echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config

        sed -i '/^ClientAliveCountMax /d' /etc/ssh/sshd_config
        echo "ClientAliveCountMax 2" >> /etc/ssh/sshd_config

        sed -i '/^Compression /d' /etc/ssh/sshd_config
        echo "Compression no" >> /etc/ssh/sshd_config

        sed -i '/^LogLevel /d' /etc/ssh/sshd_config
        echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config

        sed -i '/^MaxAuthTries /d' /etc/ssh/sshd_config
        echo "MaxAuthTries 3" >> /etc/ssh/sshd_config

        sed -i '/^MaxSessions /d' /etc/ssh/sshd_config
        echo "MaxSessions 2" >> /etc/ssh/sshd_config

        sed -i '/^Port /d' /etc/ssh/sshd_config
      
        # echo "Port 22" >> /etc/ssh/sshd_config

        sed -i '/^TCPKeepAlive /d' /etc/ssh/sshd_config
        echo "TCPKeepAlive no" >> /etc/ssh/sshd_config

        sed -i '/^X11Forwarding /d' /etc/ssh/sshd_config
        echo "X11Forwarding no" >> /etc/ssh/sshd_config

        sed -i '/^AllowAgentForwarding /d' /etc/ssh/sshd_config
        echo "AllowAgentForwarding no" >> /etc/ssh/sshd_config

        echo 60
        sleep 0.2

        sed -i '/^AllowUsers /d' /etc/ssh/sshd_config
        sed -i '/^Ciphers /d' /etc/ssh/sshd_config
        sed -i '/^MACs /d' /etc/ssh/sshd_config

        echo "AllowUsers your_user" >> /etc/ssh/sshd_config
        echo "Ciphers aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/sshd_config
        echo "MACs hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config
        echo 85
        sleep 0.2

        systemctl restart sshd || {
            printf "\033[1;31m[-] Failed to restart SSH service. Check your configuration.\033[0m\n"
            echo 100
            sleep 0.2
            return 1
        }
        echo 100
        sleep 0.2
    } | whiptail --gauge "Hardening SSH configuration..." 8 60 0

    printf "\033[1;32m[+] SSH configuration hardened successfully.\033[0m\n"
}


stig_set_randomize_va_space() {
    {
        echo 10
        sleep 0.2
        printf "\033[1;31m[+] Setting kernel.randomize_va_space...\033[0m\n"
        echo "kernel.randomize_va_space = 2" > /etc/sysctl.d/hardn.conf
        echo 50
        sleep 0.2
        if ! sysctl --system; then
            printf "\033[1;31m[-] Failed to reload sysctl settings.\033[0m\n"
            echo 100
            sleep 0.2
            exit 1
        fi
        echo 80
        sleep 0.2
        if ! sysctl -w kernel.randomize_va_space=2; then
            printf "\033[1;31m[-] Failed to set kernel.randomize_va_space.\033[0m\n"
            echo 100
            sleep 0.2
            exit 1
        fi
        echo 100
        sleep 0.2
    } | whiptail --gauge "Setting kernel.randomize_va_space..." 8 60 0
}


enable_services() {
       printf "\033[1;31m[+] Enabling and starting Fail2Ban and AppArmor services...\033[0m\n"
       systemctl enable --now fail2ban
       systemctl enable --now apparmor
}

enable_process_accounting_and_sysstat() {
    printf "\\033[1;31m[+] Enabling process accounting (acct) and system statistics (sysstat)...\\033[0m\\n"
    local changed_acct=false
    local changed_sysstat=false

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
        local sysstat_conf="/etc/default/sysstat"
        if [ -f "$sysstat_conf" ]; then
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

    if [ "$changed_acct" = true ] || [ "$changed_sysstat" = true ]; then
        whiptail --infobox "Process accounting (acct) and sysstat configured." 7 70
    else
        whiptail --infobox "Process accounting (acct) and sysstat checked. No changes made or needed." 8 70
    fi
}

enable_aide() {
    printf "\\033[1;31m[+] Installing and configuring AIDE (Advanced Intrusion Detection Environment)...\\033[0m\\n"
    whiptail --title "AIDE Setup" --infobox "Installing AIDE for file integrity monitoring..." 7 70

    if ! dpkg -s aide >/dev/null 2>&1 || ! dpkg -s aide-common >/dev/null 2>&1; then
        apt-get update -y
        apt-get install -y aide aide-common
        if [ $? -ne 0 ]; then

            whiptail --msgbox "Failed to install AIDE. Please check for errors." 8 60
            return 1
        fi
    else
        whiptail --infobox "AIDE is already installed." 7 60
    fi

    local aide_conf="/etc/aide/aide.conf"
    if [ -f "$aide_conf" ]; then
      
        if ! grep -q "^All =.*sha512" "$aide_conf"; then 
            printf "\\033[1;33m[*] Configuring AIDE for strong checksums (SHA512/SHA256)...\\033[0m\\n"
           
            if grep -q "^All =" "$aide_conf"; then
                sed -i 's/^All =.*/All = sha512+sha256+rmd160+tiger/' "$aide_conf"
            else 
                echo "All = sha512+sha256+rmd160+tiger" >> "$aide_conf" 
            fi
            # More specific for common rule types:
            sed -i 's/^NORMAL = .*/NORMAL = p+i+n+u+g+s+b+m+c+sha512+sha256/' "$aide_conf"
            sed -i 's/^DIR = .*/DIR = p+i+n+u+g/' "$aide_conf" 
            sed -i 's/^PERMS = .*/PERMS = p+i+u+g/' "$aide_conf"
            whiptail --infobox "AIDE configuration updated for strong checksums (SHA512/SHA256)." 7 70
        else
            whiptail --infobox "AIDE already configured with strong checksums (found SHA512)." 7 70
        fi
    else
        whiptail --msgbox "AIDE configuration file $aide_conf not found. Cannot ensure strong checksums." 8 70
    fi

    if [ ! -f /var/lib/aide/aide.db.gz ] && [ ! -f /var/lib/aide/aide.db ]; then
        whiptail --title "AIDE Initialization" --infobox "Initializing AIDE database. This may take a very long time..." 10 70
        printf "\\033[1;33m[*] Initializing AIDE database. This can take a significant amount of time, please be patient...\\033[0m\\n"
        
        if aideinit; then
            printf "\\033[1;32m[+] AIDE database initialized successfully by aideinit.\\033[0m\\n"
          
            if [ -f /var/lib/aide/aide.db.new.gz ] && [ ! -f /var/lib/aide/aide.db.gz ]; then
                 mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
                 printf "\\033[1;32m[+] Moved new AIDE database (aide.db.new.gz) to active location (aide.db.gz).\033[0m\\n"
            elif [ -f /var/lib/aide/aide.db.new ] && [ ! -f /var/lib/aide/aide.db ]; then # For non-gzipped new db
                 mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
                 printf "\\033[1;32m[+] Moved new AIDE database (aide.db.new) to active location (aide.db).\033[0m\\n"
            fi
            
            if [ -f /var/lib/aide/aide.db.gz ] || [ -f /var/lib/aide/aide.db ]; then
                 whiptail --infobox "AIDE database initialized and ready." 7 70
            else
                 whiptail --msgbox "AIDE database initialization completed by aideinit, but the final database file (/var/lib/aide/aide.db.gz or /var/lib/aide/aide.db) was not found. Please check /var/lib/aide/." 12 78
                 return 1 # FINT-4316 might persist
            fi
        else
            whiptail --msgbox "AIDE database initialization (aideinit) failed. Please check /var/log/aide/aideinit.log or run 'aideinit -v' manually." 10 70
            return 1 # FINT-4316 will persist
        fi
    else
        printf "\\033[1;32m[+] AIDE database already exists.\\033[0m\\n"
        whiptail --infobox "AIDE database already initialized." 7 70
    fi

    
    if [ -f "$aide_conf" ]; then
        printf "\\033[1;32m[+] AIDE configuration found at %s.\\033[0m\\n" "$aide_conf"
    else
        printf "\\033[1;33m[!] AIDE configuration %s not found. The cron job might fail.\\033[0m\\n" "$aide_conf"
        whiptail --msgbox "AIDE configuration %s not found. The daily check might fail." 10 70
    fi
    
    printf "\\033[1;32m[+] AIDE setup complete. Daily checks are configured via cron.\\033[0m\\n"
}

install_additional_tools() {
    printf "\\033[1;31m[+] Installing additional security tools...\\033[0m\\n"

    whiptail --title "Additional Tools" --infobox "Installing chkrootkit..." 7 60
    if ! dpkg -s chkrootkit >/dev/null 2>&1; then
        apt-get update -qq
        apt-get install -y chkrootkit >/dev/null 2>&1 || \
            whiptail --title "Error" --msgbox "Failed to install chkrootkit." 8 60
    else
        whiptail --infobox "chkrootkit is already installed." 7 60
    fi

    whiptail --title "Additional Tools" --infobox "Installing Maldet (LMD)..." 7 60
    if [ ! -f /usr/local/sbin/maldet ]; then
        cd /tmp || return 1
        wget -q http://www.rfxn.com/downloads/maldetect-current.tar.gz -O maldetect-current.tar.gz && \
        tar -xzf maldetect-current.tar.gz && \
        cd maldetect-* && \
        ./install.sh > /dev/null 2>&1 || \
            whiptail --title "Error" --msgbox "Failed to install Maldet. Please check /tmp/maldetect-install.log" 8 70
        
        # Clean up
        cd /tmp
        rm -f maldetect-current.tar.gz
        rm -rf maldetect-*
        
        if [ -f /usr/local/sbin/maldet ]; then
            whiptail --infobox "Maldet installed successfully." 7 60
            # Initial update
            /usr/local/sbin/maldet -u -d >/dev/null 2>&1
        else
             whiptail --title "Error" --msgbox "Maldet installation script ran, but /usr/local/sbin/maldet not found." 8 70
        fi
    else
        whiptail --infobox "Maldet appears to be already installed." 7 60
        # Optionally, offer to update Maldet if already installed
        if (whiptail --title "Maldet Update" --yesno "Maldet is installed. Update signatures?" 8 60); then
            /usr/local/sbin/maldet -u -d >/dev/null  2>&1
            whiptail --infobox "Maldet signatures updated." 7 60
        fi
    fi
    printf "\\033[1;32m[+] Additional security tools installation process completed.\\033[0m\\n"
}

configure_cron() {
    whiptail --infobox "Configuring cron jobs... \"$name\"..." 7 50

    (crontab -l 2>/dev/null | grep -v "lynis audit system --cronjob" | \
     grep -v "apt update && apt upgrade -y" | \
     grep -v "/opt/eset/esets/sbin/esets_update" | \
     grep -v "chkrootkit" | \
     grep -v "maldet --update" | \
     grep -v "maldet --scan-all" | \
     grep -v "rkhunter --cronjob" | \
     grep -v "debsums -s" | \
     grep -v "aide --check" | \
     grep -v "/usr/bin/yara -r /etc/yara/rules/index.yar" | \
     crontab -) || true

    (crontab -l 2>/dev/null || true) > mycron
    cat >> mycron << 'EOFCRON'
0 1 * * * lynis audit system --cronjob >> /var/log/lynis_cron.log 2>&1
0 2 * * * rkhunter --cronjob --report-warnings-only >> /var/log/rkhunter_cron.log 2>&1
0 2 * * * debsums -s >> /var/log/debsums_cron.log 2>&1
0 3 * * * /opt/eset/esets/sbin/esets_update
0 4 * * * chkrootkit
0 5 * * * maldet --update
0 6 * * * maldet --scan-all / >> /var/log/maldet_scan.log 2>&1
0 7 * * * aide --check -c /etc/aide/aide.conf >> /var/log/aide_check.log 2>&1
0 8 * * * /usr/bin/yara -r /etc/yara/rules/index.yar / >> /var/log/yara_scan.log 2>&1
0 9 * * * rkhunter --cronjob --report-warnings-only >> /var/log/rkhunter_cron.log 2>&1
0 10 * * * debsums -s >> /var/log/debsums_cron.log 2>&1
EOFCRON
    crontab mycron
    rm mycron
    whiptail --infobox "Cron jobs configured for security scans and updates." 7 60
}


main() {
    print_ascii_banner
    welcomemsg # Initial welcome and choice to proceed

    if ! preinstallmsg; then # Asks if user wants to proceed with STIG/Security compliance
        clear
        printf "User aborted installation.\\n"
        exit 0
    fi

    if (whiptail --title "Initial System Update" --yesno "Perform an initial update of all system packages?" 10 60); then
        update_system_packages
    fi

    if (whiptail --title "Install Dependencies & Security Tools" --yesno "Install common dependencies and essential security tools (ufw, fail2ban, apparmor, libpam-tmpdir, apt-listbugs, apt-listchanges, needrestart, apt-show-versions etc.)?" 12 78); then
      
        local essential_packages="git curl whiptail apt-utils lsb-release libpam-tmpdir apt-listbugs apt-listchanges needrestart apt-show-versions" # Added Lynis suggestions
        for pkg in $essential_packages; do
            install_package_dependencies "$pkg" "Essential utility"
        done
        check_security_tools 
    fi

    if (whiptail --title "Build HARDN Package" --yesno "Build and install the HARDN custom package from source (if available)?" 10 70); then
        build_hardn_package
    fi

    if (whiptail --title "Install Additional Tools (progs.csv)" --yesno "Install additional tools and packages as defined in progs.csv?" 10 78); then
        installationloop
    fi
    
    if (whiptail --title "STIG: Kernel Hardening" --yesno "Apply STIG-compliant kernel parameter hardening (sysctl)? This includes ASLR, restricting kernel pointers, dmesg, and disabling IPv6." 12 78); then
        stig_kernel_setup
    fi

    if (whiptail --title "STIG: Password Policy" --yesno "Configure STIG-compliant password policies (hashing rounds in login.defs)?" 10 78); then
        stig_password_policy # Covers AUTH-9230
    fi

    if (whiptail --title "STIG: File Permissions & umask" --yes-button "HARDN" \
            --no-button "RETURN" \
            --yesno "\n\n\nSet restrictive default file permissions (umask)?\n(Covers AUTH-9328)\n\n" 12 70); then
        stig_file_permissions # Covers AUTH-9328
    fi
    
    if (whiptail --title "STIG: Disable Core Dumps" --yesno "Disable system-wide core dumps for security (Covers KRNL-5820)?" 10 70); then
        stig_disable_core_dumps # Covers KRNL-5820
    fi

    if (whiptail --title "Security: Disable USB Storage" --yesno "Disable USB storage device access (via modprobe) (Covers USB-1000)?" 10 70); then
        disable_usb_storage # Covers USB-1000
    fi

    if (whiptail --title "Security: GRUB Bootloader" --yesno "Secure GRUB bootloader (e.g., set password)? Requires manual password input." 10 78); then
        grub_security
    fi

    if (whiptail --title "STIG: SSH Hardening" --yesno "Apply STIG-compliant SSH server hardening (/etc/ssh/sshd_config)?" 10 78); then
        stig_harden_ssh 
    fi

    if (whiptail --title "Firewall: UFW Configuration" --yesno "Configure Uncomplicated Firewall (UFW) with default deny and allow essential outgoing traffic?" 10 78); then
        configure_ufw
    fi

    if (whiptail --title "STIG: Auditd Service" --yesno "Install and configure 'auditd' for system auditing with STIG-based rules (Covers ACCT-9628)?" 10 78); then
        stig_enable_auditd # Covers ACCT-9628
    fi
    
    if (whiptail --title "Security: AppArmor" --yesno "Reload AppArmor profiles to enforce application confinement?" 10 70); then
        reload_apparmor
    fi
    
    if (whiptail --title "Network: Disable Uncommon Protocols" --yesno "Disable uncommon network protocols like dccp, sctp, rds, tipc (Covers NETW-3200)?" 10 78); then
        disable_uncommon_network_protocols # Covers NETW-3200
    fi

    if (whiptail --title "Security: Set Legal Banners" --yesno "Set legal warning banners for login prompts (/etc/issue, /etc/issue.net) (Covers BANN-7126, BANN-7130)?" 10 78); then
        set_legal_banners # Covers BANN-7126, BANN-7130
    fi
    
    if (whiptail --title "Accounting: Process & System Stats" --yesno "Enable process accounting (acct) and system statistics (sysstat) (Covers ACCT-9622, ACCT-9626)?" 10 78); then
        enable_process_accounting_and_sysstat # Covers ACCT-9622, ACCT-9626
    fi

    if (whiptail --title "IDS: Suricata" --yesno "Install and enable Suricata Intrusion Detection System?" 10 70); then
        enable_suricata
    fi

    if (whiptail --title "HIDS: AIDE" --yesno "Install and initialize AIDE for file integrity monitoring (uses SHA512/SHA256) (Covers FINT-4316, FINT-4402)?" 12 78); then
        enable_aide # Covers FINT-4316, FINT-4402
    fi

    if (whiptail --title "Network: Check Promiscuous Mode" --yesno "Check for and optionally disable network interfaces in promiscuous mode (Covers NETW-3015)?" 10 78); then
        check_promiscuous_mode # Covers NETW-3015
    fi

    if (whiptail --title "Malware Scan: YARA" --yesno "Install YARA and download rules for malware scanning (sets up daily cron job)?" 10 78); then
        enable_yara
    fi

    if (whiptail --title "Rootkit Scan: Rkhunter" --yesno "Install and configure Rkhunter for rootkit scanning?" 10 70); then
        enable_rkhunter
    fi
    
    if (whiptail --title "Additional Security Tools" --yesno "Install additional security tools like chkrootkit and Maldet?" 10 70); then
        install_additional_tools
    fi
    
    if (whiptail --title "Security: Fail2Ban Enhancement" --yesno "Enhance Fail2Ban configuration (e.g., ensure sshd jail is active) (Covers DEB-0880)?" 10 78); then
        enhance_fail2ban # Covers DEB-0880
    fi

    if (whiptail --title "STIG: Harden Services" --yesno "Harden system services by disabling unnecessary ones (e.g., telnet, avahi)? Review carefully." 10 78); then
        stig_hardn_services
    fi

    if (whiptail --title "STIG: Lock Inactive Accounts" --yesno "Configure automatic locking for new inactive accounts and optionally scan/lock existing ones? \\n(AUTH-9284: Removal is an option after locking)" 12 78); then
        stig_lock_inactive_accounts
    fi
    
    if (whiptail --title "STIG: Enforce Password Expiry (Existing Users)" --yesno "Enforce password expiry policies (e.g., max 60 days) for existing non-system users (Covers AUTH-9282)?" 12 78); then
        enforce_password_expiry_existing_users
    fi
    
    if (whiptail --title "Security: Restrict Compilers" --yesno "Restrict access to compilers (gcc, clang, etc.) to a specific group (\'devs\') (Covers HRDN-7222)?" 10 78); then
        restrict_compilers # Covers HRDN-7222
    fi

    if (whiptail --title "Security: Firejail Browser Sandboxing" --yesno "Configure Firejail to sandbox web browsers (Firefox, Chrome, etc.) if installed?" 10 78); then
        configure_firejail
    fi
    
    if (whiptail --title "Automation: Configure Cron Jobs" --yesno "Setup daily/weekly cron jobs for security scans (Lynis, Rkhunter, Debsums, AIDE, YARA, Maldet) and updates?" 12 78); then
        configure_cron
    fi
    
    if (whiptail --title "Final System Update" --yesno "Perform a final update of all system packages?" 10 60); then
        update_system_packages
    fi

    finalize 
}

main