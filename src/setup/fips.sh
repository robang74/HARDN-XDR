#!/bin/bash

# author(s) : 
# Tim Burns
# Kiumarz Hashemi
# date : 2023-10-01
# version : 0.2
# description :
# This script is designed to enable FIPS 140-3 compliance on Debian systems.
# It installs necessary packages, configures OpenSSL, updates GRUB settings,
# and ensures compliance with ISO/IEC 19790:2012 and FIPS 140-3 Annexes.



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

                                                   v 1.1.2
EOF
    printf "${RESET}"
}

print_ascii_banner
sleep 5 



backup_grub_settings() {
    echo "Creating a backup of the current GRUB configuration..."
    cp /etc/default/grub /etc/default/grub.bak || { echo "Failed to create a backup of GRUB configuration. Exiting."; exit 1; }
}

set -euo pipefail

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Exiting."
    exit 1
fi

setup_fips_compliance() {
    echo "Starting FIPS 140-3 compliance setup for Debian..."

    if grep -q "fips=1" /proc/cmdline; then
    echo "FIPS mode is already enabled. Continuing with other setup steps..."
fi

    echo "Installing required packages for FIPS..."
    apt update -y
    apt install -y dracut-core grub2 openssl linux-image-$(uname -r) linux-headers-$(uname -r) linux-modules-extra-$(uname -r)

    echo "Configuring OpenSSL for FIPS mode..."
    if ! openssl version | grep -q "fips"; then
        echo "FIPS mode not enabled in OpenSSL. Updating configuration..."
        sed -i 's/#.*fips_mode = 1/fips_mode = 1/' /etc/ssl/openssl.cnf
    fi
}

apply_security_settings() {
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
}

add_fips_to_grub() {
    echo "Adding fips=1 to GRUB configuration..."
    if ! grep -q "fips=1" /etc/default/grub; then
        if ! grep -q "^GRUB_CMDLINE_LINUX=" /etc/default/grub; then
            echo 'GRUB_CMDLINE_LINUX="fips=1"' >> /etc/default/grub
        else
            sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="fips=1 /' /etc/default/grub
        fi
    fi
    update-grub
}

handle_missing_fips_module() {
    echo "ERROR: Required FIPS kernel modules (e.g., sha512hmac) are missing."
    echo "Attempting to install linux-modules-extra for your kernel..."
    apt update -y
    apt install -y linux-modules-extra-$(uname -r)
    echo "Re-running dracut to regenerate initramfs with FIPS modules..."
    dracut --force --add fips /boot/initramfs-$(uname -r).img $(uname -r)
    echo "If you still see errors, please check that the sha512hmac module exists in /lib/modules/$(uname -r)/kernel/crypto/."
}

regenerate_initramfs() {
    echo "Regenerating initramfs with FIPS modules..."
    if ! dracut --force --add fips /boot/initramfs-$(uname -r).img $(uname -r) 2>&1 | tee /tmp/dracut.log | grep -q "ERROR: installing 'sha512hmac'"; then
        echo "Initramfs regenerated successfully."
        return 0
    else
        handle_missing_fips_module
        return 1
    fi
}

verify_fips_mode() {
    echo "Verifying FIPS mode..."
    if grep -q "fips=1" /proc/cmdline; then
        echo "FIPS mode enabled successfully."
    else
        YELLOW_BOLD="\033[1;33m"
        RESET="\033[0m"
        echo -e "${YELLOW_BOLD}FIPS mode is not yet enabled. Please reboot your system to activate FIPS mode.${RESET}"
        echo -e "${YELLOW_BOLD}After reboot, verify with: cat /proc/sys/crypto/fips_enabled (should return 1)${RESET}"
    fi

    print_ascii_banner
}

setup_cron_updates() {
    echo "Setting up a Cron job for periodic updates..."
    local cron_job="0 3 * * * /usr/bin/apt update && /usr/bin/apt upgrade -y"
    (crontab -l 2>/dev/null | grep -v -F "$cron_job"; echo "$cron_job") | crontab -
    echo "Cron job for periodic updates has been set."
}

main() {
    echo "Starting FIPS 140-3 compliance setup..."
    RED_BOLD="\033[1;31m"
    GREEN_BOLD="\033[1;32m"
    RESET="\033[0m"

    echo -e "${RED_BOLD}Backing up GRUB settings...${RESET}"
    backup_grub_settings
    echo -e "${RED_BOLD}GRUB settings backed up.${RESET}"
    echo "----------------------------------------"
    sleep 1

    echo -e "${RED_BOLD}Setting up FIPS compliance...${RESET}"
    setup_fips_compliance
    echo -e "${RED_BOLD}FIPS compliance setup done.${RESET}"
    echo "----------------------------------------"
    sleep 1

    echo -e "${RED_BOLD}Applying additional security settings...${RESET}"
    apply_security_settings
    echo -e "${RED_BOLD}Security settings applied.${RESET}"
    echo "----------------------------------------"
    sleep 1

    echo -e "${RED_BOLD}Regenerating initramfs with FIPS modules...${RESET}"
    if regenerate_initramfs; then
        echo -e "${RED_BOLD}Initramfs regenerated.${RESET}"
        echo "----------------------------------------"
        sleep 1

        echo -e "${RED_BOLD}Adding fips=1 to GRUB and regenerating configuration...${RESET}"
        add_fips_to_grub
        echo -e "${RED_BOLD}GRUB configuration regenerated.${RESET}"
        echo "----------------------------------------"
        sleep 1
    else
        echo -e "${RED_BOLD}Failed to regenerate initramfs with FIPS modules. Not adding fips=1 to GRUB.${RESET}"
        exit 1
    fi

    echo -e "${RED_BOLD}Setting up periodic updates via Cron...${RESET}"
    setup_cron_updates
    echo -e "${RED_BOLD}Cron job for updates set.${RESET}"
    echo "----------------------------------------"
    sleep 1

    echo -e "${RED_BOLD}Verifying FIPS mode...${RESET}"
    verify_fips_mode
    echo -e "${RED_BOLD}FIPS mode verification done.${RESET}"
    echo "----------------------------------------"

    echo -e "${GREEN_BOLD}FIPS 140-3 compliance setup completed successfully!${RESET}"
}

main "$@"