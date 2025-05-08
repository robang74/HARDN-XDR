#!/bin/bash

# Debian Compliance Script (Without FIPS Tools)
# Authors: Tim Burns, Kiumarz Hashemi
# Date: 2025-05-03
# Version: 2.0
# Description:
# This script enables compliance using enhanced security measures on Debian 12.

set -euo pipefail


LOG_FILE="/var/log/compliance-setup.log"
BACKUP_DIR="/var/backups/compliance"


exec > >(tee -a "$LOG_FILE") 2>&1

print_ascii_banner() {
    CYAN_BOLD="\033[1;36m"
    RESET="\033[0m"

    printf "%s" "${CYAN_BOLD}"
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
                                    
                                            C O M P L I A N C E

                                                   v 2.1
EOF
    printf "%s" "${RESET}"
}


import_dependencies() {
    echo "[INFO] Importing dependencies..."

    if ! command -v grub-mkconfig &> /dev/null; then
        echo "[ERROR] grub-mkconfig command not found. Please install GRUB tools."
        sudo apt-get install -y grub2
    fi

    if ! command -v openssl &> /dev/null; then
        echo "[INFO] Installing OpenSSL..."
        sudo apt-get install -y openssl
    fi

    if ! dpkg -l | grep -q libssl-dev; then
        echo "[INFO] Installing OpenSSL development libraries..."
        sudo apt-get install -y libssl-dev
    fi

    if ! command -v sysctl &> /dev/null; then
        echo "[ERROR] sysctl command not found. Please ensure procps is installed."
        sudo apt-get install -y procps
    fi

    echo "[OK] Dependencies imported successfully."
}






update_grub() {
    echo "[INFO] Updating GRUB configuration with enhanced security measures..."
    local grub_cfg="/etc/default/grub"

    if [[ ! -f "$grub_cfg" ]]; then
        echo "[ERROR] GRUB configuration not found at $grub_cfg."
        return 1
    fi
    if [[ ! -w "$grub_cfg" ]]; then
        echo "[ERROR] $grub_cfg is not writable. Check permissions."
        return 1
    fi

    sudo mkdir -p "$BACKUP_DIR"
    sudo cp "$grub_cfg" "$BACKUP_DIR/grub.bak.$(date +%s)"

    if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT' "$grub_cfg"; then
        sudo sed -i \
          '/^GRUB_CMDLINE_LINUX_DEFAULT/ s/module.sig_enforce=1//; s/"$/ module.sig_enforce=1"/' \
          "$grub_cfg"
    else
        echo 'GRUB_CMDLINE_LINUX_DEFAULT="quiet module.sig_enforce=1"' \
            | sudo tee -a "$grub_cfg" >/dev/null
    fi

    echo "[INFO] Restricting GRUB configuration access..."
    sudo chmod 600 /etc/default/grub
    sudo chmod 600 /boot/grub/grub.cfg
    echo "[OK] GRUB configuration access restricted."

    echo "[INFO] Enabling Module Signature Enforcement..."
    local module_sig="module.sig_enforce=1"
    if ! grep -q "$module_sig" "$grub_cfg"; then

    if ! grep -q 'module.sig_enforce=1' "$grub_cfg"; then
        sudo sed -i \
          '/^GRUB_CMDLINE_LINUX_DEFAULT/ s/"$/ module.sig_enforce=1"/' \
          "$grub_cfg"
    fi
    sudo grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1
    echo "[OK] GRUB configuration rebuilt with enhanced security."

    echo "[INFO] Ensuring login functionality and GUI compatibility..."

    # Check for user modifications and respect them
    if grep -q '# GUI_MODIFIED' "$grub_cfg"; then
        echo "[INFO] GRUB configuration has been modified via GUI. Changes will not be overwritten."
        return 0
    fi

    # Ensure user-defined GRUB settings are respected
    echo "[INFO] Checking for user-defined GRUB settings..."
    if grep -q '# USER_DEFINED' "$grub_cfg"; then
        echo "[INFO] User-defined settings detected. Skipping script-managed changes."
        return 0
    fi

    # Add a marker to indicate script-managed changes
    echo "# SCRIPT_MANAGED" | sudo tee -a "$grub_cfg" > /dev/null

    # Add comments to clarify security measures
    echo "# Enabling kernel lockdown mode for enhanced security" | sudo tee -a "$grub_cfg" > /dev/null
    echo "# Enforcing module signature verification to prevent unsigned modules" | sudo tee -a "$grub_cfg" > /dev/null

    # Ensure critical boot parameters are not removed
    echo "[INFO] Preserving critical boot parameters for login and recovery..."
    local critical_params="single recovery"
    for param in $critical_params; do
        if ! grep -q "$param" "$grub_cfg"; then
            echo "[INFO] Adding $param to GRUB_CMDLINE_LINUX_DEFAULT."
            sudo sed -i \
              's@^GRUB_CMDLINE_LINUX_DEFAULT=\"\([^\"]*\)\"@GRUB_CMDLINE_LINUX_DEFAULT=\"\1 $param\"@' \
              "$grub_cfg"
        fi
    done

    # Retain kernel lockdown mode and module signature enforcement
    echo "[INFO] Ensuring kernel lockdown mode and module signature enforcement..."
    local lockdown_mode="lockdown=integrity"
    local module_sig="module.sig_enforce=1"
    for param in "$lockdown_mode" "$module_sig"; do
        if ! grep -q "$param" "$grub_cfg"; then
            echo "[INFO] Adding $param to GRUB_CMDLINE_LINUX_DEFAULT."
            sudo sed -i \
              's@^GRUB_CMDLINE_LINUX_DEFAULT=\"\([^\"]*\)\"@GRUB_CMDLINE_LINUX_DEFAULT=\"\1 $param\"@' \
              "$grub_cfg"
        fi
    done

    # Protect GRUB configuration files
    echo "[INFO] Restricting access to GRUB configuration files..."
    sudo chmod 600 /etc/default/grub
    sudo chmod 600 /boot/grub/grub.cfg

    # Rebuild GRUB configuration
    echo "[INFO] Rebuilding GRUB configuration..."
    sudo grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1
    echo "[OK] GRUB configuration updated securely."
}







configure_memory() {
    echo "[INFO] Configuring secure kernel, monitored updates, and protecting RAM and CPU from attacks..."

    # Ensure kernel module signing is enabled
    if ! grep -q "CONFIG_MODULE_SIG=y" "/boot/config-$(uname -r)"; then
        echo "[ERROR] Kernel does not have module signing enabled."
        return 1
    fi
    echo "[OK] Kernel supports module signing."

    # Ensure hardened usercopy is enabled
    if ! grep -q "CONFIG_HARDENED_USERCOPY=y" "/boot/config-$(uname -r)"; then
        echo "[ERROR] Kernel does not have hardened usercopy enabled."
        return 1
    fi
    echo "[OK] Hardened usercopy is enabled."

    # Ensure page table isolation is enabled
    if ! grep -q "CONFIG_PAGE_TABLE_ISOLATION=y" "/boot/config-$(uname -r)"; then
        echo "[ERROR] Kernel does not have page table isolation enabled."
        return 1
    fi
    echo "[OK] Page table isolation is enabled."

    # Configure monitored updates and panic settings
    echo "[INFO] Configuring monitored updates and panic settings..."
    sudo sysctl -w kernel.panic_on_oops=1
    sudo sysctl -w kernel.panic=10
    echo "kernel.panic_on_oops=1" | sudo tee -a /etc/sysctl.conf
    echo "kernel.panic=10" | sudo tee -a /etc/sysctl.conf
    echo "[OK] Monitored updates and panic settings configured."

    # Update GRUB configuration for secure kernel settings
    local grub_cfg="/etc/default/grub"
    if [ -f "$grub_cfg" ]; then
        sudo cp "$grub_cfg" "$BACKUP_DIR/grub.bak.$(date +%s)"
        if ! grep -q "GRUB_CMDLINE_LINUX" "$grub_cfg"; then
            echo "GRUB_CMDLINE_LINUX=\"module.sig_enforce=1 pti=on panic=10 lockdown=integrity\"" | sudo tee -a "$grub_cfg"
        else
            sudo sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="module.sig_enforce=1 pti=on panic=10 lockdown=integrity /' "$grub_cfg"
        fi
        sudo grub-mkconfig -o /boot/grub/grub.cfg
        echo "[INFO] GRUB configuration updated for secure kernel settings."
    else
        echo "[ERROR] GRUB configuration file not found at $grub_cfg."
        return 1
    fi





setup_complete() {
    echo "============================================================"
    echo -e "${GREEN_BOLD}[COMPLETED] Compliance setup completed successfully.${RESET}"
    echo "============================================================"
}






main() {
    RED_BOLD="\033[1;31m"
    GREEN_BOLD="\033[1;32m"
    RESET="\033[0m"

    print_ascii_banner
    sleep 3
    echo "============================================================"
    echo -e "${RED_BOLD}[STEP 1] Starting compliance setup...${RESET}"
    echo "============================================================"

    if [ "$(id -u)" -ne 0 ]; then
        echo "------------------------------------------------------------"
    if ! mkdir -p "$BACKUP_DIR"; then
        echo "[ERROR] Failed to create backup directory at $BACKUP_DIR. Please check permissions."
        exit 1
    fi
        echo "------------------------------------------------------------"
        exit 1
    fi
    sleep 2
    echo "------------------------------------------------------------"
    echo -e "${RED_BOLD}[STEP 2] Importing dependencies...${RESET}"
    echo "------------------------------------------------------------"
    echo -e "${GREEN_BOLD}[OK] Dependencies imported successfully.${RESET}"
    import_dependencies
    sleep 2
    echo "------------------------------------------------------------"
    echo -e "${RED_BOLD}[STEP 2] Creating backup directory at $BACKUP_DIR...${RESET}"
    echo "------------------------------------------------------------"
    mkdir -p "$BACKUP_DIR"
    echo -e "${GREEN_BOLD}[OK] Backup directory created.${RESET}"

    echo "------------------------------------------------------------"
    echo -e "${RED_BOLD}[STEP 3] Configuring secure memory and kernel settings...${RESET}"
    echo "------------------------------------------------------------"
    configure_memory
    sleep 2
    echo -e "${GREEN_BOLD}[OK] Secure memory and kernel settings configured.${RESET}"

    echo "------------------------------------------------------------"
    echo -e "${RED_BOLD}[STEP 4] Updating GRUB configuration for compliance...${RESET}"
    echo "------------------------------------------------------------"
    update_grub
    sleep 2
    echo -e "${GREEN_BOLD}[OK] GRUB configuration updated.${RESET}"
    setup_complete 
}

main "$@"