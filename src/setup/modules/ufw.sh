#!/bin/bash
source /usr/lib/hardn-xdr/src/setup/hardn-common.sh
set -e

# ...existing code...

# Install UFW if not present
if ! command -v ufw &> /dev/null; then
    apt-get update
    apt-get install -y ufw
fi

# Whiptail-driven mode selection
if command -v whiptail >/dev/null 2>&1; then
    mode=$(whiptail --title "UFW Setup Mode" --radiolist "Choose firewall setup mode:" 12 90 2 \
        "basic" "Default deny incoming, allow outgoing, enable UFW" ON \
        "advanced" "Custom rules for server/container" OFF 3>&1 1>&2 2>&3)
    if [[ $? -ne 0 ]]; then
        HARDN_STATUS "info" "User cancelled UFW setup."
        return 1
    fi
else
    mode="basic"
fi

if [[ "$mode" == "basic" ]]; then
    ufw default deny incoming
    ufw default allow outgoing
    ufw --force enable
    HARDN_STATUS "pass" "UFW basic firewall enabled: deny incoming, allow outgoing."
    ufw status verbose
fi

# Advanced mode: server/container profile selection
profile=$(whiptail --title "Firewall Profile" --radiolist "Select profile type:" 10 90 2 \
    "server" "Typical server (SSH, HTTP/S, custom)" ON \
    "container" "Container (minimal, custom)" OFF 3>&1 1>&2 2>&3)
if [[ $? -ne 0 ]]; then
    HARDN_STATUS "info" "User cancelled profile selection."
    return 1
fi

# Default policies
ufw default deny incoming
ufw default allow outgoing

# Interactive rule selection
rules=""
if [[ "$profile" == "server" ]]; then
    rules=$(whiptail --title "Server Firewall Rules" --checklist "Select services to allow:" 14 90 6 \
        "ssh" "SSH (port 22)" ON \
        "http" "HTTP (port 80)" OFF \
        "https" "HTTPS (port 443)" OFF \
        "custom" "Custom port(s)" OFF 3>&1 1>&2 2>&3)
elif [[ "$profile" == "container" ]]; then
    rules=$(whiptail --title "Container Firewall Rules" --checklist "Select services to allow:" 12 90 4 \
        "ssh" "SSH (port 22)" OFF \
        "custom" "Custom port(s)" ON 3>&1 1>&2 2>&3)
fi
rules=$(echo $rules | tr -d '"')

# Apply selected rules
if [[ "$rules" == *"ssh"* ]]; then
    ufw allow ssh
fi
if [[ "$rules" == *"http"* ]]; then
    ufw allow http
fi
if [[ "$rules" == *"https"* ]]; then
    ufw allow https
fi
if [[ "$rules" == *"custom"* ]]; then
    custom_ports=$(whiptail --title "Custom Ports" --inputbox "Enter custom port(s) to allow (comma-separated, e.g. 8080,8443):" 10 90 3>&1 1>&2 2>&3)
    if [[ -n "$custom_ports" ]]; then
        IFS=',' read -ra ports <<< "$custom_ports"
        for port in "${ports[@]}"; do
            ufw allow "${port// /}"
        done
    fi
fi

# Enable UFW
ufw --force enable

# Show summary
ufw status verbose
HARDN_STATUS "pass" "UFW advanced firewall enabled with selected rules."