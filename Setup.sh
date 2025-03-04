#!/bin/bash

# HARDN - Setup 
# Please have repo cloned before hand 
# Installs + Pre-config 
# Must have python loaded already 
# Author: Tim "TANK" Burns


set -e  # if fails run

echo "-------------------------------------------------------"
echo "  HARDN - Security Setup for Debian, and for us all.   "
echo "-------------------------------------------------------"

# ROOT - must run as 
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root. Use: sudo ./setup.sh"
   exit 1
fi

# Be sure to clone repo first 
# INSTALL 
cd "$(dirname "$0")"

echo "[+] Updating system packages..."
apt update && apt install -y python3 python3-pip

echo "[+] Installing required system dependencies..."
apt install -y python3 python3-pip ufw fail2ban apparmor apparmor-profiles apparmor-utils firejail tcpd lynis debsums 

echo "[+] Installing Python dependencies..."
pip install -r requirements.txt

echo "[+] Installing HARDN as a system-wide command..."
pip install -e .

# DEPENDENCY - to check for requirements 
if [[ -f "requirements.txt" ]]; then
    pip install -r requirements.txt
else
    echo "[-] Missing requirements.txt. Skipping Python dependency installation."
fi

# SYSTEM PACKS
echo "[+] Installing all needed system dependencies..."
apt install -y \
    python3 python3-pip ufw fail2ban apparmor apparmor-profiles apparmor-utils firejail \
    tcpd lynis debsums rkhunter pexpect libpam-pwquality \
    libvirt-daemon-system libvirt-clients qemu-kvm \
    docker.io docker-compose \
    openssh-server
   
# PY Libraries 
echo "[+] Installing Python dependencies..."
pip install pexpect # Kernal password hashing file


# SECURITY 

# UFW (update) 
ufw allow out 53,80,443/tcp
ufw allow out 53,123/udp
ufw allow out 67,68/udp  # because static Ip's are 1993
ufw allow out icmp  # ping
ufw reload
ufw status verbose
# UFW - reload 
ufw reload || { echo "[-] UFW failed to reload."; exit 1; }

echo "[+] Setting up Fail2Ban..."
systemctl enable --now fail2ban

echo "[+] Setting up AppArmor..."
systemctl enable --now apparmor

# ESET-NOD32 (update) 
echo "[+] Installing ESET NOD32 Antivirus..."
ESET_DEB="/tmp/eset.deb"
ESET_URL="https://download.eset.com/com/eset/apps/home/av/linux/latest/eset_nod32av_64bit.deb"
wget -q "$ESET_URL" -O "$ESET_DEB" || { echo "[-] Failed to download ESET. Check URL."; exit 1; }
dpkg -i "$ESET_DEB" || apt --fix-broken install -y
rm -f "$ESET_DEB"

# apparmor handle (update) 
echo "[+] Reloading AppArmor profiles..."
apparmor_parser -r /etc/apparmor.d/*

# CRON (update)
echo "[+] Configuring cron jobs..."
touch /var/log/lynis_cron.log
chmod 600 /var/log/lynis_cron.log

# CRON - old and remove 
crontab -l 2>/dev/null | grep -v "lynis audit system --cronjob" | grep -v "apt update && apt upgrade -y" | grep -v "/opt/eset/esets/sbin/esets_update" | crontab -

# CRON - add new 
(crontab -l 2>/dev/null; echo "
0 1 * * * lynis audit system --cronjob >> /var/log/lynis_cron.log 2>&1
0 2 * * * apt update && apt upgrade -y
0 3 * * * /opt/eset/esets/sbin/esets_update
") | crontab -

# USB disable - all 
echo "[+] Checking if USB storage module is disabled..."
lsmod | grep usb_storage && echo "[-] Warning: USB storage is still active!" || echo "[+] USB storage successfully disabled."
echo "[+] Disabling USB storage (optional)..."
echo 'blacklist usb-storage' >> /etc/modprobe.d/usb-storage.conf
modprobe -r usb-storage || echo "USB storage module in use, cannot unload."

# UPDATE
apt update && apt upgrade -y || { echo "[-] System update failed."; exit 1; }

echo "-------------------------------------"
echo "[+] Setup complete!"
echo "    Start HARDN using:"
echo "    hardn"
echo "-------------------------------------"
