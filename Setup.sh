#!/bin/bash
########################################
#            HARDN - Setup             #
#  Please have repo cloned before hand #
#       Installs + Pre-config          #
#    Must have python loaded already   #
#       Author: Tim "TANK" Burns       #
########################################

set -e  

echo "-------------------------------------------------------"
echo "  HARDN - Security Setup for Debian, and for us all.   "
echo "-------------------------------------------------------"
# ENSURE - the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root. Use: sudo ./Setup.sh"
   exit 1
fi

# INSTALL 
cd "$(dirname "$0")"

echo "[+] Updating system packages..."
apt update && apt install -y python3 python3-tk

echo "[+] Installing required system dependencies..."
apt install -y ufw fail2ban apparmor apparmor-profiles apparmor-utils firejail tcpd lynis debsums rkhunter libpam-pwquality libvirt-daemon-system libvirt-clients qemu-kvm docker.io docker-compose

# Install pexpect using apt
echo "[+] Installing pexpect using apt"
apt install -y python3-pexpect

# SYSTEM PACKS
echo "[+] Installing all needed system dependencies..."
apt install -y \
    ufw fail2ban apparmor apparmor-profiles apparmor-utils firejail \
    tcpd lynis debsums rkhunter libpam-pwquality \
    libvirt-daemon-system libvirt-clients qemu-kvm \
    docker.io docker-compose \
    openssh-server

# SECURITY 

# UFW (update) 
ufw allow out 53,80,443/tcp
ufw allow out 53,123/udp
ufw allow out 67,68/udp  # because static Ip's are 1993
ufw allow out 67,68/udp  
ufw allow out icmp       
# UFW - reload 
ufw reload || { echo "[-] UFW failed to reload."; exit 1; }

echo "[+] Setting up Fail2Ban..."
systemctl enable --now fail2ban

echo "[+] Setting up AppArmor..."
systemctl enable --now apparmor

# Installing ESET NOD32 Antivirus
eset_deb="/tmp/eset.deb"
eset_url="https://download.eset.com/com/eset/apps/home/av/linux/latest/eset_nod32av_64bit.deb"
wget -q "$eset_url" -O "$eset_deb" || { echo "[-] Failed to download ESET. Check URL."; exit 1; }
dpkg -i "$eset_deb" || apt --fix-broken install -y
rm -f "$eset_deb"

# Reloading AppArmor profiles
apparmor_parser -r /etc/apparmor.d/*

# Configuring cron jobs
touch /var/log/lynis_cron.log
chmod 600 /var/log/lynis_cron.log
crontab -l 2>/dev/null | grep -v "lynis audit system --cronjob" | grep -v "apt update && apt upgrade -y" | grep -v "/opt/eset/esets/sbin/esets_update" | crontab -
crontab -l 2>/dev/null > mycron
cat <<EOF >> mycron
0 1 * * * lynis audit system --cronjob >> /var/log/lynis_cron.log 2>&1
0 2 * * * apt update && apt upgrade -y
0 3 * * * /opt/eset/esets/sbin/esets_update
EOF
crontab mycron
rm mycron

# Disabling USB storage
lsmod | grep usb_storage && echo "[-] Warning: USB storage is still active!" || echo "[+] USB storage successfully disabled."
echo 'blacklist usb-storage' >> /etc/modprobe.d/usb-storage.conf
modprobe -r usb-storage || echo "USB storage module in use, cannot unload."

# Update system
apt update && apt upgrade -y || { echo "[-] System update failed."; exit 1; }

# Install grs
echo "[+] Installing grs..."
apt install -y grs

echo "-------------------------------------"
echo "[+] Setup complete!"
echo "    Start HARDN using:"
echo "    hardn"
echo "-------------------------------------"