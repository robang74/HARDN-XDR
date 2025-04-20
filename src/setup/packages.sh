#!/bin/bash
# Validates setup.sh for install and configuration setups + STIG compliance 

########################################
#           HARDN - Packages           #
#  Please have repo cloned beforehand  #
#       Installs + Pre-config          #
#    Must have python-3 loaded already #
#             Author(s):               #
#         - Chris Bingham              #
#           - Tim Burns                #
#        Date: 4/5-12/2025             #
########################################

LOG_FILE="/var/log/packages_validation.log"

initialize_log() {
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "HARDN-Packages Validation Log - $(date)" > "$LOG_FILE"
    echo "=========================================" >> "$LOG_FILE"
}

# STIG hardening validation
validate_stig_hardening() {
    echo "[+] Validating STIG compliance..." | tee -a "$LOG_FILE"

    # Password policy (pwquality.conf)
    grep -q 'minlen = 14' /etc/security/pwquality.conf &&
    grep -q 'dcredit = -1' /etc/security/pwquality.conf &&
    grep -q 'ucredit = -1' /etc/security/pwquality.conf &&
    grep -q 'ocredit = -1' /etc/security/pwquality.conf &&
    grep -q 'lcredit = -1' /etc/security/pwquality.conf &&
    echo "[+] Password policy is STIG compliant." | tee -a "$LOG_FILE" ||
    { echo "[-] Password policy not compliant." | tee -a "$LOG_FILE"; return 1; }

    # Inactive user lockout
    user_default=$(useradd -D | grep INACTIVE | awk -F= '{print $2}')
    if [ "$user_default" -le 35 ] && [ "$user_default" -ne -1 ]; then
        echo "[+] User inactivity lockout set to $user_default days." | tee -a "$LOG_FILE"
    else
        echo "[-] User inactivity lockout not configured properly." | tee -a "$LOG_FILE"
        return 1
    fi

    # Login banners
    grep -q "U.S. Government" /etc/issue && grep -q "consent to monitoring" /etc/issue.net &&
    echo "[+] Login banners configured." | tee -a "$LOG_FILE" ||
    { echo "[-] Login banners missing or incomplete." | tee -a "$LOG_FILE"; return 1; }

    # File permissions
    perms=$(stat -c "%a" /etc/shadow)
    [ "$perms" = "000" ] && echo "[+] /etc/shadow permissions correct." | tee -a "$LOG_FILE" ||
    { echo "[-] /etc/shadow permissions are $perms, expected 000." | tee -a "$LOG_FILE"; return 1; }

    # auditd rule presence
    grep -q '\-w /etc/passwd -p wa -k identity' /etc/audit/rules.d/stig.rules &&
    echo "[+] auditd rules present." | tee -a "$LOG_FILE" ||
    { echo "[-] auditd STIG rules missing." | tee -a "$LOG_FILE"; return 1; }

    # USB storage
    grep -q "install usb-storage /bin/false" /etc/modprobe.d/usb-storage.conf &&
    echo "[+] USB storage is blocked." | tee -a "$LOG_FILE" ||
    { echo "[-] USB storage not blocked." | tee -a "$LOG_FILE"; return 1; }

    # Ctrl+Alt+Del mask
    systemctl status ctrl-alt-del.target | grep -q "Masked" &&
    echo "[+] Ctrl+Alt+Del reboot disabled." | tee -a "$LOG_FILE" ||
    { echo "[-] Ctrl+Alt+Del reboot is still active." | tee -a "$LOG_FILE"; return 1; }

    # Core dump disable
    grep -q "fs.suid_dumpable = 0" /etc/sysctl.d/99-coredump.conf &&
    echo "[+] Core dumps are disabled." | tee -a "$LOG_FILE" ||
    { echo "[-] Core dumps are not properly disabled." | tee -a "$LOG_FILE"; return 1; }

    # IPv6 disable
    grep -q "net.ipv6.conf.all.disable_ipv6 = 1" /etc/sysctl.d/99-sysctl.conf &&
    echo "[+] IPv6 is disabled." | tee -a "$LOG_FILE" ||
    { echo "[-] IPv6 not disabled." | tee -a "$LOG_FILE"; return 1; }
}

# Package/service validation
validate_packages() {
    echo "[+] Validating package configurations..." | tee -a "$LOG_FILE"

    command -v getenforce >/dev/null && [ "$(getenforce)" = "Enforcing" ] &&
    echo "[+] SELinux is enforcing." | tee -a "$LOG_FILE" ||
    { echo "[-] SELinux not enforcing." | tee -a "$LOG_FILE"; return 1; }

    ufw status | grep -q "Status: active" &&
    echo "[+] UFW is active." | tee -a "$LOG_FILE" ||
    { echo "[-] UFW not active." | tee -a "$LOG_FILE"; return 1; }

    systemctl is-active --quiet fail2ban &&
    echo "[+] Fail2Ban is active." | tee -a "$LOG_FILE" ||
    { echo "[-] Fail2Ban not active." | tee -a "$LOG_FILE"; return 1; }

    command -v aa-status >/dev/null && systemctl is-active --quiet apparmor &&
    echo "[+] AppArmor is active." | tee -a "$LOG_FILE" ||
    { echo "[-] AppArmor not active." | tee -a "$LOG_FILE"; return 1; }

    command -v firejail >/dev/null &&
    echo "[+] Firejail is installed." | tee -a "$LOG_FILE" ||
    { echo "[-] Firejail missing." | tee -a "$LOG_FILE"; return 1; }

    command -v chkrootkit >/dev/null &&
    echo "[+] chkrootkit installed." | tee -a "$LOG_FILE" ||
    { echo "[-] chkrootkit missing." | tee -a "$LOG_FILE"; return 1; }

    command -v maldet >/dev/null || [ -x /usr/local/maldetect/maldet ] &&
    echo "[+] LMD installed." | tee -a "$LOG_FILE" ||
    { echo "[-] LMD not found." | tee -a "$LOG_FILE"; return 1; }

    systemctl is-active --quiet auditd &&
    echo "[+] auditd is running." | tee -a "$LOG_FILE" ||
    { echo "[-] auditd not running." | tee -a "$LOG_FILE"; return 1; }
}

validate_configuration() {
    echo "[+] Validating configuration..." | tee -a "$LOG_FILE"
    if validate_packages && validate_stig_hardening; then
        echo -e "\033[1;32m[+] ======== ALL CONFIGURATIONS ARE SUCCESSFUL =========\033[0m" | tee -a "$LOG_FILE"
    else
        echo -e "\033[1;31m[-] Some configurations failed. See log: $LOG_FILE\033[0m" | tee -a "$LOG_FILE"
        exit 1
    fi
}

main() {
    initialize_log
    validate_configuration
}

main