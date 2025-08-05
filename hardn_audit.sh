#!/bin/bash

# HARDN-XDR Unified Security Compliance Scanner
# Based on Red Hat Security Hardening Documentation
# Supports: DISA STIG, OpenSCAP, FIPS 140-2, CIS, and Debian Security Standards
# Reference: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/security_hardening/scanning-the-system-for-configuration-compliance

# set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Compliance counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
STIG_VIOLATIONS=0
FIPS_VIOLATIONS=0
CIS_VIOLATIONS=0
DEBIAN_VIOLATIONS=0

# Report files
REPORT_DIR="$(dirname "$0")/frontend/dashboard"
OSCAP_REPORT="$REPORT_DIR/oscap-compliance.html"
CUSTOM_REPORT="$REPORT_DIR/hardn-compliance.html"
DETAILED_LOG="$REPORT_DIR/compliance.log"

mkdir -p "$REPORT_DIR"

# Logging function
log_check() {
    local status="$1"
    local standard="$2"
    local check_id="$3"
    local description="$4"
    local details="${5:-}"

    ((TOTAL_CHECKS++))

    case "$status" in
        "PASS")
            echo -e "${GREEN} PASS${NC} [$standard-$check_id] $description"
            ((PASSED_CHECKS++))
            ;;
        "FAIL")
            echo -e "${RED} FAIL${NC} [$standard-$check_id] $description"
            ((FAILED_CHECKS++))
            case "$standard" in
                "STIG") ((STIG_VIOLATIONS++)) ;;
                "FIPS") ((FIPS_VIOLATIONS++)) ;;
                "CIS") ((CIS_VIOLATIONS++)) ;;
                "DEBIAN") ((DEBIAN_VIOLATIONS++)) ;;
            esac
            ;;
        "WARN")
            echo -e "${YELLOW} WARN${NC} [$standard-$check_id] $description"
            ;;
        "INFO")
            echo -e "${BLUE}ℹ INFO${NC} [$standard-$check_id] $description"
            ;;
    esac

    [[ -n "$details" ]] && echo -e "   ${CYAN}→ $details${NC}"

    # Log to file
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$status] [$standard-$check_id] $description: $details" >> "$DETAILED_LOG"
}

print_banner() {
    echo -e "${BOLD}${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════════════════╗"
    echo "║                  HARDN-XDR UNIFIED COMPLIANCE TOOL                       ║"
    echo "║                                                                          ║"
    echo "║          DISA STIG (Security Technical Implementation Guide)             ║"
    echo "║           OpenSCAP (Security Content Automation Protocol)                ║"
    echo "║             CIS Controls (Center for Internet Security)                  ║"
    echo "║                      Debian Security Standards                           ║"
    echo "╚══════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}\n"
}

# Check if OpenSCAP is available for advanced scanning
check_openscap_availability() {
    echo -e "${BOLD}${PURPLE} CHECKING OPENSCAP AVAILABILITY${NC}"
    echo "============================================"

    if command -v oscap >/dev/null 2>&1; then
        log_check "PASS" "OSCAP" "001" "OpenSCAP scanner available"
        OSCAP_AVAILABLE=true

        # Check for SCAP Security Guide
        if [ -d "/usr/share/xml/scap/ssg/content" ]; then
            log_check "PASS" "OSCAP" "002" "SCAP Security Guide content available"

            # List available profiles
            echo -e "\n${YELLOW}Available SCAP Profiles:${NC}"
            if ls /usr/share/xml/scap/ssg/content/ssg-*-ds.xml >/dev/null 2>&1; then
                for ds_file in /usr/share/xml/scap/ssg/content/ssg-*-ds.xml; do
                    if [[ -f "$ds_file" ]]; then
                        echo "  Found: $(basename "$ds_file")"
                        SCAP_DATASTREAM="$ds_file"
                    fi
                done
            fi
        else
            log_check "WARN" "OSCAP" "002" "SCAP Security Guide not installed" "Install with: sudo apt-get install ssg-debian"
            OSCAP_AVAILABLE=false
        fi
    else
        log_check "WARN" "OSCAP" "001" "OpenSCAP not installed" "Install with: sudo apt-get install libopenscap8"
        OSCAP_AVAILABLE=false
    fi
    echo
}

# DISA STIG Compliance Checks
check_stig_compliance() {
    echo -e "${BOLD}${YELLOW} DISA STIG COMPLIANCE CHECKS${NC}"
    echo "======================================"

    # STIG Account and Authentication
    echo -e "\n${YELLOW}Account and Authentication Controls:${NC}"

    # Password policy (STIG-RHEL-07-010210)
    if [ -f "/etc/security/pwquality.conf" ]; then
        minlen=$(grep "^minlen" /etc/security/pwquality.conf 2>/dev/null | cut -d'=' -f2 | tr -d ' ' || echo "")
        if [ -n "$minlen" ] && [ "$minlen" -ge 14 ] 2>/dev/null; then
            log_check "PASS" "STIG" "010210" "Password minimum length ≥14 characters" "Current: $minlen"
        else
            log_check "FAIL" "STIG" "010210" "Password minimum length insufficient" "Current: ${minlen:-'not set'}, Required: ≥14"
        fi
    else
        log_check "FAIL" "STIG" "010210" "Password quality configuration missing" "Install libpam-pwquality"
    fi

    # Account lockout policy (STIG-RHEL-07-010320)
    if grep -q "pam_faillock\|pam_tally2" /etc/pam.d/common-auth 2>/dev/null; then
        log_check "PASS" "STIG" "010320" "Account lockout policy configured"
    else
        log_check "FAIL" "STIG" "010320" "Account lockout policy missing" "Configure pam_faillock"
    fi

    # File and Directory Permissions
    echo -e "\n${YELLOW}File and Directory Security:${NC}"

    # Critical file permissions
    check_file_perms() {
        local file="$1"
        local max_perm="$2"
        local stig_id="$3"

        if [ -f "$file" ]; then
            actual=$(stat -c "%a" "$file" 2>/dev/null || echo "777")
            if [ "$actual" -le "$max_perm" ] 2>/dev/null; then
                log_check "PASS" "STIG" "$stig_id" "File permissions ($file)" "Permissions: $actual"
            else
                log_check "FAIL" "STIG" "$stig_id" "File permissions too permissive ($file)" "Current: $actual, Max: $max_perm"
            fi
        else
            log_check "FAIL" "STIG" "$stig_id" "Required file missing" "$file"
        fi
    }

    check_file_perms "/etc/passwd" "644" "020240"
    check_file_perms "/etc/shadow" "640" "020240"
    check_file_perms "/etc/group" "644" "020240"
    check_file_perms "/etc/gshadow" "640" "020240"

    # SSH Configuration (STIG-RHEL-07-040370)
    echo -e "\n${YELLOW}SSH Security Configuration:${NC}"
    if [ -f "/etc/ssh/sshd_config" ]; then
        # SSH Protocol version
        if ! grep -q "^Protocol 1" /etc/ssh/sshd_config 2>/dev/null; then
            log_check "PASS" "STIG" "040370" "SSH Protocol 1 disabled"
        else
            log_check "FAIL" "STIG" "040370" "Insecure SSH Protocol 1 enabled"
        fi

        # Empty passwords
        if grep -q "^PermitEmptyPasswords no" /etc/ssh/sshd_config 2>/dev/null; then
            log_check "PASS" "STIG" "040380" "SSH empty passwords explicitly disabled"
        else
            log_check "FAIL" "STIG" "040380" "SSH empty passwords not explicitly disabled"
        fi

        # Root login
        if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null; then
            log_check "PASS" "STIG" "040390" "SSH root login disabled"
        else
            log_check "WARN" "STIG" "040390" "SSH root login not explicitly disabled"
        fi
    else
        log_check "FAIL" "STIG" "040000" "SSH configuration file missing"
    fi

    # System hardening
    echo -e "\n${YELLOW}System Hardening Controls:${NC}"

    # Core dumps (STIG-RHEL-07-021300)
    if [ "$(ulimit -c)" = "0" ]; then
        log_check "PASS" "STIG" "021300" "Core dumps disabled"
    else
        log_check "FAIL" "STIG" "021300" "Core dumps not disabled" "Current limit: $(ulimit -c)"
    fi

    # ASLR (STIG-RHEL-07-021310)
    aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "0")
    if [ "$aslr" = "2" ]; then
        log_check "PASS" "STIG" "021310" "Address Space Layout Randomization enabled"
    else
        log_check "FAIL" "STIG" "021310" "ASLR not fully enabled" "Value: $aslr, Required: 2"
    fi

    echo
}

# FIPS 140-2 Compliance Checks
check_fips_compliance() {
    echo -e "${BOLD}${PURPLE} FIPS 140-2 COMPLIANCE CHECKS${NC}"
    echo "======================================="

    # FIPS mode
    if [ -f "/proc/sys/crypto/fips_enabled" ]; then
        fips_enabled=$(cat /proc/sys/crypto/fips_enabled)
        if [ "$fips_enabled" = "1" ]; then
            log_check "PASS" "FIPS" "001" "FIPS 140-2 mode enabled"
        else
            log_check "FAIL" "FIPS" "001" "FIPS 140-2 mode not enabled" "Enable with fips-mode-setup"
        fi
    else
        log_check "FAIL" "FIPS" "001" "FIPS 140-2 support not available" "Install fips-mode-setup package"
    fi

    # OpenSSL FIPS
    if command -v openssl >/dev/null 2>&1; then
        if openssl version | grep -qi fips; then
            log_check "PASS" "FIPS" "002" "OpenSSL FIPS module available"
        else
            log_check "FAIL" "FIPS" "002" "OpenSSL FIPS module not available"
        fi

        # Test FIPS approved algorithms
        fips_algos=("sha256" "sha384" "sha512" "aes-256-gcm")
        for algo in "${fips_algos[@]}"; do
            if openssl dgst -"$algo" /dev/null >/dev/null 2>&1 || openssl enc -"$algo" -in /dev/null >/dev/null 2>&1; then
                log_check "PASS" "FIPS" "ALG-${algo}" "FIPS algorithm $algo available"
            else
                log_check "FAIL" "FIPS" "ALG-${algo}" "FIPS algorithm $algo not available"
            fi
        done

        # Check for weak algorithms
        weak_algos=("md5" "sha1" "des" "3des" "rc4")
        for algo in "${weak_algos[@]}"; do
            if openssl dgst -"$algo" /dev/null >/dev/null 2>&1; then
                log_check "FAIL" "FIPS" "WEAK-${algo}" "Weak algorithm $algo still available"
            else
                log_check "PASS" "FIPS" "WEAK-${algo}" "Weak algorithm $algo not available"
            fi
        done
    fi

    echo
}

# CIS (Center for Internet Security) Controls
check_cis_compliance() {
    echo -e "${BOLD}${CYAN} CIS CONTROLS COMPLIANCE${NC}"
    echo "================================="

    # CIS Control 1: Inventory and Control of Hardware Assets
    echo -e "\n${YELLOW}CIS Control 1 - Asset Management:${NC}"

    # Check if hardware inventory tools are available
    if command -v lshw >/dev/null 2>&1 || command -v dmidecode >/dev/null 2>&1; then
        log_check "PASS" "CIS" "001.1" "Hardware inventory tools available"
    else
        log_check "FAIL" "CIS" "001.1" "Hardware inventory tools missing" "Install lshw or dmidecode"
    fi

    # CIS Control 2: Inventory and Control of Software Assets
    echo -e "\n${YELLOW}CIS Control 2 - Software Management:${NC}"

    # Package management
    if command -v dpkg >/dev/null 2>&1 && command -v apt >/dev/null 2>&1; then
        log_check "PASS" "CIS" "002.1" "Package management system available"

        # Check for package verification tools
        if command -v debsums >/dev/null 2>&1; then
            log_check "PASS" "CIS" "002.2" "Package integrity verification available"
        else
            log_check "WARN" "CIS" "002.2" "Package integrity verification missing" "Install debsums"
        fi
    fi

    # CIS Control 3: Continuous Vulnerability Management
    echo -e "\n${YELLOW}CIS Control 3 - Vulnerability Management:${NC}"

    # Check for vulnerability scanners
    if command -v lynis >/dev/null 2>&1; then
        log_check "PASS" "CIS" "003.1" "Vulnerability scanner available (Lynis)"
    elif command -v chkrootkit >/dev/null 2>&1; then
        log_check "PASS" "CIS" "003.1" "Basic vulnerability scanner available (chkrootkit)"
    else
        log_check "WARN" "CIS" "003.1" "No vulnerability scanner detected" "Install lynis or chkrootkit"
    fi

    # CIS Control 4: Controlled Use of Administrative Privileges
    echo -e "\n${YELLOW}CIS Control 4 - Privilege Management:${NC}"

    # Sudo configuration
    if [ -f "/etc/sudoers" ]; then
        log_check "PASS" "CIS" "004.1" "Sudo configuration present"

        # Check for NOPASSWD entries
        if grep -q "NOPASSWD" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
            nopasswd_count=$(grep -c "NOPASSWD" /etc/sudoers /etc/sudoers.d/* 2>/dev/null)
            log_check "WARN" "CIS" "004.2" "Password-less sudo entries found" "$nopasswd_count entries"
        else
            log_check "PASS" "CIS" "004.2" "No password-less sudo entries"
        fi
    fi

    # CIS Control 5: Secure Configuration for Hardware and Software
    echo -e "\n${YELLOW}CIS Control 5 - Secure Configuration:${NC}"

    # Network configuration
    ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "1")
    if [ "$ip_forward" = "0" ]; then
        log_check "PASS" "CIS" "005.1" "IP forwarding disabled"
    else
        log_check "FAIL" "CIS" "005.1" "IP forwarding enabled" "Should be disabled for workstations"
    fi

    # ICMP redirects
    icmp_redirects=$(cat /proc/sys/net/ipv4/conf/all/accept_redirects 2>/dev/null || echo "1")
    if [ "$icmp_redirects" = "0" ]; then
        log_check "PASS" "CIS" "005.2" "ICMP redirects disabled"
    else
        log_check "FAIL" "CIS" "005.2" "ICMP redirects enabled"
    fi

    echo
}

# Debian-specific Security Checks
check_debian_security() {
    echo -e "${BOLD}${GREEN} DEBIAN SECURITY STANDARDS${NC}"
    echo "==================================="

    # Debian version and support status
    if [ -f "/etc/debian_version" ]; then
        debian_version=$(cat /etc/debian_version)
        log_check "INFO" "DEBIAN" "001" "Debian version detected" "$debian_version"

        # Check if it's a supported version
        if [[ "$debian_version" =~ ^(12|11|10) ]]; then
            log_check "PASS" "DEBIAN" "002" "Supported Debian version"
        else
            log_check "WARN" "DEBIAN" "002" "Debian version may be unsupported" "Consider upgrading"
        fi
    else
        log_check "INFO" "DEBIAN" "001" "Not a Debian system" "Debian-specific checks skipped"
        return
    fi

    # APT security repositories
    echo -e "\n${YELLOW}Package Security:${NC}"
    if [ -f "/etc/apt/sources.list" ] || [ -d "/etc/apt/sources.list.d" ]; then
        # Check for security repositories
        if grep -r "security.debian.org\|security-cdn.debian.org" /etc/apt/sources.list* >/dev/null 2>&1; then
            log_check "PASS" "DEBIAN" "101" "Security repositories configured"
        else
            log_check "FAIL" "DEBIAN" "101" "Security repositories missing" "Add Debian security repos"
        fi

        # Check for automatic updates
        if [ -f "/etc/apt/apt.conf.d/20auto-upgrades" ] || [ -f "/etc/apt/apt.conf.d/50unattended-upgrades" ]; then
            log_check "PASS" "DEBIAN" "102" "Automatic security updates configured"
        else
            log_check "WARN" "DEBIAN" "102" "Automatic security updates not configured" "Install unattended-upgrades"
        fi
    fi

    # AppArmor (Debian's default MAC system)
    echo -e "\n${YELLOW}Mandatory Access Control:${NC}"
    if [ -x "/usr/sbin/apparmor_status" ] || command -v apparmor_status >/dev/null 2>&1; then
        # Check if AppArmor service is active
        if systemctl is-active --quiet apparmor 2>/dev/null; then
            log_check "PASS" "DEBIAN" "201" "AppArmor active"

            # Check AppArmor profiles using full path or command
            if [ -x "/usr/sbin/apparmor_status" ]; then
                profiles_loaded=$(/usr/sbin/apparmor_status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}' || echo "0")
            else
                profiles_loaded=$(apparmor_status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}' || echo "0")
            fi
            
            if [ "$profiles_loaded" -gt 0 ] 2>/dev/null; then
                log_check "PASS" "DEBIAN" "202" "AppArmor profiles loaded" "$profiles_loaded profiles"
            else
                log_check "WARN" "DEBIAN" "202" "No AppArmor profiles loaded"
            fi
        else
            # Check if AppArmor is installed but not active
            if [ -x "/usr/bin/aa-enabled" ] && /usr/bin/aa-enabled 2>/dev/null; then
                log_check "WARN" "DEBIAN" "201" "AppArmor installed but not active" "Enable with systemctl enable apparmor"
            else
                log_check "WARN" "DEBIAN" "201" "AppArmor not properly configured" "Configure AppArmor"
            fi
        fi
    else
        log_check "WARN" "DEBIAN" "201" "AppArmor not installed" "Install apparmor package"
    fi

    # Network security
    echo -e "\n${YELLOW}Network Security:${NC}"

    # UFW (Uncomplicated Firewall - Debian's recommended firewall)
    if [ -x "/usr/sbin/ufw" ] || command -v ufw >/dev/null 2>&1; then
        # Use full path if available, otherwise use command
        # UFW requires root privileges to check status
        if [ "$EUID" -eq 0 ] || [ "$(id -u)" -eq 0 ]; then
            if [ -x "/usr/sbin/ufw" ]; then
                ufw_status=$(/usr/sbin/ufw status 2>/dev/null)
            else
                ufw_status=$(ufw status 2>/dev/null)
            fi
            
            if echo "$ufw_status" | grep -q "Status: active"; then
                log_check "PASS" "DEBIAN" "301" "UFW firewall active"
            else
                log_check "WARN" "DEBIAN" "301" "UFW firewall not active" "Enable with: sudo ufw enable"
            fi
        else
            # Non-root user - check if UFW service is running instead
            if systemctl is-active --quiet ufw 2>/dev/null; then
                log_check "PASS" "DEBIAN" "301" "UFW firewall service active"
            else
                log_check "WARN" "DEBIAN" "301" "UFW firewall status unknown (run as root for full check)" "Check with: sudo ufw status"
            fi
        fi
    else
        log_check "WARN" "DEBIAN" "301" "UFW not installed" "Install with: apt-get install ufw"
    fi

    # Fail2ban
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        log_check "PASS" "DEBIAN" "302" "Fail2ban intrusion prevention active"
    else
        log_check "WARN" "DEBIAN" "302" "Fail2ban not active" "Install and configure fail2ban"
    fi

    echo
}

# Run OpenSCAP scan if available
run_openscap_scan() {
    if [ "$OSCAP_AVAILABLE" = true ] && [ -n "$SCAP_DATASTREAM" ]; then
        echo -e "${BOLD}${PURPLE}🔍 RUNNING OPENSCAP COMPLIANCE SCAN${NC}"
        echo "==========================================="

        # Determine appropriate profile based on system
        profiles_to_test=()

        # Check for STIG profile
        if oscap info "$SCAP_DATASTREAM" 2>/dev/null | grep -q "stig"; then
            profiles_to_test+=("stig")
        fi

        # Check for CIS profile
        if oscap info "$SCAP_DATASTREAM" 2>/dev/null | grep -q "cis"; then
            profiles_to_test+=("cis")
        fi

        # Check for PCI-DSS profile
        if oscap info "$SCAP_DATASTREAM" 2>/dev/null | grep -q "pci-dss"; then
            profiles_to_test+=("pci-dss")
        fi

        if [ ${#profiles_to_test[@]} -gt 0 ]; then
            for profile in "${profiles_to_test[@]}"; do
                echo -e "\n${YELLOW}Running OpenSCAP scan with profile: $profile${NC}"

                profile_report="$REPORT_DIR/oscap-${profile}.html"

                if timeout 300 oscap xccdf eval \
                    --report "$profile_report" \
                    --profile "$profile" \
                    "$SCAP_DATASTREAM" >/dev/null 2>&1; then
                    log_check "PASS" "OSCAP" "$profile" "OpenSCAP scan completed" "Report: $profile_report"
                else
                    log_check "WARN" "OSCAP" "$profile" "OpenSCAP scan failed or timed out" "Profile: $profile"
                fi
            done
        else
            log_check "WARN" "OSCAP" "SCAN" "No suitable SCAP profiles found" "Available profiles may not match system"
        fi
    else
        log_check "INFO" "OSCAP" "SCAN" "OpenSCAP scan skipped" "OpenSCAP or SCAP content not available"
    fi
    echo
}

# Generate comprehensive HTML report
generate_compliance_report() {
    echo -e "${BOLD}${CYAN} GENERATING VISUAL COMPLIANCE REPORT${NC}"
    echo "==========================================================="

    # Calculate compliance percentages and specific metrics
    if [ $TOTAL_CHECKS -gt 0 ]; then
        overall_compliance=$((PASSED_CHECKS * 100 / TOTAL_CHECKS))

        # Calculate per-standard compliance more accurately
        local stig_total=0 stig_passed=0
        local fips_total=0 fips_passed=0
        local cis_total=0 cis_passed=0
        local debian_total=0 debian_passed=0

        # Count checks per standard from log
        if [ -f "$DETAILED_LOG" ]; then
            stig_total=$(grep -c "\[STIG-" "$DETAILED_LOG" 2>/dev/null || echo "0")
            stig_passed=$(grep -c "\[PASS\] \[STIG-" "$DETAILED_LOG" 2>/dev/null || echo "0")
            fips_total=$(grep -c "\[FIPS-" "$DETAILED_LOG" 2>/dev/null || echo "0")
            fips_passed=$(grep -c "\[PASS\] \[FIPS-" "$DETAILED_LOG" 2>/dev/null || echo "0")
            cis_total=$(grep -c "\[CIS-" "$DETAILED_LOG" 2>/dev/null || echo "0")
            cis_passed=$(grep -c "\[PASS\] \[CIS-" "$DETAILED_LOG" 2>/dev/null || echo "0")
            debian_total=$(grep -c "\[DEBIAN-" "$DETAILED_LOG" 2>/dev/null || echo "0")
            debian_passed=$(grep -c "\[PASS\] \[DEBIAN-" "$DETAILED_LOG" 2>/dev/null || echo "0")
        fi

        # Calculate percentages
        stig_compliance=$([ "$stig_total" -gt 0 ] && echo $((stig_passed * 100 / stig_total)) || echo "0")
        fips_compliance=$([ "$fips_total" -gt 0 ] && echo $((fips_passed * 100 / fips_total)) || echo "0")
        cis_compliance=$([ "$cis_total" -gt 0 ] && echo $((cis_passed * 100 / cis_total)) || echo "0")
        debian_compliance=$([ "$debian_total" -gt 0 ] && echo $((debian_passed * 100 / debian_total)) || echo "0")
    else
        overall_compliance=0
        stig_compliance=0
        fips_compliance=0
        cis_compliance=0
        debian_compliance=0
    fi

    # Generate detailed findings breakdown
    local critical_findings=0
    local high_findings=0
    local medium_findings=0
    local low_findings=0

    # Categorize findings by severity
    critical_findings=$((STIG_VIOLATIONS + FIPS_VIOLATIONS))
    high_findings=$CIS_VIOLATIONS
    medium_findings=$DEBIAN_VIOLATIONS
    low_findings=$(grep -c "\[WARN\]" "$DETAILED_LOG" 2>/dev/null || echo "0")

    cat > "$CUSTOM_REPORT" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HARDN-XDR Enhanced Security Compliance Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            background-color: black;
            color: #00FF00;
            font-family: 'Courier New', Courier, monospace;
            min-height: 100vh;
            padding: 20px;
            line-height: 1.6;
            overflow-x: hidden;
        }

        .crt {
            animation: flicker 0.2s infinite alternate;
            text-shadow: 0 0 2px #00FF00, 0 0 5px #00FF00;
        }

        @keyframes flicker {
            from { opacity: 1; }
            to { opacity: 0.95; }
        }

        .matrix-bg {
            position: fixed;
            width: 100%;
            height: 100%;
            top: 0;
            left: 0;
            z-index: -1;
            background: repeating-linear-gradient(
                to bottom,
                rgba(0, 255, 0, 0.1),
                rgba(0, 255, 0, 0.1) 2px,
                transparent 2px,
                transparent 4px
            );
            animation: scroll 20s linear infinite;
        }

        @keyframes scroll {
            from { background-position: 0 0; }
            to { background-position: 0 100%; }
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: rgba(0, 0, 0, 0.9);
            border: 2px solid #00FF00;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
            overflow: hidden;
        }

        .header {
            background: rgba(0, 0, 0, 0.95);
            border-bottom: 2px solid #00FF00;
            color: #00FF00;
            padding: 30px;
            position: relative;
            text-align: center;
        }

        .ascii-art {
            font-size: 12px;
            white-space: pre;
            margin: 20px auto;
            display: block;
            text-align: center;
            color: #00FF00;
            text-shadow: 0 0 10px #00FF00;
        }

        @media (max-width: 768px) {
            .ascii-art { font-size: 8px; }
        }

        @media (max-width: 480px) {
            .ascii-art { font-size: 6px; }
        }

        .header h1 {
            font-size: 2.5em;
            margin: 20px 0;
            text-align: center;
            color: #00FF00;
            text-shadow: 0 0 10px #00FF00;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
        }

        .header-logo {
            height: 80px;
            width: auto;
            border-radius: 10px;
            border: 3px solid #00FF00;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.6);
            background: rgba(0, 0, 0, 0.9);
            padding: 8px;
            filter: brightness(1.4) contrast(1.2);
            margin-right: 15px;
        }

        .header-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }

        .info-card {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid #3498db;
            text-align: center;
        }

        .info-card h3 {
            font-size: 1.1em;
            margin-bottom: 10px;
            color: #ecf0f1;
        }

        .info-card p {
            font-size: 1.2em;
            font-weight: bold;
        }

        .executive-summary {
            padding: 40px;
            background: rgba(0, 0, 0, 0.9);
            border-top: 2px solid #00FF00;
        }

        .executive-summary h2 {
            color: #00FF00;
            margin-bottom: 30px;
            font-size: 2em;
            text-align: center;
            text-shadow: 0 0 10px #00FF00;
        }

        .metric-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }

        .metric-card {
            background: rgba(0, 0, 0, 0.8);
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
            border: 2px solid #00FF00;
            transition: transform 0.3s ease;
        }

        .metric-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 0 30px rgba(0, 255, 0, 0.6);
        }

        .metric-card.overall, .metric-card.critical, .metric-card.high, 
        .metric-card.medium, .metric-card.low, .metric-card.info { 
            border-color: #00FF00; 
        }

        .metric-card h3 {
            font-size: 2.5em;
            margin-bottom: 10px;
            color: #00FF00;
            text-shadow: 0 0 10px #00FF00;
        }

        .metric-card p {
            font-size: 1.1em;
            color: #00FF00;
            font-weight: 500;
            text-shadow: 0 0 5px #00FF00;
        }

        .compliance-section {
            padding: 40px;
            background: white;
        }

        .compliance-section h2 {
            color: #2c3e50;
            margin-bottom: 30px;
            font-size: 2em;
            text-align: center;
        }

        .progress-container {
            max-width: 800px;
            margin: 0 auto;
        }

        .compliance-meter {
            margin: 25px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
        }

        .meter-label {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
            font-weight: 600;
            font-size: 1.1em;
        }

        .meter-bar {
            width: 100%;
            height: 30px;
            background: #ecf0f1;
            border-radius: 15px;
            overflow: hidden;
            position: relative;
        }

        .meter-fill {
            height: 100%;
            border-radius: 15px;
            transition: width 2s ease-in-out;
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.5);
        }

        .meter-fill.stig { background: linear-gradient(90deg, #e74c3c, #c0392b); }
        .meter-fill.fips { background: linear-gradient(90deg, #9b59b6, #8e44ad); }
        .meter-fill.cis { background: linear-gradient(90deg, #3498db, #2980b9); }
        .meter-fill.debian { background: linear-gradient(90deg, #27ae60, #229954); }

        .findings-section {
            padding: 40px;
            background: #f8f9fa;
        }

        .findings-section h2 {
            color: #2c3e50;
            margin-bottom: 30px;
            font-size: 2em;
            text-align: center;
        }

        .findings-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 30px;
        }

        .findings-card {
            background: white;
            border-radius: 15px;
            overflow: hidden;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }

        .findings-card:hover {
            transform: translateY(-5px);
        }

        .findings-header {
            padding: 20px;
            font-weight: bold;
            color: white;
            text-align: center;
        }

        .findings-header h3 {
            font-size: 1.3em;
            margin: 0;
        }

        .findings-header.stig { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); }
        .findings-header.fips { background: linear-gradient(135deg, #9b59b6 0%, #8e44ad 100%); }
        .findings-header.cis { background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); }
        .findings-header.debian { background: linear-gradient(135deg, #27ae60 0%, #229954 100%); }

        .findings-content {
            padding: 20px;
            max-height: 400px;
            overflow-y: auto;
        }

        .finding-item {
            padding: 12px;
            margin: 8px 0;
            border-radius: 8px;
            border-left: 4px solid;
            font-size: 0.9em;
        }

        .finding-item strong {
            display: block;
            margin-bottom: 5px;
            font-size: 0.9em;
        }

        .finding-item.pass {
            border-color: #27ae60;
            background: #d5f4e6;
            color: #1e8449;
        }
        .finding-item.fail {
            border-color: #e74c3c;
            background: #fadbd8;
            color: #a93226;
        }
        .finding-item.warn {
            border-color: #f39c12;
            background: #fdeaa7;
            color: #b7950b;
        }
        .finding-item.info {
            border-color: #3498db;
            background: #d6eaf8;
            color: #1f618d;
        }

        .recommendations {
            padding: 40px;
            background: white;
        }

        .recommendations h2 {
            color: #2c3e50;
            margin-bottom: 30px;
            font-size: 2em;
            text-align: center;
        }

        .recommendation-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
        }

        .recommendation-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }

        .recommendation-card:hover {
            transform: translateY(-5px);
        }

        .recommendation-card h3 {
            margin-bottom: 15px;
            font-size: 1.3em;
            border-bottom: 2px solid rgba(255,255,255,0.3);
            padding-bottom: 10px;
        }

        .recommendation-card p {
            line-height: 1.8;
        }

        .footer {
            background: #2c3e50;
            color: white;
            padding: 40px;
            text-align: center;
        }

        .footer-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 30px;
            margin-bottom: 30px;
            text-align: left;
        }

        .footer-section h4 {
            margin-bottom: 15px;
            color: #3498db;
            font-size: 1.2em;
        }

        .footer-section a {
            color: #bdc3c7;
            text-decoration: none;
            display: block;
            margin: 8px 0;
            padding: 5px 0;
            border-bottom: 1px solid transparent;
            transition: all 0.3s ease;
        }

        .footer-section a:hover {
            color: #3498db;
            border-bottom-color: #3498db;
        }

        .footer-section p {
            margin: 8px 0;
            color: #bdc3c7;
        }

        .footer-section code {
            background: rgba(255,255,255,0.1);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.9em;
        }

        .risk-assessment {
            margin-top: 30px;
            padding: 20px;
            background: rgba(255,255,255,0.1);
            border-radius: 10px;
        }

        .severity-badge {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 1em;
            font-weight: bold;
            margin-left: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .severity-badge.excellent { background: #27ae60; color: white; }
        .severity-badge.good { background: #2ecc71; color: white; }
        .severity-badge.fair { background: #f39c12; color: white; }
        .severity-badge.poor { background: #e67e22; color: white; }
        .severity-badge.critical { background: #e74c3c; color: white; }

        .chart-placeholder {
            background: #ecf0f1;
            height: 300px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #7f8c8d;
            font-size: 1.2em;
            margin: 20px 0;
        }

        /* Simple CSS-only chart */
        .css-chart {
            display: flex;
            align-items: end;
            height: 200px;
            gap: 20px;
            margin: 30px 0;
            justify-content: center;
        }

        .chart-bar {
            width: 60px;
            background: linear-gradient(to top, #3498db, #2980b9);
            border-radius: 8px 8px 0 0;
            display: flex;
            align-items: end;
            justify-content: center;
            color: white;
            font-weight: bold;
            padding: 10px 5px;
            transition: all 0.5s ease;
        }

        .chart-bar.passed { background: linear-gradient(to top, #27ae60, #229954); }
        .chart-bar.failed { background: linear-gradient(to top, #e74c3c, #c0392b); }
        .chart-bar.warnings { background: linear-gradient(to top, #f39c12, #e67e22); }

        .chart-labels {
            display: flex;
            gap: 20px;
            justify-content: center;
            margin-top: 10px;
        }

        .chart-label {
            width: 60px;
            text-align: center;
            font-weight: bold;
            color: #2c3e50;
        }

        @media (max-width: 768px) {
            .header h1 { font-size: 1.8em; }
            .metric-cards { grid-template-columns: 1fr; }
            .findings-grid { grid-template-columns: 1fr; }
            .recommendation-grid { grid-template-columns: 1fr; }
            .footer-grid { grid-template-columns: 1fr; }
            body { padding: 10px; }
        }

        /* Animation classes */
        .fade-in {
            animation: fadeIn 1s ease-in;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .slide-in {
            animation: slideIn 0.8s ease-out;
        }

        @keyframes slideIn {
            from { transform: translateX(-100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
    </style>
</head>
<body class="crt">
    <div class="matrix-bg"></div>
    <div class="container">
        <div class="header fade-in">
            <h1>
                <img src="sig_logo.png" alt="HARDN-XDR Logo" class="header-logo">
                    HARDN-XDR Security Compliance Report
            </h1>
            <div class="header-info">
                <div class="info-card">
                    <h3> Generated</h3>
                    <p>$(date)</p>
                </div>
                <div class="info-card">
                    <h3>System</h3>
                    <p>$(uname -o) $(uname -r)</p>
                </div>
                <div class="info-card">
                    <h3> Scan User</h3>
                    <p>$(whoami)@$(hostname)</p>
                </div>
                <div class="info-card">
                    <h3> Scan Duration</h3>
                    <p>$(( $(date +%s) - $(stat -c %Y "$DETAILED_LOG" 2>/dev/null || date +%s) )) seconds</p>
                </div>
            </div>
        </div>

        <div class="executive-summary">
            <h2> Executive Summary</h2>

            <div class="metric-cards fade-in">
                <div class="metric-card overall">
                    <h3>$overall_compliance%</h3>
                    <p>Overall Compliance</p>
                </div>
                <div class="metric-card critical">
                    <h3>$critical_findings</h3>
                    <p>Critical Findings</p>
                </div>
                <div class="metric-card high">
                    <h3>$high_findings</h3>
                    <p>High Priority</p>
                </div>
                <div class="metric-card medium">
                    <h3>$medium_findings</h3>
                    <p>Medium Priority</p>
                </div>
                <div class="metric-card low">
                    <h3>$low_findings</h3>
                    <p>Low Priority</p>
                </div>
                <div class="metric-card info">
                    <h3>$TOTAL_CHECKS</h3>
                    <p>Total Checks</p>
                </div>
                <div class="metric-card info">
                    <h3>$PASSED_CHECKS</h3>
                    <p>Passed</p>
                </div>
                <div class="metric-card info">
                    <h3>$FAILED_CHECKS</h3>
                    <p>Failed</p>
                </div>
            </div>

            <div class="css-chart">
                <div class="chart-bar passed" style="height: $(($PASSED_CHECKS * 180 / ($TOTAL_CHECKS > 0 ? $TOTAL_CHECKS : 1)))px;">$PASSED_CHECKS</div>
                <div class="chart-bar failed" style="height: $(($FAILED_CHECKS * 180 / ($TOTAL_CHECKS > 0 ? $TOTAL_CHECKS : 1)))px;">$FAILED_CHECKS</div>
                <div class="chart-bar warnings" style="height: $(($low_findings * 180 / ($TOTAL_CHECKS > 0 ? $TOTAL_CHECKS : 1)))px;">$low_findings</div>
            </div>
            <div class="chart-labels">
                <div class="chart-label">Passed</div>
                <div class="chart-label">Failed</div>
                <div class="chart-label">Warnings</div>
            </div>
        </div>

        <div class="compliance-section">
            <h2>Compliance Progress by Standard</h2>

            <div class="progress-container slide-in">
                <div class="compliance-meter">
                    <div class="meter-label">
                        <span>DISA STIG</span>
                        <span>$stig_compliance%</span>
                    </div>
                    <div class="meter-bar">
                        <div class="meter-fill stig" style="width: $stig_compliance%;">$stig_compliance%</div>
                    </div>
                </div>

                <div class="compliance-meter">
                    <div class="meter-label">
                        <span>FIPS 140-2</span>
                        <span>$fips_compliance%</span>
                    </div>
                    <div class="meter-bar">
                        <div class="meter-fill fips" style="width: $fips_compliance%;">$fips_compliance%</div>
                    </div>
                </div>

                <div class="compliance-meter">
                    <div class="meter-label">
                        <span>CIS Controls</span>
                        <span>$cis_compliance%</span>
                    </div>
                    <div class="meter-bar">
                        <div class="meter-fill cis" style="width: $cis_compliance%;">$cis_compliance%</div>
                    </div>
                </div>

                <div class="compliance-meter">
                    <div class="meter-label">
                        <span>Debian Security</span>
                        <span>$debian_compliance%</span>
                    </div>
                    <div class="meter-bar">
                        <div class="meter-fill debian" style="width: $debian_compliance%;">$debian_compliance%</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="findings-section">
            <h2>🔍 Detailed Findings</h2>
        </div>
    </div>
    </body>
    </html>
EOF

    # Continue with the rest of the script function
    if [ "$ENABLE_DETAILED_REPORTING" = "true" ]; then
        cat >> "$CUSTOM_REPORT" << EOF
                </div>
            </div>

            <div class="findings-card">
                <div class="findings-header fips">
                    <h3><i class="fas fa-lock"></i> FIPS 140-2 Findings</h3>
                </div>
                <div class="findings-content">
EOF

    # Generate FIPS findings
    if [ -f "$DETAILED_LOG" ]; then
        grep "\[FIPS-" "$DETAILED_LOG" | while read -r line; do
            status=$(echo "$line" | grep -o '\[PASS\]\|\[FAIL\]\|\[WARN\]' | tr -d '[]' | tr '[:upper:]' '[:lower:]')
            description=$(echo "$line" | sed 's/.*\] //')
            echo "                    <div class=\"finding-item $status\">"
            echo "                        <strong>$(echo "$line" | grep -o '\[FIPS-[^]]*\]')</strong>"
            echo "                        <p>$description</p>"
            echo "                    </div>"
        done >> "$CUSTOM_REPORT"
    fi

    cat >> "$CUSTOM_REPORT" << EOF
                </div>
            </div>

            <div class="findings-card">
                <div class="findings-header cis">
                    <h3><i class="fas fa-cogs"></i> CIS Controls Findings</h3>
                </div>
                <div class="findings-content">
EOF

    # Generate CIS findings
    if [ -f "$DETAILED_LOG" ]; then
        grep "\[CIS-" "$DETAILED_LOG" | while read -r line; do
            status=$(echo "$line" | grep -o '\[PASS\]\|\[FAIL\]\|\[WARN\]' | tr -d '[]' | tr '[:upper:]' '[:lower:]')
            description=$(echo "$line" | sed 's/.*\] //')
            echo "                    <div class=\"finding-item $status\">"
            echo "                        <strong>$(echo "$line" | grep -o '\[CIS-[^]]*\]')</strong>"
            echo "                        <p>$description</p>"
            echo "                    </div>"
        done >> "$CUSTOM_REPORT"
    fi

    cat >> "$CUSTOM_REPORT" << EOF
                </div>
            </div>

            <div class="findings-card">
                <div class="findings-header debian">
                    <h3><i class="fab fa-debian"></i> Debian Security Findings</h3>
                </div>
                <div class="findings-content">
EOF

    # Generate Debian findings
    if [ -f "$DETAILED_LOG" ]; then
        grep "\[DEBIAN-" "$DETAILED_LOG" | while read -r line; do
            status=$(echo "$line" | grep -o '\[PASS\]\|\[FAIL\]\|\[WARN\]' | tr -d '[]' | tr '[:upper:]' '[:lower:]')
            description=$(echo "$line" | sed 's/.*\] //')
            echo "                    <div class=\"finding-item $status\">"
            echo "                        <strong>$(echo "$line" | grep -o '\[DEBIAN-[^]]*\]')</strong>"
            echo "                        <p>$description</p>"
            echo "                    </div>"
        done >> "$CUSTOM_REPORT"
    fi

    cat >> "$CUSTOM_REPORT" << EOF
                </div>
            </div>
        </div>

        <div class="recommendations">
            <h2><i class="fas fa-lightbulb"></i> Priority Recommendations</h2>
            <div class="recommendation-grid">
                <div class="recommendation-card">
                    <h3><i class="fas fa-exclamation-triangle"></i> Critical Actions</h3>
                    <p>• Configure password minimum length ≥14 characters<br>
                    • Implement account lockout policy<br>
                    • Enable FIPS 140-2 mode for compliance<br>
                    • Disable SSH empty password authentication</p>
                </div>

                <div class="recommendation-card">
                    <h3><i class="fas fa-tools"></i> Security Tools</h3>
                    <p>• Install and configure AppArmor<br>
                    • Enable UFW firewall<br>
                    • Install hardware inventory tools<br>
                    • Configure vulnerability scanners</p>
                </div>

                <div class="recommendation-card">
                    <h3><i class="fas fa-sync-alt"></i> Automation</h3>
                    <p>• Enable automatic security updates<br>
                    • Schedule regular compliance scans<br>
                    • Configure monitoring and alerting<br>
                    • Implement continuous compliance</p>
                </div>

                <div class="recommendation-card">
                    <h3><i class="fas fa-shield-alt"></i> Hardening</h3>
                    <p>• Review and harden SSH configuration<br>
                    • Implement network security controls<br>
                    • Enable additional MAC systems<br>
                    • Regular security assessments</p>
                </div>
            </div>
        </div>

        <div class="footer">
            <div class="footer-grid">
                <div class="footer-section">
                    <h4><i class="fas fa-book"></i> Compliance Standards</h4>
                    <a href="https://public.cyber.mil/stigs/">DISA STIG Library</a>
                    <a href="https://csrc.nist.gov/projects/cryptographic-module-validation-program">NIST FIPS 140-2</a>
                    <a href="https://www.cisecurity.org/controls/">CIS Controls</a>
                    <a href="https://www.debian.org/security/">Debian Security</a>
                </div>

                <div class="footer-section">
                    <h4><i class="fas fa-tools"></i> Security Tools</h4>
                    <a href="https://www.open-scap.org/">OpenSCAP Project</a>
                    <a href="https://wiki.apparmor.net/">AppArmor Documentation</a>
                    <a href="https://help.ubuntu.com/community/UFW">UFW Firewall Guide</a>
                    <a href="https://www.fail2ban.org/">Fail2ban</a>
                </div>

                <div class="footer-section">
                    <h4><i class="fas fa-file-alt"></i> Report Files</h4>
                    <p>Detailed Log: <code>$DETAILED_LOG</code></p>
                    <p>OpenSCAP Reports: <code>$REPORT_DIR/oscap-*.html</code></p>
                    <p>Generated: $(date)</p>
                </div>

                <div class="footer-section">
                    <h4><i class="fas fa-info-circle"></i> About</h4>
                    <p>HARDN-XDR Unified Compliance Scanner</p>
                    <p>Based on Red Hat Security Hardening</p>
                    <p>Version 2.0 Enhanced</p>
                </div>
            </div>

            <hr style="margin: 20px 0; border: none; border-top: 1px solid #34495e;">

            <p><strong>Risk Assessment:</strong>
EOF

    # Risk assessment based on compliance score
    if [ $FAILED_CHECKS -eq 0 ]; then
        echo "            <span class=\"severity-badge low\">EXCELLENT</span> - System demonstrates strong security compliance across all standards." >> "$CUSTOM_REPORT"
    elif [ $overall_compliance -ge 90 ]; then
        echo "            <span class=\"severity-badge low\">GOOD</span> - System has strong security posture with minor issues to address." >> "$CUSTOM_REPORT"
    elif [ $overall_compliance -ge 75 ]; then
        echo "            <span class=\"severity-badge medium\">FAIR</span> - System needs security improvements to meet compliance standards." >> "$CUSTOM_REPORT"
    elif [ $overall_compliance -ge 50 ]; then
        echo "            <span class=\"severity-badge high\">POOR</span> - Significant security remediation required for compliance." >> "$CUSTOM_REPORT"
    else
        echo "            <span class=\"severity-badge critical\">CRITICAL</span> - Immediate and comprehensive security remediation required!" >> "$CUSTOM_REPORT"
    fi

    cat >> "$CUSTOM_REPORT" << EOF
            </p>
        </div>
    </div>

    <script>
        // Simple animations without external dependencies
        document.addEventListener('DOMContentLoaded', function() {
            // Animate progress bars
            setTimeout(() => {
                const progressBars = document.querySelectorAll('.meter-fill');
                progressBars.forEach(bar => {
                    const targetWidth = bar.getAttribute('data-width') || bar.style.width;
                    bar.style.width = '0%';
                    setTimeout(() => {
                        bar.style.width = targetWidth;
                    }, 100);
                });
            }, 500);

            // Add hover effects to cards
            const cards = document.querySelectorAll('.metric-card, .findings-card, .recommendation-card');
            cards.forEach(card => {
                card.addEventListener('mouseenter', function() {
                    this.style.transform = 'translateY(-5px)';
                });
                card.addEventListener('mouseleave', function() {
                    this.style.transform = 'translateY(0)';
                });
            });

            // Smooth scroll for any internal links
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', function (e) {
                    e.preventDefault();
                    const target = document.querySelector(this.getAttribute('href'));
                    if (target) {
                        target.scrollIntoView({
                            behavior: 'smooth'
                        });
                    }
                });
            });

            // Simple fade-in animation for page load
            const sections = document.querySelectorAll('.fade-in, .slide-in');
            sections.forEach((section, index) => {
                section.style.opacity = '0';
                section.style.transform = 'translateY(20px)';
                setTimeout(() => {
                    section.style.transition = 'all 0.6s ease';
                    section.style.opacity = '1';
                    section.style.transform = 'translateY(0)';
                }, index * 200);
            });
        });
    </script>
</body>
</html>
EOF

    fi
    
    log_check "PASS" "REPORT" "001" "Enhanced visual compliance report generated" "$CUSTOM_REPORT"
    
    # Update server.sh with current information
    update_server_script
    
    # Start web server for dashboard
    start_web_server
}

# Update server.sh with dynamic information
update_server_script() {
    local SERVER_SCRIPT="$(dirname "$0")/frontend/server.sh"
    local TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    local SCAN_USER="$(whoami)@$(hostname)"
    local SYSTEM_INFO="$(uname -sr)"
    
    cat > "$SERVER_SCRIPT" << EOF
#!/bin/bash

# Simple HTTP Server for HARDN-XDR Dashboard
# Serves on port 8021
# Auto-updated by hardn_audit.sh

REPORT_DIR="\$(dirname "\$0")/dashboard"
PORT=8021
TIMESTAMP="$TIMESTAMP"
SCAN_USER="$SCAN_USER"
SYSTEM_INFO="$SYSTEM_INFO"

echo "🌐 Starting HARDN-XDR Dashboard Server"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Serving from: \$REPORT_DIR"
echo "URL: http://localhost:\$PORT"
echo "Report: http://localhost:\$PORT/hardn-compliance.html"
echo "Last Scan: \$TIMESTAMP"
echo "Scan User: \$SCAN_USER"
echo "System: \$SYSTEM_INFO"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

cd "\$REPORT_DIR"

# Check if Python 3 is available
if command -v python3 >/dev/null 2>&1; then
    echo " Using Python 3 HTTP server..."
    echo " Server starting on http://localhost:\$PORT"
    echo ""
    python3 -m http.server \$PORT
elif command -v python >/dev/null 2>&1; then
    echo "Using Python 2 HTTP server..."
    echo "Server starting on http://localhost:\$PORT"
    echo ""
    python -m SimpleHTTPServer \$PORT
else
    echo " Python not found. Please install Python to run the server."
    echo "   Try: sudo apt install python3"
    exit 1
fi
EOF
    
    chmod +x "$SERVER_SCRIPT"
    
    log_check "PASS" "SERVER" "001" "Server script updated" "$SERVER_SCRIPT"
}

# Function to start web server
start_web_server() {
    local server_script="$REPORT_DIR/../server.sh"
    local dashboard_url="http://localhost:8021/hardn-compliance.html"
    
    # Check if server is already running
    if netstat -tuln 2>/dev/null | grep -q ":8021 "; then
        echo -e "${GREEN} Dashboard server already running${NC}"
        return 0
    fi
    
    # Start the server in background
    if [ -x "$server_script" ]; then
        echo -e "${YELLOW} Starting dashboard server...${NC}"
        cd "$(dirname "$server_script")" && nohup ./server.sh > server.log 2>&1 &
        
        # Wait a moment and check if server started
        sleep 2
        if netstat -tuln 2>/dev/null | grep -q ":8021 "; then
            echo -e "${GREEN} Dashboard server started successfully${NC}"
            echo -e "${BLUE} Dashboard URL: ${dashboard_url}${NC}"
            return 0
        else
            echo -e "${YELLOW} Server may still be starting...${NC}"
            echo -e "${BLUE}Dashboard URL: ${dashboard_url}${NC}"
            return 1
        fi
    else
        echo -e "${RED}Server script not found or not executable${NC}"
        return 1
    fi
}

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up temporary files...${NC}"
    # Keep reports but clean up any temporary scan files
    find /tmp -name "oscap-*" -type f -mmin +60 -delete 2>/dev/null || true
}

# Main execution function
main() {
    print_banner

    echo "Starting comprehensive compliance scan at $(date)"
    echo "Report directory: $REPORT_DIR"
    echo

    # Check system requirements
    check_openscap_availability

    # Run all compliance checks
    check_stig_compliance
    check_fips_compliance
    check_cis_compliance
    check_debian_security

    # Run OpenSCAP if available
    run_openscap_scan

    # Generate comprehensive report
    generate_compliance_report

    # Final summary
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}                    COMPLIANCE SCAN COMPLETE                    ${NC}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${NC}"

    echo -e "Total Checks: ${BLUE}$TOTAL_CHECKS${NC}"
    echo -e "Passed: ${GREEN}$PASSED_CHECKS${NC}"
    echo -e "Failed: ${RED}$FAILED_CHECKS${NC}"

    if [ $TOTAL_CHECKS -gt 0 ]; then
        overall_compliance=$((PASSED_CHECKS * 100 / TOTAL_CHECKS))
        echo -e "Overall Compliance: ${BLUE}$overall_compliance%${NC}"
    fi

    echo
    echo -e "Standards Violations:"
    echo -e "  STIG: ${YELLOW}$STIG_VIOLATIONS${NC}"
    echo -e "  FIPS: ${PURPLE}$FIPS_VIOLATIONS${NC}"
    echo -e "  CIS: ${CYAN}$CIS_VIOLATIONS${NC}"
    echo -e "  Debian: ${GREEN}$DEBIAN_VIOLATIONS${NC}"

    echo
    echo -e "Reports generated:"
    echo -e "  HTML Report: ${BLUE}$CUSTOM_REPORT${NC}"
    echo -e "  Detailed Log: ${BLUE}$DETAILED_LOG${NC}"
    if [ "$OSCAP_AVAILABLE" = true ]; then
        echo -e "  OpenSCAP Reports: ${BLUE}$REPORT_DIR/oscap-*.html${NC}"
    fi
    
    echo
    echo -e "${BOLD}${CYAN}🌐 LIVE DASHBOARD ACCESS${NC}"
    echo -e "${BOLD}${CYAN}═══════════════════════${NC}"
    echo -e "Dashboard URL: ${GREEN}http://localhost:8021/hardn-compliance.html${NC}"
    echo -e "To stop server: ${YELLOW}pkill -f 'python.*8021'${NC}"

    # Set exit code based on compliance
    if [ $FAILED_CHECKS -eq 0 ]; then
        echo -e "\n${GREEN}✅ COMPLIANCE SCAN PASSED${NC}"
        exit 0
    elif [ $FAILED_CHECKS -le 5 ]; then
        echo -e "\n${YELLOW}⚠️ COMPLIANCE ISSUES DETECTED${NC}"
        echo -e "${YELLOW}Review and address failed checks${NC}"
        exit 1
    else
        echo -e "\n${RED}❌ SIGNIFICANT COMPLIANCE VIOLATIONS${NC}"
        echo -e "${RED}Immediate remediation required!${NC}"
        exit 2
    fi
}

# Trap cleanup on exit
trap cleanup EXIT

# Check for root privileges for complete scanning
if [ $EUID -ne 0 ]; then
    echo -e "${YELLOW}Warning: Not running as root. Some checks may be incomplete.${NC}"
    echo "For complete compliance scanning, run: sudo $0"
    echo
fi

# Run main function
main "$@"
