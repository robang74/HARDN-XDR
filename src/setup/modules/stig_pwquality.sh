##!/bin/bash
#source /usr/lib/hardn-xdr/src/setup/hardn-common.sh
#set -e
## Universal package installation check function
#is_installed() {
#    local pkg="$1"
#    if command -v dpkg >/dev/null 2>&1; then
#        dpkg -s "$pkg" >/dev/null 2>&1
#    elif command -v rpm >/dev/null 2>&1; then
#        rpm -q "$pkg" >/dev/null 2>&1
#    elif command -v dnf >/dev/null 2>&1; then
#        dnf list installed "$pkg" >/dev/null 2>&1
#    elif command -v yum >/dev/null 2>&1; then
#        yum list installed "$pkg" >/dev/null 2>&1
#    else
#        return 1
#    fi
#}

## Whiptail-driven password policy wizard to helo the user not get locked out
#if command -v whiptail >/dev/null 2>&1; then
#    whiptail --title "STIG Password Policy Wizard" --msgbox "This wizard will help you configure system-wide password policies.\n\nWARNING: Enforcing strict password policies may lock out users who do not update their passwords.\n\nProceed with caution." 14 70
#
#    minlen=$(whiptail --title "Minimum Password Length" --inputbox "Enter minimum password length (recommended: 8):" 10 60 8 3>&1 1>&2 2>&3)
#    ucredit=$(whiptail --title "Uppercase Letters" --inputbox "Minimum uppercase letters required (recommended: 1):" 10 60 1 3>&1 1>&2 2>&3)
#    lcredit=$(whiptail --title "Lowercase Letters" --inputbox "Minimum lowercase letters required (recommended: 1):" 10 60 1 3>&1 1>&2 2>&3)
#    dcredit=$(whiptail --title "Digits" --inputbox "Minimum digits required (recommended: 1):" 10 60 1 3>&1 1>&2 2>&3)
#    ocredit=$(whiptail --title "Special Characters" --inputbox "Minimum special characters required (recommended: 1):" 10 60 1 3>&1 1>&2 2>&3)
#
#    whiptail --title "Lockout Warning" --msgbox "After this script finishes, you MUST change your password using the 'passwd' command.\n\nIf your password does not meet the new requirements, you may be locked out.\n\nPress OK to continue or ESC to cancel." 14 70
#
#    if (whiptail --title "Apply Policy" --yesno "Apply these password policies now?\n\nminlen=$minlen\nucredit=$ucredit\nlcredit=$lcredit\ndcredit=$dcredit\nocredit=$ocredit" 14 70); then
#        if [ -f /etc/pam.d/common-password ]; then
#            if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
#                echo "password requisite pam_pwquality.so retry=3 minlen=$minlen ucredit=-$ucredit lcredit=-$lcredit dcredit=-$dcredit ocredit=-$ocredit" | sudo tee -a /etc/pam.d/common-password
#                HARDN_STATUS "pass" "PAM password quality rules applied."
#            else
#                HARDN_STATUS "info" "PAM password quality already configured."
#            fi
#        else
#            HARDN_STATUS "warning" "Warning: /etc/pam.d/common-password not found, skipping PAM configuration..."
#        fi
#    else
#        HARDN_STATUS "info" "Password policy configuration cancelled by user."
#    fi
#else
#    HARDN_STATUS "warning" "whiptail not found, skipping password policy wizard."
#    HARDN_STATUS "warning" "Please be aware that password policies will be enforced."
#fi
#
##Safe return or exit
#return 0 2>/dev/null || exit 0