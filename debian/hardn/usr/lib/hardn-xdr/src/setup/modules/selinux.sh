#!/bin/bash
source /usr/lib/hardn-xdr/src/setup/hardn-common.sh
set -e

is_installed() {
    if command -v apt >/dev/null 2>&1; then
        dpkg -s "$1" >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        dnf list installed "$1" >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        yum list installed "$1" >/dev/null 2>&1
    elif command -v rpm >/dev/null 2>&1; then
        rpm -q "$1" >/dev/null 2>&1
    else
        return 1 # Cannot determine package manager
    fi
}


# SELinux installation and setup script
# Install SELinux packages (existing logic)
if command -v dnf >/dev/null 2>&1; then
    if ! is_installed selinux-policy; then
        HARDN_STATUS info "Installing SELinux packages with dnf..."
        sudo dnf install -y selinux-policy selinux-policy-targeted policycoreutils policycoreutils-python-utils
    fi
elif command -v yum >/dev/null 2>&1; then
    if ! is_installed selinux-policy; then
        HARDN_STATUS info "Installing SELinux packages with yum..."
        sudo yum install -y selinux-policy selinux-policy-targeted policycoreutils policycoreutils-python
    fi
elif command -v apt-get >/dev/null 2>&1; then
    if ! is_installed selinux-basics; then
        HARDN_STATUS info "Updating apt-get and installing SELinux packages..."
        sudo apt-get update
        sudo apt-get install -y selinux-basics selinux-policy-default auditd
    fi
else
    HARDN_STATUS error "Unsupported package manager. Please install SELinux manually."
fi

# Whiptail checklist for SELinux features/modes
checklist_args=(
    "enforcing" "SELinux Enforcing Mode (recommended for production)" "ON"
    "permissive" "SELinux Permissive Mode (log only, no enforcement)" "OFF"
    "targeted" "Targeted Policy (default, protects key services)" "ON"
    "strict" "Strict Policy (protects all processes)" "OFF"
    "audit" "Enable Audit Logging" "ON"
    "disable" "Disable SELinux (not recommended)" "OFF"
)

selected=$(whiptail --title "SELinux Feature Selection" --checklist "Select SELinux features/modes to ENABLE (SPACE to select, TAB to move):" 20 80 8 "${checklist_args[@]}" 3>&1 1>&2 2>&3)

if [[ $? -ne 0 ]]; then
    HARDN_STATUS info "SELinux configuration cancelled by user. Exiting."
    return 0
fi

# Remove quotes from whiptail output
selected=$(echo $selected | tr -d '"')

# Apply selected SELinux features/modes
if [[ "$selected" == *"disable"* ]]; then
    # Disable SELinux
    if [ -f /etc/selinux/config ]; then
        sudo sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    elif [ -f /etc/selinux/selinux.conf ]; then
        sudo sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/selinux.conf
    fi
    HARDN_STATUS info "SELinux disabled. A reboot may be required."
    return 0
fi

if [[ "$selected" == *"enforcing"* ]]; then
    if [ -f /etc/selinux/config ]; then
        sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
    elif [ -f /etc/selinux/selinux.conf ]; then
        sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/selinux.conf
    fi
    HARDN_STATUS info "SELinux set to enforcing mode."
elif [[ "$selected" == *"permissive"* ]]; then
    if [ -f /etc/selinux/config ]; then
        sudo sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config
    elif [ -f /etc/selinux/selinux.conf ]; then
        sudo sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/selinux.conf
    fi
    HARDN_STATUS info "SELinux set to permissive mode."
fi

if [[ "$selected" == *"targeted"* ]]; then
    if [ -f /etc/selinux/config ]; then
        sudo sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE=targeted/' /etc/selinux/config
    elif [ -f /etc/selinux/selinux.conf ]; then
        sudo sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE=targeted/' /etc/selinux/selinux.conf
    fi
    HARDN_STATUS info "SELinux policy set to targeted."
elif [[ "$selected" == *"strict"* ]]; then
    if [ -f /etc/selinux/config ]; then
        sudo sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE=strict/' /etc/selinux/config
    elif [ -f /etc/selinux/selinux.conf ]; then
        sudo sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE=strict/' /etc/selinux/selinux.conf
    fi
    HARDN_STATUS info "SELinux policy set to strict."
fi

if [[ "$selected" == *"audit"* ]]; then
    sudo auditctl -e 1
    HARDN_STATUS info "SELinux audit logging enabled."
fi

# For Debian/Ubuntu, initialize SELinux if needed
if command -v selinux-activate >/dev/null 2>&1; then
    HARDN_STATUS info "Running selinux-activate..."
    sudo selinux-activate
fi

HARDN_STATUS info "SELinux installation and configuration complete. A reboot may be required for changes to take effect."
