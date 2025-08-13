#!/bin/bash
source /usr/lib/hardn-xdr/src/setup/hardn-common.sh
set -e

# Check for container environment
if is_container_environment; then
    check_container_limitations
    
    # Check if we can modify kernel parameters
    if [[ ! -w /proc/sys ]]; then
        HARDN_STATUS "warning" "Container has read-only /proc/sys - kernel parameters cannot be modified"
        HARDN_STATUS "info" "Core dump settings should be configured on the container host"
        return 0 2>/dev/null || hardn_module_exit 0
    fi
fi

HARDN_STATUS "info" "Disabling core dumps..."

# Configure limits.conf if writable and not in container
if [[ -w /etc/security/limits.conf ]] && ! is_container_environment; then
    if ! grep -q "^\* hard core 0" /etc/security/limits.conf 2>/dev/null; then
        echo "* hard core 0" >> /etc/security/limits.conf
        HARDN_STATUS "info" "Added core dump limits to /etc/security/limits.conf"
    fi
else
    HARDN_STATUS "info" "Skipping limits.conf modification (container environment or file not writable)"
fi

# Use safe sysctl functions for kernel parameters
safe_sysctl_set "fs.suid_dumpable" "0"
safe_sysctl_set "kernel.core_pattern" "/dev/null"

HARDN_STATUS "pass" "Core dump protection configured"
HARDN_STATUS "info" "Settings applied: suid_dumpable=0, core_pattern=/dev/null"

return 0 2>/dev/null || hardn_module_exit 0
