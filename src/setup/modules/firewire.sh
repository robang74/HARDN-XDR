#!/bin/bash

# shellcheck source=/usr/lib/hardn-xdr/src/setup/hardn-common.sh
source /usr/lib/hardn-xdr/src/setup/hardn-common.sh
set -e

# Check for container environment first
if is_container_environment; then
    HARDN_STATUS "info" "Container environment detected - hardware module management is typically handled by the host"
    HARDN_STATUS "info" "FireWire modules are usually not loaded in containers"
    HARDN_STATUS "pass" "FireWire protection: handled by container runtime/host"
    return 0 2>/dev/null || hardn_module_exit 0
fi

HARDN_STATUS "info" "Checking/Disabling FireWire (IEEE 1394) drivers..."
firewire_modules="firewire_core firewire_ohci firewire_sbp2"
changed=0
blacklist_file="/etc/modprobe.d/blacklist-firewire.conf"

for module_name in $firewire_modules; do
	if lsmod | grep -q "^${module_name}"; then
		HARDN_STATUS "info" "FireWire module $module_name is loaded. Attempting to unload..."
		if rmmod "$module_name" 2>/dev/null; then
			HARDN_STATUS "pass" "FireWire module $module_name unloaded successfully."
			changed=1
		else
			HARDN_STATUS "warning" "Could not unload FireWire module $module_name (may be in use or built-in)"
		fi
	else
		HARDN_STATUS "info" "FireWire module $module_name is not currently loaded."
	fi
done

if [[ ! -f "$blacklist_file" ]]; then
	touch "$blacklist_file"
	HARDN_STATUS "pass" "Created FireWire blacklist file: $blacklist_file"
fi

for module_name in $firewire_modules; do
	if ! grep -q "blacklist $module_name" "$blacklist_file"; then
		echo "blacklist $module_name" >> "$blacklist_file"
		HARDN_STATUS "pass" "Blacklisted FireWire module $module_name in $blacklist_file"
		changed=1
	else
		HARDN_STATUS "info" "FireWire module $module_name already blacklisted in $blacklist_file."
	fi
done

if [[ "$changed" -eq 1 ]]; then
	HARDN_STATUS "pass" "FireWire drivers checked. Unloaded and/or blacklisted where applicable"
else
	HARDN_STATUS "info" "FireWire drivers checked. No changes made (likely already disabled/not present)"
fi

return 0 2>/dev/null || hardn_module_exit 0
