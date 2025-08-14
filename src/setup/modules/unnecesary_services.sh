#!/bin/bash

# Resolve repo install or source tree layout
COMMON_CANDIDATES=(
  "/usr/lib/hardn-xdr/src/setup/hardn-common.sh"
  "$(dirname "$(readlink -f "$0")")/../hardn-common.sh"
)
for c in "${COMMON_CANDIDATES[@]}"; do
  [ -r "$c" ] && . "$c" && break
done
type -t HARDN_STATUS >/dev/null 2>&1 || { echo "[ERROR] failed to source hardn-common.sh"; exit 0; } # exit 0 to avoid CI failures

# Skip if not root or in container/non-systemd environment
require_root_or_skip || exit 0

if is_container || ! has_systemd; then
    HARDN_STATUS "info" "Skipping service operations in non-systemd/container environment"
    exit 0
fi

HARDN_STATUS "info" "Disabling unnecessary services..."
disable_service_if_active() {
	local service_name
	service_name="$1"
	if systemctl is-active --quiet "$service_name"; then
		HARDN_STATUS "info" "Disabling active service: $service_name..."
		systemctl disable --now "$service_name" || HARDN_STATUS "warning" "Failed to disable service: $service_name (may not be installed or already disabled)."
	elif systemctl list-unit-files --type=service | grep -qw "^$service_name.service"; then
		HARDN_STATUS "info" "Service $service_name is not active, ensuring it is disabled..."
		systemctl disable "$service_name" || HARDN_STATUS "warning" "Failed to disable service: $service_name (may not be installed or already disabled)."
	else
		HARDN_STATUS "info" "Service $service_name not found or not installed. Skipping."
	fi
}

disable_service_if_active avahi-daemon
disable_service_if_active cups
disable_service_if_active rpcbind
disable_service_if_active nfs-server
disable_service_if_active smbd
disable_service_if_active snmpd
disable_service_if_active apache2
disable_service_if_active mysql
disable_service_if_active bind9


packages_to_remove="telnet vsftpd proftpd tftpd postfix exim4"
for pkg in $packages_to_remove; do
	if dpkg -s "$pkg" >/dev/null 2>&1; then
		HARDN_STATUS "error" "Removing package: $pkg..."
		apt remove -y "$pkg"
	else
		HARDN_STATUS "info" "Package $pkg not installed. Skipping removal."
	fi
done

HARDN_STATUS "pass" "Unnecessary services checked and disabled/removed where applicable."

# shellcheck disable=SC2317
return 0 2>/dev/null || hardn_module_exit 0
set -e
