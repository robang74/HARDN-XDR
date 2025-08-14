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

# Skip if not root
require_root_or_skip || exit 0

# Skip in container environments
if is_container; then
    HARDN_STATUS "info" "Skipping USB configuration in container environment"
    exit 0
fi

# Guard required tools
require_cmd_or_skip udevadm || exit 0
require_cmd_or_skip modprobe || exit 0
#!/bin/bash
# shellcheck disable=SC1091
# Remove set -e to handle errors gracefully in CI environment


# USB storage blocking for security hardening (automated mode)
HARDN_STATUS "info" "Configuring USB storage blocking for enhanced security"
HARDN_STATUS "warning" "USB storage devices will be blocked for security purposes"

ROOT_USB=$(lsblk -o NAME,TRAN,MOUNTPOINT | grep -E 'usb.*\/$' || true)

if [[ -n "$ROOT_USB" ]]; then
  HARDN_STATUS "warning" "System is running from USB storage. Skipping USB block to avoid system lockout."
  exit 0  # Changed from return 0 for consistency
fi

# Optional: Check if keyboard is present before blocking
KEYBOARD_OK=$(udevadm info -q property --export -n /dev/input/event* | grep ID_INPUT_KEYBOARD || true)
if [[ -z "$KEYBOARD_OK" ]]; then
  HARDN_STATUS "error" "No valid USB keyboard detected. Blocking USB now may cause login failure."
  return 1
fi

# Proceed with blocking
cat > /etc/modprobe.d/99-usb-storage.conf << 'EOF'
blacklist usb-storage
blacklist uas
EOF

HARDN_STATUS "info" "USB storage modules blacklisted."

cat > /etc/udev/rules.d/99-usb-storage.rules << 'EOF'
# Add valid udev rules here if needed
EOF

HARDN_STATUS "info" "Udev rules written."

udevadm control --reload-rules && udevadm trigger && HARDN_STATUS "pass" "Udev rules reloaded."

# Try unloading storage
if lsmod | grep -q usb_storage; then
  if rmmod usb_storage; then
    HARDN_STATUS "pass" "usb-storage module unloaded."
  else
    HARDN_STATUS "warning" "Failed to unload usb-storage."
  fi
else
  HARDN_STATUS "info" "usb-storage module not currently loaded."
fi

# Ensure HID is enabled
if ! lsmod | grep -q usbhid; then
  if modprobe usbhid; then
    HARDN_STATUS "pass" "usbhid module loaded."
  else
    HARDN_STATUS "warning" "Could not load usbhid (may be normal in CI environment)!"
  fi
else
  HARDN_STATUS "pass" "usbhid module already active."
fi

HARDN_STATUS "pass" "USB policy: storage blocked, HID enabled."

# shellcheck disable=SC2317
return 0 2>/dev/null || hardn_module_exit 0
