#!/bin/bash
# HARDN-XDR Module: Ubuntu FIPS Compliance
# File: src/setup/modules/ubuntu_fips.sh
# Purpose: Detect, (optionally) enable, and report FIPS mode on Ubuntu systems.
# Behavior:
#   - No-ops on non-Ubuntu.
#   - In CI / non-interactive (SKIP_WHIPTAIL=1), only enforces if HARDN_ENFORCE_FIPS=1.
#   - Writes a JSON compliance record and a reboot flag if changes require reboot.
#MUSTA: Must have Ubuntu-1 lifense with Fips Certificate installed. 
# Env flags:
#   SKIP_WHIPTAIL=1         # Non-interactive (auto mode)
#   HARDN_ENFORCE_FIPS=1    # Enforce FIPS mode if non-compliant
#
set -Euo pipefail

# Load shared utilities
if [[ -f /usr/lib/hardn-xdr/src/setup/hardn-common.sh ]]; then
  # shellcheck source=/dev/null
  source /usr/lib/hardn-xdr/src/setup/hardn-common.sh
else
  # Fallback minimal logger if common isn't present (keeps module usable in isolation)
  HARDN_STATUS() { printf '[%s] %s\n' "${1^^}" "$2"; }
fi

# ---- Helpers -----------------------------------------------------------------

is_ubuntu() {
  [[ -f /etc/os-release ]] || return 1
  . /etc/os-release
  [[ "${ID,,}" == "ubuntu" ]]
}

require_root() {
  if [[ $(id -u) -ne 0 ]]; then
    HARDN_STATUS "warning" "Ubuntu FIPS module requires root; skipping."
    return 1
  fi
}

json_write() {
  # args: key value (string), appends JSON fragment into a temp file var $JSON_TMP
  local k="$1" v="$2"
  printf '  "%s": %s,\n' "$k" "$v" >> "$JSON_TMP"
}

trim_trailing_comma() {
  # removes trailing comma from last JSON field
  sed -i '$ s/,\s*$//' "$1" || true
}

# Prefer 'pro' command name; fall back to 'ua'
pro_cmd() {
  if command -v pro >/dev/null 2>&1; then echo "pro"
  elif command -v ua >/dev/null 2>&1; then echo "ua"
  else echo ""; fi
}

# ---- Detection ---------------------------------------------------------------

detect_fips_kernel() {
  # 1 if FIPS kernel mode enabled, else 0
  if [[ -r /proc/sys/crypto/fips_enabled ]] && [[ "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0)" == "1" ]]; then
    echo 1
  else
    echo 0
  fi
}

detect_cmdline_has_fips() {
  if grep -q -w 'fips=1' /proc/cmdline 2>/dev/null; then
    echo 1
  else
    echo 0
  fi
}

detect_openssl_fips() {
  # Heuristic: look for "fips" in openssl version output or active provider list (OpenSSL 3)
  if ! command -v openssl >/dev/null 2>&1; then
    echo "unknown"
    return
  fi
  local ver="$(openssl version 2>/dev/null || true)"
  local has_ver_fips=0
  [[ "${ver,,}" == *"fips"* ]] && has_ver_fips=1

  local has_provider_fips=0
  if openssl list -providers 2>/dev/null | grep -iq '\bfips\b'; then
    has_provider_fips=1
  fi

  if (( has_ver_fips == 1 || has_provider_fips == 1 )); then
    echo "enabled-or-available"
  else
    echo "not-detected"
  fi
}

check_pro_status() {
  local pcmd
  pcmd="$(pro_cmd)"
  [[ -n "$pcmd" ]] || { echo "missing"; return; }

  local out
  if ! out="$("$pcmd" status 2>&1)"; then
    echo "unknown"
    return
  fi
  if grep -qi 'attached' <<<"$out"; then
    echo "attached"
  else
    echo "not-attached"
  fi
}

# ---- Enforcement -------------------------------------------------------------

ensure_ua_tools() {
  if command -v pro >/dev/null 2>&1 || command -v ua >/dev/null 2>&1; then
    return 0
  fi
  HARDN_STATUS "info" "Installing ubuntu-advantage-tools (for 'pro/ua' command)..."
  apt-get update -y && apt-get install -y ubuntu-advantage-tools || {
    HARDN_STATUS "error" "Failed to install ubuntu-advantage-tools."
    return 1
  }
}

enable_fips_repos() {
  local pcmd; pcmd="$(pro_cmd)"
  [[ -n "$pcmd" ]] || { HARDN_STATUS "error" "Ubuntu Pro/UA tool not found."; return 1; }

  HARDN_STATUS "info" "Enabling FIPS via '$pcmd enable fips'..."
  # --assume-yes keeps it non-interactive; 'pro' accepts -y; 'ua' accepts --assume-yes
  if "$pcmd" enable fips -y 2>/dev/null || "$pcmd" enable fips --assume-yes 2>/dev/null; then
    HARDN_STATUS "pass" "Ubuntu FIPS repositories enabled."
    return 0
  fi

  HARDN_STATUS "error" "Failed to enable FIPS. System may not be attached to Ubuntu Pro."
  return 1
}

ensure_grub_cmdline_fips() {
  local grub_def="/etc/default/grub"
  [[ -f "$grub_def" ]] || { HARDN_STATUS "warning" "GRUB default not found at $grub_def"; return 1; }

  if grep -q '^GRUB_CMDLINE_LINUX=' "$grub_def"; then
    if grep -q 'fips=1' "$grub_def"; then
      return 0
    fi
    sed -i 's/^\(GRUB_CMDLINE_LINUX="[^"]*\)"/\1 fips=1"/' "$grub_def" || return 1
  else
    echo 'GRUB_CMDLINE_LINUX="fips=1"' >> "$grub_def"
  fi

  HARDN_STATUS "info" "Updating GRUB with fips=1..."
  if command -v update-grub >/dev/null 2>&1; then
    update-grub || true
  elif command -v grub-mkconfig >/dev/null 2>&1; then
    grub-mkconfig -o /boot/grub/grub.cfg || true
  fi
}

regen_initramfs() {
  if command -v update-initramfs >/dev/null 2>&1; then
    HARDN_STATUS "info" "Regenerating initramfs..."
    update-initramfs -u || true
  fi
}

mark_reboot_required() {
  local flag="/var/run/hardn/fips_reboot_required"
  mkdir -p /var/run/hardn
  echo "reboot-required" > "$flag"
  HARDN_STATUS "warning" "Reboot required to finalize FIPS mode."
}

# ---- Reporting ---------------------------------------------------------------

write_report() {
  local out_dir="/var/log/hardn/compliance"
  local out_file="$out_dir/fips_ubuntu.json"
  mkdir -p "$out_dir"

  local now iso
  now="$(date +'%Y-%m-%d %H:%M:%S%z')"
  iso="$(date -Iseconds)"

  JSON_TMP="$(mktemp)"
  {
    echo "{"
    json_write "timestamp" "\"$iso\""
    json_write "distro" "\"ubuntu\""
    json_write "kernel_fips_enabled" "$(detect_fips_kernel)"
    json_write "cmdline_has_fips" "$(detect_cmdline_has_fips)"
    local oss; oss="$(detect_openssl_fips)"
    json_write "openssl_fips" "\"$oss\""
    local pc; pc="$(check_pro_status)"
    json_write "ubuntu_pro_status" "\"$pc\""
    echo "  \"notes\": \"Generated by HARDN-XDR Ubuntu FIPS module\""
    echo "}"
  } >> "$JSON_TMP"
  trim_trailing_comma "$JSON_TMP"
  mv -f "$JSON_TMP" "$out_file"
  HARDN_STATUS "info" "Wrote FIPS report: $out_file"
}

summarize_status() {
  local kf="$(detect_fips_kernel)"
  local cf="$(detect_cmdline_has_fips)"
  local oss="$(detect_openssl_fips)"

  if [[ "$kf" == "1" ]] && [[ "$cf" == "1" ]]; then
    HARDN_STATUS "pass" "FIPS mode detected (kernel and cmdline). OpenSSL: $oss"
  else
    HARDN_STATUS "error" "FIPS NOT fully enabled. kernel=$kf cmdline=$cf OpenSSL=$oss"
  fi
}

# ---- Interactive gate --------------------------------------------------------

confirm_enforce_interactive() {
  # returns 0 if user confirmed enforcement, 1 otherwise
  if [[ "${SKIP_WHIPTAIL:-0}" == "1" ]] || ! command -v whiptail >/dev/null 2>&1; then
    return 1
  fi
  whiptail --yesno "Enable Ubuntu FIPS mode? This may change packages and require a reboot." 12 64
}

# ---- Main --------------------------------------------------------------------

main() {
  if ! is_ubuntu; then
    HARDN_STATUS "info" "Ubuntu FIPS module: non-Ubuntu system detected — skipping."
    return 0
  fi
  if ! require_root; then
    write_report
    return 0
  fi

  HARDN_STATUS "info" "Ubuntu FIPS compliance check starting..."

  local kf="$(detect_fips_kernel)"
  local cf="$(detect_cmdline_has_fips)"

  # Already compliant enough (kernel+cmdline); still write report and exit
  if [[ "$kf" == "1" && "$cf" == "1" ]]; then
    summarize_status
    write_report
    return 0
  fi

  # Decide whether to enforce
  local enforce=0
  if [[ "${HARDN_ENFORCE_FIPS:-0}" == "1" ]]; then
    enforce=1
  elif confirm_enforce_interactive; then
    enforce=1
  fi

  if (( enforce == 0 )); then
    HARDN_STATUS "warning" "FIPS is not enabled. Set HARDN_ENFORCE_FIPS=1 to auto-enforce, or rerun interactively."
    summarize_status
    write_report
    return 0
  fi

  # Enforce path
  HARDN_STATUS "info" "Attempting to enforce FIPS mode on Ubuntu..."
  ensure_ua_tools || { summarize_status; write_report; return 0; }

  local pro_state; pro_state="$(check_pro_status)"
  if [[ "$pro_state" == "not-attached" || "$pro_state" == "unknown" ]]; then
    HARDN_STATUS "error" "System is not attached to Ubuntu Pro. Attach first: 'pro attach <token>' or 'ua attach <token>'."
    summarize_status
    write_report
    return 0
  elif [[ "$pro_state" == "missing" ]]; then
    HARDN_STATUS "error" "Ubuntu Pro/UA tool missing after install attempt."
    summarize_status
    write_report
    return 0
  fi

  if ! enable_fips_repos; then
    summarize_status
    write_report
    return 0
  fi

  # Ensure GRUB and initramfs reflect fips=1
  ensure_grub_cmdline_fips || true
  regen_initramfs || true
  mark_reboot_required

  # Post-enforcement summary (pre-reboot state may still show kernel_fips=0)
  summarize_status
  write_report
  return 0
}

main "$@"