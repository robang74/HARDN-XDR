#!/bin/bash
# shellcheck disable=SC1091
source /usr/lib/hardn-xdr/src/setup/hardn-common.sh


HARDN_STATUS "info" "Restricting compiler access to root only (HRDN-7222)..."

compilers="/usr/bin/gcc /usr/bin/g++ /usr/bin/make /usr/bin/cc /usr/bin/c++ /usr/bin/as /usr/bin/ld"
for bin in $compilers; do
	if [[ -f "$bin" ]]; then
		chmod 755 "$bin"
		chown root:root "$bin"
		HARDN_STATUS "pass" "Set $bin to 755 root:root (default for compilers)."
	fi
done

#Safe return or exit

# shellcheck disable=SC2317
return 0 2>/dev/null || hardn_module_exit 0

