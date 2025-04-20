#!/bin/bash
set -euo pipefail

INSTALL_DIR="/opt/hardn"
SERVICE_FILE="/etc/systemd/system/hardn.service"
HARDN_BIN="/usr/local/bin/hardn"
KERNEL_SRC="$INSTALL_DIR/kernel.c"
KERNEL_BIN="/usr/local/bin/kernel"
SETUP_SCRIPT="$INSTALL_DIR/setup/setup.sh"
PKG_SCRIPT="$INSTALL_DIR/setup/packages.sh"
GUI_MAIN="$INSTALL_DIR/gui/main.py"

# Ensure root
if [ "$(id -u)" -ne 0 ]; then
    echo "This installer must be run as root."
    exit 1
fi

echo "[+] Validating required files..."
for file in "$HARDN_BIN" "$KERNEL_SRC" "$SETUP_SCRIPT" "$PKG_SCRIPT" "$GUI_MAIN"; do
    if [ ! -f "$file" ]; then
        echo "Missing: $file"
        exit 1
    fi
done

echo "[+] Making scripts executable..."
chmod +x "$SETUP_SCRIPT" "$PKG_SCRIPT" "$GUI_MAIN"

echo "[+] Compiling kernel.c..."
gcc "$KERNEL_SRC" -o "$KERNEL_BIN"
chmod +x "$KERNEL_BIN"

echo "[+] Setting up HARDN systemd service..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=HARDN Endpoint Orchestration
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$HARDN_BIN --all
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "$SERVICE_FILE"

echo "[+] Reloading systemd and enabling service..."
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable --now hardn.service

echo "[+] HARDN installation complete and service started."