#!/usr/bin/env bash
# install-ip-mask-service.sh — Install the IP Mask Decoder systemd service
# Run with: sudo bash install-ip-mask-service.sh

set -e

SERVICE_FILE="/etc/systemd/system/ip-mask-decoder.service"
SOURCE_SERVICE="/home/hermes/ip-mask-decoder.service"
TORCH_SCRIPT="/home/hermes/ip_mask.py"
KEY_FILE="/home/hermes/keys/private.pem"

echo "=== IP Mask Decoder — Systemd Service Installer ==="
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root (sudo)."
    echo "  sudo bash $0"
    exit 1
fi

# Check prerequisites
if [ ! -f "$SOURCE_SERVICE" ]; then
    echo "ERROR: Service file not found at $SOURCE_SERVICE"
    exit 1
fi

if [ ! -f "$TORCH_SCRIPT" ]; then
    echo "ERROR: ip_mask.py not found at $TORCH_SCRIPT"
    exit 1
fi

if [ ! -f "$KEY_FILE" ]; then
    echo "WARNING: Private key not found at $KEY_FILE"
    echo "  Generate keys first: python3 ip_mask.py generate-keys --type ec --out /home/hermes/keys"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Customize the service file (replace paths if needed)
echo "Installing service..."
cp "$SOURCE_SERVICE" "$SERVICE_FILE"

# Make sure the key path in the service matches reality
if [ ! -f "$KEY_FILE" ]; then
    # Remove the --priv-key line if key doesn't exist
    sed -i '/--priv-key/d' "$SERVICE_FILE"
    echo "  Removed --priv-key from service (key not found)."
else
    echo "  Private key: $KEY_FILE"
fi

echo "  Service file: $SERVICE_FILE"

# Reload systemd
echo ""
echo "Reloading systemd..."
systemctl daemon-reload

# Enable and start
echo "Enabling service..."
systemctl enable ip-mask-decoder.service

echo "Starting service..."
systemctl start ip-mask-decoder.service

# Status
echo ""
echo "=== Service Status ==="
systemctl status ip-mask-decoder.service --no-pager || true

echo ""
echo "=== Logs (live) ==="
echo "  journalctl -u ip-mask-decoder -f"

echo ""
echo "=== Management ==="
echo "  Stop:  sudo systemctl stop ip-mask-decoder"
echo "  Start: sudo systemctl start ip-mask-decoder"
echo "  Restart: sudo systemctl restart ip-mask-decoder"
echo "  Disable: sudo systemctl disable ip-mask-decoder"
echo ""
echo "Installation complete."
