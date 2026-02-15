#!/bin/bash
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must be run as root"
    exit 1
fi

# Stop and disable service
systemctl stop socketley.service 2>/dev/null || true
systemctl disable socketley.service 2>/dev/null || true

# Remove files
rm -f /usr/bin/socketley
rm -f /usr/lib/systemd/system/socketley.service
rm -f /usr/share/man/man1/socketley.1

systemctl daemon-reload

echo "socketley uninstalled"
echo "  state left at /var/lib/socketley (remove manually if desired)"
echo "  config left at /etc/socketley (remove manually if desired)"
echo "  user 'socketley' left (remove with: userdel socketley)"
