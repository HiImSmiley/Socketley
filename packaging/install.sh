#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_ROOT/bin/Release/socketley"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must be run as root"
    exit 1
fi

if [ ! -f "$BINARY" ]; then
    echo "error: release binary not found at $BINARY"
    echo "build first: cd make && make config=release_x64 -j\$(nproc)"
    exit 1
fi

# Create system user
if ! id -u socketley >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin socketley
fi

# Install binary
install -Dm755 "$BINARY" /usr/bin/socketley

# Install man page
if [ -f "$PROJECT_ROOT/man/socketley.1" ]; then
    install -Dm644 "$PROJECT_ROOT/man/socketley.1" /usr/share/man/man1/socketley.1
    mandb -q 2>/dev/null || true
fi

# Install help script
install -Dm755 "$PROJECT_ROOT/man/socketley-help.sh" /usr/share/socketley/socketley-help.sh

# Install systemd service
install -Dm644 "$SCRIPT_DIR/socketley.service" /usr/lib/systemd/system/socketley.service

# Create state directories
install -dm755 -o socketley -g socketley /var/lib/socketley/runtimes
install -dm755 -o socketley -g socketley /run/socketley
install -dm755 /etc/socketley

# Enable and start service
systemctl daemon-reload
systemctl enable socketley.service

echo "socketley installed successfully"
echo "  start:   systemctl start socketley"
echo "  status:  systemctl status socketley"
echo "  logs:    journalctl -u socketley -f"
