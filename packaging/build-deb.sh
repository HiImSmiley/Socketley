#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_ROOT/bin/Release/socketley"
VERSION="${1:-1.0.6}"
ARCH="amd64"
PKG_DIR="$PROJECT_ROOT/socketley_${VERSION}_${ARCH}"

if [ ! -f "$BINARY" ]; then
    echo "error: release binary not found at $BINARY"
    echo "build first: cd make && make config=release_x64 -j\$(nproc)"
    exit 1
fi

rm -rf "$PKG_DIR"

# Directory structure
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/lib/systemd/system"
mkdir -p "$PKG_DIR/usr/share/man/man1"
mkdir -p "$PKG_DIR/var/lib/socketley/runtimes"
mkdir -p "$PKG_DIR/etc/socketley"

# Binary
cp "$BINARY" "$PKG_DIR/usr/bin/socketley"
chmod 755 "$PKG_DIR/usr/bin/socketley"

# Man page
if [ -f "$PROJECT_ROOT/man/socketley.1" ]; then
    cp "$PROJECT_ROOT/man/socketley.1" "$PKG_DIR/usr/share/man/man1/"
fi

# Help script
mkdir -p "$PKG_DIR/usr/share/socketley"
cp "$PROJECT_ROOT/man/socketley-help.sh" "$PKG_DIR/usr/share/socketley/"
chmod 755 "$PKG_DIR/usr/share/socketley/socketley-help.sh"

# Service file
cp "$SCRIPT_DIR/socketley.service" "$PKG_DIR/usr/lib/systemd/system/"

# Control file
cat > "$PKG_DIR/DEBIAN/control" << EOF
Package: socketley
Version: $VERSION
Architecture: $ARCH
Maintainer: Socketley Developers
Description: Network runtime daemon with Docker-style management
 Socketley is a Linux-only daemon that manages long-living network
 runtimes (server, client, proxy, cache) in a Docker-like style.
Depends: liburing2
Section: net
Priority: optional
EOF

# Post-install script
cat > "$PKG_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

# Create system user
if ! id -u socketley >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin socketley
fi

# Fix ownership
chown -R socketley:socketley /var/lib/socketley
install -dm755 -o socketley -g socketley /run/socketley

# Kill any stale dev-mode daemon (user-space, socket at /tmp/socketley.sock)
pkill -x socketley 2>/dev/null || true

# Enable and restart system service
systemctl daemon-reload
systemctl enable socketley.service
systemctl try-restart socketley.service 2>/dev/null || true
EOF
chmod 755 "$PKG_DIR/DEBIAN/postinst"

# Pre-remove script
cat > "$PKG_DIR/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e
systemctl stop socketley.service 2>/dev/null || true
systemctl disable socketley.service 2>/dev/null || true
EOF
chmod 755 "$PKG_DIR/DEBIAN/prerm"

# Build package
dpkg-deb --build "$PKG_DIR"
rm -rf "$PKG_DIR"

echo "built: socketley_${VERSION}_${ARCH}.deb"
