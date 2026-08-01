#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_ROOT/bin/Release/socketley"
VERSION="${1:-1.0.9}"
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
#
# `Depends: liburing2` — with no version — was a package that installed cleanly
# and then would not start.  The binary calls io_uring_register_napi(), a real
# exported symbol added in liburing 2.6, so it records a versioned dependency:
#
#   $ objdump -p bin/Release/socketley | grep -A3 'required from liburing'
#     required from liburing.so.2:
#       LIBURING_2.6
#
# Ubuntu 24.04's liburing2 is 2.5 and satisfies an unversioned `liburing2`, so
# dpkg was happy, and the first exec then died on a version lookup for
# LIBURING_2.6.  Stating the constraint makes apt refuse the install instead,
# which is the same news delivered where it can be acted on.
#
# 2.6 and not the 2.7 the *source* needs: the two extra things 2.7 provides that
# this tree uses are preprocessor constants compiled into the binary, not
# symbols resolved from the shared object at load time.
cat > "$PKG_DIR/DEBIAN/control" << EOF
Package: socketley
Version: $VERSION
Architecture: $ARCH
Maintainer: Socketley Developers
Description: Network runtime daemon with Docker-style management
 Socketley is a Linux-only daemon that manages long-living network
 runtimes (server, client, proxy, cache) in a Docker-like style.
Depends: liburing2 (>= 2.6)
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
