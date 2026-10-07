#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_ROOT/bin/Release/socketley"
VERSION="${1:-1.1.0}"
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
# Stated in the payload too, not only in the postinst: dpkg takes the mode from
# the directory as built here, so a package built on a machine with a loose
# umask would ship a 0777 state directory and be correct only after postinst
# ran.  See the note beside the postinst's install -dm750.
chmod 750 "$PKG_DIR/var/lib/socketley/runtimes"
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

# Copyright file
#
# Debian policy 12.5 makes /usr/share/doc/<pkg>/copyright mandatory, and until
# this was added the package shipped without one.  That was not only a policy
# break: the binary statically links LuaJIT and compiles in sol2, both MIT, and
# MIT requires its notice to accompany the distribution.  A .deb with no
# copyright file distributed both of them with no notice at all.
#
# Assembled from the licence files in thirdparty/ rather than restated here, so
# a vendored component that is updated cannot leave a stale notice behind.  A
# missing licence file is a hard error for the same reason.
mkdir -p "$PKG_DIR/usr/share/doc/socketley"
COPYRIGHT="$PKG_DIR/usr/share/doc/socketley/copyright"

cat > "$COPYRIGHT" << 'HEADER'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: socketley
Source: https://github.com/HiImSmiley/Socketley

Files: *
Copyright: Socketley contributors
License: Apache-2.0
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 .
     http://www.apache.org/licenses/LICENSE-2.0
 .
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 .
 The complete text is at /usr/share/common-licenses/Apache-2.0

HEADER

# Only what actually reaches the binary.  doctest is vendored but test-only and
# is in no shipped artefact, so it is deliberately not listed here -- it is
# covered by THIRD_PARTY_NOTICES.md in the source distribution instead.
emit_notice() {
    local name="$1" what="$2" path="$PROJECT_ROOT/$3"
    if [ ! -f "$path" ]; then
        echo "error: licence file missing: $3" >&2
        exit 1
    fi
    {
        echo "-------------------------------------------------------------------------------"
        echo "$name -- $what"
        echo "-------------------------------------------------------------------------------"
        echo
        cat "$path"
        echo
    } >> "$COPYRIGHT"
}

echo "The binary in this package includes or links the following components." \
    >> "$COPYRIGHT"
echo >> "$COPYRIGHT"

emit_notice "LuaJIT"   "statically linked into /usr/bin/socketley" \
    thirdparty/luajit/COPYRIGHT
emit_notice "sol2"     "header-only, compiled into /usr/bin/socketley" \
    thirdparty/sol2/LICENSE.txt
# The documented build links liburing's archive from bin/build-thirdparty.sh; one against a shared liburing names it in Depends.
if objdump -p "$BINARY" | grep -q 'NEEDED *liburing\.so'; then
    URING_HOW="dynamically linked (see Depends)"
else
    URING_HOW="statically linked into /usr/bin/socketley"
fi
emit_notice "liburing" "$URING_HOW" \
    thirdparty/liburing/LICENSE
# HTTP/3's libraries, when bin/build-thirdparty.sh http3 built them in: OpenSSL is then linked statically too.
if [ -f thirdparty/ngtcp2/COPYING ]; then
    emit_notice "OpenSSL"  "statically linked into /usr/bin/socketley" thirdparty/openssl/LICENSE.txt
    emit_notice "ngtcp2"   "statically linked into /usr/bin/socketley" thirdparty/ngtcp2/COPYING
    emit_notice "nghttp3"  "statically linked into /usr/bin/socketley" thirdparty/nghttp3/COPYING
fi

chmod 644 "$COPYRIGHT"

# Control file
#
# Depends is what the binary loads, as dpkg-shlibdeps finds it in the packages that hold each library, so a
# library from no package -- a liburing built from source into /usr/lib -- stops the build here instead of an
# exec on the machine it was installed on.
SHLIBS_DIR=$(mktemp -d)
mkdir "$SHLIBS_DIR/debian"
printf 'Source: socketley\n\nPackage: socketley\nArchitecture: any\n' > "$SHLIBS_DIR/debian/control"
if ! SHLIBS=$(cd "$SHLIBS_DIR" && dpkg-shlibdeps -O "$PKG_DIR/usr/bin/socketley"); then
    rm -rf "$SHLIBS_DIR" "$PKG_DIR"
    echo "error: a library the binary loads belongs to no package; run bin/build-thirdparty.sh and build again"
    exit 1
fi
rm -rf "$SHLIBS_DIR"
DEPENDS=$(printf '%s\n' "$SHLIBS" | sed -n 's/^shlibs:Depends=//p')
cat > "$PKG_DIR/DEBIAN/control" << EOF
Package: socketley
Version: $VERSION
Architecture: $ARCH
Maintainer: Socketley Developers
Description: Network runtime daemon with Docker-style management
 Socketley is a Linux-only daemon that manages long-living network
 runtimes (server, client, proxy, cache) in a Docker-like style.
Depends: $DEPENDS
Section: net
Priority: optional
EOF

# Post-install script
cat > "$PKG_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

# Create system user and the group that reaches its socket.
#
# Explicit, not useradd's default: the IPC socket is 0660 socketley:socketley,
# so membership of `socketley` is the set of people who may administer this
# daemon — and whether useradd creates a matching group at all depends on
# USERGROUPS_ENAB, which differs between distributions.
if ! getent group socketley >/dev/null 2>&1; then
    groupadd --system socketley
fi

if ! id -u socketley >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
            --gid socketley socketley
fi

# Fix ownership
chown -R socketley:socketley /var/lib/socketley
# 0750 on an upgrade as well as a fresh install: the runtime records in here
# carry --master-pw in plaintext and the paths of the TLS private keys, and an
# install that predates this change has the directory at 0755.  The daemon
# narrows the files themselves to 0600 at startup; this narrows the directory.
install -dm750 -o socketley -g socketley /var/lib/socketley/runtimes
install -dm755 -o socketley -g socketley /run/socketley

# Enabled and started on a first install only, so an upgrade keeps an administrator's disable, and restarted onto
# the new binary only if it was running; a system without systemd, a container's, is installed without either.
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    if [ "$1" = configure ] && [ -z "${2:-}" ]; then
        systemctl enable --now socketley.service
    else
        systemctl try-restart socketley.service || true
    fi
fi

# Said on install because an upgrade changes who can reach the daemon.  The
# socket was 0666 and is now 0660 socketley:socketley, so anyone who has been
# driving the system daemon without being in that group stops being able to.
echo "socketley: the daemon's IPC socket is 0660 socketley:socketley."
echo "socketley: to let a user run socketley commands against it:"
echo "socketley:   usermod -aG socketley <user>   (the user must log in again)"
EOF
chmod 755 "$PKG_DIR/DEBIAN/postinst"

# Pre-remove script
cat > "$PKG_DIR/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e
# Stopped and disabled when the package goes, not on an upgrade, which the postinst restarts onto the new binary.
if [ -d /run/systemd/system ] && { [ "$1" = remove ] || [ "$1" = deconfigure ]; }; then
    systemctl stop socketley.service || true
    systemctl disable socketley.service || true
fi
EOF
chmod 755 "$PKG_DIR/DEBIAN/prerm"

# Build package
dpkg-deb --build "$PKG_DIR"
rm -rf "$PKG_DIR"

echo "built: socketley_${VERSION}_${ARCH}.deb"
