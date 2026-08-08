#!/bin/sh
set -e

REPO="HiImSmiley/Socketley"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "Fetching latest release..."
URL=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep -oP '"browser_download_url": "\K[^"]*\.deb')

if [ -z "$URL" ]; then
  echo "error: no .deb found in latest release" >&2
  exit 1
fi

echo "Downloading $(basename "$URL")..."
curl -fsSL "$URL" -o "$TMP/socketley.deb"

echo "Installing dependencies..."
apt-get update -qq && apt-get install -y -qq liburing2 > /dev/null

# The binary needs liburing.so.2 with the LIBURING_2.6 symbol version, because
# it calls io_uring_register_napi().  Ubuntu 24.04 packages 2.5, so on a stock
# 24.04 the line above installs something the daemon cannot load, and the dpkg
# below then fails its `liburing2 (>= 2.6)` dependency.  Say why here, where the
# person running this can still read it, rather than letting dpkg's unmet
# dependency be the whole explanation.
if ! ldconfig -p 2>/dev/null | grep -q 'liburing\.so\.2' \
   || ! grep -qs LIBURING_2.6 /usr/lib/*/liburing.so.2* 2>/dev/null; then
  cat >&2 <<'WARN'

note: this system's liburing appears older than 2.6 (Ubuntu 24.04 ships 2.5).
      socketley needs 2.6+ to run.  If the install below fails on liburing2,
      install a current one and retry:

        git clone --depth 1 --branch liburing-2.15 https://github.com/axboe/liburing
        cd liburing && ./configure --prefix=/usr \
            --libdir="/usr/lib/$(gcc -print-multiarch)" && make && sudo make install

WARN
fi

UPGRADE=false
if dpkg -s socketley >/dev/null 2>&1; then
  UPGRADE=true
fi

echo "Installing..."
dpkg -i "$TMP/socketley.deb"

if [ "$UPGRADE" = true ]; then
  echo "Done. Restart the daemon to apply the update: sudo systemctl restart socketley"
else
  echo "Done. Start the daemon with: sudo systemctl start socketley"
fi

cat <<'PERMS'

The daemon's IPC socket is 0660 socketley:socketley. Every socketley command
goes through it, and a runtime's --lua script runs with the daemon's
privileges, so reaching it is an administrative right. To grant it:

  sudo usermod -aG socketley "$USER"     # then log in again

PERMS
