#!/bin/sh
set -e

REPO="HiImSmiley/Socketley"

# Said here rather than by dpkg halfway through.  The README documents
# `curl ... | sudo sh`, so the usual way to arrive without privileges is to have
# dropped the sudo -- and without this the script gets as far as apt-get before
# failing, having already changed the package lists of a machine whose owner
# thought nothing had happened yet.
if [ "$(id -u)" -ne 0 ]; then
  echo "error: this installer must run as root" >&2
  echo "  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | sudo sh" >&2
  exit 1
fi

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

UPGRADE=false
if dpkg -s socketley >/dev/null 2>&1; then
  UPGRADE=true
fi

# apt, not dpkg, so the package's Depends (libc6, libssl3, libstdc++6) are installed with it; liburing is linked in.
echo "Installing..."
apt-get update -qq
apt-get install -y -qq "$TMP/socketley.deb"

if [ "$UPGRADE" = true ]; then
  echo "Done. A running daemon was restarted onto the new version."
else
  echo "Done. The daemon is running: systemctl status socketley"
fi

cat <<'PERMS'

The daemon's IPC socket is 0660 socketley:socketley. Every socketley command
goes through it, and a runtime's --lua script runs with the daemon's
privileges, so reaching it is an administrative right. To grant it:

  sudo usermod -aG socketley "$USER"     # then log in again

PERMS

# This script creates no directories of its own — the state directory's mode
# comes from the package payload and the postinst, which set it to 0750. What
# it owns is telling whoever ran it, and on an UPGRADE that is not optional:
# every version before this one wrote those files world-readable with the
# passwords in them, and no amount of tightening now un-reads what was already
# readable.
if [ "$UPGRADE" = true ]; then
  cat <<'STATE'
UPGRADE NOTE — read this one.

Versions before this wrote /var/lib/socketley/runtimes/*.json with the mode the
daemon's umask happened to give them: 0644 under systemd, 0666 from a shell
with "umask 0". Those files carry each runtime's --master-pw in plaintext and
the paths of its TLS private keys, so on a multi-user machine they were
readable — and in the 0666 case writable — by every local account.

The daemon narrows them to 0600 on its first start and says so in the log. It
cannot undo the exposure. If this machine has accounts other than yours:

  rotate every --master-pw    socketley edit <name>, or recreate the runtime

STATE
fi
