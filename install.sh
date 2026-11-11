#!/bin/sh
# Installs socketley from a release .deb: it reads what the package needs, asks before installing each missing
# dependency, and where socketley is installed already offers to upgrade or uninstall it.
#
#   curl -fsSL https://raw.githubusercontent.com/HiImSmiley/Socketley/main/install.sh | sudo sh
#   sudo sh install.sh [--deb FILE] [--yes] [--uninstall]
set -eu

REPO="HiImSmiley/Socketley"
DEB=""
YES=0
UNINSTALL=0

usage() {
  cat <<'USAGE'
usage: install.sh [--deb FILE] [--yes] [--uninstall]
  --deb FILE    install this package instead of downloading the newest release
  --yes         take every question's default answer (the capital letter) without asking
  --uninstall   remove an installed socketley
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --deb) [ $# -ge 2 ] || { usage; exit 1; }; DEB=$2; shift 2 ;;
    -y|--yes) YES=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# Said here rather than by dpkg halfway through: without sudo the script would get as far as apt before failing.
[ "$(id -u)" -eq 0 ] || die "this installer must run as root: curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | sudo sh"
command -v dpkg >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1 \
  || die "this installer is for Debian and Ubuntu (dpkg and apt); the README says how to build from source elsewhere"

# Questions are read from the terminal, since under curl | sh the script itself is standard input; apt and dpkg get
# /dev/null, so they never take an answer typed for the next question.
if [ "$YES" = 0 ] && ! ( : </dev/tty ) 2>/dev/null; then
  die "there is no terminal to ask on; run with --yes to take every default"
fi

# ask QUESTION y|n -- true for yes, the second argument being the answer an empty line or --yes gives.
ask() {
  if [ "$YES" = 1 ]; then [ "$2" = y ]; return; fi
  while :; do
    if [ "$2" = y ]; then printf '%s [Y/n] ' "$1" >/dev/tty; else printf '%s [y/N] ' "$1" >/dev/tty; fi
    read -r answer </dev/tty || answer=""
    case "$answer" in
      "") [ "$2" = y ]; return ;;
      [yYjJ]*) return 0 ;;
      [nN]*) return 1 ;;
    esac
  done
}

# The version of this machine's architecture, as a host with i386 alongside lists a library once per architecture.
installed_version() {
  dpkg-query -W -f='${Status} ${Architecture} ${Version}\n' "$1" 2>/dev/null \
    | awk -v arch="$(dpkg --print-architecture)" '$3 == "installed" && ($4 == arch || $4 == "all") { print $5; exit }'
}

uninstall() {
  if [ -n "$(installed_version socketley)" ]; then
    apt-get remove -y -qq socketley </dev/null >/dev/null
    echo "socketley is uninstalled."
  else
    echo "/usr/bin/socketley belongs to no package; it was installed from source, and"
    echo "  bash scripts/install-from-source.sh --uninstall"
    echo "in the clone it was built from removes exactly what that install put there."
    exit 1
  fi
  if [ -d /var/lib/socketley ] || [ -d /etc/socketley ]; then
    size=$(du -sh /var/lib/socketley /etc/socketley 2>/dev/null | awk '{print $1}' | paste -sd+)
    if ask "Delete its runtimes and data as well (/var/lib/socketley, /etc/socketley: $size)? This cannot be undone." n; then
      rm -rf /var/lib/socketley /etc/socketley
      userdel socketley 2>/dev/null || true
      groupdel socketley 2>/dev/null || true
      echo "Its data, configuration and the socketley account are deleted."
    else
      echo "Its data is kept in /var/lib/socketley and /etc/socketley."
    fi
  fi
}

# What is there already.
OLD=$(installed_version socketley)
if [ -n "$OLD" ]; then
  echo "socketley $OLD is installed."
elif [ -e /usr/bin/socketley ]; then
  OLD=unpackaged
  echo "socketley is installed in /usr/bin, not from a package."
fi

if [ "$UNINSTALL" = 1 ]; then
  [ -n "$OLD" ] || die "socketley is not installed"
  uninstall
  exit 0
fi

if [ -n "$OLD" ] && [ "$YES" = 0 ]; then
  while :; do
    printf '[u]pgrade, [r]emove or [c]ancel? [U/r/c] ' >/dev/tty
    read -r answer </dev/tty || answer=c
    case "$answer" in
      ""|[uU]*) break ;;
      [rR]*) uninstall; exit 0 ;;
      [cC]*) echo "Nothing was changed."; exit 0 ;;
    esac
  done
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# The package: the one given, or the newest release's, the one built for this distribution where there is one.
if [ -z "$DEB" ]; then
  command -v curl >/dev/null 2>&1 || die "curl is needed to download the release; or pass --deb FILE"
  echo "Looking for the newest release..."
  # A private repository's releases are read with a token, as socketley update reads them.
  set -- -H "Accept: application/vnd.github+json"
  [ -n "${GITHUB_TOKEN:-}" ] && set -- "$@" -H "Authorization: Bearer $GITHUB_TOKEN"
  curl -fsSL "$@" "https://api.github.com/repos/${REPO}/releases/latest" -o "$TMP/release.json" \
    || die "the newest release could not be read from GitHub (a private repository needs GITHUB_TOKEN); download a .deb and pass --deb FILE"
  . /etc/os-release
  # Only the packages built for this machine's architecture, since dpkg refuses any other.
  ARCH=$(dpkg --print-architecture)
  URLS=$(sed -n 's/.*"browser_download_url": *"\([^"]*\/socketley_[^"]*_'"$ARCH"'\.deb\)".*/\1/p' "$TMP/release.json")
  # A rolling distribution names no version, which set -u would otherwise stop at.
  URL=$(printf '%s\n' "$URLS" | grep -F "${ID:-}${VERSION_ID:-}" | head -1 || true)
  [ -n "$URL" ] || URL=$(printf '%s\n' "$URLS" | head -1)
  [ -n "$URL" ] || die "the newest release has no .deb for $ARCH; build from a clone with scripts/install-from-source.sh"
  # The SHA-256 GitHub keeps of the asset, which comes before its download URL in the asset's object.
  # A field a line whichever way GitHub laid the JSON out, as no digest or URL holds a comma.
  SUM=$(tr ',' '\n' < "$TMP/release.json" | awk -v url="$URL" '/"digest":/ { d = $0; sub(/.*"sha256:/, "", d); sub(/".*/, "", d) }
    /"browser_download_url":/ && index($0, "\"" url "\"") { print d; exit }')
  # With a token the asset comes through the API, which a private repository's needs; its URL opens the asset's object.
  API=$(tr ',' '\n' < "$TMP/release.json" | awk -v url="$URL" '/"url": *"https:\/\/api\.github\.com\/repos\/.*\/releases\/assets\// { a = $0; sub(/.*"url": *"/, "", a); sub(/".*/, "", a) }
    /"browser_download_url":/ && index($0, "\"" url "\"") { print a; exit }')
  [ -n "$SUM" ] || die "the release says no SHA-256 of $(basename "$URL"); download it and pass --deb FILE"
  echo "Downloading $(basename "$URL")..."
  if [ -n "${GITHUB_TOKEN:-}" ] && [ -n "$API" ]; then
    curl -fsSL -H "Accept: application/octet-stream" -H "Authorization: Bearer $GITHUB_TOKEN" "$API" -o "$TMP/socketley.deb"
  else
    curl -fsSL "$URL" -o "$TMP/socketley.deb"
  fi
  [ "$(sha256sum "$TMP/socketley.deb" | cut -d' ' -f1)" = "$SUM" ] \
    || die "$(basename "$URL") is not the file the release published: its SHA-256 differs; nothing was installed"
  DEB="$TMP/socketley.deb"
fi
[ -r "$DEB" ] || die "$DEB cannot be read"
NEW=$(dpkg-deb -f "$DEB" Version) || die "$DEB is not a .deb"

if [ "$OLD" = "$NEW" ] && ! ask "socketley $NEW is what is installed already. Install it again?" n; then
  echo "Nothing was changed."
  exit 0
fi

# What the package needs, held against what is installed and what apt can install.
echo "Reading the package lists..."
apt-get update -qq </dev/null || echo "warning: apt-get update failed; checking against the lists there are"
WANT=""
MISSING=0
echo "socketley $NEW needs:"
printf '%s\n' "$(dpkg-deb -f "$DEB" Depends)" | tr ',' '\n' | sed 's/^ *//; s/ *|.*//' | while read -r dep; do
  [ -n "$dep" ] || continue
  name=${dep%% *}
  op=$(printf '%s' "$dep" | sed -n 's/.*(\([<>=]*\) *\(.*\))/\1/p')
  ver=$(printf '%s' "$dep" | sed -n 's/.*(\([<>=]*\) *\(.*\))/\2/p')
  have=$(installed_version "$name")
  cand=$(apt-cache policy "$name" 2>/dev/null | sed -n 's/^ *Candidate: //p')
  [ "$cand" = "(none)" ] && cand=""
  fits() { [ -n "$1" ] && { [ -z "$op" ] || dpkg --compare-versions "$1" "$op" "$ver"; }; }
  if fits "$have"; then
    echo "  ok       $dep  (installed: $have)"
  elif fits "$cand"; then
    echo "  missing  $dep  (apt has $cand)"
    echo "$name" >> "$TMP/want"
  else
    echo "  MISSING  $dep  (installed: ${have:-none}, apt has: ${cand:-none})"
    echo "$name" >> "$TMP/unmet"
  fi
done

if [ -s "$TMP/unmet" ]; then
  echo
  echo "This package was built for a newer distribution than this one: apt has no version of"
  echo "$(paste -sd' ' "$TMP/unmet") that it accepts. Nothing was changed."
  echo "A package built on this distribution installs here, or socketley builds from source:"
  echo "  git clone https://github.com/${REPO} && cd Socketley && bash scripts/install-from-source.sh"
  exit 1
fi

if [ -s "$TMP/want" ]; then
  for name in $(cat "$TMP/want"); do
    if ask "socketley needs $name. Install it?" y; then
      WANT="$WANT $name"
    else
      MISSING=1
    fi
  done
  [ "$MISSING" = 0 ] || die "socketley does not run without what it needs; nothing was installed"
fi

# ffmpeg is the one thing a runtime can do without: the storage runtime's thumbnails and video streams are made by it.
if ! command -v ffmpeg >/dev/null 2>&1; then
  cand=$(apt-cache policy ffmpeg 2>/dev/null | sed -n 's/^ *Candidate: //p')
  if [ -n "$cand" ] && [ "$cand" != "(none)" ] \
     && ask "Optional: ffmpeg ($cand) makes the storage runtime's thumbnails and video streams. Install it?" n; then
    WANT="$WANT ffmpeg"
  fi
fi

if [ -n "$WANT" ]; then
  echo "Installing$WANT..."
  # shellcheck disable=SC2086
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $WANT </dev/null >/dev/null
fi

echo "Installing socketley $NEW..."
dpkg -i "$DEB" </dev/null >"$TMP/dpkg.log" 2>&1 || { cat "$TMP/dpkg.log" >&2; die "dpkg could not install $DEB"; }

if [ -d /run/systemd/system ]; then
  if [ "$(systemctl is-active socketley 2>/dev/null)" = active ]; then
    echo "Done: socketley $NEW is running (systemctl status socketley)."
  else
    echo "Done: socketley $NEW is installed; start it with: systemctl start socketley"
  fi
else
  echo "Done: socketley $NEW is installed; with no systemd here, start it with: socketley daemon"
fi

# The IPC socket is 0660 socketley:socketley, so whoever ran sudo is offered the group that reaches it.
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] && ! id -nG "$SUDO_USER" | tr ' ' '\n' | grep -qx socketley; then
  if ask "Let $SUDO_USER run socketley commands (the group socketley, whose members administer the daemon)?" y; then
    usermod -aG socketley "$SUDO_USER"
    echo "$SUDO_USER is in the group socketley from their next login."
  fi
fi

# The 1.0 releases wrote the runtime records, each with its --master-pw in plaintext, readable to every account; the
# numbering began again at 0.2.0, so it is the 1.0 series that is asked for and not everything lower than a number.
if [ -n "$OLD" ] && [ "$OLD" != unpackaged ] && dpkg --compare-versions "$OLD" ge 1.0~ && dpkg --compare-versions "$OLD" lt 1.1.0~; then
  cat <<'STATE'

Upgraded from a version that wrote /var/lib/socketley/runtimes/*.json readable
to every local account, with each runtime's --master-pw in plaintext. The daemon
narrows them to 0600 on its first start, which cannot undo the exposure: if this
machine has accounts other than yours, rotate every --master-pw
(socketley edit <name>, or recreate the runtime).
STATE
fi
