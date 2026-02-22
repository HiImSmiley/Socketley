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

echo "Installing..."
dpkg -i "$TMP/socketley.deb"

echo "Done. Run 'socketley daemon &' to start."
