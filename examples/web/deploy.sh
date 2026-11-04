#!/usr/bin/env bash
# =============================================================================
# deploy.sh - A static site behind a web runtime, and a deploy with no restart
# =============================================================================
#
# USAGE:
#   bash examples/web/deploy.sh /srv/site ./public        # ./public: a static site generator's output
#
# Each run copies the build into a new release directory and swaps the `current`
# link to it in one rename. The web runtime watches the directory holding
# --root, so the next request is answered from the new release; nothing is
# restarted and no request sees half of one release and half of the other.
#
# Behind the entrance proxy of a dns runtime the site is https://www.<zone>:
#   socketley create web www -p 9501 --bind 127.0.0.1 --root /srv/site/current --domain www -s
# A name with a dot is taken whole, so the zone's own name works the same way:
#   socketley create web apex -p 9502 --bind 127.0.0.1 --root /srv/site/current --domain example.com -s
# A single-page app's routes have no file behind them; --fallback answers them:
#   socketley create web app -p 9503 --bind 127.0.0.1 --root /srv/app/current --fallback index.html -s
# =============================================================================
set -euo pipefail

base=${1:?the directory releases live under, such as /srv/site}
build=${2:?the directory a build wrote, such as ./public}

release="$base/releases/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$release"
cp -a "$build/." "$release/"

# A .gz beside each text file lets the first visitor have it compressed too; without one the runtime makes it.
find "$release" -type f \( -name '*.html' -o -name '*.css' -o -name '*.js' -o -name '*.svg' -o -name '*.json' \) \
    -exec gzip -9 -k -f {} \;

ln -sfn "$release" "$base/next"
mv -T "$base/next" "$base/current"

if ! socketley ls 2>/dev/null | grep -q '^site\b'; then
    socketley create web site -p 9500 --bind 127.0.0.1 --root "$base/current" -s
fi
echo "serving $release"
