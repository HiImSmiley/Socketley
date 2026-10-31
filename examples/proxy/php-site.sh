#!/bin/bash
# =============================================================================
# php-site.sh - A PHP site: php-fpm runs the scripts, a proxy does the rest
# =============================================================================
#
# What Apache's mod_php or nginx's fastcgi_pass did, as one proxy:
#
#   --backend fastcgi://unix:/run/php/php8.2-fpm.sock   the application server
#   --root /var/www/site                                where the site is
#
# A request for an existing *.php under --root runs it; an existing file that
# is no script (css, js, images) is served by the proxy itself, with ETag,
# ranges and keep-alive; a directory is its index.php; and any other path goes
# to /index.php, which is the front controller WordPress, Laravel and most
# frameworks expect.
#
# What it never does: run a file that is not a .php beneath --root
# (/uploads/avatar.jpg/x.php goes to index.php, not to avatar.jpg), follow a
# link out of --root, serve a hidden file (.env, .git) or a leftover copy
# (wp-config.php.bak, config.inc, dump.sql), or pass a Proxy header on as
# HTTP_PROXY.
#
# In front of it an entrance ends TLS for the domain; the proxy sees the
# entrance's X-Forwarded-Proto over the loopback and sets HTTPS=on for PHP.
#
# Usage: sudo ./php-site.sh example.com /var/www/site
# =============================================================================
set -euo pipefail

DOMAIN="${1:?usage: $0 <domain> <document root>}"
ROOT="${2:?usage: $0 <domain> <document root>}"
FPM_SOCK="${FPM_SOCK:-$(ls /run/php/php*-fpm.sock 2>/dev/null | head -1)}"
[ -S "$FPM_SOCK" ] || { echo "no php-fpm socket under /run/php; start php-fpm or set FPM_SOCK"; exit 1; }

# The site, its scripts run by php-fpm and its files served here.
socketley create proxy site --domain "$DOMAIN" -p 8080 \
    --backend "fastcgi://unix:$FPM_SOCK" --root "$ROOT" -s

# php-fpm in a container sees the site at another path: name it as it sees it.
#   socketley create proxy site ... --root /srv/site --fastcgi-root /var/www/html

# Another index script than index.php:
#   socketley edit site --index app.php

socketley stats site    # files_served, files_not_modified, request_latency
