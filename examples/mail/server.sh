#!/bin/bash
# =============================================================================
# server.sh - A mail server for a domain, its users and its apps
# =============================================================================
#
# A dns runtime serves example.com and the mail runtime gives the zone its MX,
# SPF, DKIM, DMARC and SRV records. The users of an idp runtime get mailboxes
# in a storage runtime, within a quota, send on 587 with their password, read
# over IMAP on every shard or at https://mail.example.com in the browser, and
# put Sieve filters over ManageSieve; the apps send from no-reply@example.com,
# and the daemon's alerts are mailed. A blocklist keeps out what it lists.
# Ports 25, 587 and 143 need the daemon to be allowed to bind them.
# =============================================================================

set -e

socketley create dns ns -p 53 --zone example.com --publish 203.0.113.10 -s
socketley create idp auth -p 9443 --issuer https://auth.example.com -s
socketley create storage files -p 9000 --dir /var/lib/socketley/files -s
socketley idp-user auth add alice --password - --email alice@example.com \
    --set mail_quota=2G <<< 'a long password'

socketley create mail m -p 25 --dns ns --no-reply \
    --idp auth --storage files/mail \
    --submission 587 --imap 143 --sieve 4190 --shards 2 --web 9480 --domain mail \
    --dnsbl zen.spamhaus.org --tls -s

# alice's filter, as she would put it from her mail client.
socketley mail m sieve alice put main "$(dirname "$0")/filter.sieve"
socketley mail m sieve alice activate main

# What the zone now holds for mail.
socketley mail m dns

# An app's message, from no-reply@example.com, signed with DKIM.
df -h | socketley send m --to alice@example.com --subject "Disks on $(hostname)"

# The spool: what waits, and why.
socketley mail m queue
