#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# Integration test: a CalDAV user's sync journal stays in the mail runtime's own journal folder, whatever the name.
#
# ─── THE DEFECT (round 8b) ──────────────────────────────────────────────────
#
# dav_store::journal_of built <state>/mail/<rt>.dav/<user>/<kind>-<coll>.log from the user's name as given, and the
# identity provider takes ".." for a name (letters, digits and . _ - @ +).  Measured on dev 3b7db9690: a user ".."
# PUTting an event (path /dav/%2e%2e/..., split before it is decoded) had the runtime append its journal to
# <state>/mail/calendars-personal.log, outside <rt>.dav/, and read it back from there.  The name is now escaped into
# one folder of its own (a leading dot and anything outside [A-Za-z0-9._@+-] as %XX).
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ready.sh"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate mail_dav_dots
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1985)); J=$((P+1)); PI=$((P+2)); PS=$((P+3))
trap daemon_stop EXIT

echo "=== Integration: a DAV journal stays below the runtime's journal folder ==="
daemon_start "$BIN"
printf 'spa - http://localhost:5173/cb\n' > "$T/clients"
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
"$BIN" idp-user auth add alice --password alicepassword1 --email alice@example.test >/dev/null 2>&1
"$BIN" idp-user auth add .. --password dotdotpassword1 --email dd@example.test >/dev/null 2>&1
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --jmap "$J" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$J" || bad "the JMAP port listens" "$(tail -3 "$SOCKETLEY_DLOG")"

ev=$'BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:t\r\nBEGIN:VEVENT\r\nUID:e1\r\nDTSTART:20261026T090000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n'
put() { curl -s -o /dev/null -w '%{http_code}' -u "$1:$2" -H 'Content-Type: text/calendar' --path-as-is -X PUT \
        --data-binary "$ev" "http://127.0.0.1:$J/dav/$3/calendars/personal/e1.ics"; }
expect "alice puts an event" "$(put alice alicepassword1 alice)" 201
expect "so does the user named '..'" "$(put .. dotdotpassword1 %2e%2e)" 201

dav=$(find "$T" -type d -name 'm.dav' | head -1)
expect "alice's journal is in her folder" "$(find "$dav/alice" -name 'calendars-personal.log' | wc -l)" 1
outside=$(find "$T/home" -name '*-personal.log' ! -path "$dav/*" -printf '%P ')
expect "no journal is written outside the runtime's journal folder" "$outside" ""
expect "the user '..' has a journal of its own below it" "$(find "$dav" -mindepth 2 -maxdepth 2 -name 'calendars-personal.log' | wc -l)" 2
sync='<?xml version="1.0"?><d:sync-collection xmlns:d="DAV:"><d:sync-token/><d:sync-level>1</d:sync-level><d:prop><d:getetag/></d:prop></d:sync-collection>'
got=$(curl -s -u ..:dotdotpassword1 --path-as-is -X REPORT -H 'Content-Type: application/xml' --data "$sync" \
      "http://127.0.0.1:$J/dav/%2e%2e/calendars/personal/" | grep -c 'e1.ics')
expect "and its sync report still lists its event" "$got" 1

echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
