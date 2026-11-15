#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# A db's backup is written beside where it goes under a name anyone who may write in that folder can foresee; what
# lies at that name is taken away, never written through.
#
# What each part would catch:
#   * a link planted at <backup>.tmp in a shared backup folder making the daemon truncate and fill the file it names
#     (any file its account may write) with every document of the database
#   * the backup failing, or being left as the planted link, rather than written as a file of its own
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

echo "=== Integration: a db backup writes through no link planted at its name ==="
daemon_isolate dbbackuplink
T=$SOCKETLEY_TMPD
PD=$((SL_PORT_BASE + 1641))
trap 'daemon_stop' EXIT
daemon_start "$BIN"

printf 'pub  public\n' > "$T/schema"
printf 'backend backuplinksecret0123456789\n' > "$T/keys"
chmod 600 "$T/keys"
"$BIN" create db data -p "$PD" --schema "$T/schema" --keys "$T/keys" -s >/dev/null 2>&1 \
    && ok || bad "the db runtime is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PD/")" = 200 ] && break; sleep 0.1; done
expect "a document is written" "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H 'Authorization: Bearer backuplinksecret0123456789' \
    -H 'Content-Type: application/json' -d '{"secret":"the-whole-database"}' "http://127.0.0.1:$PD/c/pub/one")" 201

mkdir -p "$T/shared"
printf 'precious\n' > "$T/victim"
ln -s "$T/victim" "$T/shared/data.dbbackup.tmp"
out=$("$BIN" db-backup data "$T/shared/data.dbbackup" 2>&1); rc=$?
for _ in $(seq 1 50); do [ -f "$T/shared/data.dbbackup" ] && break; sleep 0.1; done
expect "the file the link names is untouched" "$(cat "$T/victim")" "precious"
[ -f "$T/shared/data.dbbackup" ] && [ ! -L "$T/shared/data.dbbackup" ] && ok \
    || bad "the backup is a file of its own" "rc $rc: $out; $(ls -l "$T/shared" 2>&1)"
grep -q 'the-whole-database' "$T/shared/data.dbbackup" 2>/dev/null && ok || bad "and holds the documents" "$(ls -l "$T/shared")"
[ ! -e "$T/shared/data.dbbackup.tmp" ] && [ ! -L "$T/shared/data.dbbackup.tmp" ] && ok || bad "and the planted name is gone" "$(ls -l "$T/shared")"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
