#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a mail runtime's Sieve scripts and its sign-in record are written under a name of their own and
# never through a link left beside them.
#
# What each part would catch:
#   * a Sieve script written through "<script>.tmp.<pid>" opened with O_TRUNC and no O_NOFOLLOW: a link left at that
#     name had its target overwritten with the script
#   * the sign-in record written through a fixed "auth.tmp" the same way
#   * a write that leaves its file beside the one it replaces
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a mail runtime's kept files are written under a name of their own ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }
daemon_isolate mailnolink
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1950))
IM=$((SL_PORT_BASE + 1951))
SV=$((SL_PORT_BASE + 1952))
PI=$((SL_PORT_BASE + 1953))
PS=$((SL_PORT_BASE + 1954))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=mail.example.test" \
    -keyout "$T/key.pem" -out "$T/cert.pem" >/dev/null 2>&1
daemon_start "$BIN"
printf 'spa - http://localhost:5173/cb\n' > "$T/clients"
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
"$BIN" idp-user auth add alice --password alicepassword1 --email alice@example.test >/dev/null 2>&1
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --imap "$IM" --sieve "$SV" \
    --tls --cert "$T/cert.pem" --key "$T/key.pem" -s >/dev/null 2>&1
for _ in $(seq 1 100); do (exec 3<>"/dev/tcp/127.0.0.1/$IM") 2>/dev/null && break; sleep 0.1; done
pids() { echo "$SOCKETLEY_DPID $(pgrep -P "$SOCKETLEY_DPID" | tr '\n' ' ')"; }

# ─── a Sieve script ─────────────────────────────────────────────────────────
printf 'keep;\n' > "$T/first.sieve"
"$BIN" mail m sieve alice put first "$T/first.sieve" >/dev/null 2>&1
dir=$(find "$HOME" -type d -path '*m.sieve/alice' 2>/dev/null | head -1)
if [ -z "$dir" ] || [ ! -f "$dir/first.sieve" ]; then
    echo "  FATAL: the first script was not kept: dir '$dir', $(tail -3 "$SOCKETLEY_DLOG")"
    echo "=== Results: 0 passed, 1 failed ==="; exit 1
fi
printf 'not a script\n' > "$T/victim-sieve"
# A link at the name the old writer used, in whichever process writes it.
for p in $(pids); do ln -s "$T/victim-sieve" "$dir/second.sieve.tmp.$p"; done
printf 'discard;\n' > "$T/second.sieve"
"$BIN" mail m sieve alice put second "$T/second.sieve" >/dev/null 2>&1
if [ "$(cat "$T/victim-sieve")" = "not a script" ]; then ok
else bad "a link beside a Sieve script is not written through" "its target now holds: $(head -c 80 "$T/victim-sieve")"; fi
grep -q discard "$dir/second.sieve" 2>/dev/null && ok || bad "and the script is kept" "$(ls -la "$dir")"
rm -f "$dir"/second.sieve.tmp.*
left=$(find "$dir" -name '*.tmp' -o -name '*.tmp.*' | wc -l)
[ "$left" = 0 ] && ok || bad "and nothing is left beside the scripts" "$(find "$dir" -name '*.tmp*')"

# ─── the sign-in record ─────────────────────────────────────────────────────
state=$(find "$HOME" -type d -path '*mail/m' 2>/dev/null | head -1)
if [ -z "$state" ]; then
    bad "the mail runtime has a state directory" "$(find "$HOME" -type d -name m | head -3)"
else
    printf 'not the record\n' > "$T/victim-auth"
    ln -s "$T/victim-auth" "$state/auth.tmp"
    # A sign-in from an address not seen before is written down at the next tick.
    python3 - "$IM" <<'PY' >/dev/null 2>&1
import imaplib, sys
M = imaplib.IMAP4("127.0.0.1", int(sys.argv[1])); M.login("alice", "alicepassword1"); M.logout()
PY
    for _ in $(seq 1 50); do [ -f "$state/auth" ] && break; sleep 0.1; done
    if [ "$(cat "$T/victim-auth")" = "not the record" ]; then ok
    else bad "a link beside the sign-in record is not written through" "its target now holds: $(head -c 80 "$T/victim-auth")"; fi
    grep -q alice "$state/auth" 2>/dev/null && ok || bad "and the record has the sign-in" "$(cat "$state/auth" 2>&1 | head -3)"
    rm -f "$state/auth.tmp"
fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
