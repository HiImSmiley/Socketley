#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a mail runtime's spool keeps what it was given and nothing it should not, in segments a commit
# shares.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * messages arriving together each synced on their own, rather than in one commit of the segment
#   * a message over a mebibyte squeezed into a record, or a small one given a file of its own
#   * a queued message of either kind lost by a restart
#   * a message dropped with `socketley mail ... drop` brought back by a restart, as its record is still there
#   * a record a crash cut taken as a message, or the messages before it lost with it
#   * a segment a deferred message keeps never used again, or the message lost by its move
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ready.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate mail_spool
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1990))
SINK=$((SL_PORT_BASE+1991))
NS=$((SL_PORT_BASE+1992))
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a mail runtime's spool, its segments and their commits ==="

python3 "$HERE/lib_fake_dns.py" "$NS" 0 normal remote.test=MX:10:mx.remote.test mx.remote.test=127.0.0.1 \
    >/dev/null 2>&1 &
PIDS+=($!)
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1 port:%s\n' "$NS" > "$T/resolv.conf"
# A segment emptied but for a deferred message is moved out of at once.
export SOCKETLEY_RESOLV_CONF="$T/resolv.conf" SOCKETLEY_MAIL_MX_PORT="$SINK" SOCKETLEY_MAIL_SPOOL_MOVE_MS=0
mkdir -p "$T/sink"
python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/sink" --reply later@remote.test 451 >/dev/null 2>&1 &
PIDS+=($!)
ready_tcp 127.0.0.1 "$SINK" || bad "the sink listens" "-"
daemon_start "$BIN"

"$BIN" create mail s -p "$P" --mail-domain example.test -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P" || bad "the mail runtime listens" "$(tail -3 "$SOCKETLEY_DLOG")"
stat_of() { "$BIN" stats s 2>/dev/null | sed -n "s/^$1://p"; }
spool_dir() { find "$HOME/.local/share" -type d -path '*/mail/s/spool' 2>/dev/null | head -1; }
kept() { "$BIN" mail s queue 2>/dev/null | grep -c "keep[12]@example.test"; }

# ─── one commit for messages that end together ──────────────────────────────
# Twenty sessions each hold back the dot that ends their message, then all send it at once.
r=$(python3 - "$P" <<'PY'
import socket, sys
port = int(sys.argv[1])
socks = []
for i in range(20):
    s = socket.create_connection(("127.0.0.1", port)); f = s.makefile("rb"); f.readline()
    s.sendall(b"EHLO x\r\n")
    while not f.readline().startswith(b"250 "): pass
    s.sendall(b"MAIL FROM:<a@example.test>\r\nRCPT TO:<frank@remote.test>\r\nDATA\r\n")
    for _ in range(3): f.readline()
    s.sendall(b"Subject: together %d\r\n\r\nbody %d\r\n" % (i, i))
    socks.append((s, f))
for s, f in socks: s.sendall(b".\r\n")
print(sum(f.readline().startswith(b"250") for s, f in socks))
PY
)
check "twenty messages ending together are all taken" "$r" "20"
# The worker's counts reach the daemon a moment after they change.
for _ in $(seq 1 50); do committed=$(stat_of mail_spool_committed); [ "${committed:-0}" -ge 20 ] && break; sleep 0.1; done
commits=$(stat_of mail_spool_commits)
[ "${committed:-0}" -ge 20 ] && [ "${commits:-99}" -lt 20 ] \
    && ok "and share their commits ($committed messages in $commits syncs)" \
    || bad "and share their commits" "$committed messages in $commits syncs"

# ─── a large message, and the restart ───────────────────────────────────────
"$BIN" send s --from keep1@example.test --to later@remote.test --subject small --text "small kept" >/dev/null 2>&1
head -c 1500000 /dev/zero | tr '\0' 'x' | fold -w 76 > "$T/big.txt"
"$BIN" send s --from keep2@example.test --to later@remote.test --subject big --text big --attach "$T/big.txt" >/dev/null 2>&1
D=$(spool_dir)
check "a message over a mebibyte is a file of its own" "$(ls "$D" 2>/dev/null | grep -c '\.msg$')" "1"
[ "$(ls "$D" 2>/dev/null | grep -c '^seg-.*\.spool$')" -ge 1 ] && ok "and the small ones records of a segment" \
    || bad "and the small ones records of a segment" "$(ls "$D" 2>&1)"
for _ in $(seq 1 50); do [ "$(kept)" = 2 ] && break; sleep 0.1; done
id=$("$BIN" send s --from a@example.test --to later@remote.test --subject dropped --text "dropped body" 2>&1 \
     | sed -n 's/^queued //p')
"$BIN" mail s drop "$id" >/dev/null 2>&1
"$BIN" stop s >/dev/null 2>&1; "$BIN" start s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P" >/dev/null
check "both waiting messages are kept across a restart" "$(kept)" "2"
"$BIN" mail s show "$id" >/dev/null 2>&1
check "and the dropped one is not brought back" "$?" "1"

# ─── a record a crash cut ───────────────────────────────────────────────────
id=$("$BIN" send s --from a@example.test --to later@remote.test --subject cut --text "cut body" 2>&1 \
     | sed -n 's/^queued //p')
"$BIN" stop s >/dev/null 2>&1
seg=$(grep -l "cut body" "$D"/seg-*.spool 2>/dev/null | head -1)
# The last byte of the message's record, its trailer's line end, overwritten as a torn write would leave it.
python3 - "$seg" <<'PY'
import sys
p = sys.argv[1]
b = open(p, "rb").read()
at = b.rfind(b"cut body")
end = b.find(b"\nend ", at)
end = b.find(b"\n", end + 1)
with open(p, "r+b") as f:
    f.seek(end); f.write(b"#")
PY
"$BIN" start s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P" >/dev/null
"$BIN" mail s show "$id" >/dev/null 2>&1
check "a record a crash cut is not a message" "$?" "1"
check "and the messages before it are kept" "$(kept)" "2"
grep -q "cut short by a crash while it was written" "$SOCKETLEY_DLOG" && ok "and the log says one was dropped" \
    || bad "and the log says one was dropped" "$(grep -i 'mail' "$SOCKETLEY_DLOG" | tail -3)"

# ─── a segment kept by a deferred message ───────────────────────────────────
# Forty messages of most of a mebibyte fill the segment the deferred ones are in; they are delivered and leave it.
head -c 700000 /dev/zero | tr '\0' 'y' | fold -w 76 > "$T/fill.txt"
for i in $(seq 1 40); do
    "$BIN" send s --from a@example.test --to "fill$i@remote.test" --subject "fill $i" --text fill --attach "$T/fill.txt" \
        >/dev/null 2>&1
done
for _ in $(seq 1 100); do
    [ "$(ls "$T"/sink/*.eml 2>/dev/null | xargs grep -l '^Subject: fill' 2>/dev/null | wc -l)" -ge 40 ] && \
        [ "${moved:-0}" -ge 1 ] && break
    sleep 0.2; moved=$(stat_of mail_spool_moved)
done
[ "${moved:-0}" -ge 1 ] && ok "a segment left with a deferred message has it moved ($moved)" \
    || bad "a segment left with a deferred message has it moved" "moved ${moved:-absent}, $(ls -la "$D")"
"$BIN" stop s >/dev/null 2>&1; "$BIN" start s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P" >/dev/null
check "and the moved message is kept across a restart" "$(kept)" "2"
"$BIN" mail s show "$("$BIN" mail s queue 2>/dev/null | grep keep1@ | cut -f1)" 2>/dev/null \
    | grep -q 'rcpt: later@remote.test' && ok "and still shows" || bad "and still shows" "$("$BIN" mail s queue 2>&1)"
n=$(ls "$D" | grep -c '^seg-.*\.spool$')
[ "$n" -le 4 ] && ok "segments are used again rather than piling up ($n)" || bad "segments are used again" "$(ls "$D")"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
