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
#   * a message of a commit read back from where another, begun while that commit ended, put its own
#   * a message delivered and gone brought back by the second restart after it, its record still in a segment
#   * a message of many recipients lost at a restart: a file whose envelope is past 64 KiB, or a record past 2 MiB
#   * a large message waiting for its next try holding a descriptor of its file
#   * a remove deleting mail the runtime still holds, or leaving its users' IMAP and Sieve state behind
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

# down.test's exchanger answers no connection, so its mail waits.
python3 "$HERE/lib_fake_dns.py" "$NS" 0 normal remote.test=MX:10:mx.remote.test mx.remote.test=127.0.0.1 \
    down.test=MX:10:mx.down.test mx.down.test=127.0.0.9 >/dev/null 2>&1 &
PIDS+=($!)
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1 port:%s\n' "$NS" > "$T/resolv.conf"
# A segment emptied but for a deferred message is moved out of at once; a body past 64 KiB is read back from it.
export SOCKETLEY_RESOLV_CONF="$T/resolv.conf" SOCKETLEY_MAIL_MX_PORT="$SINK" SOCKETLEY_MAIL_SPOOL_MOVE_MS=0 \
    SOCKETLEY_MAIL_SPOOL_KEEP_BYTES=65536
mkdir -p "$T/sink"
python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/sink" --reply later@remote.test 451 >/dev/null 2>&1 &
PIDS+=($!)
ready_tcp 127.0.0.1 "$SINK" || bad "the sink listens" "-"
daemon_start "$BIN"

"$BIN" create mail s -p "$P" --mail-domain example.test --no-reply --max-recipients 6000 -s >/dev/null 2>&1
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

# A commit that holds mail failing at once and larger mail after it: the failure's report is queued as the commit ends,
# and the larger messages, not kept in memory, are read back from where they are. gone@ fails at once, suppressed.
printf 'From: <>\r\nSubject: failed\r\n\r\nFinal-Recipient: rfc822; gone@remote.test\r\nAction: failed\r\n' > "$T/dsn.txt"
python3 - "$P" "$T/dsn.txt" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1])); s.ehlo("x")
s.sendmail("", ["no-reply@example.test"], open(sys.argv[2], "rb").read())
PY
for _ in $(seq 1 50); do [ "$("$BIN" mail s suppressed 2>/dev/null)" = gone@remote.test ] && break; sleep 0.1; done
r=$(python3 - "$P" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
taken = 0
for rnd in range(3):
    socks = []
    for i in range(16):
        s = socket.create_connection(("127.0.0.1", port)); f = s.makefile("rb"); f.readline()
        s.sendall(b"EHLO x\r\n")
        while not f.readline().startswith(b"250 "): pass
        to = b"gone@remote.test" if i % 2 == 0 else b"whole%d-%d@remote.test" % (rnd, i)
        s.sendall(b"MAIL FROM:<back@remote.test>\r\nRCPT TO:<" + to + b">\r\nDATA\r\n")
        for _ in range(3): f.readline()
        if i % 2 == 0:
            s.sendall(b"Subject: dead %d-%d\r\n\r\nd\r\n" % (rnd, i))
        else:
            s.sendall(b"Subject: whole %d-%d\r\n\r\n" % (rnd, i) + (b"marker-%d-%d " % (rnd, i) + b"y" * 70 + b"\r\n") * 1200)
        socks.append((s, f))
    # The bodies are in before any ends, so the ends come in the order sent, a failing one before each larger one.
    time.sleep(0.5)
    for s, f in socks: s.sendall(b".\r\n")
    taken += sum(f.readline().startswith(b"250") for s, f in socks)
print(taken)
PY
)
check "forty-eight messages, half of them failing at once, are taken" "$r" "48"
whole() {
    n=0
    for rnd in 0 1 2; do for i in 1 3 5 7 9 11 13 15; do
        f=$(grep -l "^Subject: whole $rnd-$i[[:space:]]*$" "$T"/sink/*.eml 2>/dev/null | head -1)
        [ -n "$f" ] && [ "$(grep -c "^marker-$rnd-$i y" "$f")" = 1200 ] && n=$((n+1))
    done; done
    echo "$n"
}
for _ in $(seq 1 100); do [ "$(whole)" = 24 ] && break; sleep 0.2; done
check "and every larger one arrives whole, read back from its own place" "$(whole)" "24"

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
[ -n "$id" ] && "$BIN" mail s show "$id" >/dev/null 2>&1 && ok "the message to drop is queued" \
    || bad "the message to drop is queued" "${id:-no id}"
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
[ -n "$id" ] && [ -n "$seg" ] && ok "the message a crash will cut is queued, in a segment" \
    || bad "the message a crash will cut is queued, in a segment" "id ${id:-none}, segment ${seg:-none}"
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
from=$(($(wc -l < "$SOCKETLEY_DLOG") + 1))
"$BIN" start s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P" >/dev/null
"$BIN" mail s show "$id" >/dev/null 2>&1
check "a record a crash cut is not a message" "$?" "1"
check "and the messages before it are kept" "$(kept)" "2"
# A move the spool made since may have put a whole record after the cut one, which makes it one damaged in the middle.
tail -n +"$from" "$SOCKETLEY_DLOG" | grep -qE "cut short by a crash while it was written|was damaged on disk, and is dropped" \
    && ok "and the log says one was dropped" || bad "and the log says one was dropped" "$(grep -i 'mail' "$SOCKETLEY_DLOG" | tail -3)"

# ─── a record damaged in the middle of a segment ────────────────────────────
mids=()
for i in 1 2 3; do
    mids+=("$("$BIN" send s --from "mid$i@example.test" --to later@remote.test --subject "mid $i" --text "mid body $i" 2>&1 \
              | sed -n 's/^queued //p')")
done
"$BIN" stop s >/dev/null 2>&1
seg=$(grep -l "mid body 1" "$D"/seg-*.spool 2>/dev/null | head -1)
python3 - "$seg" <<'PY'
import sys
p = sys.argv[1]
b = open(p, "rb").read()
at = b.find(b"mid body 1")
with open(p, "r+b") as f:
    f.seek(at); f.write(b"M")
PY
from=$(($(wc -l < "$SOCKETLEY_DLOG") + 1))
"$BIN" start s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P" >/dev/null
"$BIN" mail s show "${mids[0]}" >/dev/null 2>&1
check "a record damaged on disk is not a message" "$?" "1"
for i in 1 2; do
    "$BIN" mail s show "${mids[$i]}" >/dev/null 2>&1
    check "and the one after it, $((i+1)), is kept" "$?" "0"
done
tail -n +"$from" "$SOCKETLEY_DLOG" | grep -q "was damaged on disk, and is dropped; the messages after it are kept" \
    && ok "and the log says one was damaged" || bad "and the log says one was damaged" "$(grep -i 'mail' "$SOCKETLEY_DLOG" | tail -3)"
for i in 1 2; do "$BIN" mail s drop "${mids[$i]}" >/dev/null 2>&1; done

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

# ─── what a restart brings back ─────────────────────────────────────────────
restart() { "$BIN" stop "$1" >/dev/null 2>&1; "$BIN" start "$1" >/dev/null 2>&1; ready_tcp 127.0.0.1 "$2" >/dev/null; }
# A fresh spool: messages that wait fill more than a quarter of its first segment, so it is neither moved out of nor
# used again, and the delivered one's record stays in it.
P2=$((SL_PORT_BASE+1993))
"$BIN" create mail s2 -p "$P2" --mail-domain example.test -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P2" >/dev/null
head -c 600000 /dev/zero | tr '\0' 'k' | fold -w 76 > "$T/keep.txt"
for i in $(seq 1 12); do
    "$BIN" send s2 --from a@example.test --to "keepalive$i@down.test" --subject waits --text "waits on" \
        --attach "$T/keep.txt" >/dev/null 2>&1
done
"$BIN" send s2 --from a@example.test --to once@remote.test --subject once --text "delivered once" >/dev/null 2>&1
for _ in $(seq 1 50); do grep -l 'delivered once' "$T"/sink/*.eml >/dev/null 2>&1 && break; sleep 0.1; done
restart s2 "$P2"; restart s2 "$P2"; sleep 1.5
check "a message delivered is not delivered again by the second restart after it" \
    "$(grep -l 'delivered once' "$T"/sink/*.eml 2>/dev/null | wc -l)" "1"
# Many recipients, waiting: one message past a mebibyte whose envelope is past 64 KiB, and one under a mebibyte whose
# envelope is past one.
python3 - "$P" <<'PY'
import smtplib, sys
port = int(sys.argv[1])
def send(n, local_len, body, tag, orcpt=0):
    s = smtplib.SMTP("127.0.0.1", port, timeout=120); s.ehlo("x")
    s.mail("many@remote.test")
    for i in range(n):
        s.rcpt("%s%05d%s@down.test" % (tag, i, "r" * local_len),
               ["ORCPT=rfc822;" + "o" * orcpt + "%05d@else.test" % i] if orcpt else [])
    s.data(b"Subject: " + tag.encode() + b"\r\n\r\n" + body)
    s.quit()
send(1200, 40, (b"b" * 78 + b"\r\n") * 15000, "wide")
send(5000, 50, b"short body\r\n", "tall", 400)
PY
restart s "$P"
check "a file of its own whose envelope is past 64 KiB is kept across a restart" \
    "$("$BIN" mail s queue 2>/dev/null | grep -c 'many@remote.test.*0/1200')" "1"
check "and so is a message whose envelope is past a mebibyte" \
    "$("$BIN" mail s queue 2>/dev/null | grep -c 'many@remote.test.*0/5000')" "1"
# Large messages from this runtime's domain are read whole to be signed; waiting, they hold no descriptor.
head -c 1500000 /dev/zero | tr '\0' 'z' | fold -w 76 > "$T/large.txt"
for i in 1 2 3 4 5 6; do
    "$BIN" send s --from a@example.test --to "w$i@down.test" --subject "large $i" --text large --attach "$T/large.txt" \
        >/dev/null 2>&1
done
sleep 3
w=$(ss -ltnpH "sport = :$P" | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
check "six large messages waiting for their next try hold no descriptor of their files" \
    "$(ls -l /proc/"$w"/fd 2>/dev/null | grep -c '\.msg$')" "0"
# A remove keeps aside mail the runtime took and still holds, and takes its users' state with it.
mkdir -p "$(dirname "$D")/../s.imap" "$(dirname "$D")/../s.sieve"
held_n=$("$BIN" mail s queue 2>/dev/null | grep -c .)
"$BIN" remove s >/dev/null 2>&1
base=$(dirname "$(dirname "$D")")
# What the runtime leaves is dealt with once its worker has stopped.
for _ in $(seq 1 100); do [ ! -e "$base/s" ] && break; sleep 0.1; done
held=$(ls -d "$base"/s.held-* 2>/dev/null | head -1)
[ -n "$held" ] && [ "$(ls "$held/spool" | grep -c '\.msg$')" -ge 1 ] && ok "a removed runtime's queued mail is kept aside ($held_n)" \
    || bad "a removed runtime's queued mail is kept aside" "$(ls "$base")"
[ ! -e "$base/s.imap" ] && [ ! -e "$base/s.sieve" ] && ok "and its users' IMAP and Sieve state go with it" \
    || bad "and its users' IMAP and Sieve state go with it" "$(ls "$base")"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
