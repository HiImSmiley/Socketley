#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: messages APPENDed through several shards in the same microsecond are each kept under a name of
# their own, and none answered OK is lost.
#
# What each part would catch:
#   * every shard naming its messages as shard 0 from a counter of its own that starts at 0: two APPENDs in one
#     microsecond took one name, the second's bytes overwrote the first's and both were answered OK with one UID,
#     seen once in a full gate as 39 of 40 messages; the clock is frozen here so they meet every time
#   * a new message written over a name another took meanwhile, rather than under a new one: the same loss from any
#     writer that meets another, a second runtime on the bucket among them
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

echo "=== Integration: APPENDs through several shards in one microsecond are each kept ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
daemon_isolate imapnames
T=$SOCKETLEY_TMPD
PI=$((SL_PORT_BASE + 1940)); PS=$((SL_PORT_BASE + 1941)); P=$((SL_PORT_BASE + 1942)); IM=$((SL_PORT_BASE + 1943))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
# Every message id of every process named after one microsecond, as writers in it would be.
SOCKETLEY_MAIL_SPOOL_FROZEN_US=1800000000000000 daemon_start "$BIN"
printf 'spa - http://localhost:5173/cb\n' > "$T/clients"
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
"$BIN" idp-user auth add alice --password alicepassword1 --email alice@example.test >/dev/null 2>&1
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --imap "$IM" --shards 3 \
    -s >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(ss -ltnpH "sport = :$IM" | grep -o 'pid=[0-9]*' | sort -u | wc -l)" -ge 3 ] && break; sleep 0.1; done
shards=$(ss -ltnpH "sport = :$IM" | grep -o 'pid=[0-9]*' | sort -u | wc -l)
[ "$shards" -ge 3 ] && ok || bad "IMAP listens on three shards" "$shards"

out=$(timeout 180 python3 - "$IM" <<'PY'
import imaplib, sys, threading
port = int(sys.argv[1])
def conn():
    M = imaplib.IMAP4("127.0.0.1", port, timeout=60); M.login("alice", "alicepassword1"); return M
M0 = conn(); M0.create("Shared"); M0.logout()
errs = []
def appender(i):
    try:
        M = conn()
        for k in range(8):
            typ, data = M.append("Shared", None, None, b"From: x@else.test\r\nSubject: s%d-%d\r\n\r\nbody %d-%d\r\n" % (i, k, i, k))
            if typ != "OK": errs.append(data)
        M.logout()
    except Exception as e:
        errs.append(repr(e))
ts = [threading.Thread(target=appender, args=(i,)) for i in range(12)]
[t.start() for t in ts]; [t.join() for t in ts]
M = conn(); M.select("Shared")
typ, data = M.uid("FETCH", "1:*", "(BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
subjects = [d[1].strip() for d in data if isinstance(d, tuple)]
print(len(errs), len(subjects), len(set(subjects)))
PY
)
read -r errs got distinct <<<"$out"
echo "  96 APPENDs through ${shards} shards with the clock frozen: ${errs:-?} refused, ${got:-?} messages, ${distinct:-?} distinct"
[ "${errs:-x}" = 0 ] && ok || bad "every APPEND is answered OK" "$out"
[ "${got:-0}" = 96 ] && [ "${distinct:-0}" = 96 ] && ok || bad "and every one is kept, its own message" "$out"
# The bucket holds one object for each, none written over another.
objects=$(curl -s "http://127.0.0.1:$PS/mail?list-type=2&prefix=alice/Shared/" | grep -o '<Key>[^<]*</Key>' | wc -l)
[ "$objects" = 96 ] && ok || bad "under a name of its own in the bucket" "$objects objects"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
