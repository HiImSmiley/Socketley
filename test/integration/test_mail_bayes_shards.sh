#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: what a shard other than the first learns while the first folds the journal under it -- the line
# written to a journal opened before the fold moved it aside and read it -- is learned all the same, and once.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a learned line that went into a journal already folded and removed lost, from the table the first shard scores
#     with and from its file, so a restart scores without it too
#   * that line, written again into the new journal, counted twice
#   * the test aid no longer holding the line where the fold catches it, which would leave the rest proving nothing
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ready.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v ss >/dev/null 2>&1 || { echo "  SKIP: ss is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
tally() { while read -r verdict rest; do [ "$verdict" = ok ] && ok "$rest" || bad "${rest%%:*}" "${rest#*: }"; done; }

daemon_isolate mail_bayes_shards
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1990)); IM=$((P+1)); PI=$((P+2)); PS=$((P+3))
trap 'daemon_stop' EXIT

echo "=== Integration: a learned line the fold moved aside under its writer ==="

# Folds 6 s apart, so the two lines of the second move below go in well before the fold after the first; the second
# shard's line to a journal holding lines already is held until the first shard folded that journal and removed it.
export SOCKETLEY_MAIL_BAYES_FOLD_MS=6000 SOCKETLEY_MAIL_BAYES_HOLD_MS=30000
daemon_start "$BIN"
"$BIN" create idp auth -p "$PI" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
"$BIN" idp-user auth add alice --password alicepassword1 --email alice@example.test >/dev/null 2>&1
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --imap "$IM" --shards 2 -s \
    >/dev/null 2>&1
ready_tcp 127.0.0.1 "$IM" || bad "the IMAP port listens" "$(tail -3 "$SOCKETLEY_DLOG")"

cat > "$T/race.py" <<'PY'
import imaplib, os, re, subprocess, sys, time
port, smtp, binary, home, dlog = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
def say(name, cond, why=""):
    print(("ok " if cond else "bad ") + name + ("" if cond else ": " + str(why)[:600]), flush=True)
def pid(flags, q):
    m = re.search(r"pid=(\d+)", subprocess.run(["ss", flags, q], capture_output=True).stdout.decode())
    return m.group(1) if m else None
# Mail is taken on the first shard alone, so the process listening for it is that shard.
first = pid("-ltnpH", "sport = :%d" % smtp)
def on_second():
    for _ in range(200):
        M = imaplib.IMAP4("127.0.0.1", port)
        if pid("-tnpH", "sport = :%d and dport = :%d" % (port, M.sock.getsockname()[1])) not in (None, first):
            M.login("alice", "alicepassword1")
            return M
        M.shutdown()
    raise SystemExit("bad a session reached the second shard")
def spam():
    out = subprocess.run([binary, "stats", "m"], capture_output=True, timeout=30).stdout.decode()
    got = [int(l.split(":")[1]) for l in out.splitlines() if l.strip().startswith("mail_bayes_spam:")]
    return got[0] if got else None
def names():
    return sorted(f for _, _, fs in os.walk(home) for f in fs if f.startswith("m.bayes"))
def folded():
    n = names()
    return "m.bayes" in n and "m.bayes.journal" not in n and "m.bayes.folding" not in n
def until(cond, secs):
    end = time.time() + secs
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.1)
    return cond()
def held():
    with open(dlog, errors="replace") as f:
        return f.read().count("a learned line held until its journal was folded")

M = on_second()
for k in range(3):
    M.append("INBOX", None, None, b"From: promo@deals.test\r\nSubject: Offer %d\r\n\r\ncheap pills casino %d\r\n" % (k, k))
M.select("INBOX")
uids = M.uid("SEARCH", None, "ALL")[1][0].split()
say("three messages for alice, on the second shard", len(uids) == 3, uids)
M.uid("MOVE", uids[0], "Junk")
say("the first moved into Junk is learned and folded into the file",
    until(lambda: spam() == 1 and folded(), 30), (spam(), names()))
# A fold just now: the second move's first line starts a new journal, its second opens that one and is written only
# once the fold 6 s from now has read it and removed it.
M.uid("MOVE", b",".join(uids[1:]), "Junk")
say("the second shard's line was held until its journal was folded", until(lambda: held() == 1, 30), held())
say("and the line written to the journal folded under it is learned", until(lambda: spam() == 3, 20), spam())
say("once, though it went into two files", until(folded, 20) and spam() == 3, (spam(), names()))
M.logout()
PY
timeout 180 python3 "$T/race.py" "$IM" "$P" "$BIN" "$T" "$SOCKETLEY_DLOG" 2>&1 | grep -E '^(ok|bad) ' > "$T/race.out"
tally < "$T/race.out"
[ -s "$T/race.out" ] || bad "the race ran" "$(tail -3 "$SOCKETLEY_DLOG")"

# What the first shard learned is what its file holds: a restart scores with the three, each once.
"$BIN" restart m >/dev/null 2>&1
ready_tcp 127.0.0.1 "$IM" >/dev/null 2>&1
spam_now() { "$BIN" stats m 2>/dev/null | sed -n 's/^ *mail_bayes_spam: *//p' | head -1; }
for _ in $(seq 1 100); do [ -n "$(spam_now)" ] && break; sleep 0.1; done
[ "$(spam_now)" = 3 ] && ok "and a restart reads the three from its file, each once" || bad "after a restart" "$(spam_now)"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
