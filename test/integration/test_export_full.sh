#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: socketley export --full writes a machine's setup and its data into one archive tar reads, and
# socketley restore puts it back on a machine whose state and data are gone, every runtime coming back with what it
# held: a storage's object, an idp's account, a mailbox's message, a db's document, a cache's key, a dns zone.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * an archive tar or gzip does not take, or one that is not smaller with --compress best
#   * compressing on several threads that loses or reorders a piece, which one thread would not
#   * a runtime's data left out: its buckets, its accounts, its mailboxes, its documents, its keys
#   * a restore over a running daemon, over runtimes already there, or of a file that is no such archive
#   * a restore that brings the runtimes back stopped, or without what they held
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ready.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v curl >/dev/null 2>&1 || { echo "  SKIP: curl is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

daemon_isolate export_full
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1960)); IM=$((P+1)); PI=$((P+2)); PS=$((P+3)); PD=$((P+4)); PC=$((P+5)); NS=$((P+6))
trap daemon_stop EXIT

echo "=== Integration: export --full and restore ==="

daemon_start "$BIN"
printf 'spa - http://localhost:5173/cb\n' > "$T/clients"
printf 'backend dbbackendsecret0123456789\n' > "$T/keys"; chmod 600 "$T/keys"
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
"$BIN" create db docs -p "$PD" --keys "$T/keys" -s >/dev/null 2>&1
"$BIN" create cache kv -p "$PC" --persistent "$T/kv.rdb" --persistent-interval 1s -s >/dev/null 2>&1
"$BIN" create dns ns -p "$NS" --bind 127.0.0.1 --zone example.test --publish 127.0.0.1 --proxy none -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/" "$PD/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
"$BIN" idp-user auth add alice --password alicepassword1 --email alice@example.test >/dev/null 2>&1
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --imap "$IM" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$IM" || bad "the IMAP port listens" "$(tail -3 "$SOCKETLEY_DLOG")"
ready_tcp 127.0.0.1 "$PC" >/dev/null 2>&1

python3 - "$P" "$PS" "$PD" "$PC" <<'PY'
import http.client, json, smtplib, socket, sys, time, urllib.request
P, PS, PD, PC = map(int, sys.argv[1:5])
c = http.client.HTTPConnection("127.0.0.1", PS, timeout=10)
c.request("PUT", "/files"); c.getresponse().read()
c.request("PUT", "/files/hello.txt", body=b"kept across machines\n"); c.getresponse().read()
c = http.client.HTTPConnection("127.0.0.1", PD, timeout=10)
c.request("POST", "/c/notes", body=json.dumps({"text": "a note to keep"}),
          headers={"Authorization": "Bearer dbbackendsecret0123456789", "Content-Type": "application/json"})
c.getresponse().read()
s = socket.create_connection(("127.0.0.1", PC), timeout=5)
s.sendall(b"*3\r\n$3\r\nSET\r\n$4\r\nkept\r\n$5\r\nvalue\r\n"); time.sleep(0.3); s.recv(100)
m = smtplib.SMTP("127.0.0.1", P); m.ehlo("x")
m.sendmail("zed@else.test", ["alice@example.test"], "From: zed@else.test\r\nTo: alice@example.test\r\nSubject: keep me\r\n\r\nbody\r\n")
m.quit()
for _ in range(100):
    try:
        if b"<Key>" in urllib.request.urlopen("http://127.0.0.1:%d/mail?list-type=2&prefix=alice/INBOX/" % PS).read():
            break
    except Exception:
        pass
    time.sleep(0.05)
PY

# A cache's write reaches its journal within the second it journals at.
sleep 1.5
out=$("$BIN" export --full "$T/fast.tar.gz" 2>&1); rc=$?
case "$out" in "exported "*" files of "*" runtimes, "*"into $T/fast.tar.gz ("*) [ "$rc" -eq 0 ] && ok "export --full writes the archive and says what went in" \
    || bad "export --full" "rc $rc: $out" ;; *) bad "export --full" "rc $rc: $out" ;; esac
"$BIN" export --full "$T/best.tar.gz" --compress best >/dev/null 2>&1
"$BIN" export --full "$T/plain.tar" --compress none >/dev/null 2>&1
out=$("$BIN" export --full "$T/fast.tar.gz" 2>&1); rc=$?
[ "$rc" -eq 1 ] && ok "an archive is not written over" || bad "an archive over another" "rc $rc: $out"
gzip -t "$T/fast.tar.gz" 2>/dev/null && gzip -t "$T/best.tar.gz" 2>/dev/null && ok "gzip takes both, the fast and the best" || bad "gzip -t" "$(gzip -t "$T/fast.tar.gz" 2>&1)"
list=$(tar tzf "$T/fast.tar.gz" 2>&1)
st_dir=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['state_dir'])" "$(tar xzOf "$T/fast.tar.gz" socketley-backup/manifest.json)")
case "$list" in *"socketley-backup/manifest.json"*"socketley-backup/setup/config.lua"*) ok "tar lists the manifest and the Lua setup" ;; *) bad "tar's listing" "$(printf '%s' "$list" | head -5)" ;; esac
for want in "${T#/}/data/files/" "${T#/}/kv.rdb" "${st_dir#/}/db/docs/seg-00000001.log" "${st_dir#/}/idp/auth.accounts/" "${st_dir#/}/mail/m.dkim.skl.key"; do
    grep -q "^$want" <<< "$list" || { bad "the archive holds $want" "$(printf '%s\n' "$list" | grep -c .) entries"; continue; }
    ok "the archive holds ${want%/}"
done
[ "$(stat -c %s "$T/best.tar.gz")" -le "$(stat -c %s "$T/fast.tar.gz")" ] && [ "$(stat -c %s "$T/fast.tar.gz")" -lt "$(stat -c %s "$T/plain.tar")" ] \
    && ok "best is no larger than fast, and fast smaller than none" \
    || bad "the sizes" "$(stat -c '%n %s' "$T/best.tar.gz" "$T/fast.tar.gz" "$T/plain.tar")"
tar tf "$T/plain.tar" >/dev/null 2>&1 && ok "--compress none is a plain tar" || bad "a plain tar" "$(file "$T/plain.tar")"
"$BIN" export --full "$T/one.tar.gz" --threads 1 >/dev/null 2>&1
[ "$(tar tzf "$T/one.tar.gz" 2>/dev/null | wc -l)" -eq "$(printf '%s\n' "$list" | wc -l)" ] && ok "compressed on one thread, the archive holds the same" \
    || bad "--threads 1" "$(tar tzf "$T/one.tar.gz" 2>&1 | wc -l) entries"
out=$("$BIN" export --full "$T/zero.tar.gz" --threads 0 2>&1); rc=$?
[ "$rc" -eq 1 ] && [ ! -e "$T/zero.tar.gz" ] && ok "--threads 0 is refused" || bad "--threads 0" "rc $rc: $out"
[ "$(stat -c %a "$T/fast.tar.gz")" = 600 ] && ok "the archive is its writer's alone" || bad "the archive's mode" "$(stat -c %a "$T/fast.tar.gz")"

out=$("$BIN" restore "$T/fast.tar.gz" 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"daemon is running"*) true ;; *) false ;; esac && ok "restore refuses a running daemon" || bad "restore over a running daemon" "rc $rc: $out"

# The machine lost: the daemon gone, its state and every runtime's data with it.
daemon_stop_keep() { kill "$SOCKETLEY_DPID" 2>/dev/null; for _ in $(seq 1 100); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done; }
daemon_stop_keep
out=$("$BIN" restore "$T/fast.tar.gz" 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"--force"*) true ;; *) false ;; esac && ok "restore over runtimes already there asks for --force" || bad "restore without --force" "rc $rc: $out"
rm -rf "$st_dir" "$T/data" "$T/kv.rdb"*
# An archive whose manifest names one place and whose entries write another is refused before it writes there.
python3 - "$T/evil.tar.gz" "$T" <<'PY'
import io, json, sys, tarfile
t = tarfile.open(sys.argv[1], "w:gz")
def add(name, data):
    i = tarfile.TarInfo(name); i.size = len(data); t.addfile(i, io.BytesIO(data))
add("socketley-backup/manifest.json", json.dumps({"format": 1, "state_dir": sys.argv[2] + "/nowhere",
                                                  "roots": [sys.argv[2] + "/nowhere"]}).encode())
add(sys.argv[2].lstrip("/") + "/escaped", b"written where it was not to be")
t.close()
PY
out=$("$BIN" restore "$T/evil.tar.gz" 2>&1); rc=$?
[ "$rc" -eq 2 ] && [ ! -e "$T/escaped" ] && case "$out" in *"outside what its manifest says"*) true ;; *) false ;; esac \
    && ok "an entry outside the manifest's roots refuses the archive, and is not written" || bad "an escaping entry" "rc $rc: $out"
printf 'no archive at all' > "$T/junk.tar.gz"
out=$("$BIN" restore "$T/junk.tar.gz" 2>&1); rc=$?
[ "$rc" -eq 1 ] && ok "a file that is no such archive is refused" || bad "a junk archive" "rc $rc: $out"
out=$("$BIN" restore "$T/fast.tar.gz" 2>&1); rc=$?
case "$out" in "restored "*" files, "*"start the daemon"*) [ "$rc" -eq 0 ] && ok "restore puts it all back" || bad "restore" "rc $rc: $out" ;; *) bad "restore" "rc $rc: $out" ;; esac

daemon_start "$BIN"
for _ in $(seq 1 100); do [ "$("$BIN" ls 2>/dev/null | grep -c ' Up ')" -ge 6 ] && break; sleep 0.2; done
up=$("$BIN" ls 2>/dev/null | grep -c ' Up ')
[ "$up" -ge 6 ] && ok "every runtime comes back running" || bad "the runtimes after a restore" "$("$BIN" ls 2>&1)"
for p in "$PS/" "$PD/"; do for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done; done
ready_tcp 127.0.0.1 "$IM" >/dev/null 2>&1; ready_tcp 127.0.0.1 "$PC" >/dev/null 2>&1
[ "$(curl -s "http://127.0.0.1:$PS/files/hello.txt")" = "kept across machines" ] && ok "the storage's object is back" \
    || bad "the storage's object" "$(curl -s "http://127.0.0.1:$PS/files/hello.txt")"
case "$("$BIN" db-query docs notes 2>&1)" in *'"a note to keep"'*) ok "the db's document is back" ;; *) bad "the db's document" "$("$BIN" db-query docs notes 2>&1)" ;; esac
got=$(python3 - "$IM" "$PC" <<'PY'
import socket, sys, time
IM, PC = int(sys.argv[1]), int(sys.argv[2])
s = socket.create_connection(("127.0.0.1", PC), timeout=5); s.sendall(b"*2\r\n$3\r\nGET\r\n$4\r\nkept\r\n"); time.sleep(0.2)
cache = s.recv(100)
i = socket.create_connection(("127.0.0.1", IM), timeout=10); f = i.makefile("rb"); f.readline()
i.sendall(b"a LOGIN alice alicepassword1\r\nb STATUS INBOX (MESSAGES)\r\nc LOGOUT\r\n")
imap = i.makefile("rb").read().decode(errors="replace")
print(("cache-ok" if b"value" in cache else "cache-bad:%r" % cache), ("imap-ok" if "a OK" in imap and "MESSAGES 1" in imap else "imap-bad:" + imap.replace("\r\n", " ")[:300]))
PY
)
case "$got" in *cache-ok*) ok "the cache's key is back" ;; *) bad "the cache's key" "$got" ;; esac
case "$got" in *imap-ok*) ok "the account signs in and its message is in its mailbox" ;; *) bad "the account and mailbox" "$got" ;; esac
if ! command -v dig >/dev/null 2>&1; then echo "  SKIP: dig is not installed"
elif [ "$(dig +short +time=2 +tries=1 -p "$NS" @127.0.0.1 example.test SOA 2>/dev/null | wc -l)" -ge 1 ]; then ok "the dns zone is served again"
else bad "the dns zone" "no SOA"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
