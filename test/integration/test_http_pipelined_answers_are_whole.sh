#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Answers to requests pipelined over one HTTP connection to a db and an idp arrive whole and in order, however slowly
# the client reads.
#
# What each part would catch:
#   * an answer appended to the connection's buffer while the ring still sent from it: the append moved the buffer,
#     and the kernel went on reading the old one -- bytes nobody owns any more on the wire, or a send that fails
#     with EFAULT and closes the connection. Under a sanitizer build, ASAN_OPTIONS=free_fill_byte=85 fills that
#     old buffer the moment it is freed, so an answer read from it is garbage
#   * an answer lost, or two run together, when the client reads slower than the runtime answers
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
tally() { while IFS= read -r line; do case "$line" in ok\ *) ok ;; bad\ *) bad "${line#bad }" "" ;; *) echo "  $line" ;; esac; done; }

echo "=== Integration: answers pipelined over one HTTP connection arrive whole ==="
daemon_isolate httppipe
T=$SOCKETLEY_TMPD
PD=$((SL_PORT_BASE + 1997))
PI=$((SL_PORT_BASE + 1998))
export ASAN_OPTIONS="${ASAN_OPTIONS:+$ASAN_OPTIONS:}free_fill_byte=85:max_free_fill_size=16777216"
trap 'daemon_stop' EXIT
daemon_start "$BIN"

printf 'docs private\n' > "$T/schema"
printf 'bench pipelinesecret0123456789\n' > "$T/keys"
chmod 600 "$T/keys"
"$BIN" create db d -p "$PD" --schema "$T/schema" --keys "$T/keys" -s >/dev/null 2>&1 \
    && ok || bad "a db runtime is made" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create idp i -p "$PI" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1 \
    && ok || bad "an idp runtime is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for p in "$PD/c/docs/none" "$PI/jwks"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done

run() {
    python3 - "$PD" "$PI" 2>&1 <<'PY' || echo "bad the checks ran to their end"
import sys, json, socket, time, urllib.request
pd, pi = sys.argv[1:3]
KEY = {"Authorization": "Bearer pipelinesecret0123456789", "Content-Type": "application/json"}
def parsed(b):
    try:
        return json.loads(b)
    except ValueError:
        return None

def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))

# A document large enough that a few answers fill the socket's buffer, so the sends behind them wait in the ring.
big = {"v": "x" * 700000}
r = urllib.request.Request("http://127.0.0.1:%s/c/docs/big" % pd, data=json.dumps(big).encode(), method="PUT", headers=KEY)
urllib.request.urlopen(r, timeout=10).read()

def pipelined(port, path, n, headers="", batch=1):
    s = socket.create_connection(("127.0.0.1", int(port)), 10)
    req = ("GET %s HTTP/1.1\r\nHost: x\r\n%s\r\n" % (path, headers)).encode()
    # One at a time and nothing read, so later requests are answered while the sends of earlier ones wait in the
    # ring for a buffer the client is not emptying.
    for _ in range(n // batch):
        s.sendall(req * batch)
        time.sleep(0.03)
    time.sleep(1.0)
    data = b""
    # Read until the runtime has had two seconds with nothing more to say.
    s.settimeout(2)
    while True:
        try:
            chunk = s.recv(1 << 20)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    s.close()
    answers = []
    while data:
        end = data.find(b"\r\n\r\n")
        if end < 0:
            break
        head = data[:end].decode("latin-1")
        length = 0
        for line in head.split("\r\n")[1:]:
            k, _, v = line.partition(":")
            if k.strip().lower() == "content-length":
                length = int(v.strip())
        body = data[end + 4:end + 4 + length]
        if len(body) < length:
            break
        answers.append((head.split("\r\n")[0], body))
        data = data[end + 4 + length:]
    return answers, data

auth = "Authorization: Bearer pipelinesecret0123456789\r\n"
answers, rest = pipelined(pd, "/c/docs/big", 30, auth)
check("every pipelined db answer arrives", len(answers), 30)
whole = sum(1 for st, b in answers if st.startswith("HTTP/1.1 200") and (parsed(b) or {}).get("v") == big["v"])
check("and each is the document, byte for byte", whole, len(answers))
check("with nothing after them", rest, b"")

answers, rest = pipelined(pi, "/jwks", 3000, batch=100)
check("every pipelined idp answer arrives", len(answers), 3000)
first = answers[0][1] if answers else b""
check("and each is the same key set", sum(1 for st, b in answers if st.startswith("HTTP/1.1 200") and b == first), len(answers))
check("which is JSON", "keys" in (parsed(first) or {}), True)
PY
}
tally < <(run)

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
