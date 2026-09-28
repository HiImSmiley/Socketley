#!/usr/bin/env bash
# Integration test: a TCP proxy delivers both directions byte for byte, in
# order, through every mix of sends taken at once and sends that had to queue
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A relayed message is sent with send() when nothing is queued ahead of it,
# and through the ring when the socket is full or a write is in flight.  The
# two must never overtake each other: a direct send while an earlier message
# still waits in the queue delivers the stream out of order, and a partial
# direct send whose remainder is queued from the start again delivers bytes
# twice.  Both are silent -- every byte arrives, just not the right ones.
#
# So both peers stall at first, which fills the kernel buffers and forces the
# proxy through partial sends and a queue, then read everything; records of
# 1 byte to 70 KB go each way, and each side's digest must match what the
# other side sent.  Twice: once with the backend half-closing after the
# client's end has reached it, and once with the backend half-closing the
# moment it has sent -- a backend's FIN used to end the pair, as it does on
# nginx's default, and 12 of 12 runs lost the rest of the upload.  Both on the
# copy path and on the splice path, which hold a half-close in different code.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the upstream stream reaching the backend reordered, duplicated or short,
#     or cut off by the backend's half-close
#   * the downstream stream reaching the client the same way
#   * a pair whose two sides have both closed left open behind them
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
PASS=0; FAIL=0; TOTAL=0
PEER_DIR=$(mktemp -d /tmp/socketley-relayorder-peer-XXXXXX)
cleanup(){ [ -n "${BE_PID:-}" ] && kill "$BE_PID" 2>/dev/null || true; daemon_stop; rm -rf "$PEER_DIR"; }
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a TCP proxy relays both directions in order ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

BE=$((SL_PORT_BASE + 1301)); PX=$((SL_PORT_BASE + 1302))
cat > "$PEER_DIR/peer.py" <<'PY'
import hashlib, random, socket, sys, threading, time

def records(seed, total):
    """Records of mixed sizes, each carrying its index so a reorder changes the digest."""
    rnd = random.Random(seed)
    out, n, i = [], 0, 0
    while n < total:
        size = rnd.choice([1, 7, 64, 1000, 16384, 70000])
        rec = (b"%08d|" % i) + bytes([48 + i % 64]) * size
        out.append(rec); n += len(rec); i += 1
    return out

def pump(sock, recs, stall):
    time.sleep(stall)
    h = hashlib.sha256()
    for r in recs:
        sock.sendall(r); h.update(r)
    return h.hexdigest()

def drain(sock, stall, result):
    time.sleep(stall)
    h, n = hashlib.sha256(), 0
    while True:
        b = sock.recv(1 << 16)
        if not b: break
        h.update(b); n += len(b)
    result.append((h.hexdigest(), n))

def run(sock, seed, stall_send, stall_recv, tag, close_first):
    """Half-closes as soon as everything is sent, or only once the other
    side's end has been read, as an answer does."""
    recs = records(seed, 12 << 20)
    got = []
    t = threading.Thread(target=drain, args=(sock, stall_recv, got)); t.start()
    sent = pump(sock, recs, stall_send)
    if not close_first:
        t.join(60)
    sock.shutdown(socket.SHUT_WR)
    t.join(60)
    print("%s sent=%s %d recv=%s %d" % (tag, sent, sum(map(len, recs)),
                                       got[0][0] if got else "-", got[0][1] if got else 0), flush=True)

mode, port = sys.argv[1], int(sys.argv[2])
if mode == "backend":
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port)); ls.listen(1)
    print("ready", flush=True)
    c, _ = ls.accept()
    run(c, 2, 0.2, 1.0, "backend", sys.argv[3] == "first")   # reads late, so the proxy's upstream queues
else:
    c = socket.create_connection(("127.0.0.1", port))
    run(c, 1, 0.0, 1.0, "client", True)     # reads late, so the proxy's downstream queues
PY

exchange(){   # backend's half-close: late | first, and the path
    python3 "$PEER_DIR/peer.py" backend "$BE" "$1" > "$SOCKETLEY_TMPD/be.out" 2>&1 &
    BE_PID=$!
    for _ in $(seq 1 50); do grep -q ready "$SOCKETLEY_TMPD/be.out" 2>/dev/null && break; sleep 0.1; done

    CL=$(timeout 90 python3 "$PEER_DIR/peer.py" client "$PX" 2>&1 || true)
    wait "$BE_PID" 2>/dev/null || true
    BE_PID=""
    BEO=$(grep '^backend' "$SOCKETLEY_TMPD/be.out" || true)
    echo "  $2, backend half-closes $1:"
    echo "    $CL"
    echo "    $BEO"

    c_sent=$(sed -n 's/.*sent=\([0-9a-f]*\) \([0-9]*\).*/\1 \2/p' <<<"$CL")
    c_recv=$(sed -n 's/.*recv=\([0-9a-f-]*\) \([0-9]*\).*/\1 \2/p' <<<"$CL")
    b_sent=$(sed -n 's/.*sent=\([0-9a-f]*\) \([0-9]*\).*/\1 \2/p' <<<"$BEO")
    b_recv=$(sed -n 's/.*recv=\([0-9a-f-]*\) \([0-9]*\).*/\1 \2/p' <<<"$BEO")

    # what the client sent is what the backend read
    if [ -n "$c_sent" ] && [ "$c_sent" = "$b_recv" ]; then pass
    else fail "the upstream stream arrives whole and in order ($2, $1)" "client sent '$c_sent', backend read '$b_recv'"; fi
    # and what the backend sent is what the client read
    if [ -n "$b_sent" ] && [ "$b_sent" = "$c_recv" ]; then pass
    else fail "the downstream stream arrives whole and in order ($2, $1)" "backend sent '$b_sent', client read '$c_recv'"; fi
}

phase(){   # copy | splice | sockmap
    daemon_isolate relayorder
    unset SOCKETLEY_PROXY_SPLICE SOCKETLEY_PROXY_SOCKMAP
    if [ "$1" = splice ]; then export SOCKETLEY_PROXY_SPLICE=1; fi
    if [ "$1" = sockmap ]; then export SOCKETLEY_PROXY_SOCKMAP=1; fi
    daemon_start "$BIN"
    # A --write-buffer above the 12 MiB each side sends, because a peer that
    # reads late piles the whole transfer into the kernel, and the sockmap
    # path drops a pair whose in-kernel backlog passes that bound (it cannot
    # hand a queued backlog to the copy path without losing it).  The copy and
    # splice paths pace losslessly and do not need it, but it is harmless there.
    "$BIN" create proxy relayp -p "$PX" --backend "127.0.0.1:$BE" --protocol tcp \
        --write-buffer 32M -s >/dev/null 2>&1 || true
    for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$PX " && break; sleep 0.1; done

    # The kernel relay needs CAP_BPF/CAP_NET_ADMIN; without them the proxy logs
    # once and stays on the copy path, so this phase is skipped rather than
    # failed on a box that cannot load BPF.
    if [ "$1" = sockmap ]; then
        for _ in $(seq 1 30); do grep -q 'kernel relay is unavailable' "$SOCKETLEY_DLOG" 2>/dev/null && break; sleep 0.1; done
        if grep -q 'kernel relay is unavailable' "$SOCKETLEY_DLOG" 2>/dev/null; then
            echo "  SKIP: kernel relay unavailable (needs CAP_BPF/CAP_NET_ADMIN)"
            daemon_stop
            for _ in $(seq 1 50); do ss -ltn 2>/dev/null | grep -q ":$PX " || break; sleep 0.1; done
            return 0
        fi
    fi

    exchange late "$1"
    exchange first "$1"

    # Both sides have closed, so nothing of either pair may be left open.
    local st=""
    for _ in $(seq 1 30); do
        st=$("$BIN" stats relayp 2>/dev/null | awk -F: '/^(connections|backend_connections):/{printf "%s=%s ", $1, $2+0}')
        [ "$st" = "connections=0 backend_connections=0 " ] && break
        sleep 0.1
    done
    if [ "$st" = "connections=0 backend_connections=0 " ]; then pass
    else fail "both pairs are released once their sides have closed ($1)" "stats: '$st'"; fi

    if [ "$FAIL" -gt 0 ]; then
        grep -v '\[INFO\]' "$SOCKETLEY_DLOG" 2>/dev/null | tail -8 | sed 's/^/        log: /' || true
    fi
    daemon_stop
    for _ in $(seq 1 50); do ss -ltn 2>/dev/null | grep -q ":$PX " || break; sleep 0.1; done
}

# ── 1-5. the copy path: the backend half-closes late, then first ─────────
phase copy
# ── 6-10. the splice path, the same two ───────────────────────────────────
phase splice
# ── 11-15. the kernel relay (sockmap), the same two; skips without CAP_BPF ─
phase sockmap

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
