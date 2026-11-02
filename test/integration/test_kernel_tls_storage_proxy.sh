#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: storage and a FastCGI proxy's files over TLS move a connection's send key to the kernel for a
# large answer, and only then, as --http does.
#
# What each part would catch:
#   * plaintext reaching a TLS socket the kernel does not encrypt yet, or OpenSSL's own records sent through the
#     kernel once more: answers a client cannot read
#   * a connection moved for a small answer, or an HTTP/2 one moved at all, whose frames sendfile cannot carry
#   * the answers after the move on the same connection, a range, and many at once, sent the wrong way
#   * an object or file out of the page cache, read through the ring, unencrypted over a moved connection
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: storage and a FastCGI proxy move a TLS connection's send key to the kernel for a large answer ==="
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
[ -r /proc/net/tls_stat ] || { echo "  SKIP: the kernel has no TLS layer here (modprobe tls)"; exit 0; }
daemon_isolate ktlssp
P=$((SL_PORT_BASE + 1954)); PF=$((SL_PORT_BASE + 1955))
unset SOCKETLEY_CONFIG
# On a disk, not a tmpfs, so pages can be put out of the page cache.
W=$(mktemp -d /var/tmp/socketley-ktlssp-XXXXXX)
trap 'daemon_stop; rm -rf "$W"' EXIT
mkdir -p "$W/www" "$W/got"
for f in small:16 big:2048 huge:8192; do head -c $(( ${f#*:} * 1024 )) /dev/urandom > "$W/www/${f%%:*}.bin"; done
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=127.0.0.1 \
    -keyout "$W/k.pem" -out "$W/c.pem" >/dev/null 2>&1
daemon_start "$BIN"
"$BIN" create storage objs -p "$P" --dir "$W/st" --anonymous --tls --cert "$W/c.pem" --key "$W/k.pem" -s >/dev/null 2>&1
"$BIN" create proxy fc -p "$PF" --domain fc.test --backend "fastcgi://unix:$W/none.sock" --root "$W/www" \
    --tls --cert "$W/c.pem" --key "$W/k.pem" -s >/dev/null 2>&1
for port in "$P" "$PF"; do for _ in $(seq 1 50); do curl -sk -o /dev/null "https://127.0.0.1:$port/" && break; sleep 0.1; done; done
curl -sk -X PUT "https://127.0.0.1:$P/bkt" >/dev/null
for f in small big huge; do curl -sk -T "$W/www/$f.bin" "https://127.0.0.1:$P/bkt/$f.bin" >/dev/null; done
tx() { awk '$1=="TlsTxSw" {print $2}' /proc/net/tls_stat; }
cold() {
    sync
    python3 - "$@" <<'PY'
import os, sys
for root in sys.argv[1:]:
    for d, _, names in os.walk(root):
        for n in names:
            fd = os.open(os.path.join(d, n), os.O_RDONLY); os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED); os.close(fd)
PY
}

for side in storage proxy; do
    if [ $side = storage ]; then U="https://127.0.0.1:$P/bkt"; else U="https://127.0.0.1:$PF"; fi

    t0=$(tx)
    curl -sk --http1.1 -o "$W/got/s" "$U/small.bin"
    if cmp -s "$W/got/s" "$W/www/small.bin" && [ "$(tx)" = "$t0" ]; then ok
    else bad "$side: a connection with a small answer only stays in user space" "kernel TLS sockets $t0 -> $(tx)"; fi

    t0=$(tx)
    curl -sk --http1.1 -o "$W/got/1" "$U/big.bin" -o "$W/got/2" "$U/small.bin" -o "$W/got/3" "$U/huge.bin" -o "$W/got/4" "$U/small.bin"
    whole=0
    for x in 1:big 2:small 3:huge 4:small; do cmp -s "$W/got/${x%%:*}" "$W/www/${x#*:}.bin" && whole=$((whole + 1)); done
    if [ "$whole" = 4 ] && [ "$(tx)" = $((t0 + 1)) ]; then ok
    else bad "$side: a large answer moves its connection, and four answers on it each come back whole" \
        "$whole of 4, kernel TLS sockets $t0 -> $(tx)"; fi

    curl -sk --http1.1 -r 1000000-2999999 -o "$W/got/r" "$U/huge.bin"
    if [ "$(stat -c %s "$W/got/r")" = 2000000 ] && cmp -s -i 1000000:0 -n 2000000 "$W/www/huge.bin" "$W/got/r"; then ok
    else bad "$side: a range over a moved connection is that range" "$(stat -c %s "$W/got/r" 2>/dev/null) bytes"; fi

    pids=()
    for i in $(seq 1 8); do curl -sk --http1.1 -o "$W/got/c$i" "$U/huge.bin" & pids+=($!); done
    for p in "${pids[@]}"; do wait "$p"; done
    whole=0; for i in $(seq 1 8); do cmp -s "$W/got/c$i" "$W/www/huge.bin" && whole=$((whole + 1)); done
    if [ "$whole" = 8 ]; then ok; else bad "$side: eight moved connections at once each carry their answer" "$whole of 8"; fi

    cold "$W/st" "$W/www"
    curl -sk --http1.1 -o "$W/got/cold" "$U/huge.bin"
    cmp -s "$W/got/cold" "$W/www/huge.bin" && ok || bad "$side: an answer out of the page cache arrives whole when moved" "bytes differ"
done

# HTTP/2 frames what it sends, so a storage connection that speaks it is never moved, and still answers whole.
t0=$(tx)
v=$(curl -sk --http2 -o "$W/got/h2" -w '%{http_version}' "https://127.0.0.1:$P/bkt/huge.bin")
if [ "$v" = 2 ] && cmp -s "$W/got/h2" "$W/www/huge.bin" && [ "$(tx)" = "$t0" ]; then ok
elif [ "$v" != 2 ]; then echo "  note: storage offered no HTTP/2 here (version '$v'), so its row says nothing"; ok
else bad "storage: an HTTP/2 connection is never moved, and answers whole" "kernel TLS sockets $t0 -> $(tx)"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
