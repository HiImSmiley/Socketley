#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: --http over TLS hands a connection's send key to the kernel for a large file, and only then.
#
# What each part would catch:
#   * plaintext reaching a TLS socket the kernel does not encrypt yet, or the records OpenSSL encrypted before the key
#     change sent through the kernel once more: a client that cannot read the answer
#   * a connection switched for a small file, which costs it more than the copy encrypted here
#   * the answers after a switch on the same connection -- small, large, a range, a HEAD -- sent the wrong way
#   * a file out of the page cache, whose windows go through the pipe, unencrypted over a switched connection
#   * a key update the client asks for after the switch, which the kernel must take or the connection must end
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: --http over TLS moves a connection's send key to the kernel for a large file ==="
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
[ -r /proc/net/tls_stat ] || { echo "  SKIP: the kernel has no TLS layer here (modprobe tls)"; exit 0; }
daemon_isolate httpktls
P=$((SL_PORT_BASE + 1953))
unset SOCKETLEY_CONFIG
# On a disk, not a tmpfs, so a file's pages can be put out of the page cache.
W=$(mktemp -d /var/tmp/socketley-ktls-XXXXXX)
trap 'daemon_stop; rm -rf "$W"' EXIT
mkdir -p "$W/www" "$W/got"
for f in 1:1 small:16 mid:200 big:2048 huge:8192; do head -c $(( ${f#*:} * 1024 )) /dev/urandom > "$W/www/${f%%:*}.bin"; done
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=127.0.0.1 \
    -keyout "$W/k.pem" -out "$W/c.pem" >/dev/null 2>&1
daemon_start "$BIN"
"$BIN" create server kt -p "$P" --http "$W/www" --tls --cert "$W/c.pem" --key "$W/k.pem" -s >/dev/null 2>&1
for _ in $(seq 1 50); do ss -ltnH "( sport = :$P )" | grep -q . && break; sleep 0.1; done
U="https://127.0.0.1:$P"
tx() { awk '$1=="TlsTxSw" {print $2}' /proc/net/tls_stat; }

# Small files alone: no connection of theirs is moved.
t0=$(tx)
curl -sk -o "$W/got/a" "$U/small.bin" -o "$W/got/b" "$U/mid.bin"
if cmp -s "$W/got/a" "$W/www/small.bin" && cmp -s "$W/got/b" "$W/www/mid.bin" && [ "$(tx)" = "$t0" ]; then ok
else bad "a connection asking for small files only stays in user space" "kernel TLS sockets $t0 -> $(tx)"; fi

# One connection: a large file moves it, and everything after goes the way it now must.
t0=$(tx)
curl -sk -o "$W/got/1" "$U/big.bin" -o "$W/got/2" "$U/small.bin" -o "$W/got/3" "$U/1.bin" -o "$W/got/4" "$U/huge.bin" \
     -o "$W/got/5" "$U/mid.bin"
whole=0
for x in 1:big 2:small 3:1 4:huge 5:mid; do cmp -s "$W/got/${x%%:*}" "$W/www/${x#*:}.bin" && whole=$((whole + 1)); done
if [ "$whole" = 5 ] && [ "$(tx)" = $((t0 + 1)) ]; then ok
else bad "a large file moves its connection, and five answers on it each come back whole" "$whole of 5, kernel TLS sockets $t0 -> $(tx)"; fi

# A range and a HEAD on a moved connection.
curl -sk -o "$W/got/r0" "$U/big.bin" -r 1000000-1999999 -o "$W/got/r" "$U/huge.bin"
cmp -s -i 1000000:0 -n 1000000 "$W/www/huge.bin" "$W/got/r" && [ "$(stat -c %s "$W/got/r")" = 1000000 ] && ok \
    || bad "a range on a moved connection is that range" "$(stat -c %s "$W/got/r" 2>/dev/null) bytes"
len=$(curl -sk -o /dev/null "$U/big.bin" -I -D - "$U/huge.bin" | tr -d '\r' | awk -F': ' 'tolower($1)=="content-length"{v=$2} END{print v}')
if [ "$len" = $((8192 * 1024)) ]; then ok; else bad "a HEAD on a moved connection says the length" "got '$len'"; fi

# Eight at once, and a file out of the page cache, through the pipe arm.
pids=()
for i in $(seq 1 8); do curl -sk -o "$W/got/c$i" "$U/huge.bin" & pids+=($!); done
for p in "${pids[@]}"; do wait "$p"; done
whole=0; for i in $(seq 1 8); do cmp -s "$W/got/c$i" "$W/www/huge.bin" && whole=$((whole + 1)); done
if [ "$whole" = 8 ]; then ok; else bad "eight moved connections at once each carry their file" "$whole of 8"; fi
sync
python3 - "$W/www/huge.bin" <<'PY'
import os, sys
fd = os.open(sys.argv[1], os.O_RDONLY); os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED); os.close(fd)
PY
curl -sk -o "$W/got/cold" "$U/huge.bin"
cmp -s "$W/got/cold" "$W/www/huge.bin" && ok || bad "a file out of the page cache arrives whole over a moved connection" "bytes differ"

# Key updates after the switch, the client's own and one it asks the server for, which the kernel must take or the
# connection must end.  Not -ign_eof, which turns s_client's command letters off.
for cmd in k K; do
    { printf 'GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n'; sleep 1; printf '%s\n' "$cmd"; sleep 1
      printf 'GET /small.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'; sleep 2; } |
        timeout 15 openssl s_client -connect "127.0.0.1:$P" -tls1_3 > "$W/got/ku$cmd" 2>&1
    answers=$(grep -ac '^HTTP/1.1 200' "$W/got/ku$cmd")
    broken=$(grep -acE 'bad record mac|decryption failed|wrong version number|record layer failure' "$W/got/ku$cmd")
    if [ "$broken" = 0 ] && [ "$answers" = 2 ]; then ok
    elif [ "$cmd" = K ] && [ "$broken" = 0 ] && [ "$answers" = 1 ]; then
        echo "  note: this kernel takes no second send key, so the connection ended at the asked-for update"; ok
    else bad "a key update ('$cmd') after the switch is followed by the next answer" \
        "$answers answers, $broken record errors: $(grep -aE 'error|alert' "$W/got/ku$cmd" | head -2 | tr '\n' ' ')"; fi
done

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
