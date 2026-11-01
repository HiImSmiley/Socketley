#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: --http sends every download of a file out of the page cache whole, however many at once.
#
# What it would catch: a window out of the page cache going through a pipe the ring reads, and a download dropped
# when the runtime's pipe budget (64 at the default --write-buffer) is spent, where it can be sent as it is: measured,
# 23 of 150 such downloads at once came back cut short.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: cold downloads past the pipe budget come back whole ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
daemon_isolate httpcold
P=$((SL_PORT_BASE + 1977))
unset SOCKETLEY_CONFIG
# On a disk, not a tmpfs, whose pages could not be put out of the page cache.
W=$(mktemp -d /var/tmp/socketley-cold-XXXXXX)
trap 'daemon_stop; rm -rf "$W"' EXIT
mkdir -p "$W/www" "$W/got"
N=150
for i in $(seq 1 $N); do head -c $((4 << 20)) /dev/urandom > "$W/www/f$i.bin"; done
daemon_start "$BIN"
"$BIN" create server cold -p "$P" --http "$W/www" -s >/dev/null 2>&1
for _ in $(seq 1 50); do ss -ltnH "( sport = :$P )" | grep -q . && break; sleep 0.1; done

# Written back and then dropped, so every one of them is read from the disk.
sync
python3 - "$W/www" "$N" <<'PY'
import os, sys
for i in range(1, int(sys.argv[2]) + 1):
    fd = os.open("%s/f%d.bin" % (sys.argv[1], i), os.O_RDONLY)
    os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
    os.close(fd)
PY
pids=()
for i in $(seq 1 $N); do curl -s -m 60 --limit-rate 4M -o "$W/got/f$i.bin" "http://127.0.0.1:$P/f$i.bin" & pids+=($!); done
for p in "${pids[@]}"; do wait "$p"; done
whole=0
for i in $(seq 1 $N); do cmp -s "$W/www/f$i.bin" "$W/got/f$i.bin" && whole=$((whole + 1)); done
if [ "$whole" = "$N" ]; then ok; else bad "$N cold downloads at once each come back whole" "$whole of $N did"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
