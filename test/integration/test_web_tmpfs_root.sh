#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a web runtime whose --root is on tmpfs keeps its small files in memory, as on a disk.
#
# What it would catch:
#   * tmpfs answering preadv2(RWF_NOWAIT) with EOPNOTSUPP taken for "not in the page cache": every answer then went
#     by sendfile from a descriptor, about three times the CPU of one sent from memory (stats: from_memory 0)
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a web runtime on a tmpfs root sends its small files from memory ==="
if [ "$(findmnt -no FSTYPE --target /dev/shm 2>/dev/null)" != tmpfs ] || [ ! -w /dev/shm ]; then
    echo "  SKIP: /dev/shm is not a writable tmpfs here"; echo "  Results: 0/0 passed (0 failed)"; exit 0
fi
daemon_isolate webtmpfs
P=$((SL_PORT_BASE + 1975))
unset SOCKETLEY_CONFIG
R=$(mktemp -d /dev/shm/skl-webtmpfs.XXXXXX)
trap 'daemon_stop; rm -rf "$R"' EXIT
daemon_start "$BIN"

head -c 4096 /dev/zero | tr '\0' a > "$R/page.txt"
printf '<html><body>home</body></html>\n' > "$R/index.html"
"$BIN" create web site -p "$P" --root "$R" -s >/dev/null 2>&1 || bad "create" "the web runtime was not made"
ready_tcp 127.0.0.1 "$P" 15 || bad "listen" "port $P"

# Twenty answers on one connection, each of the 4096 bytes written.
n=$(curl -s $(for i in $(seq 1 20); do printf 'http://127.0.0.1:%s/page.txt ' "$P"; done) | wc -c)
[ "$n" = $((20 * 4096)) ] && ok || bad "the file is served" "$n bytes for 20 answers of 4096"

# The worker reports its figures on an interval, so they are read until they have caught up with the answers.
mem=0; zc=0
for _ in $(seq 1 40); do
    s=$("$BIN" stats site 2>/dev/null)
    mem=$(awk -F: '$1 == "from_memory" {print $2}' <<<"$s"); zc=$(awk -F: '$1 == "zero_copy" {print $2}' <<<"$s")
    [ $(( ${mem:-0} + ${zc:-0} )) -ge 20 ] && break
    sleep 0.25
done
[ "${mem:-0}" -ge 19 ] && ok || bad "a 4 KiB file on tmpfs is sent from memory" "from_memory ${mem:-?}, zero_copy ${zc:-?}"

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
