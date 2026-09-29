#!/usr/bin/env bash
# Integration test: a storage runtime under `daemon --fast-lo`.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
# With the loopback shortcut a send on a 127.0.0.1 pair is placed in the peer's
# receive queue without passing through TCP, and a socket read with splice(2)
# reads the TCP queue only -- which is why the proxy keeps a pair with a leg on
# the shortcut on its copy path.  The storage runtime reads every body with a
# receive and only splices in the other direction, file to pipe to socket, so
# nothing it does reads a socket with splice; this file holds that down by
# moving 40 MiB in and out of a runtime, directly and through a proxy, in the
# modes that put a local client on the shortcut, and reading it back byte for
# byte with the shortcut counting sockets it took.
#
# Needs CAP_BPF and CAP_NET_ADMIN, given to a copy of the binary with
# `sudo -n setcap`; without sudo, or where the shortcut does not attach, it is
# skipped.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgflo
WORK=$(mktemp -d /tmp/socketley-stgflo-work-XXXXXX)
daemon_watch "$WORK"

P=$((SL_PORT_BASE+1670))
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

CAPBIN="$WORK/socketley-fastlo"
cleanup() {
    for r in sf_stg sf_px; do "$CAPBIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    daemon_stop
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "=== Integration: storage under daemon --fast-lo ==="
skip() { echo "  SKIP: $1"; echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; exit 0; }
command -v curl >/dev/null 2>&1 || skip "curl is not available"
cp "$BIN" "$CAPBIN"
sudo -n setcap cap_bpf,cap_net_admin+ep "$CAPBIN" 2>/dev/null || skip "no sudo -n setcap for CAP_BPF/CAP_NET_ADMIN"

head -c 41943040 /dev/urandom > "$WORK/big"
want=$(md5sum < "$WORK/big" | cut -d' ' -f1)
want_r=$(tail -c +1000001 "$WORK/big" | head -c 30000000 | md5sum | cut -d' ' -f1)

run_mode() {   # mode
    local mode=$1
    : > "$SOCKETLEY_DLOG"
    daemon_start "$CAPBIN" --fast-lo "$mode"
    if grep -q 'fast-lo: unavailable' "$SOCKETLEY_DLOG"; then
        skip "the shortcut did not attach here: $(grep 'fast-lo' "$SOCKETLEY_DLOG" | head -1)"
    fi
    "$CAPBIN" create storage sf_stg -p "$P" --dir "$WORK/objects-$mode" --anonymous -s >/dev/null 2>&1 || bad "$mode: create" "sf_stg"
    "$CAPBIN" create proxy sf_px -p $((P+1)) --protocol tcp --backend sf_stg -s >/dev/null 2>&1 || bad "$mode: create" "sf_px"
    for _ in $(seq 1 100); do
        [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/")" = 200 ] && \
        [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((P+1))/")" = 200 ] && break
        sleep 0.1
    done
    curl -s -X PUT "http://127.0.0.1:$P/flobkt" -o /dev/null
    local base
    for base in "direct:http://127.0.0.1:$P" "proxy:http://127.0.0.1:$((P+1))"; do
        local how=${base%%:*} url=${base#*:}
        expect "$mode $how: a 40 MiB put is 200" \
            "$(curl -s -m 60 -o /dev/null -w '%{http_code}' -X PUT --data-binary @"$WORK/big" "$url/flobkt/$how")" 200
        expect "$mode $how: it comes back byte for byte" \
            "$(curl -s -m 60 "$url/flobkt/$how" | md5sum | cut -d' ' -f1)" "$want"
        expect "$mode $how: a 30 MB Range read is exact" \
            "$(curl -s -m 60 -H 'Range: bytes=1000000-30999999' "$url/flobkt/$how" | md5sum | cut -d' ' -f1)" "$want_r"
    done
    local entered zc
    entered=$("$CAPBIN" daemon stats 2>&1 | sed -n 's/^fast_lo_entered://p')
    if [ "${entered:-0}" -gt 0 ]; then ok "$mode: the shortcut took sockets ($entered)"; else bad "$mode: the shortcut was engaged" "fast_lo_entered=$entered"; fi
    for _ in $(seq 1 50); do
        zc=$("$CAPBIN" stats sf_stg 2>/dev/null | sed -n 's/^zero_copy_bytes://p')
        [ "${zc:-0}" -ge 143886080 ] && break
        sleep 0.1
    done
    if [ "${zc:-0}" -ge 143886080 ]; then ok "$mode: every download went by splice ($zc bytes)"; else bad "$mode: downloads by splice" "zero_copy_bytes=$zc"; fi
    "$CAPBIN" stop sf_stg >/dev/null 2>&1; "$CAPBIN" stop sf_px >/dev/null 2>&1
    sleep 0.3
    "$CAPBIN" remove sf_stg >/dev/null 2>&1; "$CAPBIN" remove sf_px >/dev/null 2>&1
    kill "$SOCKETLEY_DPID" 2>/dev/null
    for _ in $(seq 1 50); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
    daemon_sweep "${SOCKETLEY_SOCKET:-}"
}

run_mode all
run_mode trust

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
