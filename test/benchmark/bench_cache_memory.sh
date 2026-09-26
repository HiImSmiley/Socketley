#!/usr/bin/env bash
# Memory per key, for each shape a cache holds, against Redis.
#
# The README's memory table was measured by hand, and one of its rows read
# 1,047 bytes for a fifty-element list while the tree it described held 665.
# A number nobody can reproduce goes stale without anyone noticing, so this is
# the method written down: a million keys of one shape over RESP, and the worker's
# resident memory before and after, with huge pages off so a page the kernel
# rounds up is not counted as ours.  Redis is measured the way it reports
# itself, `used_memory` across the same load -- what its allocator hands out,
# which is the smaller of the two ways to count and so the fair side to give it.
#
# Each shape gets a fresh cache, because a worker's RSS never gives back what
# the previous shape freed.
#
# Usage: bench_cache_memory.sh      (BENCH_MEM_KEYS=1000000)

set -uo pipefail
source "$(dirname "$0")/utils.sh"

KEYS=${BENCH_MEM_KEYS:-1000000}
B=${BENCH_MEM_PORT_BASE:-29800}
P_CACHE=$((B + 0))
P_REDIS=$((B + 1))

# name|what one key is, as the generator below spells it
SHAPES='
string, 16-byte key, 3-byte value|string|1
hash, 5 fields of 6 bytes|hash|5
set, 5 members|set|5
sorted set, 5 members|zset|5
list, 1 element|list|1
list, 5 elements|list|5
list, 50 elements|list|50
'

WORK=$(mktemp -d /tmp/cmem.XXXXXX)
REDIS_PID=""
cleanup() {
    local p
    for p in $(pgrep -x socketley 2>/dev/null); do
        grep -qz "SOCKETLEY_SOCKET=$WORK/d.sock" "/proc/$p/environ" 2>/dev/null && kill -9 "$p" 2>/dev/null
    done
    [ -n "$REDIS_PID" ] && kill -9 "$REDIS_PID" 2>/dev/null
    rm -rf "$WORK"
    return 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM   # see setup_cleanup_trap in utils.sh

check_binary || exit 1
command -v redis-cli >/dev/null 2>&1 || { log_error "redis-cli is needed to send the load"; exit 1; }
for p in "$P_CACHE" "$P_REDIS"; do
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$p\$" && { log_error "refusing: port $p is already listening"; exit 2; }
done

log_section "Memory per key: $KEYS keys of each shape, against Redis"

# One key's commands, RESP-framed, for `redis-cli --pipe`.
load() {   # kind count -> RESP on stdout
    awk -v k="$KEYS" -v f="$2" -v kind="$1" '
      function b(s) { return "$" length(s) "\r\n" s "\r\n" }
      BEGIN {
        for (i = 0; i < k; i++) {
          if (kind == "string") { printf "*3\r\n%s%s%s", b("SET"), b(sprintf("key:%012d", i)), b("xxx"); continue }
          for (j = 0; j < f; j++) {
            if (kind == "hash")      printf "*4\r\n%s%s%s%s", b("HSET"), b("user:" i), b("field" j), b("value" j)
            else if (kind == "set")  printf "*3\r\n%s%s%s", b("SADD"), b("set:" i), b("member" j)
            else if (kind == "zset") printf "*4\r\n%s%s%s%s", b("ZADD"), b("z:" i), b(j), b("member" j)
            else                     printf "*3\r\n%s%s%s", b("RPUSH"), b("l:" i), b("item" j)
          }
        }
      }'
}

export HOME=$WORK/home SOCKETLEY_SOCKET=$WORK/d.sock SOCKETLEY_HUGEPAGE=0
unset SOCKETLEY_CONFIG
mkdir -p "$HOME"
"$SOCKETLEY_BIN" daemon >"$WORK/daemon.log" 2>&1 &
for _ in $(seq 1 100); do [ -S "$SOCKETLEY_SOCKET" ] && break; sleep 0.1; done
[ -S "$SOCKETLEY_SOCKET" ] || { log_error "the private daemon did not come up"; exit 1; }

HAVE_REDIS=0
if command -v redis-server >/dev/null 2>&1; then
    redis-server --port "$P_REDIS" --save "" --appendonly no --dir "$WORK" \
        --logfile "$WORK/redis.log" >/dev/null 2>&1 &
    REDIS_PID=$!
    wait_for_port "$P_REDIS" && HAVE_REDIS=1
fi
[ "$HAVE_REDIS" = 1 ] || log_warn "no redis-server: the Redis column is left empty"

rss_kb() { awk '/^VmRSS/{print $2}' "/proc/$1/status" 2>/dev/null; }

printf '\n  %-32s %12s %12s %8s\n' shape socketley redis ratio
printf '  %s\n' "$(printf '%.0s─' {1..68})"
while IFS='|' read -r name kind n; do
    [ -n "$name" ] || continue

    "$SOCKETLEY_BIN" create cache cmem -p "$P_CACHE" -s >/dev/null 2>&1
    wait_for_port "$P_CACHE" || { log_error "$name: the cache never bound"; continue; }
    w=$(ss -ltnp "sport = :$P_CACHE" 2>/dev/null | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
    r0=$(rss_kb "$w")
    load "$kind" "$n" | redis-cli -p "$P_CACHE" --pipe >/dev/null 2>&1
    got=$(redis-cli -p "$P_CACHE" dbsize 2>/dev/null)
    r1=$(rss_kb "$w")
    "$SOCKETLEY_BIN" stop cmem >/dev/null 2>&1
    "$SOCKETLEY_BIN" remove cmem >/dev/null 2>&1
    wait_for_port_free "$P_CACHE" >/dev/null 2>&1
    ours="-"
    [ "${got:-0}" = "$KEYS" ] && ours=$(( (r1 - r0) * 1024 / KEYS ))

    theirs="-"
    if [ "$HAVE_REDIS" = 1 ]; then
        redis-cli -p "$P_REDIS" flushall >/dev/null 2>&1
        m0=$(redis-cli -p "$P_REDIS" info memory | awk -F: '/^used_memory:/{print $2+0}')
        load "$kind" "$n" | redis-cli -p "$P_REDIS" --pipe >/dev/null 2>&1
        m1=$(redis-cli -p "$P_REDIS" info memory | awk -F: '/^used_memory:/{print $2+0}')
        [ "$(redis-cli -p "$P_REDIS" dbsize)" = "$KEYS" ] && theirs=$(( (m1 - m0) / KEYS ))
    fi

    ratio="-"
    [ "$ours" != "-" ] && [ "$theirs" != "-" ] && ratio=$(awk -v a="$ours" -v b="$theirs" 'BEGIN{printf "%.1fx", a/b}')
    # A load that did not arrive whole measured something else, and says so.
    [ "$ours" = "-" ] && log_warn "$name: $got of $KEYS keys arrived, not measured"
    printf '  %-32s %10s B %10s B %8s\n' "$name" "$ours" "$theirs" "$ratio"
done <<< "$SHAPES"
echo ""
log_info "socketley: worker RSS over the load, huge pages off; Redis: used_memory"
