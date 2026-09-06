#!/bin/bash
# Every RESP command we accept, against Redis, in one table.
#
# bench_cache_resp.sh compares six commands: SET, GET, LPUSH, LPOP, SADD, HSET.
# The cache accepts fifty-six that Redis also has, and the fifty it does not
# measure are exactly where a defect can sit for a year without anybody
# noticing -- pub/sub sat there and was worth 3x when somebody finally looked.
#
# So this is not a ranking and not a contest.  It is an outlier detector: run
# every command against both, print the ratio, and flag what falls outside the
# band.  A command where we are level is uninteresting; a command where we are
# a third of Redis is a morning's work with a known payoff.
#
# ─── WHAT MAKES A CELL MEAN ANYTHING ────────────────────────────────────────
#
# Two things, and both are ways this has already gone wrong elsewhere in this
# directory.
#
# State.  redis-benchmark sends one command over and over, so GET against a
# key that does not exist measures the miss path and LRANGE against a list of
# unknown length measures nothing repeatable.  Both arms are therefore loaded
# with the same key space, written in the same format redis-benchmark's
# __rand_int__ produces -- twelve digits, zero padded, verified rather than
# assumed -- and every size that an O(N) command depends on is printed beside
# the number.
#
# The client.  One redis-benchmark process saturates a core near 200k ops/s on
# this box, and a cell measured there reports the client and not the cache.
# Client cores are sampled per cell and a cell whose clients sat at their
# ceiling is printed as unusable rather than as a ratio.
#
# ─── THE TWO ARMS ───────────────────────────────────────────────────────────
#
# Unsharded: one socketley cache against one redis-server.
#
# Sharded: four socketley shards against a four-master Redis Cluster -- which
# compares two architectures rather than two protocols, and says so.  Our
# shards are four processes behind ONE port that the kernel picks between;
# a Redis cluster is four processes on four ports that the client routes
# between by slot.  socketley therefore takes a plain redis-benchmark and
# Redis takes --cluster.  The common denominator is four cores of cache on
# each side, which is the comparison worth having.

source "$(dirname "$0")/utils.sh"
source "$(dirname "$0")/lib_paired.sh"

MODE=${BENCH_MATRIX_MODE:-unsharded}     # unsharded | sharded
PASSES=${BENCH_MATRIX_PASSES:-3}
OPS=${BENCH_MATRIX_OPS:-100000}
CLIENTS=${BENCH_MATRIX_CLIENTS:-50}
PIPE=${BENCH_MATRIX_PIPE:-16}
PROCS=${BENCH_MATRIX_PROCS:-4}           # client processes per cell
SKL_PORT=19811
REDIS_PORT=7301
CLUSTER_PORTS="7311 7312 7313 7314"

# The key space, printed with every table because an O(N) command has no
# meaning without it.
K_STR=1000       # str:%012d and num:%012d
K_COLL=100       # hash:/list:/set:/zset:%012d
N_FIELD=10       # fields per hash
N_ELEM=100       # elements per list, set and zset
V_SIZE=100       # bytes per string value

# name|keyspace|command template
#
# ─── WHAT IS AND IS NOT IN HERE ─────────────────────────────────────────────
#
# Every command takes a FIXED member, field or index argument -- `m42`, `f3`,
# `0 9` -- and not a random one.  That is what keeps the structure it reads the
# same size on the last operation as on the first: SADD of a member already
# present adds nothing, HSET of a field already there overwrites, and both stay
# comparable across four hundred thousand repetitions.  A random member would
# grow the set under the measurement and quietly change what the next command
# in the table is reading.
#
# Some commands cannot be made idempotent that way and are deliberately absent:
# LPOP, RPOP, DEL, HDEL, SREM, ZREM -- and now SPOP, ZPOPMIN, ZPOPMAX, LREM,
# LINSERT, GETDEL, UNLINK and the ZREMRANGE pair -- consume what they measure,
# so after the structure is drained they time the empty path instead.  They
# need their own key family reloaded between passes, which is a separate piece
# of work; a number for them here would be a number for an empty list.
#
# EXISTS appears twice on purpose.  The one-key row is what the table always
# had; EXISTS3 is the arity that was answering 1 for any number of keys, and a
# row that only ever passes one key is a row that could not have caught it.
#
# EXPIRE and its family get their own `ttl:` keys rather than sharing `str:`,
# because a TTL set on a string is a string that disappears mid-table.
CMDS_DEFAULT='
GET|1000|GET KEYTAGstr:__rand_int__
MGET|1000|MGET KEYTAGstr:__rand_int__ KEYTAGstr:__rand_int__ KEYTAGstr:__rand_int__
SET|1000|SET KEYTAGstr:__rand_int__ xxxxxxxxxxxxxxxxxxxx
SETNX|1000|SETNX KEYTAGstr:__rand_int__ v
SETEX|1000|SETEX KEYTAGvolatile:__rand_int__ 10000 v
PSETEX|1000|PSETEX KEYTAGvolatile:__rand_int__ 10000000 v
GETSET|1000|GETSET KEYTAGstr:__rand_int__ yyyyyyyyyyyyyyyyyyyy
MSET|1000|MSET KEYTAGstr:__rand_int__ a KEYTAGstr:__rand_int__ b
STRLEN|1000|STRLEN KEYTAGstr:__rand_int__
GETRANGE|1000|GETRANGE KEYTAGstr:__rand_int__ 0 9
SETRANGE|1000|SETRANGE KEYTAGstr:__rand_int__ 0 zzzz
INCR|1000|INCR KEYTAGnum:__rand_int__
DECR|1000|DECR KEYTAGnum:__rand_int__
INCRBY|1000|INCRBY KEYTAGnum:__rand_int__ 3
DECRBY|1000|DECRBY KEYTAGnum:__rand_int__ 3
INCRBYFLOAT|1000|INCRBYFLOAT KEYTAGnum:__rand_int__ 0
EXISTS|1000|EXISTS KEYTAGstr:__rand_int__
EXISTS3|1000|EXISTS KEYTAGstr:__rand_int__ KEYTAGstr:__rand_int__ KEYTAGstr:__rand_int__
TOUCH|1000|TOUCH KEYTAGstr:__rand_int__
TYPE|1000|TYPE KEYTAGstr:__rand_int__
EXPIRE|1000|EXPIRE KEYTAGttl:__rand_int__ 10000
PEXPIRE|1000|PEXPIRE KEYTAGttl:__rand_int__ 10000000
EXPIREAT|1000|EXPIREAT KEYTAGttl:__rand_int__ 4102444800
PEXPIREAT|1000|PEXPIREAT KEYTAGttl:__rand_int__ 4102444800000
TTL|1000|TTL KEYTAGttl:__rand_int__
PTTL|1000|PTTL KEYTAGttl:__rand_int__
PERSIST|1000|PERSIST KEYTAGttl:__rand_int__
HSET|100|HSET KEYTAGhash:__rand_int__ f3 v
HGET|100|HGET KEYTAGhash:__rand_int__ f3
HGETALL|100|HGETALL KEYTAGhash:__rand_int__
HLEN|100|HLEN KEYTAGhash:__rand_int__
HEXISTS|100|HEXISTS KEYTAGhash:__rand_int__ f3
HSTRLEN|100|HSTRLEN KEYTAGhash:__rand_int__ f3
HKEYS|100|HKEYS KEYTAGhash:__rand_int__
HVALS|100|HVALS KEYTAGhash:__rand_int__
HMGET|100|HMGET KEYTAGhash:__rand_int__ f1 f3 f5
HMSET|100|HMSET KEYTAGhash:__rand_int__ f3 v f4 v
HSETNX|100|HSETNX KEYTAGhash:__rand_int__ f3 v
HINCRBY|100|HINCRBY KEYTAGhash:__rand_int__ ctr 1
LPUSH|100|LPUSH pushKEYTAGlist:__rand_int__ e
RPUSH|100|RPUSH pushKEYTAGlist:__rand_int__ e
LLEN|100|LLEN KEYTAGlist:__rand_int__
LINDEX|100|LINDEX KEYTAGlist:__rand_int__ 42
LRANGE|100|LRANGE KEYTAGlist:__rand_int__ 0 9
LSET|100|LSET KEYTAGlist:__rand_int__ 0 zz
LTRIM|100|LTRIM KEYTAGlist:__rand_int__ 0 -1
SADD|100|SADD KEYTAGset:__rand_int__ m42
SCARD|100|SCARD KEYTAGset:__rand_int__
SISMEMBER|100|SISMEMBER KEYTAGset:__rand_int__ m42
SMEMBERS|100|SMEMBERS KEYTAGset:__rand_int__
SMISMEMBER|100|SMISMEMBER KEYTAGset:__rand_int__ m42 m43 nope
SRANDMEMBER|100|SRANDMEMBER KEYTAGset:__rand_int__
ZADD|100|ZADD zKEYTAGset:__rand_int__ 42 m42
ZCARD|100|ZCARD zKEYTAGset:__rand_int__
ZSCORE|100|ZSCORE zKEYTAGset:__rand_int__ m42
ZINCRBY|100|ZINCRBY zKEYTAGset:__rand_int__ 1 m42
ZRANK|100|ZRANK zKEYTAGset:__rand_int__ m42
ZREVRANK|100|ZREVRANK zKEYTAGset:__rand_int__ m42
ZRANGE|100|ZRANGE zKEYTAGset:__rand_int__ 0 9
ZREVRANGE|100|ZREVRANGE zKEYTAGset:__rand_int__ 0 9
ZRANGEBYSCORE|100|ZRANGEBYSCORE zKEYTAGset:__rand_int__ 0 9
ZREVRANGEBYSCORE|100|ZREVRANGEBYSCORE zKEYTAGset:__rand_int__ 9 0
ZCOUNT|100|ZCOUNT zKEYTAGset:__rand_int__ 0 9
PUBLISH|1000|PUBLISH KEYTAGchan:__rand_int__ hello
PING|1|PING
DBSIZE|1|DBSIZE
'
CMDS=${BENCH_MATRIX_CMDS:-$CMDS_DEFAULT}

TMPD=$(mktemp -d)
SKL_HOME=$(mktemp -d)
cleanup_all_arms() {
    for p in $(pgrep -x socketley 2>/dev/null || true); do
        grep -qz "SOCKETLEY_SOCKET=$SKL_HOME/d.sock" "/proc/$p/environ" 2>/dev/null && kill -9 "$p"
    done
    redis-cli -p "$REDIS_PORT" shutdown nosave >/dev/null 2>&1
    for p in $CLUSTER_PORTS; do redis-cli -p "$p" shutdown nosave >/dev/null 2>&1; done
    rm -rf "$TMPD" "$SKL_HOME"
}
trap cleanup_all_arms EXIT

# ─── Loading both arms with the same keys ───────────────────────────────────
#
# Twelve digits, zero padded, because that is what __rand_int__ substitutes --
# checked against a real redis-benchmark run rather than taken from the manual.
# A key written any other way makes every read in the table a miss, which is
# fast, repeatable, and completely wrong.
emit_load() {   # emit_load [TAG] > file
    # RESP arrays and not inline commands, which is not a style choice.
    #
    # `SET k v\r\n` is a legal RESP inline command AND a legal socketley text
    # command, and from the line alone the two are indistinguishable.  Redis
    # answers an inline command in RESP (`+OK\r\n`); socketley answers it in
    # its own dialect (`ok\n`).  redis-cli --pipe sends inline commands, cannot
    # parse `ok\n`, and gives up part way through -- which reads as the server
    # losing writes and is not: fed the same file through nc, the cache stores
    # all fifty thousand.  Sending arrays sidesteps the ambiguity entirely,
    # because an array is RESP and nothing else.
    #
    # awk and not a bash loop: this emits half a million commands and the loop
    # form spent longer generating the file than the benchmark spent using it.
    local T=""
    [ -n "${1:-}" ] && T="{$1}"
    awk -v T="$T" -v KS="$K_STR" -v KC="$K_COLL" -v NFI="$N_FIELD" \
        -v NE="$N_ELEM" -v VS="$V_SIZE" '
        function arg(s) { printf "$%d\r\n%s\r\n", length(s), s }
        BEGIN {
            val = ""; for (i = 0; i < VS; i++) val = val "x"
            for (i = 0; i < KS; i++) {
                printf "*3\r\n"; arg("SET"); arg(sprintf("%sstr:%012d", T, i));  arg(val)
                printf "*3\r\n"; arg("SET"); arg(sprintf("%snum:%012d", T, i));  arg("0")
                printf "*3\r\n"; arg("SET"); arg(sprintf("%sttl:%012d", T, i));  arg("v")
            }
            for (i = 0; i < KC; i++) {
                # Its own family, because LPUSH grows what it writes to and
                # LLEN, LINDEX and LRANGE must keep reading a known length.
                printf "*3\r\n"; arg("RPUSH"); arg(sprintf("%spushlist:%012d", T, i)); arg("seed")
                hk = sprintf("%shash:%012d", T, i)
                for (j = 0; j < NFI; j++) { printf "*4\r\n"; arg("HSET"); arg(hk); arg("f" j); arg("v" j) }
                printf "*4\r\n"; arg("HSET"); arg(hk); arg("ctr"); arg("0")
                lk = sprintf("%slist:%012d", T, i)
                sk = sprintf("%sset:%012d",  T, i)
                zk = sprintf("%szset:%012d", T, i)
                for (j = 0; j < NE; j++) {
                    printf "*3\r\n"; arg("RPUSH"); arg(lk); arg("e" j)
                    printf "*3\r\n"; arg("SADD");  arg(sk); arg("m" j)
                    printf "*4\r\n"; arg("ZADD");  arg(zk); arg(j); arg("m" j)
                }
            }
        }'
}

# --pipe always, and never plain `redis-cli < file`.
#
# --pipe sends the file as raw bytes, which is what a file of RESP arrays is.
# Plain redis-cli reads stdin as command LINES and silently stores nothing from
# a protocol file: the cluster came up with zero keys while socketley held
# fourteen thousand, every Redis read was a miss, misses are fast, and the
# table said we were half Redis' speed across forty-seven commands.  The key
# count control caught it; nothing else would have.
#
# No redirects arise because each file holds one tag's keys and goes to the one
# master that owns that tag's slot.
load_arm() {    # load_arm PORT FILE
    redis-cli -p "$1" --pipe < "$2" >/dev/null 2>&1
}

# ─── One cell ───────────────────────────────────────────────────────────────
#
# Echoes: ops_per_sec client_cores
#
# PROCS processes rather than one, because a single redis-benchmark caps near
# one core and a cell measured at its ceiling reports the client.  Their rates
# sum; their CPU sums too, and the sum is what decides whether the cell is
# readable.
run_cell() {    # run_cell TOPO KEYSPACE COMMAND...
    #
    # TOPO is either a single port ("19811") or a list of node:tag pairs
    # ("7311:b 7312:c ..."), which is what both arms look like once each side
    # advertises its nodes.  One client process per node, each with the tag
    # whose slot that node owns, so no request is ever redirected.
    local topo=$1 range=$2; shift 2
    local tmpl=("$@")
    # A floor on the per-process count, because a short run reports the clock:
    # 2000 operations came back as 1,999,999 requests per second, which is one
    # tick of resolution wearing a rate's clothes.
    local per=$(( OPS / PROCS )); [ "$per" -lt 50000 ] && per=50000
    local pids=() outs=() i
    local t0 t1 cpu=0
    t0=$(date +%s%N)
    local nodes=($topo) j
    for ((i = 0; i < PROCS; i++)); do
        outs+=("$TMPD/c$i.out")
        local ent=${nodes[$(( i % ${#nodes[@]} ))]}
        local p_i=${ent%%:*} tag=""
        [ "$ent" != "$p_i" ] && tag=${ent##*:}
        local args=()
        if [ -n "$tag" ]; then
            for j in "${tmpl[@]}"; do args+=("${j//KEYTAG/\{$tag\}}"); done
        else
            for j in "${tmpl[@]}"; do args+=("${j//KEYTAG/}"); done
        fi
        # /usr/bin/time and not a /proc sampler.  A cell against socketley is
        # tens of milliseconds -- 100k operations at three million a second --
        # so a sampler on any interval reads zero for the fast arm and the
        # client-bound check can never fire where it matters most.  Measured:
        # redis showed 0.2 cores and socketley 0 in the same table, which was
        # the instrument and not the client.
        /usr/bin/time -f '%U %S' -o "$TMPD/t$i" \
            redis-benchmark -h 127.0.0.1 -p "$p_i" -n "$per" -c "$CLIENTS" \
                -P "$PIPE" -r "$range" -q "${args[@]}" > "$TMPD/c$i.out" 2>/dev/null &
        pids+=($!)
    done
    for p in "${pids[@]}"; do wait "$p" 2>/dev/null; done
    t1=$(date +%s%N)

    for ((i = 0; i < PROCS; i++)); do
        cpu=$(awk -v a="$cpu" '{print a + $1 + $2}' "$TMPD/t$i" 2>/dev/null || echo "$cpu")
    done

    # redis-benchmark -q prints "CMD: 12345.67 requests per second", and the
    # rates of concurrent processes add.
    local total=0 v
    for f in "${outs[@]}"; do
        v=$(grep -oE '[0-9]+\.[0-9]+ requests per second' "$f" 2>/dev/null | head -1 | cut -d' ' -f1)
        [ -n "$v" ] && total=$(awk -v a="$total" -v b="$v" 'BEGIN{printf "%.0f", a + b}')
    done
    awk -v r="$total" -v c="$cpu" -v ns=$((t1 - t0)) \
        'BEGIN { printf "%d %.2f", r, (ns > 0 ? c / (ns / 1e9) : 0) }'
}

# ─── Bringing the two arms up ───────────────────────────────────────────────

start_socketley() {
    export HOME="$SKL_HOME" SOCKETLEY_SOCKET="$SKL_HOME/d.sock"
    unset SOCKETLEY_CONFIG
    "$SOCKETLEY_BIN" daemon --detach >/dev/null 2>&1
    local i; for ((i = 0; i < 60; i++)); do [ -S "$SKL_HOME/d.sock" ] && break; sleep 0.1; done
    # --cluster as well as --shards: it binds each shard at base+1+i and makes
    # CLUSTER SLOTS report the real four-node map.  Without it a sharded cache
    # presents as ONE node owning all 16384 slots -- which is what the first
    # sharded table measured, so it compared a Redis with client-side routing
    # against a socketley without, and read the difference as architecture.
    local sh=""; [ "$MODE" = "sharded" ] && sh="--shards 4 --cluster"
    "$SOCKETLEY_BIN" create cache m -p "$SKL_PORT" $sh -s >/dev/null 2>&1
    for ((i = 0; i < 120; i++)); do nc -z 127.0.0.1 "$SKL_PORT" 2>/dev/null && break; sleep 0.1; done
    sleep 2
    if [ "$MODE" = "sharded" ]; then
        S_TOPO=$(discover_topology "$SKL_PORT")
        [ -n "$S_TOPO" ] || { log_error "could not read socketley's shard topology"; exit 1; }
        log_info "socketley shards: $S_TOPO"
    fi
}

# One hash tag per master, so a client process can be pointed straight at the
# node that owns its keys.
#
# This exists because redis-benchmark --cluster cannot drive an arbitrary
# command: it does not know which argument of `GET str:x` is the key, sends to
# whichever node it picked, and stops at the MOVED.  Measured -- every keyed
# command returned zero while PING, DBSIZE and PUBLISH, which have no key,
# returned numbers.  The cluster was healthy the whole time, so the
# cluster_state check above did not catch it and would not have.
#
# So each of the four client processes gets a tag whose slot its own master
# owns and runs WITHOUT --cluster.  No redirects arise, all four masters carry
# load, and the arms stay symmetric: four client processes against four cache
# processes on both sides.
# `cluster slots` renders as a flat list: start, end, host, port, id per entry.
discover_topology() {   # discover_topology PORT -> "port:tag port:tag ..."
    local from=$1 out="" lo hi port t slot
    while read -r lo hi _host port _id; do
        [ -n "$port" ] || continue
        for t in a b c d e f g h i j k l m n o p q r s t u v w x y z; do
            slot=$(redis-cli -p "$from" cluster keyslot "{$t}k" 2>/dev/null | tr -dc '0-9')
            [ -n "$slot" ] && [ "$slot" -ge "$lo" ] && [ "$slot" -le "$hi" ] && { out="$out $port:$t"; break; }
        done
    # Empty lines dropped before grouping: Redis renders six lines per node
    # (five fields and a blank), socketley five, so a fixed grouping that fits
    # one arm slides by one node per entry on the other.  Measured -- it
    # reported two of four Redis masters, and the arm was then driven with four
    # client processes against half its cluster.
    done < <(redis-cli -p "$from" cluster slots 2>/dev/null | grep -v '^$' | paste - - - - -)
    printf '%s' "${out# }"
}

start_redis() {
    if [ "$MODE" = "sharded" ]; then
        local p
        for p in $CLUSTER_PORTS; do
            mkdir -p "$TMPD/$p"
            (cd "$TMPD/$p" && redis-server --port "$p" --cluster-enabled yes \
                --cluster-config-file nodes.conf --dir "$TMPD/$p" --daemonize yes \
                --save '' --appendonly no >/dev/null 2>&1)
        done
        sleep 2
        local nodes=""; for p in $CLUSTER_PORTS; do nodes="$nodes 127.0.0.1:$p"; done
        redis-cli --cluster create $nodes --cluster-yes >/dev/null 2>&1
        sleep 2
        # Said out loud, because a cluster that did not form turns every Redis
        # cell into a connection error that reads as "we are infinitely fast".
        local st i
        for ((i = 0; i < 30; i++)); do
            st=$(redis-cli -p "${CLUSTER_PORTS%% *}" cluster info 2>/dev/null | sed -n 's/cluster_state:\([a-z]*\).*/\1/p')
            [ "$st" = "ok" ] && break
            sleep 1
        done
        [ "$st" = "ok" ] || { log_error "the Redis cluster did not form (cluster_state:${st:-none})"; exit 1; }
        R_TOPO=$(discover_topology "${CLUSTER_PORTS%% *}")
        [ -n "$R_TOPO" ] || { log_error "could not read the Redis cluster topology"; exit 1; }
        log_info "Redis nodes: $R_TOPO"
    else
        redis-server --port "$REDIS_PORT" --dir "$TMPD" --daemonize yes \
            --save '' --appendonly no >/dev/null 2>&1
        sleep 1
        [ "$(redis-cli -p "$REDIS_PORT" ping 2>/dev/null)" = "PONG" ] \
            || { log_error "redis-server did not come up on $REDIS_PORT"; exit 1; }
    fi
}

# ─── Run ────────────────────────────────────────────────────────────────────

log_section "RESP matrix: every command we accept, against Redis ($MODE)"
check_binary || exit 1

if [ "$MODE" = "sharded" ]; then
    R_PORT=${CLUSTER_PORTS%% *}; R_FLAG=cluster
    S_LABEL="socketley --shards 4 --cluster"; R_LABEL="Redis Cluster 4"
else
    R_PORT=$REDIS_PORT;          R_FLAG=plain
    S_LABEL="socketley 1 shard";  R_LABEL="redis-server"
    S_TOPO=$SKL_PORT; R_TOPO=$REDIS_PORT
fi

start_socketley
start_redis

log_info "loading both arms: ${K_STR} str/num keys, ${K_COLL} each of hash(${N_FIELD} fields plus a numeric ctr), list/set/zset(${N_ELEM} elements), ${V_SIZE}-byte values"
if [ "$R_FLAG" = "cluster" ]; then
    # One file per tag, each going to the master that owns that tag's slot, so
    # no write ever needs a redirect.  socketley is loaded with all of them; it
    # ignores the tag and spreads the keys by its own hash.
    # The tags come from the Redis topology and are used for both arms, which
    # is sound because the two split the slot space the same way: a tag is a
    # CRC16 of its own bytes, so `{b}` lands in 0-4095 on either side and both
    # nodes for that range hold the same keys.  Verified by the key-count
    # control below, which has caught three different loading mistakes today.
    i=0
    for ent in $R_TOPO; do
        emit_load "${ent##*:}" > "$TMPD/load_$i.txt"
        load_arm "${ent%%:*}" "$TMPD/load_$i.txt"
        i=$((i + 1))
    done
    # Per shard port and not through the shared one: a tag's keys belong to one
    # shard, and loading them at their owner is what makes every later read a
    # local hit on both arms alike.
    i=0
    for ent in $S_TOPO; do
        load_arm "${ent%%:*}" "$TMPD/load_$i.txt"
        i=$((i + 1))
    done
else
    emit_load > "$TMPD/load.txt"
    load_arm "$SKL_PORT" "$TMPD/load.txt"
    load_arm "$R_PORT" "$TMPD/load.txt"
fi

# A control before any number is believed: both arms must hold the same keys.
S_N=$(redis-cli -p "$SKL_PORT" dbsize 2>/dev/null | tr -dc '0-9')
if [ "$R_FLAG" = "cluster" ]; then
    R_N=0; for p in $CLUSTER_PORTS; do R_N=$(( R_N + $(redis-cli -p "$p" dbsize 2>/dev/null | tr -dc '0-9') )); done
else
    R_N=$(redis-cli -p "$R_PORT" dbsize 2>/dev/null | tr -dc '0-9')
fi
log_info "keys loaded: socketley ${S_N:-?}, redis ${R_N:-?}"
if [ "${S_N:-0}" != "${R_N:-1}" ]; then
    log_warn "the two arms hold different key counts — every read below compares a hit against a miss"
fi

printf '%s\n' "$CMDS" | grep -v '^\s*$' | while IFS='|' read -r name range tmpl; do
    sv=""; rv=""; sc=""; rc=""
    for ((pass = 1; pass <= PASSES; pass++)); do
        if (( pass % 2 )); then
            read -r a b <<<"$(run_cell "$S_TOPO" "$range" $tmpl)"; sv="$sv $a"; sc="$sc $b"
            read -r a b <<<"$(run_cell "$R_TOPO" "$range" $tmpl)"; rv="$rv $a"; rc="$rc $b"
        else
            read -r a b <<<"$(run_cell "$R_TOPO" "$range" $tmpl)"; rv="$rv $a"; rc="$rc $b"
            read -r a b <<<"$(run_cell "$S_TOPO" "$range" $tmpl)"; sv="$sv $a"; sc="$sc $b"
        fi
    done
    s=$(median_of "$sv"); r=$(median_of "$rv")
    scm=$(median_of "$sc"); rcm=$(median_of "$rc")
    ratio=$(awk -v a="$s" -v b="$r" 'BEGIN{printf "%.2f", (b > 0 ? a / b : 0)}')
    # The ceiling first, because a ratio taken at it is a statement about
    # redis-benchmark.  PROCS processes can hold PROCS cores between them.
    # The ceiling is decided per cell and carried, not judged here: PROCS
    # processes can hold PROCS cores between them, and a cell measured at that
    # is a statement about redis-benchmark.
    capped=$(awk -v sc="$scm" -v rc="$rcm" -v p="$PROCS" \
        'BEGIN{ print (sc >= p * 0.95 || rc >= p * 0.95) ? "yes" : "no" }')
    printf '%s|%.0f|%.0f|%s|%s|%s|%s\n' "$name" "$s" "$r" "$ratio" "$scm" "$rcm" "$capped" \
        >> "$TMPD/rows.txt"
done

# ─── The band, and why it is relative ───────────────────────────────────────
#
# Judging each command against 1.0 answers "are we faster than Redis", which is
# the question this file says it is not asking.  If we are typically 1.8x and
# one command is 1.1x, that command is carrying something the others are not --
# and against 1.0 it reads as a pass.  So the band is drawn around our own
# median ratio, and a cell that was client-bound is never given one at all.
MED=$(awk -F'|' '$7 == "no" {print $4}' "$TMPD/rows.txt" | sort -g | \
      awk '{v[n++]=$1} END{if(n) printf "%.3f", (n%2)?v[int(n/2)]:(v[n/2-1]+v[n/2])/2}')

printf '\n  %-11s %14s %14s %8s %9s %9s  %s\n' \
    command "$S_LABEL" "$R_LABEL" ratio skl_cli redis_cli verdict
printf '  %s\n' "$(printf '%.0s─' {1..90})"
sort -t'|' -k4 -g "$TMPD/rows.txt" | while IFS='|' read -r name s r ratio scm rcm capped; do
    verdict=$(awk -v x="$ratio" -v m="$MED" -v c="$capped" \
        'BEGIN{ if (c == "yes") { print "client-bound — not readable"; exit }
                if (m <= 0)      { print "-"; exit }
                rel = x / m
                if      (rel < 0.55) printf "WELL BELOW our %.2fx norm — look here", m
                else if (rel < 0.75) printf "below our %.2fx norm", m
                else if (rel > 1.4)  print "above the norm"
                else                 print "as usual" }')
    printf '  %-11s %14s %14s %8s %9s %9s  %s\n' "$name" "$s" "$r" "${ratio}x" "$scm" "$rcm" "$verdict"
done

echo
log_info "$PASSES passes per cell, order alternating, $PROCS client processes x $CLIENTS connections, pipeline $PIPE"
