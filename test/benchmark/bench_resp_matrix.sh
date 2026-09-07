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
PASSES=${BENCH_MATRIX_PASSES:-5}
OPS=${BENCH_MATRIX_OPS:-2000000}
CLIENTS=${BENCH_MATRIX_CLIENTS:-50}
PIPE=${BENCH_MATRIX_PIPE:-16}
# Twice as many client processes as there are server shards, because one
# redis-benchmark does not saturate a core here and four of them left both arms
# short of what they could serve -- which compresses the ratio, since a ceiling
# holds the faster arm back harder.  Measured against a four-shard cluster
# cache, 600k operations per process, pipeline 16:
#
#   GET    4 procs            2,727,273/s
#          8 procs            4,060,925/s   <- +49%
#         12 procs            2,878,466/s   (16 cores, 4 of them shards)
#          8 procs, 100 conn  4,013,423/s   (connections are not the lever)
#          4 procs x 4 thr    2,390,438/s   (--threads is worse in every shape)
#   PING   4 procs            7,784,675/s
#          8 procs           10,929,834/s
#          4 procs x 4 thr    5,966,619/s
#
# PING is in that list on purpose: it touches no data, so a PING cell that
# reads 1.23x is measuring the load generator and nothing else.  It is the
# control for whether this number is set high enough.
PROCS=${BENCH_MATRIX_PROCS:-8}           # client processes per cell
# The longest a single client process may take before it is taken to be stuck.
# Generous against the slowest legitimate cell measured here -- SMEMBERS over
# hundred-element sets is about twenty seconds -- and far under the ninety-odd
# minutes a wedged one ran for.
CELL_TIMEOUT=${BENCH_MATRIX_CELL_TIMEOUT:-120}
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
# LINSERT, GETDEL, UNLINK, RPOPLPUSH, LMOVE and the ZREMRANGE pair -- consume
# what they measure,
# so after the structure is drained they time the empty path instead.  They
# need their own key family reloaded between passes, which is a separate piece
# of work; a number for them here would be a number for an empty list.
#
# BLPOP and BRPOP are absent for a third reason, which is worse than not being
# idempotent: on an empty list they measure their own timeout -- the rate would
# be exactly clients divided by the timeout, a constant wearing a rate's
# clothes -- and on a full one they are LPOP with a different name and the
# blocking path is never entered.  What can be asked of them is a latency
# (LPUSH to woken) and not a throughput, and that needs a different instrument.
#
# PSUBSCRIBE is absent because it accumulates: the tenth call on one connection
# is not the first.  What it costs is measured separately, as a publish rate
# with and without a pattern subscriber attached.
#
# WATCH is absent for the same reason and it printed 10.16x before anybody
# checked.  Redis dedupes a client's watched keys with a linear scan of the
# list, so its rate falls with the number of DISTINCT keys one connection has
# watched -- measured at -c 1, 60k ops: 69204/s at r=1, 57143 at r=1000, 23220
# at r=10000, 7964 at r=60000.  Ours is flat over the same sweep (71942 down to
# 68729) because it deduped through a hash set.  At r=1 the two are level with
# each other and with GET, which is the honest answer: one WATCH costs one
# lookup on both sides, and the ratio the row printed was the keyspace size.
#
# RPOPLPUSH and LMOVE could be made idempotent by moving a list onto itself,
# which rotates -- but only with the SAME key on both sides, and
# __rand_int__ is substituted per occurrence, so the two would be different
# keys.  A fixed key would hammer one list and, sharded, one shard.  Their path
# is covered by test_cache_queue_and_scan.sh instead.
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
SETKEEPTTL|1000|SET KEYTAGstr:__rand_int__ xxxxxxxxxxxxxxxxxxxx KEEPTTL
SETGET|1000|SET KEYTAGstr:__rand_int__ xxxxxxxxxxxxxxxxxxxx GET
# No spaces in either script: run_cell splits the template on whitespace, so a
# script written the readable way arrives as several arguments and the cell
# measures a syntax error on both arms -- which reads as two zeroes and no
# warning at all.
EVAL|1000|EVAL return(1) 0
EVALKEY|1000|EVAL return(redis.call('get',KEYS[1])) 1 KEYTAGstr:__rand_int__
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
HSCAN|100|HSCAN KEYTAGhash:__rand_int__ 0
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
SSCAN|100|SSCAN KEYTAGset:__rand_int__ 0
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
ZSCAN|100|ZSCAN zKEYTAGset:__rand_int__ 0
PUBLISH|1000|PUBLISH KEYTAGchan:__rand_int__ hello|60000
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

# Everything above is the command table, the key space and how to load it, and
# the profiler wants exactly that and none of the measuring below.  Sourcing
# with this set stops here, so the two never drift: a command added to the
# table is profiled without anybody remembering to add it twice.
if [ -n "${BENCH_MATRIX_TABLE_ONLY:-}" ]; then
    return 0 2>/dev/null || exit 0
fi

# The ratio of each pass, sorted, with its median and its two ends.  A cell
# whose ends straddle the decision threshold has not measured anything, and
# saying so is the point of carrying them.
paired_ratio() {   # paired_ratio "s1 s2 .." "r1 r2 .." -> "median lo hi"
    awk -v A="$1" -v B="$2" 'BEGIN{
        na = split(A, a, " "); nb = split(B, b, " ")
        n  = (na < nb ? na : nb); m = 0
        for (i = 1; i <= n; i++) if (b[i] > 0) r[++m] = a[i] / b[i]
        if (m == 0) { print "0 0 0"; exit }
        for (i = 2; i <= m; i++) { v = r[i]; j = i - 1
            while (j > 0 && r[j] > v) { r[j+1] = r[j]; j-- }
            r[j+1] = v }
        med = (m % 2) ? r[int(m/2)+1] : (r[m/2] + r[m/2+1]) / 2
        printf "%.2f %.2f %.2f", med, r[1], r[m]
    }'
}

# Every node of a topology still answering.  A dead one is not a slow cell, it
# is a different cluster, and the difference is invisible in the numbers.
topo_alive() {   # topo_alive "port:tag port:tag .."
    local ent p
    for ent in $1; do
        p=${ent%%:*}
        [ "$(timeout 3 redis-cli -p "$p" ping 2>/dev/null)" = "PONG" ] || return 1
    done
    return 0
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
    # A floor on the per-process count, because a short run reports the clock
    # and then the connections: 2000 operations came back as 1,999,999 requests
    # per second, and 50,000 made the whole cell 70 ms with fifty connections
    # being opened inside it.  Measured on one command, four processes:
    #
    #     50,000 ops/proc   70 ms cell   3,419,054/s
    #    200,000 ops/proc  320 ms cell   2,597,444/s
    #    500,000 ops/proc  660 ms cell   3,085,234/s
    #  1,500,000 ops/proc  1.91 s cell   3,151,676/s
    #
    # The rate does not settle until the cell is most of a second long, and at
    # 50,000 it reads eleven per cent high.  Paired against Redis over five
    # passes that showed up as 58 of 66 cells whose passes disagreed by more
    # than a quarter -- two commands sharing one code path came out at 0.91x
    # and 1.53x.
    local per=$(( OPS / PROCS )); [ "$per" -lt 500000 ] && per=500000
    # A command may ask for fewer, and one does.  PUBLISH on a Redis cluster is
    # broadcast to every node over the cluster bus, the bus link has no
    # client-output-buffer-limit, and at this pipeline depth the buffer grows
    # until the kernel steps in: measured twice, one node at 5.77 GB and then
    # 3.44 GB, both "Out of memory: Killed process (redis-server)".  The node
    # dies, redis-benchmark spins on a refused connection, and every later cell
    # measures a three-node cluster in state fail.  The command is kept -- it
    # is a real difference between the two -- at a load both survive.
    [ -n "${CELL_OPS:-}" ] && per=$(( CELL_OPS / PROCS ))
    [ "$per" -lt 1000 ] && per=1000
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
        # Under `timeout`, because a cell must not be able to hang the table.
        # Measured: PUBLISH against a four-master Redis Cluster wedged two of
        # eight client processes at 100% CPU for ninety-three minutes on a cell
        # that takes five seconds -- Redis broadcasts every publish over the
        # cluster bus, and at eight clients x fifty connections x pipeline 16
        # the node stops making progress rather than slowing down.  A killed
        # process writes no rate, the cell reports what it has, and the run
        # goes on; an unreadable row is a row, an unfinished table is nothing.
        /usr/bin/time -f '%U %S' -o "$TMPD/t$i" \
            timeout -k 5 "$CELL_TIMEOUT" \
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

printf '%s\n' "$CMDS" | grep -v '^\s*$' | while IFS='|' read -r name range tmpl cell_ops; do
    export CELL_OPS="${cell_ops:-}"
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
    # Both arms still whole?  The startup check cannot see a node that dies
    # halfway, and the run went on for another forty minutes against a
    # three-node cluster in state fail before anybody looked.  Loud and at
    # once, because a table built on that is worse than no table.
    if ! topo_alive "$S_TOPO"; then
        log_error "a socketley shard stopped answering during $name -- discarding the run"
        exit 2
    fi
    if ! topo_alive "$R_TOPO"; then
        log_error "a Redis node stopped answering during $name -- discarding the run"
        log_error "check dmesg for the OOM killer: a cluster PUBLISH has no bus buffer limit"
        exit 2
    fi

    s=$(median_of "$sv"); r=$(median_of "$rv")
    scm=$(median_of "$sc"); rcm=$(median_of "$rc")
    # The ratio PER PASS, then the median of those -- not the ratio of two
    # medians.  The two arms of a pass ran seconds apart on the same box, so a
    # pass that was disturbed moves both and cancels; the ratio of two medians
    # does not cancel anything.  Measured: a cell whose two commands share one
    # code path and benchmark identically when asked directly came out of this
    # table at 0.91x against the other's 1.53x, three passes each.
    read -r ratio rlo rhi <<<"$(paired_ratio "$sv" "$rv")"
    spread=$(awk -v m="$ratio" -v lo="$rlo" -v hi="$rhi" \
        'BEGIN{ printf "%.2f", (m > 0 ? (hi - lo) / m : 9) }')
    # The ceiling first, because a ratio taken at it is a statement about
    # redis-benchmark.  PROCS processes can hold PROCS cores between them.
    # The ceiling is decided per cell and carried, not judged here: PROCS
    # processes can hold PROCS cores between them, and a cell measured at that
    # is a statement about redis-benchmark.
    capped=$(awk -v sc="$scm" -v rc="$rcm" -v p="$PROCS" \
        'BEGIN{ print (sc >= p * 0.95 || rc >= p * 0.95) ? "yes" : "no" }')
    printf '%s|%.0f|%.0f|%s|%s|%s|%s|%s\n' "$name" "$s" "$r" "$ratio" "$scm" "$rcm" "$capped" \
        "$spread" >> "$TMPD/rows.txt"
done

# ─── The band, and why it is relative ───────────────────────────────────────
#
# Judging each command against 1.0 answers "are we faster than Redis", which is
# the question this file says it is not asking.  If we are typically 1.8x and
# one command is 1.1x, that command is carrying something the others are not --
# and against 1.0 it reads as a pass.  So the band is drawn around our own
# median ratio, and a cell that was client-bound is never given one at all.
MED=$(awk -F'|' '$7 == "no" && $8 <= 0.25 {print $4}' "$TMPD/rows.txt" | sort -g | \
      awk '{v[n++]=$1} END{if(n) printf "%.3f", (n%2)?v[int(n/2)]:(v[n/2-1]+v[n/2])/2}')

printf '\n  %-11s %14s %14s %8s %7s %9s %9s  %s\n' \
    command "$S_LABEL" "$R_LABEL" ratio spread skl_cli redis_cli verdict
printf '  %s\n' "$(printf '%.0s─' {1..100})"
sort -t'|' -k4 -g "$TMPD/rows.txt" | while IFS='|' read -r name s r ratio scm rcm capped spread; do
    # The spread is read before the level.  A cell whose passes disagree by
    # more than a quarter of their own median has not measured this command,
    # and a verdict drawn from it is a verdict about the box.
    verdict=$(awk -v x="$ratio" -v m="$MED" -v c="$capped" -v sp="$spread" \
        'BEGIN{ if (c == "yes")  { print "client-bound — not readable"; exit }
                if (sp > 0.25)   { printf "spread %.0f%% — not readable", sp * 100; exit }
                if (m <= 0)      { print "-"; exit }
                rel = x / m
                if      (rel < 0.55) printf "WELL BELOW our %.2fx norm — look here", m
                else if (rel < 0.75) printf "below our %.2fx norm", m
                else if (rel > 1.4)  print "above the norm"
                else                 print "as usual" }')
    printf '  %-11s %14s %14s %8s %7s %9s %9s  %s\n' \
        "$name" "$s" "$r" "${ratio}x" "$spread" "$scm" "$rcm" "$verdict"
done

echo
log_info "$PASSES passes per cell, order alternating, $PROCS client processes x $CLIENTS connections, pipeline $PIPE"
