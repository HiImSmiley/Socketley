#!/usr/bin/env bash
# The four things a proxy can be put in front of, brought up identically for
# both arms — and the checks that say so before anything is timed.
#
# bench_proxy_matrix.sh measures these and profile_proxy_scenarios.sh profiles
# them, and they have to be the SAME fixtures or the profile is of a different
# program than the table.  Eighty lines of setup copied into two files is eighty
# lines that drift, and the drift shows up as a profile that explains a number
# nobody measured.
#
# ─── THE FOUR ──────────────────────────────────────────────────────────────
#
#   tcp    raw byte forwarding to a loopback TCP backend.  The floor: nothing is
#          parsed, nothing is routed, and what is left is the wake-up path.
#   unix   the same with an AF_UNIX backend leg.  --backend unix: exists to take
#          TCP out of one of the two hops; the man page claims 2.2-2.4x for a
#          cache on one and nothing had ever checked what a PROXY gets.
#   rr4    four backends, round-robin.  Choosing a backend per connection is work
#          neither of the first two does, and it is the first thing a real
#          deployment turns on.
#   http   request parsing, path routing and a rewritten request line.  The mode
#          HAProxy was written for.
#
# Both proxies front the SAME backend object in every case, started once and
# left alone, so a difference between the arms cannot be a difference between
# two fixtures.
#
# ─── THE CHECKS, EACH OF WHICH HAS ALREADY BOUGHT A WORTHLESS RUN ───────────
#
#   THE 404.  socketley's HTTP proxy routes on a leading `/<runtime-name>/` and
#   strips it; HAProxy is given the bare path.  Point both arms at one URL and
#   socketley answers 404 -- cheaper to produce than the file, and followed by a
#   close that turns keep-alive into something else.  Measured that way it "did"
#   6656 req/s and every worker ended in an error no throughput number mentions.
#   So each arm gets its own path, and both are fetched and required to answer
#   200 with the same body length.
#
#   THE SILENT FORWARD.  A TCP proxy that refuses the connection is faster than
#   one that forwards it, so every TCP fixture must complete a round trip on
#   both arms first.  Not with `nc`: `nc -q0` exits the moment stdin ends, which
#   is before a reply has come back through two hops, so it reports silence for
#   a fixture that works -- and `-q1` buys the answer at a second a probe.
#
#   THE STALE HAPROXY.  One left from an earlier run holds the port and answers
#   on it, and every wait-for-port below would be satisfied by it.  The whole
#   comparison would then run against somebody else's configuration, pointed at
#   somebody else's backend, and say nothing about it.
#
#   THE SHARD THAT IS A QUARTER OF THE TRUTH.  A sharded proxy is four processes
#   behind one SO_REUSEPORT listener, so CPU read from whichever pid `ss` printed
#   first is a quarter of what was spent -- and the backend-bound check built on
#   it would never fire.  Every arm resolves to a LIST of pids.
#
# ─── What the caller provides ───────────────────────────────────────────────
#
#   WORK          a scratch directory it owns and will delete
#   MODE          single | sharded
#   SHARDS        how many, when sharded
#   P_BE_TCP P_BE_HTTP P_BE_RR P_SK_* P_HA_*   the port block
#   SK_HTTP_NAME  the runtime name, which is also the HTTP arm's path prefix
#   utils.sh and its log_* / socketley_cmd / wait_for_port, already sourced
#
# ─── What it sets ───────────────────────────────────────────────────────────
#
#   SKPORT[f] HAPORT[f] SKPIDS[f] BEPIDS[f] for f in tcp unix rr4 http
#   HA_PIDS   HA_PID   HA_THREADS   BE_SOCK

declare -gA SKPORT HAPORT SKPIDS BEPIDS
HA_PID=""

pids_on_port() {
    ss -ltnp 2>/dev/null | awk -v p=":$1\$" '$4 ~ p' \
        | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u | tr '\n' ' '
}
# The unix backend has no TCP port to ask about, so it is found by the socket it
# listens on instead.
pids_on_unix() {
    ss -lxp 2>/dev/null | awk -v s="$1" '$0 ~ s' \
        | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u | tr '\n' ' '
}

tcp_echo() {   # port -> what came back, or empty
    python3 - "$1" <<'PY' 2>/dev/null
import socket, sys
try:
    s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5); s.settimeout(3)
    s.sendall(b"ping\n")
    sys.stdout.write(s.recv(64).decode("latin1").strip())
except Exception:
    pass
PY
}

fetch_status_len() {   # port path -> "status bodylen"
    python3 - "$1" "$2" <<'PY' 2>/dev/null || echo "ERR 0"
import socket, sys
port, path = int(sys.argv[1]), sys.argv[2]
req = ("GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n" % path).encode()
try:
    s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(5)
    s.sendall(req)
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(65536)
        if not d: break
        buf += d
    head = buf.split(b"\r\n\r\n", 1)[0]
    status = head.split(b"\r\n")[0].split(b" ")[1].decode()
    cl = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            cl = int(line.split(b":")[1])
    s.close()
    print(status, cl)
except Exception:
    print("ERR", 0)
PY
}

# Refuse rather than measure whoever is already there.
proxy_fixtures_ports_free() {
    local p
    for p in "$P_SK_TCP" "$P_SK_UNIX" "$P_SK_RR" "$P_SK_HTTP" \
             "$P_HA_TCP" "$P_HA_UNIX" "$P_HA_RR" "$P_HA_HTTP" \
             "$P_BE_TCP" "$P_BE_HTTP" $((P_BE_RR)) $((P_BE_RR+1)) $((P_BE_RR+2)) $((P_BE_RR+3)); do
        if ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$p\$"; then
            log_error "refusing: port $p is already listening — this run would measure whoever holds it"
            return 1
        fi
    done
    return 0
}

proxy_fixtures_up() {
    mkdir -p "$WORK/www"
    printf 'ok' > "$WORK/www/small.txt"
    # Not an .html file: `--http` injects a WebSocket script into every .html it
    # serves, so an HTML fixture would time a rewrite as well as a send.
    head -c 16384 /dev/zero | tr '\0' 'x' > "$WORK/www/large.txt"
    chmod -R a+rX "$WORK"
    BE_SOCK=$WORK/be.sock

    # In sharded mode the backends are sharded too.  A single-process echo
    # server saturates near one core, which four proxy shards reach long before
    # they reach their own limit -- and then both arms report the backend.
    local BE_SHARD="" PX_SHARD=""
    if [ "$MODE" = "sharded" ]; then
        BE_SHARD="--shards $SHARDS"; PX_SHARD="--shards $SHARDS"
    fi

    up() { local n=$1; shift; socketley_cmd create "$@" -s >/dev/null 2>&1; return 0; }

    up be_tcp  server be_tcp  -p "$P_BE_TCP"  --mode in --lua "$BENCH_ECHO_LUA" $BE_SHARD
    # --listen unix: refuses --shards, so the unix backend is one process in
    # both modes.  Named here rather than worked around: the unix rows in
    # sharded mode are four proxy shards in front of one backend process, and
    # the backend-bound check is what decides whether that spoiled them.
    up be_unix server be_unix --listen "unix:$BE_SOCK" --mode in --lua "$BENCH_ECHO_LUA"
    up be_http server be_http -p "$P_BE_HTTP" --http "$WORK/www" --http-cache $BE_SHARD
    local RR_LIST="" i
    for i in 0 1 2 3; do
        up "be_rr$i" server "be_rr$i" -p $((P_BE_RR + i)) --mode in --lua "$BENCH_ECHO_LUA"
        RR_LIST="$RR_LIST,127.0.0.1:$((P_BE_RR + i))"
    done
    RR_LIST=${RR_LIST#,}

    local p
    for p in "$P_BE_TCP" "$P_BE_HTTP" $((P_BE_RR)) $((P_BE_RR+1)) $((P_BE_RR+2)) $((P_BE_RR+3)); do
        wait_for_port "$p" || { log_error "backend on $p did not come up"; return 1; }
    done
    for _ in $(seq 1 100); do [ -S "$BE_SOCK" ] && break; sleep 0.1; done
    [ -S "$BE_SOCK" ] || { log_error "the unix backend never created $BE_SOCK"; return 1; }

    up pm_tcp  proxy pm_tcp  -p "$P_SK_TCP"  --backend "127.0.0.1:$P_BE_TCP" --protocol tcp $PX_SHARD
    up pm_unix proxy pm_unix -p "$P_SK_UNIX" --backend "unix:$BE_SOCK"       --protocol tcp $PX_SHARD
    up pm_rr   proxy pm_rr   -p "$P_SK_RR"   --backend "$RR_LIST" --strategy round-robin --protocol tcp $PX_SHARD
    up "$SK_HTTP_NAME" proxy "$SK_HTTP_NAME" -p "$P_SK_HTTP" --backend "127.0.0.1:$P_BE_HTTP" --protocol http $PX_SHARD
    for p in "$P_SK_TCP" "$P_SK_UNIX" "$P_SK_RR" "$P_SK_HTTP"; do
        wait_for_port "$p" || { log_error "socketley proxy on $p did not come up"; return 1; }
    done

    HA_THREADS=1
    [ "$MODE" = "sharded" ] && HA_THREADS=$SHARDS
    {
    cat <<EOF
global
    nbthread $HA_THREADS
    maxconn 60000

defaults
    timeout connect 5s
    timeout client  30s
    timeout server  30s

listen l_tcp
    mode tcp
    bind 127.0.0.1:$P_HA_TCP
    server s1 127.0.0.1:$P_BE_TCP

listen l_unix
    mode tcp
    bind 127.0.0.1:$P_HA_UNIX
    server s1 unix@$BE_SOCK

listen l_rr
    mode tcp
    balance roundrobin
    bind 127.0.0.1:$P_HA_RR
EOF
    for i in 0 1 2 3; do echo "    server s$i 127.0.0.1:$((P_BE_RR + i))"; done
    cat <<EOF

listen l_http
    mode http
    bind 127.0.0.1:$P_HA_HTTP
    server s1 127.0.0.1:$P_BE_HTTP
EOF
    } > "$WORK/haproxy.cfg"

    haproxy -f "$WORK/haproxy.cfg" -db > "$WORK/haproxy.out" 2>&1 &
    HA_PID=$!
    for p in "$P_HA_TCP" "$P_HA_UNIX" "$P_HA_RR" "$P_HA_HTTP"; do
        wait_for_port "$p" || {
            log_error "haproxy did not bind $p:"; sed 's/^/    /' "$WORK/haproxy.out" >&2; return 1; }
    done
    sleep 0.5

    SKPORT[tcp]=$P_SK_TCP;   HAPORT[tcp]=$P_HA_TCP
    SKPORT[unix]=$P_SK_UNIX; HAPORT[unix]=$P_HA_UNIX
    SKPORT[rr4]=$P_SK_RR;    HAPORT[rr4]=$P_HA_RR
    SKPORT[http]=$P_SK_HTTP; HAPORT[http]=$P_HA_HTTP
    local f
    for f in tcp unix rr4 http; do SKPIDS[$f]=$(pids_on_port "${SKPORT[$f]}"); done
    BEPIDS[tcp]=$(pids_on_port "$P_BE_TCP")
    BEPIDS[unix]=$(pids_on_unix "$BE_SOCK")
    BEPIDS[http]=$(pids_on_port "$P_BE_HTTP")
    BEPIDS[rr4]="$(pids_on_port $((P_BE_RR)))$(pids_on_port $((P_BE_RR+1)))$(pids_on_port $((P_BE_RR+2)))$(pids_on_port $((P_BE_RR+3)))"
    HA_PIDS=$(pids_on_port "$P_HA_TCP")

    for f in tcp unix rr4 http; do
        [ -n "${SKPIDS[$f]## }" ] || { log_error "no pid found for the socketley $f proxy"; return 1; }
        [ -n "${BEPIDS[$f]## }" ] || { log_error "no pid found for the $f backend"; return 1; }
    done
    [ -n "$HA_PIDS" ] || { log_error "no pid found for haproxy"; return 1; }
    if [ "$MODE" = "sharded" ]; then
        local n; n=$(wc -w <<<"${SKPIDS[tcp]}")
        [ "$n" -eq "$SHARDS" ] || log_warn "expected $SHARDS shards on the tcp proxy, ss reports $n"
    fi
    log_info "socketley tcp pids: ${SKPIDS[tcp]}  haproxy pid: $HA_PIDS  ($HA_THREADS thread(s))"
    return 0
}

# Both arms serve the same thing, on every fixture, before anything is timed.
proxy_fixtures_check() {
    local f a b got side
    for f in small.txt large.txt; do
        a=$(fetch_status_len "$P_SK_HTTP" "/$SK_HTTP_NAME/$f")
        b=$(fetch_status_len "$P_HA_HTTP" "/$f")
        if [ "$a" != "$b" ]; then
            log_error "the HTTP arms do not serve the same thing for $f: socketley '$a', haproxy '$b'"
            log_error "a ratio between these would compare an error page with a file"
            return 1
        fi
        [ "${a%% *}" = "200" ] || { log_error "both HTTP arms answered ${a%% *} for $f, not 200"; return 1; }
        log_info "both HTTP arms serve $f identically: ${a%% *}, ${a##* } bytes"
    done
    for f in tcp unix rr4; do
        for side in "${SKPORT[$f]}" "${HAPORT[$f]}"; do
            got=$(tcp_echo "$side")
            [ -n "$got" ] || { log_error "the $f fixture answered nothing on port $side — nothing is forwarded"; return 1; }
        done
    done
    log_info "all four fixtures forward on both arms"
    return 0
}
