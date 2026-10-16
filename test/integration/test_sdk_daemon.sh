#!/usr/bin/env bash
# Integration test: a daemon and a runtime type written against the SDK.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
# Two claims the SDK makes, both of which were false when they were first
# measured:
#
# 1. `include/linux/socketley/daemon.h` documents a four-line main() that serves
#    the control socket.  It did serve it -- `ls` and `stats` worked -- but it
#    could not start a single runtime.  The supervisor forks and execs
#    self_exe() with `proxy-worker`, and a custom binary that does not dispatch
#    that argument starts a SECOND DAEMON instead of a worker, which exits
#    because the socket is taken.  Measured on the parent commit, the header's
#    own example, one `create server`:
#
#        main() entered 13 times          1 daemon, 12 dead worker forks
#        create said                      "the worker did not accept its
#                                          configuration"
#
#    The worker never saw a configuration; it was never a worker.  The dispatch
#    now lives in daemon_start() itself, so the documented example is the whole
#    example.
#
# 2. A runtime type of one's own derives from server_instance and inherits its
#    connection sniffer, which reads the first four bytes.  `GET `, `PUT `,
#    `POST`, `HEAD`, `DELE`, `PATC` and `OPTI` are routed to the HTTP path
#    before on_client_message is reached -- so a store whose verbs are GET and
#    PUT is silent on exactly the two commands it exists for, and answers
#    normally on every other one.  set_wire_protocol() is how a runtime says
#    the protocol is its own.
#
# ─── WHY THE ASSERTIONS ARE SHAPED THIS WAY ─────────────────────────────────
#
# The first defect passed every oracle that stopped at "the daemon is up": the
# socket existed, `ls` answered, and only starting something showed it.  So the
# daemon here is asked to run a runtime and that runtime is asked to serve
# traffic, which is the shortest path that would have failed.
#
# The second defect is asserted with BOTH a colliding verb and a non-colliding
# one in the same session, because a store that answers COUNT and not GET looks
# like a broken store rather than like a hijacked protocol.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_sdk.sh"
ROOT=$(cd "$HERE/../.." && pwd)
BINDIR=$(dirname "$BIN")

daemon_isolate sdkdaemon

PORT=$((SL_PORT_BASE+1390))
PASS=0; FAIL=0; TOTAL=0

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
has() { case "$1" in *"$2"*) return 0;; *) return 1;; esac; }

SDK_PID=""
ONE_PID=""
cleanup() {
    [ -n "$ONE_PID" ] && kill "$ONE_PID" 2>/dev/null
    [ -n "$SDK_PID" ] && kill "$SDK_PID" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a daemon and a runtime type from the SDK ==="

if ! command -v g++ >/dev/null 2>&1; then
    echo "  SKIP: g++ is required to build the SDK binaries"
    exit 0
fi
if [ ! -f "$BINDIR/libsocketley_sdk.a" ]; then
    echo "  SKIP: $BINDIR/libsocketley_sdk.a is not built"
    exit 0
fi

SANFLAGS=""
case "$BINDIR" in *Sanitize*) SANFLAGS="-fsanitize=address,undefined";; esac

build() {   # build <src> <out>
    sdk_cxx "$1" \
        -I"$ROOT" -I"$ROOT/include/linux" \
        -isystem "$ROOT/thirdparty/sol2" -isystem "$ROOT/thirdparty/luajit" \
        -L"$ROOT/thirdparty/liburing" $("$ROOT/sdk/socketley-config" --config "$(basename "$BINDIR")" --cflags --libs) \
        -o "$2" 2>"$SOCKETLEY_TMPD/gxx.err"
}

# ── The header's usage example, verbatim and with nothing added ─────────────
cat > "$SOCKETLEY_TMPD/sdkd.cpp" <<'EOF'
#include <socketley/daemon.h>
int main(int argc, char** argv)
{
    runtime_manager manager;
    event_loop loop;
    return socketley::daemon_start(manager, loop, argc, argv);
}
EOF

if build "$SOCKETLEY_TMPD/sdkd.cpp" "$SOCKETLEY_TMPD/sdkd"; then ok; else
    bad "the documented daemon example builds" "$(tail -5 "$SOCKETLEY_TMPD/gxx.err")"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; exit 1
fi

# ── A store whose verbs are exactly the ones the sniffer claims ─────────────
cat > "$SOCKETLEY_TMPD/kv.cpp" <<'EOF'
#include <socketley/worker.h>
#include <map>
#include <memory>
#include <string>
#include "socketley/runtime/server/server_instance.h"

namespace {
class kv final : public server_instance
{
public:
    explicit kv(std::string_view name) : server_instance(name)
    {
        set_wire_protocol(proto_tcp);
        set_on_client_message([this](int fd, std::string_view line) {
            while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
                line.remove_suffix(1);
            send_to(fd, run(line));
        });
    }
private:
    std::string run(std::string_view line)
    {
        const size_t a = line.find(' ');
        const std::string verb(line.substr(0, a == std::string_view::npos ? line.size() : a));
        if (verb == "COUNT") return std::to_string(m_kv.size()) + "\n";
        if (a == std::string_view::npos) return "ERR\n";
        std::string_view rest = line.substr(a + 1);
        const size_t b = rest.find(' ');
        const std::string key(rest.substr(0, b == std::string_view::npos ? rest.size() : b));
        if (verb == "GET")
        {
            auto it = m_kv.find(key);
            return it == m_kv.end() ? "NIL\n" : it->second + "\n";
        }
        if (verb == "PUT" && b != std::string_view::npos)
        {
            m_kv[key] = std::string(rest.substr(b + 1));
            return "OK\n";
        }
        return "ERR\n";
    }
    std::map<std::string, std::string> m_kv;
};
}

int main(int argc, char** argv)
{
    socketley::worker::register_type("kvtest",
        [](std::string_view n) -> std::unique_ptr<runtime_instance> {
            return std::make_unique<kv>(n);
        });
    return socketley::worker::run(argc, argv);
}
EOF

if build "$SOCKETLEY_TMPD/kv.cpp" "$SOCKETLEY_TMPD/kv-worker"; then ok; else
    bad "a runtime type of one's own builds" "$(tail -5 "$SOCKETLEY_TMPD/gxx.err")"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; exit 1
fi

mkdir -p "$HOME/.config/socketley/types"
cat > "$HOME/.config/socketley/types/kvtest.toml" <<EOF
name = "kvtest"
exec = "$SOCKETLEY_TMPD/kv-worker"
manifest_version = 1
EOF

# A manifest naming something that is not a worker at all, for the diagnosis.
cat > "$HOME/.config/socketley/types/notaworker.toml" <<EOF
name = "notaworker"
exec = /bin/true
manifest_version = 1
EOF
sed -i 's|exec = /bin/true|exec = "/bin/true"|' "$HOME/.config/socketley/types/notaworker.toml"

# ── The SDK daemon serves the socket the ordinary CLI dials ─────────────────
"$SOCKETLEY_TMPD/sdkd" daemon >>"$SOCKETLEY_DLOG" 2>&1 &
SDK_PID=$!
for _ in $(seq 1 100); do
    [ -S "$SOCKETLEY_SOCKET" ] && "$BIN" ls >/dev/null 2>&1 && break
    sleep 0.1
done

if [ -S "$SOCKETLEY_SOCKET" ]; then ok; else
    bad "the SDK daemon binds the control socket" "no socket at $SOCKETLEY_SOCKET"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; exit 1
fi

# The whole point of the first defect: it is starting a runtime that failed,
# not answering a query.
if "$BIN" create server sdk_web -p $((PORT+1)) -s </dev/null >/dev/null 2>&1; then ok; else
    bad "the SDK daemon starts a built-in runtime" \
        "$("$BIN" create server sdk_web2 -p $((PORT+2)) -s </dev/null 2>&1)"
fi

STATUS=$("$BIN" ls </dev/null 2>/dev/null | awk '$2 == "sdk_web" { print $7 }')
if [ "$STATUS" = "Up" ]; then ok; else
    bad "and it reports it running" "ls said '${STATUS:-<nothing>}'"
fi

# The runtime is served by the SDK binary re-entered AS A WORKER, which is the
# fix stated positively -- "daemon started appears once" is true of the broken
# build too, because a fork that cannot bind the socket dies before it logs.
WORKER_ARGS=$(ps -eo ppid,args 2>/dev/null | awk -v d="$SDK_PID" '$1 == d { $1=""; print substr($0,2) }' | head -1)
case "$WORKER_ARGS" in
    *sdkd*proxy-worker*) ok ;;
    *) bad "the SDK binary is re-entered as a worker" \
           "the child of $SDK_PID is '${WORKER_ARGS:-<none>}'" \
           "a binary that does not dispatch proxy-worker forks a second daemon here" ;;
esac

# ── A registered type in an SDK daemon, speaking its own verbs ──────────────
if "$BIN" create kvtest sdk_kv -p "$PORT" -s </dev/null >/dev/null 2>&1; then ok; else
    bad "a registered type is created in an SDK daemon" \
        "$("$BIN" create kvtest sdk_kv2 -p $((PORT+3)) -s </dev/null 2>&1)"
fi

for _ in $(seq 1 60); do
    ss -ltn 2>/dev/null | awk -v p=":$PORT\$" '$4 ~ p' | grep -q . && break
    sleep 0.25
done

if command -v nc >/dev/null 2>&1; then
    # COUNT does not collide with any HTTP method and answered even when the
    # sniffer was in charge, so it is the control rather than the finding.
    OUT=$(printf 'COUNT\n' | timeout 5 nc -q2 127.0.0.1 "$PORT" 2>/dev/null)
    if [ "$OUT" = "0" ]; then ok; else
        bad "a non-colliding verb reaches the runtime" "got '${OUT:-<nothing>}'"
    fi

    # PUT and GET are the two the sniffer used to take.
    OUT=$(printf 'PUT k hello\nGET k\nCOUNT\n' | timeout 5 nc -q2 127.0.0.1 "$PORT" 2>/dev/null)
    if [ "$(printf '%s' "$OUT" | tr '\n' '|')" = "OK|hello|1" ]; then ok; else
        bad "PUT and GET reach the runtime rather than the HTTP path" \
            "got '$(printf '%s' "$OUT" | tr '\n' '|')', wanted 'OK|hello|1'" \
            "an empty answer here is the connection sniffer taking the line"
    fi
else
    echo "  (nc absent -- the wire-protocol assertions did not run)"
fi

# ── One binary that is the daemon AND the worker for its own type ───────────
#
# main() registers the type before daemon_start, so by the time the manifest
# loader runs the name is already taken.  register_type() refused it, the
# manifest was dropped, and `create counter` then resolved to a runtime the
# caller never asked for: exit 0, silent, "type": "server".  The loader adopts
# the name instead, and takes the placeholder factory with it -- a daemon holds
# a placeholder and must not build the caller's object, whose type is whatever
# base it derives from.
cat > "$SOCKETLEY_TMPD/one.cpp" <<'EOF'
#include <socketley/daemon.h>
#include <socketley/worker.h>
#include <map>
#include <memory>
#include <string>
#include "socketley/runtime/server/server_instance.h"
namespace {
class counter final : public server_instance
{
public:
    explicit counter(std::string_view name) : server_instance(name)
    {
        set_wire_protocol(proto_tcp);
        set_on_client_message([this](int fd, std::string_view line) {
            while (!line.empty() && (line.back()=='\n'||line.back()=='\r'))
                line.remove_suffix(1);
            send_to(fd, std::to_string(++m_hits[std::string(line)]) + "\n");
        });
    }
private:
    std::map<std::string, long> m_hits;
};
}
int main(int argc, char** argv)
{
    socketley::worker::register_type("counter",
        [](std::string_view n) -> std::unique_ptr<runtime_instance> {
            return std::make_unique<counter>(n);
        });
    runtime_manager manager;
    event_loop loop;
    return socketley::daemon_start(manager, loop, argc, argv);
}
EOF

if build "$SOCKETLEY_TMPD/one.cpp" "$SOCKETLEY_TMPD/onebin"; then ok; else
    bad "a one-binary daemon builds" "$(tail -5 "$SOCKETLEY_TMPD/gxx.err")"
fi

cat > "$HOME/.config/socketley/types/counter.toml" <<EOF
name = "counter"
exec = "$SOCKETLEY_TMPD/onebin"
manifest_version = 1
EOF

ONE_SOCK="$SOCKETLEY_TMPD/one.sock"
ONE_LOG="$SOCKETLEY_TMPD/one.log"
SOCKETLEY_SOCKET="$ONE_SOCK" "$SOCKETLEY_TMPD/onebin" daemon >"$ONE_LOG" 2>&1 &
ONE_PID=$!
for _ in $(seq 1 100); do [ -S "$ONE_SOCK" ] && break; sleep 0.1; done

if SOCKETLEY_SOCKET="$ONE_SOCK" "$BIN" create counter hits -p $((PORT+6)) -s </dev/null >/dev/null 2>&1; then ok
else bad "the one-binary daemon creates its own type" \
         "$(SOCKETLEY_SOCKET="$ONE_SOCK" "$BIN" create counter h2 -p $((PORT+7)) -s </dev/null 2>&1)"; fi

# The whole defect in one assertion: it used to answer "server" here, quietly.
TYPE=$(SOCKETLEY_SOCKET="$ONE_SOCK" "$BIN" show hits </dev/null 2>/dev/null | sed -n 's/.*"type": "\([^"]*\)".*/\1/p')
if [ "$TYPE" = "counter" ]; then ok; else
    bad "and it is the type that was asked for" \
        "show reports type '${TYPE:-<nothing>}', wanted 'counter'" \
        "a refused manifest leaves the name resolving to something else"
fi

if command -v nc >/dev/null 2>&1; then
    for _ in $(seq 1 60); do
        ss -ltn 2>/dev/null | awk -v p=":$((PORT+6))\$" '$4 ~ p' | grep -q . && break
        sleep 0.25
    done
    OUT=$(printf 'a\na\nb\n' | timeout 5 nc -q2 127.0.0.1 $((PORT+6)) 2>/dev/null | tr '\n' '|')
    if [ "$OUT" = "1|2|1|" ]; then ok; else
        bad "the one-binary daemon serves its own type" "got '$OUT', wanted '1|2|1|'"
    fi
fi
kill "$ONE_PID" 2>/dev/null

# ── A binary that is not a worker is diagnosed, not blamed for its config ───
OUT=$("$BIN" create notaworker naw -p $((PORT+4)) -s </dev/null 2>&1)
if has "$OUT" "/bin/true"; then ok; else
    bad "the refusal names the binary that failed" "said: $OUT"
fi
if has "$OUT" "proxy-worker"; then ok; else
    bad "and names what would fix it" "said: $OUT"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
