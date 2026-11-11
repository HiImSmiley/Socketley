#!/usr/bin/env bash
# suite: isolated -- no daemon at all, and a port window of its own
# Integration test: libsocketley.so, and the Rust and Node programs built on it.
#
# The two bindings are what a program outside C++ actually uses, and each crosses threads its own way: a Rust closure
# gets a call it can move, a JavaScript function runs on Node's one thread however the engine called it.  So each
# language runs a real program with tools answered in place, from elsewhere, and by failing, and is asked over HTTP.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
ROOT=$(cd "$HERE/../.." && pwd)
BINDIR=$(dirname "$BIN")
LIB="$BINDIR/libsocketley.so"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: ${2:-}"; }
expect() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

echo "=== Integration: libsocketley.so, from Rust and Node ==="
if [ ! -f "$LIB" ]; then echo "  SKIP: $LIB is not built"; exit 0; fi

T=$(mktemp -d /tmp/socketley-lang-XXXXXX)
HOST=""
cleanup() { [ -n "$HOST" ] && kill -9 "$HOST" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT

expect "the library shows nothing but the C interface" "$(nm -D --defined-only "$LIB" | awk '{print $3}' | grep -vc '^skl_')" 0
expect "and all of it" "$(nm -D --defined-only "$LIB" | awk '{print $3}' | grep -c '^skl_')" 18

say() { python3 -c "
import socket,sys
s=socket.create_connection(('127.0.0.1',int(sys.argv[1])),5); s.sendall(sys.argv[2].encode()+b'\\n'); s.settimeout(5)
print(s.recv(99).decode().strip())" "$@" 2>&1 | tail -1; }
mcp() { python3 "$HERE/lib_mcp_call.py" "$@" 2>&1 | tail -1; }
wait_ready() { for _ in $(seq 1 300); do grep -q '^READY' "$T/$1.out" 2>/dev/null && return 0; kill -0 "$HOST" 2>/dev/null || return 1; sleep 0.1; done; return 1; }

case "$BINDIR" in
*Sanitize*) echo "  SKIP: a Rust or Node process carries no sanitizer runtime for the library to link" ;;
*)
P=$SL_PORT_BASE

# ── Rust ─────────────────────────────────────────────────────────────────────
# Not `command -v`: rustup installs a cargo that cannot run with HOME moved, as run_all moves it.
if cargo --version >/dev/null 2>&1; then
    if SOCKETLEY_LIB_DIR="$BINDIR" CARGO_TARGET_DIR="$T/target" cargo build -q --offline --examples \
         --manifest-path "$ROOT/sdk/rust/Cargo.toml" 2>"$T/cargo.err"; then
        ok
        "$T/target/debug/examples/mcp_tool" $((P+1)) > "$T/rust.out" 2>"$T/rust.err" &
        HOST=$!
        wait_ready rust || bad "the Rust program comes up" "$(tail -3 "$T/rust.out" "$T/rust.err" | cut -c1-240)"
        expect "Rust: its version is the tree's" "$(grep -m1 '^READY' "$T/rust.out")" "READY $("$BIN" --version | head -1)"
        expect "Rust: tools/list" "$(mcp $((P+1)) list)" "echo,failing,later,silent"
        expect "Rust: a closure answers in place" "$(mcp $((P+1)) call echo '{"a":1}')" 'args {"a":1} False'
        expect "Rust: and from a thread it moved the call to" "$(mcp $((P+1)) call later)" "from a thread False"
        expect "Rust: a failure says so" "$(mcp $((P+1)) call failing)" "it broke True"
        expect "Rust: a call dropped unanswered still gets an answer" "$(mcp $((P+1)) call silent)" "the tool did not answer True"
        kill -9 "$HOST" 2>/dev/null; wait "$HOST" 2>/dev/null; HOST=""
        "$T/target/debug/examples/echo_server" $((P+5)) > "$T/rust2.out" 2>"$T/rust2.err" &
        HOST=$!
        wait_ready rust2 || bad "the Rust server comes up" "$(tail -3 "$T/rust2.err" | cut -c1-240)"
        expect "Rust: a server answers on the connection" "$(say $((P+5)) hi)" "echo: hi"
        sleep 0.3
        expect "Rust: and was told it opened and went" "$(grep -c -E '^(OPEN|GONE) true' "$T/rust2.out")" 2
        kill -9 "$HOST" 2>/dev/null; wait "$HOST" 2>/dev/null; HOST=""
        mkdir -p "$T/pub"; echo plain > "$T/pub/a.txt"
        "$T/target/debug/examples/web_app" $((P+7)) "$T/pub" > "$T/rust3.out" 2>"$T/rust3.err" &
        HOST=$!
        wait_ready rust3 || bad "the Rust site comes up" "$(tail -3 "$T/rust3.err" | cut -c1-240)"
        expect "Rust: a handler, with a cache beside it" "$(curl -s -m 5 -d x "http://127.0.0.1:$((P+7))/api/a?b=1")" "POST /api/a b=1 hits 1 body x"
        expect "Rust: answered from a thread" "$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((P+7))/slow")" 202
        expect "Rust: a request dropped unanswered is a 500" "$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((P+7))/forgets")" 500
        expect "Rust: files still answer beside it" "$(curl -s -m 5 "http://127.0.0.1:$((P+7))/a.txt")" "plain"
        kill -9 "$HOST" 2>/dev/null; wait "$HOST" 2>/dev/null; HOST=""
    else
        bad "the crate builds" "$(head -8 "$T/cargo.err" | cut -c1-240)"
    fi
else
    echo "  SKIP: no cargo runs here"
fi

# ── Node ─────────────────────────────────────────────────────────────────────
if command -v node >/dev/null 2>&1 && [ -f "$(dirname "$(dirname "$(readlink -f "$(command -v node)")")")/include/node/node_api.h" ]; then
    NODEINC="$(dirname "$(dirname "$(readlink -f "$(command -v node)")")")/include/node"
    if gcc -std=gnu11 -Wall -Wextra -Werror -shared -fPIC "$ROOT/sdk/node/src/addon.c" -I"$NODEINC" -I"$ROOT/sdk/include/linux" \
         -L"$BINDIR" -lsocketley -Wl,-rpath,"$BINDIR" -o "$T/socketley.node" 2>"$T/addon.err"; then
        ok
        mkdir -p "$T/site"; echo 'echo("page from node")' > "$T/site/i.lua"
        cat > "$T/host.js" <<JS
const crypto = require('crypto');
const { Engine, version } = require('$ROOT/sdk/node');
const engine = new Engine();
const site = engine.runtime('web', 'site', '-p $((P+2)) --root $T/site --lua-pages').start();
const tools = engine.runtime('mcp', 'tools', '-p $((P+3)) --anonymous');
tools.tool('echo', { description: 'Echo.', input: { a: 'number' } }, ({ a }, caller) => 'a is ' + a + ' from [' + caller + ']');
tools.tool('later', {}, async () => { await new Promise((r) => setTimeout(r, 50)); return 'after a wait'; });
tools.tool('object', {}, () => ({ ok: true }));
tools.tool('throws', {}, () => { throw new Error('it broke'); });
tools.tool('hash', {}, () => crypto.createHash('sha256').update('x').digest('hex').slice(0, 8));
tools.start();
const lines = engine.runtime('server', 'lines', '-p $((P+6)) --mode in');
let opened = 0;
lines.on('connect', () => { opened++; });
lines.on('message', (c, d) => { lines.send(c, 'echo: ' + d.toString() + ' seen ' + opened); });
lines.start();
const kv = engine.runtime('cache', 'kv', '-p $((P+8))').start();
kv.command('set n 5');
const site2 = engine.runtime('web', 'site2', '-p $((P+9)) --root $T/site');
site2.handle('/api', async (q) => { await new Promise((r) => setTimeout(r, 10)); return { status: 201, headers: { 'X-From': 'node' }, body: q.method + ' ' + q.query + ' ' + q.body + ' n=' + kv.command('get n') }; });
site2.handle('/boom', () => { throw new Error('nope'); });
site2.start();
try { engine.runtime('web', 'bad', '--no-such-flag'); } catch (e) { console.log('CAUGHT', e.message); }
process.on('SIGTERM', () => { engine.close(); console.log('CLOSED'); });
console.log('READY', version);
JS
        node --check "$ROOT/sdk/node/examples/app.js" && ok || bad "Node: the example parses"
        SOCKETLEY_NODE_ADDON="$T/socketley.node" node "$T/host.js" > "$T/node.out" 2>"$T/node.err" &
        HOST=$!
        wait_ready node || bad "the Node program comes up" "$(tail -3 "$T/node.out" "$T/node.err" | cut -c1-240)"
        expect "Node: a refusal is a thrown error" "$(grep -m1 '^CAUGHT' "$T/node.out")" "CAUGHT unknown flag: --no-such-flag"
        expect "Node: a page served beside its JavaScript" "$(curl -s -m 5 "http://127.0.0.1:$((P+2))/i.lua")" "page from node"
        expect "Node: tools/list" "$(mcp $((P+3)) list)" "echo,hash,later,object,throws"
        expect "Node: a function answers with its arguments" "$(mcp $((P+3)) call echo '{"a":7}')" "a is 7 from [] False"
        expect "Node: an async function" "$(mcp $((P+3)) call later)" "after a wait False"
        expect "Node: an object is sent as JSON" "$(mcp $((P+3)) call object)" '{"ok":true} False'
        expect "Node: a throw is a failure of the tool" "$(mcp $((P+3)) call throws)" "it broke True"
        expect "Node: its own OpenSSL still works" "$(mcp $((P+3)) call hash)" "2d711642 False"
        expect "Node: a server's message reaches JavaScript and its answer the connection" "$(say $((P+6)) hi)" "echo: hi seen 1"
        expect "Node: an async handler, a cache beside it" "$(curl -s -m 5 -D - -d zz "http://127.0.0.1:$((P+9))/api?q=1" | grep -E '^HTTP|^X-From|n=' | tr -d '\r' | tr '\n' ' ')" "HTTP/1.1 201 Created X-From: node POST q=1 zz n=5 "
        expect "Node: a throw is a 500" "$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((P+9))/boom")" 500
        kill -TERM "$HOST"
        for _ in $(seq 1 100); do grep -q '^CLOSED' "$T/node.out" && break; sleep 0.1; done
        for _ in $(seq 1 100); do kill -0 "$HOST" 2>/dev/null || break; sleep 0.1; done
        if kill -0 "$HOST" 2>/dev/null; then bad "Node: the program ends once closed" "still running"; kill -9 "$HOST"; else ok; fi
        wait "$HOST" 2>/dev/null; HOST=""
        grep -q '^CLOSED' "$T/node.out" && ok || bad "Node: its own signal handler ran" "$(tail -2 "$T/node.err" | cut -c1-240)"
    else
        bad "the addon builds" "$(head -8 "$T/addon.err" | cut -c1-240)"
    fi
else
    echo "  SKIP: node and its headers are not on PATH"
fi
;;
esac

echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
