#!/usr/bin/env bash
# suite: isolated -- no daemon at all, and a port window of its own
# Integration test: the C interface, from a program written in C.
#
# A host in another language can only reach what a plain C header offers, and it owns its process: its signals stay
# its own, nothing is written to its stdout, a refusal comes back as text.  So the program below is C compiled by gcc,
# keeps its own SIGTERM handler, runs two engines at once and answers an MCP tool both in the callback and from a
# thread of its own.  A reply after the runtime stopped has nobody to reach, and must be dropped.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_sdk.sh"
. "$HERE/lib_ports.sh"
ROOT=$(cd "$HERE/../.." && pwd)
BINDIR=$(dirname "$BIN")
CFG=$(basename "$BINDIR")

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: ${2:-}"; }
expect() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

echo "=== Integration: the SDK's C interface, from C ==="
if [ ! -f "$BINDIR/libsocketley_sdk.a" ]; then echo "  SKIP: $BINDIR/libsocketley_sdk.a is not built"; exit 0; fi
command -v gcc >/dev/null 2>&1 || { echo "  SKIP: gcc is required"; exit 0; }

T=$(mktemp -d /tmp/socketley-capi-XXXXXX)
HOST=""
cleanup() { [ -n "$HOST" ] && kill -9 "$HOST" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT

SANFLAGS=""
case "$BINDIR" in *Sanitize*) SANFLAGS="-fsanitize=address,undefined";; esac

cat > "$T/host.c" <<'C'
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <socketley/capi.h>

static volatile sig_atomic_t term;
static void on_term(int s) { (void)s; term = 1; }

static void add(void* user, skl_mcp_call* call, const char* args, const char* caller)
{
    (void)user; (void)caller;
    char text[512];
    snprintf(text, sizeof text, "args %s", args);
    skl_mcp_reply(call, text, 0);
}

static void* later_thread(void* arg)
{
    usleep(100000);
    skl_mcp_reply((skl_mcp_call*)arg, "from a thread", 0);
    return NULL;
}
static void later(void* user, skl_mcp_call* call, const char* args, const char* caller)
{
    (void)user; (void)args; (void)caller;
    pthread_t t;
    pthread_create(&t, NULL, later_thread, call);
    pthread_detach(t);
}

static void failing(void* user, skl_mcp_call* call, const char* args, const char* caller)
{
    (void)user; (void)args; (void)caller;
    skl_mcp_reply(call, "it broke", 1);
}

static skl_mcp_call* _Atomic held;
static void hold(void* user, skl_mcp_call* call, const char* args, const char* caller)
{
    (void)user; (void)args; (void)caller;
    held = call;
}

/* a server and a client of it, each told of its connections */
static skl_runtime* server_rt;
static skl_runtime* client_rt;
static _Atomic int opened, closed;
static char client_got[128];

static void on_open(void* user, skl_connection c) { (void)user; if (c) opened++; }
static void on_gone(void* user, skl_connection c) { (void)user; if (c) closed++; }

struct echo { skl_connection c; char text[200]; };
static void* echo_thread(void* arg)
{
    struct echo* e = arg;
    skl_send(server_rt, e->c, e->text, strlen(e->text));
    free(e);
    return NULL;
}
static void on_line(void* user, skl_connection c, const char* data, size_t n)
{
    (void)user;
    struct echo* e = malloc(sizeof *e);
    e->c = c;
    if (n == 2 && memcmp(data, "id", 2) == 0)
        snprintf(e->text, sizeof e->text, "%llu", c);
    else
        snprintf(e->text, sizeof e->text, "echo: %.*s", (int)n, data);
    pthread_t t;
    pthread_create(&t, NULL, echo_thread, e);
    pthread_detach(t);
}

static void client_open(void* user, skl_connection c)
{
    (void)user; (void)c;
    skl_send(client_rt, 1, "from client", 11);
}
static void client_line(void* user, skl_connection c, const char* data, size_t n)
{
    (void)user; (void)c;
    snprintf(client_got, sizeof client_got, "%.*s", (int)n, data);
}

static void* slow_thread(void* arg)
{
    usleep(50000);
    skl_web_reply(arg, 202, "Content-Type: text/plain\nX-From: thread", "later", 5);
    return NULL;
}
static void api(void* user, skl_web_request* r, const char* method, const char* path, const char* query,
                const char* headers, const char* body, size_t n)
{
    (void)user;
    if (strcmp(path, "/api/slow") == 0)
    {
        pthread_t t;
        pthread_create(&t, NULL, slow_thread, r);
        pthread_detach(t);
        return;
    }
    char text[600];
    int len = snprintf(text, sizeof text, "%s %s %s ua=%d body=%.*s", method, path, query, strstr(headers, "User-Agent:") != NULL, (int)n, n ? body : "");
    skl_web_reply(r, 200, "Content-Type: text/plain", text, (size_t)len);
}

static void say_err(const char* what, char* err)
{
    printf("ERR %s: %s\n", what, err ? err : "(none)");
    skl_free(err);
}

int main(int argc, char** argv)
{
    (void)argc;
    char flags[512], *err = NULL;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_term;
    sigaction(SIGTERM, &sa, NULL);

    skl_engine* one = skl_engine_new(&err);
    skl_engine* two = skl_engine_new(&err);
    if (!one || !two) { say_err("engine", err); return 2; }
    printf("VERSION %s\n", skl_version());

    snprintf(flags, sizeof flags, "-p %s --root %s --lua-pages", argv[1], argv[4]);
    skl_runtime* web = skl_runtime_create(one, "web", "site", flags, &err);
    if (!web || skl_web_handler(web, "/api", api, NULL, &err) || skl_runtime_start(web, &err)) { say_err("web", err); return 2; }

    snprintf(flags, sizeof flags, "-p %s --anonymous", argv[2]);
    skl_runtime* mcp = skl_runtime_create(one, "mcp", "tools", flags, &err);
    if (!mcp) { say_err("mcp", err); return 2; }
    if (skl_mcp_tool(mcp, "add", "Adds.", "{\"type\":\"object\"}", add, NULL, &err) ||
        skl_mcp_tool(mcp, "later", "From a thread.", NULL, later, NULL, &err) ||
        skl_mcp_tool(mcp, "failing", "Fails.", NULL, failing, NULL, &err) ||
        skl_mcp_tool(mcp, "hold", "Answers late.", NULL, hold, NULL, &err)) { say_err("tool", err); return 2; }
    if (skl_runtime_start(mcp, &err)) { say_err("mcp start", err); return 2; }

    snprintf(flags, sizeof flags, "-p %s --mode in", argv[5]);
    server_rt = skl_runtime_create(one, "server", "lines", flags, &err);
    if (!server_rt || skl_on_connect(server_rt, on_open, NULL, &err) || skl_on_disconnect(server_rt, on_gone, NULL, &err) ||
        skl_on_message(server_rt, on_line, NULL, &err) || skl_runtime_start(server_rt, &err)) { say_err("server", err); return 2; }
    snprintf(flags, sizeof flags, "-t 127.0.0.1:%s", argv[5]);
    client_rt = skl_runtime_create(one, "client", "out", flags, &err);
    if (!client_rt || skl_on_connect(client_rt, client_open, NULL, &err) || skl_on_message(client_rt, client_line, NULL, &err) ||
        skl_runtime_start(client_rt, &err)) { say_err("client", err); return 2; }

    snprintf(flags, sizeof flags, "-p %s", argv[3]);
    skl_runtime* cache = skl_runtime_create(two, "cache", "store", flags, &err);
    if (!cache || skl_runtime_start(cache, &err)) { say_err("cache", err); return 2; }
    skl_free(skl_cache_command(cache, "set k embedded", &err));
    char* got = skl_cache_command(cache, "get k", &err);
    printf("CACHE %s", got ? got : "none\n");
    if (got && got[strlen(got) - 1] != '\n') printf("\n");
    skl_free(got);
    if (skl_cache_command(web, "get k", &err)) return 3;
    say_err("command on web", err); err = NULL;
    if (skl_web_handler(cache, "/x", api, NULL, &err) == 0) return 3;
    say_err("handler on cache", err); err = NULL;

    /* what is refused comes back as text */
    if (skl_runtime_create(one, "web", "bad", "--no-such-flag", &err)) return 3;
    say_err("flag", err); err = NULL;
    if (skl_runtime_create(one, "nosuch", "bad", "", &err)) return 3;
    say_err("type", err); err = NULL;
    if (skl_runtime_create(one, "web", "site", "", &err)) return 3;
    say_err("name", err); err = NULL;
    if (skl_on_message(web, on_line, NULL, &err) == 0) return 3;
    say_err("hook on web", err); err = NULL;
    if (skl_send(server_rt, 999999, "x", 1) != 0) return 3;
    if (skl_mcp_tool(web, "x", "", NULL, add, NULL, &err) == 0) return 3;
    say_err("tool on web", err); err = NULL;
    snprintf(flags, sizeof flags, "-p %s --root %s", argv[1], argv[4]);
    skl_runtime* twice = skl_runtime_create(two, "web", "twice", flags, &err);
    if (!twice) { say_err("twice", err); return 2; }
    if (skl_runtime_start(twice, &err) == 0) return 3;
    printf("REFUSED port taken\n");
    skl_free(err); err = NULL;
    skl_runtime_free(twice);

    char* stats = skl_runtime_stats(mcp);
    printf("STATS %s", stats && strstr(stats, "tools:4") ? "tools:4\n" : "wrong\n");
    skl_free(stats);

    printf("READY\n");
    fflush(stdout);
    while (!term)
        usleep(10000);

    usleep(100000);
    printf("CLIENT GOT %s\n", client_got);
    printf("SERVER opened %d closed %d\n", (int)opened, (int)closed);
    skl_runtime_free(client_rt);
    skl_runtime_free(server_rt);

    /* an answer after the runtime is gone, its memory freed, has no one to reach */
    skl_runtime_free(mcp);
    usleep(200000);
    skl_runtime_free(web);
    usleep(50000);
    if (held) skl_mcp_reply(held, "late", 0);
    usleep(50000);

    skl_engine_free(one);
    skl_runtime_free(cache);
    skl_engine_free(two);
    printf("HOST HANDLER RAN\n");
    return 0;
}
C

CF=$("$ROOT/sdk/socketley-config" --config "$CFG" --cflags)
LB=$("$ROOT/sdk/socketley-config" --config "$CFG" --libs)
if ! gcc -std=c11 -Wall -Wextra -Werror $SANFLAGS -c "$T/host.c" $CF -o "$T/host.o" 2>"$T/gcc.err"; then
    bad "the header compiles as C" "$(head -5 "$T/gcc.err")"
    echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"; exit 1
fi
ok
if ! sdk_cxx "$T/host.o" $LB -o "$T/host" 2>"$T/gxx.err"; then
    bad "it links" "$(grep -m3 -E 'undefined|error' "$T/gxx.err" | cut -c1-220)"
    echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"; exit 1
fi
ok

P=$SL_PORT_BASE
mkdir -p "$T/site"; echo 'echo("embedded page")' > "$T/site/i.lua"
"$T/host" $((P+1)) $((P+2)) $((P+3)) "$T/site" $((P+4)) > "$T/out" 2>"$T/err" &
HOST=$!
for _ in $(seq 1 300); do grep -q '^READY' "$T/out" 2>/dev/null && break; kill -0 "$HOST" 2>/dev/null || break; sleep 0.1; done
grep -q '^READY' "$T/out" || bad "the host comes up" "$(tail -3 "$T/out" "$T/err" | cut -c1-240)"

line() { grep -m1 "^$1" "$T/out"; }
expect "the version is the tree's" "$(line VERSION)" "VERSION $("$BIN" --version | head -1)"
expect "an unknown flag comes back as text" "$(line 'ERR flag')" "ERR flag: unknown flag: --no-such-flag"
expect "an unknown type too" "$(line 'ERR type')" "ERR type: unknown runtime type: nosuch"
expect "a name in use too" "$(line 'ERR name')" "ERR name: name taken: site"
expect "a tool is only for an mcp runtime" "$(line 'ERR tool on web')" "ERR tool on web: not a runtime of type mcp"
expect "a port in use is a refused start" "$(line REFUSED)" "REFUSED port taken"
expect "tools are counted" "$(line STATS)" "STATS tools:4"
expect "nothing but the host wrote to its stdout" "$(grep -c -E '^(unknown|name taken|--)' "$T/out")" 0
expect "a page of a runtime on the first engine" "$(curl -s -m 5 "http://127.0.0.1:$((P+1))/i.lua")" "embedded page"
expect "a request under a handler's path is the program's" "$(curl -s -m 5 "http://127.0.0.1:$((P+1))/api/x?y=1")" "GET /api/x y=1 ua=1 body="
expect "with its body" "$(curl -s -m 5 -d hello "http://127.0.0.1:$((P+1))/api")" "POST /api  ua=1 body=hello"
expect "and answered from a thread, with its status and headers" \
    "$(curl -s -m 5 -D - "http://127.0.0.1:$((P+1))/api/slow" | grep -E '^HTTP|^X-From|^later' | tr -d '\r' | tr '\n' ' ')" "HTTP/1.1 202 Accepted X-From: thread later "
expect "a path that only begins like it is not" "$(curl -s -o /dev/null -w '%{http_code}' -m 5 "http://127.0.0.1:$((P+1))/apix")" 404
expect "a cache command from the program" "$(line CACHE)" "CACHE embedded"
expect "a command is only for a cache" "$(line 'ERR command on web')" "ERR command on web: not a runtime of type cache"
expect "a handler is only for a web runtime" "$(line 'ERR handler on cache')" "ERR handler on cache: not a runtime of type web"
if command -v redis-cli >/dev/null 2>&1; then :; fi
expect "the second engine serves beside it" \
    "$(python3 -c "
import socket,sys
s=socket.create_connection(('127.0.0.1',$((P+3))),5); s.sendall(b'set k v\r\nget k\r\n'); s.settimeout(3)
d=b''
try:
    while b'v' not in d: d+=s.recv(99)
except Exception: pass
print('v' in d.decode())")" True

python3 - $((P+2)) > "$T/mcp.out" 2>&1 <<'PY'
import json, sys, threading, urllib.request
port = sys.argv[1]
def call(method, params=None, name=None, timeout=8):
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
         "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method}
    if name: h["Mcp-Name"] = name
    body = {"jsonrpc": "2.0", "id": 1, "method": method}
    meta = {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientInfo": {"name": "t", "version": "1"},
            "io.modelcontextprotocol/clientCapabilities": {}}
    body["params"] = dict(params or {}); body["params"]["_meta"] = meta
    r = urllib.request.Request(f"http://127.0.0.1:{port}/mcp", data=json.dumps(body).encode(), headers=h)
    return json.load(urllib.request.urlopen(r, timeout=timeout))
def tool(name, args=None):
    return call("tools/call", {"name": name, "arguments": args or {}}, name=name)["result"]
names = sorted(t["name"] for t in call("tools/list")["result"]["tools"])
print("LIST", names)
r = tool("add", {"a": 1})
print("ADD", r["content"][0]["text"], r.get("isError", False))
r = tool("later")
print("LATER", r["content"][0]["text"])
r = tool("failing")
print("FAILING", r["content"][0]["text"], r.get("isError"))
out = []
ts = [threading.Thread(target=lambda: out.append(tool("later")["content"][0]["text"])) for _ in range(8)]
[t.start() for t in ts]; [t.join() for t in ts]
print("MANY", len(out), set(out))
threading.Thread(target=lambda: call("tools/call", {"name": "hold", "arguments": {}}, name="hold", timeout=3), daemon=True).start()
import time; time.sleep(0.5)
print("DONE")
PY
m() { grep -m1 "^$1" "$T/mcp.out"; }
expect "tools/list has what the program declared" "$(m LIST)" "LIST ['add', 'failing', 'hold', 'later']"
expect "a tool gets its arguments and answers in the callback" "$(m ADD)" 'ADD args {"a":1} False'
expect "a tool answers from a thread of the program" "$(m LATER)" "LATER from a thread"
expect "a tool that failed says so" "$(m FAILING)" "FAILING it broke True"
expect "eight at once all get theirs" "$(m MANY)" "MANY 8 {'from a thread'}"
grep -q '^DONE' "$T/mcp.out" || bad "the client ran through" "$(tail -4 "$T/mcp.out" | cut -c1-260)"

expect "a hook is only for a server or client" "$(line 'ERR hook on web')" "ERR hook on web: not a runtime of type server or client"
expect "a server answers from a thread of the program, on the connection the line came on" \
    "$(python3 -c "
import socket
s=socket.create_connection(('127.0.0.1',$((P+4))),5); s.sendall(b'hello\\n'); s.settimeout(5)
print(s.recv(99).decode().strip())")" "echo: hello"

# The kernel gives the next connection the descriptor the last one closed, and its number must still be new.
ask_id() { python3 -c "
import socket
s=socket.create_connection(('127.0.0.1',$((P+4))),5); s.sendall(b'id\\n'); s.settimeout(5)
print(s.recv(99).decode().strip())"; }
first=$(ask_id); sleep 0.2; second=$(ask_id)
if [ -n "$first" ] && [ "$first" != "$second" ]; then ok; else bad "a connection after one that closed has a number of its own" "'$first' and '$second'"; fi

kill -TERM "$HOST"
for _ in $(seq 1 200); do kill -0 "$HOST" 2>/dev/null || break; sleep 0.1; done
wait "$HOST"; rc=$?; HOST=""
expect "a client runtime heard the server" "$(line 'CLIENT GOT')" "CLIENT GOT echo: from client"
expect "the server told of both connections, and of the one that closed" "$(line 'SERVER')" "SERVER opened 4 closed 3"
expect "the host ends by its own handler, the engines freed, a late answer dropped" "$rc $(grep -c 'HOST HANDLER RAN' "$T/out")" "0 1"
[ -z "$SANFLAGS" ] || expect "and the sanitizer saw nothing" "$(grep -c -E 'ERROR: (Address|Leak)Sanitizer|runtime error:' "$T/err")" 0

echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
