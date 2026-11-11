#!/usr/bin/env bash
# suite: isolated -- no daemon at all, and a port window of its own
# Integration test: every runtime type runs embedded, by the flags `socketley create` takes.
#
# The typed classes cover four of the types, and the SDK's other reach was the daemon's.  any_runtime and flags() read
# a create line with the daemon's parsers, so what is held down here is that a program linked against the archive
# gets a runtime that serves, that a refused flag is refused, and that the Lua-less archive links at all.
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

echo "=== Integration: every runtime type embedded through the SDK ==="
if [ ! -f "$BINDIR/libsocketley_sdk.a" ]; then echo "  SKIP: $BINDIR/libsocketley_sdk.a is not built"; exit 0; fi

T=$(mktemp -d /tmp/socketley-anyrt-XXXXXX)
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done; rm -rf "$T"; }
trap cleanup EXIT

SANFLAGS=""
case "$BINDIR" in *Sanitize*) SANFLAGS="-fsanitize=address,undefined";; esac

sdk_cxx "$ROOT/sdk/examples/basic/any_runtime.cpp" $("$ROOT/sdk/socketley-config" --config "$CFG" --cflags --libs) -o "$T/any" 2>"$T/gxx.err" ||
    { bad "the example builds" "$(head -5 "$T/gxx.err")"; echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"; exit 1; }

cat > "$T/typed.cpp" <<'CPP'
#include <socketley/server.h>
int main(int, char** argv)
{
    socketley::server srv(static_cast<uint16_t>(atoi(argv[1])));
    srv.flags(argv[2]);
    return srv.start() ? 0 : 1;
}
CPP
sdk_cxx "$T/typed.cpp" $("$ROOT/sdk/socketley-config" --config "$CFG" --cflags --libs) -o "$T/typed" 2>"$T/gxx.err" ||
    bad "a typed class with flags() builds" "$(head -5 "$T/gxx.err")"

mkdir -p "$T/site" "$T/files" "$T/here" "$T/home"
echo 'echo("page ok")' > "$T/site/i.lua"
printf 'cli secretsecretsecretsecret http://127.0.0.1:1/cb\n' > "$T/clients"
printf 'backend dbbackendsecret0123456789\n' > "$T/keys"; chmod 600 "$T/keys"
printf 'access_key = anyrtaccess\nsecret_key = anyrtsecretsecretsecret\n' > "$T/creds"; chmod 600 "$T/creds"
printf '$ORIGIN t.test.\n$TTL 60\n@ IN SOA ns.t.test. h.t.test. 1 60 60 60 60\n@ IN NS ns.t.test.\nns IN A 127.0.0.1\n' > "$T/t.zone"

listening() { ss -ltnuH 2>/dev/null | grep -q "[:.]$1 "; }
wait_port() { local n=0; until listening "$1"; do n=$((n+1)); [ "$n" -gt 300 ] && return 1; sleep 0.1; done; }

# Up, listening where it should, and gone with exit 0 on SIGTERM.
embedded() {   # type port flags
    local type=$1 port=$2 flags=$3
    ( cd "$T"; exec env HOME="$T/home" "$T/any" "$type" "x_$type" "$flags" ) > "$T/o.$type" 2>&1 &
    local pid=$!
    PIDS+=("$pid")
    if [ -n "$port" ]; then
        wait_port "$port" && ok || bad "$type listens" "$(head -3 "$T/o.$type")"
    else
        sleep 1.5
    fi
    if kill -0 "$pid" 2>/dev/null; then ok; else bad "$type stays up" "$(head -3 "$T/o.$type")"; fi
    [ "$type" != web ] || expect "a web runtime answers a .lua page" "$(curl -s -m 5 "http://127.0.0.1:$port/i.lua")" "page ok"
    kill -TERM "$pid" 2>/dev/null
    wait "$pid"; expect "$type ends on SIGTERM" "$?" 0
}

P=$SL_PORT_BASE
embedded server  $((P+1))  "-p $((P+1))"
embedded client  ""        "-t 127.0.0.1:1"
embedded proxy   $((P+2))  "-p $((P+2)) --backend 127.0.0.1:1"
embedded cache   $((P+3))  "-p $((P+3))"
embedded web     $((P+4))  "-p $((P+4)) --root $T/site --lua-pages"
embedded storage $((P+5))  "-p $((P+5)) --dir $T/files --anonymous"
embedded sync    ""        "--dir $T/here --storage 127.0.0.1:$((P+5))/docs --credentials $T/creds --mode in --every 2s"
embedded idp     $((P+6))  "-p $((P+6)) --clients $T/clients --issuer http://127.0.0.1:$((P+6))"
embedded db      $((P+7))  "-p $((P+7)) --keys $T/keys"
embedded dns     $((P+8))  "-p $((P+8)) --bind 127.0.0.1 --zone $T/t.zone --rrl 0 --proxy none"
embedded mqtt    $((P+9))  "-p $((P+9)) --anonymous"
embedded mail    $((P+10)) "-p $((P+10)) --mail-domain t.test --hostname m.t.test"
embedded tunnel  $((P+11)) "--mode edge -p $((P+11))"
embedded metrics $((P+12)) "-p $((P+12)) --every 1s"
embedded mcp     $((P+13)) "-p $((P+13)) --anonymous"

# ── flags() on a typed class ─────────────────────────────────────────────────
"$T/typed" $((P+14)) "--bind 127.0.0.1" > "$T/o.typed" 2>&1 &
pid=$!; PIDS+=("$pid")
wait_port $((P+14)) && ok || bad "flags() reaches a flag the class has no setter for" "$(head -3 "$T/o.typed")"
expect "and it took effect" "$(ss -ltnH "sport = :$((P+14))" | awk '{print $4}')" "127.0.0.1:$((P+14))"
kill -TERM "$pid" 2>/dev/null; wait "$pid"
out=$("$T/typed" $((P+15)) "--no-such-flag" 2>&1); rc=$?
expect "a flag flags() refuses stops start()" "$rc $(echo "$out" | grep -c 'unknown flag: --no-such-flag')" "1 1"

# ── what is refused ──────────────────────────────────────────────────────────
out=$("$T/any" web x "--no-such-flag" 2>&1); rc=$?
expect "an unknown flag is refused" "$rc $(echo "$out" | grep -c 'unknown flag')" "1 1"
out=$("$T/any" cache x "-p $((P+16)) --shards 2" 2>&1); rc=$?
expect "--shards is refused, there being no daemon to fork them" "$rc $(echo "$out" | grep -c 'forked by the daemon')" "1 1"
out=$("$T/any" nosuch x 2>&1); rc=$?
expect "an unknown type is refused" "$rc $(echo "$out" | grep -c 'unknown runtime type')" "1 1"
expect "the SDK says the version of the tree" "$("$ROOT/sdk/socketley-config" --version)" "$("$BIN" --version | head -1)"

# ── the library without Lua ──────────────────────────────────────────────────
if [ -f "$BINDIR/libsocketley_sdk_nolua.a" ]; then
    if sdk_cxx "$ROOT/sdk/examples/basic/any_runtime.cpp" $("$ROOT/sdk/socketley-config" --config "$CFG" --no-lua --cflags --libs) \
         -o "$T/any_nolua" 2>"$T/gxx.err"; then
        ok
        "$T/any_nolua" cache x_nolua "-p $((P+17))" > "$T/o.nolua" 2>&1 &
        pid=$!; PIDS+=("$pid")
        wait_port $((P+17)) && ok || bad "the Lua-less library serves" "$(head -3 "$T/o.nolua")"
        kill -TERM "$pid" 2>/dev/null; wait "$pid"; expect "and ends on SIGTERM" "$?" 0
    else
        bad "the Lua-less library links" "$(grep -m3 -E 'undefined|error' "$T/gxx.err" | cut -c1-200)"
    fi
fi

echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
