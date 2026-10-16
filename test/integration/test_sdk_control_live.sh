#!/usr/bin/env bash
# Integration test: every Tier-1 SDK function, executed against a live daemon.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# control.h has 67 functions and the suite called none of them.  test_sdk_
# control.cpp is a compile cover -- its body is `if (false) { ... }`, which
# proves the symbols exist and nothing else -- so eight of them shipped sending
# commands no daemon has ever had:
#
#     restart()      exit=1  unknown command: restart
#     version()      exit=1  unknown command: version
#     cluster_ls()   exit=1  unknown command: cluster
#
# measured against a 1.1.0 daemon.  restart and version are CLI-side
# constructions and the cluster subcommands are CLI renderings over the cluster
# directory; none is a daemon verb, and none ever was.
#
# ─── WHAT MAKES IT STAY COMPLETE ────────────────────────────────────────────
#
# The last assertion reads the header and fails if it declares a function this
# file does not call.  A test that covers 67 of 68 looks identical to one that
# covers all of them on the day the 68th is added, and this API's whole failure
# mode is a function nobody ever ran.
#
# The load-bearing assertion is not "everything exits 0" -- plenty of these
# refuse for good reasons here (no cluster is configured, /nonexistent is not a
# file).  It is that no reply is the daemon's "unknown command", because a
# wrong verb and a legitimate refusal are indistinguishable from the exit code
# alone.  That is exactly how these eight went unnoticed.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_sdk.sh"
ROOT=$(cd "$HERE/../.." && pwd)
BINDIR=$(dirname "$BIN")

daemon_isolate sdkctl

PORT=$((SL_PORT_BASE+1480))
PASS=0; FAIL=0; TOTAL=0

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: every Tier-1 SDK function against a live daemon ==="

if ! command -v g++ >/dev/null 2>&1; then echo "  SKIP: g++ is required"; exit 0; fi
if [ ! -f "$BINDIR/libsocketley_sdk.a" ]; then
    echo "  SKIP: $BINDIR/libsocketley_sdk.a is not built"; exit 0
fi

cat > "$SOCKETLEY_TMPD/probe.cpp" <<'PROBE_EOF'

// Every ctl:: function, called for real against a live daemon.  One line per
// function: name, exit code, first line of the reply.
#include <socketley/control.h>
#include <socketley/attach.h>
#include <cstdio>
#include <string>

static void say(const char* name, const socketley::result& r)
{
    // The whole reply on one line: an assertion about `ls` has to see past the
    // header row, and a tab-separated record cannot carry a newline.
    std::string flat = r.data;
    for (char& c : flat) if (c == '\n' || c == '\t') c = ' ';
    while (!flat.empty() && flat.back() == ' ') flat.pop_back();
    printf("%s\t%d\t%s\n", name, r.exit_code, flat.c_str());
}
#define P(fn, call) say(fn, (call))

int main(int argc, char** argv)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    const std::string port = argc > 1 ? argv[1] : "19900";
    const std::string sock = argc > 2 ? argv[2] : "";
    const std::string SRV = "sdkctl_srv";
    const std::string CSH = "sdkctl_cache";
    const std::string TMP = "sdkctl_tmp";

    // ── the raw escape hatch, both spellings ────────────────────────────
    P("command",        socketley::ctl::command("ls"));
    P("command_sock",   socketley::ctl::command(sock, "ls"));
    P("ipc_send",       socketley::detail::ipc_send(sock, "ls"));

    // ── lifecycle, on a runtime this probe owns end to end ──────────────
    P("create",         socketley::ctl::create("server", TMP, "-p " + port));
    P("start",          socketley::ctl::start(TMP));
    P("edit",           socketley::ctl::edit(TMP, "--max-connections 64"));
    P("reload",         socketley::ctl::reload(TMP));
    P("reload_lua",     socketley::ctl::reload_lua(TMP));
    P("restart",        socketley::ctl::restart(TMP));
    P("owner",          socketley::ctl::owner(TMP));
    P("stats",          socketley::ctl::stats(TMP));
    P("show",           socketley::ctl::show(TMP));
    P("send",           socketley::ctl::send(TMP, "hello"));
    P("stop",           socketley::ctl::stop(TMP));
    P("remove",         socketley::ctl::remove(TMP));

    // ── listings and identity ──────────────────────────────────────────
    P("ls",             socketley::ctl::ls());
    P("ps",             socketley::ctl::ps());
    P("ping",           socketley::ctl::ping());
    P("version",        socketley::ctl::version());
    P("dashboard",      socketley::ctl::dashboard());
    P("add",            socketley::ctl::add("/nonexistent/runtime.json"));
    P("import_runtime", socketley::ctl::import_runtime(SRV, "{}"));

    // ── daemon and cluster ─────────────────────────────────────────────
    P("daemon_name",    socketley::ctl::daemon_name());
    P("cluster_dir",    socketley::ctl::cluster_dir());
    P("cluster_status", socketley::ctl::cluster_status());
    P("cluster_ls",     socketley::ctl::cluster_ls());
    P("cluster_show",   socketley::ctl::cluster_show("nobody"));
    P("cluster_ps",     socketley::ctl::cluster_ps());
    P("cluster_group",  socketley::ctl::cluster_group("api"));
    P("cluster_stats",  socketley::ctl::cluster_stats("nobody"));
    P("cluster_watch",  socketley::ctl::cluster_watch());

    // ── the cache surface, against a live cache runtime ────────────────
    P("cache_set",      socketley::ctl::cache_set(CSH, "k", "v"));
    P("cache_get",      socketley::ctl::cache_get(CSH, "k"));
    P("cache_exists",   socketley::ctl::cache_exists(CSH, "k"));
    P("cache_append",   socketley::ctl::cache_append(CSH, "k", "w"));
    P("cache_mset",     socketley::ctl::cache_mset(CSH, {{"a","1"},{"b","2"}}));
    P("cache_mget",     socketley::ctl::cache_mget(CSH, {"a","b"}));
    P("cache_keys",     socketley::ctl::cache_keys(CSH));
    P("cache_size",     socketley::ctl::cache_size(CSH));
    P("cache_memory",   socketley::ctl::cache_memory(CSH));
    P("cache_incr",     socketley::ctl::cache_incr(CSH, "n"));
    P("cache_incrby",   socketley::ctl::cache_incrby(CSH, "n", 5));
    P("cache_decr",     socketley::ctl::cache_decr(CSH, "n"));
    P("cache_decrby",   socketley::ctl::cache_decrby(CSH, "n", 2));
    P("cache_expire",   socketley::ctl::cache_expire(CSH, "k", 60));
    P("cache_ttl",      socketley::ctl::cache_ttl(CSH, "k"));
    P("cache_persist",  socketley::ctl::cache_persist(CSH, "k"));
    P("cache_lpush",    socketley::ctl::cache_lpush(CSH, "L", "x"));
    P("cache_rpush",    socketley::ctl::cache_rpush(CSH, "L", "y"));
    P("cache_llen",     socketley::ctl::cache_llen(CSH, "L"));
    P("cache_lindex",   socketley::ctl::cache_lindex(CSH, "L", 0));
    P("cache_lrange",   socketley::ctl::cache_lrange(CSH, "L", 0, -1));
    P("cache_lpop",     socketley::ctl::cache_lpop(CSH, "L"));
    P("cache_rpop",     socketley::ctl::cache_rpop(CSH, "L"));
    P("cache_sadd",     socketley::ctl::cache_sadd(CSH, "S", "m"));
    P("cache_sismember",socketley::ctl::cache_sismember(CSH, "S", "m"));
    P("cache_scard",    socketley::ctl::cache_scard(CSH, "S"));
    P("cache_smembers", socketley::ctl::cache_smembers(CSH, "S"));
    P("cache_srem",     socketley::ctl::cache_srem(CSH, "S", "m"));
    P("cache_hset",     socketley::ctl::cache_hset(CSH, "H", "f", "v"));
    P("cache_hget",     socketley::ctl::cache_hget(CSH, "H", "f"));
    P("cache_hlen",     socketley::ctl::cache_hlen(CSH, "H"));
    P("cache_hgetall",  socketley::ctl::cache_hgetall(CSH, "H"));
    P("cache_hdel",     socketley::ctl::cache_hdel(CSH, "H", "f"));
    P("cache_publish",  socketley::ctl::cache_publish(CSH, "chan", "msg"));
    P("cache_del",      socketley::ctl::cache_del(CSH, "k"));
    P("cache_load",     socketley::ctl::cache_load(CSH, "/nonexistent/dump"));
    P("cache_flush",    socketley::ctl::cache_flush(CSH));

    // ── Tier 3, which has no result type of its own ────────────────────
    const bool att = socketley::daemon_attach(
        "sdkctl_att", "server",
        static_cast<uint16_t>(std::stoi(port) + 3), "");
    printf("daemon_attach\t%d\t%s\n", att ? 0 : 1,
           att ? "attached" : socketley::attach_error().c_str());
    socketley::daemon_detach("sdkctl_att");
    printf("daemon_detach\t0\tdetached\n");
    return 0;
}
PROBE_EOF

SANFLAGS=""
case "$BINDIR" in *Sanitize*) SANFLAGS="-fsanitize=address,undefined";; esac

if sdk_cxx "$SOCKETLEY_TMPD/probe.cpp" \
     -I"$ROOT" -I"$ROOT/include/linux" \
     -isystem "$ROOT/thirdparty/sol2" -isystem "$ROOT/thirdparty/luajit" \
     -o "$SOCKETLEY_TMPD/probe" 2>"$SOCKETLEY_TMPD/gxx.err"
then ok
else
    bad "the probe builds against control.h" "$(tail -5 "$SOCKETLEY_TMPD/gxx.err")"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
    exit 1
fi

daemon_start "$BIN"

"$BIN" create server sdkctl_srv   -p $((PORT+1)) -s </dev/null >/dev/null 2>&1
"$BIN" create cache  sdkctl_cache -p $((PORT+2)) -s </dev/null >/dev/null 2>&1
sleep 0.5

OUT=$("$SOCKETLEY_TMPD/probe" "$PORT" "$SOCKETLEY_SOCKET" 2>&1)
printf '%s\n' "$OUT" > "$SOCKETLEY_TMPD/probe.out"

reply() { awk -F'\t' -v n="$1" '$1==n {print $3}' "$SOCKETLEY_TMPD/probe.out"; }
code()  { awk -F'\t' -v n="$1" '$1==n {print $2}' "$SOCKETLEY_TMPD/probe.out"; }

if [ "$(grep -c . "$SOCKETLEY_TMPD/probe.out")" -gt 60 ]; then ok; else
    bad "the probe ran and answered for every call" \
        "$(grep -c . "$SOCKETLEY_TMPD/probe.out") lines" "$OUT"
fi

# ── The one that matters: no function sends a verb the daemon has not got ───
UNKNOWN=$(awk -F'\t' '$3 ~ /^unknown command/ { print "  " $1 " -> " $3 }' "$SOCKETLEY_TMPD/probe.out")
if [ -z "$UNKNOWN" ]; then ok; else
    bad "no Tier-1 function sends a command the daemon does not have" \
        "$(grep -c . <<<"$UNKNOWN") of them do:" $UNKNOWN
fi

# Same shape, one level down: a flag the daemon parses but does not know.
BADFLAG=$(awk -F'\t' '$3 ~ /^unknown flag|^unknown format|^unknown type/ { print "  " $1 " -> " $3 }' "$SOCKETLEY_TMPD/probe.out")
if [ -z "$BADFLAG" ]; then ok; else
    bad "and none sends a flag it does not have either" $BADFLAG
fi

# ── Positive answers, so this is not only a negative test ───────────────────
case "$(reply ping)" in socketley-daemon*) ok;;
    *) bad "ping identifies the daemon" "said: $(reply ping)";; esac

case "$(reply version)" in [0-9]*) ok;;
    *) bad "version returns a version, not a refusal" "said: $(reply version)";; esac

if [ "$(code create)" = "0" ] && [ "$(code start)" = "0" ] &&
   [ "$(code stop)" = "0" ] && [ "$(code remove)" = "0" ]; then ok; else
    bad "the create/start/stop/remove lifecycle works through the SDK" \
        "create=$(code create) start=$(code start) stop=$(code stop) remove=$(code remove)"
fi

# restart is stop-then-start in the header, not a daemon verb; it has to work
# on a live runtime and refuse a name that is not there.
if [ "$(code restart)" = "0" ]; then ok; else
    bad "restart works on a runtime that exists" \
        "exit $(code restart), said: $(reply restart)"
fi

case "$(reply ls)" in *sdkctl_srv*) ok;;
    *) bad "ls returns the runtimes" "said: $(reply ls)";; esac

if [ "$(code cache_set)" = "0" ] && [ "$(reply cache_get)" = "v" ]; then ok; else
    bad "a cache round-trips through the SDK" \
        "set=$(code cache_set) get=[$(reply cache_get)]"
fi

if [ "$(reply cache_mget)" != "" ] && [ "$(code cache_mset)" = "0" ]; then ok; else
    bad "mset/mget answer" "mset=$(code cache_mset) mget=[$(reply cache_mget)]"
fi

# The four that are refused on purpose: terminal CLI renderings a library
# cannot honestly perform.  They must refuse locally, with a recipe -- not by
# sending something.
REFUSED=0
for f in cluster_ps cluster_group cluster_stats cluster_watch; do
    case "$(reply $f)" in
        ""|unknown*) ;;
        *) REFUSED=$((REFUSED+1));;
    esac
done
if [ "$REFUSED" -eq 4 ]; then ok; else
    bad "the four terminal cluster renderings refuse by name" \
        "$REFUSED of 4 gave a reason" \
        "cluster_ps: $(reply cluster_ps)" \
        "cluster_watch: $(reply cluster_watch)"
fi

if [ "$(code daemon_attach)" = "0" ]; then ok; else
    bad "Tier 3 attaches to the daemon" "said: $(reply daemon_attach)"
fi

# ── And it stays complete ───────────────────────────────────────────────────
#
# Read from the header rather than a list kept here, because a list here is a
# thing to forget to update on exactly the commit that adds the 68th function.
MISSING=""
while read -r fn; do
    grep -q "^$fn	" "$SOCKETLEY_TMPD/probe.out" || MISSING="$MISSING $fn"
done < <(grep -oP '^inline result \K[a-z_0-9]+' "$ROOT/include/linux/socketley/control.h" | sort -u)

if [ -z "$MISSING" ]; then ok; else
    bad "every function control.h declares is called here" \
        "never called:$MISSING" \
        "a function nobody runs is how the eight broken ones shipped"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
