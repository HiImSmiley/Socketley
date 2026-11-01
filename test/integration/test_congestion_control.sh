#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: --congestion sets the TCP congestion control of every connection a runtime accepts.
#
# What each part would catch:
#   * the option set nowhere, or on a socket its connections do not inherit it from, for each of the four listeners
#   * a name that is no name, or the flag on a runtime whose listener never reads it, taken without a word
#   * a name the kernel refuses started anyway on the kernel's default, with nobody told
#   * the choice lost when the runtime is written to its state
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }
has() { if printf '%s' "$2" | grep -qE -- "$3"; then ok; else bad "$1" "no /$3/ in: $(printf '%s' "$2" | head -c 400)"; fi; }

echo "=== Integration: --congestion is the congestion control of every accepted connection ==="
command -v ss >/dev/null 2>&1 || { echo "  SKIP: ss is required"; exit 0; }
daemon_isolate congest
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1990))
unset SOCKETLEY_CONFIG
trap 'exec 3>&- 4>&- 2>/dev/null; daemon_stop' EXIT
daemon_start "$BIN"
mkdir -p "$T/www"; printf 'x' > "$T/www/a.txt"

# reno is in every kernel and in the default allowed list, and is nobody's default.
default_cc=$(cat /proc/sys/net/ipv4/tcp_congestion_control)
[ "$default_cc" != reno ] || { echo "  SKIP: the kernel's default is reno, so nothing would tell the two apart"; exit 0; }

# The congestion control ss reports for the accepted side of a connection held open to `port`.
cc_of() {
    local port=$1 out=""
    exec 3<>"/dev/tcp/127.0.0.1/$port" || { echo none; return; }
    for _ in $(seq 1 20); do
        out=$(ss -tinH state established "( sport = :$port )" 2>/dev/null | tr ' \t' '\n\n' | grep -xE 'reno|cubic|bbr|[a-z_]+cc' | head -1)
        [ -n "$out" ] && break
        sleep 0.05
    done
    exec 3>&-
    echo "${out:-none}"
}
up() { for _ in $(seq 1 50); do ss -ltnH "( sport = :$1 )" 2>/dev/null | grep -q . && return 0; sleep 0.1; done; return 1; }

"$BIN" create server srvc -p "$P" --http "$T/www" --congestion reno -s >/dev/null 2>&1; up "$P"
expect "a server's connections run its --congestion" "$(cc_of "$P")" "reno"
"$BIN" create proxy prxc -p $((P+1)) --backend "127.0.0.1:$P" --congestion reno -s >/dev/null 2>&1; up $((P+1))
expect "a proxy's connections run its --congestion" "$(cc_of $((P+1)))" "reno"
"$BIN" create cache cchc -p $((P+2)) --congestion reno -s >/dev/null 2>&1; up $((P+2))
expect "a cache's connections run its --congestion" "$(cc_of $((P+2)))" "reno"
"$BIN" create storage stgc -p $((P+3)) --dir "$T/stg" --anonymous --congestion reno -s >/dev/null 2>&1; up $((P+3))
expect "a storage's connections run its --congestion" "$(cc_of $((P+3)))" "reno"
"$BIN" create server srvd -p $((P+4)) --http "$T/www" -s >/dev/null 2>&1; up $((P+4))
expect "and without it the kernel's default" "$(cc_of $((P+4)))" "$default_cc"

out=$("$BIN" create server badname -p $((P+5)) --congestion 'BBR!' 2>&1); rc=$?
expect "a name that is no name is refused" "$rc" "1"
has "and says what it wants" "$out" 'congestion control'
out=$("$BIN" create client cl -p "$P" --congestion reno 2>&1); rc=$?
expect "a client is refused it" "$rc" "1"
out=$("$BIN" create mqtt mq -p $((P+6)) --congestion reno 2>&1); rc=$?
expect "and a runtime whose listener never reads it" "$rc" "1"

"$BIN" create server nosuch -p $((P+7)) --http "$T/www" --congestion nosuchcc -s >/dev/null 2>&1
for _ in $(seq 1 50); do grep -q 'congestion nosuchcc was refused' "$SOCKETLEY_DLOG" 2>/dev/null && break; sleep 0.1; done
has "a name the kernel refuses is said in the log" "$(cat "$SOCKETLEY_DLOG")" 'congestion nosuchcc was refused: .*no such congestion control'
if ss -ltnH "( sport = :$((P+7)) )" 2>/dev/null | grep -q .; then
    bad "and the runtime does not start on the default instead" "port $((P+7)) is listening"
else ok; fi

has "--congestion is kept in the runtime's state" "$(grep -rl '"name": *"srvc"' "$HOME" 2>/dev/null | head -1 | xargs cat 2>/dev/null)" '"congestion": *"reno"'

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
