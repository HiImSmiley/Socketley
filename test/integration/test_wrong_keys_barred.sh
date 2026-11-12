#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# An address that keeps showing wrong keys to an mcp, a metrics or a db runtime is barred, as at every other sign-in.
#
# What each part would catch:
#   * a key of --keys guessed at without end from one address
#   * the right key still answered to a barred address, which would tell a guesser it has it
#   * one address's guesses shutting out another, or this machine's own 127.0.0.1
#   * a client behind the entrance counted as the entrance, or one that names its own X-Forwarded-For slipping the count
#   * a request with no key, or with a lapsed cookie, counted as a guess
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { [ "$2" = "$3" ] && ok || bad "$1" "got '$2', want '$3'"; }

echo "=== Integration: wrong keys from one address are counted at mcp, metrics and db ==="
command -v curl >/dev/null 2>&1 || { echo "  SKIP: curl is required"; exit 0; }
daemon_isolate wrongkeys
T=$SOCKETLEY_TMPD
PM=$((SL_PORT_BASE + 1950)); PR=$((SL_PORT_BASE + 1951)); PD=$((SL_PORT_BASE + 1952))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"

KEY=wrongkeysrightsecret0123
printf 'ops %s\n' "$KEY" > "$T/keys"; chmod 600 "$T/keys"
printf 'notes private\n' > "$T/schema"
"$BIN" create mcp m -p "$PM" --keys "$T/keys" -s >/dev/null 2>&1 || bad "the mcp runtime starts" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create metrics r -p "$PR" --keys "$T/keys" -s >/dev/null 2>&1 || bad "the metrics runtime starts" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create db d -p "$PD" --keys "$T/keys" --schema "$T/schema" -s >/dev/null 2>&1 || bad "the db runtime starts" "$(tail -3 "$SOCKETLEY_DLOG")"
for p in "$PM" "$PR" "$PD"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/")" != 000 ] && break; sleep 0.1; done
done

# ask <port> <path> <method> <source address> <key or -> [header]: the status one request is answered with.
ask() {
    local port=$1 path=$2 method=$3 from=$4 key=$5; shift 5
    local auth=()
    [ "$key" = "-" ] || auth=(-H "Authorization: Bearer $key")
    local body=()
    [ "$method" = "POST" ] && body=(-H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"ping"}')
    curl -s -o /dev/null -w '%{http_code}' --interface "$from" -X "$method" "${auth[@]}" "${body[@]}" "$@" \
        "http://127.0.0.1:$port$path"
}

# one <name> <port> <path> <method> <status the right key gets>
one() {
    local name=$1 port=$2 path=$3 method=$4 right=$5 i st
    expect "$name: the right key is taken from a new address" "$(ask "$port" "$path" "$method" 127.0.0.2 "$KEY")" "$right"
    # No key at all is no guess.
    for i in $(seq 1 12); do ask "$port" "$path" "$method" 127.0.0.2 - >/dev/null; done
    expect "$name: asking without a key is not counted" "$(ask "$port" "$path" "$method" 127.0.0.2 "$KEY")" "$right"
    for i in $(seq 1 10); do st=$(ask "$port" "$path" "$method" 127.0.0.2 "wrongkeywrongkey000$i"); done
    expect "$name: the tenth wrong key is still answered as wrong" "$st" 401
    expect "$name: the eleventh is told to wait" "$(ask "$port" "$path" "$method" 127.0.0.2 wrongkeywrongkey00011)" 429
    expect "$name: and so is the right key from that address" "$(ask "$port" "$path" "$method" 127.0.0.2 "$KEY")" 429
    expect "$name: another address is not shut out" "$(ask "$port" "$path" "$method" 127.0.0.3 "$KEY")" "$right"
    # This machine's own programs come from 127.0.0.1, and one of them with a stale key bars none of the others.
    for i in $(seq 1 12); do ask "$port" "$path" "$method" 127.0.0.1 "wrongkeywrongkey000$i" >/dev/null; done
    expect "$name: 127.0.0.1 is not counted" "$(ask "$port" "$path" "$method" 127.0.0.1 "$KEY")" "$right"
    # Behind the entrance the client is the hop it names last, whatever the client itself wrote before it.
    for i in $(seq 1 10); do
        ask "$port" "$path" "$method" 127.0.0.1 "wrongkeywrongkey000$i" -H "X-Forwarded-For: 198.51.100.$i, 203.0.113.9" >/dev/null
    done
    expect "$name: a client behind the entrance is barred by the hop the entrance names" \
        "$(ask "$port" "$path" "$method" 127.0.0.1 "$KEY" -H 'X-Forwarded-For: 203.0.113.9')" 429
    expect "$name: and another client behind it is not" \
        "$(ask "$port" "$path" "$method" 127.0.0.1 "$KEY" -H 'X-Forwarded-For: 203.0.113.10')" "$right"
    # A peer that is not the entrance names no client: its X-Forwarded-For does not move the count elsewhere.
    for i in $(seq 1 10); do
        ask "$port" "$path" "$method" 127.0.0.4 "wrongkeywrongkey000$i" -H "X-Forwarded-For: 192.0.2.$i" >/dev/null
    done
    expect "$name: a stranger's own X-Forwarded-For does not hide it" \
        "$(ask "$port" "$path" "$method" 127.0.0.4 "$KEY" -H 'X-Forwarded-For: 192.0.2.77')" 429
}

one mcp "$PM" /mcp POST 200
one metrics "$PR" /api/v1/labels GET 200
one db "$PD" /me GET 200

# A cookie is signed and no key: a browser that polls with a lapsed one is not barred for it.
for i in $(seq 1 12); do
    curl -s -o /dev/null --interface 127.0.0.5 -H 'Cookie: skl_idp=lapsed.lapsed.lapsed' "http://127.0.0.1:$PR/api/v1/labels"
done
expect "metrics: a lapsed cookie is not counted" "$(ask "$PR" /api/v1/labels GET 127.0.0.5 "$KEY")" 200

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
