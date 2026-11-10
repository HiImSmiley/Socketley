#!/usr/bin/env bash
# Integration test: a web page's sessions in a cache runtime, socketley.cache.command, and a password hash off the loop
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# session.open reads the table its cookie names from a cache runtime and
# session.save writes it back, so a sign-in survives the next request and every
# shard of the site.  What would be wrong and quiet: an id the client picked
# taken as its session, a regenerated session still reachable by its old id, a
# destroyed one still read, or a password hash that holds every other request
# of the runtime for the tens of milliseconds scrypt takes.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate websess

P=$((SL_PORT_BASE+1991)); CP=$((SL_PORT_BASE+1992))
NAMES="sessweb sesscache"
W="$SOCKETLEY_TMPD/www"
JAR="$SOCKETLEY_TMPD/jar"
mkdir -p "$W"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

cleanup() {
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: page sessions, socketley.cache and password hashes ==="

get() { curl -s --max-time 5 -b "$JAR" -c "$JAR" "http://127.0.0.1:$P$1" "${@:2}"; }
sid() { awk '$6 == "sid" { print $7 }' "$JAR" 2>/dev/null | tail -1; }

cat > "$W/count.lua" <<'EOF'
local s = session.open("sesscache")
s.n = (s.n or 0) + 1
session.save(s)
echo("n=", s.n)
EOF
cat > "$W/login.lua" <<'EOF'
local s = session.open("sesscache")
s.user = req.get.user
session.regenerate(s)
echo("user=", s.user)
EOF
cat > "$W/who.lua" <<'EOF'
local s = session.open("sesscache")
echo("user=", s.user or "-", " n=", s.n or 0)
EOF
cat > "$W/logout.lua" <<'EOF'
session.destroy(session.open("sesscache"))
echo("bye")
EOF
cat > "$W/raw.lua" <<'EOF'
local v, err = socketley.cache.command("sesscache", req.get.cmd)
local none, why = socketley.cache.command("nosuchcache", "get x")
echo(tostring(v), "|", tostring(none), "|", tostring(why))
EOF
cat > "$W/hash.lua" <<'EOF'
local h = socketley.password_hash(req.get.pw)
echo(h:sub(1, 8), " ", tostring(socketley.password_verify(h, req.get.pw)), " ",
     tostring(socketley.password_verify(h, req.get.pw .. "x")))
EOF
echo 'echo("quick")' > "$W/quick.lua"

daemon_start "$BIN"
create_ok "a cache for the sessions" "$BIN" create cache sesscache -p "$CP" -s
create_ok "a site with pages" "$BIN" create web sessweb -p "$P" --root "$W" --lua-pages -s
for _ in $(seq 1 50); do [ "$(curl -s "http://127.0.0.1:$P/quick.lua")" = quick ] && break; sleep 0.1; done

check "socketley.cache.command answers with what the cache said, and nil for no such runtime" \
    "ok|nil|no runtime of that name answers socketley.cache" "$(get '/raw.lua?cmd=set%20k%20v')"
check "and reads it back" "v|nil|no runtime of that name answers socketley.cache" "$(get '/raw.lua?cmd=get%20k')"

rm -f "$JAR"
check "a new session starts empty and is saved" "n=1" "$(get /count.lua)"
FIRST=$(sid)
check "its id is 32 hex digits the server made" "1" "$(printf '%s\n' "$FIRST" | grep -cE '^[0-9a-f]{32}$' || true)"
check "the next request reads it back" "n=2" "$(get /count.lua)"
check "the cache holds it under session:<id>" '{"n":2}' "$(printf 'get session:%s\n' "$FIRST" | nc -q1 127.0.0.1 "$CP" | tr -d '\r')"

check "an id the client picked is not taken" "n=1" \
    "$(curl -s -b 'sid=00000000000000000000000000000000' "http://127.0.0.1:$P/count.lua")"

check "a sign-in regenerates the id" "user=bob" "$(get '/login.lua?user=bob')"
SECOND=$(sid)
if [ -n "$SECOND" ] && [ "$SECOND" != "$FIRST" ]; then ok; else bad "the id changes at the sign-in" "$FIRST -> $SECOND"; fi
check "the session goes on under the new id" "user=bob n=2" "$(get /who.lua)"
check "and the old id finds nothing" "user=- n=0" "$(curl -s -b "sid=$FIRST" "http://127.0.0.1:$P/who.lua")"

check "a sign-out destroys it" "bye" "$(get /logout.lua)"
check "and it is gone" "user=- n=0" "$(curl -s -b "sid=$SECOND" "http://127.0.0.1:$P/who.lua")"

check "a password hash is scrypt's and verifies" "\$scrypt\$ true false" "$(get '/hash.lua?pw=secret')"

# Two hashes at once take tens of milliseconds each on the helper thread; a page asked meanwhile is not held for them.
curl -s "http://127.0.0.1:$P/hash.lua?pw=a" > /dev/null &
H1=$!
curl -s "http://127.0.0.1:$P/hash.lua?pw=b" > /dev/null &
H2=$!
sleep 0.005
T0=$(date +%s%N)
QUICK=$(curl -s "http://127.0.0.1:$P/quick.lua")
T1=$(date +%s%N)
wait "$H1" "$H2" || true
MS=$(( (T1 - T0) / 1000000 ))
if [ "$QUICK" = quick ] && [ "$MS" -lt 40 ]; then ok; else
    bad "a page is answered while hashes are made" "'$QUICK' after ${MS}ms"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
