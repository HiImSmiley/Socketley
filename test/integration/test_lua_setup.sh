#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a machine's setup as Lua -- a config.lua that includes a file a runtime, made by `socketley --lua`,
# brought to what the files say on a second run, written back by `socketley export`, and made again by a fresh daemon
# that reads it as its own configuration file.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a flag of the schema with no Lua key (a mail runtime's ports, its dnsbl and its web port were none), include() of
#     a file or of a directory not read, or a relative path read from where the command was typed and not beside
#     config.lua
#   * a second run refused for runtimes that exist, or restarting one the files say nothing new of
#   * a value the files change not changed, or one they no longer say left in place
#   * an unknown key taken
#   * export leaving a runtime, its zone or a setting out, or writing one another runtime made
#   * a fresh daemon whose configuration file is the export not making its runtimes as they were, or not starting them
#   * the daemon's own configuration file refused by `--lua` for the settings only a daemon's start reads
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

daemon_isolate lua_setup
W=$(mktemp -d /tmp/socketley-lua-setup-XXXXXX)
P=$((SL_PORT_BASE+1960))
cleanup() { daemon_stop; rm -rf "$W"; }
trap cleanup EXIT

echo "=== Integration: a setup as Lua files, applied, exported and made again ==="

S="$W/setup"
mkdir -p "$S/runtimes/more" "$S/secrets" "$S/zones"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$S/secrets/key.pem" -out "$S/secrets/cert.pem" -days 2 \
    -subj /CN=mail.try.test >/dev/null 2>&1
printf 'admin:adminsecret0123456789\n' > "$S/secrets/store.creds"; chmod 600 "$S/secrets/store.creds"
cat > "$S/zones/try.test.zone" <<'EOF'
$ORIGIN try.test.
$TTL 3600
@    SOA  ns1 hostmaster 2026102401 1h 15m 1w 300
     NS   ns1
ns1  A    127.0.0.1
www  A    127.0.0.9
EOF
cat > "$S/config.lua" <<'EOF'
runtimes = {
    include "runtimes/ns.lua",
    include "runtimes/auth.lua",
    include "runtimes/more",
}
EOF
cat > "$S/runtimes/ns.lua" <<EOF
return { type = "dns", name = "ns", port = $((P+0)), bind = "127.0.0.1", zone = { "zones/try.test.zone" },
         publish = { "127.0.0.1" }, proxy = "none", start = true }
EOF
cat > "$S/runtimes/auth.lua" <<EOF
return { type = "idp", name = "auth", port = $((P+1)), bind = "127.0.0.1", issuer = "https://auth.try.test",
         cookie_domain = "try.test", domain = "auth", start = true }
EOF
cat > "$S/runtimes/more/1-store.lua" <<EOF
return { type = "storage", name = "store", port = $((P+2)), bind = "127.0.0.1", dir = "$W/data/store",
         credentials = "secrets/store.creds", idp = "auth", sync = "per-user", start = true }
EOF
mail_lua() {
    cat > "$S/runtimes/more/2-mail.lua" <<EOF
return { type = "mail", name = "post", port = $((P+3)), dns = "ns", idp = "auth", storage = "store/mail",
         tls = true, cert = "secrets/cert.pem", key = "secrets/key.pem",
         submission = $((P+4)), imap = $((P+5)), $1 web = $((P+7)), domain = "mail",
         dnsbl = "$2", max_recipients = 50, start = true }
EOF
}
mail_lua "sieve = $((P+6))," "zen.spamhaus.org"

daemon_start "$BIN"
show() { "$BIN" show "$1" 2>&1; }
field() { python3 -c "import json,sys; d=json.loads(sys.argv[1]); print(d.get(sys.argv[2], ''))" "$(show "$1")" "$2" 2>/dev/null; }
up_seconds() { "$BIN" ls | awk -v n="$1" '$2 == n { for (i = 1; i <= NF; i++) if ($i == "Up") { print $(i+1); exit } }'; }

# ─── made from the files ────────────────────────────────────────────────────
(cd /; "$BIN" --lua "$S/config.lua") > "$W/out" 2>&1; rc=$?
[ "$rc" -eq 0 ] && ok "--lua makes the runtimes config.lua and the files it includes describe" || bad "--lua makes them" "rc $rc: $(cat "$W/out")"
for _ in $(seq 1 50); do [ "$(up_seconds post)" != "" ] && break; sleep 0.1; done
n=$("$BIN" ls | grep -cE ' (ns|auth|store|post) .* Up ')
[ "$n" -eq 4 ] && ok "a file's runtime, and each of a directory's, is made and started" || bad "each runtime is made and started" "$("$BIN" ls)"
[ "$(field post submission)/$(field post imap)/$(field post sieve)/$(field post web)/$(field post dnsbl)" = "$((P+4))/$((P+5))/$((P+6))/$((P+7))/zen.spamhaus.org" ] \
    && ok "a mail runtime's ports, its dnsbl and its web port are keys of their flags' names" || bad "a mail runtime's keys" "$(show post)"
[ "$(field store credentials)" = "$S/secrets/store.creds" ] && [ "$(field post cert_path)" = "$S/secrets/cert.pem" ] \
    && [ "$(field ns zones)" = "$S/zones/try.test.zone" ] \
    && ok "a relative path is one beside config.lua, wherever --lua was typed" || bad "relative paths" "$(field store credentials) $(field post cert_path) $(field ns zones)"

# ─── the second run ─────────────────────────────────────────────────────────
sleep 3
before=$(up_seconds post)
"$BIN" --lua "$S/config.lua" > "$W/out" 2>&1; rc=$?
after=$(up_seconds post)
[ "$rc" -eq 0 ] && [ -n "$after" ] && [ "$after" -ge "$before" ] \
    && ok "a second run changes nothing and restarts nothing the files say nothing new of" || bad "a second run" "rc $rc, up $before then $after: $(cat "$W/out")"

mail_lua "" "dnsbl.test"
"$BIN" --lua "$S/config.lua" > "$W/out" 2>&1; rc=$?
[ "$rc" -eq 0 ] && [ "$(field post dnsbl)" = "dnsbl.test" ] && [ -z "$(field post sieve)" ] && "$BIN" ls | grep -qE ' post .* Up ' \
    && ok "a value the files change is changed, one they no longer say is gone, and the runtime runs again" \
    || bad "a change" "rc $rc: $(cat "$W/out") / $(show post)"

printf 'runtimes = { { type = "server", name = "typo", port = %s, prot = 1 } }\n' "$((P+8))" > "$W/typo.lua"
out=$("$BIN" --lua "$W/typo.lua" 2>&1); rc=$?
case "$out" in *"unknown key: prot"*) [ "$rc" -eq 1 ] && ok "an unknown key is refused by name" || bad "an unknown key" "rc $rc: $out" ;;
    *) bad "an unknown key is refused by name" "rc $rc: $out" ;; esac

if [ "$(id -u)" -ne 0 ]; then
mkdir -p "$W/locked"; chmod 000 "$W/locked"
out=$("$BIN" create dns locked -p $((P+10)) --bind 127.0.0.1 --zone "$W/locked/l.test.zone" --publish 127.0.0.1 --proxy none 2>&1); rc=$?
chmod 755 "$W/locked"
case "$out" in *"cannot be read"*) [ "$rc" -eq 1 ] && [ ! -e "$W/locked/l.test.zone" ] && ok "a zone file the daemon may not look at is refused, not written over" \
    || bad "an unreadable zone file" "rc $rc: $out" ;; *) bad "a zone file the daemon may not look at is refused, not written over" "rc $rc: $out" ;; esac
fi

# ─── written back ───────────────────────────────────────────────────────────
"$BIN" export "$W/exp" > "$W/out" 2>&1; rc=$?
[ "$rc" -eq 0 ] && [ -f "$W/exp/config.lua" ] && [ -f "$W/exp/runtimes/post.lua" ] && [ -f "$W/exp/zones/try.test.zone" ] \
    && ok "export writes config.lua, a file a runtime and the zones, and reads them back as the daemon has them" \
    || bad "export" "rc $rc: $(cat "$W/out") $(ls -R "$W/exp" 2>&1 | head -20)"
grep -q 'www  A    127.0.0.9' "$W/exp/zones/try.test.zone" && grep -q 'submission = ' "$W/exp/runtimes/post.lua" \
    && grep -q '"zones/try.test.zone"' "$W/exp/runtimes/ns.lua" && ! grep -q 'sieve' "$W/exp/runtimes/post.lua" \
    && grep -q 'sync = "per-user"' "$W/exp/runtimes/store.lua" \
    && ok "with the zone's own records and every setting, and nothing the runtime no longer has" \
    || bad "the export's content" "$(cat "$W/exp/runtimes/post.lua" "$W/exp/runtimes/ns.lua")"
grep -q "$S/secrets/store.creds" "$W/exp/config.lua" && ok "what the setup reads and does not hold is named in config.lua" \
    || bad "the files named" "$(head -12 "$W/exp/config.lua")"
order=$(grep -o 'runtimes/[a-z]*\.lua' "$W/exp/config.lua" | tr '\n' ' ')
[ "$order" = "runtimes/ns.lua runtimes/auth.lua runtimes/store.lua runtimes/post.lua " ] \
    && ok "in an order that makes a runtime before those that name it" || bad "the order" "$order"
out=$("$BIN" export "$W/exp" 2>&1); rc=$?
[ "$rc" -eq 1 ] && ok "export does not write over a setup" || bad "export over a setup" "rc $rc: $out"
# The zone is the export's copy now, beside its config.lua.
for n in ns auth store post; do show "$n" | grep -v '"id"\|was_running' | sed "s|$S/zones/|$W/exp/zones/|" > "$W/before.$n"; done

# ─── a fresh daemon whose configuration file is the export ──────────────────
daemon_stop
daemon_isolate lua_setup_fresh
cat > "$W/exp/own.lua" <<EOF
daemon = { metrics_port = $((P+9)) }
dofile("$W/exp/config.lua")
EOF
export SOCKETLEY_CONFIG="$W/exp/own.lua"
daemon_start "$BIN"
for _ in $(seq 1 100); do [ "$("$BIN" ls | grep -cE ' (ns|auth|store|post) .* Up ')" -eq 4 ] && break; sleep 0.1; done
[ "$("$BIN" ls | grep -cE ' (ns|auth|store|post) .* Up ')" -eq 4 ] && ok "a fresh daemon makes and starts the runtimes of its configuration file" \
    || bad "a fresh daemon makes them" "$("$BIN" ls) $(grep -i config "$SOCKETLEY_DLOG" | tail -5)"
same=0
for n in ns auth store post; do
    if diff <(show "$n" | grep -v '"id"\|was_running') "$W/before.$n" > "$W/diff.$n"; then same=$((same+1)); fi
done
[ "$same" -eq 4 ] && ok "each as it was on the daemon the export was written from" || bad "each as it was" "$(cat "$W"/diff.*)"
out=$("$BIN" --lua "$W/exp/own.lua" 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "--lua takes the daemon's own file, whose start-only settings are its next start's" || bad "the daemon's own file" "rc $rc: $out"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
