#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a dns runtime with --dnssec signs its zone, and a validator that trusts its key takes every kind
# of answer: a record, a name that is not there, a type that is not there, a wildcard's and a delegation's.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a DS for the registrar that is not of the key the zone is signed with, or a key made anew on a restart
#   * a signature delv does not take, or one sent to a query that did not ask for it
#   * a denial whose NSEC records do not prove it, for a name, a type or a wildcard
#   * the DS command on a runtime that signs nothing
#   * a zone transfer without the signatures
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

command -v dig >/dev/null 2>&1 || { echo "  SKIP: dig is required"; exit 0; }
command -v delv >/dev/null 2>&1 || { echo "  SKIP: delv is required"; exit 0; }

daemon_isolate dns_dnssec
T="$SOCKETLEY_TMPD"
NS=$((SL_PORT_BASE+1720))
NS2=$((SL_PORT_BASE+1721))
trap daemon_stop EXIT

echo "=== Integration: DNSSEC ==="

cat > "$T/example.zone" <<'EOF'
$ORIGIN example.test.
$TTL 3600
@         IN SOA ns1 hostmaster ( 2026102501 1h 15m 1w 300 )
          IN NS  ns1
          IN MX  10 mail
          IN A   192.0.2.1
ns1       IN A   192.0.2.53
mail      IN A   192.0.2.25
www       IN CNAME mail
*.apps    IN A   192.0.2.80
deep.a.b  IN TXT "under an empty name"
sub       IN NS  ns.sub
ns.sub    IN A   192.0.2.99
EOF

daemon_start "$BIN"
"$BIN" create dns ns -p "$NS" --bind 127.0.0.1 --zone "$T/example.zone" --transfer 127.0.0.1 --dnssec --proxy none -s >/dev/null 2>&1
for _ in $(seq 1 50); do dig +short +time=1 +tries=1 -p "$NS" @127.0.0.1 example.test SOA >/dev/null 2>&1 && break; sleep 0.1; done

ds=$("$BIN" dnssec ns 2>&1); rc=$?
case "$ds" in "example.test. IN DS "*" 13 2 "*"example.test. IN DNSKEY 257 3 13 "*) [ "$rc" -eq 0 ] && ok "socketley dnssec prints the DS and the DNSKEY" \
    || bad "the DS" "rc $rc: $ds" ;; *) bad "the DS" "rc $rc: $ds" ;; esac
key=$(printf '%s\n' "$ds" | sed -n 's/^example\.test\. IN DNSKEY 257 3 13 //p')
served=$(dig +short +time=2 +tries=1 -p "$NS" @127.0.0.1 example.test DNSKEY 2>/dev/null)
case "$served" in "257 3 13 "*) [ "$(printf '%s' "${served#257 3 13 }" | tr -d ' ')" = "$key" ] && ok "the zone serves the DNSKEY the DS is of" \
    || bad "the DNSKEY served" "$served / $key" ;; *) bad "the DNSKEY served" "$served" ;; esac

printf 'trust-anchors {\n  example.test. static-key 257 3 13 "%s";\n};\n' "$key" > "$T/anchor.conf"
v() { delv -a "$T/anchor.conf" +root=example.test -p "$NS" @127.0.0.1 "$@" 2>&1; }
case "$(v mail.example.test A)" in *"; fully validated"*"192.0.2.25"*) ok "a record validates" ;; *) bad "a record" "$(v mail.example.test A)" ;; esac
case "$(v www.example.test A)" in *"; fully validated"*"CNAME"*"192.0.2.25"*) ok "an alias and its target validate" ;; *) bad "an alias" "$(v www.example.test A)" ;; esac
case "$(v nothing.example.test A)" in *"; negative response, fully validated"*|*"NXDOMAIN"*"fully validated"*) ok "a name that is not there is proven so" ;;
    *) bad "NXDOMAIN" "$(v nothing.example.test A)" ;; esac
case "$(v mail.example.test AAAA)" in *"; negative response, fully validated"*) ok "a type that is not there is proven so" ;;
    *) bad "NODATA" "$(v mail.example.test AAAA)" ;; esac
case "$(v a.b.example.test TXT)" in *"; negative response, fully validated"*) ok "and an empty name between others" ;;
    *) bad "an empty non-terminal" "$(v a.b.example.test TXT)" ;; esac
case "$(v x.apps.example.test A)" in *"; fully validated"*"192.0.2.80"*) ok "a wildcard's answer validates, with its proof" ;;
    *) bad "a wildcard" "$(v x.apps.example.test A)" ;; esac
case "$(v sub.example.test DS)" in *"; negative response, fully validated"*) ok "a delegation without a DS is proven insecure" ;;
    *) bad "no DS" "$(v sub.example.test DS)" ;; esac

plain=$(dig +norec +time=2 +tries=1 -p "$NS" @127.0.0.1 mail.example.test A 2>/dev/null)
signed=$(dig +dnssec +norec +time=2 +tries=1 -p "$NS" @127.0.0.1 mail.example.test A 2>/dev/null)
case "$plain" in *RRSIG*) bad "no signature to a query without DO" "$plain" ;; *)
    case "$signed" in *"flags: do;"*RRSIG*) ok "a signature goes to a query with DO alone, and DO goes back" ;; *) bad "DO" "$signed" ;; esac ;; esac
axfr=$(dig +time=2 +tries=1 -p "$NS" @127.0.0.1 example.test AXFR 2>/dev/null)
[ "$(printf '%s\n' "$axfr" | grep -c 'IN	RRSIG')" -gt 5 ] && printf '%s' "$axfr" | grep -q 'IN	NSEC' \
    && ok "a zone transfer carries the signatures and the chain" || bad "AXFR" "$(printf '%s\n' "$axfr" | head -20)"

"$BIN" stop ns >/dev/null 2>&1; "$BIN" start ns >/dev/null 2>&1
for _ in $(seq 1 50); do dig +short +time=1 +tries=1 -p "$NS" @127.0.0.1 example.test SOA >/dev/null 2>&1 && break; sleep 0.1; done
[ "$("$BIN" dnssec ns 2>&1)" = "$ds" ] && case "$(v mail.example.test A)" in *"; fully validated"*) true ;; *) false ;; esac \
    && ok "a restart signs with the key the DS is of" || bad "after a restart" "$("$BIN" dnssec ns 2>&1)"

cat > "$T/plain.zone" <<'EOF'
$ORIGIN plain.test.
$TTL 3600
@ IN SOA ns1 hostmaster ( 1 1h 15m 1w 300 )
  IN NS ns1
ns1 IN A 192.0.2.53
EOF
"$BIN" create dns ns2 -p "$NS2" --bind 127.0.0.1 --zone "$T/plain.zone" --proxy none -s >/dev/null 2>&1
out=$("$BIN" dnssec ns2 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"--dnssec"*) true ;; *) false ;; esac && ok "a runtime that signs nothing has no DS, and says why" \
    || bad "dnssec without --dnssec" "rc $rc: $out"
for _ in $(seq 1 50); do dig +short +time=1 +tries=1 -p "$NS2" @127.0.0.1 plain.test SOA >/dev/null 2>&1 && break; sleep 0.1; done
case "$(dig +dnssec +norec +time=2 +tries=1 -p "$NS2" @127.0.0.1 ns1.plain.test A 2>/dev/null)" in *RRSIG*) bad "an unsigned zone" "RRSIG" ;;
    *"192.0.2.53"*) ok "an unsigned zone answers DO without signatures" ;; *) bad "an unsigned zone" "no answer" ;; esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
