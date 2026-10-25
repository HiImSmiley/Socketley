#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: how a mail client finds a mailbox -- Thunderbird's autoconfig, Outlook's autodiscover (XML and the
# JSON that points at it), an Apple profile for the signed-in user, the names and the SRV record that lead there, and
# the webmail telling its user the same.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a client told another host or port than the runtime's, a port it does not open, or a password asked over a port
#     that begins in the clear
#   * an address of a domain it does not keep answered as though it did
#   * autoconfig.<zone> and autodiscover.<zone> not given to the webmail, or no SRV record for Outlook
#   * a profile given to someone not signed in, or naming another address than theirs
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ready.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v dig >/dev/null 2>&1 || { echo "  SKIP: dig is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

daemon_isolate mail_setup
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1940)); SUBS=$((P+1)); IMAPS=$((P+2)); WEB=$((P+3)); NS=$((P+4)); GATE=$((P+5)); PI=$((P+6)); PS=$((P+7))
trap daemon_stop EXIT

echo "=== Integration: mail clients set themselves up ==="

daemon_start "$BIN"
"$BIN" create idp auth -p "$PI" --bind 127.0.0.1 --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --bind 127.0.0.1 --dir "$T/data" --anonymous -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
"$BIN" idp-user auth add alice --password alicepassword1 --email alice@example.test >/dev/null 2>&1
"$BIN" create dns ns -p "$NS" --bind 127.0.0.1 --zone example.test --publish 127.0.0.1 --proxy-port "$GATE" -s >/dev/null 2>&1
"$BIN" create mail m -p "$P" --dns ns --idp auth --storage st/mail --tls --submissions "$SUBS" --imaps "$IMAPS" \
    --web "$WEB" --domain mail -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$WEB" || bad "the webmail listens" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 100); do ready_tcp 127.0.0.1 "$IMAPS" >/dev/null 2>&1 && break; sleep 0.1; done

W="http://127.0.0.1:$WEB"
# The runtime learns the domains it keeps from the zones of its dns runtime, a tick after it starts.
for _ in $(seq 1 100); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$W/mail/config-v1.1.xml?emailaddress=alice%40example.test")" = 200 ] && break
    sleep 0.1
done
xml=$(curl -s "$W/mail/config-v1.1.xml?emailaddress=alice%40example.test")
case "$xml" in *"<hostname>mail.example.test</hostname>"*"<port>$IMAPS</port>"*"<socketType>SSL</socketType>"*"<port>$SUBS</port>"*"%EMAILADDRESS%"*) \
    ok "Thunderbird's autoconfig names the host, its IMAP and SMTP ports over TLS, and the address to sign in with" ;;
    *) bad "Thunderbird's autoconfig" "$xml" ;; esac
case "$xml" in *"STARTTLS"*|*"pop3"*) bad "and no port it does not open" "$xml" ;; *) ok "and no port it does not open" ;; esac
case "$xml" in *'<addressBook type="carddav">'*'<serverURL>https://mail.example.test/dav/</serverURL>'*'<calendar type="caldav">'*) \
    ok "and the calendars and contacts beside the mail" ;; *) bad "the calendars in autoconfig" "$xml" ;; esac
[ "$(curl -s -o /dev/null -w '%{http_code}' "$W/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress=alice%40example.test")" = 200 ] \
    && ok "at the well-known path as well" || bad "the well-known path" "-"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$W/mail/config-v1.1.xml?emailaddress=bob%40else.test")" = 404 ] \
    && ok "an address of a domain it does not keep is answered 404" || bad "another domain" "-"

pox=$(curl -s -X POST "$W/Autodiscover/Autodiscover.xml" -H 'Content-Type: text/xml' --data \
    '<?xml version="1.0"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>alice@example.test</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>')
case "$pox" in *"<Type>IMAP</Type>"*"<Server>mail.example.test</Server>"*"<Port>$IMAPS</Port>"*"<Type>SMTP</Type>"*"<Port>$SUBS</Port>"*"<LoginName>alice@example.test</LoginName>"*) \
    ok "Outlook's autodiscover names IMAP and SMTP, their ports and the login" ;; *) bad "Outlook's autodiscover" "$pox" ;; esac
json=$(curl -s -H 'Host: autodiscover.example.test' "$W/autodiscover/autodiscover.json/v1.0/alice@example.test?Protocol=AutodiscoverV1")
[ "$json" = '{"Protocol":"AutodiscoverV1","Url":"https://autodiscover.example.test/autodiscover/autodiscover.xml"}' ] \
    && ok "and its JSON lookup points at that document" || bad "the JSON lookup" "$json"

[ "$(curl -s -o /dev/null -w '%{http_code}' "$W/~mail/mobileconfig")" = 401 ] && ok "the Apple profile is for one signed in" \
    || bad "the profile unsigned" "$(curl -s -o /dev/null -w '%{http_code}' "$W/~mail/mobileconfig")"
prof=$(curl -s -D "$T/ph" -u alice:alicepassword1 -H 'X-Forwarded-Proto: https' "$W/~mail/mobileconfig")
case "$prof" in *"<key>EmailAddress</key><string>alice@example.test</string>"*"<key>IncomingMailServerPortNumber</key><integer>$IMAPS</integer>"*"<key>OutgoingMailServerPortNumber</key><integer>$SUBS</integer>"*) \
    grep -qi 'content-type: application/x-apple-aspen-config' "$T/ph" && ok "and names their address, the ports, as a configuration profile" \
    || bad "the profile's type" "$(cat "$T/ph")" ;; *) bad "the Apple profile" "$prof" ;; esac
case "$prof" in *"<string>com.apple.caldav.account</string>"*"<string>com.apple.carddav.account</string>"*) \
    case "$prof" in *"<key>CalDAVHostName</key><string>mail.example.test</string>"*) ok "the profile sets up the calendar and the contacts" ;;
        *) bad "the profile's calendar host" "$prof" ;; esac ;; *) bad "the profile's calendar and contacts" "$prof" ;; esac

q() { dig +short +time=2 +tries=1 -p "$NS" @127.0.0.1 "$@" 2>/dev/null; }
for _ in $(seq 1 50); do [ -n "$(q autoconfig.example.test A)" ] && break; sleep 0.2; done
[ "$(q autoconfig.example.test A)" = 127.0.0.1 ] && [ "$(q autodiscover.example.test A)" = 127.0.0.1 ] \
    && ok "autoconfig and autodiscover are names of the zone, through the entrance" || bad "the names" "$(q autoconfig.example.test A) / $(q autodiscover.example.test A)"
for _ in $(seq 1 50); do [ -n "$(q _autodiscover._tcp.example.test SRV)" ] && break; sleep 0.2; done
[ "$(q _autodiscover._tcp.example.test SRV)" = "0 1 443 autodiscover.example.test." ] && ok "and Outlook's SRV record leads there" \
    || bad "the SRV record" "$(q _autodiscover._tcp.example.test SRV)"

for _ in $(seq 1 50); do [ -n "$(q _caldavs._tcp.example.test SRV)" ] && break; sleep 0.2; done
[ "$(q _caldavs._tcp.example.test SRV)" = "0 1 443 mail.example.test." ] && [ "$(q _carddavs._tcp.example.test TXT)" = '"path=/dav/"' ] \
    && ok "and the calendar and contacts records lead to the webmail's name (RFC 6764)" \
    || bad "the DAV records" "$(q _caldavs._tcp.example.test SRV) / $(q _carddavs._tcp.example.test TXT)"
sess=$(curl -s -u alice:alicepassword1 -H 'X-Forwarded-Proto: https' -H 'X-Socketley-UI: 1' "$W/~mail/session")
case "$sess" in *'"setup":{"host":"mail.example.test","imaps":'"$IMAPS"',"imap":0,"pop3s":0,"pop3":0,"submissions":'"$SUBS"',"submission":0,"dav":"https://mail.example.test/dav/"}'*) \
    ok "the webmail tells its user the same" ;; *) bad "the webmail's setup" "$sess" ;; esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
