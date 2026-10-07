#!/usr/bin/env bash
# Integration test: names runtimes are reached by, and the entrance that routes requests by them.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   ownership    a name belongs to one runtime: a second one is refused at
#                create, edit and import, whatever its case or trailing dot,
#                and across types; the runtimes of one group share a name; the
#                entrance, a proxy without --backend, has none of its own
#   own names    --domain with no name after it is the runtime's own name
#   zones        --zone with a zone's name writes the zone's file itself, once,
#                with ns1 and ns2 and their addresses, and leaves it to be edited
#   its entrance a dns runtime makes the proxy its names are reached through,
#                <dns>-proxy on 443 (--proxy-port) with TLS, as its child: it
#                stops, starts and is removed with it, passes to another dns
#                runtime naming it, and is none with --proxy none
#   publishing   a dns runtime with --proxy answers every runtime's name with
#                this machine's public address, or --publish's; a cache's name
#                too, though only HTTP runtimes are routed
#   the table    the entrance's routes: each HTTP runtime's names, a short name
#                under each zone, a storage runtime's buckets beneath it, the
#                runtimes of a group together, nothing for a cache
#   the entrance a proxy without --backend routes each request by its Host to
#                the runtime with that name, the path and the Host as they came:
#                exact before wildcard, a group spread over and standing in for
#                each other, 404 for a name no runtime has, 400 without a Host,
#                508 for a request that came round again, new runtimes without
#                a restart
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate edge
P=$((SL_PORT_BASE+1740))
T="$SOCKETLEY_TMPD"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
has() { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1" "'$3' not in: $2" ;; esac; }

cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: names and the entrance ==="
daemon_start "$BIN"

# ── ownership ───────────────────────────────────────────────────────────────
expect "a runtime takes a name" "$("$BIN" create server a -p "$P" --domain chat 2>&1)" ""
has "a second runtime is refused it, whatever its case and trailing dot" \
    "$("$BIN" create server b -p $((P+1)) --domain Chat. 2>&1)" "chat is already the name of runtime 'a'"
has "and so is a runtime of another type" \
    "$("$BIN" create storage s -p $((P+2)) --dir "$T/s" --anonymous --domain chat 2>&1)" "already the name of runtime 'a'"
expect "the runtimes of one group share a name" \
    "$("$BIN" create server g1 -p $((P+3)) -g web --domain www 2>&1)$("$BIN" create server g2 -p $((P+4)) -g web --domain www 2>&1)" ""
has "edit cannot take another's name" "$("$BIN" edit g1 --domain chat 2>&1)" "already the name of runtime 'a'"
has "nor import" "$("$BIN" import a '{"name":"a","domain":"www"}' 2>&1)" "already the name of runtime"
has "and the refused import left the runtime as it was" "$("$BIN" show a 2>&1)" '"domain": "chat"'
has "the entrance has no name of its own" "$("$BIN" create proxy e -p $((P+5)) --domain x 2>&1)" "has no name of its own"
expect "and nothing refused was made" "$("$BIN" ls 2>/dev/null | awk 'NR>1 {print $2}' | sort | tr '\n' ' ')" "a g1 g2 "
for r in a g1 g2; do "$BIN" remove "$r" >/dev/null 2>&1; done

# --domain with no name after it is the runtime's own name.
expect "--domain alone takes the runtime's name" "$("$BIN" create server own -p $((P+6)) --domain -s 2>&1)" ""
has "and show says so" "$("$BIN" show own 2>&1)" '"domain": "own"'
expect "a storage runtime's too" "$("$BIN" create storage ownstore -p $((P+7)) --dir "$T/os" --anonymous --domain 2>&1)" ""
has "with its buckets beneath it" "$("$BIN" show ownstore 2>&1)" '"domain": "ownstore"'
has "a runtime's name that is no DNS name is refused, and said to be the runtime's" \
    "$("$BIN" create server my_x -p $((P+8)) --domain 2>&1)" "the runtime's name, taken since no name followed --domain"
for r in own ownstore; do "$BIN" remove "$r" >/dev/null 2>&1; done

# ── publishing, through the entrance ────────────────────────────────────────
command -v dig >/dev/null 2>&1 || { echo "  SKIP: dig is not installed, so names are not asked for"; echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; exit "$FAIL"; }
cat > "$T/z.zone" <<'EOF'
$ORIGIN example.com.
$TTL 300
@    SOA ns1 hostmaster 1 1h 15m 1w 60
     NS  ns1
ns1  A   192.0.2.53
mail A   192.0.2.25
EOF
DNS=$((P+10))
# An entrance made by hand, in plain HTTP, which the dns runtime takes as it is.
"$BIN" create proxy web -p $((P+11)) >/dev/null 2>&1
"$BIN" create dns ns -p "$DNS" --zone "$T/z.zone" --proxy web --rrl 0 -s >/dev/null 2>&1
"$BIN" create storage ui -p $((P+12)) --dir "$T/ui" --anonymous --domain ui >/dev/null 2>&1
"$BIN" create cache mycache -p $((P+13)) --domain mycache >/dev/null 2>&1
qd() { dig @127.0.0.1 -p "$DNS" +time=2 +tries=1 +short "$@" 2>&1; }
got=""
for _ in $(seq 1 40); do got=$(qd ui.example.com A); [ -n "$got" ] && break; sleep 0.2; done
mine=$(ip -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
if [ -n "$got" ]; then
    case " $(echo $mine) " in *" $got "*) ok "with --proxy and no --publish, a name is answered with this machine's address ($got)" ;;
        *) bad "this machine's address" "answered $got; this machine has: $(echo $mine)" ;; esac
else
    echo "  SKIP: this machine has no public address on its interfaces, so --proxy publishes nothing by itself"
fi
"$BIN" stop ns >/dev/null 2>&1; "$BIN" remove ns >/dev/null 2>&1
"$BIN" create dns ns -p "$DNS" --zone "$T/z.zone" --proxy web --publish 198.51.100.7 --rrl 0 -s >/dev/null 2>&1
for _ in $(seq 1 40); do got=$(qd ui.example.com A); [ "$got" = 198.51.100.7 ] && break; sleep 0.2; done
expect "--publish names the address instead" "$got" "198.51.100.7"
expect "a storage runtime's buckets under its short name" "$(qd photos.ui.example.com A)" "198.51.100.7"
expect "a cache's name is published too" "$(qd mycache.example.com A)" "198.51.100.7"
expect "a name the zone file gives an address keeps it" "$(qd mail.example.com A)" "192.0.2.25"

# ── a zone given by its name ────────────────────────────────────────────────
Z=$((P+20))
cd "$T"
expect "--zone with a zone's name and no file makes the runtime" \
    "$("$BIN" create dns nsz -p "$Z" --zone Zed.Example. --publish 198.51.100.9 --rrl 0 --proxy none -s 2>&1)" ""
zf=$(find "$T" -path '*zones/zed.example.zone' | head -1)
[ -n "$zf" ] && ok "and its file is written in the state directory" || bad "zone file" "none under $T"
dz() { dig @127.0.0.1 -p "$Z" +time=2 +tries=1 +short "$@" 2>&1; }
for _ in $(seq 1 40); do [ -n "$(dz zed.example SOA)" ] && break; sleep 0.2; done
expect "it answers the zone's SOA" "$(dz zed.example SOA | cut -d' ' -f1-2)" "ns1.zed.example. hostmaster.zed.example."
expect "and names ns1 and ns2 as its servers" "$(dz zed.example NS | sort | tr '\n' ' ')" "ns1.zed.example. ns2.zed.example. "
expect "with --publish's address" "$(dz ns2.zed.example A)" "198.51.100.9"
echo 'www  A  192.0.2.80' >> "$zf"
for _ in $(seq 1 40); do got=$(dz www.zed.example A); [ -n "$got" ] && break; sleep 0.2; done
expect "the file is the user's to edit, and read again" "$got" "192.0.2.80"
"$BIN" stop nsz >/dev/null 2>&1; "$BIN" start nsz >/dev/null 2>&1
for _ in $(seq 1 40); do got=$(dz www.zed.example A); [ -n "$got" ] && break; sleep 0.2; done
expect "and kept, not written over, at a restart" "$got" "192.0.2.80"
"$BIN" remove nsz >/dev/null 2>&1
expect "a missing <zone>.zone path is written where it was given" \
    "$("$BIN" create dns nsf -p "$Z" --zone "$T/zz/third.example.zone" --publish 198.51.100.9 --proxy none 2>&1; ls "$T/zz")" "third.example.zone"
"$BIN" remove nsf >/dev/null 2>&1
has "a missing file of another name is refused" \
    "$("$BIN" create dns nsn -p "$Z" --zone "$T/zz/nope.txt" --publish 198.51.100.9 2>&1)" "does not exist"
has "and so is a name that is no zone's" "$("$BIN" create dns nsn -p "$Z" --zone nozone --publish 198.51.100.9 2>&1)" \
    "neither a zone's name"
cd - >/dev/null

# ── the entrance a dns runtime makes ────────────────────────────────────────
X=$((P+21))
expect "a dns runtime is made with its entrance" \
    "$("$BIN" create dns nse -p "$X" --zone ent.example --publish 198.51.100.9 --proxy-port $((X+1)) --rrl 0 -s 2>&1)" ""
row() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2 == n {print $3, $6, $7}'; }
expect "named after it, owned by it, running, on --proxy-port" "$(row nse-proxy) $("$BIN" show nse-proxy 2>&1 | grep -c "\"port\": $((X+1))")" "proxy nse Up 1"
has "and speaking TLS, its certificate its own to ask for" "$("$BIN" show nse-proxy 2>&1)" '"tls": true'
has "the dns runtime names it" "$("$BIN" show nse 2>&1)" '"proxy": "nse-proxy"'
"$BIN" stop nse >/dev/null 2>&1
expect "it stops with the dns runtime" "$(row nse-proxy | cut -d' ' -f3)" "Stopped"
"$BIN" start nse >/dev/null 2>&1
expect "and starts with it" "$(row nse-proxy | cut -d' ' -f3)" "Up"
has "a port already taken is refused, and nothing is left made" \
    "$("$BIN" create dns nsb -p $((X+2)) --zone b.example --publish 198.51.100.9 --proxy-port $((X+1)) -s 2>&1; "$BIN" ls 2>/dev/null | grep -c ' nsb')" "could not be made
0"
expect "--proxy none makes none" \
    "$("$BIN" create dns nsn -p $((X+3)) --zone n.example --publish 198.51.100.9 --proxy none 2>&1; row nsn-proxy)" ""
"$BIN" remove nsn >/dev/null 2>&1
"$BIN" create dns nss -p $((X+4)) --zone s.example --publish 198.51.100.9 --proxy nse-proxy -s >/dev/null 2>&1
expect "a second dns runtime may name the same entrance, which stays the first one's" "$(row nse-proxy | cut -d' ' -f2)" "nse"
"$BIN" remove nse >/dev/null 2>&1
expect "removed with the first, it passes to the other instead" "$(row nse-proxy | cut -d' ' -f2)" "nss"
"$BIN" remove nss >/dev/null 2>&1
expect "and goes with the last" "$(row nse-proxy)" ""

# ── the table the entrance routes by ────────────────────────────────────────
mkdir -p "$T/c1" "$T/c2" "$T/late"; echo one > "$T/c1/who.txt"; echo two > "$T/c2/who.txt"; echo late > "$T/late/who.txt"
"$BIN" create server chat1 -p $((P+14)) -g chat --domain chat --http "$T/c1" -s >/dev/null 2>&1
"$BIN" create server chat2 -p $((P+15)) -g chat --domain chat --http "$T/c2" -s >/dev/null 2>&1
want="zone example.com
route *.ui.example.com 127.0.0.1:$((P+12))
route chat.example.com 127.0.0.1:$((P+14)) 127.0.0.1:$((P+15))
route ui.example.com 127.0.0.1:$((P+12))"
table=""
for _ in $(seq 1 40); do table=$(cat "$(find "$T" -name routes-web | head -1)" 2>/dev/null); [ "$table" = "$want" ] && break; sleep 0.2; done
expect "the entrance's table: each HTTP runtime's names, a group together, no cache" "$table" "$want"

# ── the entrance ────────────────────────────────────────────────────────────
E=$((P+11))
"$BIN" start ui >/dev/null 2>&1; "$BIN" start web >/dev/null 2>&1
hc() { local h=$1 p=$2; shift 2; curl -s --noproxy '*' -m 3 -H "Host: $h" "$@" "http://127.0.0.1:$E$p"; }
code() { local h=$1 p=$2; shift 2; hc "$h" "$p" -o /dev/null -w '%{http_code}' "$@"; }
got=""
for _ in $(seq 1 40); do got=$(hc chat.example.com /who.txt); [ -n "$got" ] && break; sleep 0.2; done
case "$got" in one|two) ok "the entrance routes a name to its runtime, the path as it came" ;; *) bad "routed" "got '$got'" ;; esac
seen=$(for _ in 1 2 3 4; do hc chat.example.com /who.txt; done | sort -u | tr '\n' ' ')
expect "and spreads a group's name over its runtimes" "$seen" "one two "
expect "a name in any case, with a trailing dot and a port" "$(hc CHAT.Example.com.:443 /who.txt | tr -d '\n' | sed 's/two/one/')" "one"
expect "a name no runtime has is 404" "$(code nobody.example.com /who.txt)" 404
expect "a name outside the zones is 404" "$(code chat.example.org /who.txt)" 404
expect "a request without a Host is 400" "$(code '' /who.txt -H 'Host:')" 400
expect "a request that came round again is 508" "$(code chat.example.com /who.txt -H "Via: 1.1 web.$(hostname)")" 508
expect "and one that only passed another proxy is not" "$(code chat.example.com /who.txt -H "Via: 1.1 xweb.$(hostname), 1.1 other")" 200
expect "the absolute form names the host itself" \
    "$(curl -s --noproxy '*' -m 3 --request-target http://chat.example.com/who.txt "http://127.0.0.1:$E/x" | sed 's/two/one/')" "one"

# A storage runtime is told the name asked for, which is how it finds the bucket.
for _ in $(seq 1 40); do [ "$(code ui.example.com /)" = 200 ] && break; sleep 0.2; done
hc ui.example.com /photos -X PUT >/dev/null
echo hello > "$T/hello.txt"
hc ui.example.com /photos/hello.txt -T "$T/hello.txt" >/dev/null
expect "a bucket under a storage runtime's short name, through the entrance" "$(hc photos.ui.example.com /hello.txt)" "hello"
expect "and the runtime itself, path style" "$(hc ui.example.com /photos/hello.txt)" "hello"

"$BIN" create server late -p $((P+16)) --domain late --http "$T/late" -s >/dev/null 2>&1
got=""
for _ in $(seq 1 40); do got=$(hc late.example.com /who.txt); [ "$got" = late ] && break; sleep 0.2; done
expect "a runtime made while the entrance runs is reached without a restart" "$got" "late"
if command -v python3 >/dev/null 2>&1; then
    two=$(python3 - "$E" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3)
out = []
for host in ("late.example.com", "photos.ui.example.com", "late.example.com"):
    path = "/hello.txt" if host.startswith("photos") else "/who.txt"
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(65536)
    head, body = buf.split(b"\r\n\r\n", 1)
    n = int([l.split(b":")[1] for l in head.split(b"\r\n") if l.lower().startswith(b"content-length")][0])
    while len(body) < n:
        body += s.recv(65536)
    out.append(body[:n].decode().strip())
print(" ".join(out))
PY
)
    expect "each request on one connection goes where its own name says" "$two" "late hello late"
fi

"$BIN" stop chat2 >/dev/null 2>&1
seen=$(for _ in 1 2 3 4; do hc chat.example.com /who.txt; done | tr '\n' ' ')
expect "one runtime of a group stopped, the others answer for it" "$seen" "one one one one "
"$BIN" stop chat1 >/dev/null 2>&1
expect "all of them stopped, 502" "$(code chat.example.com /who.txt)" 502
"$BIN" start chat1 >/dev/null 2>&1

# Over TLS a connection belongs to the name its handshake gave.
if command -v openssl >/dev/null 2>&1; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=example.com \
        -addext "subjectAltName=DNS:*.example.com,DNS:example.com" \
        -keyout "$T/e.key" -out "$T/e.pem" >/dev/null 2>&1
    S=$((P+17))
    "$BIN" create proxy webs -p "$S" --tls --cert "$T/e.pem" --key "$T/e.key" -s >/dev/null 2>&1
    "$BIN" create dns ns2 -p $((P+18)) --zone "$T/z.zone" --proxy webs --publish 198.51.100.7 --rrl 0 -s >/dev/null 2>&1
    hs() { curl -sk --noproxy '*' -m 3 --resolve "$1:$S:127.0.0.1" "${@:3}" "https://$1:$S$2"; }
    got=""
    for _ in $(seq 1 40); do got=$(hs chat.example.com /who.txt); [ "$got" = one ] && break; sleep 0.2; done
    expect "over TLS, the name of the handshake and of the request the same, the request is routed" "$got" "one"
    expect "and a request for another name on that connection is 421" \
        "$(hs chat.example.com /who.txt -H 'Host: late.example.com' -o /dev/null -w '%{http_code}')" 421
    expect "while the same name in another case is the same name" \
        "$(hs chat.example.com /who.txt -H 'Host: CHAT.Example.COM' -o /dev/null -w '%{http_code}')" 200
    "$BIN" remove webs >/dev/null 2>&1; "$BIN" stop ns2 >/dev/null 2>&1; "$BIN" remove ns2 >/dev/null 2>&1
else
    echo "  SKIP: openssl is not installed, so the entrance is not asked over TLS"
fi
"$BIN" remove chat2 >/dev/null 2>&1
for _ in $(seq 1 40); do grep -q "$((P+15))" "$(find "$T" -name routes-web | head -1)" || break; sleep 0.2; done
has "a runtime removed leaves the table" "$(cat "$(find "$T" -name routes-web | head -1)")" "route chat.example.com 127.0.0.1:$((P+14))
"
"$BIN" remove web >/dev/null 2>&1
for _ in $(seq 1 40); do [ -z "$(find "$T" -name routes-web)" ] && break; sleep 0.2; done
expect "and an entrance removed, its table" "$(find "$T" -name routes-web | wc -l)" 0

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
