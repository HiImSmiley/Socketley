#!/usr/bin/env bash
# Integration test: what a user of the web interface is told, and what they turn off.
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: notifications in the web interface ==="
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate stgnotes
trap 'daemon_stop' EXIT
daemon_start "$BIN"
P1=$((SL_PORT_BASE + 1920))
U="http://127.0.0.1:$P1"
T="$SOCKETLEY_TMPD"
J="AKIANOTEJONAS0000000:notejonassecretnotejonassecretnotejonas0"
H="AKIANOTEHENRI0000000:notehenrisecretnotehenrisecretnotehenri0"
cat > "$T/creds" <<EOC
[jonas]
${J%%:*}:${J#*:}
[henri]
${H%%:*}:${H#*:}
EOC
"$BIN" create storage notes -p "$P1" --dir "$T/notes" --credentials "$T/creds" -s >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/")" != 000 ] && break; sleep 0.1; done

ui() { local who=$1 m=$2 p=$3; shift 3; curl -s -m 10 -u "$who" -H 'X-Socketley-UI: 1' -H 'Content-Type: application/json' -X "$m" "$@" "$U$p"; }
code() { local who=$1 m=$2 p=$3; shift 3; curl -s -m 10 -o /dev/null -w '%{http_code}' -u "$who" -H 'X-Socketley-UI: 1' -H 'Content-Type: application/json' -X "$m" "$@" "$U$p"; }
j() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1" 2>/dev/null; }
notes() { ui "$1" GET /~ui/notifications; }

curl -s -u "$H" -X MKCOL "$U/~dav/henris/" >/dev/null
curl -s -u "$J" -X MKCOL "$U/~dav/jonas-docs/" >/dev/null
printf 'one\n' | curl -s -u "$J" -T - "$U/~dav/jonas-docs/a.txt" >/dev/null

expect "nobody is told anything at first" "$(notes "$J" | j "d['unread'], len(d['items'])")" "(0, 0)"
expect "and every kind is on" "$(notes "$J" | j "[k['id'] for k in d['kinds'] if k['on']]")" "['sync', 'share', 'library']"

# A library shared.
ui "$H" POST /~ui/access -d '{"bucket":"henris","user":"jonas","access":"write"}' >/dev/null
expect "a library shared with a user is news for that user" "$(notes "$J" | j "d['unread'], d['items'][0]['kind'], d['items'][0]['title']")" \
       "(1, 'library', 'henri shared henris with you')"
expect "that leads to it" "$(notes "$J" | j "d['items'][0]['link']")" "#/henris/"
expect "and nobody else's" "$(notes "$H" | j "d['unread']")" 0

# A download through a link that counts them.
L=$(ui "$J" POST /~share -d '{"bucket":"jonas-docs","key":"a.txt","expires_in":3600,"max_downloads":3}' | j "d['url']")
curl -s -o /dev/null "$U$L"
expect "a download through a link is news for whoever made it" "$(notes "$J" | j "d['items'][0]['kind'], d['items'][0]['title'], d['items'][0]['text']")" \
       "('share', 'Downloaded: a.txt', '1 of 3 downloads through your link')"

# An upload through a folder's link.
F=$(ui "$J" POST /~share -d '{"bucket":"jonas-docs","key":"in/","expires_in":3600,"upload":true}' | j "d['url']")
printf 'from a stranger\n' | curl -s -o /dev/null -T - "$U${F}gift.txt"
expect "an upload through a link is news for whoever made it" "$(notes "$J" | j "d['items'][0]['title']")" "Uploaded through your link: gift.txt"

# Read, turned off, posted, cleared.
expect "opened is read" "$(code "$J" POST /~ui/notifications -d '{"action":"read"}') $(notes "$J" | j "d['unread']")" "204 0"
expect "a kind is turned off" "$(code "$J" POST /~ui/notifications -d '{"action":"prefs","off":["share"]}')" 204
curl -s -o /dev/null "$U$L"
expect "and what it would have said is not kept" "$(notes "$J" | j "d['unread'], [k['id'] for k in d['kinds'] if not k['on']]")" "(0, ['share'])"
expect "a sync tells its user of its own" "$(code "$J" POST /~ui/notifications -d '{"action":"post","kind":"sync","title":"laptop: 3 files carried"}') $(notes "$J" | j "d['items'][0]['title']")" \
       "204 laptop: 3 files carried"
expect "but tells nothing in another's name or kind" "$(code "$J" POST /~ui/notifications -d '{"action":"post","kind":"library","title":"x"}')" 400
expect "and what was told is cleared" "$(code "$J" POST /~ui/notifications -d '{"action":"clear"}') $(notes "$J" | j "len(d['items'])")" "204 0"
expect "nobody signed in is told nothing" "$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Socketley-UI: 1' "$U/~ui/notifications")" 401

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
