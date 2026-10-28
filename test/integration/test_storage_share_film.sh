#!/usr/bin/env bash
# Integration test: a film's share link plays in a chat.
#
# A chat embeds a player for a link whose page carries og:video:url, ending in
# .mp4, and a still it need not make itself.  The link of a film now answers a browser and a chat's preview
# with that page, as it does anything else but a player reading by range: a chat
# asks by HEAD and under names that change, and told the film it embeds nothing.
# ?raw and ?download are the file; a film no browser plays as it is gets a web copy, H.264 and AAC with
# its index in front, made once and then named by the page.
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: a film's share link plays in a chat ==="
FF="${SOCKETLEY_FFMPEG:-$(command -v ffmpeg || true)}"
[ -n "$FF" ] && [ -x "$FF" ] || { echo "  SKIP: ffmpeg is required (on the PATH or in SOCKETLEY_FFMPEG)"; exit 0; }
FFPROBE="$(dirname "$FF")/ffprobe"
[ -x "$FFPROBE" ] || FFPROBE="$(command -v ffprobe || true)"
[ -n "$FFPROBE" ] || { echo "  SKIP: ffprobe is required beside ffmpeg"; exit 0; }
. "$HERE/lib_ffmpeg.sh"
LACKS=$(ffmpeg_lacks "$FF" fmt:lavfi fmt:hls fmt:mp4 filter:testsrc2 filter:sine filter:scale enc:libx264 enc:aac enc:mjpeg fmt:matroska filter:testsrc filter:noise enc:mpeg4)
[ -z "$LACKS" ] || { echo "  SKIP: $FF has no $LACKS, which the films here or the storage's renditions are made with"; exit 0; }
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate stgfilm
trap 'daemon_stop' EXIT
export SOCKETLEY_FFMPEG="$FF"
daemon_start "$BIN"
P1=$((SL_PORT_BASE + 1915))
U="http://127.0.0.1:$P1"
T="$SOCKETLEY_TMPD"
cat > "$T/creds" <<EOF
[admin]
AKIAFILMADMIN0000000:filmadminsecretfilmadminsecretfilmadmin0
admin = true
EOF
A="AKIAFILMADMIN0000000:filmadminsecretfilmadminsecretfilmadmin0"
"$BIN" create storage film -p "$P1" --dir "$T/film" --credentials "$T/creds" -s >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/")" != 000 ] && break; sleep 0.1; done

ff() { "$FF" -hide_banner -loglevel error -y "$@"; }
# One a browser plays as it is, and one it does not: MPEG-4 Part 2 and MP3 in Matroska.
ff -f lavfi -i testsrc=size=640x360:rate=25 -f lavfi -i sine=frequency=440 -t 4 -c:v libx264 -pix_fmt yuv420p \
   -c:a aac -shortest "$T/clip.mp4"
ff -f lavfi -i testsrc=size=480x270:rate=25 -f lavfi -i sine=frequency=330 -t 4 -c:v mpeg4 -c:a libmp3lame \
   -shortest "$T/old.mkv" 2>/dev/null || ff -f lavfi -i testsrc=size=480x270:rate=25 -t 4 -c:v mpeg4 "$T/old.mkv"
curl -s -u "$A" -X MKCOL "$U/~dav/films/" >/dev/null
curl -s -u "$A" -T "$T/clip.mp4" -H "Content-Type: video/mp4" "$U/~dav/films/clip.mp4" >/dev/null
curl -s -u "$A" -T "$T/old.mkv" -H "Content-Type: video/x-matroska" "$U/~dav/films/old.mkv" >/dev/null
link() { curl -s -u "$A" -H 'X-Socketley-UI: 1' -H 'Content-Type: application/json' \
         -d "{\"bucket\":\"films\",\"key\":\"$1\",\"expires_in\":3600}" "$U/~share" |
         python3 -c 'import json,sys; print(json.load(sys.stdin)["url"])'; }
tw() { python3 -c 'import re,sys; m=re.search(r"<meta name=\"%s\" content=\"([^\"]*)\"" % sys.argv[1], sys.stdin.read()); print(m.group(1) if m else "")' "$1"; }
og() { python3 -c 'import re,sys; m=re.search(r"<meta property=\"%s\" content=\"([^\"]*)\"" % sys.argv[1], sys.stdin.read()); print(m.group(1) if m else "")' "$1"; }
L1=$(link clip.mp4)
L2=$(link old.mkv)

# ── a film a browser plays as it is ──
# What the interface asks for when it makes the link, which the page's size is read from.
curl -s -o /dev/null "$U/~media/info/~share/${L1#/~share/}"
PAGE=$(curl -s -H 'Accept: text/html' "$U$L1")
check "a browser opening a film's link gets a page with a player" "$(grep -c '<video' <<<"$PAGE")" 1
check "until its web copy is made a chat is given the still alone" \
      "$(og og:video:url <<<"$PAGE")|$(grep -o 'twitter:card" content="[^"]*' <<<"$PAGE")" '|twitter:card" content="summary_large_image'
curl -s -o /dev/null "$U/~media/web/~share/${L1#/~share/}?prepare"
for _ in $(seq 1 120); do
    [ "$(curl -s -I -o /dev/null -w '%{http_code}' "$U/~media/web/~share/${L1#/~share/}?prepare")" = 200 ] && break
    sleep 0.5
done
PAGE=$(curl -s -H 'Accept: text/html' "$U$L1")
# Discord embeds a player for a still it need not make and a URL ending in .mp4.
check "then the film, as a URL ending in .mp4" "$(og og:video:url <<<"$PAGE")" "$U/~media/web/~share/${L1#/~share/}.mp4"
check "which is the web copy" "$(curl -s -o /dev/null -w '%{http_code} %{content_type}' "$U/~media/web/~share/${L1#/~share/}.mp4")" "200 video/mp4"
check "as a player" "$(grep -o 'twitter:card" content="[^"]*' <<<"$PAGE")" 'twitter:card" content="player'
check "of the film's size" "$(og og:video:width <<<"$PAGE")x$(og og:video:height <<<"$PAGE")" "640x360"
check "with its still as the picture" "$(og og:image <<<"$PAGE")" "$U/~media/thumb-1280/~share/${L1#/~share/}"
check "named an MP4, to Open Graph and as the player's stream" \
      "$(og og:video:type <<<"$PAGE")|$(tw twitter:player:stream:content_type <<<"$PAGE")" "video/mp4|video/mp4"
check "and the film as the player's stream, which Discord plays without making a still" \
      "$(tw twitter:player:stream <<<"$PAGE")|$(tw twitter:image <<<"$PAGE")" \
      "$U/~media/web/~share/${L1#/~share/}.mp4|$U/~media/thumb-1280/~share/${L1#/~share/}"
check "a chat's preview gets the page too" \
      "$(curl -s -A 'Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)' "$U$L1" | grep -c 'og:video:url')" 1
# Discord asks by HEAD, and as an old Firefox accepting anything; told the film itself it embeds nothing.
check "so does a HEAD, which a chat asks first" "$(curl -s -I -o /dev/null -w '%{content_type}' "$U$L1")" "text/html; charset=utf-8"
check "and anything that is no player reading by range" \
      "$(curl -s -A 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:38.0) Gecko/20100101 Firefox/38.0' -H 'Accept: */*' "$U$L1" | grep -c 'og:video:url')" 1
check "?download is the file" "$(curl -s "$U$L1?download" | cmp -s - "$T/clip.mp4" && echo same)" same
check "and ?raw is the file for a browser too" "$(curl -s -H 'Accept: text/html' "$U$L1?raw" | cmp -s - "$T/clip.mp4" && echo same)" same
check "which a player reads by range" "$(curl -s -o /dev/null -w '%{http_code} %{size_download}' -r 0-99 "$U$L1?raw")" "206 100"
check "the still is there without a sign-in" "$(curl -s -o /dev/null -w '%{http_code}' "$U/~media/thumb-1280/~share/${L1#/~share/}")" 200

# ── a film it does not ──
PAGE=$(curl -s -H 'Accept: text/html' "$U$L2")
check "a film no browser plays gives a chat no film until its web copy is made" "$(og og:video:url <<<"$PAGE")" ""
check "and its page asks for that copy" "$(grep -c "web/~share/${L2#/~share/}?prepare" <<<"$PAGE")" 1
check "asking for it to be made does not wait for it" \
      "$(curl -s -o /dev/null -m 10 -w '%{http_code}' "$U/~media/web/~share/${L2#/~share/}?prepare")" 202
WEB=""
for _ in $(seq 1 120); do
    WEB=$(curl -s -o "$T/web.mp4" -w '%{http_code} %{content_type}' "$U/~media/web/~share/${L2#/~share/}")
    [ "$WEB" = "200 video/mp4" ] && break
    sleep 0.5
done
check "the web copy is made" "$WEB" "200 video/mp4"
check "as H.264 and AAC" "$("$FFPROBE" -v error -show_entries stream=codec_name -of csv=p=0 "$T/web.mp4" | sort | tr '\n' ' ')" \
      "$(grep -q mp3 <<<"$("$FFPROBE" -v error -show_entries stream=codec_name -of csv=p=0 "$T/old.mkv")" && echo 'aac h264 ' || echo 'h264 ')"
check "with its index in front, so it plays before it is whole" \
      "$(python3 -c 'import sys; b=open(sys.argv[1],"rb").read(); print(b.find(b"moov") < b.find(b"mdat"))' "$T/web.mp4")" True
check "and is read by range" "$(curl -s -o /dev/null -w '%{http_code} %{size_download}' -r 0-99 "$U/~media/web/~share/${L2#/~share/}")" "206 100"
PAGE=$(curl -s -H 'Accept: text/html' "$U$L2")
check "the page names the web copy once it is made" "$(og og:video:url <<<"$PAGE")" "$U/~media/web/~share/${L2#/~share/}.mp4"
check "and asks for nothing more" "$(grep -c '?prepare' <<<"$PAGE")" 0

check "and a HEAD asking for it says it is there" "$(curl -s -I -o /dev/null -w '%{http_code}' "$U/~media/web/~share/${L2#/~share/}?prepare")" 200

# ── a film denser than a chat embeds ──
# An H.264 MP4 a browser plays as it is, at a bitrate no chat proxies: its web copy is made again, at most 12 Mbit/s.
ff -f lavfi -i "testsrc2=size=640x360:rate=25,noise=alls=60:allf=t" -t 3 -c:v libx264 -crf 0 -preset ultrafast \
   -pix_fmt yuv420p "$T/dense.mp4"
curl -s -u "$A" -T "$T/dense.mp4" -H "Content-Type: video/mp4" "$U/~dav/films/dense.mp4" >/dev/null
L4=$(link dense.mp4)
curl -s -o /dev/null "$U/~media/info/~share/${L4#/~share/}"
for _ in $(seq 1 120); do
    [ "$(curl -s -I -o /dev/null -w '%{http_code}' "$U/~media/web/~share/${L4#/~share/}?prepare")" = 200 ] && break
    sleep 0.5
done
curl -s -o "$T/dense-web.mp4" "$U/~media/web/~share/${L4#/~share/}"
check "the film is denser than a chat embeds" \
      "$("$FFPROBE" -v error -show_entries format=bit_rate -of csv=p=0 "$T/dense.mp4" | awk '{print ($1 > 12000000)}')" 1
# The cap, and the one buffer of two seconds' worth an encoder may spend at once, over the film's three seconds.
check "and its web copy is not" \
      "$("$FFPROBE" -v error -show_entries format=bit_rate -of csv=p=0 "$T/dense-web.mp4" | awk '{print ($1 > 0 && $1 <= 20500000)}')" 1

# ── a long film of 60 frames a second ──
# Long enough that its copy is below the bitrate of 1440 lines, so it is made at 30 frames.
ff -f lavfi -i "testsrc2=size=320x180:rate=60" -t 50 -c:v mpeg4 -q:v 8 "$T/long60.mkv"
curl -s -u "$A" -T "$T/long60.mkv" "$U/~dav/films/long60.mkv" >/dev/null
L5=$(link long60.mkv)
curl -s -o /dev/null "$U/~media/info/~share/${L5#/~share/}"
for _ in $(seq 1 240); do
    [ "$(curl -s -I -o /dev/null -w '%{http_code}' "$U/~media/web/~share/${L5#/~share/}?prepare")" = 200 ] && break
    sleep 0.5
done
curl -s -o "$T/long60-web.mp4" "$U/~media/web/~share/${L5#/~share/}"
check "a long film of 60 frames a second gets a web copy of 30" \
      "$("$FFPROBE" -v error -select_streams v:0 -show_entries stream=r_frame_rate -of csv=p=0 "$T/long60-web.mp4")" "30/1"

# ── a library that prepares its films as they arrive ──
UI=(-u "$A" -H 'X-Socketley-UI: 1' -H 'Content-Type: application/json')
check "a library makes no web copies of what is put into it unless told to" \
      "$(curl -s "${UI[@]}" "$U/~ui/library?bucket=films")" '{"bucket":"films","web_copies":false,"may_change":true}'
check "and is told to by whoever may change its tags" \
      "$(curl -s -o /dev/null -w '%{http_code}' "${UI[@]}" -d '{"bucket":"films","web_copies":true}' "$U/~ui/library")" 204
check "which it then says" "$(curl -s "${UI[@]}" "$U/~ui/library?bucket=films")" '{"bucket":"films","web_copies":true,"may_change":true}'
check "as a tag of the library" "$(curl -s --aws-sigv4 aws:amz:us-east-1:s3 -u "$A" "$U/films?tagging" | grep -o '<Key>socketley:web-copies</Key><Value>on</Value>')" \
      '<Key>socketley:web-copies</Key><Value>on</Value>'
# Long enough that its copy is 720 lines, from a picture of 1080 at a frame a second, which is quick to make.
ff -f lavfi -i "testsrc2=size=1920x1080:rate=1" -t 150 -c:v libx264 -preset ultrafast -pix_fmt yuv420p "$T/wide.mp4"
curl -s -u "$A" -T "$T/wide.mp4" "$U/~dav/films/wide.mp4" >/dev/null
L6=$(link wide.mp4)
# The page asks for nothing, so a copy it names was made because the film was put.
PAGE=""
for _ in $(seq 1 240); do
    PAGE=$(curl -s -H 'Accept: text/html' "$U$L6")
    [ -n "$(og og:video:url <<<"$PAGE")" ] && break
    sleep 0.5
done
check "a film put into it has its web copy made with no one asking" "$(og og:video:url <<<"$PAGE")" "$U/~media/web/~share/${L6#/~share/}.mp4"
curl -s -o "$T/wide-web.mp4" "$U/~media/web/~share/${L6#/~share/}"
check "and its page gives a chat the copy's size, not the film's" \
      "$(og og:video:width <<<"$PAGE")x$(og og:video:height <<<"$PAGE")|$(tw twitter:player:width <<<"$PAGE")x$(tw twitter:player:height <<<"$PAGE")" \
      "$("$FFPROBE" -v error -select_streams v:0 -show_entries stream=width,height -of csv=p=0:s=x "$T/wide-web.mp4")|1280x720"
check "which is smaller" "$("$FFPROBE" -v error -select_streams v:0 -show_entries stream=width,height -of csv=p=0:s=x "$T/wide-web.mp4")" "1280x720"
check "and turned off again" \
      "$(curl -s -o /dev/null -w '%{http_code}' "${UI[@]}" -d '{"bucket":"films","web_copies":false}' "$U/~ui/library")|$(curl -s "${UI[@]}" "$U/~ui/library?bucket=films")" \
      '204|{"bucket":"films","web_copies":false,"may_change":true}'
check "a setting that is not true or false is refused" \
      "$(curl -s -o /dev/null -w '%{http_code}' "${UI[@]}" -d '{"bucket":"films","web_copies":"yes"}' "$U/~ui/library")" 400

# ── what is not a film ──
printf 'hello\n' > "$T/note.txt"
curl -s -u "$A" -T "$T/note.txt" "$U/~dav/films/note.txt" >/dev/null
L3=$(link note.txt)
check "a link of anything else is the file for a browser too" "$(curl -s -H 'Accept: text/html' "$U$L3")" "hello"
check "and for anything else" "$(curl -s "$U$L3")" "hello"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
