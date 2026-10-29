#!/usr/bin/env bash
# Integration test: thumbnails and HLS made by ffmpeg from the objects, and kept
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a thumbnail not a JPEG, or not of the width asked for, of a film, a picture
#     or a film shorter than the still's offset
#   * a stream that does not play to the film's end at the height asked for, or
#     a copied one that is not the source's
#   * a medium made again for a request the cache has it for, or lost by a restart
#   * one medium asked for at once on two shards made twice, or made differently
#   * media given to a caller the object is not given to, or not given through a
#     link to it
#   * ffmpeg's own address for an object opening without its signature
#   * something that is no medium answered as one, or a cache past its size
#   * a film's sound tracks or chapters, or a song's tags, missing from its info,
#     or a stream asked for with another sound track carrying the first
#   * a film's stills for a seek bar not a row of tiles, or offered for a song
#   * a film whose container claims a trillion seconds cut into that many
#     segments, holding its shard in the loop that writes the playlist
#   * an info or a playlist answered 304 to the tag of a binary that wrote less in
#     it, so a browser keeps showing what the binary before said
#   * an object that is an HLS playlist making ffmpeg open a URL it names
# suite: isolated
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: storage media ==="
FF="${SOCKETLEY_FFMPEG:-$(command -v ffmpeg || true)}"
[ -n "$FF" ] && [ -x "$FF" ] || { echo "  SKIP: ffmpeg is required (on the PATH or in SOCKETLEY_FFMPEG)"; exit 0; }
FFPROBE="$(dirname "$FF")/ffprobe"
[ -x "$FFPROBE" ] || FFPROBE="$(command -v ffprobe || true)"
[ -n "$FFPROBE" ] || { echo "  SKIP: ffprobe is required beside ffmpeg"; exit 0; }
. "$HERE/lib_ffmpeg.sh"
LACKS=$(ffmpeg_lacks "$FF" fmt:lavfi fmt:hls fmt:mp4 filter:testsrc2 filter:sine filter:scale enc:libx264 enc:aac enc:mjpeg fmt:matroska filter:testsrc filter:anullsrc filter:noise enc:libx265 enc:ac3 enc:libmp3lame enc:libopus enc:mpeg4 enc:png enc:webvtt)
[ -z "$LACKS" ] || { echo "  SKIP: $FF has no $LACKS, which the films here or the storage's renditions are made with"; exit 0; }
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate stgmedia
trap 'daemon_stop' EXIT
# ffmpeg two seconds slow to start, so that a stream queued behind others is seen to wait.
mkdir -p "$SOCKETLEY_TMPD/bin"
printf '#!/bin/sh\nsleep 2\nexec "%s" "$@"\n' "$FF" > "$SOCKETLEY_TMPD/bin/ffmpeg"; chmod +x "$SOCKETLEY_TMPD/bin/ffmpeg"
ln -s "$FFPROBE" "$SOCKETLEY_TMPD/bin/ffprobe"
export SOCKETLEY_FFMPEG="$SOCKETLEY_TMPD/bin/ffmpeg"
# Small enough that the last film below overruns it, so that the cache's bound is seen to hold.
export SOCKETLEY_MEDIA_CACHE_MB=2
daemon_start "$BIN"
P1=$((SL_PORT_BASE + 1905))
U="http://127.0.0.1:$P1"
T="$SOCKETLEY_TMPD"
cat > "$T/creds" <<EOF
[admin]
AKIAMEDIAADMIN000000:mediaadminsecretmediaadminsecret00000000
admin = true
[eve]
AKIAMEDIAEVE00000000:mediaevesecretmediaevesecretmediaeve0000
EOF
A="AKIAMEDIAADMIN000000:mediaadminsecretmediaadminsecret00000000"
E="AKIAMEDIAEVE00000000:mediaevesecretmediaevesecretmediaeve0000"
"$BIN" create storage media -p "$P1" --dir "$T/media" --credentials "$T/creds" --shards 2 -s >/dev/null 2>&1
up() { for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/")" != 000 ] && return 0; sleep 0.1; done; return 1; }
up || bad "the runtime serves" "no answer on $P1"

ff() { "$FF" -hide_banner -loglevel error -y "$@"; }
ff -f lavfi -i testsrc=size=640x360:rate=25 -f lavfi -i sine=frequency=440 -t 10 -c:v libx264 -pix_fmt yuv420p \
   -c:a aac -shortest "$T/clip.mp4"
ff -f lavfi -i testsrc=size=800x600 -frames:v 1 "$T/pic.png"
ff -f lavfi -i testsrc=size=320x240:rate=25 -t 1 -c:v libx264 -pix_fmt yuv420p "$T/short.mp4"
printf 'just text\n' > "$T/note.txt"
code() { curl -s -m 60 -o /dev/null -w '%{http_code}' "$@"; }
# The status of a GET whose body goes to the file named first.
get() { local f=$1; shift; curl -s -m 60 -o "$f" -w '%{http_code}' "$@"; }
check "a bucket is made" "$(code -u "$A" -X MKCOL "$U/~dav/films/")" 201
for f in clip.mp4 pic.png short.mp4 note.txt; do
    check "$f is stored" "$(code -u "$A" -T "$T/$f" "$U/~dav/films/$f")" 201
done
# A counter summed over the shards, once it has stopped moving: a worker tells its figures every 250 ms.
stat_now() { "$BIN" stats media | awk -F: -v k="$1" '$1 == k { s += $2 } END { print s + 0 }'; }
stat() {
    local a b
    a=$(stat_now "$1")
    for _ in $(seq 1 20); do sleep 0.6; b=$(stat_now "$1"); [ "$a" = "$b" ] && break; a=$b; done
    echo "$a"
}
width() { "$FFPROBE" -v error -select_streams v:0 -show_entries stream=width -of csv=p=0 "$1" 2>/dev/null; }
height() { "$FFPROBE" -v error -select_streams v:0 -show_entries stream=height -of csv=p=0 "$1" 2>/dev/null; }

# Thumbnails.
check "a film's thumbnail" "$(get "$T/t1.jpg" -u "$A" "$U/~media/thumb-256/films/clip.mp4")" 200
check "is a JPEG" "$(head -c 3 "$T/t1.jpg" | od -An -tx1 | tr -d ' ')" ffd8ff
check "of the width asked for" "$(width "$T/t1.jpg")" 256
check "a picture's thumbnail" "$(get "$T/t2.jpg" -u "$A" "$U/~media/thumb-128/films/pic.png")" 200
check "of the width asked for" "$(width "$T/t2.jpg")" 128
check "a film shorter than the still's offset has one" "$(get "$T/t3.jpg" -u "$A" "$U/~media/thumb-128/films/short.mp4")" 200
check "and it is a picture" "$(width "$T/t3.jpg")" 128
made=$(ls "$T/media/.media" | grep -c '^[0-9a-f]\{64\}$')
t0=$(date +%s%N)
check "a thumbnail asked for again" "$(get "$T/t1b.jpg" -u "$A" "$U/~media/thumb-256/films/clip.mp4")" 200
t1=$(date +%s%N)
check "is the one kept" "$(cmp -s "$T/t1.jpg" "$T/t1b.jpg" && echo same)" same
check "and nothing is made for it" "$(ls "$T/media/.media" | grep -c '^[0-9a-f]\{64\}$')" "$made"
check "by ffmpeg" "$(stat media_made)" 3
# Under the 2 s the ffmpeg above sleeps first, so a thumbnail made again cannot pass it, and a loaded box has 1.5 s.
[ $(( (t1 - t0) / 1000000 )) -lt 1500 ] && ok || bad "a kept thumbnail is served at once" "$(( (t1 - t0) / 1000000 )) ms"
# One new thumbnail asked for four times at once, on either shard, is made once.
made_before=$(stat media_made)
>"$T/pcodes"; pids=()
for i in 1 2 3 4; do
    curl -s -m 60 -w '%{http_code}\n' -u "$A" -o "$T/p$i.jpg" "$U/~media/thumb-640/films/pic.png" >> "$T/pcodes" & pids+=($!)
done
wait "${pids[@]}"
check "four at once are answered" "$(sort "$T/pcodes" | uniq -c | awk '{print $1":"$2}')" "4:200"
check "a thumbnail asked for at once is the same for all" \
      "$(cmp -s "$T/p1.jpg" "$T/p2.jpg" && cmp -s "$T/p1.jpg" "$T/p3.jpg" && cmp -s "$T/p1.jpg" "$T/p4.jpg" && echo same)" same
check "and made once" "$(( $(stat media_made) - made_before ))" 1
check "into one place" "$(ls "$T/media/.media" | grep -c '^[0-9a-f]\{64\}$')" "$((made + 1))"
check "something that is no medium is 415" "$(code -u "$A" "$U/~media/thumb-128/films/note.txt")" 415
check "an unknown variant is 404" "$(code -u "$A" "$U/~media/thumb-129/films/clip.mp4")" 404
check "a missing object is 404" "$(code -u "$A" "$U/~media/thumb-128/films/none.mp4")" 404

# Who may have them.
check "media without credentials are 401" "$(code "$U/~media/thumb-256/films/clip.mp4")" 401
check "and to a user the object is not given, 403" "$(code -u "$E" "$U/~media/thumb-256/films/clip.mp4")" 403
link=$(curl -s -u "$A" -X POST -d '{"bucket":"films","key":"clip.mp4"}' "$U/~share" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
check "a link's medium needs no credentials" "$(code "$U/~media/thumb-256/~share/$link")" 200
folder=$(curl -s -u "$A" -X POST -d '{"bucket":"films","key":""}' "$U/~share" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
check "nor a folder link's" "$(code "$U/~media/thumb-128/~share/$folder/pic.png")" 200
check "a link no medium is named by is 404" "$(code "$U/~media/thumb-128/~share/AAAAAAAAAAAAAAAAAAAAAA")" 404
check "ffmpeg's address for an object without its signature is 403" "$(code "$U/~media/src/films/clip.mp4?t=9999999999&s=00")" 403

# Streams: the playlist grows until it ends, and its segments play to the film's end.
stream() {
    local v=$1 src=$2 dir=$3
    mkdir -p "$dir"
    for _ in $(seq 1 600); do
        get "$dir/index.m3u8" -u "$A" "$U/~media/$v/films/$src/index.m3u8" > "$dir/code"
        grep -q EXT-X-ENDLIST "$dir/index.m3u8" 2>/dev/null && break
        sleep 0.1
    done
    # The segments are fragments of one MP4, whose start is the playlist's map.
    curl -s -u "$A" "$U/~media/$v/films/$src/init.mp4" > "$dir/all.mp4"
    for s in $(grep '^seg' "$dir/index.m3u8"); do
        curl -s -u "$A" "$U/~media/$v/films/$src/$s" >> "$dir/all.mp4"
    done
}
stream hls-240 clip.mp4 "$T/h240"
check "a stream's playlist" "$(cat "$T/h240/code")" 200
check "is HLS" "$(head -1 "$T/h240/index.m3u8")" "#EXTM3U"
check "and ends" "$(grep -c EXT-X-ENDLIST "$T/h240/index.m3u8")" 1
check "and maps its segments' start" "$(grep -c 'EXT-X-MAP:URI="init.mp4?v=[0-9a-f]*"' "$T/h240/index.m3u8")" 1
check "its segments are of the height asked for" "$(height "$T/h240/all.mp4")" 240
dur=$("$FFPROBE" -v error -show_entries format=duration -of csv=p=0 "$T/h240/all.mp4" | cut -d. -f1)
check "and play to the film's end" "$dur" 10
check "with its sound" "$("$FFPROBE" -v error -select_streams a:0 -show_entries stream=codec_name -of csv=p=0 "$T/h240/all.mp4")" aac
stream hls-copy clip.mp4 "$T/hcopy"
check "a copied stream keeps the source's height" "$(height "$T/hcopy/all.mp4")" 360
check "a segment past the end is 404" "$(code -u "$A" "$U/~media/hls-240/films/clip.mp4/seg00999.m4s")" 404
check "a file a stream has none of is 404" "$(code -u "$A" "$U/~media/hls-240/films/clip.mp4/x.ts")" 404

# Streams do not queue behind one another, as thumbnails do: five at once over two shards all start together,
# where two per shard would hold one back until another's ffmpeg had run.
# The spread between the first and the last answer, as one held back waits out a whole other ffmpeg and its 2 s sleep.
pids=(); n=0
for path in hls-240/films/short.mp4/seg00000.m4s hls-360/films/short.mp4/seg00000.m4s hls-480/films/short.mp4/seg00000.m4s \
            hls-720/films/short.mp4/seg00000.m4s hls-copy/films/short.mp4/index.m3u8; do
    n=$((n + 1))
    { curl -s -m 60 -u "$A" -o /dev/null "$U/~media/$path"; date +%s%N > "$T/five$n"; } & pids+=($!)
done
wait "${pids[@]}"
ms=$(( ($(sort -n "$T"/five? | tail -1) - $(sort -n "$T"/five? | head -1)) / 1000000 ))
[ "$ms" -lt 2000 ] && ok || bad "five streams at once start together" "the last answer $ms ms after the first"

# Adaptive streaming: what the object is, the ladder a player chooses from, and renditions written up front.
info=$(curl -s -u "$A" "$U/~media/info/films/clip.mp4")
check "info says what the film is" \
      "$(python3 -c 'import json,sys; j=json.loads(sys.argv[1]); print(j["width"], j["height"], j["video"], j["audio"], j["hdr"], j["renditions"])' "$info")" \
      "640 360 h264 aac False [360, 240]"
check "and the type a browser is asked about" "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["mime"])' "$info")" \
      'video/mp4; codecs="avc1.64001e, mp4a.40.2"'
master=$(curl -s -u "$A" "$U/~media/hls/films/clip.mp4/master.m3u8")
check "the master names a rendition for every rung the film fills" "$(grep -c '^/~media/hls-[0-9]*/films/clip.mp4/index.m3u8?v=[0-9a-f]*$' <<<"$master")" 2
check "with its size and codecs" "$(grep -o 'RESOLUTION=[0-9x]*,CODECS="[^"]*"' <<<"$master" | head -2 | tr '\n' ' ')" \
      'RESOLUTION=640x360,CODECS="avc1.64002a,mp4a.40.2" RESOLUTION=426x240,CODECS="avc1.64002a,mp4a.40.2" '
check "the bandwidth a segment can reach, and the frame rate" "$(grep -o 'BANDWIDTH=[0-9]*\|FRAME-RATE=[0-9.]*' <<<"$master" | head -2 | tr '\n' ' ')" \
      "BANDWIDTH=1410000 FRAME-RATE=25.000 "
check "and the film's own stream, copied" "$(grep -c '^/~media/hls-copy/films/clip.mp4/index.m3u8?v=[0-9a-f]*$' <<<"$master")" 1
idx=$(curl -s -u "$A" "$U/~media/hls-240/films/clip.mp4/index.m3u8")
check "a rendition's playlist is whole from the start" "$(grep -c '^seg' <<<"$idx") $(grep -c ENDLIST <<<"$idx") $(grep -c 'PLAYLIST-TYPE:VOD' <<<"$idx")" "3 1 1"

# The cache directory of a variant of a stored file: its name hashes the variant, the object and its ETag.
mdir() { printf '%s\nfilms\n%s\n%s' "$1" "$2" "$(md5sum < "$3" | cut -d' ' -f1)" | sha256sum | sed "s|  -||; s|^|$T/media/.media/|"; }
secs() { awk '{printf "%.0f", $1}'; }

# A seek: a segment far into a film is made from there, on the film's own clock, and the rest joins up with it.
ff -f lavfi -i testsrc2=size=640x360:rate=25 -f lavfi -i sine=frequency=330 -t 180 -c:v libx264 -preset ultrafast \
   -pix_fmt yuv420p -c:a aac -shortest "$T/long.mp4"
code -u "$A" -T "$T/long.mp4" "$U/~dav/films/long.mp4" >/dev/null
L="$U/~media/hls-240/films/long.mp4"
get "$T/init.mp4" -u "$A" "$L/init.mp4" >/dev/null
t0=$(date +%s%N)
check "a segment 48 s in, asked for first" "$(get "$T/s12.m4s" -u "$A" "$L/seg00012.m4s")" 200
cat "$T/init.mp4" "$T/s12.m4s" > "$T/s12.mp4"
check "begins 48 s into the film" "$("$FFPROBE" -v error -select_streams v:0 -show_entries stream=start_time -of csv=p=0 "$T/s12.mp4" | secs)" 48
mkdir -p "$T/lng"
for i in $(seq 0 44); do curl -s -u "$A" -o "$T/lng/$(printf 'seg%05d.m4s' $i)" "$L/$(printf 'seg%05d.m4s' $i)"; done
cat "$T/init.mp4" "$T"/lng/seg*.m4s > "$T/lng.mp4"
check "and the whole film joins up, seek and all" "$("$FFPROBE" -v error -show_entries format=duration -of csv=p=0 "$T/lng.mp4" | secs)" 180
check "and decodes without an error" "$("$FF" -v error -i "$T/lng.mp4" -f null - 2>&1 | grep -c .)" 0
for _ in $(seq 1 20); do [ -e "$(mdir hls-240 long.mp4 "$T/long.mp4")/done" ] && break; sleep 0.1; done
check "and is done, from two jobs" "$([ -e "$(mdir hls-240 long.mp4 "$T/long.mp4")/done" ] && echo yes)" yes

# Held still: a job far ahead of every player waits for one, and goes on when one comes near.
R="$U/~media/hls-360/films/long.mp4"
dir=$(mdir hls-360 long.mp4 "$T/long.mp4")
# Until the count rests for 2 s, asking the first segment again so the job is never one nobody asks of.
made=-1; still=0
for _ in $(seq 1 120); do
    code -u "$A" "$R/seg00000.m4s" >/dev/null
    sleep 0.5
    n=$(ls "$dir" 2>/dev/null | grep -c '^seg.*\.m4s$')
    if [ "$n" = "$made" ]; then still=$((still + 1)); else still=0; made=$n; fi
    [ "$made" -ge 14 ] && [ "$still" -ge 4 ] && break
done
[ "$made" -ge 14 ] && [ "$made" -le 20 ] && ok || bad "a job far ahead of its player is held still" "$made segments made"
sleep 2
check "and stays held" "$(ls "$dir" | grep -c '^seg.*\.m4s$')" "$made"
code -u "$A" "$R/seg00010.m4s" >/dev/null
for _ in $(seq 1 50); do [ "$(ls "$dir" | grep -c '^seg.*\.m4s$')" -gt "$made" ] && break; sleep 0.2; done
[ "$(ls "$dir" | grep -c '^seg.*\.m4s$')" -gt "$made" ] && ok || bad "a player coming near lets it go on" "still $made"

# HDR is made SDR for an H.264 rendition, and a sound no browser plays is made AAC in a copied stream.
ff -f lavfi -i testsrc2=size=640x360:rate=25 -t 4 -c:v libx265 -pix_fmt yuv420p10le \
   -x265-params colorprim=bt2020:transfer=smpte2084:colormatrix=bt2020nc:log-level=error "$T/hdr.mp4"
code -u "$A" -T "$T/hdr.mp4" "$U/~dav/films/hdr.mp4" >/dev/null
check "an HDR film is said to be one" "$(curl -s -u "$A" "$U/~media/info/films/hdr.mp4" | python3 -c 'import json,sys; j=json.load(sys.stdin); print(j["video"], j["hdr"])')" "hevc True"
get "$T/hi.mp4" -u "$A" "$U/~media/hls-360/films/hdr.mp4/init.mp4" >/dev/null
get "$T/h0.m4s" -u "$A" "$U/~media/hls-360/films/hdr.mp4/seg00000.m4s" >/dev/null
cat "$T/hi.mp4" "$T/h0.m4s" > "$T/h0.mp4"
check "and its rendition is SDR, 8 bit" "$("$FFPROBE" -v error -select_streams v:0 -show_entries stream=pix_fmt,color_transfer -of csv=p=0 "$T/h0.mp4")" "yuv420p,bt709"
ff -f lavfi -i testsrc2=size=320x240:rate=25 -f lavfi -i sine=frequency=500 -t 6 -c:v libx264 -preset ultrafast -pix_fmt yuv420p \
   -c:a ac3 -shortest "$T/ac3.mkv"
code -u "$A" -T "$T/ac3.mkv" "$U/~dav/films/ac3.mkv" >/dev/null
stream hls-copy ac3.mkv "$T/hac3"
check "a copied stream keeps the picture and makes the sound AAC" \
      "$("$FFPROBE" -v error -show_entries stream=codec_name -of csv=p=0 "$T/hac3/all.mp4" | tr '\n' ' ')" "h264 aac "

# A HEAD's answer has no body, so the next answer on the connection is read as itself.
# What follows a HEAD's head on one connection, with a GET sent behind it: the GET's status line when the HEAD
# carried no body, as curl would hide by opening another connection.
after_head() { python3 - "$1" "$2" "$3" "$4" <<'PYEOF'
import socket, sys, base64
port, auth, head, get = sys.argv[1:5]
a = base64.b64encode(auth.encode()).decode()
req = lambda m, p: ("%s %s HTTP/1.1\r\nHost: x\r\nAuthorization: Basic %s\r\n\r\n" % (m, p, a)).encode()
s = socket.create_connection(("127.0.0.1", int(port)))
s.sendall(req("HEAD", head) + req("GET", get))
s.settimeout(3)
data = b""
try:
    while b"\r\n\r\n" not in data[data.find(b"\r\n\r\n") + 4:]:
        d = s.recv(65536)
        if not d:
            break
        data += d
except Exception:
    pass
i = data.find(b"\r\n\r\n")
print(data[i + 4:i + 16].decode(errors="replace"))
PYEOF
}
check "a HEAD of an application answers no body" "$(after_head "$P1" "$A" /~media/info/films/clip.mp4 /~media/info/films/clip.mp4)" "HTTP/1.1 200"

# What a versioned URL is cached for, a revalidation, and a range.
seg=$(grep -m1 '^seg' <<<"$idx")
hdrs=$(curl -s -u "$A" -D - -o /dev/null "$U/~media/hls-240/films/clip.mp4/$seg")
check "a segment by a versioned URL is cached for good" "$(grep -i '^cache-control' <<<"$hdrs" | tr -d '\r')" \
      "Cache-Control: private, max-age=31536000, immutable"
etag=$(grep -i '^etag' <<<"$hdrs" | cut -d' ' -f2 | tr -d '\r')
check "and revalidates to 304" "$(code -u "$A" -H "If-None-Match: $etag" "$U/~media/hls-240/films/clip.mp4/$seg")" 304
check "a range of it is 206" "$(curl -s -u "$A" -r 0-99 -o "$T/r.bin" -w '%{http_code}' "$U/~media/hls-240/films/clip.mp4/$seg") $(wc -c < "$T/r.bin")" "206 100"
# A range wholly past the end is told the length, not handed the whole segment.
seglen=$(curl -s -u "$A" -o /dev/null -w '%{size_download}' "$U/~media/hls-240/films/clip.mp4/$seg")
check "a range past its end is 416 with its length" \
    "$(curl -s -u "$A" -H "Range: bytes=$seglen-" -D - -o "$T/r416.bin" "$U/~media/hls-240/films/clip.mp4/$seg" | tr -d '\r' | grep -iE '^(HTTP|content-range)' | tr '\n' ' ')$(wc -c < "$T/r416.bin")" \
    "HTTP/1.1 416 Range Not Satisfiable Content-Range: bytes */$seglen 0"
check "and a suffix of it is its last bytes" "$(curl -s -u "$A" -H 'Range: bytes=-10' -o "$T/rs.bin" -w '%{http_code}' "$U/~media/hls-240/films/clip.mp4/$seg") $(wc -c < "$T/rs.bin")" "206 10"
check "the master is asked again, and has an ETag" \
      "$(curl -s -u "$A" -D - -o /dev/null "$U/~media/hls/films/clip.mp4/master.m3u8" | grep -ciE '^(cache-control: private, no-cache|etag:)')" 2
# The info's tag names its text, so what a browser kept from a binary that wrote less is sent again, as it is not 304.
itag=$(curl -s -u "$A" -D - -o /dev/null "$U/~media/info/films/clip.mp4" | grep -i '^etag' | cut -d' ' -f2 | tr -d '\r')
check "the info revalidates to 304 on its own tag" "$(code -u "$A" -H "If-None-Match: $itag" "$U/~media/info/films/clip.mp4")" 304
over=$(curl -s -u "$A" -I "$U/~dav/films/clip.mp4" | grep -i '^etag' | sed 's/[^"]*"\([0-9a-f]\{16\}\).*/\1/')
[[ "$over" =~ ^[0-9a-f]{16}$ ]] && ok || bad "the object's tag begins with the version the info's tag names" "'$over'"
check "and is sent again to the tag a binary gave it that named only the object's version" \
      "$(code -u "$A" -H "If-None-Match: \"$over-info/info\"" "$U/~media/info/films/clip.mp4")" 200

# The object's file is read directly, not over the listener.
check "ffmpeg reads an unencrypted object's file" "$( [ "$(stat media_direct)" -gt 0 ] && echo yes)" yes

# An init asked for before a far segment: the job it began at 0 goes, and the one at the far segment stays.
L4="$U/~media/hls-480/films/long.mp4"
curl -s -m 60 -u "$A" -o "$T/i4.mp4" "$L4/init.mp4" & ip=$!
sleep 0.3
check "a far segment asked beside the init" "$(get "$T/s4.m4s" -u "$A" "$L4/seg00020.m4s")" 200
wait $ip
# The job the init began at 0 is let go by the seek, on whichever shard it runs.
for _ in $(seq 1 30); do [ "$(ls "$(mdir hls-480 long.mp4 "$T/long.mp4")/jobs" | grep -c '\.lock$')" = 1 ] && break; sleep 0.1; done
check "leaves the one job there, and none at the start" "$(ls "$(mdir hls-480 long.mp4 "$T/long.mp4")/jobs" | grep '\.lock$' | tr '\n' ' ')" "20.lock "
cat "$T/i4.mp4" "$T/s4.m4s" > "$T/s4.mp4"
check "and the init fits it" "$("$FFPROBE" -v error -select_streams v:0 -show_entries stream=start_time -of csv=p=0 "$T/s4.mp4" | secs)" 80

# A picture that ends before its sound: the last segment is the picture's, and none past it waits for ever.
ff -f lavfi -i testsrc2=size=320x240:rate=25:duration=6 -f lavfi -i sine=frequency=600:duration=9 -c:v libx264 \
   -preset ultrafast -pix_fmt yuv420p -c:a aac "$T/short_pic.mp4"
code -u "$A" -T "$T/short_pic.mp4" "$U/~dav/films/short_pic.mp4" >/dev/null
sp=$(curl -s -u "$A" "$U/~media/hls-240/films/short_pic.mp4/index.m3u8")
check "a film whose sound outlasts its picture has the picture's segments" "$(grep -c '^seg' <<<"$sp")" 2
check "and every one of them is made" "$(for s in $(grep '^seg' <<<"$sp"); do code -u "$A" "$U/~media/hls-240/films/short_pic.mp4/$s"; echo; done | tr '\n' ' ')" "200 200 "

# Text subtitles as WebVTT, in the master and as a track.
printf '1\n00:00:01,000 --> 00:00:03,000\nHello from the subtitles\n\n2\n00:00:04,000 --> 00:00:06,000\nSecond line\n' > "$T/s.srt"
ff -f lavfi -i testsrc2=size=320x240:rate=25:duration=7 -i "$T/s.srt" -map 0:v -map 1:s -c:v libx264 -preset ultrafast \
   -pix_fmt yuv420p -c:s srt -metadata:s:s:0 language=eng -metadata:s:s:0 title=English "$T/subbed.mkv"
code -u "$A" -T "$T/subbed.mkv" "$U/~dav/films/subbed.mkv" >/dev/null
sinfo=$(curl -s -u "$A" "$U/~media/info/films/subbed.mkv")
check "info names the text subtitles" "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["subtitles"])' "$sinfo")" \
      "[{'index': 1, 'lang': 'eng', 'title': 'English'}]"
smaster=$(curl -s -u "$A" "$U/~media/hls/films/subbed.mkv/master.m3u8")
check "the master offers them" "$(grep -c '^#EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID="subs",NAME="English",LANGUAGE="eng"' <<<"$smaster") $(grep -c 'SUBTITLES="subs"' <<<"$smaster")" "1 2"
vtt=$(curl -s -u "$A" "$U/~media/sub-1/films/subbed.mkv/subs.vtt")
check "as WebVTT on the film's clock" "$(head -2 <<<"$vtt" | tr '\n' '|')" "WEBVTT|X-TIMESTAMP-MAP=MPEGTS:0,LOCAL:00:00:00.000|"
check "with its cues" "$(grep -c 'Hello from the subtitles\|Second line' <<<"$vtt")" 2
check "a stream that is no text subtitle is 404" "$(code -u "$A" "$U/~media/sub-0/films/subbed.mkv/subs.vtt")" 404

# Sound tracks, chapters and a song's tags.
printf ';FFMETADATA1\n[CHAPTER]\nTIMEBASE=1/1000\nSTART=0\nEND=3000\ntitle=Intro\n[CHAPTER]\nTIMEBASE=1/1000\nSTART=3000\nEND=7000\ntitle=Main part\n' > "$T/chap.txt"
ff -f lavfi -i testsrc2=size=320x240:rate=25:duration=7 -f lavfi -i sine=frequency=440:duration=7 -f lavfi -i anullsrc=channel_layout=5.1:sample_rate=48000 \
   -i "$T/chap.txt" -map 0:v -map 1:a -map 2:a -map_chapters 3 -t 7 -c:v libx264 -preset ultrafast -pix_fmt yuv420p -c:a aac \
   -metadata:s:a:0 language=eng -metadata:s:a:0 title=English -metadata:s:a:1 language=ger -metadata:s:a:1 title=Deutsch \
   -disposition:a:0 default -disposition:a:1 0 "$T/dual.mkv"
code -u "$A" -T "$T/dual.mkv" "$U/~dav/films/dual.mkv" >/dev/null
dinfo=$(curl -s -u "$A" "$U/~media/info/films/dual.mkv")
check "info names every sound track" \
      "$(python3 -c 'import json,sys; print([(t["codec"], t["channels"], t["lang"], t["title"], t["default"]) for t in json.loads(sys.argv[1])["tracks"]])' "$dinfo")" \
      "[('aac', 1, 'eng', 'English', True), ('aac', 6, 'ger', 'Deutsch', False)]"
check "and the chapters" "$(python3 -c 'import json,sys; print([(c["start"], c["end"], c["title"]) for c in json.loads(sys.argv[1])["chapters"]])' "$dinfo")" \
      "[(0.0, 3.0, 'Intro'), (3.0, 7.0, 'Main part')]"
check "and no song's title from a film's sound track" "$(python3 -c 'import json,sys; print(repr(json.loads(sys.argv[1])["tags"]["title"]))' "$dinfo")" "''"
loud() { "$FF" -hide_banner -i "$1" -map 0:a:0 -af volumedetect -f null - 2>&1 | grep -o 'mean_volume: [-0-9.]*' | awk '{ print ($2 > -60) ? "loud" : "silent" }'; }
check "a master for another sound track names its streams with it" \
      "$(curl -s -u "$A" "$U/~media/hls-a1/films/dual.mkv/master.m3u8" | grep -c '^/~media/hls-\(240\|copy\)-a1/films/dual.mkv/index.m3u8')" 2
stream hls-240 dual.mkv "$T/d0"; stream hls-240-a1 dual.mkv "$T/d1"
check "a stream carries the first sound track" "$(loud "$T/d0/all.mp4")" loud
check "and with -a1 the second" "$(loud "$T/d1/all.mp4")" silent
stream hls-copy-a1 dual.mkv "$T/dc1"
check "a copied stream of it makes six channels two" "$(loud "$T/dc1/all.mp4") $("$FFPROBE" -v error -select_streams a:0 -show_entries stream=channels -of csv=p=0 "$T/dc1/all.mp4")" "silent 2"
check "a track the film has not is 404" "$(code -u "$A" "$U/~media/hls-240-a2/films/dual.mkv/index.m3u8")" 404
ff -f lavfi -i sine=frequency=500:duration=2 -c:a libmp3lame -metadata title="First Song" -metadata artist="The Band" \
   -metadata album="A Record" -metadata album_artist="The Band" -metadata track=3/12 -metadata date=2019 -metadata genre=Rock "$T/song.mp3"
ff -f lavfi -i sine=frequency=500:duration=2 -c:a libopus -metadata TITLE="Second Song" -metadata ARTIST="Other" \
   -metadata ALBUM="B Sides" -metadata TRACKNUMBER=7 -metadata DISCNUMBER=2 "$T/song.opus"
code -u "$A" -T "$T/song.mp3" "$U/~dav/films/song.mp3" >/dev/null; code -u "$A" -T "$T/song.opus" "$U/~dav/films/song.opus" >/dev/null
tags() { curl -s -u "$A" "$U/~media/info/films/$1" | python3 -c 'import json,sys; t=json.load(sys.stdin)["tags"]; print(t["title"], "|", t["artist"], "|", t["album"], "|", t["album_artist"], "|", t["track"], t["disc"], "|", t["date"], "|", t["genre"])'; }
check "info gives a song's tags" "$(tags song.mp3)" "First Song | The Band | A Record | The Band | 3 0 | 2019 | Rock"
check "Vorbis comments too, kept on the sound" "$(tags song.opus)" "Second Song | Other | B Sides |  | 7 2 |  | "

# A film's stills for a seek bar, tiled in one JPEG.
check "info says how its stills are laid out" \
      "$(curl -s -u "$A" "$U/~media/info/films/clip.mp4" | python3 -c 'import json,sys; t=json.load(sys.stdin)["trick"]; print(t["every"], t["count"], t["columns"], t["width"], t["height"])')" "2 5 10 160 90"
check "the stills are a JPEG" "$(get "$T/trick.jpg" -u "$A" "$U/~media/trick/films/clip.mp4") $(head -c 3 "$T/trick.jpg" | od -An -tx1 | tr -d ' ')" "200 ffd8ff"
check "a row of ten tiles" "$(width "$T/trick.jpg")x$(height "$T/trick.jpg")" 1600x90
check "and a song has none" "$(code -u "$A" "$U/~media/trick/films/song.mp3") $(curl -s -u "$A" "$U/~media/info/films/song.mp3" | grep -c '"trick"')" "415 0"

# A container's claimed length past what a segment's name can count is no length, so no playlist is written for it.
ff -f lavfi -i testsrc=size=320x240:rate=25 -t 2 -c:v libx264 -pix_fmt yuv420p -f matroska "$T/liar.mkv"
python3 - "$T/liar.mkv" <<'XEOF' || bad "a container is made to claim a trillion seconds" "liar.mkv has no 8-byte Duration element"
import struct, sys
b = bytearray(open(sys.argv[1], 'rb').read())
i = b.find(b'\x44\x89\x88')
if i < 0:
    sys.exit(1)
b[i + 3:i + 11] = struct.pack('>d', 1e15)
open(sys.argv[1], 'wb').write(b)
XEOF
code -u "$A" -T "$T/liar.mkv" "$U/~dav/films/liar.mkv" >/dev/null
check "a container that claims a trillion seconds has no length" \
      "$(curl -s -m 10 -u "$A" "$U/~media/info/films/liar.mkv" | python3 -c 'import json,sys; print(json.load(sys.stdin)["duration"])' 2>&1 | tail -1)" 0.0
check "and its stream is not cut into that many segments" "$(code -m 10 -u "$A" "$U/~media/hls-240/films/liar.mkv/index.m3u8")" 415

# A copied HEVC stream is tagged hvc1, as Apple's players take it.
get "$T/hvc.mp4" -u "$A" "$U/~media/hls-copy/films/hdr.mp4/index.m3u8" >/dev/null
for _ in $(seq 1 100); do curl -s -u "$A" "$U/~media/hls-copy/films/hdr.mp4/index.m3u8" | grep -q ENDLIST && break; sleep 0.1; done
curl -s -u "$A" -o "$T/hvc.mp4" "$U/~media/hls-copy/films/hdr.mp4/init.mp4"
check "a copied HEVC stream is hvc1" "$(grep -c hvc1 "$T/hvc.mp4") $(grep -c hev1 "$T/hvc.mp4")" "1 0"

# A restart keeps what was made.
"$BIN" stop media >/dev/null 2>&1; "$BIN" start media >/dev/null 2>&1; up
check "a thumbnail outlives a restart" "$(get "$T/t1c.jpg" -u "$A" "$U/~media/thumb-128/films/short.mp4")" 200
check "and is the one kept" "$(cmp -s "$T/t3.jpg" "$T/t1c.jpg" && echo same)" same

# The cache's bound: a film past it leaves only itself, and what was asked for before it is made anew.
ff -f lavfi -i testsrc2=size=640x360:rate=25,noise=alls=30:allf=t -t 1 -c:v mpeg4 -q:v 2 "$T/big.mp4"
check "a film larger than the cache is stored" "$(code -u "$A" -T "$T/big.mp4" "$U/~dav/films/big.mp4")" 201
stream hls-copy big.mp4 "$T/hbig"
check "is streamed" "$(grep -c EXT-X-ENDLIST "$T/hbig/index.m3u8")" 1
# The stream's playlist ends before ffmpeg does, and the cache is cut back at the turn that sees ffmpeg end.
for _ in $(seq 1 30); do [ "$(ls "$T/media/.media" | grep -c '^[0-9a-f]\{64\}$')" = 1 ] && break; sleep 0.1; done
check "and is all the cache keeps" "$(ls "$T/media/.media" | grep -c '^[0-9a-f]\{64\}$')" 1
check "a thumbnail it pushed out is made again" "$(get "$T/t1d.jpg" -u "$A" "$U/~media/thumb-256/films/clip.mp4")" 200
check "as it was" "$(cmp -s "$T/t1.jpg" "$T/t1d.jpg" && echo same)" same

# An object that is an HLS playlist is no medium, read over the listener as an encrypted one is: ffmpeg opens no URL
# it names, on this host or another.
PS2=$((SL_PORT_BASE + 1906)); PL=$((SL_PORT_BASE + 1907)); U2="http://127.0.0.1:$PS2"
head -c 32 /dev/urandom > "$T/sse.key"; chmod 600 "$T/sse.key"
"$BIN" create storage msse -p "$PS2" --dir "$T/msse" --anonymous --sse-key-file "$T/sse.key" -s >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(code "$U2/")" != 000 ] && break; sleep 0.1; done
python3 - "$PL" "$T/fetched" <<'PY' &
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(16)
while True:
    c, _ = s.accept()
    with open(sys.argv[2], "a") as f:
        f.write("asked\n")
    c.close()
PY
LISTENER=$!
trap 'kill $LISTENER 2>/dev/null; daemon_stop' EXIT
printf '#EXTM3U\n#EXT-X-TARGETDURATION:10\n#EXTINF:10,\nhttp://127.0.0.1:%s/x.ts\n#EXT-X-ENDLIST\n' "$PL" > "$T/x.m3u8"
code -X PUT "$U2/films" >/dev/null
check "a playlist is stored encrypted" \
      "$(code -X PUT -H 'x-amz-server-side-encryption: AES256' -H 'Content-Type: application/vnd.apple.mpegurl' \
              --data-binary @"$T/x.m3u8" "$U2/films/x.m3u8")" 200
check "its thumbnail is 415" "$(code "$U2/~media/thumb-128/films/x.m3u8")" 415
check "and ffmpeg opened no URL it names" "$(cat "$T/fetched" 2>/dev/null | wc -l)" 0

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
