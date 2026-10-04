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
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate stgmedia
trap 'daemon_stop' EXIT
# ffmpeg two seconds slow to start, so that a stream queued behind others is seen to wait.
printf '#!/bin/sh\nsleep 2\nexec "%s" "$@"\n' "$FF" > "$SOCKETLEY_TMPD/slowff"; chmod +x "$SOCKETLEY_TMPD/slowff"
export SOCKETLEY_FFMPEG="$SOCKETLEY_TMPD/slowff"
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
[ $(( (t1 - t0) / 1000000 )) -lt 500 ] && ok || bad "a kept thumbnail is served at once" "$(( (t1 - t0) / 1000000 )) ms"
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
check "and maps its segments' start" "$(grep -c 'EXT-X-MAP:URI="init.mp4"' "$T/h240/index.m3u8")" 1
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
t0=$(date +%s%N); pids=()
for v in hls-240 hls-360 hls-480 hls-720 hls-copy; do
    curl -s -m 60 -u "$A" -o /dev/null "$U/~media/$v/films/short.mp4/index.m3u8" & pids+=($!)
done
wait "${pids[@]}"
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
[ "$ms" -lt 3800 ] && ok || bad "five streams at once start together" "the last playlist after $ms ms"

# A restart keeps what was made.
"$BIN" stop media >/dev/null 2>&1; "$BIN" start media >/dev/null 2>&1; up
check "a thumbnail outlives a restart" "$(get "$T/t1c.jpg" -u "$A" "$U/~media/thumb-128/films/short.mp4")" 200
check "and is the one kept" "$(cmp -s "$T/t3.jpg" "$T/t1c.jpg" && echo same)" same

# The cache's bound: a film past it leaves only itself, and what was asked for before it is made anew.
ff -f lavfi -i testsrc2=size=640x360:rate=25,noise=alls=30:allf=t -t 1 -c:v mpeg4 -q:v 2 "$T/big.mp4"
check "a film larger than the cache is stored" "$(code -u "$A" -T "$T/big.mp4" "$U/~dav/films/big.mp4")" 201
stream hls-copy big.mp4 "$T/hbig"
check "is streamed" "$(grep -c EXT-X-ENDLIST "$T/hbig/index.m3u8")" 1
check "and is all the cache keeps" "$(ls "$T/media/.media" | grep -c '^[0-9a-f]\{64\}$')" 1
check "a thumbnail it pushed out is made again" "$(get "$T/t1d.jpg" -u "$A" "$U/~media/thumb-256/films/clip.mp4")" 200
check "as it was" "$(cmp -s "$T/t1.jpg" "$T/t1d.jpg" && echo same)" same

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
