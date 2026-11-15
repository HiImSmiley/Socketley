#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: each ffmpeg a storage starts on an object is held to a memory bound and is the first the kernel
# ends when memory runs out.
#
# What each part would catch:
#   * a crafted medium (a decoder told of a frame of 64k x 64k, a header asking for gigabytes) taking all the memory
#     there is, and the kernel ending the daemon for it rather than that ffmpeg
#   * SOCKETLEY_MEDIA_MEMORY_MB not being what bounds it
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: an ffmpeg a storage starts is bounded ==="
FF="${SOCKETLEY_FFMPEG:-$(command -v ffmpeg || true)}"
[ -n "$FF" ] && [ -x "$FF" ] || { echo "  SKIP: ffmpeg is required (on the PATH or in SOCKETLEY_FFMPEG)"; exit 0; }
FFPROBE="$(dirname "$FF")/ffprobe"; [ -x "$FFPROBE" ] || FFPROBE=$(command -v ffprobe || true)
[ -n "$FFPROBE" ] || { echo "  SKIP: ffprobe is required beside ffmpeg"; exit 0; }
. "$HERE/lib_ffmpeg.sh"
LACKS=$(ffmpeg_lacks "$FF" fmt:lavfi filter:testsrc enc:libx264 enc:mjpeg fmt:mp4)
[ -z "$LACKS" ] || { echo "  SKIP: $FF has no $LACKS"; exit 0; }
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate stgmediabound
trap 'daemon_stop' EXIT
T="$SOCKETLEY_TMPD"
# An ffmpeg that says what it was started with, a moment after it was, and then is the real one.
mkdir -p "$T/bin" "$T/seen"
cat > "$T/bin/ffmpeg" <<EOF
#!/bin/sh
sleep 0.5
{ cat /proc/\$\$/limits; echo "oom_score_adj \$(cat /proc/\$\$/oom_score_adj)"; } > "$T/seen/\$\$"
exec "$FF" "\$@"
EOF
chmod +x "$T/bin/ffmpeg"
ln -s "$FFPROBE" "$T/bin/ffprobe"
export SOCKETLEY_FFMPEG="$T/bin/ffmpeg"
export SOCKETLEY_MEDIA_MEMORY_MB=1500
daemon_start "$BIN"
P=$((SL_PORT_BASE + 1631))
U="http://127.0.0.1:$P"
cat > "$T/creds" <<EOF
[admin]
AKIAMEDIABOUND000000:mediaboundsecretmediaboundsecret000000000
admin = true
EOF
A="AKIAMEDIABOUND000000:mediaboundsecretmediaboundsecret000000000"
"$BIN" create storage media -p "$P" --dir "$T/media" --credentials "$T/creds" -s >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/")" != 000 ] && break; sleep 0.1; done
"$FF" -hide_banner -loglevel error -y -f lavfi -i testsrc=size=320x240:rate=25 -t 2 -c:v libx264 -pix_fmt yuv420p "$T/clip.mp4"
code() { curl -s -m 60 -o /dev/null -w '%{http_code}' "$@"; }
check "a bucket is made" "$(code -u "$A" -X MKCOL "$U/~dav/films/")" 201
check "a film is stored" "$(code -u "$A" -T "$T/clip.mp4" "$U/~dav/films/clip.mp4")" 201
check "its thumbnail is made" "$(code -u "$A" "$U/~media/thumb-128/films/clip.mp4")" 200

seen=$(cat "$T/seen"/* 2>/dev/null)
[ -n "$seen" ] && ok || bad "an ffmpeg was started" "nothing in $T/seen"
data=$(awk '/^Max data size/ {print $4}' <<<"$seen" | sort -u)
oom=$(awk '/^oom_score_adj/ {print $2}' <<<"$seen" | sort -u)
check "each ffmpeg's memory is SOCKETLEY_MEDIA_MEMORY_MB" "$data" "$((1500 << 20))"
check "and the kernel ends it first when memory runs out" "$oom" "1000"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
