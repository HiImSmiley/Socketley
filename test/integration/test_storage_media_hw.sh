#!/usr/bin/env bash
# Integration test: the GPU encoder's detection and fallback, on a machine without one, and its renditions on one
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a render node that is no GPU taken for one, so renditions would never be made
#   * a GPU job that fails at its start leaving its rendition failed, instead of
#     the rendition going on with x264
#   * a rendition's encoder changing between its jobs, whose inits would differ
#   * a rendition that does not say BT.709, whose colours a player would guess
#   * with a GPU this process may use: a rendition made with x264 after all, or
#     a GPU job that fails and is made again, so the GPU is never used; or
#     no more than eight streams made at once, a CPU's share, on the GPU
# suite: isolated
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: storage media on the GPU ==="
FF="${SOCKETLEY_FFMPEG:-$(command -v ffmpeg || true)}"
[ -n "$FF" ] && [ -x "$FF" ] || { echo "  SKIP: ffmpeg is required (on the PATH or in SOCKETLEY_FFMPEG)"; exit 0; }
FFPROBE="$(dirname "$FF")/ffprobe"
[ -x "$FFPROBE" ] || { echo "  SKIP: ffprobe is required beside ffmpeg"; exit 0; }
. "$HERE/lib_ffmpeg.sh"
LACKS=$(ffmpeg_lacks "$FF" fmt:lavfi fmt:hls fmt:mp4 filter:testsrc2 filter:sine filter:scale enc:libx264 enc:aac enc:mjpeg enc:libx265)
[ -z "$LACKS" ] || { echo "  SKIP: $FF has no $LACKS, which the films here or the storage's renditions are made with"; exit 0; }
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }
A="AKIAMEDIAHW000000000:mediahwsecretmediahwsecretmediahwsecre00"
code() { curl -s -m 60 -o /dev/null -w '%{http_code}' "$@"; }

# One daemon per setting of SOCKETLEY_MEDIA_HWACCEL, which a worker reads at its first medium.
run() { # hwaccel tag
    daemon_isolate "$2"
    trap 'daemon_stop' EXIT
    export SOCKETLEY_FFMPEG="$FF" SOCKETLEY_MEDIA_HWACCEL="$1"
    daemon_start "$BIN"
    T="$SOCKETLEY_TMPD"
    P1=$((SL_PORT_BASE + 1918))
    U="http://127.0.0.1:$P1"
    printf '[admin]\n%s\nadmin = true\n' "$A" > "$T/creds"
    "$BIN" create storage hw -p "$P1" --dir "$T/data" --credentials "$T/creds" -s >/dev/null 2>&1
    for _ in $(seq 1 100); do [ "$(code "$U/")" != 000 ] && break; sleep 0.1; done
    "$FF" -hide_banner -loglevel error -y -f lavfi -i testsrc2=size=640x360:rate=25:duration=8 -f lavfi \
        -i sine=frequency=440:duration=8 -c:v libx264 -preset ultrafast -pix_fmt yuv420p -c:a aac "$T/clip.mp4"
    code -u "$A" -X MKCOL "$U/~dav/films/" >/dev/null
    code -u "$A" -T "$T/clip.mp4" "$U/~dav/films/clip.mp4" >/dev/null
    # The test run of the GPU, if any, ends before the first rendition is asked for.
    code -u "$A" "$U/~media/info/films/clip.mp4" >/dev/null
    sleep 2
}
stat_of() { "$BIN" stats hw | awk -F: -v k="$1" '$1 == k { s += $2 } END { print s + 0 }'; }
encoder_of() { cat "$T"/data/.media/*/encoder 2>/dev/null | sort -u | tr '\n' ' '; }

# A render node that is no GPU: the test run fails, and renditions are made with x264 from the start.
run /dev/null stgmhw1
check "with no GPU a rendition's segment is made" "$(code -u "$A" "$U/~media/hls-240/films/clip.mp4/seg00000.m4s")" 200
check "by x264" "$(encoder_of)" "x264 "
check "and no job ran on a GPU" "$(sleep 0.6; stat_of media_hw)" 0
daemon_stop; trap - EXIT

# A GPU taken on trust that fails: the job fails at its start, and the rendition goes on with x264.
run vaapi-unchecked:/nonexistent/renderD128 stgmhw2
check "a GPU job that fails at its start leaves the segment to x264" "$(code -u "$A" "$U/~media/hls-240/films/clip.mp4/seg00000.m4s")" 200
check "which the rendition keeps" "$(encoder_of)" "x264 "
check "after one job tried the GPU" "$(sleep 0.6; stat_of media_hw)" 1
check "and the rest of the rendition is x264's too" "$(code -u "$A" "$U/~media/hls-240/films/clip.mp4/seg00001.m4s")" 200
check "with no further GPU job" "$(sleep 0.6; stat_of media_hw)" 1
cat "$T"/data/.media/*/init.mp4 "$T"/data/.media/*/seg00001.m4s > "$T/joined.mp4" 2>/dev/null
check "and its segments decode against its init" "$("$FF" -v error -i "$T/joined.mp4" -f null - 2>&1 | grep -c .)" 0
check "and say BT.709 all through" "$("$FFPROBE" -v error -select_streams v:0 -show_entries stream=color_primaries,color_transfer,color_space -of csv=p=0 "$T/joined.mp4")" bt709,bt709,bt709
daemon_stop; trap - EXIT

# A render node this process may use and ffmpeg encodes on: every job of a rendition runs there and none fails.
NODE=/dev/dri/renderD128
if [ -r "$NODE" ] && [ -w "$NODE" ] && "$FF" -hide_banner -loglevel error -init_hw_device "vaapi=va:$NODE" \
        -filter_hw_device va -f lavfi -i testsrc2=s=320x180:d=1 -vf format=nv12,hwupload -c:v h264_vaapi -f null - 2>/dev/null; then
    run "" stgmhw3
    check "with a GPU a rendition's segment is made" "$(code -u "$A" "$U/~media/hls-240/films/clip.mp4/seg00000.m4s")" 200
    check "on the GPU" "$(encoder_of | cut -c1-5)" vaapi
    check "with no job that failed" "$(sleep 0.6; stat_of media_failed)" 0
    check "and the next segment too" "$(code -u "$A" "$U/~media/hls-240/films/clip.mp4/seg00001.m4s")" 200
    cat "$T"/data/.media/*/init.mp4 "$T"/data/.media/*/seg00001.m4s > "$T/joined.mp4" 2>/dev/null
    check "its segments decode against its init" "$("$FF" -v error -i "$T/joined.mp4" -f null - 2>&1 | grep -c .)" 0
    check "and say BT.709 all through" "$("$FFPROBE" -v error -select_streams v:0 -show_entries stream=color_primaries,color_transfer,color_space -of csv=p=0 "$T/joined.mp4")" bt709,bt709,bt709
    # Twelve streams asked for at once, four rungs of three films, run side by side on the GPU.
    "$FF" -hide_banner -loglevel error -y -f lavfi -i testsrc2=size=1280x720:rate=25:duration=90 -f lavfi \
        -i sine=frequency=440:duration=90 -c:v libx264 -preset ultrafast -pix_fmt yuv420p -c:a aac "$T/long.mp4"
    for f in a b c; do
        code -u "$A" -T "$T/long.mp4" "$U/~dav/films/$f.mp4" >/dev/null
        code -u "$A" "$U/~media/info/films/$f.mp4" >/dev/null
    done
    worker=$("$BIN" stats hw | awk -F: '/^pid:/ {print $2}' | tr ',' ' ' | awk '{print $1}')
    asks=()
    for f in a b c; do for h in 720 480 360 240; do
        code -u "$A" "$U/~media/hls-$h/films/$f.mp4/seg00000.m4s" >/dev/null &
        asks+=($!)
    done; done
    most=0
    for _ in $(seq 1 200); do
        n=$(ps --ppid "$worker" -o comm= 2>/dev/null | grep -c '^ffmpeg$')
        [ "$n" -gt "$most" ] && most=$n
        sleep 0.02
    done
    wait "${asks[@]}"
    echo "  (at most $most ffmpeg at once)"
    check "more than eight streams are made at once on the GPU" "$([ "$most" -gt 8 ] && echo yes || echo "no: $most")" yes
    check "and none of them failed" "$(stat_of media_failed)" 0
    # HDR10 with its mastering display metadata is tone-mapped on the GPU; PQ without it goes to x264 at once.
    x265="log-level=none:colorprim=bt2020:transfer=smpte2084:colormatrix=bt2020nc"
    md=":hdr10=1:master-display=G(13250,34500)B(7500,3000)R(34000,16000)WP(15635,16450)L(10000000,1):max-cll=1000,400"
    encoders() { find "$T/data/.media" -name encoder | sort; }
    declare -A made
    for v in md:"$x265$md" bare:"$x265"; do
        "$FF" -hide_banner -loglevel error -y -f lavfi -i testsrc2=size=640x360:rate=25:duration=8 -c:v libx265 \
            -preset ultrafast -pix_fmt yuv420p10le -x265-params "${v#*:}" -color_primaries bt2020 -color_trc smpte2084 \
            -colorspace bt2020nc "$T/hdr-${v%%:*}.mp4"
        code -u "$A" -T "$T/hdr-${v%%:*}.mp4" "$U/~dav/films/hdr-${v%%:*}.mp4" >/dev/null
        code -u "$A" "$U/~media/info/films/hdr-${v%%:*}.mp4" >/dev/null
        before=$(encoders) hw=$(stat_of media_hw)
        code -u "$A" "$U/~media/hls-240/films/hdr-${v%%:*}.mp4/seg00000.m4s" >/dev/null
        sleep 0.6
        made[${v%%:*}]="$(comm -13 <(echo "$before") <(encoders) | xargs -r cat) $(( $(stat_of media_hw) - hw ))"
    done
    check "HDR10 with its mastering display is made on the GPU" "$(sed 's/^\(vaapi\)[^ ]*/\1/' <<<"${made[md]}")" "vaapi 1"
    check "and PQ without it with x264, trying no GPU job first" "${made[bare]}" "x264 0"
    check "with no job that failed" "$(sleep 0.6; stat_of media_failed)" 0
    daemon_stop; trap - EXIT
else
    echo "  (no render node this process may use and ffmpeg encodes on: the GPU's own renditions are not made here)"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
