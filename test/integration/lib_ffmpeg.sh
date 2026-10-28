# What an ffmpeg can make, asked of it by name, so that a build without what a media test needs is a skip that names it.

# Prints, comma-separated, each of the named encoders, filters and formats (enc:NAME, filter:NAME, fmt:NAME) FFMPEG lacks.
ffmpeg_lacks() {   # ffmpeg want...
    local ff=$1 want kind name list missing=""
    shift
    local enc fil fmt
    enc=$("$ff" -hide_banner -encoders 2>/dev/null)
    fil=$("$ff" -hide_banner -filters 2>/dev/null)
    fmt=$("$ff" -hide_banner -formats 2>/dev/null)
    for want in "$@"; do
        kind=${want%%:*}; name=${want#*:}
        case "$kind" in
            enc) list=$enc ;;
            filter) list=$fil ;;
            *) list=$fmt ;;
        esac
        # The name follows one or two flag columns, a device's split by a space, and a format may be a comma list.
        awk -v n="$name" '{ for (i = 2; i <= 3 && i <= NF; i++) { k = split($i, a, ","); for (j = 1; j <= k; j++) if (a[j] == n) f = 1 } }
                          END { exit !f }' <<<"$list" || missing="$missing, $name"
    done
    printf '%s' "${missing#, }"
}
