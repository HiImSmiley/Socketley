# Where Pebble, the ACME test CA, lives for this machine's architecture -- only ever sourced, since run_all.sh globs
# test_*.sh.
# Pebble's release assets are named for the architecture, pebble-linux-amd64 and pebble-linux-arm64, and each unpacks to
# a directory of the same name holding linux/<arch>/<binary>.
case "$(uname -m)" in
    aarch64|arm64) PEBBLE_ARCH=arm64 ;;
    *)             PEBBLE_ARCH=amd64 ;;
esac
PEBBLE_DIR="${PEBBLE_DIR:-$HOME/socketley-perf/acme}"
PEBBLE="$PEBBLE_DIR/pebble-linux-$PEBBLE_ARCH/linux/$PEBBLE_ARCH/pebble"
CHALL="$PEBBLE_DIR/pebble-challtestsrv-linux-$PEBBLE_ARCH/linux/$PEBBLE_ARCH/pebble-challtestsrv"
