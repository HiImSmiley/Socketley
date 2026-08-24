#!/bin/bash
# Builds the vendored static archives this tree links but does not track.
#
# Both are gitignored by the `*.a` rule, so a fresh clone or a new worktree has
# the headers and no archive, and the link fails with `cannot find -lluajit` or
# `cannot find -luring` -- which reads like a missing system package and is not.
#
#   ./bin/build-thirdparty.sh [liburing|luajit|all]
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WHAT=${1:-all}
LIBURING_TAG=liburing-2.15   # pinned deliberately: see thirdparty/liburing/README

build_liburing() {
  local tmp; tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  echo "== liburing $LIBURING_TAG"
  git clone --depth 1 --branch "$LIBURING_TAG" https://github.com/axboe/liburing.git "$tmp" >/dev/null 2>&1
  ( cd "$tmp" && ./configure >/dev/null 2>&1 && make -C src -j"$(nproc)" >/dev/null 2>&1 )
  mkdir -p "$ROOT/thirdparty/liburing/liburing"
  cp "$tmp/src/liburing.a"                  "$ROOT/thirdparty/liburing/"
  cp "$tmp/src/include/liburing.h"          "$ROOT/thirdparty/liburing/"
  cp "$tmp/src/include/liburing"/*.h        "$ROOT/thirdparty/liburing/liburing/"
  # Checked in the artefact, not in the tag: a clone that silently landed on a
  # different commit would produce a working build of the wrong version.
  local v
  v=$(grep -hoE "IO_URING_VERSION_(MAJOR|MINOR) [0-9]+" \
        "$ROOT/thirdparty/liburing/liburing/io_uring_version.h" | awk '{print $2}' | paste -sd.)
  echo "   archive $(stat -c%s "$ROOT/thirdparty/liburing/liburing.a") bytes, headers report $v"
  [ "$v" = "2.15" ] || { echo "   REFUSED: headers report $v, expected 2.15"; return 2; }
}

build_luajit() {
  echo "== luajit"
  if [ -f "$ROOT/thirdparty/luajit/libluajit.a" ]; then
    echo "   already present, left alone"
  else
    echo "   NOT AUTOMATED.  libluajit.a is built out of tree here; copy it from"
    echo "   another worktree: cp <other>/thirdparty/luajit/libluajit.a $ROOT/thirdparty/luajit/"
  fi
}

case "$WHAT" in
  liburing) build_liburing ;;
  luajit)   build_luajit ;;
  all)      build_liburing; build_luajit ;;
  *) echo "usage: $0 [liburing|luajit|all]"; exit 1 ;;
esac
