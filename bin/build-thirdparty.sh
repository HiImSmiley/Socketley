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
  # Recursive, because liburing.h includes headers from liburing/io_uring/.
  cp -r "$tmp/src/include/liburing"/.       "$ROOT/thirdparty/liburing/liburing/"
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
  local dest="$ROOT/thirdparty/luajit/libluajit.a"
  if [ -f "$dest" ]; then
    echo "   already present, left alone"
    return 0
  fi

  # This used to print "NOT AUTOMATED" and tell the reader to copy the archive
  # from another worktree.  A fresh clone has no other worktree, so the one
  # person the script exists for was the one it could not help -- and the README
  # sent them straight from `apt install libluajit-5.1-dev` into a build that
  # ends in `cannot find -lluajit`.
  #
  # The distribution package is not a drop-in for that: premake links -lluajit
  # and Ubuntu installs libluajit-5.1.a, so the name never matches however many
  # -dev packages are present.  release.yml has always known this and copied the
  # file across by hand; that step lives here now, where the documented build
  # can reach it.
  local sys
  sys=$(find /usr/lib /usr/local/lib -name 'libluajit-5.1.a' 2>/dev/null | head -1)
  if [ -n "$sys" ]; then
    cp "$sys" "$dest"
    echo "   copied from $sys ($(stat -c%s "$dest") bytes)"
    return 0
  fi

  echo "   no system libluajit-5.1.a found, building from source"
  local tmp; tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  git clone --depth 1 --branch v2.1 https://github.com/LuaJIT/LuaJIT.git "$tmp" >/dev/null 2>&1 \
    || { echo "   FAILED: could not clone LuaJIT"; return 2; }
  ( cd "$tmp" && make -j"$(nproc)" >/dev/null 2>&1 ) \
    || { echo "   FAILED: LuaJIT build"; return 2; }
  cp "$tmp/src/libluajit.a" "$dest"
  echo "   built from source ($(stat -c%s "$dest") bytes)"
}

case "$WHAT" in
  liburing) build_liburing ;;
  luajit)   build_luajit ;;
  all)      build_liburing; build_luajit ;;
  *) echo "usage: $0 [liburing|luajit|all]"; exit 1 ;;
esac
