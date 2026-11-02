#!/bin/bash
# Builds the vendored static archives this tree links but does not track.
#
# They are gitignored by the `*.a` rule, so a fresh clone or a new worktree has
# the headers and no archive, and the link fails with `cannot find -lluajit` or
# `cannot find -luring` -- which reads like a missing system package and is not.
#
# `http3` is OpenSSL 3.5, the first with the API a QUIC stack drives TLS 1.3
# through, and ngtcp2 and nghttp3 over it; OpenSSL is linked statically into
# every runtime then, so the binary needs no libssl of the system's. They are
# built here, headers and all, into thirdparty/{openssl,ngtcp2,nghttp3}, which
# git ignores, and need perl and cmake.
#
# `premake` builds premake itself into thirdparty/premake/, only where bin/premake5, an x86-64 binary, cannot run.
#
#   ./bin/build-thirdparty.sh [liburing|luajit|http3|premake|all]
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WHAT=${1:-all}
LIBURING_TAG=liburing-2.15   # pinned deliberately: see thirdparty/liburing/README
# Pinned as liburing is: a release that changes under the build is a different build. OpenSSL 3.5 is an LTS line.
OPENSSL_TAG=openssl-3.5.9
# Kernel TLS, for a runtime that hands a connection's send key to the kernel; a _TAG, so a change rebuilds OpenSSL.
OPENSSL_OPTIONS_TAG=enable-ktls
NGHTTP3_TAG=v1.18.0
NGTCP2_TAG=v1.25.0
PREMAKE_REF=v5.0.0-beta8   # bin/premake5's version; not a _TAG, so a change here rebuilds no library in scripts/update.sh

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

build_premake() {
  echo "== premake"
  if "$ROOT/bin/premake5" --version >/dev/null 2>&1; then
    echo "   bin/premake5 runs here, nothing to build"
    return 0
  fi
  local dest="$ROOT/thirdparty/premake/premake5"
  if "$dest" --version 2>/dev/null | grep -qF "${PREMAKE_REF#v}"; then
    echo "   already built, left alone"
    return 0
  fi
  local tmp; tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  git clone --depth 1 --branch "$PREMAKE_REF" https://github.com/premake/premake-core.git "$tmp" >/dev/null 2>&1 \
    || { echo "   FAILED: could not clone premake"; return 2; }
  # Its bootstrap links libuuid, which is uuid-dev on Debian.
  ( cd "$tmp" && make -f Bootstrap.mak linux >/dev/null 2>&1 ) \
    || { echo "   FAILED: premake build, which needs uuid-dev"; return 2; }
  mkdir -p "$(dirname "$dest")"
  cp "$tmp/bin/release/premake5" "$dest"
  echo "   built $("$dest" --version)"
}

build_http3() {
  # Left alone when the archives of these very tags are there, so a second run costs a few stats.
  local stamp="$OPENSSL_TAG $OPENSSL_OPTIONS_TAG $NGHTTP3_TAG $NGTCP2_TAG"
  if [ "$(cat "$ROOT/thirdparty/ngtcp2/.built" 2>/dev/null)" = "$stamp" ] && \
     [ -f "$ROOT/thirdparty/openssl/lib/libssl.a" ] && [ -f "$ROOT/thirdparty/nghttp3/lib/libnghttp3.a" ] && \
     [ -f "$ROOT/thirdparty/ngtcp2/lib/libngtcp2_crypto_ossl.a" ]; then
    echo "== http3: $stamp already built, left alone"
    return 0
  fi
  local tmp; tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  local jobs; jobs=$(nproc)
  for tool in perl cmake git make; do
    command -v "$tool" >/dev/null 2>&1 || { echo "   FAILED: $tool is needed to build HTTP/3's libraries"; return 2; }
  done

  echo "== openssl $OPENSSL_TAG"
  local ossl="$ROOT/thirdparty/openssl"
  git clone --depth 1 --branch "$OPENSSL_TAG" https://github.com/openssl/openssl.git "$tmp/openssl" >/dev/null 2>&1 \
    || { echo "   FAILED: could not clone OpenSSL"; return 2; }
  rm -rf "$ossl" && mkdir -p "$ossl"
  ( cd "$tmp/openssl" && ./Configure $OPENSSL_OPTIONS_TAG no-shared no-tests no-docs no-apps --prefix="$ossl" --libdir=lib \
        --openssldir=/usr/lib/ssl -fPIC >/dev/null && make -j"$jobs" build_libs >/dev/null 2>&1 && make install_dev >/dev/null 2>&1 ) \
    || { echo "   FAILED: OpenSSL build"; return 2; }
  # The archives only: a headers-and-archive tree, which premake puts before the system's.
  rm -rf "$ossl/lib/pkgconfig" "$ossl/lib/cmake"
  cp "$tmp/openssl/LICENSE.txt" "$ossl/LICENSE.txt"
  echo "   libssl.a $(stat -c%s "$ossl/lib/libssl.a") bytes, libcrypto.a $(stat -c%s "$ossl/lib/libcrypto.a") bytes"

  echo "== nghttp3 $NGHTTP3_TAG"
  local h3="$ROOT/thirdparty/nghttp3"
  git clone --depth 1 --branch "$NGHTTP3_TAG" --recurse-submodules https://github.com/ngtcp2/nghttp3.git "$tmp/nghttp3" >/dev/null 2>&1 \
    || { echo "   FAILED: could not clone nghttp3"; return 2; }
  rm -rf "$h3"
  ( cmake -S "$tmp/nghttp3" -B "$tmp/nghttp3/b" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$h3" \
        -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_STATIC_LIB=ON -DENABLE_SHARED_LIB=OFF -DENABLE_LIB_ONLY=ON \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON >/dev/null && cmake --build "$tmp/nghttp3/b" -j"$jobs" >/dev/null && \
    cmake --install "$tmp/nghttp3/b" >/dev/null ) || { echo "   FAILED: nghttp3 build"; return 2; }
  rm -rf "$h3/lib/pkgconfig" "$h3/lib/cmake"
  cp "$tmp/nghttp3/COPYING" "$h3/COPYING"
  echo "   libnghttp3.a $(stat -c%s "$h3/lib/libnghttp3.a") bytes"

  echo "== ngtcp2 $NGTCP2_TAG"
  local tc="$ROOT/thirdparty/ngtcp2"
  git clone --depth 1 --branch "$NGTCP2_TAG" --recurse-submodules https://github.com/ngtcp2/ngtcp2.git "$tmp/ngtcp2" >/dev/null 2>&1 \
    || { echo "   FAILED: could not clone ngtcp2"; return 2; }
  rm -rf "$tc"
  ( cmake -S "$tmp/ngtcp2" -B "$tmp/ngtcp2/b" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$tc" \
        -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_STATIC_LIB=ON -DENABLE_SHARED_LIB=OFF -DENABLE_LIB_ONLY=ON \
        -DENABLE_OPENSSL=ON -DOPENSSL_ROOT_DIR="$ossl" -DOPENSSL_USE_STATIC_LIBS=ON \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON >/dev/null 2>&1 && cmake --build "$tmp/ngtcp2/b" -j"$jobs" >/dev/null && \
    cmake --install "$tmp/ngtcp2/b" >/dev/null ) || { echo "   FAILED: ngtcp2 build"; return 2; }
  rm -rf "$tc/lib/pkgconfig" "$tc/lib/cmake"
  cp "$tmp/ngtcp2/COPYING" "$tc/COPYING"
  # Built against the OpenSSL above or not at all: the crypto helper is what drives its QUIC API.
  [ -f "$tc/lib/libngtcp2_crypto_ossl.a" ] || { echo "   REFUSED: ngtcp2 built no OpenSSL crypto helper"; return 2; }
  echo "   libngtcp2.a $(stat -c%s "$tc/lib/libngtcp2.a") bytes, libngtcp2_crypto_ossl.a $(stat -c%s "$tc/lib/libngtcp2_crypto_ossl.a") bytes"
  echo "$stamp" > "$tc/.built"
}

case "$WHAT" in
  liburing) build_liburing ;;
  luajit)   build_luajit ;;
  http3)    build_http3 ;;
  premake)  build_premake ;;
  all)      build_liburing; build_luajit; build_http3; build_premake ;;
  *) echo "usage: $0 [liburing|luajit|http3|premake|all]"; exit 1 ;;
esac
