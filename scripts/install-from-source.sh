#!/usr/bin/env bash
#
# Build socketley from a clone and install it, on a machine that has nothing.
#
# ─── WHY THIS FILE AND NOT install.sh ───────────────────────────────────────
#
# install.sh at the repo root downloads the newest release .deb and builds
# nothing; this is the source path, so the two cannot share a name.  It lives
# beside scripts/install-liburing.sh because it calls it, and because that
# script is already the one place the liburing pin is written down.
#
# ─── WHERE THE DEPENDENCY LIST COMES FROM ───────────────────────────────────
#
# Nothing below is a guess.  Each item names the file that already encoded it:
#
#   build-essential libssl-dev libluajit-5.1-dev git ca-certificates cmake perl
#                                 Dockerfile builder stage, ci.yml, release.yml
#   liburing >= 2.7, from source  scripts/install-liburing.sh, which owns the pin
#   thirdparty/luajit/libluajit.a scripts/build-thirdparty.sh luajit, as CI runs it
#   premake5 gmake2, release_<arch>  release.yml; make/Makefile names the arch
#   Linux 5.19                    README.md's Requirements, sdk/CMakeLists.txt:5
#   x86_64 or aarch64             premake5.lua's target_arch; on aarch64 premake is built, with uuid-dev
#
# netcat-openbsd, bc, groff-base, clang-18 and libclang-rt-18-dev appear in
# ci.yml and are deliberately absent here: they belong to the test suite, the
# man page render check and libFuzzer, none of which an install runs.
#
# `scripts/build-thirdparty.sh luajit` and not `all`, which is what the Dockerfile,
# ci.yml and release.yml all do.  `all` also drops thirdparty/liburing/liburing.a
# into a directory that is on the link path, so -luring resolves to it and the
# result is a statically linked liburing -- not what this project ships, and not
# what the .deb's `Depends: liburing2 (>= 2.6)` describes.
#
# ─── WHY THE PREFIX DEFAULTS TO /usr AND NOT /usr/local ─────────────────────
#
# The binary decides for itself whether it is installed, by testing
# /usr/bin/socketley for execute -- socketley/shared/persist/paths.cpp:53.  Under any
# other prefix that test fails, so even as root the daemon stays in user mode:
# socket at /tmp/socketley.sock, state under $HOME, and `socketley --help`
# looking for /usr/share/socketley/socketley-help.sh and finding nothing.  /usr
# is therefore not a packaging preference here, it is the only prefix at which
# the systemd service behaves as documented -- so --prefix elsewhere installs a
# binary, a man page and a help script, no service and no system user, and says
# so before it starts.
#
# ─── USE ────────────────────────────────────────────────────────────────────
#
#   bash scripts/install-from-source.sh              # build and install
#   bash scripts/install-from-source.sh --dry-run    # print every command, run none
#   bash scripts/install-from-source.sh --uninstall  # remove what this installed
#
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PREFIX="/usr"
DRY_RUN=0
MODE="install"
ASSUME_YES=0
SKIP_DEPS=0
NO_START=0
FORCE=0
JOBS=""

MANIFEST_REL="share/socketley/install-manifest"
SYSTEMD_UNIT="/usr/lib/systemd/system/socketley.service"

# ─── Failure says which step, and what to do about it ───────────────────────
# A bare `set -e` abort names a line number in a file nobody has open.  Every
# step sets both of these before it runs, so the trap can name the step and the
# way out instead.
STEP="startup"
HINT=""

step() { STEP="$1"; HINT="$2"; printf '==> %s\n' "$1"; }
note() { printf '    %s\n' "$*"; }

fail() {
    printf 'error: %s\n' "$1" >&2
    shift
    local l
    for l in "$@"; do printf '  %s\n' "$l" >&2; done
    exit 2
}

usage_error() {
    printf 'error: %s\n' "$1" >&2
    printf '  see: bash %s --help\n' "${BASH_SOURCE[0]}" >&2
    exit 1
}

on_err() {
    local rc=$?
    printf '\nerror: %s failed (exit %d)\n' "$STEP" "$rc" >&2
    if [ -n "$HINT" ]; then printf '  %s\n' "$HINT" >&2; fi
    exit 2
}
trap on_err ERR

# ─── Commands that change something go through these two, and only these ────
# --dry-run is honest only if there is no second way to touch the machine, so
# every mutating command in this file is one of these calls.
run() {
    if [ "$DRY_RUN" = 1 ]; then printf '  %s\n' "$*"; return 0; fi
    "$@"
}
run_root() {
    if [ "$DRY_RUN" = 1 ]; then printf '  %s%s\n' "${SUDO:+sudo }" "$*"; return 0; fi
    if [ -n "$SUDO" ]; then "$SUDO" "$@"; else "$@"; fi
}

show_help() {
    cat <<'USAGE'
socketley: build from this clone and install.

  bash scripts/install-from-source.sh [options]

Options
  --prefix DIR    where to install (default /usr; see the note below)
  --dry-run       print every command this would run, run none of them
  --uninstall     remove exactly what a previous run of this script installed
  --skip-deps     do not install distribution packages, they are already here
  --no-start      install and enable the service but do not start it
  --jobs N        make -j N (default: the smaller of nproc and RAM / 1.5 GiB)
  --yes, -y       do not ask before the privileged steps
  --force         proceed even when a socketley .deb already owns /usr/bin
  -h, --help      this text

The prefix defaults to /usr because the binary tests /usr/bin/socketley to
decide whether it is installed (socketley/shared/persist/paths.cpp:53).  Under any
other prefix the daemon runs in user mode -- socket /tmp/socketley.sock, state
under $HOME -- so this script installs no systemd service there, and says so.

State, configuration and the runtime socket are not under the prefix and never
move: /var/lib/socketley, /etc/socketley, /run/socketley.  Neither --uninstall
nor anything else here deletes them.
USAGE
}

# ─── Arguments ──────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)     [ $# -ge 2 ] || usage_error "--prefix needs a directory"; PREFIX="$2"; shift 2 ;;
        --prefix=*)   PREFIX="${1#*=}"; shift ;;
        --jobs)       [ $# -ge 2 ] || usage_error "--jobs needs a number"; JOBS="$2"; shift 2 ;;
        --jobs=*)     JOBS="${1#*=}"; shift ;;
        --dry-run)    DRY_RUN=1; shift ;;
        --uninstall)  MODE="uninstall"; shift ;;
        --skip-deps)  SKIP_DEPS=1; shift ;;
        --no-start)   NO_START=1; shift ;;
        --yes|-y)     ASSUME_YES=1; shift ;;
        --force)      FORCE=1; shift ;;
        -h|--help)    show_help; exit 0 ;;
        *)            usage_error "unknown option: $1" ;;
    esac
done

case "$PREFIX" in
    /*) ;;
    *)  usage_error "--prefix must be an absolute path, got: $PREFIX" ;;
esac
PREFIX="${PREFIX%/}"
if [ -z "$PREFIX" ]; then usage_error "--prefix / is not accepted"; fi

if [ -n "$JOBS" ]; then
    case "$JOBS" in
        ''|*[!0-9]*) usage_error "--jobs must be a positive integer, got: $JOBS" ;;
    esac
    if [ "$JOBS" -lt 1 ]; then usage_error "--jobs must be at least 1"; fi
fi

MANIFEST="$PREFIX/$MANIFEST_REL"

# The unit's ExecStart is /usr/bin/socketley, and paths.cpp only enters system
# mode for a binary installed there, so the service belongs to one prefix.
WANT_SERVICE=0
if [ "$PREFIX" = "/usr" ]; then WANT_SERVICE=1; fi

# ─── How this run reaches root, decided once ────────────────────────────────
# Both shapes have to work: a developer with sudo, and a container that is
# already root and has no sudo binary at all.
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
else
    SUDO=""
fi

need_root_or_refuse() {
    if [ "$(id -u)" -ne 0 ] && [ -z "$SUDO" ]; then
        fail "this script needs root for the install step and there is no sudo on this machine" \
             "run it as root, or install sudo first"
    fi
}

confirm() {
    if [ "$ASSUME_YES" = 1 ] || [ "$DRY_RUN" = 1 ]; then return 0; fi
    if [ ! -t 0 ]; then
        fail "refusing to take root without being asked, and stdin is not a terminal" \
             "re-run with --yes once you have read the list above, or run it from a terminal"
    fi
    local reply=""
    printf 'Proceed? [y/N] '
    read -r reply || reply=""
    case "$reply" in
        [yY]|[yY][eE][sS]) return 0 ;;
        *) printf 'nothing was changed.\n'; exit 0 ;;
    esac
}

# ════════════════════════════════════════════════════════════════════════════
#  Uninstall
# ════════════════════════════════════════════════════════════════════════════
do_uninstall() {
    step "uninstall: reading the manifest" \
         "the manifest is written by the install step; without it this script does not know what it put there"

    if [ ! -r "$MANIFEST" ]; then
        fail "no install manifest at $MANIFEST" \
             "this script removes only paths it recorded, so with no record it removes nothing." \
             "if socketley came from the .deb:            sudo apt-get remove socketley" \
             "if it was installed under another prefix:   re-run with --prefix <that one>" \
             "otherwise remove the files by hand"
    fi

    # Read the whole manifest before deleting anything: a line naming something
    # outside this prefix, or outside the one systemd path, is a line this
    # script did not write, and the right answer to that is to stop.
    local paths=()
    local line
    while IFS= read -r line; do
        case "$line" in
            ''|'#'*) continue ;;
            "$PREFIX"/*|"$SYSTEMD_UNIT") paths+=("$line") ;;
            *) fail "manifest names a path outside $PREFIX: $line" \
                    "refusing to delete it -- this manifest was not written by this script at this prefix" ;;
        esac
    done < "$MANIFEST"

    if [ "${#paths[@]}" -eq 0 ]; then
        note "the manifest records no paths; removing it and stopping"
        need_root_or_refuse
        run_root rm -f "$MANIFEST"
        exit 0
    fi
    note "${#paths[@]} paths recorded"

    local has_unit=0
    local p
    for p in "${paths[@]}"; do
        if [ "$p" = "$SYSTEMD_UNIT" ]; then has_unit=1; fi
    done

    if [ "$has_unit" = 1 ] && command -v systemctl >/dev/null 2>&1; then
        step "uninstall: stopping and disabling the service" \
             "systemctl refused; check: systemctl status socketley"
        need_root_or_refuse
        run_root systemctl stop socketley.service || true
        run_root systemctl disable socketley.service || true
    fi

    step "uninstall: removing files" "check who owns the paths listed below"
    need_root_or_refuse
    for p in "${paths[@]}"; do
        # A binary dpkg owns belongs to the .deb whatever the manifest says --
        # an install that refused to overwrite it must not delete it either.
        if [ "$p" = "/usr/bin/socketley" ] && command -v dpkg >/dev/null 2>&1 \
           && dpkg -S /usr/bin/socketley >/dev/null 2>&1; then
            note "left alone, dpkg owns it: $p"
            continue
        fi
        if [ -e "$p" ] || [ -L "$p" ]; then
            run_root rm -f "$p"
            note "removed $p"
        else
            note "already gone: $p"
        fi
    done

    run_root rm -f "$MANIFEST"
    # Only if it is empty, because something else may have put a file there.
    run_root rmdir "$PREFIX/share/socketley" 2>/dev/null || true

    if [ "$has_unit" = 1 ] && command -v systemctl >/dev/null 2>&1; then
        run_root systemctl daemon-reload || true
    fi

    printf '\n'
    note "left in place, deliberately, because they are not this script's to delete:"
    note "  /var/lib/socketley   the runtime records, one JSON per runtime"
    note "  /etc/socketley       config.lua and any custom types"
    note "  /run/socketley       the daemon's socket directory, gone at reboot"
    note "  the socketley user and group"
    note "to remove the account too:  sudo userdel socketley && sudo groupdel socketley"
    exit 0
}

if [ "$MODE" = "uninstall" ]; then do_uninstall; fi

# ════════════════════════════════════════════════════════════════════════════
#  Refusals, before anything is changed
# ════════════════════════════════════════════════════════════════════════════

step "checking this machine" \
     "each refusal below names what it wants and the file that already said so"

# ── Linux, and this architecture ────────────────────────────────────────────
if [ "$(uname -s)" != "Linux" ]; then
    fail "socketley is Linux only: this is $(uname -s)" \
         "io_uring has no equivalent elsewhere"
fi

ARCH="$(uname -m)"
# Who runs the install, through sudo or not, and is given the daemon's socket.
ADMIN_USER="${SUDO_USER:-$(id -un)}"
# scripts/premake5 is an x86-64 binary, so on aarch64 premake is built from source, and its bootstrap links libuuid.
ARCH_DEPS=""
case "$ARCH" in
    x86_64) ;;
    aarch64) ARCH_DEPS=" uuid-dev" ;;
    *) fail "socketley builds for x86_64 and aarch64: this is $ARCH" \
            "premake5.lua knows the platforms x64 and arm64, and Release compiles a -march floor for each." ;;
esac

# ── The kernel ──────────────────────────────────────────────────────────────
# 5.19 is the floor README.md's Requirements and sdk/CMakeLists.txt:5 both
# state, for io_uring multishot accept.  Read as two integers and never as one
# decimal, for the same reason install-liburing.sh gives about 2.5 and 2.15.
KREL="$(uname -r)"
KMAJ="${KREL%%.*}"
KREST="${KREL#*.}"
KMIN="${KREST%%.*}"
KMIN="${KMIN%%[!0-9]*}"
case "${KMAJ}.${KMIN}" in
    ''|*[!0-9.]*|.*|*.) fail "cannot read a version out of the kernel release '$KREL'" \
                             "socketley needs Linux 5.19 or newer; check \`uname -r\` by hand" ;;
esac
if [ "$KMAJ" -lt 5 ] || { [ "$KMAJ" -eq 5 ] && [ "$KMIN" -lt 19 ]; }; then
    fail "kernel $KREL is too old: socketley needs Linux 5.19 or newer" \
         "5.19 is where io_uring multishot accept landed, which every listening runtime arms." \
         "the floor is stated in README.md's Requirements and in sdk/CMakeLists.txt:5," \
         "and there is no build option that lowers it."
fi
note "kernel $KREL, floor is 5.19"

# ── io_uring actually reachable ─────────────────────────────────────────────
# Not derived from this repository: it is a kernel knob (6.6 and newer) that
# makes every io_uring_setup fail, and a daemon that cannot create a ring does
# nothing at all, so it is worth saying here rather than at the first start.
if [ -r /proc/sys/kernel/io_uring_disabled ]; then
    IOU="$(cat /proc/sys/kernel/io_uring_disabled)"
    if [ "$IOU" = "2" ]; then
        fail "io_uring is disabled on this kernel (kernel.io_uring_disabled = 2)" \
             "every socketley runtime is an io_uring loop, so nothing here can work." \
             "to allow it:  sudo sysctl -w kernel.io_uring_disabled=0" \
             "that is a machine-wide security decision -- make it deliberately, not because this script asked."
    elif [ "$IOU" = "1" ]; then
        note "warning: kernel.io_uring_disabled = 1, so io_uring needs CAP_SYS_ADMIN here."
        note "         the service runs as the unprivileged socketley user and will fail to start."
    fi
fi

# ── Are we in a socketley clone at all ──────────────────────────────────────
for f in premake5.lua scripts/premake5 scripts/build-thirdparty.sh scripts/install-liburing.sh \
         man/socketley.1 man/socketley-help.sh packaging/socketley.service; do
    if [ ! -e "$ROOT/$f" ]; then
        fail "$ROOT does not look like a socketley clone: $f is missing" \
             "clone it:  git clone https://github.com/HiImSmiley/Socketley" \
             "then run this script from inside that clone"
    fi
done

# ── The distribution ────────────────────────────────────────────────────────
# Debian and its derivatives are the only family whose package names this
# repository encodes -- the Dockerfile, ci.yml and release.yml all build on
# ubuntu-24.04.  Anywhere else the names would be a guess, and a guess run
# under sudo on somebody's machine is the failure this script exists to avoid.
DISTRO_ID="unknown"
DISTRO_LIKE=""
DISTRO_NAME="unknown"
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_LIKE="${ID_LIKE:-}"
    DISTRO_NAME="${PRETTY_NAME:-$DISTRO_ID}"
fi

IS_DEBIAN=0
case " $DISTRO_ID $DISTRO_LIKE " in
    *" debian "*|*" ubuntu "*) IS_DEBIAN=1 ;;
esac
if ! command -v apt-get >/dev/null 2>&1; then IS_DEBIAN=0; fi

if [ "$SKIP_DEPS" = 0 ] && [ "$IS_DEBIAN" = 0 ]; then
    fail "this script installs packages only on Debian and its derivatives, and this is $DISTRO_NAME" \
         "the package names in this repository are Debian's -- the Dockerfile, ci.yml and" \
         "release.yml all build on ubuntu-24.04 -- and there is no second list to read here." \
         "" \
         "install the equivalents yourself, then re-run with --skip-deps.  What is needed," \
         "as capabilities rather than package names:" \
         "  a C++ compiler: GCC 12 or newer, and make" \
         "  OpenSSL headers and libraries (libssl, libcrypto)" \
         "  LuaJIT: a static libluajit-5.1.a, or none and scripts/build-thirdparty.sh builds one" \
         "  git and a CA bundle, for the two source clones the build makes" \
         "" \
         "liburing is not on that list: scripts/install-liburing.sh builds the pinned release" \
         "from source and runs on any distribution."
fi
note "$DISTRO_NAME"

# ── Does a .deb already own the prefix ──────────────────────────────────────
if [ "$PREFIX" = "/usr" ] && [ "$FORCE" = 0 ] && command -v dpkg >/dev/null 2>&1; then
    if dpkg -s socketley >/dev/null 2>&1; then
        fail "the socketley .deb is installed and owns /usr/bin/socketley" \
             "writing over a file dpkg owns leaves the two disagreeing, and the next" \
             "\`apt-get upgrade\` silently replaces this build with the packaged one." \
             "" \
             "remove the package first:   sudo apt-get remove socketley" \
             "or install somewhere else:  --prefix /usr/local  (no systemd service; see --help)" \
             "or accept the overwrite:    --force"
    fi
fi

# ── The prefix, said plainly when it is not /usr ────────────────────────────
if [ "$WANT_SERVICE" = 0 ]; then
    note ""
    note "prefix is $PREFIX and not /usr.  The binary tests /usr/bin/socketley to decide"
    note "whether it is installed (socketley/shared/persist/paths.cpp:53), so from here it runs in"
    note "user mode: socket /tmp/socketley.sock, state in ~/.local/share/socketley, and"
    note "\`socketley --help\` will not find its help script.  This run installs no systemd"
    note "service, no system user and no /var/lib/socketley."
    note ""
fi

# ── How many make jobs this machine can afford ──────────────────────────────
# Release compiles and links with -flto=auto, so `make -jN` is up to N link
# steps each fanning out to nproc LTO jobs, and the Dockerfile records one
# cc1plus on this tree at 1.1 GB resident.  A box that takes -j$(nproc) with
# less memory than that per core meets the OOM reaper, whose message says
# nothing about memory.  1.5 GiB per job is that measurement with headroom.
NPROC="$(nproc 2>/dev/null || echo 1)"
if [ -z "$JOBS" ]; then
    MEM_KB="$(awk '/^MemAvailable:/ {print $2; exit}' /proc/meminfo 2>/dev/null || echo 0)"
    if [ -z "$MEM_KB" ]; then MEM_KB=0; fi
    if [ "$MEM_KB" -gt 0 ]; then
        BY_MEM=$(( MEM_KB / 1572864 ))
        if [ "$BY_MEM" -lt 1 ]; then BY_MEM=1; fi
        if [ "$NPROC" -lt "$BY_MEM" ]; then JOBS="$NPROC"; else JOBS="$BY_MEM"; fi
    else
        JOBS=1
    fi
fi
note "build jobs: $JOBS of $NPROC cores -- -flto=auto fans each one out further"

# ════════════════════════════════════════════════════════════════════════════
#  Say what needs root, and why, before taking any
# ════════════════════════════════════════════════════════════════════════════
printf '\n'
printf 'This run needs root for the following, and for nothing else:\n\n'
if [ "$SKIP_DEPS" = 0 ]; then
    printf '  apt-get update, then apt-get install -y --no-install-recommends\n'
    printf '      build-essential libssl-dev libluajit-5.1-dev git ca-certificates cmake perl%s\n' "$ARCH_DEPS"
    printf '      the build dependencies, taken from the Dockerfile and ci.yml.\n\n'
fi
printf '  make install, inside scripts/install-liburing.sh, then ldconfig\n'
printf '      liburing 2.15 into /usr.  The distribution package is 2.5 on Ubuntu 24.04\n'
printf '      and the binary needs the LIBURING_2.6 symbol version at run time.\n'
printf '      Skipped without asking if the installed headers already clear 2.7.\n\n'
printf '  install -D, for the binary, the man page and the help script under %s\n' "$PREFIX"
if [ "$WANT_SERVICE" = 1 ]; then
    printf '\n  groupadd --system socketley, useradd --system socketley\n'
    printf '      the daemon runs unprivileged, and membership of the socketley group is\n'
    printf '      exactly the set of people who may reach its 0660 IPC socket.\n\n'
    if [ "$ADMIN_USER" != root ]; then
        printf '  usermod -aG socketley %s\n' "$ADMIN_USER"
        printf '      you, who installs it, may then run socketley commands without sudo.\n\n'
    fi
    printf '  install -dm750 /var/lib/socketley/runtimes\n'
    printf '  install -dm755 /run/socketley, install -dm755 /etc/socketley\n'
    printf '      0750 because each runtime record carries that runtime master password\n'
    printf '      in plaintext and the paths of its TLS private keys.\n\n'
    printf '  install -Dm644 packaging/socketley.service %s\n' "$SYSTEMD_UNIT"
    printf '  systemctl daemon-reload, systemctl enable socketley.service\n'
    if [ "$NO_START" = 0 ]; then
        printf '  systemctl start socketley.service, then socketley ls to check it answers\n'
    fi
fi
printf '\nEverything else -- the two source clones, the compile, the link -- runs as %s.\n' "$(id -un)"

if [ "$DRY_RUN" = 1 ]; then
    printf '\n--dry-run: every command below is printed and none of them is run.\n'
    printf 'The working directory for all of them is %s.\n\n' "$ROOT"
else
    printf '\n'
    need_root_or_refuse
    confirm
fi

cd "$ROOT"

# ════════════════════════════════════════════════════════════════════════════
#  Build
# ════════════════════════════════════════════════════════════════════════════

# apt-get install is already idempotent: a package that is present and current
# is reported and not reinstalled.
if [ "$SKIP_DEPS" = 1 ]; then
    step "dependencies: skipped, --skip-deps" ""
else
    step "installing build dependencies" \
         "apt-get failed; check the network and the package lists, then re-run -- nothing after this point has happened"
    run_root apt-get update
    run_root apt-get install -y --no-install-recommends \
        build-essential libssl-dev libluajit-5.1-dev git ca-certificates cmake perl $ARCH_DEPS
fi

# ── The compiler, checked where the answer is still actionable ──────────────
step "checking the compiler" "install GCC 12 or newer, then re-run"
if ! command -v g++ >/dev/null 2>&1; then
    if [ "$DRY_RUN" = 1 ] && [ "$SKIP_DEPS" = 0 ]; then
        note "g++ is not here yet; the step above would have installed it"
    else
        fail "no g++ on this machine" \
             "socketley is a GCC build start to finish -- README.md's Toolchain section says so," \
             "and clang is a testing toolchain here, not a second way to build." \
             "on Debian and Ubuntu:  sudo apt-get install build-essential"
    fi
else
    GCCV="$(g++ -dumpfullversion -dumpversion 2>/dev/null | head -1)"
    GCCMAJ="${GCCV%%.*}"
    case "$GCCMAJ" in
        ''|*[!0-9]*) fail "cannot read a version out of \`g++ -dumpversion\` ($GCCV)" \
                          "socketley needs GCC 12 or newer for C++23" ;;
    esac
    if [ "$GCCMAJ" -lt 12 ]; then
        fail "GCC $GCCV is too old: socketley needs GCC 12 or newer" \
             "premake5.lua asks for cppdialect \"C++latest\" and the tree is C++23 throughout;" \
             "README.md's Requirements states the same floor." \
             "on Debian and Ubuntu:  sudo apt-get install g++-12, then select it with update-alternatives"
    fi
    note "g++ $GCCV"
fi

# ── liburing ────────────────────────────────────────────────────────────────
# Idempotent by construction: the script reads the installed headers' version
# and exits 0 without building when they already clear 2.7.
step "installing liburing, floor 2.7, pinned at 2.15" \
     "read scripts/install-liburing.sh -- it prints the version it found and the one it wanted"
run bash scripts/install-liburing.sh

# ── The vendored static archive ─────────────────────────────────────────────
# luajit only, and not `all`; the header of this file says why.  The script
# leaves an existing archive alone, so a second run costs one stat.
step "building the vendored LuaJIT archive" \
     "scripts/build-thirdparty.sh luajit failed; the first run needs git and a network"
run bash scripts/build-thirdparty.sh luajit
# HTTP/3's libraries, OpenSSL 3.5 with them; a few minutes once, a few stats after.
step "building OpenSSL 3.5, ngtcp2 and nghttp3 for HTTP/3" \
     "scripts/build-thirdparty.sh http3 failed; it needs perl, cmake, git and a network"
run bash scripts/build-thirdparty.sh http3

# ── Makefiles, then the Release build ───────────────────────────────────────
step "premake for this machine" "scripts/build-thirdparty.sh premake failed; on aarch64 it needs uuid-dev, git and a network"
run bash scripts/build-thirdparty.sh premake
PREMAKE=./scripts/premake5
"$PREMAKE" --version >/dev/null 2>&1 || PREMAKE=./thirdparty/premake/premake5
step "generating makefiles" "$PREMAKE gmake2 failed; check that it is executable"
run "$PREMAKE" gmake2
# The configuration premake5.lua made for this machine, release_x64 or release_arm64.
CONFIG="$(sed -n 's/^  config=debug_/release_/p' make/Makefile 2>/dev/null || true)"
[ -n "$CONFIG" ] || CONFIG="release_$([ "$ARCH" = aarch64 ] && echo arm64 || echo x64)"

step "building Release with -j$JOBS" \
     "if this was killed with no message it was the OOM reaper: re-run with --jobs 1"
# The daemon alone: the SDK archives, tests, fuzzers and benchmarks are no part of an install.
run make -C make config="$CONFIG" -j"$JOBS" socketley

step "checking the build produced a binary" \
     "make can exit 0 having linked nothing, so this is checked rather than assumed"
if [ "$DRY_RUN" = 1 ]; then
    note "would check: test -x bin/Release/socketley"
else
    if [ ! -x "$ROOT/bin/Release/socketley" ]; then
        fail "the build reported success but there is no binary at bin/Release/socketley" \
             "re-run the build alone and read its last lines:  make -C make config=$CONFIG -j1 socketley"
    fi
    note "$(stat -c%s "$ROOT/bin/Release/socketley") bytes"
fi

# ════════════════════════════════════════════════════════════════════════════
#  Install
# ════════════════════════════════════════════════════════════════════════════

# What this run puts on the machine, recorded so that --uninstall does not have
# to guess and cannot reach anything this script did not write.
INSTALLED=()

step "installing under $PREFIX" "check that $PREFIX is writable by root and not read-only"
run_root install -Dm755 "$ROOT/bin/Release/socketley" "$PREFIX/bin/socketley"
INSTALLED+=("$PREFIX/bin/socketley")

run_root install -Dm644 "$ROOT/man/socketley.1" "$PREFIX/share/man/man1/socketley.1"
INSTALLED+=("$PREFIX/share/man/man1/socketley.1")

run_root install -Dm755 "$ROOT/man/socketley-help.sh" "$PREFIX/share/socketley/socketley-help.sh"
INSTALLED+=("$PREFIX/share/socketley/socketley-help.sh")

# Best effort: a machine with no man database is not a failed install.
run_root mandb -q >/dev/null 2>&1 || true

# This repository carries no shell completion under any name, so nothing is
# installed for one and nothing is invented here.

# The highest system uid that no account has and no running process holds: a container's processes share the host's
# uid numbers, and MariaDB's, PostgreSQL's and Redis's images all run as 999, which useradd would hand out first.
free_system_uid() {
    taken=" $(getent passwd | cut -d: -f3 | tr '\n' ' ') $(awk '/^Uid:/ { print $3 }' /proc/[0-9]*/status 2>/dev/null | tr '\n' ' ') "
    u=999
    while [ "$u" -ge 100 ]; do
        case "$taken" in *" $u "*) u=$((u - 1)) ;; *) echo "$u"; return ;; esac
    done
}

if [ "$WANT_SERVICE" = 1 ]; then
    step "creating the socketley user and group" \
         "groupadd or useradd refused; check whether the name is already taken by something else"
    # Explicit, and not left to useradd's default: the IPC socket is 0660
    # socketley:socketley, so membership of that group is the set of people who
    # may administer the daemon, and whether useradd creates a matching group
    # depends on USERGROUPS_ENAB.
    if getent group socketley >/dev/null 2>&1; then
        note "group socketley already exists"
    else
        run_root groupadd --system socketley
    fi
    NOLOGIN=/usr/sbin/nologin
    if [ ! -x "$NOLOGIN" ]; then NOLOGIN=/sbin/nologin; fi
    if id -u socketley >/dev/null 2>&1; then
        note "user socketley already exists"
    else
        uid=$(free_system_uid)
        run_root useradd --system ${uid:+--uid "$uid"} --no-create-home --shell "$NOLOGIN" --gid socketley socketley
    fi
    if [ "$ADMIN_USER" = root ]; then
        :
    elif id -nG "$ADMIN_USER" 2>/dev/null | tr ' ' '\n' | grep -qx socketley; then
        note "$ADMIN_USER is in the socketley group already"
    else
        run_root usermod -aG socketley "$ADMIN_USER"
    fi

    step "creating the state, runtime and configuration directories" \
         "check that /var, /run and /etc are writable by root"
    # 0750 and not 0755: these files carry each runtime's --master-pw in
    # plaintext and the paths of its TLS private keys.  The daemon writes the
    # files themselves 0600; this stops anyone outside the group listing which
    # runtimes exist.  install -d on an existing directory resets the mode and
    # does nothing else, which is what makes a second run safe.
    run_root install -dm750 -o socketley -g socketley /var/lib/socketley/runtimes
    run_root install -dm755 -o socketley -g socketley /run/socketley
    run_root install -dm755 /etc/socketley

    if command -v systemctl >/dev/null 2>&1; then
        step "installing the systemd unit" "check: systemctl status socketley"
        run_root install -Dm644 "$ROOT/packaging/socketley.service" "$SYSTEMD_UNIT"
        INSTALLED+=("$SYSTEMD_UNIT")
        run_root systemctl daemon-reload
        run_root systemctl enable socketley.service
    else
        note "no systemctl here, so no service was installed"
        note "start the daemon by hand:  $PREFIX/bin/socketley daemon"
    fi
fi

# ── The manifest ────────────────────────────────────────────────────────────
step "recording what was installed" "check that $PREFIX/share/socketley is writable by root"
if [ "$DRY_RUN" = 1 ]; then
    note "would write $MANIFEST, listing:"
    for p in "${INSTALLED[@]}"; do note "  $p"; done
else
    MTMP="$(mktemp)"
    {
        printf '# socketley install manifest -- written by scripts/install-from-source.sh\n'
        printf '# prefix=%s date=%s\n' "$PREFIX" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '%s\n' "${INSTALLED[@]}"
    } > "$MTMP"
    run_root install -Dm644 "$MTMP" "$MANIFEST"
    rm -f "$MTMP"
    note "$MANIFEST"
fi

# ════════════════════════════════════════════════════════════════════════════
#  Verify
# ════════════════════════════════════════════════════════════════════════════
# An install that produced no working binary is the failure this script exists
# to catch, so it is checked here rather than left to whoever runs it next.

if [ "$DRY_RUN" = 1 ]; then
    step "verification, which would run" ""
    note "$PREFIX/bin/socketley version"
    note "ldd $PREFIX/bin/socketley        # every line resolved, liburing.so.2 among them"
    if [ "$WANT_SERVICE" = 1 ] && [ "$NO_START" = 0 ]; then
        note "systemctl start socketley.service"
        note "$PREFIX/bin/socketley ls"
    fi
    printf '\n--dry-run finished: nothing on this machine was changed.\n'
    exit 0
fi

step "verifying the binary runs" \
     "the binary is installed but will not execute; run \`ldd $PREFIX/bin/socketley\` and look for 'not found'"
VER="$("$PREFIX/bin/socketley" version 2>/dev/null || true)"
if [ -z "$VER" ]; then
    fail "$PREFIX/bin/socketley version printed nothing" \
         "run it by hand to see the loader's message:  $PREFIX/bin/socketley version"
fi
note "socketley $VER"

step "verifying every shared library resolves" \
     "a 'not found' line below names the library to install; liburing is the usual one"
if ldd "$PREFIX/bin/socketley" | grep -q 'not found'; then
    ldd "$PREFIX/bin/socketley" | grep 'not found' >&2 || true
    fail "the binary has unresolved shared libraries" \
         "if the missing one is liburing.so.2:  bash scripts/install-liburing.sh"
fi
note "$(ldd "$PREFIX/bin/socketley" | grep -c '=>' || true) shared libraries, all resolved"
note "$(ldd "$PREFIX/bin/socketley" | grep liburing || echo 'liburing is not dynamically linked into this build')"

if [ "$WANT_SERVICE" = 1 ] && [ "$NO_START" = 0 ] && command -v systemctl >/dev/null 2>&1; then
    step "starting the daemon" "read the log:  journalctl -u socketley -n 50 --no-pager"
    run_root systemctl start socketley.service

    # Waiting on the socket and not on a fixed sleep, because the socket
    # existing is the thing that says the daemon is up.
    step "waiting for the daemon's socket" \
         "the service started but never bound /run/socketley/socketley.sock; read: journalctl -u socketley -n 50 --no-pager"
    for _ in $(seq 1 50); do
        if [ -S /run/socketley/socketley.sock ]; then break; fi
        sleep 0.2
    done
    if [ ! -S /run/socketley/socketley.sock ]; then
        fail "the daemon did not create /run/socketley/socketley.sock within 10 seconds" \
             "read the log:  journalctl -u socketley -n 50 --no-pager"
    fi

    step "asking the daemon for its runtime list" \
         "the socket is there but the daemon did not answer; read: journalctl -u socketley -n 50 --no-pager"
    run_root "$PREFIX/bin/socketley" ls >/dev/null
    note "the daemon answered"
fi

# ════════════════════════════════════════════════════════════════════════════
printf '\n'
printf 'socketley %s is installed at %s/bin/socketley.\n' "$VER" "$PREFIX"
printf '\n'
if [ "$WANT_SERVICE" = 1 ]; then
    printf '  status:  systemctl status socketley\n'
    printf '  logs:    journalctl -u socketley -f\n'
    printf '\n'
    printf 'The daemon IPC socket is 0660 socketley:socketley.  Every socketley command\n'
    printf 'goes through it, and a runtime Lua script runs with the daemon privileges, so\n'
    printf 'reaching it is an administrative right.\n'
    if [ "$ADMIN_USER" != root ]; then
        printf '%s has it now; log in again, or run  newgrp socketley,  for it to take effect.\n' "$ADMIN_USER"
    fi
    printf 'To grant it to someone else:  sudo usermod -aG socketley <user>\n'
    printf '\n'
fi
printf '  first runtime:  socketley create server hello -p 9000 -s\n'
printf '  then:           socketley send hello "hi"\n'
printf '  help:           socketley --help   or   man socketley\n'
printf '  remove:         bash %s --uninstall\n' "$ROOT/scripts/install-from-source.sh"
