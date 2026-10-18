#pragma once
// The liburing floor, checked here so the failure says the version instead of
// arriving as `not declared in this scope` errors inside event_loop.cpp.
#define SOCKETLEY_LIBURING_MIN_MAJOR 2
#define SOCKETLEY_LIBURING_MIN_MINOR 7

// liburing/io_uring_version.h is two #defines rather than the whole of
// liburing.h, which keeps this header cheap enough to force-include
// everywhere.
#if defined(__has_include)
#  if __has_include(<liburing/io_uring_version.h>)
#    include <liburing/io_uring_version.h>
#  endif
#else
#  include <liburing/io_uring_version.h>
#endif

#define SOCKETLEY_STRINGIFY_(x) #x
#define SOCKETLEY_STRINGIFY(x)  SOCKETLEY_STRINGIFY_(x)

#if !defined(IO_URING_VERSION_MAJOR) || !defined(IO_URING_VERSION_MINOR)
#  pragma message ("socketley needs liburing >= " \
        SOCKETLEY_STRINGIFY(SOCKETLEY_LIBURING_MIN_MAJOR) "." \
        SOCKETLEY_STRINGIFY(SOCKETLEY_LIBURING_MIN_MINOR) \
        ", and this system's liburing does not report a version at all "        \
        "(no <liburing/io_uring_version.h>, or no liburing headers installed).")
#  error "liburing is missing or predates version reporting -- install liburing >= 2.7: bash scripts/install-liburing.sh"
#endif

// Two independent integers and never one decimal number, because a comparison
// that reads "2.5" and "2.15" as decimals gets this exactly backwards.
#if (IO_URING_VERSION_MAJOR < SOCKETLEY_LIBURING_MIN_MAJOR) ||                  \
    (IO_URING_VERSION_MAJOR == SOCKETLEY_LIBURING_MIN_MAJOR &&                  \
     IO_URING_VERSION_MINOR < SOCKETLEY_LIBURING_MIN_MINOR)
#  pragma message ("liburing is too old: socketley requires >= "                \
        SOCKETLEY_STRINGIFY(SOCKETLEY_LIBURING_MIN_MAJOR) "."                   \
        SOCKETLEY_STRINGIFY(SOCKETLEY_LIBURING_MIN_MINOR)                       \
        ", found " SOCKETLEY_STRINGIFY(IO_URING_VERSION_MAJOR) "."              \
        SOCKETLEY_STRINGIFY(IO_URING_VERSION_MINOR)                             \
        ".  The event loop uses IORING_SETUP_NO_SQARRAY and "                   \
        "io_uring_register_napi (2.6) and IORING_ACCEPT_POLL_FIRST (2.7); "     \
        "none of them exists in the liburing-dev that Ubuntu 24.04 packages "   \
        "(2.5).  Install a current one with:  bash scripts/install-liburing.sh")
#  error "liburing too old -- the note printed with this error gives the version found and the command that fixes it"
#endif
// #error is a diagnostic and not a halt, so the unit carries on; premake5.lua
// force-includes this header everywhere instead, and make stops on the first
// file.

// Not left defined: this header is force-included into every translation unit in
// the project, and a two-token stringify helper is not something the rest of the
// tree should find already taken.
#undef SOCKETLEY_STRINGIFY_
#undef SOCKETLEY_STRINGIFY
