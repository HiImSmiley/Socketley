#pragma once
// What the same work costs in this build: a sanitizer checks every access it instruments, so an allowance of CPU is
// this many times itself there, as measured 2-4x on the select, Sieve, db and metrics paths and 55-58x on state json
// and IAM wildcards under ASan and UBSan.  An unoptimized build without one (Debug, and the invariants build made
// from it) inlines nothing, and ran 2.4-3.2 times past the Release bounds on a GitHub runner: state json 436 ms of
// 150, Sieve 3.2 s of 1, db 2.0 s of 1.
//
// GCC says a sanitizer build by __SANITIZE_ADDRESS__ / __SANITIZE_THREAD__; clang (18 at least) defines neither and
// answers __has_feature instead, so a clang ASan build -- the libFuzzer one -- read 1 here.  Both compilers define
// __OPTIMIZE__ from -O1 up.
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define SOCKETLEY_BUILD_SANITIZED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
#define SOCKETLEY_BUILD_SANITIZED 1
#endif
#endif
#ifdef SOCKETLEY_BUILD_SANITIZED
inline constexpr int build_cpu_factor = 64;
#elif !defined(__OPTIMIZE__)
inline constexpr int build_cpu_factor = 8;
#else
inline constexpr int build_cpu_factor = 1;
#endif
