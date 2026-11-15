#pragma once
// What the same work costs in this build: a sanitizer checks every access it instruments, so an allowance of CPU is
// this many times itself there, as measured 2-4x on the select, Sieve, db and metrics paths and 55-58x on state json
// and IAM wildcards under ASan and UBSan.
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
inline constexpr int build_cpu_factor = 64;
#else
inline constexpr int build_cpu_factor = 1;
#endif
