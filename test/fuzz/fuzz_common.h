#pragma once
// Shared plumbing for the fuzz targets.
//
// Every target here exposes the libFuzzer entry point:
//
//     extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);
//
// and nothing else.  Which driver calls it is a build-time decision:
//
//   * clang + libFuzzer  — coverage-guided, the real thing.  Built by
//     test/fuzz/build_libfuzzer.sh when the toolchain has it.
//   * GCC + fuzz_replay_main.cpp — a deterministic corpus replayer with a
//     seeded mutator.  No coverage feedback, but it is reproducible, needs
//     nothing beyond the compiler the project already builds with, and it is
//     what premake builds.  This is the path CI can always take.
//
// The targets themselves must not care which one is driving them.
//
// FAILURE POLICY.  A fuzz target that only checks "did it crash" is worth very
// little on a parser that is careful about bounds.  Each target here also
// states properties the parser must hold to (an argument view has to point
// inside the buffer it was parsed from; two parsers over the same grammar have
// to agree; a rewritten request must not gain a header the original did not
// have) and calls FUZZ_CHECK on them.  FUZZ_CHECK aborts, which is what turns a
// property violation into a red CI job rather than a line in a log.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>

namespace fuzz {

// The input currently under test.  The replay driver's crash handler reads
// this so a SIGABRT/SIGSEGV still names the bytes that caused it.  Under
// libFuzzer this is unused — libFuzzer writes its own crash- artifact.
inline const uint8_t*& current_data()
{
    static const uint8_t* p = nullptr;
    return p;
}
inline size_t& current_size()
{
    static size_t n = 0;
    return n;
}

inline void set_current(const uint8_t* data, size_t size)
{
    current_data() = data;
    current_size() = size;
}

// Dump `size` bytes as a C string literal so a failure report can be pasted
// straight into a unit test.  Bounded: a 64 KB dump helps nobody.
inline void dump(const char* label, const uint8_t* data, size_t size)
{
    constexpr size_t MAX = 512;
    size_t n = size < MAX ? size : MAX;
    std::fprintf(stderr, "%s (%zu bytes%s): \"", label, size, size > MAX ? ", truncated" : "");
    for (size_t i = 0; i < n; i++)
    {
        unsigned char c = data[i];
        if (c == '\\')      std::fputs("\\\\", stderr);
        else if (c == '"')  std::fputs("\\\"", stderr);
        else if (c == '\r') std::fputs("\\r", stderr);
        else if (c == '\n') std::fputs("\\n", stderr);
        else if (c == '\t') std::fputs("\\t", stderr);
        else if (c >= 0x20 && c < 0x7F) std::fputc(static_cast<int>(c), stderr);
        else std::fprintf(stderr, "\\x%02x", c);
    }
    std::fputs("\"\n", stderr);
}

[[noreturn]] inline void fail(const char* expr, const char* file, int line, const char* what)
{
    std::fprintf(stderr, "\n=== FUZZ PROPERTY VIOLATED ===\n"
                         "  %s\n  check: %s\n  at:    %s:%d\n",
                 what, expr, file, line);
    dump("  input", current_data(), current_size());
    std::fflush(stderr);
    std::abort();
}

// Read a value out of the fuzz input without ever running off the end.  Fuzz
// targets that need a knob (a split offset, a flag) take it from the input so
// the fuzzer can drive it, but the input is also allowed to be empty.
inline uint8_t byte_at(const uint8_t* data, size_t size, size_t idx, uint8_t dflt = 0)
{
    return idx < size ? data[idx] : dflt;
}

// A zero-length input is a legitimate test case, but a null pointer is not:
// UBSan reports memcpy(dst, nullptr, 0) and std::string_view(nullptr, 0), and
// those reports would be about this harness rather than about the parser.
// Substitute a valid address and keep the length at zero.
inline const uint8_t* never_null(const uint8_t* data)
{
    static const uint8_t empty = 0;
    return data ? data : &empty;
}

} // namespace fuzz

#define FUZZ_CHECK(expr, what) \
    do { if (!(expr)) ::fuzz::fail(#expr, __FILE__, __LINE__, (what)); } while (0)

// Non-fatal observation.  Used only where a difference between two code paths
// is real and reportable but not on its own proof of a defect — see the note in
// fuzz_resp.cpp.  Set FUZZ_STRICT=1 to make these abort too.
inline void fuzz_observe(const char* what, const uint8_t* data, size_t size)
{
    static const bool strict = [] {
        const char* e = std::getenv("FUZZ_STRICT");
        return e && e[0] == '1';
    }();
    static unsigned long reported = 0;
    if (strict)
    {
        std::fprintf(stderr, "\n=== FUZZ OBSERVATION (FUZZ_STRICT=1) ===\n  %s\n", what);
        ::fuzz::dump("  input", data, size);
        std::fflush(stderr);
        std::abort();
    }
    if (reported < 5)
    {
        std::fprintf(stderr, "[fuzz] observation: %s\n", what);
        ::fuzz::dump("  input", data, size);
        reported++;
    }
}
