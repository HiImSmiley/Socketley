// Deterministic corpus-replay driver.
//
// WHY THIS EXISTS.  libFuzzer needs clang.  This project builds with GCC, and
// the machine it is developed on has no clang installed at all — so a pipeline
// that only knows how to run libFuzzer is a pipeline that runs nothing here and
// says "ok" while doing it.  This driver is the floor: it needs nothing but the
// compiler the project already uses, it runs the same LLVMFuzzerTestOneInput
// the libFuzzer build runs, and it is fully deterministic, so a failure in CI
// reproduces byte-for-byte on a laptop.
//
// WHAT IT IS NOT.  There is no coverage feedback.  It replays the seed corpus
// and then applies a seeded mutator to it — that finds shallow bugs and
// regressions, and it will not find the deep ones a coverage-guided fuzzer
// finds.  When clang is available, build_libfuzzer.sh builds the real thing and
// CI runs both.  Do not mistake a green replay run for a fuzzed parser.
//
// FAILING LOUDLY.  A replay over an empty or unreadable corpus takes no time
// and reports success, which is worse than not running at all — it is a green
// check mark attached to nothing.  So:
//
//   * no corpus path given, or none of them exist          -> exit 2
//   * corpus resolves to zero files                        -> exit 2
//   * zero inputs executed, or zero bytes fed              -> exit 2
//   * a file cannot be read                                -> exit 2
//
// and the summary line always states how many inputs and bytes went through.
//
// USAGE
//   fuzz_x <corpus-dir-or-file>...            replay + mutate, defaults below
//   FUZZ_SECONDS=n     wall-clock budget for the mutation phase (default 10)
//   FUZZ_ITERS=n       mutation iterations (default 20000, whichever ends first)
//   FUZZ_SEED=n        PRNG seed (default 1 — deterministic on purpose)
//   FUZZ_ARTIFACTS=dir where a crashing input is written (default ./fuzz-artifacts)
//   FUZZ_MAX_LEN=n     mutated inputs are capped at this many bytes (default 65536)

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

namespace {

// ─── crash reporting ────────────────────────────────────────────────────────
//
// ASan and UBSan print their own diagnosis and then abort.  What they cannot
// print is which input was being replayed, because they do not know.  The
// handler below writes it out — with write(2) only, so it is safe from a signal
// handler — and drops the same bytes into an artifact file so the failing case
// survives the CI job.

constexpr size_t MAX_KEEP = 1 << 20;
unsigned char g_current[MAX_KEEP];
volatile size_t g_current_len = 0;
char g_artifact_path[4096] = "fuzz-artifacts/crash-input.bin";

void write_all(int fd, const char* p, size_t n)
{
    while (n)
    {
        ssize_t w = ::write(fd, p, n);
        if (w <= 0)
            return;
        p += w;
        n -= static_cast<size_t>(w);
    }
}

void write_hex(int fd, const unsigned char* p, size_t n)
{
    static const char* hex = "0123456789abcdef";
    char line[64 * 2 + 2];
    while (n)
    {
        size_t chunk = n < 64 ? n : 64;
        size_t o = 0;
        for (size_t i = 0; i < chunk; i++)
        {
            line[o++] = hex[p[i] >> 4];
            line[o++] = hex[p[i] & 0xF];
        }
        line[o++] = '\n';
        write_all(fd, line, o);
        p += chunk;
        n -= chunk;
    }
}

void crash_handler(int sig)
{
    const char* msg = "\n=== fuzz replay: the input below caused a fault ===\n";
    write_all(2, msg, std::strlen(msg));
    write_hex(2, g_current, g_current_len < 4096 ? g_current_len : 4096);

    int fd = ::open(g_artifact_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0)
    {
        write_all(fd, reinterpret_cast<const char*>(g_current), g_current_len);
        ::close(fd);
        const char* tail = "=== written to the artifact path ===\n";
        write_all(2, tail, std::strlen(tail));
    }
    else
    {
        const char* tail = "=== could not write the artifact file ===\n";
        write_all(2, tail, std::strlen(tail));
    }

    ::signal(sig, SIG_DFL);
    ::raise(sig);
}

// ─── deterministic PRNG ─────────────────────────────────────────────────────

struct rng
{
    uint64_t s;
    explicit rng(uint64_t seed) : s(seed ? seed : 0x9E3779B97F4A7C15ULL) {}
    uint64_t next()
    {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        return s;
    }
    size_t below(size_t n) { return n ? static_cast<size_t>(next() % n) : 0; }
};

// ─── corpus ─────────────────────────────────────────────────────────────────

bool read_file(const std::string& path, std::vector<uint8_t>& out)
{
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f)
        return false;
    out.clear();
    uint8_t buf[16384];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0)
        out.insert(out.end(), buf, buf + n);
    bool bad = std::ferror(f) != 0;
    std::fclose(f);
    return !bad;
}

bool collect(const std::string& path, std::vector<std::string>& files, int depth = 0)
{
    struct stat st;
    if (::stat(path.c_str(), &st) != 0)
        return false;

    if (S_ISREG(st.st_mode))
    {
        files.push_back(path);
        return true;
    }
    if (!S_ISDIR(st.st_mode) || depth > 8)
        return false;

    DIR* d = ::opendir(path.c_str());
    if (!d)
        return false;
    bool ok = true;
    struct dirent* e;
    while ((e = ::readdir(d)) != nullptr)
    {
        if (std::strcmp(e->d_name, ".") == 0 || std::strcmp(e->d_name, "..") == 0)
            continue;
        if (!collect(path + "/" + e->d_name, files, depth + 1))
            ok = false;
    }
    ::closedir(d);
    return ok;
}

// ─── mutation ───────────────────────────────────────────────────────────────
//
// Five operators, all length-bounded.  Splice is the one that matters for
// protocol parsers: it grafts a header from one seed onto the body of another,
// which is how a fuzzer without coverage feedback still reaches combinations no
// single seed contains.

void mutate(std::vector<uint8_t>& buf, const std::vector<std::vector<uint8_t>>& corpus,
            rng& r, size_t max_len)
{
    switch (r.below(6))
    {
        case 0:  // bit flip
            if (!buf.empty())
                buf[r.below(buf.size())] ^= static_cast<uint8_t>(1u << r.below(8));
            break;
        case 1:  // byte set, biased toward protocol-significant bytes
        {
            if (buf.empty())
                break;
            static const uint8_t interesting[] = {
                0x00, 0x01, 0x7F, 0x80, 0xFF, '\r', '\n', ' ', ':', '*', '$', '"',
                '0', '9', 0x81, 0x88, 0x89, 0x8A, 126, 127, 125
            };
            buf[r.below(buf.size())] = (r.below(2) == 0)
                ? interesting[r.below(sizeof(interesting))]
                : static_cast<uint8_t>(r.next());
            break;
        }
        case 2:  // erase a run
            if (buf.size() > 1)
            {
                size_t at = r.below(buf.size());
                size_t n = 1 + r.below(buf.size() - at);
                buf.erase(buf.begin() + static_cast<long>(at),
                          buf.begin() + static_cast<long>(at + n));
            }
            break;
        case 3:  // duplicate a run
            if (!buf.empty() && buf.size() < max_len)
            {
                size_t at = r.below(buf.size());
                size_t n = 1 + r.below(buf.size() - at);
                if (n > max_len - buf.size())
                    n = max_len - buf.size();
                std::vector<uint8_t> run(buf.begin() + static_cast<long>(at),
                                         buf.begin() + static_cast<long>(at + n));
                buf.insert(buf.begin() + static_cast<long>(at), run.begin(), run.end());
            }
            break;
        case 4:  // splice another seed onto this one
            if (!corpus.empty())
            {
                const auto& other = corpus[r.below(corpus.size())];
                if (!other.empty())
                {
                    size_t keep = buf.empty() ? 0 : r.below(buf.size());
                    size_t take = 1 + r.below(other.size());
                    buf.resize(keep);
                    if (keep + take > max_len)
                        take = max_len > keep ? max_len - keep : 0;
                    buf.insert(buf.end(), other.begin(), other.begin() + static_cast<long>(take));
                }
            }
            break;
        default: // truncate — the shape a peer produces by simply stopping
            if (!buf.empty())
                buf.resize(r.below(buf.size()));
            break;
    }
    if (buf.size() > max_len)
        buf.resize(max_len);
}

size_t env_size(const char* name, size_t dflt)
{
    const char* v = std::getenv(name);
    if (!v || !*v)
        return dflt;
    char* end = nullptr;
    unsigned long long n = std::strtoull(v, &end, 10);
    if (end == v)
        return dflt;
    return static_cast<size_t>(n);
}

void run_one(const std::vector<uint8_t>& in)
{
    size_t keep = in.size() < MAX_KEEP ? in.size() : MAX_KEEP;
    if (keep)
        std::memcpy(g_current, in.data(), keep);
    g_current_len = keep;
    LLVMFuzzerTestOneInput(in.empty() ? reinterpret_cast<const uint8_t*>("") : in.data(), in.size());
}

} // namespace

int main(int argc, char** argv)
{
    const char* artifacts = std::getenv("FUZZ_ARTIFACTS");
    if (!artifacts || !*artifacts)
        artifacts = "fuzz-artifacts";
    ::mkdir(artifacts, 0755);
    std::snprintf(g_artifact_path, sizeof(g_artifact_path), "%s/crash-input.bin", artifacts);

    ::signal(SIGSEGV, crash_handler);
    ::signal(SIGBUS, crash_handler);
    ::signal(SIGABRT, crash_handler);
    ::signal(SIGFPE, crash_handler);
    ::signal(SIGILL, crash_handler);

    // ── resolve the corpus ──
    std::vector<std::string> paths;
    for (int i = 1; i < argc; i++)
        paths.emplace_back(argv[i]);
    if (paths.empty())
    {
        const char* env = std::getenv("FUZZ_CORPUS");
        if (env && *env)
            paths.emplace_back(env);
    }
    if (paths.empty())
    {
        std::fprintf(stderr,
            "fuzz replay: no corpus given.  Pass a directory or file, or set FUZZ_CORPUS.\n"
            "Refusing to run: a fuzzer with no input is a green check mark attached to nothing.\n");
        return 2;
    }

    std::vector<std::string> files;
    for (const auto& p : paths)
    {
        if (!collect(p, files))
        {
            std::fprintf(stderr, "fuzz replay: corpus path is missing or unreadable: %s\n", p.c_str());
            return 2;
        }
    }
    if (files.empty())
    {
        std::fprintf(stderr,
            "fuzz replay: the corpus resolved to zero files.  Run test/fuzz/make_corpus.py first.\n");
        return 2;
    }

    std::vector<std::vector<uint8_t>> corpus;
    corpus.reserve(files.size());
    size_t seed_bytes = 0;
    for (const auto& f : files)
    {
        std::vector<uint8_t> buf;
        if (!read_file(f, buf))
        {
            std::fprintf(stderr, "fuzz replay: could not read corpus file: %s\n", f.c_str());
            return 2;
        }
        seed_bytes += buf.size();
        corpus.push_back(std::move(buf));
    }

    const size_t iters    = env_size("FUZZ_ITERS", 20000);
    const size_t seconds  = env_size("FUZZ_SECONDS", 10);
    const size_t max_len  = env_size("FUZZ_MAX_LEN", 65536);
    const uint64_t prng   = static_cast<uint64_t>(env_size("FUZZ_SEED", 1));

    std::fprintf(stderr, "fuzz replay: %zu seeds (%zu bytes), %zu iters / %zus budget, seed=%llu\n",
                 corpus.size(), seed_bytes, iters, seconds,
                 static_cast<unsigned long long>(prng));

    // ── phase 1: every seed, unmutated.  This is the regression half — a seed
    //    that was once a crash must stay non-crashing forever. ──
    size_t executed = 0, bytes = 0;
    for (const auto& c : corpus)
    {
        run_one(c);
        executed++;
        bytes += c.size();
    }

    // ── phase 2: seeded mutation ──
    rng r(prng);
    std::vector<uint8_t> buf;
    time_t start = ::time(nullptr);
    for (size_t i = 0; i < iters; i++)
    {
        if (seconds && (i % 256) == 0 && ::time(nullptr) - start >= static_cast<time_t>(seconds))
            break;
        buf = corpus[r.below(corpus.size())];
        size_t rounds = 1 + r.below(4);
        for (size_t k = 0; k < rounds; k++)
            mutate(buf, corpus, r, max_len);
        run_one(buf);
        executed++;
        bytes += buf.size();
    }

    if (executed == 0)
    {
        std::fprintf(stderr, "fuzz replay: executed zero inputs.\n");
        return 2;
    }
    if (bytes == 0)
    {
        std::fprintf(stderr,
            "fuzz replay: executed %zu inputs totalling zero bytes — every seed is empty.\n", executed);
        return 2;
    }

    std::fprintf(stderr, "fuzz replay: OK — %zu inputs executed, %zu bytes, %ld s\n",
                 executed, bytes, static_cast<long>(::time(nullptr) - start));
    return 0;
}
