// Fuzz target: the Sieve interpreter's step budget (socketley/runtime/mail/mail_sieve.cpp).
//
// Reachable by any mail user who may put a script by ManageSieve, and the message it runs on by any stranger who can
// send that user mail: the script is the user's, the message is the sender's. A run stops past 1,000,000 steps, a
// step being one test, one action, 512 bytes scanned or decoded, or a turn of the wildcard matcher, so that no script
// and no message together hold a delivery thread for longer than that buys.
//
// Unlike fuzz_mail, whose Sieve case takes the script as bytes, this one makes it: an input is a program for a small
// generator of scripts that are expensive on purpose -- variables doubled into themselves, :matches patterns of many
// stars against long headers, :regex, body tests, nested allof and anyof, editheader, duplicate, an include of
// itself -- and of a message whose body and headers it repeats up to about a megabyte.
//
// What must hold, beside no report from the sanitizers:
//
//   * A compile and a run together take no more than five seconds of this thread's CPU in a build without
//     sanitizers, which is what a budget of 1,000,000 steps promises with room to spare (the slowest input known,
//     R10c-4, stops at the step bound after 0.35-0.54 s at GCC -O2); a run that does not stop there spends a
//     stranger's message on more than the budget says.  Every build of this target has sanitizers -- the replay
//     binary premake builds is ASan+UBSan as the libFuzzer one is -- and R10c-4 took 5-9 s in the one and 7.5-13 s
//     in the other, still stopping at the step bound.  So the five seconds are scaled by what this build, on this
//     machine, costs on this interpreter: a fixed reference run, timed once (sanitizer_factor()), against what it
//     costs at GCC -O2.  Capped by build_cpu_factor, the slowdown no sanitizer build exceeds on any path, so a slow
//     moment during the reference run cannot make the line looser than the shared one.
//   * A run has at least one action; one that failed keeps the message and does nothing else, and says the line.

#include <algorithm>
#include <ctime>
#include <string>
#include <string_view>

#include "fuzz_common.h"

#include "../../socketley/runtime/mail/mail_sieve.h"
#include "../../socketley/shared/util/build_cost.h"

namespace
{

namespace sieve = socketley::mail::sieve;

// Every read of the input is a statement of its own, never two in one expression: the operands of `+`, `|` or a
// call's arguments are evaluated in an order the language leaves open, and GCC and clang took different ones, so one
// input built two different scripts (round 10b: a find took 0.002 s in the GCC replay and 0.78 s under clang -O2).
struct reader
{
    const uint8_t* p;
    size_t n, at{0};
    uint8_t byte() { return at < n ? p[at++] : 0; }
    bool done() const { return at >= n; }
};

// A string a script quotes: letters, the wildcard characters, a variable or two, an escape.
std::string text(reader& r, size_t most = 24)
{
    static const char* const parts[] = {"a", "b", "*", "?", "*a*", "${v0}", "${v1}", "${v2}", "\\\\", "\\*",
                                        "${v0}${v0}", "x", "Re: ", "${1}", "%", ".", "\\\""};
    std::string s;
    const size_t len = r.byte() % most;
    for (size_t i = 0; i < len && !r.done(); ++i)
        s += parts[r.byte() % (sizeof parts / sizeof parts[0])];
    return s;
}

std::string quoted(reader& r, size_t most = 24) { return "\"" + text(r, most) + "\""; }

std::string regex_text(reader& r)
{
    static const char* const parts[] = {"a", "(a|b)", "*", "+", ".*", "[a-z]", "(.*)*", "x{1,9}", "^", "$", "|"};
    std::string s;
    const size_t len = r.byte() % 12;
    for (size_t i = 0; i < len && !r.done(); ++i)
        s += parts[r.byte() % (sizeof parts / sizeof parts[0])];
    return "\"" + s + "\"";
}

std::string test(reader& r, int depth);

std::string tests(reader& r, int depth)
{
    std::string s = "(";
    const int n = 1 + r.byte() % 4;
    for (int i = 0; i < n; ++i)
        s += (i ? ", " : "") + test(r, depth + 1);
    return s + ")";
}

std::string test(reader& r, int depth)
{
    switch (depth > 6 ? 8 : r.byte() % 11)
    {
        case 0: return "header :matches \"Subject\" " + quoted(r);
        case 1: return "header :regex \"Subject\" " + regex_text(r);
        case 2: return "body :contains " + quoted(r);
        case 3: return "body :raw :matches " + quoted(r);
        case 4:
        {
            const std::string v = std::to_string(r.byte() % 3);
            return "string :matches \"${v" + v + "}\" " + quoted(r);
        }
        case 5: return "allof " + tests(r, depth);
        case 6: return "anyof " + tests(r, depth);
        case 7: return "not " + test(r, depth + 1);
        case 8: return "header :count \"ge\" :comparator \"i;ascii-numeric\" \"Received\" \"3\"";
        case 9: return "address :all :matches \"From\" " + quoted(r);
        default: return "header :index 2 :contains \"Received\" " + quoted(r);
    }
}

std::string statements(reader& r, int depth, int most);

std::string statement(reader& r, int depth)
{
    const std::string v = "\"v" + std::to_string(r.byte() % 3) + "\"";
    switch (r.byte() % 10)
    {
        case 0: return "set " + v + " " + quoted(r) + ";";
        case 1: return "set :upper " + v + " \"${v0}${v1}${v2}${v0}${v1}${v2}\";";
        case 2:
        {
            const std::string cond = test(r, depth);
            const std::string then = statements(r, depth + 1, 4);
            const std::string otherwise = statements(r, depth + 1, 3);
            return "if " + cond + " {" + then + "} else {" + otherwise + "}";
        }
        case 3: return "addheader \"X-F\" \"${v0}\";";
        case 4: return "deleteheader :matches \"Received\" " + quoted(r) + ";";
        case 5: return "if duplicate :uniqueid \"${v1}\" { keep; }";
        case 6: return "include :personal \"self\";";
        case 7: return "fileinto :copy \"${v2}\";";
        case 8: return "if " + test(r, depth) + " { set " + v + " \"${1}${2}${v0}\"; }";
        default: return "addflag \"${v1}\";";
    }
}

std::string statements(reader& r, int depth, int most)
{
    std::string s;
    const int n = depth > 6 ? 0 : r.byte() % (most + 1);
    for (int i = 0; i < n && !r.done(); ++i)
        s += statement(r, depth) + "\n";
    return s;
}

double thread_cpu_s()
{
    timespec ts{};
    ::clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return static_cast<double>(ts.tv_sec) + static_cast<double>(ts.tv_nsec) / 1e9;
}

// How many times its plain cost the same Sieve work takes in this build.  The reference is wildcard :matches over a
// long header and a long variable, a body test and a regex, the interpreter's slow paths and R10c-4's; it does not
// reach the step bound.  14.5 ms at GCC -O2 (laptop, best of 5); 0.26 s under GCC's ASan+UBSan at -O3, 18x, where
// R10c-4 measured 9-17x; 0.20 s under clang's at -O1 with coverage, 14x, so R10c-4's 7.5-13 s meets a line of 70 s.
// Best of two, since a run can only be slowed by what else the machine does.
constexpr double reference_plain_s = 0.0145;

double sanitizer_factor()
{
    static const double factor = [] {
        std::string msg = "From: a@example.org\r\nTo: me@example.com\r\nSubject: ";
        for (int i = 0; i < 2000; ++i)
            msg += "aaaaaaaa ";
        msg += "\r\n";
        for (int i = 0; i < 20; ++i)
            msg += "Received: from h" + std::to_string(i) + " by mx\r\n";
        msg += "\r\n";
        for (int i = 0; i < 200; ++i)
            msg += "body line of the message aaaa\r\n";
        std::string script = "require [\"variables\", \"body\", \"regex\"];\n"
                             "set \"v\" \"aaaaaaaa\";\n"
                             "set \"v\" \"${v}${v}${v}${v}${v}${v}${v}${v}\";\n";
        for (int i = 0; i < 16; ++i)
            script += "if header :matches \"Subject\" \"*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b\" { keep; }\n"
                      "if string :matches \"${v}${v}\" \"*a?a*a?a*a*a*a*b\" { keep; }\n"
                      "if body :contains \"zzz\" { keep; }\n"
                      "if header :regex \"Subject\" \"(a|b)*c\" { keep; }\n";
        double best = 1e9;
        for (int r = 0; r < 2; ++r)
        {
            const double began = thread_cpu_s();
            std::string err;
            const auto s = sieve::script::compile(script, err);
            if (!s)
                fuzz::fail("compile", __FILE__, __LINE__, "the reference script does not compile");
            sieve::context c;
            (void)s->run({msg, "a@example.org", "me@example.com"}, c);
            best = std::min(best, thread_cpu_s() - began);
        }
        return std::clamp(best / reference_plain_s, 1.0, static_cast<double>(build_cpu_factor));
    }();
    return factor;
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz::set_current(data, size);
    if (size < 4 || size > 4096)
        return 0;
    reader r{data, size};

    // The message: a header that repeats, a long subject, and a body of one chunk many times over.
    const std::string chunk = text(r, 64) + "\r\n";
    const size_t subject_times = 1 + r.byte() * 4;
    const size_t received = r.byte() % 64;
    const size_t body_high = r.byte();
    const size_t body_low = r.byte();
    const size_t body_times = 1 + (body_high << 4 | body_low >> 4);
    std::string msg = "From: \"A B\" <a@example.org>\r\nTo: me@example.com\r\nSubject: ";
    for (size_t i = 0; i < subject_times && msg.size() < (256u << 10); ++i)
        msg += chunk.substr(0, chunk.size() - 2) + " ";
    msg += "\r\n";
    for (size_t i = 0; i < received; ++i)
        msg += "Received: from h" + std::to_string(i) + " by mx\r\n";
    msg += "\r\n";
    for (size_t i = 0; i < body_times && msg.size() < (1u << 20); ++i)
        msg += chunk;

    std::string script = "require [\"fileinto\", \"copy\", \"variables\", \"body\", \"regex\", \"editheader\", "
                         "\"duplicate\", \"include\", \"imap4flags\", \"relational\", \"index\", "
                         "\"comparator-i;ascii-numeric\"];\n";
    script += statements(r, 0, 32);

    const double began = thread_cpu_s();
    const sieve::loader load = [&script](bool, std::string_view name, std::string& out) {
        if (name != "self")
            return false;
        out = script;
        return true;
    };
    std::string err;
    const auto s = sieve::script::compile(script, err, load);
    if (s)
    {
        sieve::context c;
        c.own = {"me@example.com"};
        c.now_s = 1700000000;
        c.seen = [](std::string_view key) { return key.size() % 3 == 0; };
        const sieve::outcome o = s->run({msg, "a@example.org", "me@example.com"}, c);
        FUZZ_CHECK(!o.actions.empty(), "an outcome with no action");
        if (!o.error.empty())
            FUZZ_CHECK(o.error.starts_with("line ") && o.actions.size() == 1 &&
                           o.actions[0].k == sieve::action::kind::keep,
                       "a failed run that does more than keep, or does not say its line");
    }
    const double spent = thread_cpu_s() - began;
    const double allowed = 5.0 * sanitizer_factor();
    if (spent > allowed)
    {
        fuzz::dump("the script", reinterpret_cast<const uint8_t*>(script.data()), script.size());
        std::fprintf(stderr,
                     "a compile and a run took %.2f s of CPU over a message of %zu bytes, "
                     "allowed %.2f s (5 s x %.1f)\n",
                     spent, msg.size(), allowed, sanitizer_factor());
    }
    FUZZ_CHECK(spent <= allowed, "a Sieve run took longer than its step budget allows");
    return 0;
}
