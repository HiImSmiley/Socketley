// Fuzz target: the cache's RESP command dispatch (socketley/runtime/cache/cache_instance.cpp, process_resp() and
// everything it calls), past the parser fuzz_resp covers and over the store fuzz_cache_ops covers.
//
// Reachable by any client of a cache runtime, before any AUTH where the cache takes none: every argument of every
// command is the client's. The commands come from resp_command_table.h, the table COMMAND answers from, so a
// command added there is a command fuzzed here.
//
// An input is a program for a generator: each command is a byte for its name, a byte for how many arguments, and
// for each argument a byte that picks a key, a number at an edge, an option word, a short Lua script, or a run of
// the input's own bytes. The commands are written as RESP arrays into one connection's read buffer, cut where the
// input says, and dispatched as a read would dispatch them; the cache has no event loop, so nothing it answers is
// sent and nothing it arms is armed.
//
// Left out, because they reach outside this process: SAVE, BGSAVE, BGREWRITEAOF, SHUTDOWN, REPLICAOF and SLAVEOF,
// SYNC and PSYNC, FAILOVER, MIGRATE, MONITOR, DEBUG, and CONFIG (whose SET may name a directory to write to).
//
// What must hold, beside no report from the sanitizers:
//
//   * What the cache wrote back is a sequence of whole RESP values, RESP2 or RESP3, and nothing after the last.
//   * A batch of commands none of which may block, subscribe or silence its replies is answered at least once per
//     command, so no command is swallowed.

#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "fuzz_common.h"

#include "shared/loop/event_loop_definitions.h"
#include "shared/runtime/runtime_instance.h"
#include "shared/runtime/runtime_manager.h"
#include "shared/loop/conn_alloc.h"
#include "shared/loop/write_queue.h"
#include "runtime/cache/resp_command_table.h"

// Reaching inside the class, as fuzz_server_ops does: process_resp() and the connection it reads are private, and
// the alternative is a test-only accessor in socketley/. Every header cache_instance.h needs is included above.
#define private public
#include "runtime/cache/cache_instance.h"
#undef private

namespace
{

bool left_out(std::string_view n)
{
    for (std::string_view x : {"save", "bgsave", "bgrewriteaof", "shutdown", "replicaof", "slaveof", "sync", "psync",
                               "failover", "migrate", "monitor", "debug", "config"})
        if (n == x)
            return true;
    return false;
}

// Commands that may answer nothing for now, answer more than once, or stop answering.
bool may_not_answer(std::string_view n)
{
    for (std::string_view x : {"blpop", "brpop", "blmove", "brpoplpush", "bzpopmin", "bzpopmax", "blmpop", "bzmpop",
                               "xread", "xreadgroup", "wait", "waitaof", "subscribe", "psubscribe", "ssubscribe",
                               "unsubscribe", "punsubscribe", "sunsubscribe", "client", "quit", "reset", "multi",
                               "exec", "discard", "hello", "eval", "evalsha", "eval_ro", "evalsha_ro", "fcall",
                               "fcall_ro", "auth"})
        if (n == x)
            return true;
    return false;
}

std::vector<std::string_view> names()
{
    std::vector<std::string_view> out;
    for (const auto& c : resp_command_table)
        if (!left_out(c.name))
            out.push_back(c.name);
    return out;
}

struct reader
{
    const uint8_t* p;
    size_t n, at{0};
    uint8_t byte() { return at < n ? p[at++] : 0; }
    bool done() const { return at >= n; }
};

std::string argument(reader& r)
{
    static const char* const words[] = {
        "k0", "k1", "k2", "{k}a", "{k}b", "f", "m", "0", "1", "-1", "2", "10", "1000000", "9223372036854775807",
        "-9223372036854775808", "18446744073709551616", "inf", "-inf", "+inf", "nan", "1e308", "0.5", "(1", "[a",
        "(", "[", "-", "+", "*", "$", "EX", "PX", "EXAT", "NX", "XX", "GT", "LT", "KEEPTTL", "GET", "WITHSCORES",
        "LIMIT", "COUNT", "MATCH", "TYPE", "BY", "STORE", "ASC", "DESC", "ALPHA", "LEFT", "RIGHT", "BEFORE", "AFTER",
        "MAXLEN", "MINID", "~", "=", "BYSCORE", "BYLEX", "REV", "IDLE", "FORCE", "JUSTID", "NOMKSTREAM", "WEIGHTS",
        "AGGREGATE", "SUM", "MIN", "MAX", "CH", "INCR", "PERSIST", "FIELDS", "LEN", "IDX", "RANK", "MAXAGE",
        "return redis.call('get', KEYS[1])", "return {1, 2, {3, 'x'}, redis.status_reply('ok')}",
        "return redis.call('lpush', KEYS[1], ARGV[1])", "return redis.error_reply('no')", "return 1.5",
        "local t = {} for i = 1, 100000 do t[i] = i end return #t", "return redis.pcall('nosuch')", "*0-0", "0-1"};
    const uint8_t pick = r.byte();
    if (pick < 0xE0)
        return words[pick % (sizeof words / sizeof words[0])];
    // A run of the input's own bytes, CR, LF and NUL among them.
    std::string s;
    const size_t len = r.byte() % 40;
    for (size_t i = 0; i < len && !r.done(); ++i)
        s.push_back(static_cast<char>(r.byte()));
    return s;
}

void encode(std::string& out, const std::vector<std::string>& args)
{
    out += "*" + std::to_string(args.size()) + "\r\n";
    for (const auto& a : args)
        out += "$" + std::to_string(a.size()) + "\r\n" + a + "\r\n";
}

// One RESP2 or RESP3 value at `at`; false when what is there is none.
bool value(std::string_view s, size_t& at, int depth)
{
    if (depth > 64 || at >= s.size())
        return false;
    const char t = s[at];
    const size_t eol = s.find("\r\n", at);
    if (eol == std::string_view::npos)
        return false;
    const std::string_view head = s.substr(at + 1, eol - at - 1);
    at = eol + 2;
    const auto number = [&](long long& n) {
        if (head.empty())
            return false;
        char* end = nullptr;
        const std::string h(head);
        n = std::strtoll(h.c_str(), &end, 10);
        return end && *end == '\0';
    };
    long long n = 0;
    switch (t)
    {
        case '+': case '-': case ':': case '_': case '#': case ',': case '(':
            return head.find_first_of("\r\n") == std::string_view::npos;
        case '$': case '!': case '=':
            if (!number(n))
                return false;
            if (n < 0)
                return t == '$' && n == -1;
            if (s.size() - at < static_cast<size_t>(n) + 2 || s.compare(at + static_cast<size_t>(n), 2, "\r\n") != 0)
                return false;
            at += static_cast<size_t>(n) + 2;
            return true;
        case '*': case '~': case '>': case '%': case '|':
            if (!number(n))
                return false;
            if (n < 0)
                return t == '*' && n == -1;
            for (long long i = 0; i < n * (t == '%' || t == '|' ? 2 : 1); ++i)
                if (!value(s, at, depth + 1))
                    return false;
            // An attribute is followed by the value it describes.
            return t != '|' || value(s, at, depth + 1);
        default:
            return false;
    }
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz::set_current(data, size);
    if (size < 2 || size > 8192)
        return 0;
    static const std::vector<std::string_view> table = names();
    reader r{data, size};
    const size_t cut = 1 + r.byte() * 13u;

    std::string wire;
    size_t commands = 0;
    bool every_one_answers = true;
    while (!r.done() && commands < 48)
    {
        const std::string_view name = table[r.byte() % table.size()];
        std::vector<std::string> args{std::string(name)};
        const size_t argc = r.byte() % 7;
        for (size_t i = 0; i < argc && !r.done(); ++i)
            args.push_back(argument(r));
        // Upper case now and then, which the dispatch folds.
        if (r.byte() & 1)
            for (char& c : args[0])
                c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        encode(wire, args);
        every_one_answers = every_one_answers && !may_not_answer(name);
        ++commands;
    }

    auto cache = std::make_unique<cache_instance>("fuzz-cache");
    cache->set_max_memory(32u << 20);
    auto conn = socketley::make_connection<client_connection>();
    conn->fd = -1;
    // The bytes arrive in reads of `cut`, as a socket hands them over, each dispatched before the next comes.
    for (size_t at = 0; at < wire.size() && !conn->closing; at += cut)
    {
        conn->partial.append(wire, at, cut);
        cache->process_resp(conn.get());
    }

    const std::string_view out = conn->response_buf;
    size_t at = 0, replies = 0;
    while (at < out.size())
    {
        const size_t from = at;
        if (!value(out, at, 0))
        {
            fuzz::dump("the reply that is no RESP value", reinterpret_cast<const uint8_t*>(out.data()) + from,
                       std::min<size_t>(out.size() - from, 200));
            FUZZ_CHECK(false, "the cache answered with bytes that are no RESP value");
        }
        ++replies;
    }
    if (every_one_answers && !conn->closing && !conn->blocked)
        FUZZ_CHECK(replies >= commands, "a command the cache took was not answered");
    return 0;
}
