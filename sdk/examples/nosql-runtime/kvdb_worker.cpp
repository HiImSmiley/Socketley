// A NoSQL runtime of my own: a document store the daemon has never heard of.
//
// The daemon learns its name and its flags from kvdb.toml and never loads a
// line of this file; it forks and execs this binary like any other worker.
#include <socketley/worker.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <socketley/runtime/server.h>

namespace
{

// One document: a flat string->string map, which is what a NoSQL store is
// before anybody adds indexes.
using document = std::map<std::string, std::string>;

std::vector<std::string> split_ws(std::string_view line, size_t limit)
{
    std::vector<std::string> out;
    size_t i = 0;
    while (i < line.size() && out.size() + 1 < limit)
    {
        while (i < line.size() && line[i] == ' ') ++i;
        const size_t start = i;
        while (i < line.size() && line[i] != ' ') ++i;
        if (i > start) out.emplace_back(line.substr(start, i - start));
    }
    while (i < line.size() && line[i] == ' ') ++i;
    if (i < line.size()) out.emplace_back(line.substr(i));
    return out;
}

class kvdb final : public server_instance
{
public:
    explicit kvdb(std::string_view name) : server_instance(name)
    {
        // My verbs are GET, PUT and DEL, which the sniffer would read as
        // HTTP -- but a registered type gets lines unless it says otherwise,
        // so this constructor says nothing and a type that wants the
        // auto-detection back calls set_wire_protocol(proto_unknown).

        // One read can carry several commands, so the buffer is split rather
        // than treated as one line -- a store that answers only the first
        // command of a pipelined batch is not a store.
        set_on_client_message([this](int fd, std::string_view raw) {
            std::string out;
            while (!raw.empty())
            {
                const size_t nl = raw.find('\n');
                std::string_view line = nl == std::string_view::npos
                                      ? raw : raw.substr(0, nl);
                raw = nl == std::string_view::npos
                    ? std::string_view{} : raw.substr(nl + 1);
                while (!line.empty() && line.back() == '\r')
                    line.remove_suffix(1);
                if (!line.empty())
                    out += dispatch(line);
            }
            if (!out.empty())
                send_to(fd, out);
        });
    }

    // Everything the manifest declared, already validated by the daemon.
    void apply_config(const std::vector<std::pair<std::string, std::string>>& in) override
    {
        m_extra = in;
        for (const auto& [k, v] : in)
        {
            if (k == "path")          m_path = v;
            else if (k == "readonly") m_readonly = (v == "true");
            else if (k == "maxdocs")  m_maxdocs = std::stoul(v);
        }
        load();

        // The buffer's other end.  100 ms is the durability window; a store
        // that needs a smaller one needs a different design, not a smaller
        // number, because the write still lands on this thread.
        set_tick_interval(100);
        set_on_tick([this](double) { flush(); });
        set_on_stop([this] { flush(); });
    }

    void capture_config(std::vector<std::pair<std::string, std::string>>& out) const override
    {
        out = m_extra;
    }

    std::string stats_lines() const override
    {
        std::string s = "documents:" + std::to_string(m_docs.size());
        s += "\nreads:"  + std::to_string(m_reads);
        s += "\nwrites:" + std::to_string(m_writes);
        s += "\nreadonly:" + std::string(m_readonly ? "true" : "false");
        s += "\nstore:" + (m_path.empty() ? std::string("(memory)") : m_path);
        s += "\nunflushed:" + std::to_string(m_pending.size());
        s += "\n";
        return s;
    }

private:
    std::string dispatch(std::string_view line)
    {
        if (line.empty()) return "\n";
        const auto tok = split_ws(line, 4);
        std::string cmd = tok[0];
        std::transform(cmd.begin(), cmd.end(), cmd.begin(),
                       [](unsigned char c) { return std::toupper(c); });

        if (cmd == "PUT")
        {
            if (tok.size() < 4)  return "ERR usage: PUT <collection> <field> <value>\n";
            if (m_readonly)      return "ERR store is readonly\n";
            if (!m_docs.count(tok[1]) && m_docs.size() >= m_maxdocs)
                return "ERR maxdocs reached\n";
            m_docs[tok[1]][tok[2]] = tok[3];
            ++m_writes;
            journal('+', tok[1], tok[2], tok[3]);
            return "OK\n";
        }
        if (cmd == "GET")
        {
            if (tok.size() < 3) return "ERR usage: GET <collection> <field>\n";
            ++m_reads;
            auto d = m_docs.find(tok[1]);
            if (d == m_docs.end()) return "NIL\n";
            auto f = d->second.find(tok[2]);
            return f == d->second.end() ? "NIL\n" : f->second + "\n";
        }
        if (cmd == "DOC")
        {
            if (tok.size() < 2) return "ERR usage: DOC <collection>\n";
            ++m_reads;
            auto d = m_docs.find(tok[1]);
            if (d == m_docs.end()) return "NIL\n";
            std::string out;
            for (const auto& [k, v] : d->second) out += k + "=" + v + "\n";
            return out.empty() ? "EMPTY\n" : out;
        }
        if (cmd == "DEL")
        {
            if (tok.size() < 2) return "ERR usage: DEL <collection>\n";
            if (m_readonly)     return "ERR store is readonly\n";
            const bool had = m_docs.erase(tok[1]) > 0;
            if (had) { ++m_writes; journal('-', tok[1], "", ""); }
            return had ? "OK\n" : "NIL\n";
        }
        if (cmd == "KEYS")
        {
            ++m_reads;
            std::string out;
            for (const auto& [k, _] : m_docs) out += k + "\n";
            return out.empty() ? "EMPTY\n" : out;
        }
        if (cmd == "COUNT") { ++m_reads; return std::to_string(m_docs.size()) + "\n"; }
        return "ERR unknown command: " + tok[0] + "\n";
    }

    // ── Durability, off the hot path ────────────────────────────────────
    //
    // This runtime owns one thread and one io_uring loop, and this handler
    // runs ON that loop, so anything that blocks here blocks every connection
    // this runtime has.  Rewriting the whole store per PUT with a synchronous
    // ofstream measured 2147 ops/s against 24782 with no persistence at all --
    // an 11.5x tax paid by every reader for one writer's fsync.
    //
    // So a write appends one record to a buffer and returns.  The buffer
    // reaches the disk on the tick below, which is the trade this example
    // exists to show: the durability window is the tick interval, stated
    // rather than hidden.
    void journal(char op, const std::string& coll, const std::string& field,
                 const std::string& value)
    {
        if (m_path.empty()) return;
        m_pending += op;
        m_pending += coll;
        m_pending += '\t';
        m_pending += field;
        m_pending += '\t';
        m_pending += value;
        m_pending += '\n';

        // A cap as well as a timer, because a burst must not turn the buffer
        // into the memory leak the disk write was avoiding.
        if (m_pending.size() >= flush_bytes)
            flush();
    }

    // One append of whatever accumulated, and no fsync: the page cache is the
    // guarantee this example makes, which is the honest one for a log written
    // from an event loop.
    void flush()
    {
        if (m_pending.empty() || m_path.empty()) return;
        std::ofstream f(m_path, std::ios::app | std::ios::binary);
        if (f) f.write(m_pending.data(),
                       static_cast<std::streamsize>(m_pending.size()));
        m_pending.clear();
    }

    // Replay, last record wins, then rewrite the file with the live set --
    // at startup, where a full pass costs nobody a request.
    void load()
    {
        if (m_path.empty()) return;
        {
            std::ifstream f(m_path);
            if (!f) return;
            std::string line;
            while (std::getline(f, line))
            {
                if (line.size() < 2) continue;
                const char op = line[0];
                const size_t t1 = line.find('\t', 1);
                if (t1 == std::string::npos) continue;
                const std::string coll = line.substr(1, t1 - 1);
                if (op == '-') { m_docs.erase(coll); continue; }
                const size_t t2 = line.find('\t', t1 + 1);
                if (t2 == std::string::npos) continue;
                m_docs[coll][line.substr(t1 + 1, t2 - t1 - 1)] = line.substr(t2 + 1);
            }
        }
        compact();
    }

    void compact()
    {
        if (m_path.empty()) return;
        std::ofstream f(m_path, std::ios::trunc | std::ios::binary);
        if (!f) return;
        for (const auto& [coll, doc] : m_docs)
            for (const auto& [k, v] : doc)
                f << '+' << coll << '\t' << k << '\t' << v << '\n';
    }

    std::vector<std::pair<std::string, std::string>> m_extra;
    std::map<std::string, document> m_docs;
    static constexpr size_t flush_bytes = 64 * 1024;
    std::string m_pending;
    std::string m_path;
    bool        m_readonly = false;
    size_t      m_maxdocs  = 1000000;
    uint64_t    m_reads    = 0;
    uint64_t    m_writes   = 0;
};

} // namespace

int main(int argc, char** argv)
{
    socketley::worker::register_type("kvdb",
        [](std::string_view name) -> std::unique_ptr<runtime_instance> {
            return std::make_unique<kvdb>(name);
        });
    return socketley::worker::run(argc, argv);
}
