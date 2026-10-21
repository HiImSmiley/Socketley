#pragma once
// The messages a mail runtime holds until they are delivered: a file each, its envelope in lines ahead of the message
// and its length after it, written on the ring and synced before the client is told 250, as Postfix does.  A file
// whose end says no length is one a crash cut while it was received, and is deleted at the next start.
//
// What became of each recipient is appended to one log beside the files and read back at the start; a line it lost
// to a crash is a recipient tried again, never one forgotten.  A message small enough is kept in memory as well, so
// the delivery that follows its arrival reads nothing back.
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "../../shared/loop/event_loop.h"
#include "../../shared/loop/file_io.h"

namespace socketley::mail
{

enum class rcpt_state : uint8_t { waiting, delivered, failed };

struct spool_rcpt
{
    std::string addr;
    rcpt_state  state{rcpt_state::waiting};
    // The last answer, for the bounce and for `socketley mail ... show`.
    std::string why;
};

struct spool_entry
{
    std::string id;
    std::string from;
    std::vector<spool_rcpt> rcpts;
    // Who sent it: the signed-in user, the peer and its HELO, and when.
    std::string user;
    std::string peer;
    std::string helo;
    int64_t     at_ms{0};
    // A bounce this runtime wrote, so a failure of its own is not answered with another.
    bool        bounce{false};
    // What SPF, DKIM and DMARC said of it as it arrived: the value of its Authentication-Results, and the folder
    // DMARC sent it to.
    std::string auth;
    std::string folder;
    uint64_t    body_off{0};
    uint64_t    body_len{0};
    uint32_t    attempts{0};
    int64_t     next_ms{0};
    // The message's bytes while it is small and new, dropped once its delivery is over or the cache is full.
    std::shared_ptr<const std::string> body;
    size_t waiting() const;
};
using entry_ptr = std::shared_ptr<spool_entry>;

class spool
{
public:
    spool(event_loop& loop, file_io& io) : m_loop(loop), m_io(io) {}
    ~spool();
    spool(const spool&)            = delete;
    spool& operator=(const spool&) = delete;

    // The directory made, the files a crash cut deleted and the rest read back; blocking, at the start.
    bool open(const std::string& dir, bool relaxed, std::string& why);
    void close();
    const std::string& dir() const { return m_dir; }

    // A message being received, its envelope in `e` and the bytes ahead of its body, its Received line, in `head`.
    uint64_t begin(entry_ptr e, std::string_view head);
    void append(uint64_t w, std::string_view bytes);
    // On the disk, then `done(true)` and the entry is held; `done(false)` when it could not be written.
    void finish(uint64_t w, std::function<void(bool)> done);
    void abort(uint64_t w);

    // A recipient delivered or failed for good, its answer kept.
    void mark(spool_entry& e, size_t rcpt, rcpt_state s, std::string_view why);
    // The next try of what is still waiting.
    void retry(spool_entry& e, uint32_t attempts, int64_t next_ms);
    // What the checks of its arrival said, kept for its mailboxes.
    void note_auth(spool_entry& e, std::string results, std::string folder);
    // Every recipient's delivery is over: the file goes.
    void remove(const std::string& id);
    // A message written and then refused before it was taken, which nothing will deliver.
    void forget_written(const std::string& id) { remove(id); }

    std::map<std::string, entry_ptr>& entries() { return m_entries; }
    const std::map<std::string, entry_ptr>& entries() const { return m_entries; }
    entry_ptr find(const std::string& id) const;
    // The file a message is kept in, for a helper thread that reads it whole.
    std::string file_of(const std::string& id) const { return path_of(id); }
    // `len` bytes of a message's body from `off`, read from memory or its file.
    void read(const entry_ptr& e, uint64_t off, uint32_t len, std::function<void(bool ok, std::string_view bytes)> cb);

    uint64_t bytes() const { return m_bytes; }
    uint64_t written() const { return m_written; }
    uint64_t write_failures() const { return m_write_failures; }
    // A message's body kept in memory up to this size, and all of them up to the second.
    static constexpr size_t keep_one = 1u << 20;
    static constexpr size_t keep_all = 64u << 20;

private:
    struct writer
    {
        entry_ptr   e;
        int         fd{-1};
        bool        opening{false};
        bool        writing{false};
        bool        finishing{false};
        bool        aborted{false};
        bool        failed{false};
        uint64_t    off{0};
        std::string buf;
        std::string flying;
        // The body as it came, kept while it is small enough to be the in-memory copy.
        std::string copy;
        bool        copying{true};
        std::function<void(bool)> done;
    };
    void pump(uint64_t w);
    void end(uint64_t w, bool ok);
    void log(std::string line);
    std::string path_of(const std::string& id) const { return m_dir + "/" + id + ".msg"; }
    // The opened file of a message being read, kept while its delivery reads it.
    struct reader
    {
        int fd{-1};
        bool opening{false};
        uint32_t users{0};
        std::vector<std::function<void(int)>> waiting;
    };

    event_loop& m_loop;
    file_io&    m_io;
    std::string m_dir;
    bool        m_relaxed{false};
    int         m_log_fd{-1};
    std::string m_log_buf;
    bool        m_log_writing{false};
    std::map<std::string, entry_ptr> m_entries;
    std::unordered_map<uint64_t, std::unique_ptr<writer>> m_writers;
    std::unordered_map<std::string, reader> m_readers;
    uint64_t m_next_writer{1};
    uint64_t m_bytes{0};
    uint64_t m_kept{0};
    uint64_t m_written{0};
    uint64_t m_write_failures{0};
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
};

// A message id for the spool: the time, a counter and the shard, in hex, sorting by arrival.
std::string new_spool_id(uint32_t shard);

}   // namespace socketley::mail
