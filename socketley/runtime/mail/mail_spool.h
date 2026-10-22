#pragma once
// The messages a mail runtime holds until they are delivered, each its envelope in lines ahead of the message and its
// length after it, synced before the client is told 250.  One up to a mebibyte is a record of a segment, a file of
// 32 MiB written before it is used, so one fdatasync of a few overwritten blocks commits every message waiting for
// it; a larger one is a file of its own.  A record is checked by its segment's generation and a CRC, so what a crash
// cut or an earlier use of the segment left is where reading stops; a file whose end says no length is deleted.
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
#include "../../shared/loop/hash_pool.h"

namespace socketley::mail
{

enum class rcpt_state : uint8_t { waiting, delivered, failed };

struct spool_rcpt
{
    spool_rcpt() = default;
    explicit spool_rcpt(std::string a) : addr(std::move(a)) {}
    std::string addr;
    rcpt_state  state{rcpt_state::waiting};
    // The last answer, for the bounce and for `socketley mail ... show`.
    std::string why;
    // What its sender asked to be told (RFC 3461): NOTIFY's bits and ORCPT as given.
    uint8_t     notify{0};
    std::string orcpt;
    // Delivered where its NOTIFY went no further, so a success is this runtime's to report: 1 delivered, 2 relayed.
    uint8_t     report{0};
    // Its sender was told what became of it, by a report made before the message's end.
    bool        told{false};
    // The targets an alias made of it that took the message, which a later try does not send to again, and those
    // that refused it for good, with why.
    std::vector<std::string> targets_done;
    std::vector<std::string> targets_failed;
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
    // RET (1 FULL, 2 HDRS) and ENVID of its MAIL, and whether its delay was reported.
    uint8_t     ret{0};
    std::string envid;
    bool        delay_told{false};
    // REQUIRETLS was asked of its MAIL: it goes on only to a server checked by DANE or MTA-STS (RFC 8689).
    bool        requiretls{false};
    // What SPF, DKIM and DMARC said of it as it arrived: the value of its Authentication-Results, and the folder
    // DMARC sent it to.
    std::string auth;
    std::string folder;
    // The segment generation its record is in, 0 for a file of its own, the record's length, and where the body lies.
    uint32_t    seg{0};
    uint32_t    rec_len{0};
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
    // Segments are made ready on `pool`'s lane 0, which takes blocking work.
    spool(event_loop& loop, file_io& io, hash_pool& pool) : m_loop(loop), m_io(io), m_pool(pool) {}
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
    // One of the targets an alias made of a recipient took the message, or refused it for good.
    void target_over(spool_entry& e, size_t rcpt, std::string_view addr, bool ok, std::string_view why);
    // Its sender was told of the recipient.
    void told(spool_entry& e, size_t rcpt);
    // The next try of what is still waiting.
    void retry(spool_entry& e, uint32_t attempts, int64_t next_ms);
    // Its sender was told the message is late.
    void delay_told(spool_entry& e);
    // What the checks of its arrival said, kept for its mailboxes.
    void note_auth(spool_entry& e, std::string results, std::string folder);
    // Every recipient's delivery is over, or the message is dropped: its file goes, or its record no longer counts.
    void remove(const std::string& id);
    // A message written and then refused before it was taken, which nothing will deliver.
    void forget_written(const std::string& id) { remove(id); }

    std::map<std::string, entry_ptr>& entries() { return m_entries; }
    const std::map<std::string, entry_ptr>& entries() const { return m_entries; }
    entry_ptr find(const std::string& id) const;
    // The file a message is kept in, its segment's or its own, for a helper thread that reads it at body_off.
    std::string file_of(const spool_entry& e) const;
    // Sparse segments' messages moved to the current one, so the segment can be used again.
    void tick(int64_t now_ms);
    // `len` bytes of a message's body from `off`, read from memory or its file.
    void read(const entry_ptr& e, uint64_t off, uint32_t len, std::function<void(bool ok, std::string_view bytes)> cb);

    uint64_t bytes() const { return m_bytes; }
    uint64_t written() const { return m_written; }
    uint64_t write_failures() const { return m_write_failures; }
    // Syncs of the segments and the messages they committed, and the segments on the disk.
    uint64_t commits() const { return m_commits; }
    uint64_t committed() const { return m_committed; }
    uint64_t moved() const { return m_moved; }
    size_t segments() const { return m_segs.size() + m_spare.size() + m_free.size(); }
    // A message's body kept in memory up to this size, and all of them up to the second.
    static constexpr size_t keep_one = 1u << 20;
    static constexpr size_t keep_all = 64u << 20;
    static constexpr uint64_t seg_size = 32u << 20;
    // The block at the start of a segment that names its generation; its records follow.
    static constexpr uint64_t seg_head = 4096;
    static constexpr size_t rec_head = 16;

private:
    struct writer
    {
        entry_ptr   e;
        // In a file of its own once it outgrew a record; until then its bytes wait in `buf`.
        bool        own{false};
        // The envelope's length ahead of the body in `buf`.
        size_t      head{0};
        int         fd{-1};
        bool        opening{false};
        bool        writing{false};
        bool        finishing{false};
        bool        aborted{false};
        bool        failed{false};
        uint64_t    off{0};
        std::string buf;
        std::string flying;
        std::function<void(bool)> done;
    };
    struct segment
    {
        uint32_t    gen{0};
        int         fd{-1};
        std::string path;
        uint64_t    tail{seg_head};
        uint32_t    live{0};
        uint64_t    live_bytes{0};
        // Reads in flight, which keep it from being used again.
        uint32_t    reading{0};
        bool        sealed{false};
        int64_t     sealed_ms{0};
        // Its messages are being moved out, which the next look at the segments does not start again.
        bool        moving{false};
    };
    // A record waiting for the next commit: a writer's message, or a message moved out of a sparse segment.
    struct queued
    {
        uint64_t    writer{0};
        entry_ptr   moved;
        uint32_t    from_seg{0};
        size_t      at{0};
        size_t      len{0};
        size_t      header_len{0};
    };
    void pump(uint64_t w);
    void go_own(uint64_t w);
    void end(uint64_t w, bool ok);
    void enqueue(queued q, std::string_view header, std::string_view body);
    void commit();
    void committed(bool ok);
    void prepare();
    void release(spool_entry& e);
    void recycle(uint32_t gen);
    void move_out(uint32_t gen);
    void log(std::string line);
    // The log as the messages here say it, and the messages gone whose records a segment still holds.
    std::string log_text() const;
    void compact_log();
    void forget_gone(uint32_t gen);
    // A message's file a read is done with, closed once no read holds it.
    void release_reader(const std::string& id);
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
    hash_pool&  m_pool;
    std::string m_dir;
    bool        m_relaxed{false};
    int         m_log_fd{-1};
    int         m_dir_fd{-1};
    std::string m_log_buf;
    bool        m_log_writing{false};
    // Appended since the log was last written whole, and whether it is being written whole now.
    uint64_t    m_log_grown{0};
    uint64_t    m_log_base{0};
    bool        m_log_compacting{false};
    // Messages gone whose records stay in a segment until it is used again, so a restart does not bring them back.
    std::unordered_map<std::string, uint32_t> m_gone_in_seg;
    std::map<std::string, entry_ptr> m_entries;
    std::unordered_map<uint64_t, std::unique_ptr<writer>> m_writers;
    std::unordered_map<std::string, reader> m_readers;
    uint64_t m_next_writer{1};
    uint64_t m_bytes{0};
    uint64_t m_kept{0};
    uint64_t m_written{0};
    uint64_t m_write_failures{0};
    // The segments by generation, the current one taking records, and those ready or free to be made ready.
    std::map<uint32_t, segment> m_segs;
    uint32_t m_cur{0};
    std::vector<segment> m_spare;
    std::vector<segment> m_free;
    bool     m_preparing{false};
    uint32_t m_next_gen{1};
    uint32_t m_next_file{1};
    // Records waiting, and the batch being written and synced.
    std::string m_batch;
    std::vector<queued> m_waiting;
    std::string m_flying;
    std::vector<queued> m_flying_recs;
    uint32_t m_flying_seg{0};
    uint64_t m_flying_at{0};
    bool     m_committing{false};
    uint64_t m_commits{0};
    uint64_t m_committed{0};
    uint64_t m_moved{0};
    int64_t  m_moved_ms{0};
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
};

// A message id for the spool: the time, a counter and the shard, in hex, sorting by arrival.
std::string new_spool_id(uint32_t shard);

}   // namespace socketley::mail
