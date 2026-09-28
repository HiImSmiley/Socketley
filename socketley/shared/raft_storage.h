#pragma once
// Raft's durable state on disk: an append-only WAL of CRC32C-checked records plus snapshot files, written through io_uring.
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "event_loop_definitions.h"
#include "raft.h"

class event_loop;

namespace socketley::raft::storage
{

uint32_t crc32c(const void* data, size_t len, uint32_t crc = 0);

enum class record : uint8_t { hard = 1, entry = 2, truncate = 3, snapshot = 4 };

// Every record is u32 payload length, u32 CRC32C over the type byte and payload, the type byte, the payload.
inline constexpr size_t record_header = 9;

// A record bigger than this is a corrupt length, since no entry the host proposes comes near it.
inline constexpr uint32_t max_record = 64u * 1024u * 1024u;

void append_hard(std::string& out, const hard_state& h);
void append_entry(std::string& out, const entry& e);
void append_truncate(std::string& out, index_t from);
void append_snapshot(std::string& out, const snapshot& s);

struct replay_result
{
    // Bytes of whole, valid records, where a torn or corrupt tail begins.
    size_t valid = 0;
    // Why replay stopped before the end, empty when it did not.
    std::string stopped;
};

// Applies the records in `bytes` to `state` in order, entries at or below the snapshot ignored.
replay_result replay(std::string_view bytes, persisted& state);

// A snapshot file's content, false when it is torn, corrupt or not one.
bool decode_snapshot_file(std::string_view bytes, snapshot& out);

struct recovery
{
    persisted state;
    // The segment appends continue in, with its valid length and sequence number.
    std::string segment;
    uint64_t    segment_seq = 0;
    uint64_t    segment_len = 0;
    // What recovery threw away, one line each, for the log.
    std::vector<std::string> notes;
};

// Reads `dir` back into a node's persisted state, truncating a torn tail on disk; false with `err` when data a peer may have been told about is unreadable.
bool recover(const std::string& dir, recovery& out, std::string& err);

// Makes `dir` hold a fresh state, with the files fsynced before it returns; used once, before any node exists.
bool initialize(const std::string& dir, const persisted& state, std::string& err);

// The durable half of a ready, written and fsynced through io_uring with the loop never waiting on the disk.
class wal : public io_handler
{
public:
    using done_fn = std::function<void(bool ok)>;

    wal() = default;
    ~wal() override;
    wal(const wal&) = delete;
    wal& operator=(const wal&) = delete;

    // Opens the segment recovery ended in, before the first persist().
    bool open(event_loop& loop, const std::string& dir, const recovery& rec, std::string& err);

    // Writes hard state, snapshot, truncation and entries of `r`, and calls `done` once all of it is fsynced; one at a time.
    // A snapshot starts a new segment holding `n`'s whole log, after which the older segments and snapshots are deleted.
    bool persist(const ready& r, const node& n, done_fn done);

    bool busy() const { return m_inflight > 0 || m_done != nullptr; }
    // Set once a write or fsync failed; nothing more is written after that.
    bool failed() const { return m_failed; }
    const std::string& error() const { return m_error; }

    // Deregisters from the loop and returns the token to wait on before freeing, as cluster_discovery::retire() does.
    uint32_t retire();

    void on_cqe(struct io_uring_cqe* cqe) override;

    // Counters for status output.
    uint64_t fsyncs() const { return m_fsyncs; }
    uint64_t bytes_written() const { return m_bytes; }

private:
    // A deletion in flight, whose path must live until the kernel reports.
    struct unlink_op
    {
        io_request  req{};
        std::string path;
    };

    io_request* chain_req(uint8_t kind);
    void finish();
    void sweep_old(uint64_t keep_seq, index_t keep_snap);

    event_loop* m_loop = nullptr;
    std::string m_dir;
    int         m_dir_fd = -1;
    int         m_fd     = -1;
    uint64_t    m_seq    = 0;
    uint64_t    m_off    = 0;

    // The chain in flight, whose buffers and requests outlive the kernel's use of them.
    std::string m_buf;
    std::string m_snap_buf;
    std::string m_tmp_path, m_snap_path;
    int         m_tmp_fd   = -1;
    int         m_next_fd  = -1;
    uint64_t    m_next_seq = 0;
    uint64_t    m_next_len = 0;
    index_t     m_new_snap = 0;
    bool        m_rotating = false;
    io_request  m_reqs[8]{};
    size_t      m_used = 0;
    uint32_t    m_inflight = 0;
    bool        m_chain_ok = true;
    std::string m_chain_err;
    done_fn     m_done;

    std::vector<std::unique_ptr<unlink_op>> m_unlinks;

    bool        m_failed = false;
    std::string m_error;
    uint32_t    m_owner_token = 0;
    uint64_t    m_fsyncs = 0;
    uint64_t    m_bytes  = 0;
};

std::string segment_name(uint64_t seq);
std::string snapshot_name(index_t index, term_t term);

}   // namespace socketley::raft::storage
