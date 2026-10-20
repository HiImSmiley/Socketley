#pragma once
// A durable list of what a shard owes another host, appended by the owner of a key before the change it is about is
// answered and retired once the host has it, which the event notifications and the replication of a runtime's
// buckets each keep one of.
//
// ─── THE FILE ───────────────────────────────────────────────────────────────
//   <dir>/<sub>/outbox.<shard>   records `u32 length | u32 crc32 | payload`, the payload one of
//                                  'E' id bytes          an entry of a change that was made
//                                  'S' change check      a change about to be made, and what tells a start whether it was
//                                  'T' id change bytes   an entry of such a change
//                                  'C' change / 'X' change   the change was made / was not
//                                  'D' id                the entry was delivered
//
// A change's entries are synced beside the change itself and it is answered once both are durable, so an answered
// change's entries survive a crash.
//
// A start keeps the entries of a change with neither 'C' nor 'X' only when the check finds it in the files, so nothing
// is owed for a change that was never made.
//
// A start hands back every entry kept with no delivery record, in the order they were made, and writes the file again
// with only those; once nothing is owed and it has grown past a megabyte, it is started again empty.
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "../loop/event_loop.h"
#include "../loop/file_io.h"

namespace socketley
{

class outbox
{
public:
    // `what` names the outbox in the log, the runtime it is for first.
    outbox(event_loop& loop, file_io& io, std::string what);
    ~outbox();

    outbox(const outbox&)            = delete;
    outbox& operator=(const outbox&) = delete;

    // Whether the change a staged entry's check describes is in the files, asked at start of every change the file does
    // not say the end of.
    using change_made = std::function<bool(std::string_view check)>;
    // Opens <dir>/<sub>/outbox.<shard>, hands `keep` each entry not delivered in the order they were made, and writes
    // the file again with those it kept; blocking, so it runs at start.
    using keeper = std::function<bool(uint64_t id, std::string_view payload)>;
    bool open(const std::string& dir, std::string_view sub, uint32_t shard, const change_made& made, const keeper& keep,
              std::string& err);
    bool is_open() const { return m_fd >= 0; }

    // Queues an entry of a change already made, written with the next batch, and returns its id.
    uint64_t add(std::string_view payload);
    // Writes the entries of a change about to be made, held back until settle(), and starts their sync; returns the
    // change's ticket, never 0, with each entry's id in `ids`.
    uint64_t stage(std::string_view check, const std::vector<std::string>& payloads, std::vector<uint64_t>& ids);
    // Runs `then` once the records of the change `ticket` names are synced.
    void staged(uint64_t ticket, std::function<void()> then);
    // The change was made or not, and `then` runs once that record is synced; a change not made owes nothing.
    void settle(uint64_t ticket, bool made, std::function<void()> then);
    // Queues the delivery record of entry `id`, which a later sync or a stop makes durable.
    void done(uint64_t id);
    // Runs `then` once every entry added so far is synced.
    void sync(std::function<void()> then) { wait_for(m_appended, std::move(then)); }
    // Writes and syncs the delivery records not yet synced, blocking as a stop may, and closes the file.
    void stop();

    // Entries added and not delivered, a staged change's counted until it is settled not made.
    uint64_t owed() const { return m_owed; }

private:
    // An 'E' or 'T' record carries its bytes, a 'T' and an 'S' the change's number first.
    void append_record(char type, uint64_t id, std::string_view payload = {}, uint64_t change = 0);
    // Runs `then`, which may be empty, once the first `at` bytes appended since the file was opened are synced.
    void wait_for(uint64_t at, std::function<void()> then);
    void kick();
    // A write that took the appended bytes up to `upto` ended, synced or not.
    void written(int64_t res, uint64_t upto, bool synced);
    void maybe_rotate();

    event_loop& m_loop;
    file_io&    m_io;
    std::string m_what;
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
    uint64_t    m_next_id{1};
    uint64_t    m_owed{0};
    bool        m_stopped{false};

    // Its directory and file, where the next record goes, and what waits to be written and synced.
    int         m_dir_fd{-1};
    int         m_fd{-1};
    std::string m_name;
    uint64_t    m_off{0};
    std::string m_buf;
    // Bytes appended since the file was opened, which a wait is a count of, and how many of them are synced.
    uint64_t    m_appended{0};
    uint64_t    m_synced{0};
    struct waiter
    {
        uint64_t at;
        std::function<void()> then;
    };
    std::vector<waiter> m_waiters;
    // Each change staged and not yet settled, by ticket: where its records end and how many entries it owes.
    struct staged_change
    {
        uint64_t at{0};
        uint64_t entries{0};
    };
    std::unordered_map<uint64_t, staged_change> m_staged;
    bool        m_writing{false};
    // Delivery records written and not yet synced, which a stop syncs.
    bool        m_unsynced{false};
    bool        m_rotating{false};
    bool        m_write_failed{false};
};

}   // namespace socketley
