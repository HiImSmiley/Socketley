#pragma once
// The db runtime's files: numbered segments of records, appended to the newest and never changed once a newer one
// begins, so a document's bytes stay where they were written until a merge copies the living ones elsewhere and the
// old segments go.
//
// A segment is a header and records, each `u32 length | u32 crc32 | payload`: the CRC tells a record torn by a crash
// from a whole one, and a torn tail of the newest segment is cut at the start, as is the room of zeros it was given
// ahead of its records. Damage anywhere else refuses the start.
#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace socketley::db
{

// Where a document's JSON lies: a segment, the offset of its first byte, its length; segment 0 is nowhere.
struct location
{
    uint32_t seg{0};
    uint64_t off{0};
    uint32_t len{0};
};

class seglog
{
public:
    static constexpr char     magic[8]       = {'S', 'K', 'L', 'D', 'B', 'S', 'G', '1'};
    static constexpr size_t   header_bytes   = 16;
    static constexpr size_t   record_head    = 8;
    static constexpr size_t   max_record     = 64u << 20;
    // Past this the newest segment is closed and another begun.
    static constexpr uint64_t segment_bytes  = 64ull << 20;
    // The room of zeros made ahead of the newest segment's records, this much at a time.
    static constexpr uint64_t room_bytes     = 4ull << 20;

    using visitor = std::function<bool(uint32_t seg, uint64_t payload_off, std::string_view payload)>;

    seglog() = default;
    seglog(const seglog&) = delete;
    seglog& operator=(const seglog&) = delete;
    ~seglog() { close(); }

    // The segments under `dir`, every whole record handed to `each` in segment order, then the newest opened to append
    // to, or a first one made; false with `why` when a segment does not read or `each` refuses a record.
    bool open(const std::string& dir, const visitor& each, std::string& why);
    void close();

    // A record appended to what the newest segment will hold; the offset of its payload's first byte in that segment.
    location append(std::string_view payload);
    // What was appended written to the file, and synced to the disk.
    bool flush();
    bool sync();
    // The newest segment's descriptor, for a sync made elsewhere after flush().
    int fd() const { return m_fd; }
    // The bytes at `at`, from the file or from what is not yet written to it.
    bool read(const location& at, std::string& out);

    // A new newest segment when this one is past segment_bytes, its own records written first.
    bool roll_if_full(std::string& why);
    // True while the segment before the newest is sealed off the loop, when no sync of the newest may be told.
    bool sealing();
    uint32_t active() const { return m_active; }
    // Every segment but the newest, oldest first.
    std::vector<uint32_t> sealed() const;
    uint64_t size_of(uint32_t seg) const;
    uint64_t total_bytes() const;
    // A segment's number for a file a merge or a restore writes, never one in use.
    uint32_t reserve() { return ++m_highest; }
    std::string path_of(uint32_t seg) const;
    // A segment written whole elsewhere, at path_of(seg), taken in.
    bool adopt(uint32_t seg, std::string& why);
    void remove(uint32_t seg);
    // Every segment deleted and a first one begun, as a replica does when it takes another copy whole.
    bool clear(std::string& why);
    const std::string& dir() const { return m_dir; }

    // How many times the set of segments changed: one begun, adopted, removed, or all of them cleared.
    uint64_t layout() const { return m_layout; }

    // ── Reading another process's log ───────────────────────────────────────
    // The segments under `dir` opened to read and kept open, so a document in one the writer removes is still read
    // where it was found; nothing is ever written, cut or removed.
    bool follow_open(const std::string& dir, std::string& why);
    // The segment numbers in the directory now.
    std::vector<uint32_t> listed() const;
    // The whole records of `seg` from `off` on, each told to `each` until it says stop: the offset after the last one
    // taken. A record cut short, a room of zeros or the end of the file ends the reading.
    uint64_t read_records(uint32_t seg, uint64_t off,
                          const std::function<bool(uint64_t payload_off, std::string_view payload)>& each);
    // A segment let go, once no document lies in it and the writer removed it.
    void forget(uint32_t seg);

    // Records into a new segment file at `path`, written beside it and renamed into place once on the disk: the
    // payload offsets of each are in `offs`. Run off the loop, by a merge or a backup.
    static bool write_file(const std::string& path, const std::vector<std::string>& payloads, std::vector<uint64_t>& offs,
                           std::string& why);
    // A file of records as `open` reads one, for a backup being restored; false with `why` when it is not one.
    static bool scan_file(const std::string& path, const visitor& each, bool cut_torn_tail, std::string& why);

private:
    int fd_of(uint32_t seg);
    bool begin(uint32_t seg, std::string& why);
    // Room asked for once the records near the end of what is made, and a finished or a needed one waited for.
    void plan_room();
    void end_room();

    std::string m_dir;
    uint64_t m_layout{0};
    bool m_follow{false};
    // Every segment by number, with its size and a descriptor opened when first read.
    struct seg_info
    {
        uint64_t size{0};
        int fd{-1};
    };
    std::map<uint32_t, seg_info> m_segs;
    uint32_t m_active{0};
    uint32_t m_highest{0};
    int m_fd{-1};
    // The newest segment's bytes from m_written on, appended and not yet written.
    std::string m_pending;
    uint64_t m_written{0};
    // Zeros written and synced past the records off the loop, so a sync of records into them changes nothing else of
    // the file, which on ext4 is a journal commit a sync saved.
    struct room_job
    {
        uint64_t from{0};
        uint64_t to{0};
        int fd{-1};
        // Records below `zeroed` go on while the rest is written, since no zero is written there again.
        std::atomic<uint64_t> zeroed{0};
        std::atomic<bool> stop{false};
        bool ok{false};
        bool failed{false};
        std::atomic<bool> done{false};
        std::thread th;
    };
    std::unique_ptr<room_job> m_room;
    // The next segment's file made and synced off the loop as the newest nears its size, under a name a start deletes.
    struct next_job
    {
        int fd{-1};
        bool ok{false};
        std::atomic<bool> done{false};
        std::thread th;
    };
    std::unique_ptr<next_job> m_next;
    // A full segment sealed off the loop: its room ended, its records synced and its end cut, then the next one renamed
    // into place and the directory synced.
    struct seal_job
    {
        uint32_t seg{0};
        uint64_t end{0};
        int fd{-1};
        std::unique_ptr<room_job> room;
        std::string from, to, dir;
        bool ok{false};
        std::atomic<bool> done{false};
        std::thread th;
    };
    std::unique_ptr<seal_job> m_seal;
    void start_next();
    void end_next();
    void end_seal();
    // The old way, every step on the loop, when no next segment could be made ahead.
    bool roll_here(std::string& why);
    // A room that could not be made is not asked for again in this segment: its records are appended as they come.
    bool m_room_failed{false};
    // Below this the newest segment's file is records, or zeros on the disk.
    uint64_t m_alloc{0};
    bool m_failed{false};
};

}   // namespace socketley::db
