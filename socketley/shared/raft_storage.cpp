#include "raft_storage.h"

#include "event_loop.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace socketley::raft::storage
{

// ─── CRC32C ───

namespace {

constexpr std::array<uint32_t, 256> make_crc_table()
{
    std::array<uint32_t, 256> t{};
    for (uint32_t i = 0; i < 256; ++i)
    {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k)
            c = (c & 1) ? (c >> 1) ^ 0x82F63B78u : c >> 1;
        t[i] = c;
    }
    return t;
}

constexpr std::array<uint32_t, 256> crc_table = make_crc_table();

uint32_t crc32c_table(const unsigned char* p, size_t len, uint32_t crc)
{
    crc = ~crc;
    for (size_t i = 0; i < len; ++i)
        crc = crc_table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

#if defined(__x86_64__)
// SSE4.2's crc32 instruction computes this very polynomial eight bytes a step.
__attribute__((target("sse4.2")))
uint32_t crc32c_sse42(const unsigned char* p, size_t len, uint32_t crc)
{
    uint64_t c = static_cast<uint32_t>(~crc);
    while (len >= 8)
    {
        uint64_t v;
        std::memcpy(&v, p, 8);
        c = __builtin_ia32_crc32di(c, v);
        p += 8;
        len -= 8;
    }
    uint32_t c32 = static_cast<uint32_t>(c);
    while (len--)
        c32 = __builtin_ia32_crc32qi(c32, *p++);
    return ~c32;
}
#endif

}   // namespace

uint32_t crc32c(const void* data, size_t len, uint32_t crc)
{
    const auto* p = static_cast<const unsigned char*>(data);
#if defined(__x86_64__)
    static const bool hw = __builtin_cpu_supports("sse4.2");
    if (hw)
        return crc32c_sse42(p, len, crc);
#endif
    return crc32c_table(p, len, crc);
}

// ─── records ───

namespace {

void put_u32(std::string& o, uint32_t v)
{
    for (int b = 0; b < 4; ++b)
        o += static_cast<char>((v >> (8 * b)) & 0xFF);
}

void put_u64(std::string& o, uint64_t v)
{
    for (int b = 0; b < 8; ++b)
        o += static_cast<char>((v >> (8 * b)) & 0xFF);
}

uint32_t get_u32(const char* p)
{
    uint32_t v = 0;
    for (int b = 0; b < 4; ++b)
        v |= static_cast<uint32_t>(static_cast<unsigned char>(p[b])) << (8 * b);
    return v;
}

uint64_t get_u64(const char* p)
{
    uint64_t v = 0;
    for (int b = 0; b < 8; ++b)
        v |= static_cast<uint64_t>(static_cast<unsigned char>(p[b])) << (8 * b);
    return v;
}

// Two record types only a segment's opening image uses: its base snapshot, and the mark that the image is whole.
constexpr uint8_t rec_base = 5;
constexpr uint8_t rec_seal = 6;

void frame(std::string& out, uint8_t type, const std::string& payload)
{
    put_u32(out, static_cast<uint32_t>(payload.size()));
    uint32_t crc = crc32c(&type, 1);
    crc = crc32c(payload.data(), payload.size(), crc);
    put_u32(out, crc);
    out += static_cast<char>(type);
    out += payload;
}

void append_base(std::string& out, index_t index, term_t term)
{
    std::string p;
    put_u64(p, index);
    put_u64(p, term);
    frame(out, rec_base, p);
}

void append_seal(std::string& out)
{
    frame(out, rec_seal, {});
}

struct cursor
{
    std::string_view in;
    size_t off = 0;

    bool u64(uint64_t& v)
    {
        if (in.size() - off < 8)
            return false;
        v = get_u64(in.data() + off);
        off += 8;
        return true;
    }

    bool u32(uint32_t& v)
    {
        if (in.size() - off < 4)
            return false;
        v = get_u32(in.data() + off);
        off += 4;
        return true;
    }

    bool bytes(std::string& s)
    {
        uint32_t n = 0;
        if (!u32(n) || n > in.size() - off)
            return false;
        s.assign(in.substr(off, n));
        off += n;
        return true;
    }

    bool ids(std::vector<node_id>& v)
    {
        uint32_t n = 0;
        if (!u32(n) || static_cast<uint64_t>(n) * 8 > in.size() - off)
            return false;
        v.resize(n);
        for (node_id& id : v)
            if (!u64(id))
                return false;
        return true;
    }

    bool done() const { return off == in.size(); }
};

bool parse_snapshot(std::string_view payload, snapshot& s)
{
    cursor c{payload};
    return c.u64(s.index) && c.u64(s.term) && c.ids(s.voters) && c.ids(s.learners) && c.bytes(s.data) && c.done();
}

// One record at `off`: false when what is there is not a whole record with a matching CRC.
bool next_record(std::string_view bytes, size_t off, uint8_t& type, std::string_view& payload, size_t& next)
{
    if (bytes.size() - off < record_header)
        return false;
    const uint32_t len = get_u32(bytes.data() + off);
    const uint32_t crc = get_u32(bytes.data() + off + 4);
    if (len > max_record || bytes.size() - off - record_header < len)
        return false;
    type = static_cast<uint8_t>(bytes[off + 8]);
    payload = bytes.substr(off + record_header, len);
    uint32_t c = crc32c(&type, 1);
    c = crc32c(payload.data(), payload.size(), c);
    if (c != crc)
        return false;
    next = off + record_header + len;
    return true;
}

index_t last_of(const persisted& st)
{
    return st.log.empty() ? st.snap.index : st.log.back().index;
}

}   // namespace

void append_hard(std::string& out, const hard_state& h)
{
    std::string p;
    put_u64(p, h.term);
    put_u64(p, h.vote);
    frame(out, static_cast<uint8_t>(record::hard), p);
}

void append_entry(std::string& out, const entry& e)
{
    std::string p;
    p.reserve(21 + e.data.size());
    put_u64(p, e.term);
    put_u64(p, e.index);
    p += static_cast<char>(e.type);
    put_u32(p, static_cast<uint32_t>(e.data.size()));
    p += e.data;
    frame(out, static_cast<uint8_t>(record::entry), p);
}

void append_truncate(std::string& out, index_t from)
{
    std::string p;
    put_u64(p, from);
    frame(out, static_cast<uint8_t>(record::truncate), p);
}

void append_snapshot(std::string& out, const snapshot& s)
{
    std::string p;
    put_u64(p, s.index);
    put_u64(p, s.term);
    put_u32(p, static_cast<uint32_t>(s.voters.size()));
    for (node_id v : s.voters)
        put_u64(p, v);
    put_u32(p, static_cast<uint32_t>(s.learners.size()));
    for (node_id l : s.learners)
        put_u64(p, l);
    put_u32(p, static_cast<uint32_t>(s.data.size()));
    p += s.data;
    frame(out, static_cast<uint8_t>(record::snapshot), p);
}

bool decode_snapshot_file(std::string_view bytes, snapshot& out)
{
    uint8_t type = 0;
    std::string_view payload;
    size_t next = 0;
    if (!next_record(bytes, 0, type, payload, next) || next != bytes.size()
        || type != static_cast<uint8_t>(record::snapshot))
        return false;
    return parse_snapshot(payload, out);
}

replay_result replay(std::string_view bytes, persisted& state)
{
    replay_result r;
    size_t off = 0;
    while (off < bytes.size())
    {
        uint8_t type = 0;
        std::string_view payload;
        size_t next = 0;
        if (!next_record(bytes, off, type, payload, next))
        {
            r.stopped = "torn or corrupt record at byte " + std::to_string(off);
            break;
        }

        cursor c{payload};
        bool ok = true;
        switch (type)
        {
        case static_cast<uint8_t>(record::hard):
        {
            hard_state h;
            ok = c.u64(h.term) && c.u64(h.vote) && c.done();
            if (ok)
                state.hard = h;
            break;
        }
        case static_cast<uint8_t>(record::entry):
        {
            entry e;
            uint8_t t = 0;
            ok = c.u64(e.term) && c.u64(e.index);
            if (ok && c.off < payload.size())
                t = static_cast<uint8_t>(payload[c.off++]);
            else
                ok = false;
            ok = ok && t <= static_cast<uint8_t>(entry_type::config) && c.bytes(e.data) && c.done();
            if (!ok)
                break;
            e.type = static_cast<entry_type>(t);
            if (e.index <= state.snap.index)
                break;
            const index_t last = last_of(state);
            if (e.index > last + 1)
            {
                r.stopped = "entry " + std::to_string(e.index) + " leaves a gap after " + std::to_string(last);
                r.valid = off;
                return r;
            }
            if (e.index <= last)
            {
                entry& have = state.log[e.index - state.snap.index - 1];
                // A segment's image re-states entries the log already holds, which must not cut off what follows them.
                if (have.term == e.term)
                    break;
                state.log.resize(e.index - state.snap.index - 1);
            }
            state.log.push_back(std::move(e));
            break;
        }
        case static_cast<uint8_t>(record::truncate):
        {
            index_t from = 0;
            ok = c.u64(from) && c.done();
            if (ok)
                std::erase_if(state.log, [from](const entry& e) { return e.index >= from; });
            break;
        }
        case rec_base:
        case rec_seal:
            break;
        default:
            ok = false;
        }
        if (!ok)
        {
            r.stopped = "unreadable record of type " + std::to_string(type) + " at byte " + std::to_string(off);
            break;
        }
        off = next;
    }
    r.valid = off;
    return r;
}

// ─── files ───

std::string segment_name(uint64_t seq)
{
    char buf[40];
    std::snprintf(buf, sizeof buf, "wal-%016" PRIx64 ".log", seq);
    return buf;
}

std::string snapshot_name(index_t index, term_t term)
{
    char buf[64];
    std::snprintf(buf, sizeof buf, "snap-%016" PRIx64 "-%016" PRIx64, index, term);
    return buf;
}

namespace {

bool parse_segment_name(const std::string& n, uint64_t& seq)
{
    unsigned long long s = 0;
    char tail[8] = {};
    if (n.size() != 4 + 16 + 4 || std::sscanf(n.c_str(), "wal-%16llx%4s", &s, tail) != 2 || std::strcmp(tail, ".log") != 0)
        return false;
    seq = s;
    return true;
}

bool parse_snapshot_name(const std::string& n, index_t& index, term_t& term)
{
    unsigned long long i = 0, t = 0;
    if (n.size() != 5 + 16 + 1 + 16 || std::sscanf(n.c_str(), "snap-%16llx-%16llx", &i, &t) != 2)
        return false;
    index = i;
    term  = t;
    return true;
}

bool read_file(const std::string& path, std::string& out)
{
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    out.clear();
    char buf[65536];
    for (;;)
    {
        const ssize_t n = ::read(fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
        {
            ::close(fd);
            return false;
        }
        if (n == 0)
            break;
        out.append(buf, static_cast<size_t>(n));
    }
    ::close(fd);
    return true;
}

bool write_all(int fd, const std::string& data)
{
    size_t off = 0;
    while (off < data.size())
    {
        const ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

bool fsync_dir(const std::string& dir)
{
    const int fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return false;
    const bool ok = ::fsync(fd) == 0;
    ::close(fd);
    return ok;
}

// Written, fsynced and renamed into place, so a crash leaves the old file or the new one and never half of either.
bool write_durably(const std::string& dir, const std::string& name, const std::string& data, std::string& err)
{
    const std::string tmp = dir + "/" + name + ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
    {
        err = "cannot create " + tmp + ": " + std::strerror(errno);
        return false;
    }
    const bool ok = write_all(fd, data) && ::fsync(fd) == 0;
    ::close(fd);
    if (!ok || ::rename(tmp.c_str(), (dir + "/" + name).c_str()) != 0)
    {
        err = "cannot write " + dir + "/" + name + ": " + std::strerror(errno);
        ::unlink(tmp.c_str());
        return false;
    }
    return true;
}

struct listing
{
    std::vector<uint64_t> segments;
    std::vector<std::pair<index_t, term_t>> snapshots;
    std::vector<std::string> temporaries;
};

bool list_dir(const std::string& dir, listing& out, std::string& err)
{
    DIR* d = ::opendir(dir.c_str());
    if (!d)
    {
        err = "cannot read " + dir + ": " + std::strerror(errno);
        return false;
    }
    while (const dirent* e = ::readdir(d))
    {
        const std::string n = e->d_name;
        uint64_t seq = 0;
        index_t i = 0;
        term_t t = 0;
        if (n.size() > 4 && n.compare(n.size() - 4, 4, ".tmp") == 0)
            out.temporaries.push_back(n);
        else if (parse_segment_name(n, seq))
            out.segments.push_back(seq);
        else if (parse_snapshot_name(n, i, t))
            out.snapshots.emplace_back(i, t);
    }
    ::closedir(d);
    std::sort(out.segments.begin(), out.segments.end());
    return true;
}

bool ensure_dir(const std::string& dir, std::string& err)
{
    if (::mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST)
    {
        err = "cannot create " + dir + ": " + std::strerror(errno);
        return false;
    }
    return true;
}

}   // namespace

bool initialize(const std::string& dir, const persisted& state, std::string& err)
{
    if (!ensure_dir(dir, err))
        return false;

    std::string snap;
    append_snapshot(snap, state.snap);
    if (!write_durably(dir, snapshot_name(state.snap.index, state.snap.term), snap, err))
        return false;

    std::string seg;
    append_base(seg, state.snap.index, state.snap.term);
    append_hard(seg, state.hard);
    for (const entry& e : state.log)
        append_entry(seg, e);
    append_seal(seg);
    if (!write_durably(dir, segment_name(1), seg, err))
        return false;

    if (!fsync_dir(dir))
    {
        err = "cannot fsync " + dir + ": " + std::strerror(errno);
        return false;
    }
    return true;
}

bool recover(const std::string& dir, recovery& out, std::string& err)
{
    out = recovery{};
    if (!ensure_dir(dir, err))
        return false;
    listing ls;
    if (!list_dir(dir, ls, err))
        return false;

    for (const std::string& t : ls.temporaries)
    {
        ::unlink((dir + "/" + t).c_str());
        out.notes.push_back("removed the unfinished " + t);
    }

    if (ls.segments.empty())
    {
        if (!ls.snapshots.empty())
        {
            err = dir + " holds snapshots but no log segment, so its votes and entries are gone";
            return false;
        }
        return true;
    }

    // The newest segment whose opening image is whole decides the state; a newer, unsealed one is a rotation that never finished.
    for (auto it = ls.segments.rbegin(); it != ls.segments.rend(); ++it)
    {
        const std::string path = dir + "/" + segment_name(*it);
        std::string bytes;
        if (!read_file(path, bytes))
        {
            err = "cannot read " + path + ": " + std::strerror(errno);
            return false;
        }

        uint8_t type = 0;
        std::string_view payload;
        size_t next = 0;
        index_t base_index = 0;
        term_t base_term = 0;
        bool sealed = false;
        if (next_record(bytes, 0, type, payload, next) && type == rec_base && payload.size() == 16)
        {
            base_index = get_u64(payload.data());
            base_term  = get_u64(payload.data() + 8);
            for (size_t off = next; next_record(bytes, off, type, payload, next); off = next)
                if (type == rec_seal)
                {
                    sealed = true;
                    break;
                }
        }

        if (!sealed)
        {
            if (it != ls.segments.rbegin())
            {
                err = path + " is not a whole segment though a newer one exists; refusing to guess what was acknowledged";
                return false;
            }
            ::unlink(path.c_str());
            out.notes.push_back("discarded " + segment_name(*it) + ", a rotation that did not finish");
            continue;
        }

        std::string snap_bytes;
        const std::string snap_path = dir + "/" + snapshot_name(base_index, base_term);
        if (!read_file(snap_path, snap_bytes) || !decode_snapshot_file(snap_bytes, out.state.snap)
            || out.state.snap.index != base_index || out.state.snap.term != base_term)
        {
            err = path + " is based on " + snap_path + ", which is missing or corrupt";
            return false;
        }

        const replay_result r = replay(bytes, out.state);
        if (!r.stopped.empty())
        {
            // Nothing past an unsynced record was acknowledged, so the tail after the last whole record is dropped.
            const int fd = ::open(path.c_str(), O_WRONLY | O_CLOEXEC);
            if (fd < 0 || ::ftruncate(fd, static_cast<off_t>(r.valid)) != 0 || ::fsync(fd) != 0)
            {
                if (fd >= 0)
                    ::close(fd);
                err = "cannot truncate the torn tail of " + path + ": " + std::strerror(errno);
                return false;
            }
            ::close(fd);
            out.notes.push_back("truncated " + segment_name(*it) + " at byte " + std::to_string(r.valid) + " of "
                                + std::to_string(bytes.size()) + " (" + r.stopped + ")");
        }
        out.segment     = path;
        out.segment_seq = *it;
        out.segment_len = r.valid;

        // What the chosen segment supersedes is garbage now, and removing it keeps a later recovery from weighing it.
        for (uint64_t seq : ls.segments)
            if (seq < *it)
                ::unlink((dir + "/" + segment_name(seq)).c_str());
        for (const auto& [si, st] : ls.snapshots)
            if (si != base_index || st != base_term)
                ::unlink((dir + "/" + snapshot_name(si, st)).c_str());
        if (!fsync_dir(dir))
        {
            err = "cannot fsync " + dir + ": " + std::strerror(errno);
            return false;
        }
        return true;
    }

    err = dir + " holds no whole log segment";
    return false;
}

// ─── the io_uring writer ───

wal::~wal()
{
    for (int* fd : {&m_fd, &m_dir_fd, &m_tmp_fd, &m_next_fd})
    {
        if (*fd < 0)
            continue;
        if (m_loop)
            m_loop->close_fd(*fd);
        else
            ::close(*fd);
        *fd = -1;
    }
}

bool wal::open(event_loop& loop, const std::string& dir, const recovery& rec, std::string& err)
{
    m_loop = &loop;
    m_dir  = dir;
    m_dir_fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (m_dir_fd < 0)
    {
        err = "cannot open " + dir + ": " + std::strerror(errno);
        return false;
    }
    m_fd = ::open(rec.segment.c_str(), O_WRONLY | O_CLOEXEC);
    if (m_fd < 0)
    {
        err = "cannot open " + rec.segment + ": " + std::strerror(errno);
        return false;
    }
    m_seq = rec.segment_seq;
    m_off = rec.segment_len;
    m_owner_token = loop.register_owner(this);
    return true;
}

io_request* wal::chain_req(uint8_t kind)
{
    io_request* r = &m_reqs[m_used++];
    *r = io_request{};
    r->owner = this;
    r->type  = static_cast<op_type>(kind);
    return r;
}

bool wal::persist(const ready& r, const node& n, done_fn done)
{
    if (m_failed || busy() || !m_loop)
        return false;

    m_used     = 0;
    m_chain_ok = true;
    m_chain_err.clear();
    m_new_snap = 0;
    m_rotating = false;
    m_buf.clear();

    if (!r.snap)
    {
        if (r.hard)
            append_hard(m_buf, *r.hard);
        if (r.truncate_from)
            append_truncate(m_buf, r.truncate_from);
        for (const entry& e : r.append)
            append_entry(m_buf, e);
        if (m_buf.empty())
            return false;
        // Refusing here, rather than writing nothing, is what keeps the caller from sending what was never made durable.
        if (!m_loop->reserve_sqes(2))
        {
            m_failed = true;
            m_error  = "the ring has no room for a WAL write";
            return false;
        }
        m_loop->submit_file_write(m_fd, m_buf.data(), static_cast<uint32_t>(m_buf.size()), m_off,
                                  chain_req(op_file_write), true);
        m_loop->submit_fsync(m_fd, true, chain_req(op_fsync), false);
        m_inflight = 2;
        m_done     = std::move(done);
        m_bytes   += m_buf.size();
        return true;
    }

    // A snapshot starts a new segment: snapshot file, then the node's whole log behind a base record, then the directory.
    const snapshot& s = *r.snap;
    m_snap_buf.clear();
    append_snapshot(m_snap_buf, s);
    m_snap_path = m_dir + "/" + snapshot_name(s.index, s.term);
    m_tmp_path  = m_snap_path + ".tmp";
    m_next_seq  = m_seq + 1;

    append_base(m_buf, s.index, s.term);
    append_hard(m_buf, hard_state{n.term(), n.vote()});
    for (index_t i = n.first_index(); i <= n.last_index(); ++i)
        append_entry(m_buf, *n.entry_at(i));
    append_seal(m_buf);
    m_next_len = m_buf.size();

    // Creating the two files is the one synchronous step: open(O_CREAT) touches only the cached directory.
    m_tmp_fd = ::open(m_tmp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    const std::string next_path = m_dir + "/" + segment_name(m_next_seq);
    m_next_fd = ::open(next_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (m_tmp_fd < 0 || m_next_fd < 0 || !m_loop->reserve_sqes(6))
    {
        m_failed = true;
        m_error  = "cannot start a WAL segment in " + m_dir + ": " + std::strerror(errno);
        return false;
    }

    m_loop->submit_file_write(m_tmp_fd, m_snap_buf.data(), static_cast<uint32_t>(m_snap_buf.size()), 0,
                              chain_req(op_file_write), true);
    m_loop->submit_fsync(m_tmp_fd, false, chain_req(op_fsync), true);
    m_loop->submit_renameat(m_dir_fd, m_tmp_path.c_str(), m_dir_fd, m_snap_path.c_str(), chain_req(op_rename), true);
    m_loop->submit_file_write(m_next_fd, m_buf.data(), static_cast<uint32_t>(m_buf.size()), 0,
                              chain_req(op_file_write), true);
    m_loop->submit_fsync(m_next_fd, false, chain_req(op_fsync), true);
    m_loop->submit_fsync(m_dir_fd, false, chain_req(op_fsync), false);
    m_inflight = 6;
    m_new_snap = s.index;
    m_rotating = true;
    m_done     = std::move(done);
    m_bytes   += m_snap_buf.size() + m_buf.size();
    return true;
}

void wal::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));

    for (auto it = m_unlinks.begin(); it != m_unlinks.end(); ++it)
        if (&(*it)->req == req)
        {
            m_unlinks.erase(it);
            return;
        }

    if (m_inflight == 0)
        return;
    --m_inflight;

    const size_t k = static_cast<size_t>(req - m_reqs);
    if (cqe->res < 0)
    {
        if (m_chain_ok)
            m_chain_err = std::string(io_op_name(req->type)) + " failed: " + std::strerror(-cqe->res);
        m_chain_ok = false;
    }
    else if (req->type == op_file_write)
    {
        const std::string& b = (m_rotating && k == 0) ? m_snap_buf : m_buf;
        if (static_cast<size_t>(cqe->res) != b.size())
        {
            m_chain_ok  = false;
            m_chain_err = "short write of " + std::to_string(cqe->res) + " of " + std::to_string(b.size()) + " bytes";
        }
    }
    else if (req->type == op_fsync)
    {
        ++m_fsyncs;
    }

    if (m_inflight == 0)
        finish();
}

void wal::finish()
{
    if (m_rotating)
    {
        if (m_tmp_fd >= 0)
            m_loop->close_fd(m_tmp_fd);
        m_tmp_fd = -1;
        if (m_chain_ok)
        {
            m_loop->close_fd(m_fd);
            m_fd      = m_next_fd;
            m_next_fd = -1;
            m_seq     = m_next_seq;
            m_off     = m_next_len;
        }
        else if (m_next_fd >= 0)
        {
            m_loop->close_fd(m_next_fd);
            m_next_fd = -1;
        }
    }
    else if (m_chain_ok)
    {
        m_off += m_buf.size();
    }

    if (!m_chain_ok)
    {
        m_failed = true;
        m_error  = "WAL write in " + m_dir + " failed (" + m_chain_err + ")";
    }
    else if (m_rotating)
    {
        sweep_old(m_seq, m_new_snap);
    }

    done_fn done = std::move(m_done);
    m_done = nullptr;
    if (done)
        done(m_chain_ok);
}

void wal::sweep_old(uint64_t keep_seq, index_t keep_snap)
{
    listing ls;
    std::string err;
    if (!list_dir(m_dir, ls, err))
        return;
    std::vector<std::string> doomed;
    for (uint64_t seq : ls.segments)
        if (seq < keep_seq)
            doomed.push_back(segment_name(seq));
    for (const auto& [i, t] : ls.snapshots)
        if (i != keep_snap)
            doomed.push_back(snapshot_name(i, t));
    for (std::string& name : doomed)
    {
        auto op = std::make_unique<unlink_op>();
        op->path      = std::move(name);
        op->req.owner = this;
        op->req.type  = op_unlink;
        if (m_loop->submit_unlinkat(m_dir_fd, op->path.c_str(), &op->req))
            m_unlinks.push_back(std::move(op));
    }
}

uint32_t wal::retire()
{
    if (!m_loop)
        return 0;
    const uint32_t tok = m_owner_token;
    m_owner_token = 0;
    m_loop->deregister_owner(this);
    return tok;
}

}   // namespace socketley::raft::storage
