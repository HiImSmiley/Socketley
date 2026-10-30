#include "metrics_block.h"

#include <algorithm>
#include <atomic>
#include <bit>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <unordered_map>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../shared/loop/blocking_write.h"
#include "../../shared/util/byte_codec.h"
#include "../../shared/util/crc.h"
#include "metrics_chunk.h"

namespace socketley::metrics
{

namespace
{

constexpr char block_magic[8] = {'S', 'K', 'L', 'M', 'B', 'L', 'K', '1'};
constexpr size_t sections = 4;
constexpr size_t footer_bytes = 8 + 4 + 3 * 8 + sections * 20 + 4;
constexpr char log_magic[8] = {'S', 'K', 'L', 'M', 'H', 'L', 'G', '1'};

enum : uint8_t
{
    rec_series = 1,
    rec_chunk = 2,
    rec_samples = 3,
};

using bytes::append32;
using bytes::append64;
using bytes::load32;
using bytes::load64;

void put_uvarint(std::string& out, uint64_t v)
{
    while (v >= 0x80)
    {
        out += static_cast<char>(static_cast<uint8_t>(v) | 0x80);
        v >>= 7;
    }
    out += static_cast<char>(v);
}

bool get_uvarint(std::span<const uint8_t> in, size_t& pos, uint64_t& v)
{
    v = 0;
    for (unsigned shift = 0; shift < 64; shift += 7)
    {
        if (pos >= in.size())
            return false;
        const uint8_t b = in[pos++];
        v |= uint64_t(b & 0x7f) << shift;
        if (!(b & 0x80))
            return true;
    }
    return false;
}

// A record's length and crc32c written over the 8 bytes begin_record() kept for them.
size_t begin_record(std::string& buf)
{
    const size_t at = buf.size();
    buf.append(8, '\0');
    return at;
}

void end_record(std::string& buf, size_t at)
{
    const size_t len = buf.size() - at - 8;
    bytes::store32(buf.data() + at, static_cast<uint32_t>(len));
    bytes::store32(buf.data() + at + 4, crc::crc32c(buf.data() + at + 8, len));
}

std::string dir_of(const std::string& path)
{
    const size_t slash = path.rfind('/');
    return slash == std::string::npos ? std::string(".") : path.substr(0, slash ? slash : 1);
}

bool sync_dir(const std::string& dir)
{
    const int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0)
        return false;
    const bool ok = ::fsync(dfd) == 0;
    ::close(dfd);
    return ok;
}

}   // namespace

std::string block_name(int64_t step, int64_t mint, int64_t maxt)
{
    return (step == 0 ? std::string("raw") : "s" + std::to_string(step)) + "_" + std::to_string(mint) + "_" +
           std::to_string(maxt) + ".blk";
}

bool parse_block_name(std::string_view name, int64_t& step, int64_t& mint, int64_t& maxt)
{
    if (!name.ends_with(".blk"))
        return false;
    name.remove_suffix(4);
    const size_t a = name.find('_');
    const size_t b = a == std::string_view::npos ? a : name.find('_', a + 1);
    if (b == std::string_view::npos)
        return false;
    const std::string_view kind = name.substr(0, a), lo = name.substr(a + 1, b - a - 1), hi = name.substr(b + 1);
    const auto num = [](std::string_view s, int64_t& v) {
        const auto r = std::from_chars(s.data(), s.data() + s.size(), v);
        return !s.empty() && r.ec == std::errc{} && r.ptr == s.data() + s.size();
    };
    if (kind == "raw")
        step = 0;
    else if (!kind.starts_with('s') || !num(kind.substr(1), step) || step <= 0)
        return false;
    return num(lo, mint) && num(hi, maxt) && mint < maxt;
}

// ── block ─────────────────────────────────────────────────────────────────

block::~block()
{
    if (m_map)
        ::munmap(const_cast<uint8_t*>(m_map), m_size);
}

std::shared_ptr<block> block::open(const std::string& path, std::string& why)
{
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return why = path + ": " + std::strerror(errno), nullptr;
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
    {
        ::close(fd);
        return why = path + ": not a regular file", nullptr;
    }
    const auto size = static_cast<uint64_t>(st.st_size);
    if (size < footer_bytes)
    {
        ::close(fd);
        return why = path + ": shorter than a footer", nullptr;
    }
    void* map = ::mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
    ::close(fd);
    if (map == MAP_FAILED)
        return why = path + ": mmap failed: " + std::strerror(errno), nullptr;

    std::shared_ptr<block> b(new block());
    b->m_path = path;
    b->m_map = static_cast<const uint8_t*>(map);
    b->m_size = size;
    const uint8_t* const m = b->m_map;
    const auto refuse = [&](const char* what) {
        why = path + ": " + what;
        return nullptr;
    };

    const uint8_t* f = m + size - footer_bytes;
    if (std::memcmp(f, block_magic, 8) != 0)
        return refuse("no block footer");
    if (load32(f + footer_bytes - 4) != crc::crc32c(f, footer_bytes - 4))
        return refuse("the footer's crc32c does not match");
    if (load32(f + 8) != block_version)
        return refuse("an unknown block version");
    b->m_step = static_cast<int64_t>(load64(f + 12));
    b->m_mint = static_cast<int64_t>(load64(f + 20));
    b->m_maxt = static_cast<int64_t>(load64(f + 28));
    if (b->m_step < 0 || b->m_step > max_abs_time || b->m_mint >= b->m_maxt || b->m_mint < -max_abs_time ||
        b->m_maxt > max_abs_time)
        return refuse("a footer with an impossible window");
    uint64_t off[sections], len[sections];
    uint64_t expect = 0;
    const uint64_t body = size - footer_bytes;
    for (size_t i = 0; i < sections; ++i)
    {
        const uint8_t* s = f + 36 + 20 * i;
        off[i] = load64(s);
        len[i] = load64(s + 8);
        if (off[i] != expect || len[i] > body - off[i])
            return refuse("sections that do not tile the file");
        if (crc::crc32c(m + off[i], len[i]) != load32(s + 16))
            return refuse(i == 0 ? "the chunks' crc32c does not match"
                          : i == 1 ? "the symbols' crc32c does not match"
                          : i == 2 ? "the series' crc32c does not match"
                                   : "the postings' crc32c does not match");
        expect = off[i] + len[i];
    }
    if (expect != body)
        return refuse("sections that do not tile the file");

    // An offset table of n+1 ascending u32s into a region the table is followed by, ending exactly at its end.
    const auto table = [&](uint64_t soff, uint64_t slen, uint32_t& n, const uint8_t*& tab, const uint8_t*& data) {
        if (slen < 4)
            return false;
        n = load32(m + soff);
        if ((slen - 4) / 4 < uint64_t(n) + 1)
            return false;
        tab = m + soff + 4;
        data = tab + 4 * (uint64_t(n) + 1);
        const uint64_t dlen = slen - 4 - 4 * (uint64_t(n) + 1);
        uint32_t prev = 0;
        for (uint64_t i = 0; i <= n; ++i)
        {
            const uint32_t o = load32(tab + 4 * i);
            if ((i == 0 && o != 0) || o < prev)
                return false;
            prev = o;
        }
        return prev == dlen;
    };
    const uint8_t* sym_data = nullptr;
    if (!table(off[1], len[1], b->m_nsyms, b->m_sym_off, sym_data))
        return refuse("a symbol table that does not add up");
    b->m_sym_bytes = sym_data;
    if (!table(off[2], len[2], b->m_nseries, b->m_series_off, b->m_series))
        return refuse("a series table that does not add up");

    for (uint32_t i = 0; i < b->m_nseries; ++i)
    {
        const uint32_t eo = load32(b->m_series_off + 4 * uint64_t(i));
        const uint64_t elen = load32(b->m_series_off + 4 * (uint64_t(i) + 1)) - eo;
        const uint8_t* e = b->m_series + eo;
        if (elen < 4)
            return refuse("a series entry cut short");
        const uint64_t nl = load32(e);
        if (elen < 4 + 8 * nl + 28)
            return refuse("a series entry cut short");
        std::string_view prev_name;
        for (uint64_t l = 0; l < nl; ++l)
        {
            const uint32_t ns = load32(e + 4 + 8 * l), vs = load32(e + 8 + 8 * l);
            if (ns >= b->m_nsyms || vs >= b->m_nsyms)
                return refuse("a label naming a symbol the block lacks");
            const std::string_view name = b->symbol(ns);
            if ((l > 0 && !(prev_name < name)) || b->symbol(vs).empty())
                return refuse("a label set out of order");
            prev_name = name;
        }
        const uint8_t* r = e + 4 + 8 * nl;
        const auto smin = static_cast<int64_t>(load64(r)), smax = static_cast<int64_t>(load64(r + 8));
        uint64_t coff = load64(r + 16);
        const uint64_t nc = load32(r + 24);
        if (nc == 0 || elen != 4 + 8 * nl + 28 + 20 * nc)
            return refuse("a series entry whose chunks do not add up");
        int64_t last = 0;
        for (uint64_t c = 0; c < nc; ++c)
        {
            const uint8_t* cm = r + 28 + 20 * c;
            const auto cmin = static_cast<int64_t>(load64(cm)), cmax = static_cast<int64_t>(load64(cm + 8));
            const uint32_t clen = load32(cm + 16);
            if (cmin > cmax || (c > 0 && cmin <= last) || coff > len[0] || clen > len[0] - coff)
                return refuse("a chunk out of order or outside the chunks");
            const bool inside = cmin > b->m_mint && cmax <= b->m_maxt;
            if (!inside)
                return refuse("a chunk outside the block's window");
            if (c == 0 && cmin != smin)
                return refuse("a series whose range is not its chunks'");
            last = cmax;
            coff += clen;
        }
        if (last != smax)
            return refuse("a series whose range is not its chunks'");
    }

    b->m_postings = m + off[3];
    b->m_postings_len = len[3];
    if (len[3] < 4)
        return refuse("postings cut short");
    const uint32_t np = load32(b->m_postings);
    uint64_t p = 4;
    for (uint32_t i = 0; i < np; ++i)
    {
        if (len[3] - p < 12)
            return refuse("postings cut short");
        const uint32_t ns = load32(b->m_postings + p), vs = load32(b->m_postings + p + 4);
        const uint64_t cnt = load32(b->m_postings + p + 8);
        p += 12;
        if (ns >= b->m_nsyms || vs >= b->m_nsyms || (len[3] - p) / 4 < cnt)
            return refuse("postings cut short");
        for (uint64_t k = 0; k < cnt; ++k)
            if (load32(b->m_postings + p + 4 * k) >= b->m_nseries)
                return refuse("a posting naming a series the block lacks");
        p += 4 * cnt;
    }
    if (p != len[3])
        return refuse("postings with bytes behind them");

    // Checked, the pages go back to the page cache until a query reads them.
    ::madvise(map, size, MADV_DONTNEED);
    return b;
}

std::string_view block::symbol(uint32_t s) const
{
    const uint32_t a = load32(m_sym_off + 4 * uint64_t(s)), e = load32(m_sym_off + 4 * (uint64_t(s) + 1));
    return std::string_view(reinterpret_cast<const char*>(m_sym_bytes) + a, e - a);
}

void block::labels(uint32_t local, label_set& out) const
{
    out.clear();
    const uint8_t* e = entry(local);
    const uint32_t nl = load32(e);
    out.reserve(nl);
    for (uint32_t l = 0; l < nl; ++l)
        out.push_back(label{std::string(symbol(load32(e + 4 + 8 * size_t(l)))),
                            std::string(symbol(load32(e + 8 + 8 * size_t(l))))});
}

void block::range(uint32_t local, int64_t& mint, int64_t& maxt) const
{
    const uint8_t* e = entry(local);
    const uint8_t* r = e + 4 + 8 * size_t(load32(e));
    mint = static_cast<int64_t>(load64(r));
    maxt = static_cast<int64_t>(load64(r + 8));
}

void block::postings(std::vector<std::pair<label, uint32_t>>& out) const
{
    out.clear();
    const uint32_t np = load32(m_postings);
    uint64_t p = 4;
    for (uint32_t i = 0; i < np; ++i)
    {
        const uint32_t cnt = load32(m_postings + p + 8);
        out.push_back({label{std::string(symbol(load32(m_postings + p))), std::string(symbol(load32(m_postings + p + 4)))},
                       cnt});
        p += 12 + 4 * uint64_t(cnt);
    }
}

void block::set_globals(std::span<const uint32_t> global_of_local)
{
    std::vector<std::pair<uint32_t, uint32_t>> v;
    v.reserve(global_of_local.size());
    for (uint32_t i = 0; i < global_of_local.size(); ++i)
        v.push_back({global_of_local[i], i});
    std::sort(v.begin(), v.end());
    m_globals.clear();
    m_locals.clear();
    m_globals.reserve(v.size());
    m_locals.reserve(v.size());
    for (const auto& [g, l] : v)
    {
        m_globals.push_back(g);
        m_locals.push_back(l);
    }
}

uint32_t block::local_of(uint32_t global) const
{
    const auto it = std::lower_bound(m_globals.begin(), m_globals.end(), global);
    if (it == m_globals.end() || *it != global)
        return 0xFFFFFFFFu;
    return m_locals[static_cast<size_t>(it - m_globals.begin())];
}

// ── block_writer ──────────────────────────────────────────────────────────

struct block_writer::impl
{
    std::string dir;
    int64_t step, mint, maxt;
    std::string tmp;
    int fd{-1};
    std::string buf;
    uint64_t data_bytes{0};
    uint32_t data_crc{0};
    bool failed{false};
    int err{0};

    std::unordered_map<std::string, uint32_t> syms;
    std::vector<const std::string*> sym_list;

    bool pending{false};
    std::vector<uint32_t> pairs;
    uint32_t global{0};
    std::string metas;
    uint32_t nchunks{0};
    int64_t smin{0}, smax{0};
    uint64_t first_off{0};

    std::string series;
    std::vector<uint32_t> series_off{0};
    std::unordered_map<uint64_t, std::vector<uint32_t>> postings;

    uint32_t intern(const std::string& s)
    {
        const auto [it, made] = syms.try_emplace(s, static_cast<uint32_t>(sym_list.size()));
        if (made)
            sym_list.push_back(&it->first);
        return it->second;
    }

    void flush()
    {
        if (!failed && !buf.empty() && !write_all(fd, buf.data(), buf.size()))
        {
            failed = true;
            err = errno;
        }
        buf.clear();
    }

    void put(const void* p, size_t n)
    {
        buf.append(static_cast<const char*>(p), n);
        if (buf.size() >= (1u << 20))
            flush();
    }

    void commit(std::vector<uint32_t>& globals)
    {
        if (!pending)
            return;
        pending = false;
        if (nchunks == 0)
            return;
        const auto local = static_cast<uint32_t>(globals.size());
        globals.push_back(global);
        append32(series, static_cast<uint32_t>(pairs.size() / 2));
        for (size_t i = 0; i < pairs.size(); i += 2)
        {
            append32(series, pairs[i]);
            append32(series, pairs[i + 1]);
            postings[(uint64_t(pairs[i]) << 32) | pairs[i + 1]].push_back(local);
        }
        append64(series, static_cast<uint64_t>(smin));
        append64(series, static_cast<uint64_t>(smax));
        append64(series, first_off);
        append32(series, nchunks);
        series += metas;
        series_off.push_back(static_cast<uint32_t>(series.size()));
    }
};

block_writer::block_writer(std::string dir, int64_t step, int64_t mint, int64_t maxt) : m(std::make_unique<impl>())
{
    m->dir = std::move(dir);
    m->step = step;
    m->mint = mint;
    m->maxt = maxt;
    m_path = m->dir + "/" + block_name(step, mint, maxt);
}

block_writer::~block_writer()
{
    if (m->fd >= 0)
    {
        ::close(m->fd);
        ::unlink(m->tmp.c_str());
    }
}

bool block_writer::begin(std::string& why)
{
    static std::atomic<uint64_t> next{0};
    m->tmp = m_path + "." + std::to_string(::getpid()) + "." + std::to_string(next.fetch_add(1)) + ".tmp";
    m->fd = ::open(m->tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (m->fd < 0)
        return why = "cannot create " + m->tmp + ": " + std::strerror(errno), false;
    m->buf.reserve(1u << 20);
    return true;
}


void block_writer::add_series(const label_set& ls, uint32_t global)
{
    m->commit(m_globals);
    m->pending = true;
    m->pairs.clear();
    for (const label& l : ls)
    {
        m->pairs.push_back(m->intern(l.name));
        m->pairs.push_back(m->intern(l.value));
    }
    m->global = global;
    m->metas.clear();
    m->nchunks = 0;
    m->first_off = m->data_bytes;
}

void block_writer::add_chunk(int64_t mint, int64_t maxt, std::span<const uint8_t> bytes)
{
    if (!m->pending || bytes.empty())
        return;
    if (m->nchunks == 0)
        m->smin = mint;
    m->smax = maxt;
    ++m->nchunks;
    append64(m->metas, static_cast<uint64_t>(mint));
    append64(m->metas, static_cast<uint64_t>(maxt));
    append32(m->metas, static_cast<uint32_t>(bytes.size()));
    m->data_crc = crc::crc32c(bytes.data(), bytes.size(), m->data_crc);
    m->data_bytes += bytes.size();
    m->put(bytes.data(), bytes.size());
}

bool block_writer::finish(std::string& why)
{
    m->commit(m_globals);
    impl& w = *m;
    if (w.series.size() > 0xFFFFFFFFull - 4 * w.series_off.size())
        return why = m_path + ": the series table outgrew its offsets", false;

    std::string part;
    uint64_t off[sections], len[sections];
    uint32_t crcs[sections];
    off[0] = 0;
    len[0] = w.data_bytes;
    crcs[0] = w.data_crc;

    const auto emit = [&](size_t i) {
        off[i] = off[i - 1] + len[i - 1];
        len[i] = part.size();
        crcs[i] = crc::crc32c(part.data(), part.size());
        w.put(part.data(), part.size());
    };

    part.clear();
    append32(part, static_cast<uint32_t>(w.sym_list.size()));
    uint32_t so = 0;
    append32(part, 0);
    for (const std::string* s : w.sym_list)
        append32(part, so += static_cast<uint32_t>(s->size()));
    for (const std::string* s : w.sym_list)
        part += *s;
    emit(1);

    part.clear();
    append32(part, static_cast<uint32_t>(w.series_off.size() - 1));
    for (uint32_t o : w.series_off)
        append32(part, o);
    part += w.series;
    emit(2);

    std::vector<uint64_t> keys;
    keys.reserve(w.postings.size());
    for (const auto& kv : w.postings)
        keys.push_back(kv.first);
    std::sort(keys.begin(), keys.end(), [&](uint64_t a, uint64_t b) {
        const std::string& an = *w.sym_list[a >> 32];
        const std::string& bn = *w.sym_list[b >> 32];
        if (an != bn)
            return an < bn;
        return *w.sym_list[uint32_t(a)] < *w.sym_list[uint32_t(b)];
    });
    part.clear();
    append32(part, static_cast<uint32_t>(keys.size()));
    for (uint64_t k : keys)
    {
        const auto& ids = w.postings[k];
        append32(part, static_cast<uint32_t>(k >> 32));
        append32(part, static_cast<uint32_t>(k));
        append32(part, static_cast<uint32_t>(ids.size()));
        for (uint32_t id : ids)
            append32(part, id);
    }
    emit(3);

    part.assign(block_magic, 8);
    append32(part, block_version);
    append64(part, static_cast<uint64_t>(w.step));
    append64(part, static_cast<uint64_t>(w.mint));
    append64(part, static_cast<uint64_t>(w.maxt));
    for (size_t i = 0; i < sections; ++i)
    {
        append64(part, off[i]);
        append64(part, len[i]);
        append32(part, crcs[i]);
    }
    append32(part, crc::crc32c(part.data(), part.size()));
    w.put(part.data(), part.size());
    w.flush();

    const auto fail = [&](const char* step, int err) {
        why = std::string(step) + " failed for " + w.tmp + ": " + std::strerror(err);
        if (w.fd >= 0)
            ::close(w.fd);
        w.fd = -1;
        ::unlink(w.tmp.c_str());
        return false;
    };
    if (w.failed)
        return fail("write", w.err);
    if (::fsync(w.fd) != 0)
        return fail("fsync", errno);
    const int fd = w.fd;
    w.fd = -1;
    if (::close(fd) != 0)
        return fail("close", errno);
    if (::rename(w.tmp.c_str(), m_path.c_str()) != 0)
        return fail("rename", errno);
    if (!sync_dir(dir_of(m_path)))
        return why = "sync failed for the directory of " + m_path + ": " + std::strerror(errno), false;
    return true;
}

// ── head log ──────────────────────────────────────────────────────────────

std::string head_log_name(int64_t window) { return std::to_string(window) + ".log"; }

bool parse_head_log_name(std::string_view name, int64_t& window)
{
    if (!name.ends_with(".log"))
        return false;
    name.remove_suffix(4);
    const auto r = std::from_chars(name.data(), name.data() + name.size(), window);
    return !name.empty() && r.ec == std::errc{} && r.ptr == name.data() + name.size();
}

void head_log_header(std::string& buf, int64_t window)
{
    buf.append(log_magic, 8);
    append64(buf, static_cast<uint64_t>(window));
}

void log_series(std::string& buf, uint32_t id, std::span<const std::pair<std::string_view, std::string_view>> labels)
{
    const size_t at = begin_record(buf);
    buf += static_cast<char>(rec_series);
    append32(buf, id);
    append32(buf, static_cast<uint32_t>(labels.size()));
    for (const auto& [n, v] : labels)
    {
        append32(buf, static_cast<uint32_t>(n.size()));
        buf.append(n);
        append32(buf, static_cast<uint32_t>(v.size()));
        buf.append(v);
    }
    end_record(buf, at);
}

void log_chunk(std::string& buf, uint32_t id, int64_t mint, int64_t maxt, std::span<const uint8_t> bytes)
{
    const size_t at = begin_record(buf);
    buf += static_cast<char>(rec_chunk);
    append32(buf, id);
    append64(buf, static_cast<uint64_t>(mint));
    append64(buf, static_cast<uint64_t>(maxt));
    buf.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    end_record(buf, at);
}

void log_samples::add(uint32_t id, int64_t t, double v)
{
    if (m_n == 0)
    {
        m_body.clear();
        m_base = t;
    }
    ++m_n;
    put_uvarint(m_body, id);
    const int64_t d = wrap_sub(t, m_base);
    put_uvarint(m_body, (static_cast<uint64_t>(d) << 1) ^ static_cast<uint64_t>(d >> 63));
    append64(m_body, std::bit_cast<uint64_t>(v));
}

void log_samples::flush_into(std::string& buf)
{
    if (m_n == 0)
        return;
    const size_t at = begin_record(buf);
    buf += static_cast<char>(rec_samples);
    append32(buf, m_n);
    append64(buf, static_cast<uint64_t>(m_base));
    buf += m_body;
    end_record(buf, at);
    m_n = 0;
    m_body.clear();
}

namespace
{

// One record's payload handed to `v`, or false, handing nothing, when it is malformed.
bool visit_record(std::span<const uint8_t> p, log_visitor& v)
{
    if (p.empty())
        return false;
    size_t pos = 1;
    const auto need = [&](size_t n) { return p.size() - pos >= n; };
    switch (p[0])
    {
        case rec_series:
        {
            if (!need(8))
                return false;
            const uint32_t id = load32(p.data() + pos), n = load32(p.data() + pos + 4);
            pos += 8;
            label_set ls;
            for (uint32_t i = 0; i < n; ++i)
            {
                std::string parts[2];
                for (auto& s : parts)
                {
                    if (!need(4))
                        return false;
                    const uint32_t len = load32(p.data() + pos);
                    pos += 4;
                    if (!need(len))
                        return false;
                    s.assign(reinterpret_cast<const char*>(p.data() + pos), len);
                    pos += len;
                }
                ls.push_back(label{std::move(parts[0]), std::move(parts[1])});
            }
            if (pos != p.size())
                return false;
            v.series(id, ls);
            return true;
        }
        case rec_chunk:
        {
            if (!need(20 + chunk_head_bytes))
                return false;
            const uint32_t id = load32(p.data() + pos);
            const auto mint = static_cast<int64_t>(load64(p.data() + pos + 4));
            const auto maxt = static_cast<int64_t>(load64(p.data() + pos + 12));
            if (mint > maxt)
                return false;
            v.chunk(id, mint, maxt, p.subspan(pos + 20));
            return true;
        }
        case rec_samples:
        {
            if (!need(12))
                return false;
            const uint32_t n = load32(p.data() + pos);
            const auto base = static_cast<int64_t>(load64(p.data() + pos + 4));
            pos += 12;
            struct one
            {
                uint32_t id;
                int64_t t;
                uint64_t v;
            };
            std::vector<one> got;
            got.reserve(std::min<size_t>(n, p.size() / 10));
            for (uint32_t i = 0; i < n; ++i)
            {
                uint64_t id = 0, zz = 0;
                if (!get_uvarint(p, pos, id) || id > 0xFFFFFFFFull || !get_uvarint(p, pos, zz) || !need(8))
                    return false;
                const auto d = static_cast<int64_t>((zz >> 1) ^ (~(zz & 1) + 1));
                got.push_back(one{static_cast<uint32_t>(id), wrap_add(base, d), load64(p.data() + pos)});
                pos += 8;
            }
            if (pos != p.size())
                return false;
            for (const one& o : got)
                v.sample(o.id, o.t, std::bit_cast<double>(o.v));
            return true;
        }
        default:
            return false;
    }
}

}   // namespace

size_t read_head_log(std::span<const uint8_t> file, int64_t& window, log_visitor& v, std::string& why)
{
    if (file.size() < head_log_header_bytes || std::memcmp(file.data(), log_magic, 8) != 0)
    {
        why = "no head log header";
        return 0;
    }
    window = static_cast<int64_t>(load64(file.data() + 8));
    size_t pos = head_log_header_bytes;
    while (pos < file.size())
    {
        if (file.size() - pos < 8)
        {
            why = "a record header torn at " + std::to_string(pos);
            break;
        }
        const uint32_t len = load32(file.data() + pos), crc = load32(file.data() + pos + 4);
        if (len == 0 || len > file.size() - pos - 8)
        {
            why = "a record torn at " + std::to_string(pos);
            break;
        }
        const auto payload = file.subspan(pos + 8, len);
        if (crc::crc32c(payload.data(), payload.size()) != crc)
        {
            why = "a record whose crc32c does not match at " + std::to_string(pos);
            break;
        }
        if (!visit_record(payload, v))
        {
            why = "a malformed record at " + std::to_string(pos);
            break;
        }
        pos += 8 + len;
    }
    return pos;
}

}   // namespace socketley::metrics
