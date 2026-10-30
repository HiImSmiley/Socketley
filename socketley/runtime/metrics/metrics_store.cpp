#include "metrics_store.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <map>
#include <mutex>
#include <new>
#include <thread>
#include <type_traits>
#include <unordered_map>

#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../shared/loop/blocking_write.h"
#include "../../shared/persist/private_dir.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/persist/replaced_file.h"
#include "../../shared/util/byte_codec.h"
#include "../../shared/util/crc.h"
#include "../../shared/util/logging.h"
#include "metrics_chunk.h"

namespace socketley::metrics
{

namespace
{

constexpr uint32_t no_slot = 0xFFFFFFFFu;
// A window is cut once samples reach this far past its end, so a late sample still lands in it.
constexpr int64_t cut_grace = block_ms / 2;
// After failed maintenance, the next attempt waits this long.
constexpr int64_t retry_ms = 60'000;
constexpr size_t page_bytes = 1u << 16;
constexpr size_t log_flush_bytes = 256u << 10;
constexpr char meta_magic[8] = {'S', 'K', 'L', 'M', 'M', 'E', 'T', '1'};

// 64 KiB mapped on its own, so a page let go goes back to the system rather than into a fragmented heap.
class page
{
public:
    page()
    {
        void* p = ::mmap(nullptr, page_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED)
            throw std::bad_alloc();
        m_p = static_cast<uint8_t*>(p);
    }
    ~page()
    {
        if (m_p)
            ::munmap(m_p, page_bytes);
    }
    page(page&& o) noexcept : m_p(o.m_p) { o.m_p = nullptr; }
    page& operator=(page&&) = delete;
    page(const page&) = delete;

    uint8_t* data() const { return m_p; }

private:
    uint8_t* m_p{nullptr};
};

// An open chunk and its state, a fixed 256 bytes whatever the series appends.
struct head_slot
{
    chunk_appender ap;
    int64_t window{0};
    uint8_t data[256 - sizeof(chunk_appender) - sizeof(int64_t)]{};
};
static_assert(sizeof(head_slot) == 256 && std::is_trivially_destructible_v<head_slot>);
constexpr size_t slot_data_bytes = sizeof(head_slot::data);

// The open chunks of every series, in pages that never move, with the slots let go kept for the next.
class slot_slab
{
public:
    static constexpr uint32_t per_page = page_bytes / sizeof(head_slot);

    uint32_t alloc()
    {
        if (!m_free.empty())
        {
            const uint32_t s = m_free.back();
            m_free.pop_back();
            return s;
        }
        if (m_used % per_page == 0)
        {
            m_pages.emplace_back();
            auto* base = reinterpret_cast<head_slot*>(m_pages.back().data());
            for (uint32_t i = 0; i < per_page; ++i)
                new (base + i) head_slot();
        }
        return m_used++;
    }
    head_slot& at(uint32_t s) { return reinterpret_cast<head_slot*>(m_pages[s / per_page].data())[s % per_page]; }
    const head_slot& at(uint32_t s) const
    {
        return reinterpret_cast<const head_slot*>(m_pages[s / per_page].data())[s % per_page];
    }
    void release(uint32_t s)
    {
        head_slot& h = at(s);
        h.ap.reset(h.data);
        m_free.push_back(s);
    }
    size_t bytes() const { return m_pages.size() * page_bytes + m_free.capacity() * 4; }

private:
    std::vector<page> m_pages;
    std::vector<uint32_t> m_free;
    uint32_t m_used{0};
};

struct head_chunk
{
    int64_t mint;
    int64_t maxt;
    uint32_t series;
    uint32_t prev;   // the series' chunk before it in this window, plus one
    uint32_t at;     // page << 16 | offset
    uint16_t len;
    uint16_t n;
};

// The closed chunks of one aligned window, immutable once sealed, which is when a cut may read it off the loop.
struct head_window
{
    int64_t start{0};
    std::vector<page> pages;
    size_t fill{page_bytes};
    std::vector<head_chunk> chunks;
    std::vector<uint32_t> last_of;
    bool sealed{false};

    std::span<const uint8_t> bytes(const head_chunk& c) const
    {
        return {pages[c.at >> 16].data() + (c.at & 0xFFFF), c.len};
    }

    void add(uint32_t series, int64_t mint, int64_t maxt, uint16_t n, std::span<const uint8_t> b)
    {
        if (fill + b.size() > page_bytes)
        {
            pages.emplace_back();
            fill = 0;
        }
        const auto at = static_cast<uint32_t>(((pages.size() - 1) << 16) | fill);
        std::memcpy(pages.back().data() + fill, b.data(), b.size());
        fill += b.size();
        if (last_of.size() <= series)
            last_of.resize(size_t(series) + 1, 0);
        chunks.push_back(head_chunk{mint, maxt, series, last_of[series], at, static_cast<uint16_t>(b.size()), n});
        last_of[series] = static_cast<uint32_t>(chunks.size());
    }

    // The chunks of `series` in time order, through `chain`.
    void chain_of(uint32_t series, std::vector<uint32_t>& chain) const
    {
        chain.clear();
        for (uint32_t c = series < last_of.size() ? last_of[series] : 0; c != 0; c = chunks[c - 1].prev)
            chain.push_back(c - 1);
        std::reverse(chain.begin(), chain.end());
    }

    size_t ram_bytes() const
    {
        return sizeof(*this) + pages.size() * page_bytes + chunks.capacity() * sizeof(head_chunk) + last_of.capacity() * 4;
    }
};

struct series_head
{
    int64_t last_t{INT64_MIN};
    int64_t head_mint{INT64_MAX};
    // The window whose head log holds this series' record under its current id.
    int64_t logged{INT64_MIN};
    uint32_t slot{no_slot};
    // Whether it counts against max_series.
    bool counted{false};
};

struct head_log
{
    int64_t window{0};
    int fd{-1};
    bool header{false};
    bool failed{false};
    std::string buf;
    log_samples samples;
    uint64_t file_bytes{0};
};

struct meta_entry
{
    metric_type type{metric_type::untyped};
    std::string help;
};

bool label_set_less(const label_set& a, const label_set& b)
{
    const size_t n = std::min(a.size(), b.size());
    for (size_t i = 0; i < n; ++i)
    {
        if (a[i].name != b[i].name)
            return a[i].name < b[i].name;
        if (a[i].value != b[i].value)
            return a[i].value < b[i].value;
    }
    return a.size() < b.size();
}

// What background work hands back for the loop to take in.
struct job_result
{
    bool ok{true};
    std::string why;
    std::vector<std::shared_ptr<block>> added;
    std::vector<std::shared_ptr<block>> removed;
    // The window a cut took from the head, or INT64_MIN.
    int64_t cut{INT64_MIN};
};

using job = std::function<std::unique_ptr<job_result>()>;

std::unique_ptr<job_result> failed(std::unique_ptr<job_result> r)
{
    r->ok = false;
    return r;
}

// The one background thread: a single job at a time, its result left for the loop to take, and syncs of the head
// logs between jobs.
class worker
{
public:
    ~worker() { stop(); }

    bool busy() const { return m_busy; }

    void submit(job j)
    {
        if (!m_th.joinable())
            m_th = std::thread([this] { run(); });
        m_busy = true;
        {
            std::lock_guard<std::mutex> g(m_mu);
            m_job = std::move(j);
        }
        m_cv.notify_one();
    }

    // The finished job's result, or null while it runs or when none was given.
    std::unique_ptr<job_result> take()
    {
        if (!m_ready.load(std::memory_order_acquire))
            return nullptr;
        std::lock_guard<std::mutex> g(m_mu);
        m_ready.store(false, std::memory_order_relaxed);
        m_busy = false;
        return std::move(m_done);
    }

    // The running job waited for, at stop only.
    std::unique_ptr<job_result> wait()
    {
        if (!m_busy)
            return nullptr;
        std::unique_lock<std::mutex> g(m_mu);
        m_done_cv.wait(g, [&] { return m_ready.load(std::memory_order_relaxed); });
        m_ready.store(false, std::memory_order_relaxed);
        m_busy = false;
        return std::move(m_done);
    }

    // `fd`, a duplicate the worker owns, synced and closed off the loop.
    void sync(int fd)
    {
        if (!m_th.joinable())
            m_th = std::thread([this] { run(); });
        {
            std::lock_guard<std::mutex> g(m_mu);
            m_syncs.push_back(fd);
        }
        m_cv.notify_one();
    }

    void stop()
    {
        if (!m_th.joinable())
            return;
        {
            std::lock_guard<std::mutex> g(m_mu);
            m_quit = true;
        }
        m_cv.notify_one();
        m_th.join();
        for (int fd : m_syncs)
            ::close(fd);
        m_syncs.clear();
    }

private:
    void run()
    {
        std::unique_lock<std::mutex> g(m_mu);
        for (;;)
        {
            m_cv.wait(g, [&] { return m_quit || m_job || !m_syncs.empty(); });
            if (!m_syncs.empty())
            {
                std::vector<int> fds;
                fds.swap(m_syncs);
                g.unlock();
                for (int fd : fds)
                {
                    if (::fdatasync(fd) != 0) {}
                    ::close(fd);
                }
                g.lock();
                continue;
            }
            if (m_job)
            {
                job j = std::move(m_job);
                m_job = nullptr;
                g.unlock();
                std::unique_ptr<job_result> r = j();
                g.lock();
                m_done = std::move(r);
                m_ready.store(true, std::memory_order_release);
                m_done_cv.notify_all();
                continue;
            }
            if (m_quit)
                return;
        }
    }

    std::thread m_th;
    std::mutex m_mu;
    std::condition_variable m_cv, m_done_cv;
    job m_job;
    std::unique_ptr<job_result> m_done;
    std::vector<int> m_syncs;
    std::atomic<bool> m_ready{false};
    bool m_quit{false};
    // Loop-side: a job submitted and its result not yet taken.
    bool m_busy{false};
};

// ── off-loop jobs ─────────────────────────────────────────────────────────

// Tier points as chunks of at most tier_chunk_points, added to `w`'s current series.
void add_tier_chunks(block_writer& w, const std::vector<tier_point>& pts, std::vector<uint8_t>& buf)
{
    for (size_t i = 0; i < pts.size(); i += tier_chunk_points)
    {
        const size_t n = std::min(tier_chunk_points, pts.size() - i);
        encode_tier_chunk(std::span<const tier_point>(pts.data() + i, n), buf);
        w.add_chunk(pts[i].t, pts[i + n - 1].t, buf);
    }
}

// A finished writer's block opened back and given its ids, or the reason it could not be.
bool finish_block(block_writer& w, std::shared_ptr<block>& out, std::string& why)
{
    if (!w.finish(why))
        return false;
    if (w.globals().empty())
    {
        ::unlink(w.path().c_str());
        return true;
    }
    out = block::open(w.path(), why);
    if (!out)
        return false;
    out->set_globals(w.globals());
    return true;
}

struct cut_input
{
    std::shared_ptr<const head_window> win;
    std::vector<std::pair<label_set, uint32_t>> series;
    std::string dir;
    int64_t tier_step{0};
};

std::unique_ptr<job_result> run_cut(cut_input& in)
{
    auto r = std::make_unique<job_result>();
    r->cut = in.win->start;
    std::sort(in.series.begin(), in.series.end(),
              [](const auto& a, const auto& b) { return label_set_less(a.first, b.first); });
    const int64_t lo = in.win->start, hi = lo + block_ms;
    std::vector<uint32_t> chain;
    std::vector<uint8_t> buf;
    std::vector<tier_point> pts;

    // The tier first, so a raw block on the disk means its tier is there too.
    if (in.tier_step > 0)
    {
        block_writer tw(in.dir, in.tier_step, lo, hi);
        if (!tw.begin(r->why))
            return failed(std::move(r));
        for (const auto& [ls, id] : in.series)
        {
            pts.clear();
            {
                tier_folder f(in.tier_step, pts);
                in.win->chain_of(id, chain);
                for (uint32_t c : chain)
                {
                    chunk_reader rd(in.win->bytes(in.win->chunks[c]));
                    while (rd.next())
                        f.add(rd.t(), rd.v());
                }
            }
            if (pts.empty())
                continue;
            tw.add_series(ls, id);
            add_tier_chunks(tw, pts, buf);
        }
        std::shared_ptr<block> b;
        if (!finish_block(tw, b, r->why))
            return failed(std::move(r));
        if (b)
            r->added.push_back(std::move(b));
    }

    block_writer rw(in.dir, 0, lo, hi);
    if (!rw.begin(r->why))
        return failed(std::move(r));
    for (const auto& [ls, id] : in.series)
    {
        rw.add_series(ls, id);
        in.win->chain_of(id, chain);
        for (uint32_t c : chain)
        {
            const head_chunk& hc = in.win->chunks[c];
            rw.add_chunk(hc.mint, hc.maxt, in.win->bytes(hc));
        }
    }
    std::shared_ptr<block> b;
    if (!finish_block(rw, b, r->why))
        return failed(std::move(r));
    if (b)
        r->added.push_back(std::move(b));
    return r;
}

struct merge_input
{
    std::vector<std::shared_ptr<block>> children;
    int64_t step{0};
    int64_t mint{0}, maxt{0};
    // The next tier, built from this one's merged day, or 0.
    int64_t next_step{0};
    std::string dir;
};

std::unique_ptr<job_result> run_merge(merge_input& in)
{
    auto r = std::make_unique<job_result>();
    std::vector<std::pair<label_set, uint32_t>> series;
    {
        std::unordered_map<uint32_t, size_t> seen;
        for (const auto& c : in.children)
        {
            const auto globals = c->globals();
            for (uint32_t g : globals)
            {
                if (seen.count(g))
                    continue;
                seen.emplace(g, series.size());
                series.emplace_back();
                c->labels(c->local_of(g), series.back().first);
                series.back().second = g;
            }
        }
    }
    std::sort(series.begin(), series.end(), [](const auto& a, const auto& b) { return label_set_less(a.first, b.first); });
    std::vector<uint8_t> buf;
    std::vector<tier_point> fine, coarse;

    if (in.next_step > 0)
    {
        block_writer tw(in.dir, in.next_step, in.mint, in.maxt);
        if (!tw.begin(r->why))
            return failed(std::move(r));
        for (const auto& [ls, g] : series)
        {
            fine.clear();
            for (const auto& c : in.children)
                if (const uint32_t local = c->local_of(g); local != no_series)
                    c->each_chunk(local, [&](const block::chunk& ch) {
                        decode_tier_chunk(ch.bytes, fine);
                        return true;
                    });
            coarse.clear();
            {
                tier_folder f(in.next_step, coarse);
                for (const tier_point& p : fine)
                    f.add(p);
            }
            if (coarse.empty())
                continue;
            tw.add_series(ls, g);
            add_tier_chunks(tw, coarse, buf);
        }
        std::shared_ptr<block> b;
        if (!finish_block(tw, b, r->why))
            return failed(std::move(r));
        if (b)
            r->added.push_back(std::move(b));
    }

    block_writer w(in.dir, in.step, in.mint, in.maxt);
    if (!w.begin(r->why))
        return failed(std::move(r));
    for (const auto& [ls, g] : series)
    {
        w.add_series(ls, g);
        for (const auto& c : in.children)
            if (const uint32_t local = c->local_of(g); local != no_series)
                c->each_chunk(local, [&](const block::chunk& ch) {
                    w.add_chunk(ch.mint, ch.maxt, ch.bytes);
                    return true;
                });
    }
    std::shared_ptr<block> b;
    if (!finish_block(w, b, r->why))
        return failed(std::move(r));
    if (b)
        r->added.push_back(std::move(b));
    r->removed = in.children;
    return r;
}

// The names in `dir` handed to `f`.
template <class F>
void each_entry(const std::string& dir, F&& f)
{
    DIR* d = ::opendir(dir.c_str());
    if (!d)
        return;
    while (const dirent* e = ::readdir(d))
    {
        const std::string_view n = e->d_name;
        if (n != "." && n != "..")
            f(std::string(n));
    }
    ::closedir(d);
}

}   // namespace

// ── the store ─────────────────────────────────────────────────────────────

struct store::impl
{
    std::string dir, blocks_dir, head_dir;
    store_config cfg;
    bool is_open{false};

    series_index index;
    std::vector<series_head> heads;
    slot_slab slab;
    std::vector<std::shared_ptr<head_window>> windows;
    std::vector<head_log> logs;
    // Blocks by kind, raw first and then each tier, each list ascending by mint.
    std::vector<std::vector<std::shared_ptr<block>>> blocks;

    // Samples before this lie in a window already cut, and are refused.
    int64_t floor{INT64_MIN};
    int64_t now{INT64_MIN};
    int64_t max_t{INT64_MIN};
    int64_t retry_after{INT64_MIN};
    bool replaying{false};

    uint64_t head_series{0};
    uint64_t appended{0}, out_of_order{0}, too_old{0}, refused_series{0}, blocks_refused{0}, failures{0};

    std::map<std::string, meta_entry, std::less<>> metas;
    bool metas_dirty{false};

    worker bg;

    label_set norm;
    std::vector<std::pair<std::string_view, std::string_view>> pairs;
    std::vector<uint32_t> chain;
    std::vector<uint32_t> candidates;

    // ── layout ──

    int64_t head_lo() const { return windows.empty() ? floor : std::min(floor, windows.front()->start); }

    // The clock tick() is given, so one sample stamped far ahead cannot expire every block; before a tick, the samples.
    int64_t ref_now() const { return now != INT64_MIN ? now : max_t; }

    // The oldest time a retention of `keep` still holds, now being what the store has seen.
    int64_t horizon(int64_t keep) const
    {
        const int64_t n = ref_now();
        return n == INT64_MIN ? INT64_MIN : n - keep;
    }

    // The kind index of a step: 0 raw, k + 1 for tier k, -1 for a step no tier has.
    int kind_of(int64_t step) const
    {
        if (step == 0)
            return 0;
        for (size_t k = 0; k < cfg.tiers.size(); ++k)
            if (cfg.tiers[k].step == step)
                return static_cast<int>(k) + 1;
        return -1;
    }
    int64_t step_of(size_t kind) const { return kind == 0 ? 0 : cfg.tiers[kind - 1].step; }
    int64_t keep_of(size_t kind) const { return kind == 0 ? cfg.keep_raw : cfg.tiers[kind - 1].keep; }
    // Whether the next tier is built from this kind's merged days.
    bool feeds_next(size_t kind) const { return kind >= 1 && kind < cfg.tiers.size(); }

    // The spans a kind's blocks grow through: from two hours or a day, through a day, by eights while one stays
    // under a sixteenth of what is kept.
    std::vector<int64_t> spans_of(size_t kind) const
    {
        std::vector<int64_t> s;
        if (kind <= 1)
            s.push_back(block_ms);
        s.push_back(day_ms);
        while (s.back() * 8 <= keep_of(kind) / 16)
            s.push_back(s.back() * 8);
        return s;
    }

    head_window* window_at(int64_t start)
    {
        for (auto it = windows.rbegin(); it != windows.rend(); ++it)
        {
            if ((*it)->start == start)
                return it->get();
            if ((*it)->start < start)
                break;
        }
        auto w = std::make_shared<head_window>();
        w->start = start;
        const auto pos = std::lower_bound(windows.begin(), windows.end(), start,
                                          [](const auto& a, int64_t s) { return a->start < s; });
        return windows.insert(pos, std::move(w))->get();
    }

    head_log& log_at(int64_t window)
    {
        for (auto it = logs.rbegin(); it != logs.rend(); ++it)
        {
            if (it->window == window)
                return *it;
            if (it->window < window)
                break;
        }
        head_log l;
        l.window = window;
        const auto pos = std::lower_bound(logs.begin(), logs.end(), window,
                                          [](const head_log& a, int64_t w) { return a.window < w; });
        return *logs.insert(pos, std::move(l));
    }

    std::string log_path(int64_t window) const { return head_dir + "/" + head_log_name(window); }

    // ── the head log ──

    void ensure_logged(uint32_t id, series_head& s, head_log& l)
    {
        if (s.logged == l.window)
            return;
        l.samples.flush_into(l.buf);
        pairs.clear();
        index.each_label(id, [&](std::string_view n, std::string_view v) { pairs.emplace_back(n, v); });
        log_series(l.buf, id, pairs);
        s.logged = l.window;
    }

    void log_closed(uint32_t id, series_head& s, int64_t window, const chunk_appender& ap, std::span<const uint8_t> b)
    {
        head_log& l = log_at(window);
        ensure_logged(id, s, l);
        l.samples.flush_into(l.buf);
        log_chunk(l.buf, id, ap.mint, ap.maxt, b);
        if (l.buf.size() >= log_flush_bytes)
            write_log(l);
    }

    void write_log(head_log& l)
    {
        l.samples.flush_into(l.buf);
        if (l.buf.empty() || l.failed)
        {
            l.buf.clear();
            return;
        }
        if (l.fd < 0)
        {
            const std::string path = log_path(l.window);
            l.fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
            if (l.fd < 0)
            {
                l.failed = true;
                LOG_ERROR(("metrics: cannot open " + path + ": " + std::strerror(errno) +
                           " -- the head of that window is kept in memory only").c_str());
                l.buf.clear();
                return;
            }
        }
        if (!l.header)
        {
            std::string h;
            head_log_header(h, l.window);
            l.buf.insert(0, h);
            l.header = true;
        }
        if (!write_all(l.fd, l.buf.data(), l.buf.size()))
        {
            l.failed = true;
            LOG_ERROR(("metrics: cannot write " + log_path(l.window) + ": " + std::strerror(errno)).c_str());
        }
        else
            l.file_bytes += l.buf.size();
        l.buf.clear();
        if (l.buf.capacity() > log_flush_bytes * 2)
            std::string().swap(l.buf);
    }

    void write_logs(bool sync)
    {
        for (head_log& l : logs)
        {
            const bool had = !l.buf.empty() || !l.samples.empty();
            write_log(l);
            if (sync && had && l.fd >= 0)
                if (const int d = ::dup(l.fd); d >= 0)
                    bg.sync(d);
        }
    }

    void close_log(int64_t window, bool remove)
    {
        for (auto it = logs.begin(); it != logs.end(); ++it)
            if (it->window == window)
            {
                write_log(*it);
                if (it->fd >= 0)
                    ::close(it->fd);
                logs.erase(it);
                break;
            }
        if (remove)
            ::unlink(log_path(window).c_str());
    }

    // ── appending ──

    // The open chunk of `id` moved into its window's closed chunks, and its slot let go when `release` says so.
    void close_open(uint32_t id, series_head& s, bool release)
    {
        if (s.slot == no_slot)
            return;
        head_slot& hs = slab.at(s.slot);
        if (hs.ap.n > 0)
        {
            const std::span<const uint8_t> b(hs.data, hs.ap.bytes());
            window_at(hs.window)->add(id, hs.ap.mint, hs.ap.maxt, hs.ap.n, b);
            if (!replaying)
                log_closed(id, s, hs.window, hs.ap, b);
            hs.ap.reset(hs.data);
        }
        if (release)
        {
            slab.release(s.slot);
            s.slot = no_slot;
        }
    }

    bool append(uint32_t id, int64_t t, double v)
    {
        if (id >= heads.size())
            return false;
        series_head& s = heads[id];
        if (t <= s.last_t)
        {
            ++out_of_order;
            return false;
        }
        if (t < floor || t > max_abs_time || t < -max_abs_time)
        {
            ++too_old;
            return false;
        }
        const int64_t w = align_down(t, block_ms);
        if (s.slot != no_slot)
        {
            const head_slot& hs = slab.at(s.slot);
            if (hs.ap.n > 0 && (hs.window != w || hs.ap.n >= chunk_samples || !hs.ap.fits(slot_data_bytes)))
                close_open(id, s, false);
        }
        else
            s.slot = slab.alloc();
        head_slot& hs = slab.at(s.slot);
        if (hs.ap.n == 0)
        {
            hs.window = w;
            window_at(w);
        }
        hs.ap.append(hs.data, slot_data_bytes, t, v);
        if (s.last_t < head_lo())
            s.head_mint = t;
        if (!s.counted)
        {
            s.counted = true;
            ++head_series;
        }
        s.last_t = t;
        if (cfg.durable && !replaying)
        {
            head_log& l = log_at(w);
            ensure_logged(id, s, l);
            l.samples.add(id, t, v);
        }
        ++appended;
        if (t > max_t)
            max_t = t;
        return true;
    }

    uint32_t create(const label_set& ls, bool limited)
    {
        const label_set* use = &ls;
        if (!is_normal(ls))
        {
            if (!normalize(ls, norm))
            {
                ++refused_series;
                return no_series;
            }
            use = &norm;
        }
        if (const uint32_t id = index.find(*use); id != no_series)
            return id;
        if (limited && head_series >= cfg.max_series)
        {
            ++refused_series;
            return no_series;
        }
        const uint32_t id = index.add(*use);
        heads.emplace_back();
        if (limited)
        {
            heads.back().counted = true;
            ++head_series;
        }
        return id;
    }

    // ── maintenance ──

    void insert_block(std::shared_ptr<block> b)
    {
        const int k = kind_of(b->step());
        if (k < 0)
            return;
        auto& list = blocks[static_cast<size_t>(k)];
        const auto pos = std::lower_bound(list.begin(), list.end(), b->mint(),
                                          [](const auto& a, int64_t t) { return a->mint() < t; });
        list.insert(pos, std::move(b));
    }

    void drop_block(const std::shared_ptr<block>& b)
    {
        const int k = kind_of(b->step());
        if (k >= 0)
        {
            auto& list = blocks[static_cast<size_t>(k)];
            list.erase(std::remove(list.begin(), list.end(), b), list.end());
        }
        ::unlink(b->path().c_str());
    }

    void recount()
    {
        const int64_t lo = head_lo();
        head_series = 0;
        for (series_head& s : heads)
        {
            s.counted = s.last_t != INT64_MIN && s.last_t >= lo;
            head_series += s.counted;
        }
    }

    void take_in(std::unique_ptr<job_result> r)
    {
        if (!r)
            return;
        if (!r->ok)
        {
            ++failures;
            retry_after = now == INT64_MIN ? INT64_MIN : now + retry_ms;
            LOG_WARN(("metrics: maintenance failed, tried again in a minute: " + r->why).c_str());
            return;
        }
        for (auto& b : r->added)
            insert_block(std::move(b));
        for (const auto& b : r->removed)
            drop_block(b);
        if (r->cut != INT64_MIN)
        {
            windows.erase(std::remove_if(windows.begin(), windows.end(), [&](const auto& w) { return w->start == r->cut; }),
                          windows.end());
            close_log(r->cut, true);
            recount();
            save_meta(durability::none);
        }
    }

    // The oldest window sealed: no sample may land in it again, and every chunk open in it is closed.
    void seal(head_window& w)
    {
        floor = std::max(floor, w.start + block_ms);
        for (uint32_t id = 0; id < heads.size(); ++id)
        {
            series_head& s = heads[id];
            if (s.slot != no_slot && slab.at(s.slot).window == w.start)
                close_open(id, s, true);
        }
        close_log(w.start, false);
        w.sealed = true;
    }

    void submit_cut(const std::shared_ptr<head_window>& w)
    {
        auto in = std::make_shared<cut_input>();
        in->win = w;
        in->dir = blocks_dir;
        in->tier_step = cfg.tiers.empty() ? 0 : cfg.tiers[0].step;
        for (uint32_t id = 0; id < w->last_of.size(); ++id)
        {
            if (w->last_of[id] == 0)
                continue;
            in->series.emplace_back();
            in->series.back().second = id;
            index.each_label(id, [&](std::string_view n, std::string_view v) {
                in->series.back().first.push_back(label{std::string(n), std::string(v)});
            });
        }
        bg.submit([in] { return run_cut(*in); });
    }

    // A merge due for `kind`, started; false when none is.
    bool plan_merge(size_t kind)
    {
        const auto spans = spans_of(kind);
        const auto& list = blocks[kind];
        const int64_t keep_from = horizon(keep_of(kind));
        for (size_t lvl = 1; lvl < spans.size(); ++lvl)
        {
            const int64_t span = spans[lvl];
            for (const auto& b : list)
            {
                if (b->maxt() - b->mint() >= span)
                    continue;
                const int64_t ps = align_down(b->mint(), span), pe = ps + span;
                // A day past this tier's retention is still merged when the next tier is built from it.
                const bool wanted = pe > keep_from || (span == day_ms && feeds_next(kind) && pe > horizon(keep_of(kind + 1)));
                if (pe > floor || !wanted)
                    continue;
                // A tier built from the one below waits until every day of that one in the span is merged.
                if (kind >= 2)
                {
                    bool finer_pending = false;
                    for (const auto& f : blocks[kind - 1])
                        if (f->mint() < pe && f->maxt() > ps && f->maxt() - f->mint() < day_ms)
                            finer_pending = true;
                    if (finer_pending)
                        continue;
                }
                auto in = std::make_shared<merge_input>();
                in->step = step_of(kind);
                in->mint = ps;
                in->maxt = pe;
                in->dir = blocks_dir;
                for (const auto& c : list)
                    if (c->mint() >= ps && c->maxt() <= pe && c->maxt() - c->mint() < span)
                        in->children.push_back(c);
                if (feeds_next(kind) && span == day_ms)
                    in->next_step = cfg.tiers[kind].step;
                bg.submit([in] { return run_merge(*in); });
                return true;
            }
        }
        return false;
    }

    void plan()
    {
        if (!windows.empty())
        {
            const auto& w = windows.front();
            if (w->sealed)
            {
                submit_cut(w);
                return;
            }
            if (w->start + block_ms + cut_grace <= ref_now())
            {
                seal(*w);
                submit_cut(w);
                return;
            }
        }
        for (size_t k = 0; k < blocks.size(); ++k)
            if (plan_merge(k))
                return;
    }

    void retain()
    {
        for (size_t k = 0; k < blocks.size(); ++k)
        {
            const int64_t keep_from = horizon(keep_of(k));
            std::vector<std::shared_ptr<block>> gone;
            for (const auto& b : blocks[k])
            {
                // A part of a day the next tier is not yet built from waits for that day's merge.
                const bool feeding = feeds_next(k) && b->maxt() - b->mint() < day_ms && b->maxt() > horizon(keep_of(k + 1));
                if (b->maxt() <= keep_from && !feeding)
                    gone.push_back(b);
            }
            for (const auto& b : gone)
                drop_block(b);
        }
    }

    // ── reading ──

    bool has_data(uint32_t id, int64_t mint, int64_t maxt) const
    {
        const series_head& s = heads[id];
        const int64_t lo = head_lo();
        if (s.last_t >= lo && s.last_t >= mint && std::max(s.head_mint, lo) <= maxt)
            return true;
        for (size_t k = 0; k < blocks.size(); ++k)
        {
            const int64_t step = step_of(k);
            for (const auto& b : blocks[k])
            {
                if (b->mint() > maxt)
                    break;
                if (b->maxt() <= mint)
                    continue;
                const uint32_t local = b->local_of(id);
                if (local == no_series)
                    continue;
                int64_t lo_t = 0, hi_t = 0;
                b->range(local, lo_t, hi_t);
                if (step > 0)
                {
                    lo_t -= step;
                    hi_t -= 1;
                }
                if (lo_t <= maxt && hi_t >= mint)
                    return true;
            }
        }
        return false;
    }

    void read_samples(uint32_t id, int64_t mint, int64_t maxt, std::vector<sample>& out)
    {
        if (id >= heads.size() || mint > maxt)
            return;
        int64_t last = INT64_MIN;
        bool first = true;
        const auto take = [&](std::span<const uint8_t> bytes) {
            chunk_reader r(bytes);
            while (r.next())
            {
                const int64_t t = r.t();
                if (t > maxt)
                    break;
                if (t >= mint && (first || t > last))
                {
                    out.push_back(sample{t, r.v()});
                    last = t;
                    first = false;
                }
            }
        };
        for (const auto& b : blocks[0])
        {
            if (b->mint() > maxt)
                break;
            if (b->maxt() <= mint)
                continue;
            const uint32_t local = b->local_of(id);
            if (local == no_series)
                continue;
            b->each_chunk(local, [&](const block::chunk& c) {
                if (c.mint > maxt)
                    return false;
                if (c.maxt >= mint)
                    take(c.bytes);
                return true;
            });
        }
        for (const auto& w : windows)
        {
            if (w->start > maxt)
                break;
            if (w->start + block_ms <= mint)
                continue;
            w->chain_of(id, chain);
            for (uint32_t c : chain)
            {
                const head_chunk& hc = w->chunks[c];
                if (hc.maxt >= mint && hc.mint <= maxt)
                    take(w->bytes(hc));
            }
        }
        const series_head& s = heads[id];
        if (s.slot != no_slot)
        {
            const head_slot& hs = slab.at(s.slot);
            if (hs.ap.n > 0 && hs.ap.maxt >= mint && hs.ap.mint <= maxt)
                take(std::span<const uint8_t>(hs.data, hs.ap.bytes()));
        }
    }

    // The points of tier `k` for `id` whose steps end in (lo, hi], ascending: from its blocks, and past the last of
    // them made from the tier below or from raw.
    void collect(size_t k, uint32_t id, int64_t lo, int64_t hi, std::vector<tier_point>& out)
    {
        if (lo >= hi)
            return;
        const int64_t step = cfg.tiers[k].step;
        const auto& list = blocks[k + 1];
        int64_t covered = INT64_MIN;
        int64_t last = INT64_MIN;
        std::vector<tier_point> tmp;
        for (const auto& b : list)
        {
            covered = std::max(covered, b->maxt());
            if (b->mint() >= hi || b->maxt() <= lo)
                continue;
            const uint32_t local = b->local_of(id);
            if (local == no_series)
                continue;
            b->each_chunk(local, [&](const block::chunk& c) {
                if (c.mint > hi)
                    return false;
                if (c.maxt <= lo)
                    return true;
                tmp.clear();
                decode_tier_chunk(c.bytes, tmp);
                for (const tier_point& p : tmp)
                    if (p.t > lo && p.t <= hi && p.t > last)
                    {
                        out.push_back(p);
                        last = p.t;
                    }
                return true;
            });
        }
        if (hi <= covered)
            return;
        const int64_t a = std::max(lo, covered);
        const int64_t first_end = step_end(a, step), last_end = align_down(hi, step);
        if (last_end < first_end)
            return;
        tmp.clear();
        {
            tier_folder f(step, tmp);
            if (k == 0)
            {
                std::vector<sample> raw;
                read_samples(id, first_end - step, last_end - 1, raw);
                for (const sample& x : raw)
                    f.add(x.t, x.v);
            }
            else
            {
                std::vector<tier_point> finer;
                collect(k - 1, id, first_end - step, last_end, finer);
                for (const tier_point& p : finer)
                    f.add(p);
            }
        }
        for (const tier_point& p : tmp)
            if (p.t > last)
            {
                out.push_back(p);
                last = p.t;
            }
    }

    // ── opening ──

    struct replayer final : log_visitor
    {
        impl& s;
        std::unordered_map<uint32_t, uint32_t> ids;
        uint64_t skipped{0};
        std::vector<metrics::sample> tmp;

        explicit replayer(impl& st) : s(st) {}

        void series(uint32_t id, label_set& ls) override
        {
            const uint32_t g = s.create(ls, false);
            if (g == no_series)
                ids.erase(id);
            else
                ids[id] = g;
        }

        void chunk(uint32_t id, int64_t mint, int64_t maxt, std::span<const uint8_t> bytes) override
        {
            const auto it = ids.find(id);
            tmp.clear();
            // A chunk that does not decode whole inside one window, in order, as its record says, is skipped.
            const bool bounded = mint >= -max_abs_time && maxt <= max_abs_time;
            const int64_t w = bounded ? align_down(mint, block_ms) : 0;
            bool ok = bounded && it != ids.end() && bytes.size() <= slot_data_bytes && decode_chunk(bytes, tmp) &&
                      !tmp.empty() && tmp.front().t == mint && tmp.back().t == maxt && maxt < w + block_ms;
            for (size_t i = 1; ok && i < tmp.size(); ++i)
                ok = tmp[i].t > tmp[i - 1].t;
            if (!ok)
            {
                ++skipped;
                return;
            }
            const uint32_t g = it->second;
            series_head& h = s.heads[g];
            if (mint > h.last_t && mint >= s.floor)
            {
                s.close_open(g, h, true);
                s.window_at(w)->add(g, mint, maxt, static_cast<uint16_t>(tmp.size()), bytes);
                if (h.last_t < s.head_lo())
                    h.head_mint = mint;
                h.last_t = maxt;
                if (maxt > s.max_t)
                    s.max_t = maxt;
                s.appended += tmp.size();
                return;
            }
            for (const metrics::sample& x : tmp)
                if (x.t > h.last_t)
                    s.append(g, x.t, x.v);
        }

        void sample(uint32_t id, int64_t t, double v) override
        {
            if (const auto it = ids.find(id); it != ids.end() && t > s.heads[it->second].last_t)
                s.append(it->second, t, v);
        }
    };

    void replay(const std::string& path, int64_t window)
    {
        std::string data, why;
        if (!read_file(path, data, read_options{.missing_ok = false, .max_bytes = SIZE_MAX, .no_follow = true}, &why))
        {
            LOG_WARN(("metrics: head log " + why).c_str());
            return;
        }
        replayer r(*this);
        int64_t named = 0;
        replaying = true;
        const size_t good = read_head_log(
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(data.data()), data.size()), named, r, why);
        replaying = false;
        if (good == 0 || named != window)
        {
            LOG_WARN(("metrics: " + path + " is not a head log of its window (" + why + "), set aside as .damaged").c_str());
            if (::rename(path.c_str(), (path + ".damaged").c_str()) != 0) {}
            return;
        }
        if (good < data.size())
        {
            LOG_WARN(("metrics: " + path + ": " + why + "; the log is cut there").c_str());
            if (::truncate(path.c_str(), static_cast<off_t>(good)) != 0)
                LOG_WARN(("metrics: cannot cut " + path + ": " + std::strerror(errno)).c_str());
        }
        if (r.skipped)
            LOG_WARN(("metrics: " + path + ": " + std::to_string(r.skipped) + " chunks that do not decode skipped").c_str());
        head_log& l = log_at(window);
        l.header = true;
        l.file_bytes = good;
    }

    bool load_meta()
    {
        std::string data;
        if (!read_file(dir + "/meta", data, read_options{.missing_ok = true, .max_bytes = 64u << 20}))
            return false;
        if (data.empty())
            return true;
        const auto* p = reinterpret_cast<const uint8_t*>(data.data());
        if (data.size() < 12 || std::memcmp(p, meta_magic, 8) != 0 ||
            bytes::load32(p + data.size() - 4) != crc::crc32c(p, data.size() - 4))
            return false;
        size_t pos = 8;
        const size_t end = data.size() - 4;
        while (pos < end)
        {
            std::string parts[2];
            uint8_t type = 0;
            for (int i = 0; i < 2; ++i)
            {
                if (end - pos < 4)
                    return false;
                const uint32_t n = bytes::load32(p + pos);
                pos += 4;
                if (end - pos < n)
                    return false;
                parts[i].assign(data, pos, n);
                pos += n;
                if (i == 0)
                {
                    if (pos >= end)
                        return false;
                    type = p[pos++];
                }
            }
            if (type > static_cast<uint8_t>(metric_type::summary))
                return false;
            metas[parts[0]] = meta_entry{static_cast<metric_type>(type), std::move(parts[1])};
        }
        return true;
    }

    void save_meta(durability d)
    {
        if (!metas_dirty)
            return;
        std::string out(meta_magic, 8);
        for (const auto& [name, m] : metas)
        {
            bytes::append32(out, static_cast<uint32_t>(name.size()));
            out += name;
            out += static_cast<char>(m.type);
            bytes::append32(out, static_cast<uint32_t>(m.help.size()));
            out += m.help;
        }
        bytes::append32(out, crc::crc32c(out.data(), out.size()));
        std::string why;
        if (!replace_file(dir + "/meta", out, d, &why))
            LOG_WARN(("metrics: " + why).c_str());
        else
            metas_dirty = false;
    }

    bool open_store(const std::string& d, const store_config& c, std::string& why)
    {
        if (c.keep_raw <= 0)
            return why = "the raw retention must be positive", false;
        if (c.tiers.size() > 8)
            return why = "at most eight tiers", false;
        for (size_t k = 0; k < c.tiers.size(); ++k)
        {
            const int64_t s = c.tiers[k].step;
            if (s < 1000 || c.tiers[k].keep <= 0)
                return why = "a tier needs a step of at least a second and a positive retention", false;
            if (k == 0 && block_ms % s != 0)
                return why = "the first tier's step must divide two hours", false;
            if (k > 0 && (s % c.tiers[k - 1].step != 0 || s <= c.tiers[k - 1].step || day_ms % s != 0))
                return why = "each later tier's step must be a larger multiple of the one before and divide a day", false;
        }
        cfg = c;
        dir = d;
        blocks_dir = dir + "/blocks";
        head_dir = dir + "/head";
        for (const std::string* p : {&dir, &blocks_dir, &head_dir})
            if (!private_dir(*p, true))
                return why = *p + " is not a directory of this user's alone", false;
        blocks.assign(cfg.tiers.size() + 1, {});

        // Blocks: each checked whole, a damaged one set aside, one inside another of its kind dropped.
        std::vector<std::string> names;
        each_entry(blocks_dir, [&](std::string n) { names.push_back(std::move(n)); });
        std::sort(names.begin(), names.end());
        std::vector<std::shared_ptr<block>> loaded;
        for (const std::string& n : names)
        {
            const std::string path = blocks_dir + "/" + n;
            if (n.ends_with(".tmp"))
            {
                ::unlink(path.c_str());
                continue;
            }
            int64_t step = 0, lo = 0, hi = 0;
            if (!parse_block_name(n, step, lo, hi))
                continue;
            if (kind_of(step) < 0)
            {
                LOG_INFO(("metrics: " + path + " is of a tier no longer configured, left alone").c_str());
                continue;
            }
            std::string bwhy;
            auto b = block::open(path, bwhy);
            if (b && (b->step() != step || b->mint() != lo || b->maxt() != hi))
            {
                bwhy = path + ": a footer that disagrees with its name";
                b.reset();
            }
            if (!b)
            {
                ++blocks_refused;
                LOG_WARN(("metrics: block refused and set aside as .damaged: " + bwhy).c_str());
                if (::rename(path.c_str(), (path + ".damaged").c_str()) != 0) {}
                continue;
            }
            loaded.push_back(std::move(b));
        }
        std::sort(loaded.begin(), loaded.end(), [](const auto& a, const auto& b) {
            if (a->step() != b->step())
                return a->step() < b->step();
            if (a->mint() != b->mint())
                return a->mint() < b->mint();
            return a->maxt() > b->maxt();
        });
        int64_t reach = INT64_MIN, reach_step = -1;
        label_set ls;
        std::vector<uint32_t> g;
        for (auto& b : loaded)
        {
            if (b->step() != reach_step)
            {
                reach_step = b->step();
                reach = INT64_MIN;
            }
            if (b->maxt() <= reach)
            {
                // A merge that finished before a crash took its children's place.
                ::unlink(b->path().c_str());
                continue;
            }
            reach = std::max(reach, b->maxt());
            g.assign(b->count(), 0);
            for (uint32_t local = 0; local < b->count(); ++local)
            {
                b->labels(local, ls);
                g[local] = create(ls, false);
            }
            b->set_globals(g);
            if (b->step() == 0 || (!cfg.tiers.empty() && b->step() == cfg.tiers[0].step))
                floor = std::max(floor, b->maxt());
            insert_block(std::move(b));
        }

        // Head logs: a window already cut is deleted, the rest replayed in order.
        names.clear();
        each_entry(head_dir, [&](std::string n) { names.push_back(std::move(n)); });
        std::vector<int64_t> wins;
        for (const std::string& n : names)
        {
            int64_t w = 0;
            if (parse_head_log_name(n, w))
                wins.push_back(w);
        }
        std::sort(wins.begin(), wins.end());
        for (int64_t w : wins)
        {
            if (w + block_ms <= floor)
                ::unlink(log_path(w).c_str());
            else
                replay(log_path(w), w);
        }
        recount();
        if (!load_meta())
            LOG_WARN(("metrics: " + dir + "/meta is damaged, the metrics' types and help start empty").c_str());
        is_open = true;
        return true;
    }

    void stop_store()
    {
        if (!is_open)
            return;
        take_in(bg.wait());
        for (uint32_t id = 0; id < heads.size(); ++id)
            close_open(id, heads[id], true);
        for (head_log& l : logs)
        {
            write_log(l);
            if (l.fd >= 0)
            {
                if (::fdatasync(l.fd) != 0) {}
                ::close(l.fd);
                l.fd = -1;
            }
        }
        bg.stop();
        save_meta(durability::data);
        is_open = false;
    }

    uint64_t ram() const
    {
        uint64_t b = sizeof(*this) + index.bytes() + slab.bytes() + heads.capacity() * sizeof(series_head) +
                     windows.capacity() * sizeof(void*) + logs.capacity() * sizeof(head_log);
        for (const auto& w : windows)
            b += w->ram_bytes();
        for (const auto& l : logs)
            b += l.buf.capacity() + l.samples.bytes();
        for (const auto& list : blocks)
            for (const auto& x : list)
                b += x->ram_bytes();
        for (const auto& [n, m] : metas)
            b += sizeof(meta_entry) + n.capacity() + m.help.capacity() + 64;
        return b;
    }
};

store::store() : m(std::make_unique<impl>()) {}

store::~store() { stop(); }

bool store::open(const std::string& dir, const store_config& cfg, std::string& why)
{
    if (m->is_open)
        return why = "the store is open already", false;
    return m->open_store(dir, cfg, why);
}

uint32_t store::get_or_create(const label_set& ls) { return m->create(ls, true); }

uint32_t store::find(const label_set& ls) const
{
    if (is_normal(ls))
        return m->index.find(ls);
    label_set n;
    return normalize(ls, n) ? m->index.find(n) : no_series;
}

bool store::append(uint32_t id, int64_t t, double v) { return m->append(id, t, v); }

bool store::mark_stale(uint32_t id, int64_t t) { return m->append(id, t, stale_nan()); }

void store::set_meta(std::string_view metric, metric_type type, std::string_view help)
{
    auto it = m->metas.find(metric);
    if (it != m->metas.end() && it->second.type == type && it->second.help == help)
        return;
    m->metas[std::string(metric)] = meta_entry{type, std::string(help)};
    m->metas_dirty = true;
}

int64_t store::tick(int64_t now)
{
    impl& s = *m;
    now = std::clamp(now, -max_abs_time, max_abs_time);
    if (!s.is_open)
        return now + 60'000;
    s.now = std::max(s.now, now);
    s.take_in(s.bg.take());
    s.write_logs(s.cfg.durable);
    if (!s.bg.busy())
    {
        s.retain();
        if (s.retry_after == INT64_MIN || now >= s.retry_after)
            s.plan();
    }
    if (s.bg.busy())
        return now + 1000;
    int64_t next = now + 60'000;
    if (!s.windows.empty())
        next = std::min(next, std::max(now, s.windows.front()->start + block_ms + cut_grace));
    return next;
}

bool store::busy() const { return m->bg.busy(); }

void store::stop() { m->stop_store(); }

store_stats store::stats() const
{
    const impl& s = *m;
    store_stats st;
    st.series = s.index.size();
    st.head_series = s.head_series;
    st.samples_appended = s.appended;
    st.refused_out_of_order = s.out_of_order;
    st.refused_too_old = s.too_old;
    st.refused_series = s.refused_series;
    st.blocks_refused = s.blocks_refused;
    st.maintenance_failures = s.failures;
    for (const auto& list : s.blocks)
        for (const auto& b : list)
        {
            ++st.blocks;
            st.bytes_on_disk += b->file_bytes();
        }
    for (const auto& l : s.logs)
        st.bytes_on_disk += l.file_bytes;
    st.head_windows = s.windows.size();
    for (const auto& w : s.windows)
        st.head_chunks += w->chunks.size();
    st.bytes_in_ram = s.ram();
    return st;
}

void store::select(std::span<const matcher> ms, int64_t mint, int64_t maxt, std::vector<uint32_t>& out)
{
    out.clear();
    m->index.match(ms, m->candidates);
    for (uint32_t id : m->candidates)
        if (m->has_data(id, mint, maxt))
            out.push_back(id);
}

const label_set& store::labels(uint32_t id) const
{
    static const label_set none;
    return id < m->index.size() ? m->index.labels(id) : none;
}

void store::samples(uint32_t id, int64_t mint, int64_t maxt, std::vector<sample>& out)
{
    m->read_samples(id, mint, maxt, out);
}

int64_t store::tier_for(int64_t mint, int64_t resolution) const
{
    int64_t best = 0;
    for (const tier_config& t : m->cfg.tiers)
        if (t.step <= resolution && m->horizon(t.keep) <= mint)
            best = std::max(best, t.step);
    return best;
}

void store::aggregates(uint32_t id, int64_t step, int64_t mint, int64_t maxt, std::vector<agg_point>& out)
{
    const int k = m->kind_of(step);
    mint = std::clamp(mint, -max_abs_time, max_abs_time);
    maxt = std::clamp(maxt, -max_abs_time, max_abs_time);
    if (k <= 0 || id >= m->heads.size() || mint >= maxt)
        return;
    std::vector<tier_point> pts;
    m->collect(static_cast<size_t>(k - 1), id, mint - step, maxt, pts);
    const tier_point* prev = nullptr;
    for (const tier_point& p : pts)
    {
        if (p.t > mint)
            out.push_back(to_agg(p, prev, step));
        prev = &p;
    }
}

void store::label_names(std::vector<std::string>& out) const { m->index.label_names(out); }

void store::label_values(std::string_view name, std::vector<std::string>& out) const { m->index.label_values(name, out); }

metric_type store::type_of(std::string_view metric) const
{
    const auto it = m->metas.find(metric);
    return it == m->metas.end() ? metric_type::untyped : it->second.type;
}

std::string_view store::help_of(std::string_view metric) const
{
    const auto it = m->metas.find(metric);
    return it == m->metas.end() ? std::string_view() : std::string_view(it->second.help);
}

}   // namespace socketley::metrics
