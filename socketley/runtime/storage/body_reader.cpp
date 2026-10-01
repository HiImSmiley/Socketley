#include "body_reader.h"

#include <algorithm>
#include <cerrno>
#include <vector>

namespace socketley::storage
{

namespace
{

constexpr uint64_t window_bytes = 1u << 20;
// A window this small is opened where it lands, since the hop to a thread costs more.
constexpr size_t open_inline_max = 64 * 1024;

// Whether a window that has reached plaintext `end` takes chunk `c` too: one holding bytes before it, or an
// empty last chunk right at it, which is what proves a stream read to its end was not cut short.
bool takes(const sse_layout::chunk& c, uint64_t end, uint64_t plain, uint64_t budget)
{
    if (c.plain_len == 0)
        return c.plain_off <= end;
    return c.plain_off < end && plain < budget;
}

}   // namespace

std::shared_ptr<body_reader> body_reader::make(file_io& io, hash_pool* pool, std::shared_ptr<bool> alive, int fd,
                                               uint64_t data_off, const object_meta& m, const sse_key* key,
                                               uint64_t first, uint64_t len)
{
    std::shared_ptr<body_reader> r(new body_reader);
    // A part list kept after the body is read before the first window, which is the only one that needs it.
    if (key && part_trailer_of(m, r->m_trailer))
        r->m_meta = std::make_unique<object_meta>(m);
    else if (key && !r->m_layout.init(m))
        return nullptr;
    r->m_io       = &io;
    r->m_pool     = pool && pool->enabled() ? pool : nullptr;
    r->m_lane     = r->m_pool ? r->m_pool->next_lane() : 0;
    r->m_alive    = std::move(alive);
    r->m_fd       = fd;
    r->m_data_off = data_off;
    if (key)
        r->m_key = *key;
    r->m_pos = first;
    r->m_end = first + len;
    return r;
}

void body_reader::next(deliver cb)
{
    if (m_held >= 0)
    {
        m_slots[m_held].state = slot_state::idle;
        m_held = -1;
    }
    m_waiter = std::move(cb);
    // A list that could not be read leaves nothing to deliver, which every later call is told too.
    if (m_list_failed)
    {
        auto w = std::move(m_waiter);
        m_waiter = nullptr;
        w(false, {});
        return;
    }
    if (m_meta)
    {
        load_list();
        return;
    }
    fetch();
    hand_out();
}

void body_reader::load_list()
{
    if (m_list_reading)
        return;
    m_list_reading = true;
    auto buf  = std::make_shared<std::string>(static_cast<size_t>(m_trailer.len), '\0');
    auto self = shared_from_this();
    auto failed = [this]
    {
        m_meta.reset();
        m_list_failed = true;
        auto cb = std::move(m_waiter);
        m_waiter = nullptr;
        if (cb)
            cb(false, {});
    };
    const bool q = m_io->pread(m_fd, buf->data(), static_cast<uint32_t>(buf->size()), m_data_off + m_trailer.at,
        [self, buf, failed](int64_t res)
        {
            if (!*self->m_alive)
                return;
            part_list list;
            if (res != static_cast<int64_t>(buf->size()) ||
                !decode_part_trailer(*buf, *self->m_meta, self->m_trailer, list) ||
                !self->m_layout.init(*self->m_meta, &list))
            {
                failed();
                return;
            }
            self->m_meta.reset();
            self->fetch();
            self->hand_out();
        });
    if (!q)
        failed();
}

void body_reader::hand_out()
{
    if (!m_waiter)
        return;
    if (m_order.empty())
    {
        if (m_pos < m_end)
            return;
        auto cb = std::move(m_waiter);
        m_waiter = nullptr;
        cb(true, {});
        return;
    }
    const int i = m_order.front();
    slot& s = m_slots[i];
    if (s.state == slot_state::busy)
        return;
    auto cb = std::move(m_waiter);
    m_waiter = nullptr;
    if (s.state == slot_state::failed)
    {
        cb(false, {});
        return;
    }
    m_order.pop_front();
    m_held = i;
    // The window may be all a consumer needs, which then lets go of this reader inside the call.
    auto self = shared_from_this();
    cb(true, std::string_view(*s.plain).substr(s.skip, s.len));
    // Ready while the consumer was using the last one, so the following window is read already.
    fetch();
}

void body_reader::fetch()
{
    while (m_pos < m_end && m_order.size() < 2)
    {
        int i = -1;
        for (int k = 0; k < 2; ++k)
            if (k != m_held && m_slots[k].state == slot_state::idle &&
                std::find(m_order.begin(), m_order.end(), k) == m_order.end())
                i = k;
        if (i < 0)
            return;
        slot& s = m_slots[i];
        if (!s.plain)
            s.plain = std::make_shared<std::string>();
        uint64_t off = 0, want = 0;
        auto chunks = std::make_shared<std::vector<sse_layout::chunk>>();
        if (!m_key)
        {
            want = std::min(window_bytes, m_end - m_pos);
            off  = m_data_off + m_pos;
            s.skip = 0;
            s.len  = static_cast<size_t>(want);
            s.plain->resize(s.len);
            m_pos += want;
        }
        else
        {
            // Whole chunks from the one that holds the next byte, a window's worth or to the end of the range.
            const sse_layout::chunk head = m_layout.at(m_pos);
            uint64_t at = head.plain_off;
            uint64_t stored = 0, plain = 0;
            sse_layout::chunk c = head;
            do
            {
                chunks->push_back(c);
                stored += c.stored();
                plain  += c.plain_len;
                at      = c.plain_off + c.plain_len;
            } while (m_layout.next(c) && takes(c, m_end, plain, window_bytes));
            off    = m_data_off + head.cipher_off;
            want   = stored;
            s.skip = static_cast<size_t>(m_pos - head.plain_off);
            s.len  = static_cast<size_t>(std::min(at, m_end) - m_pos);
            if (!s.cipher)
                s.cipher = std::make_shared<std::string>();
            s.cipher->resize(static_cast<size_t>(stored));
            s.plain->resize(static_cast<size_t>(plain));
            m_pos = std::min(at, m_end);
        }
        s.state = slot_state::busy;
        m_order.push_back(i);
        char* into = m_key ? s.cipher->data() : s.plain->data();
        auto self = shared_from_this();
        const bool q = m_io->pread(m_fd, into, static_cast<uint32_t>(want), off,
            [self, i, want, chunks](int64_t res)
            {
                if (!*self->m_alive)
                    return;
                self->read_done(i, res, want, chunks);
            });
        if (!q)
        {
            s.state = slot_state::failed;
            m_pos   = m_end;
        }
    }
}

void body_reader::read_done(int index, int64_t res, uint64_t want, std::shared_ptr<std::vector<sse_layout::chunk>> chunks)
{
    slot& s = m_slots[index];
    if (res != static_cast<int64_t>(want))
    {
        s.state = slot_state::failed;
        hand_out();
        return;
    }
    if (!m_key)
    {
        s.state = slot_state::ready;
        hand_out();
        return;
    }
    auto ok = std::make_shared<bool>(false);
    auto work = [key = *m_key, version = m_layout.version(), chunks, cipher = s.cipher, plain = s.plain, ok]
    {
        *ok = sse_open(key, version, chunks->data(), chunks->size(), cipher->data(), plain->data());
    };
    if (m_pool && want > open_inline_max)
    {
        m_pool->submit(m_lane, std::move(work), [self = shared_from_this(), index, ok]
        {
            if (!*self->m_alive)
                return;
            self->m_slots[index].state = *ok ? slot_state::ready : slot_state::failed;
            self->hand_out();
        });
        return;
    }
    work();
    s.state = *ok ? slot_state::ready : slot_state::failed;
    hand_out();
}

bool sse_open_body(const object_meta& m, const sse_key& key, std::string_view stored, std::string& plain)
{
    sse_layout l;
    part_list  list;
    part_trailer t;
    const bool trailer = part_trailer_of(m, t);
    if (trailer && (stored.size() < t.at + t.len || !decode_part_trailer(stored.substr(t.at, t.len), m, t, list)))
        return false;
    if (!l.init(m, trailer ? &list : nullptr) || stored.size() < l.stored())
        return false;
    plain.resize(static_cast<size_t>(m.size));
    // Every chunk on disk, the empty ones that end a stream too, which are the proof it was not cut short.
    std::vector<sse_layout::chunk> all;
    sse_layout::chunk c;
    for (bool more = l.first(c); more; more = l.next(c))
        all.push_back(c);
    return sse_open(key, l.version(), all.data(), all.size(), stored.data(), plain.data());
}

}   // namespace socketley::storage
