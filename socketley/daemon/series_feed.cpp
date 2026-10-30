#include "series_feed.h"

#include <bit>
#include <unistd.h>

#include "metrics_endpoint.h"
#include "../shared/persist/paths.h"

struct series_walk::facts
{
    metrics_endpoint::fact_cache cache;
};

series_walk::series_walk(runtime_manager& manager)
    : m_manager(manager), m_facts(std::make_unique<facts>()),
      m_state_dir(socketley_paths::resolve().state_dir.string())
{
    // The instance a scrape of this daemon would be told apart by is its host, and the feed's series say the same.
    char host[256] = {};
    if (::gethostname(host, sizeof host - 1) == 0 && host[0])
        m_instance = host;
    else
        m_instance = "localhost";
}

series_walk::~series_walk() = default;

std::string series_walk::answer(std::shared_ptr<void>& state, std::string_view payload)
{
    uint64_t ticket = 0;
    uint8_t flags = 0;
    if (!worker_proto::decode_series_pull(payload, ticket, flags))
        return {};
    const bool resync = (flags & worker_proto::series_resync) || !state;
    if (!state)
        state = std::make_shared<series_feed>();
    auto& feed = *static_cast<series_feed*>(state.get());
    feed.begin(resync);
    series_feed::encoder enc(feed);
    metrics_endpoint::walk_series(m_manager, m_facts->cache, m_state_dir, true, enc);
    return worker_proto::frame(worker_proto::frame_type::series_feed, feed.finish(ticket, m_instance));
}

void series_feed::encoder::operator()(const socketley::metric_catalog::series& s)
{
    m_feed.add(s);
}

void series_feed::begin(bool resync)
{
    ++m_gen;
    m_flags = resync ? worker_proto::series_resync : 0;
    if (!resync)
        return;
    m_keys.clear();
    m_fams.clear();
    m_free.clear();
    m_next_key = 0;
}

void series_feed::add(const socketley::metric_catalog::series& s)
{
    // A series is its family's name and its labels in order, which the walk gives the same way every time.
    m_buf.clear();
    m_buf += s.fam->name;
    m_buf += '\0';
    for (const auto& l : s.labels)
    {
        m_buf += l.name;
        m_buf += '\1';
        m_buf += l.value;
        m_buf += '\2';
    }
    const uint64_t bits = std::bit_cast<uint64_t>(s.value);
    if (const auto it = m_keys.find(m_buf); it != m_keys.end())
    {
        key& k = it->second;
        if (k.seen == m_gen)
            return;
        k.seen = m_gen;
        if (k.bits != bits)
        {
            k.bits = bits;
            m_w.value(k.id, s.value);
        }
        return;
    }
    uint32_t fam = 0;
    if (const auto f = m_fams.find(s.fam->name); f != m_fams.end())
        fam = f->second;
    else
    {
        fam = static_cast<uint32_t>(m_fams.size());
        m_fams.emplace(s.fam->name, fam);
        m_w.family(fam, static_cast<uint8_t>(s.fam->type), s.fam->name, s.fam->help);
    }
    uint32_t id = m_next_key;
    if (!m_free.empty())
    {
        id = m_free.back();
        m_free.pop_back();
    }
    else
        ++m_next_key;
    m_keys.emplace(m_buf, key{id, bits, m_gen});
    m_w.key(id, fam, s.labels);
    m_w.value(id, s.value);
}

std::string series_feed::finish(uint64_t ticket, std::string_view instance)
{
    // Freed only once the frame is built, so no id is both gone and new in one answer.
    std::vector<uint32_t> freed;
    for (auto it = m_keys.begin(); it != m_keys.end();)
    {
        if (it->second.seen != m_gen)
        {
            m_w.gone(it->second.id);
            freed.push_back(it->second.id);
            it = m_keys.erase(it);
        }
        else
            ++it;
    }
    m_free.insert(m_free.end(), freed.begin(), freed.end());
    return m_w.finish(ticket, m_flags, instance);
}
