#include "history.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <unordered_set>

#include <fcntl.h>
#include <unistd.h>

namespace history
{

namespace
{

constexpr char magic[8] = {'S', 'K', 'L', 'H', 'I', 'S', 'T', '1'};
constexpr size_t point_bytes = 8 + 6 * 4;

template <typename T>
void put(std::string& out, T v)
{
    char b[sizeof v];
    std::memcpy(b, &v, sizeof v);
    out.append(b, sizeof v);
}

template <typename T>
bool get(std::string_view& in, T& v)
{
    if (in.size() < sizeof v)
        return false;
    std::memcpy(&v, in.data(), sizeof v);
    in.remove_prefix(sizeof v);
    return true;
}

void number(std::string& out, double v)
{
    char b[32];
    const int n = std::snprintf(b, sizeof b, "%.6g", v);
    out.append(b, n > 0 ? static_cast<size_t>(n) : 0);
}

}   // namespace

void keeper::record(int64_t now_ms, const std::vector<std::pair<std::string, reading>>& readings)
{
    // A counter below its last value belongs to a runtime started again, so all of it is new.
    const auto grew = [](uint64_t now, uint64_t before) { return static_cast<double>(now >= before ? now - before : now); };
    std::unordered_set<std::string_view> present;
    for (const auto& [name, r] : readings)
    {
        present.insert(name);
        series& s = m_series[name];
        if (s.last_ms > 0 && now_ms > s.last_ms)
        {
            const double dt = static_cast<double>(now_ms - s.last_ms) / 1000.0;
            point p;
            p.at = now_ms / 1000;
            p.conn = static_cast<float>(r.connections);
            p.msg = static_cast<float>(grew(r.messages, s.last.messages) / dt);
            p.in = static_cast<float>(grew(r.bytes_in, s.last.bytes_in) / dt);
            p.out = static_cast<float>(grew(r.bytes_out, s.last.bytes_out) / dt);
            const double cpu = r.cpu_seconds >= s.last.cpu_seconds ? r.cpu_seconds - s.last.cpu_seconds : r.cpu_seconds;
            p.cpu = static_cast<float>(100.0 * cpu / dt);
            p.rss = static_cast<float>(r.rss_bytes);
            s.points.push_back(p);
            while (!s.points.empty() && s.points.front().at < p.at - span)
                s.points.pop_front();
        }
        s.last = r;
        s.last_ms = now_ms;
    }
    // A runtime not read now keeps its points until they are a day old: the first reading after a restart comes
    // before the runtimes are restored.
    const int64_t oldest = now_ms / 1000 - span;
    for (auto it = m_series.begin(); it != m_series.end();)
    {
        series& s = it->second;
        if (!present.contains(it->first))
        {
            s.last_ms = 0;
            while (!s.points.empty() && s.points.front().at < oldest)
                s.points.pop_front();
        }
        it = s.points.empty() && !present.contains(it->first) ? m_series.erase(it) : std::next(it);
    }
}

std::string keeper::query(std::string_view name, int64_t now_s, int64_t range, size_t points) const
{
    const auto it = m_series.find(std::string(name));
    if (it == m_series.end())
        return {};
    range = std::clamp<int64_t>(range, 60, span);
    points = std::clamp<size_t>(points, 10, 1440);
    const int64_t from = now_s - range;
    const double width = static_cast<double>(range) / static_cast<double>(points);
    std::vector<std::array<double, 6>> sum(points, std::array<double, 6>{});
    std::vector<uint32_t> n(points, 0);
    for (auto p = it->second.points.rbegin(); p != it->second.points.rend() && p->at >= from; ++p)
    {
        const size_t i = std::min(points - 1, static_cast<size_t>(static_cast<double>(p->at - from) / width));
        const float v[6] = {p->conn, p->msg, p->in, p->out, p->cpu, p->rss};
        for (size_t k = 0; k < 6; ++k)
            sum[i][k] += v[k];
        ++n[i];
    }
    std::string j = "{\"from\":" + std::to_string(from) + ",\"step\":";
    number(j, width);
    static constexpr const char* keys[6] = {"conn", "msg", "in", "out", "cpu", "rss"};
    for (size_t k = 0; k < 6; ++k)
    {
        j += ",\"";
        j += keys[k];
        j += "\":[";
        for (size_t i = 0; i < points; ++i)
        {
            if (i)
                j += ',';
            if (n[i])
                number(j, sum[i][k] / n[i]);
            else
                j += "null";
        }
        j += ']';
    }
    j += '}';
    return j;
}

void keeper::load(int64_t now_s)
{
    if (m_path.empty())
        return;
    FILE* f = std::fopen(m_path.c_str(), "rbe");
    if (!f)
        return;
    std::string data;
    char buf[65536];
    for (size_t got; (got = std::fread(buf, 1, sizeof buf, f)) > 0 && data.size() < (64u << 20);)
        data.append(buf, got);
    std::fclose(f);
    std::string_view in(data);
    if (in.size() < sizeof magic || std::memcmp(in.data(), magic, sizeof magic) != 0)
        return;
    in.remove_prefix(sizeof magic);
    uint32_t count = 0;
    if (!get(in, count))
        return;
    std::unordered_map<std::string, series> read;
    for (uint32_t c = 0; c < count; ++c)
    {
        uint16_t len = 0;
        uint32_t npoints = 0;
        if (!get(in, len) || in.size() < len)
            return;
        std::string name(in.substr(0, len));
        in.remove_prefix(len);
        if (!get(in, npoints) || in.size() / point_bytes < npoints)
            return;
        series& s = read[name];
        for (uint32_t i = 0; i < npoints; ++i)
        {
            point p;
            get(in, p.at);
            get(in, p.conn);
            get(in, p.msg);
            get(in, p.in);
            get(in, p.out);
            get(in, p.cpu);
            get(in, p.rss);
            if (p.at >= now_s - span && p.at <= now_s && (s.points.empty() || p.at > s.points.back().at))
                s.points.push_back(p);
        }
    }
    m_series = std::move(read);
}

bool keeper::save() const
{
    if (m_path.empty())
        return false;
    std::string out(magic, sizeof magic);
    put(out, static_cast<uint32_t>(m_series.size()));
    for (const auto& [name, s] : m_series)
    {
        put(out, static_cast<uint16_t>(std::min<size_t>(name.size(), 65535)));
        out.append(name, 0, 65535);
        put(out, static_cast<uint32_t>(s.points.size()));
        for (const point& p : s.points)
        {
            put(out, p.at);
            for (const float v : {p.conn, p.msg, p.in, p.out, p.cpu, p.rss})
                put(out, v);
        }
    }
    const std::string tmp = m_path + ".tmp";
    // Private as the runtimes' files beside it are, and never through a link.
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    FILE* f = fd < 0 ? nullptr : ::fdopen(fd, "wb");
    if (!f)
    {
        if (fd >= 0)
            ::close(fd);
        return false;
    }
    const bool wrote = std::fwrite(out.data(), 1, out.size(), f) == out.size();
    if (std::fclose(f) != 0 || !wrote || std::rename(tmp.c_str(), m_path.c_str()) != 0)
    {
        std::remove(tmp.c_str());
        return false;
    }
    return true;
}

}   // namespace history
