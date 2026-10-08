#include "proxy_auth.h"

#include <arpa/inet.h>
#include <sys/stat.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>

#include <openssl/crypto.h>

#include "../../shared/logging.h"
#include "../storage/checksum.h"
#include "../storage/s3_sigv4_auth.h"

namespace
{

constexpr size_t misses_max = 16384;

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

bool equal_secret(std::string_view a, std::string_view b)
{
    return !a.empty() && a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

// One holder of an IPv6 network has its whole /64, so that is what counts as one address.
std::string miss_key(std::string_view client)
{
    char text[INET6_ADDRSTRLEN]{};
    if (client.size() >= sizeof text)
        return std::string(client);
    std::memcpy(text, client.data(), client.size());
    unsigned char a[16];
    if (::inet_pton(AF_INET6, text, a) == 1)
        return std::string(reinterpret_cast<const char*>(a), 8);
    return std::string(client);
}

}   // namespace

proxy_auth::proxy_auth() = default;
proxy_auth::~proxy_auth() = default;

std::string proxy_auth::spec_error(std::string_view spec)
{
    const bool bearer = spec.starts_with("bearer:"), basic = spec.starts_with("basic:");
    if (!bearer && !basic)
        return "--auth takes bearer:<file of tokens> or basic:<credentials file of a storage runtime>, not '" +
               std::string(spec) + "'";
    const std::string file(spec.substr(bearer ? 7 : 6));
    if (file.empty() || file.front() != '/')
        return "--auth: the file is given by its absolute path, not '" + file + "'";
    return {};
}

void proxy_auth::configure(std::string_view spec, std::string_view runtime)
{
    m_kind = spec.starts_with("bearer:") ? kind::bearer : spec.starts_with("basic:") ? kind::basic : kind::none;
    m_file.assign(m_kind == kind::none ? std::string_view{} : spec.substr(m_kind == kind::bearer ? 7 : 6));
    m_runtime.assign(runtime);
    m_challenge = m_kind == kind::basic ? "WWW-Authenticate: Basic realm=\"" + m_runtime + "\", charset=\"UTF-8\"\r\n"
                                        : "WWW-Authenticate: Bearer realm=\"" + m_runtime + "\"\r\n";
    m_stamp = -1;
    m_loaded = false;
    m_tokens.clear();
    m_keys.reset();
    m_misses.clear();
}

void proxy_auth::reload(std::chrono::steady_clock::time_point now)
{
    if (m_stamp >= 0 && now - m_checked < std::chrono::seconds(1))
        return;
    m_checked = now;
    struct stat st{};
    const int64_t stamp = ::stat(m_file.c_str(), &st) != 0
                              ? 0
                              : static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec +
                                    static_cast<int64_t>(st.st_size) + static_cast<int64_t>(st.st_ino);
    if (stamp == m_stamp)
        return;
    m_stamp = stamp;
    m_loaded = false;
    m_tokens.clear();
    m_keys.reset();

    std::ifstream f(m_file);
    std::stringstream ss;
    ss << f.rdbuf();
    if (!f)
    {
        LOG_ERROR(("proxy " + m_runtime + ": --auth: " + m_file + " cannot be read; every request is refused").c_str());
        return;
    }
    const std::string text = ss.str();
    if (m_kind == kind::bearer)
    {
        for (size_t p = 0; p < text.size();)
        {
            const size_t nl = std::min(text.find('\n', p), text.size());
            const std::string_view line = trim(std::string_view(text).substr(p, nl - p));
            if (!line.empty() && line.front() != '#')
                m_tokens.emplace_back(line);
            p = nl + 1;
        }
        m_loaded = !m_tokens.empty();
        if (!m_loaded)
            LOG_ERROR(("proxy " + m_runtime + ": --auth: " + m_file + " holds no token; every request is refused").c_str());
        return;
    }
    auto keys = std::make_unique<socketley::storage::credential_set>();
    std::string err;
    const std::string dir = m_file.substr(0, m_file.rfind('/'));
    if (!socketley::storage::parse_credentials(text, *keys, err, dir))
    {
        LOG_ERROR(("proxy " + m_runtime + ": --auth: " + m_file + ": " + err + "; every request is refused").c_str());
        return;
    }
    m_keys = std::move(keys);
    m_loaded = true;
}

bool proxy_auth::admit(std::string_view authorization) const
{
    if (!m_loaded)
        return false;
    const size_t sp = authorization.find(' ');
    if (sp == std::string_view::npos)
        return false;
    const std::string_view scheme = authorization.substr(0, sp);
    const std::string_view value = trim(authorization.substr(sp + 1));
    const auto scheme_is = [&](std::string_view want) {
        return scheme.size() == want.size() &&
               std::equal(want.begin(), want.end(), scheme.begin(), [](char w, char c) { return w == (c | 0x20); });
    };
    if (m_kind == kind::bearer)
    {
        if (!scheme_is("bearer"))
            return false;
        // Every token is compared, so how long a refusal takes says nothing about which came close.
        bool ok = false;
        for (const std::string& t : m_tokens)
            ok = equal_secret(t, value) || ok;
        return ok;
    }
    std::string pair;
    if (!scheme_is("basic") || !socketley::storage::base64_decode(value, pair))
        return false;
    const size_t colon = pair.find(':');
    if (colon == std::string::npos)
        return false;
    const std::string_view key = std::string_view(pair).substr(0, colon);
    const std::string_view secret = std::string_view(pair).substr(colon + 1);
    if (!equal_secret(m_keys->secret(key), secret))
        return false;
    // A key outside any [user] signs for the default owner, who is an admin.
    const auto user = m_keys->user_of(key);
    return !user || user->admin;
}

void proxy_auth::missed(const std::string& key, std::chrono::steady_clock::time_point now)
{
    if (m_misses.size() >= misses_max && !m_misses.contains(key))
    {
        std::erase_if(m_misses, [&](const auto& m) { return now - m.second.first >= window; });
        if (m_misses.size() >= misses_max)
            m_misses.erase(std::min_element(m_misses.begin(), m_misses.end(), [](const auto& a, const auto& b)
                                            { return a.second.first < b.second.first; }));
    }
    misses& m = m_misses[key];
    if (m.count == 0 || now - m.first >= window)
    {
        m.count = 0;
        m.first = now;
    }
    ++m.count;
}

proxy_auth::verdict proxy_auth::check(std::string_view authorization, std::string_view client, int64_t& retry_after)
{
    if (m_kind == kind::none)
        return verdict::pass;
    const auto now = std::chrono::steady_clock::now();
    reload(now);
    const std::string key = miss_key(client);
    if (const auto it = m_misses.find(key); it != m_misses.end())
    {
        if (now - it->second.first >= window)
            m_misses.erase(it);
        else if (it->second.count >= tries)
        {
            retry_after = std::max<int64_t>(
                1, std::chrono::ceil<std::chrono::seconds>(it->second.first + window - now).count());
            return verdict::barred;
        }
    }
    if (admit(authorization))
        return verdict::pass;
    // A request that offered nothing is a browser asking what to offer, not a guess.
    if (authorization.empty())
        return verdict::refuse;
    missed(key, now);
    LOG_WARN(("proxy " + m_runtime + ": authorization refused from " + std::string(client)).c_str());
    return verdict::refuse;
}
