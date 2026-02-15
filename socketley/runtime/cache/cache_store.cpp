#include "cache_store.h"
#include <fstream>
#include <cstring>
#include <random>

// ─── Type conflict checks (fast-path: empty() avoids hash lookups) ───

bool cache_store::has_type_conflict_for_string(std::string_view key) const
{
    if (!m_lists.empty() && m_lists.count(key)) return true;
    if (!m_sets.empty() && m_sets.count(key)) return true;
    if (!m_hashes.empty() && m_hashes.count(key)) return true;
    return false;
}

bool cache_store::has_type_conflict_for_list(std::string_view key) const
{
    if (!m_data.empty() && m_data.count(key)) return true;
    if (!m_sets.empty() && m_sets.count(key)) return true;
    if (!m_hashes.empty() && m_hashes.count(key)) return true;
    return false;
}

bool cache_store::has_type_conflict_for_set(std::string_view key) const
{
    if (!m_data.empty() && m_data.count(key)) return true;
    if (!m_lists.empty() && m_lists.count(key)) return true;
    if (!m_hashes.empty() && m_hashes.count(key)) return true;
    return false;
}

bool cache_store::has_type_conflict_for_hash(std::string_view key) const
{
    if (!m_data.empty() && m_data.count(key)) return true;
    if (!m_lists.empty() && m_lists.count(key)) return true;
    if (!m_sets.empty() && m_sets.count(key)) return true;
    return false;
}

// ─── Strings ───

bool cache_store::set(std::string_view key, std::string_view value)
{
    if (has_type_conflict_for_string(key))
        return false;

    if (auto it = m_data.find(key); it != m_data.end())
    {
        track_sub(it->second.size());
        it->second = value;
        track_add(value.size());
        touch_lru(key);
        return true;
    }

    if (!check_memory(key.size() + value.size()))
        return false;

    m_data.emplace(std::string(key), std::string(value));
    track_add(key.size() + value.size());
    touch_lru(key);
    return true;
}

bool cache_store::get(std::string_view key, std::string& out) const
{
    auto it = m_data.find(key);
    if (it == m_data.end())
        return false;

    out = it->second;
    return true;
}

const std::string* cache_store::get_ptr(std::string_view key) const
{
    auto it = m_data.find(key);
    if (it == m_data.end())
        return nullptr;
    const_cast<cache_store*>(this)->touch_lru(key);
    return &it->second;
}

// ─── Lists ───

bool cache_store::lpush(std::string_view key, std::string_view val)
{
    auto it = m_lists.find(key);
    if (it != m_lists.end())
    {
        if (!check_memory(val.size()))
            return false;
        it->second.emplace_front(val);
        track_add(val.size());
        touch_lru(key);
        return true;
    }

    if (has_type_conflict_for_list(key))
        return false;

    if (!check_memory(key.size() + val.size()))
        return false;

    m_lists.emplace(std::string(key), std::deque<std::string>{}).first->second.emplace_front(val);
    track_add(key.size() + val.size());
    touch_lru(key);
    return true;
}

bool cache_store::rpush(std::string_view key, std::string_view val)
{
    auto it = m_lists.find(key);
    if (it != m_lists.end())
    {
        if (!check_memory(val.size()))
            return false;
        it->second.emplace_back(val);
        track_add(val.size());
        touch_lru(key);
        return true;
    }

    if (has_type_conflict_for_list(key))
        return false;

    if (!check_memory(key.size() + val.size()))
        return false;

    m_lists.emplace(std::string(key), std::deque<std::string>{}).first->second.emplace_back(val);
    track_add(key.size() + val.size());
    touch_lru(key);
    return true;
}

bool cache_store::lpop(std::string_view key, std::string& out)
{
    auto it = m_lists.find(key);
    if (it == m_lists.end() || it->second.empty())
        return false;

    out = std::move(it->second.front());
    it->second.pop_front();
    track_sub(out.size());

    if (it->second.empty())
    {
        track_sub(key.size());
        m_lists.erase(it);
        m_expiry.erase(std::string(key));
        m_lru_map.erase(std::string(key));
    }
    return true;
}

bool cache_store::rpop(std::string_view key, std::string& out)
{
    auto it = m_lists.find(key);
    if (it == m_lists.end() || it->second.empty())
        return false;

    out = std::move(it->second.back());
    it->second.pop_back();
    track_sub(out.size());

    if (it->second.empty())
    {
        track_sub(key.size());
        m_lists.erase(it);
        m_expiry.erase(std::string(key));
        m_lru_map.erase(std::string(key));
    }
    return true;
}

int cache_store::llen(std::string_view key) const
{
    auto it = m_lists.find(key);
    if (it == m_lists.end())
        return 0;
    return static_cast<int>(it->second.size());
}

const std::deque<std::string>* cache_store::list_ptr(std::string_view key) const
{
    auto it = m_lists.find(key);
    if (it == m_lists.end())
        return nullptr;
    return &it->second;
}

const std::string* cache_store::lindex(std::string_view key, int idx) const
{
    auto it = m_lists.find(key);
    if (it == m_lists.end())
        return nullptr;

    const auto& deq = it->second;
    int len = static_cast<int>(deq.size());

    if (idx < 0)
        idx += len;
    if (idx < 0 || idx >= len)
        return nullptr;

    return &deq[static_cast<size_t>(idx)];
}

// ─── Sets ───

int cache_store::sadd(std::string_view key, std::string_view member)
{
    auto it = m_sets.find(key);
    if (it != m_sets.end())
    {
        if (!check_memory(member.size()))
            return -1;
        auto [_, inserted] = it->second.emplace(member);
        if (inserted)
        {
            track_add(member.size());
            touch_lru(key);
        }
        return inserted ? 1 : 0;
    }

    if (has_type_conflict_for_set(key))
        return -1;

    if (!check_memory(key.size() + member.size()))
        return -1;

    auto& s = m_sets.emplace(std::string(key), set_inner{}).first->second;
    s.emplace(member);
    track_add(key.size() + member.size());
    touch_lru(key);
    return 1;
}

bool cache_store::srem(std::string_view key, std::string_view member)
{
    auto it = m_sets.find(key);
    if (it == m_sets.end())
        return false;

    auto mit = it->second.find(member);
    if (mit == it->second.end())
        return false;

    track_sub(mit->size());
    it->second.erase(mit);

    if (it->second.empty())
    {
        track_sub(key.size());
        m_sets.erase(it);
        m_expiry.erase(std::string(key));
        m_lru_map.erase(std::string(key));
    }
    return true;
}

bool cache_store::sismember(std::string_view key, std::string_view member) const
{
    auto it = m_sets.find(key);
    if (it == m_sets.end())
        return false;
    return it->second.count(member) > 0;
}

int cache_store::scard(std::string_view key) const
{
    auto it = m_sets.find(key);
    if (it == m_sets.end())
        return 0;
    return static_cast<int>(it->second.size());
}

const set_inner* cache_store::set_ptr(std::string_view key) const
{
    auto it = m_sets.find(key);
    if (it == m_sets.end())
        return nullptr;
    return &it->second;
}

// ─── Hashes ───

bool cache_store::hset(std::string_view key, std::string_view field, std::string_view val)
{
    auto it = m_hashes.find(key);
    if (it != m_hashes.end())
    {
        auto fit = it->second.find(field);
        if (fit != it->second.end())
        {
            track_sub(fit->second.size());
            fit->second = val;
            track_add(val.size());
        }
        else
        {
            if (!check_memory(field.size() + val.size()))
                return false;
            it->second.emplace(std::string(field), std::string(val));
            track_add(field.size() + val.size());
        }
        touch_lru(key);
        return true;
    }

    if (has_type_conflict_for_hash(key))
        return false;

    if (!check_memory(key.size() + field.size() + val.size()))
        return false;

    auto& h = m_hashes.emplace(std::string(key), hash_inner{}).first->second;
    h.emplace(std::string(field), std::string(val));
    track_add(key.size() + field.size() + val.size());
    touch_lru(key);
    return true;
}

const std::string* cache_store::hget(std::string_view key, std::string_view field) const
{
    auto it = m_hashes.find(key);
    if (it == m_hashes.end())
        return nullptr;

    auto fit = it->second.find(field);
    if (fit == it->second.end())
        return nullptr;

    return &fit->second;
}

bool cache_store::hdel(std::string_view key, std::string_view field)
{
    auto it = m_hashes.find(key);
    if (it == m_hashes.end())
        return false;

    auto fit = it->second.find(field);
    if (fit == it->second.end())
        return false;

    track_sub(fit->first.size() + fit->second.size());
    it->second.erase(fit);

    if (it->second.empty())
    {
        track_sub(key.size());
        m_hashes.erase(it);
        m_expiry.erase(std::string(key));
        m_lru_map.erase(std::string(key));
    }
    return true;
}

int cache_store::hlen(std::string_view key) const
{
    auto it = m_hashes.find(key);
    if (it == m_hashes.end())
        return 0;
    return static_cast<int>(it->second.size());
}

const hash_inner* cache_store::hash_ptr(std::string_view key) const
{
    auto it = m_hashes.find(key);
    if (it == m_hashes.end())
        return nullptr;
    return &it->second;
}

// ─── TTL / Expiry ───

bool cache_store::set_expiry(std::string_view key, int seconds)
{
    if (!exists(key))
        return false;

    auto tp = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    auto it = m_expiry.find(key);
    if (it != m_expiry.end())
        it->second = tp;
    else
        m_expiry.emplace(std::string(key), tp);
    return true;
}

int cache_store::get_ttl(std::string_view key) const
{
    if (!exists(key))
        return -2;

    auto it = m_expiry.find(key);
    if (it == m_expiry.end())
        return -1;

    auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
        it->second - std::chrono::steady_clock::now());
    return static_cast<int>(remaining.count());
}

bool cache_store::persist(std::string_view key)
{
    auto it = m_expiry.find(key);
    if (it == m_expiry.end())
        return false;
    m_expiry.erase(it);
    return true;
}

void cache_store::check_expiry(std::string_view key)
{
    if (m_expiry.empty())
        return;

    auto it = m_expiry.find(key);
    if (it == m_expiry.end())
        return;

    if (std::chrono::steady_clock::now() < it->second)
        return;

    // Expired — remove from all containers
    m_expiry.erase(it);
    if (auto sit = m_data.find(key); sit != m_data.end()) { m_data.erase(sit); return; }
    if (auto lit = m_lists.find(key); lit != m_lists.end()) { m_lists.erase(lit); return; }
    if (auto eit = m_sets.find(key); eit != m_sets.end()) { m_sets.erase(eit); return; }
    if (auto hit = m_hashes.find(key); hit != m_hashes.end()) { m_hashes.erase(hit); return; }
}

// ─── General ───

bool cache_store::del(std::string_view key)
{
    m_expiry.erase(std::string(key));

    // Remove from LRU
    if (auto lit = m_lru_map.find(std::string(key)); lit != m_lru_map.end())
    {
        m_lru_order.erase(lit->second);
        m_lru_map.erase(lit);
    }

    if (auto it = m_data.find(key); it != m_data.end())
    {
        track_sub(it->first.size() + it->second.size());
        m_data.erase(it);
        return true;
    }
    if (auto it = m_lists.find(key); it != m_lists.end())
    {
        size_t mem = it->first.size();
        for (const auto& e : it->second) mem += e.size();
        track_sub(mem);
        m_lists.erase(it);
        return true;
    }
    if (auto it = m_sets.find(key); it != m_sets.end())
    {
        size_t mem = it->first.size();
        for (const auto& e : it->second) mem += e.size();
        track_sub(mem);
        m_sets.erase(it);
        return true;
    }
    if (auto it = m_hashes.find(key); it != m_hashes.end())
    {
        size_t mem = it->first.size();
        for (const auto& [f, v] : it->second) mem += f.size() + v.size();
        track_sub(mem);
        m_hashes.erase(it);
        return true;
    }
    return false;
}

uint32_t cache_store::size() const
{
    return static_cast<uint32_t>(m_data.size() + m_lists.size() + m_sets.size() + m_hashes.size());
}

bool cache_store::exists(std::string_view key) const
{
    if (m_data.count(key)) return true;
    if (!m_lists.empty() && m_lists.count(key)) return true;
    if (!m_sets.empty() && m_sets.count(key)) return true;
    if (!m_hashes.empty() && m_hashes.count(key)) return true;
    return false;
}

// ─── Persistence ───

static constexpr char MAGIC_V2[4] = {'S', 'K', 'V', '2'};

enum : uint8_t { TYPE_STRING = 0, TYPE_LIST = 1, TYPE_SET = 2, TYPE_HASH = 3 };

bool cache_store::save(std::string_view path) const
{
    return save_v2(path);
}

bool cache_store::save_v2(std::string_view path) const
{
    std::ofstream file(std::string(path), std::ios::binary | std::ios::trunc);
    if (!file)
        return false;

    auto now = std::chrono::steady_clock::now();

    file.write(MAGIC_V2, 4);

    auto write_key = [&](uint8_t type, std::string_view key) {
        file.write(reinterpret_cast<const char*>(&type), 1);
        uint32_t klen = static_cast<uint32_t>(key.size());
        file.write(reinterpret_cast<const char*>(&klen), sizeof(klen));
        file.write(key.data(), klen);
    };

    auto write_string = [&](std::string_view s) {
        uint32_t len = static_cast<uint32_t>(s.size());
        file.write(reinterpret_cast<const char*>(&len), sizeof(len));
        file.write(s.data(), len);
    };

    auto write_expiry = [&](std::string_view key) {
        auto eit = m_expiry.find(key);
        if (eit == m_expiry.end())
        {
            uint8_t has = 0;
            file.write(reinterpret_cast<const char*>(&has), 1);
        }
        else
        {
            uint8_t has = 1;
            file.write(reinterpret_cast<const char*>(&has), 1);
            int64_t remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                eit->second - now).count();
            if (remaining_ms < 0) remaining_ms = 0;
            file.write(reinterpret_cast<const char*>(&remaining_ms), sizeof(remaining_ms));
        }
    };

    // Strings
    for (const auto& [key, value] : m_data)
    {
        write_key(TYPE_STRING, key);
        write_string(value);
        write_expiry(key);
    }

    // Lists
    for (const auto& [key, deq] : m_lists)
    {
        write_key(TYPE_LIST, key);
        uint32_t count = static_cast<uint32_t>(deq.size());
        file.write(reinterpret_cast<const char*>(&count), sizeof(count));
        for (const auto& elem : deq)
            write_string(elem);
        write_expiry(key);
    }

    // Sets
    for (const auto& [key, s] : m_sets)
    {
        write_key(TYPE_SET, key);
        uint32_t count = static_cast<uint32_t>(s.size());
        file.write(reinterpret_cast<const char*>(&count), sizeof(count));
        for (const auto& member : s)
            write_string(member);
        write_expiry(key);
    }

    // Hashes
    for (const auto& [key, h] : m_hashes)
    {
        write_key(TYPE_HASH, key);
        uint32_t count = static_cast<uint32_t>(h.size());
        file.write(reinterpret_cast<const char*>(&count), sizeof(count));
        for (const auto& [field, val] : h)
        {
            write_string(field);
            write_string(val);
        }
        write_expiry(key);
    }

    return file.good();
}

bool cache_store::load(std::string_view path)
{
    std::ifstream file(std::string(path), std::ios::binary);
    if (!file)
        return false;

    // Read first 4 bytes to detect format
    char header[4]{};
    file.read(header, 4);
    if (!file)
        return false;

    if (std::memcmp(header, MAGIC_V2, 4) == 0)
        return load_v2(file);

    // v1 format: first 4 bytes were key_len
    uint32_t first_key_len;
    std::memcpy(&first_key_len, header, sizeof(first_key_len));
    return load_v1(file, first_key_len);
}

bool cache_store::load_v2(std::ifstream& file)
{
    m_data.clear();
    m_lists.clear();
    m_sets.clear();
    m_hashes.clear();
    m_expiry.clear();
    m_current_memory = 0;
    m_lru_order.clear();
    m_lru_map.clear();

    auto now = std::chrono::steady_clock::now();

    auto read_string = [&](std::string& out) -> bool {
        uint32_t len = 0;
        file.read(reinterpret_cast<char*>(&len), sizeof(len));
        if (!file) return false;
        out.resize(len);
        file.read(out.data(), len);
        return file.good() || file.eof();
    };

    auto read_expiry = [&](const std::string& key) {
        uint8_t has = 0;
        file.read(reinterpret_cast<char*>(&has), 1);
        if (has)
        {
            int64_t remaining_ms = 0;
            file.read(reinterpret_cast<char*>(&remaining_ms), sizeof(remaining_ms));
            if (remaining_ms > 0)
                m_expiry[key] = now + std::chrono::milliseconds(remaining_ms);
            // If remaining_ms <= 0, key is already expired — don't restore
        }
    };

    while (file)
    {
        uint8_t type = 0;
        file.read(reinterpret_cast<char*>(&type), 1);
        if (!file) break;

        std::string key;
        if (!read_string(key)) break;

        bool expired = false;

        switch (type)
        {
            case TYPE_STRING:
            {
                std::string value;
                if (!read_string(value)) return false;
                // Read expiry first to check if expired
                uint8_t has = 0;
                file.read(reinterpret_cast<char*>(&has), 1);
                if (has)
                {
                    int64_t remaining_ms = 0;
                    file.read(reinterpret_cast<char*>(&remaining_ms), sizeof(remaining_ms));
                    if (remaining_ms > 0)
                        m_expiry[key] = now + std::chrono::milliseconds(remaining_ms);
                    else
                        expired = true;
                }
                if (!expired)
                    m_data[std::move(key)] = std::move(value);
                break;
            }
            case TYPE_LIST:
            {
                uint32_t count = 0;
                file.read(reinterpret_cast<char*>(&count), sizeof(count));
                if (!file) return false;
                std::deque<std::string> deq;
                for (uint32_t i = 0; i < count; i++)
                {
                    std::string elem;
                    if (!read_string(elem)) return false;
                    deq.push_back(std::move(elem));
                }
                read_expiry(key);
                if (!m_expiry.count(key) || m_expiry[key] > now)
                    m_lists[std::move(key)] = std::move(deq);
                break;
            }
            case TYPE_SET:
            {
                uint32_t count = 0;
                file.read(reinterpret_cast<char*>(&count), sizeof(count));
                if (!file) return false;
                set_inner s;
                for (uint32_t i = 0; i < count; i++)
                {
                    std::string member;
                    if (!read_string(member)) return false;
                    s.insert(std::move(member));
                }
                read_expiry(key);
                if (!m_expiry.count(key) || m_expiry[key] > now)
                    m_sets[std::move(key)] = std::move(s);
                break;
            }
            case TYPE_HASH:
            {
                uint32_t count = 0;
                file.read(reinterpret_cast<char*>(&count), sizeof(count));
                if (!file) return false;
                hash_inner h;
                for (uint32_t i = 0; i < count; i++)
                {
                    std::string field, val;
                    if (!read_string(field)) return false;
                    if (!read_string(val)) return false;
                    h[std::move(field)] = std::move(val);
                }
                read_expiry(key);
                if (!m_expiry.count(key) || m_expiry[key] > now)
                    m_hashes[std::move(key)] = std::move(h);
                break;
            }
            default:
                return false;
        }
    }

    return true;
}

bool cache_store::load_v1(std::ifstream& file, uint32_t first_key_len)
{
    m_data.clear();
    m_lists.clear();
    m_sets.clear();
    m_hashes.clear();
    m_expiry.clear();
    m_current_memory = 0;
    m_lru_order.clear();
    m_lru_map.clear();

    // Process the first entry (key_len already read)
    uint32_t key_len = first_key_len;

    while (true)
    {
        std::string key(key_len, '\0');
        file.read(key.data(), key_len);
        if (!file) break;

        uint32_t val_len = 0;
        file.read(reinterpret_cast<char*>(&val_len), sizeof(val_len));
        if (!file) break;

        std::string value(val_len, '\0');
        file.read(value.data(), val_len);
        if (!file) break;

        m_current_memory += key.size() + value.size();
        m_data[std::move(key)] = std::move(value);

        // Try reading next key_len
        file.read(reinterpret_cast<char*>(&key_len), sizeof(key_len));
        if (!file) break;
    }

    return true;
}

// ─── Eviction / Memory ───

void cache_store::set_max_memory(size_t bytes)
{
    m_max_memory = bytes;
}

void cache_store::set_eviction(eviction_policy policy)
{
    m_eviction = policy;
}

void cache_store::track_add(size_t bytes)
{
    m_current_memory += bytes;
}

void cache_store::track_sub(size_t bytes)
{
    if (bytes > m_current_memory)
        m_current_memory = 0;
    else
        m_current_memory -= bytes;
}

void cache_store::touch_lru(std::string_view key)
{
    if (m_max_memory == 0)
        return;  // No memory limit, skip LRU tracking

    std::string k(key);
    auto it = m_lru_map.find(k);
    if (it != m_lru_map.end())
    {
        m_lru_order.erase(it->second);
        m_lru_order.push_back(k);
        it->second = std::prev(m_lru_order.end());
    }
    else
    {
        m_lru_order.push_back(k);
        m_lru_map[k] = std::prev(m_lru_order.end());
    }
}

bool cache_store::try_evict(size_t needed)
{
    if (m_eviction == evict_none)
        return false;

    while (m_current_memory + needed > m_max_memory && !m_lru_order.empty())
    {
        if (m_eviction == evict_allkeys_lru)
        {
            // Evict least recently used (front of list)
            std::string victim = m_lru_order.front();
            m_lru_order.pop_front();
            m_lru_map.erase(victim);
            m_expiry.erase(victim);

            // Delete from whichever container holds it
            if (auto it = m_data.find(victim); it != m_data.end())
            {
                track_sub(it->first.size() + it->second.size());
                m_data.erase(it);
            }
            else if (auto it = m_lists.find(victim); it != m_lists.end())
            {
                size_t mem = it->first.size();
                for (const auto& e : it->second) mem += e.size();
                track_sub(mem);
                m_lists.erase(it);
            }
            else if (auto it = m_sets.find(victim); it != m_sets.end())
            {
                size_t mem = it->first.size();
                for (const auto& e : it->second) mem += e.size();
                track_sub(mem);
                m_sets.erase(it);
            }
            else if (auto it = m_hashes.find(victim); it != m_hashes.end())
            {
                size_t mem = it->first.size();
                for (const auto& [f, v] : it->second) mem += f.size() + v.size();
                track_sub(mem);
                m_hashes.erase(it);
            }
        }
        else // evict_allkeys_random
        {
            // Pick a random key from LRU order
            static thread_local std::mt19937 rng(std::random_device{}());
            auto dist = std::uniform_int_distribution<size_t>(0, m_lru_order.size() - 1);
            auto it = m_lru_order.begin();
            std::advance(it, dist(rng));
            std::string victim = *it;
            m_lru_order.erase(it);
            m_lru_map.erase(victim);
            m_expiry.erase(victim);

            if (auto dit = m_data.find(victim); dit != m_data.end())
            {
                track_sub(dit->first.size() + dit->second.size());
                m_data.erase(dit);
            }
            else if (auto lit = m_lists.find(victim); lit != m_lists.end())
            {
                size_t mem = lit->first.size();
                for (const auto& e : lit->second) mem += e.size();
                track_sub(mem);
                m_lists.erase(lit);
            }
            else if (auto sit = m_sets.find(victim); sit != m_sets.end())
            {
                size_t mem = sit->first.size();
                for (const auto& e : sit->second) mem += e.size();
                track_sub(mem);
                m_sets.erase(sit);
            }
            else if (auto hit = m_hashes.find(victim); hit != m_hashes.end())
            {
                size_t mem = hit->first.size();
                for (const auto& [f, v] : hit->second) mem += f.size() + v.size();
                track_sub(mem);
                m_hashes.erase(hit);
            }
        }
    }

    return m_current_memory + needed <= m_max_memory;
}

bool cache_store::check_memory(size_t needed)
{
    if (m_max_memory == 0)
        return true;  // No limit

    if (m_current_memory + needed <= m_max_memory)
        return true;

    return try_evict(needed);
}

// ─── Pub/Sub ───

void cache_store::subscribe(int fd, std::string_view channel)
{
    m_channels[std::string(channel)].insert(fd);
}

void cache_store::unsubscribe(int fd, std::string_view channel)
{
    auto it = m_channels.find(channel);
    if (it != m_channels.end())
    {
        it->second.erase(fd);
        if (it->second.empty())
            m_channels.erase(it);
    }
}

void cache_store::unsubscribe_all(int fd)
{
    for (auto it = m_channels.begin(); it != m_channels.end(); )
    {
        it->second.erase(fd);
        if (it->second.empty())
            it = m_channels.erase(it);
        else
            ++it;
    }
}

const std::unordered_set<int>* cache_store::get_subscribers(std::string_view channel) const
{
    auto it = m_channels.find(channel);
    if (it == m_channels.end())
        return nullptr;
    return &it->second;
}
