#pragma once
// A zone as a DNS runtime serves it: read from a master file (RFC 1035 section 5), checked whole before it is taken,
// and held as one table of names, each with its record sets, so an answer is a hash lookup and a copy.
//
// Every name of the zone is a key, the empty ones between a name and the apex included (RFC 4592's empty
// non-terminals), so "no such name" and "the name, but not that type" are told apart by the table alone, and a
// wildcard's closest encloser is the first ancestor found in it.
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "../../shared/persist/file_stamp.h"
#include "../../shared/util/transparent_string.h"

namespace socketley::dns
{

// The records of one name and type. Their data is in wire form with every name in it uncompressed and in lower case,
// which is what lets the writer compress them against the answer it is building.
struct rrset
{
    uint16_t type{0};
    uint32_t ttl{0};
    std::vector<std::string> rdata;
};

struct node
{
    std::vector<rrset> sets;
    // A zone cut: NS records on a name below the apex, which hands that name and all below it to other servers.
    bool cut{false};

    const rrset* find(uint16_t t) const
    {
        for (const auto& s : sets)
            if (s.type == t)
                return &s;
        return nullptr;
    }
};

struct zone
{
    // Wire form, lower case, the root's zero included.
    std::string origin;
    std::unordered_map<std::string, node, string_hash, string_equal> names;
    uint32_t serial{0};
    // The TTL a "no" is cached for (RFC 2308): the lesser of the SOA's own and its MINIMUM.
    uint32_t negative_ttl{0};
    size_t   records{0};
    // Whether any name below the apex is delegated, so a zone with none skips looking for a cut on every query.
    bool     has_cuts{false};
    // The file it came from and how it stood when read, so a change is noticed.
    std::string path;
    socketley::file_stamp stamp;

    const node* find(std::string_view wire) const
    {
        const auto it = names.find(wire);
        return it == names.end() ? nullptr : &it->second;
    }
    // Looked up once and kept: a zone is not changed once it is served, and every negative answer carries the SOA.
    const rrset* soa() const
    {
        if (!m_cache.soa_known)
        {
            const node* n = find(origin);
            m_cache.soa = n ? n->find(type_soa) : nullptr;
            m_cache.soa_known = true;
        }
        return m_cache.soa;
    }
    // Whether any name is a wildcard, decided once, so a zone without one looks for no closest encloser per miss.
    bool has_wildcards() const
    {
        if (m_cache.wild < 0)
        {
            m_cache.wild = 0;
            for (const auto& [n, nd] : names)
                if (n.size() >= 2 && n[0] == '\1' && n[1] == '*')
                {
                    m_cache.wild = 1;
                    break;
                }
        }
        return m_cache.wild == 1;
    }
    static constexpr uint16_t type_soa = 6;

private:
    // Pointers into this zone's own names, so a copy starts without them rather than pointing into another's.
    struct lookup_cache
    {
        const rrset* soa{nullptr};
        bool soa_known{false};
        int8_t wild{-1};
        lookup_cache() = default;
        lookup_cache(const lookup_cache&) {}
        lookup_cache& operator=(const lookup_cache&)
        {
            soa = nullptr;
            soa_known = false;
            wild = -1;
            return *this;
        }
    };
    mutable lookup_cache m_cache;

public:
};

// Bounds on a file, so a mistake -- or a file somebody else can write -- cannot take the worker's memory.
inline constexpr size_t max_zone_file  = 256u << 20;
inline constexpr size_t max_zone_records = 4u << 20;

// The zone in `path`, checked; false with the reason, naming the line, when it is not one this server can serve.
// `origin_hint`, a name in text, stands for $ORIGIN until the file sets its own.
bool load_zone(const std::string& path, std::string_view origin_hint, zone& out, std::string& why);
// The same, from text already read, for tests and for a zone given whole.
bool parse_zone(std::string_view text, std::string_view origin_hint, zone& out, std::string& why);

// A name in presentation form -- relative to `origin` unless it ends in a dot, "@" for the origin itself -- in lower
// case wire form; false when it is not one.
bool name_from_text(std::string_view text, std::string_view origin, std::string& out);

// Records a zone is given beside its file: the names runtimes are reached by, with the addresses --publish names, and
// ACME DNS-01 answers. What the file says of a name wins: a name with addresses of its own, or an alias, keeps them.
struct extra_records
{
    // Presentation form; one without a dot is taken under the apex, one with a dot as it is written.
    std::vector<std::string> names;
    // The addresses each name is given, in wire form: 4 bytes each, and 16.
    std::vector<std::string> v4, v6;
    // The name asked about (absolute, without "_acme-challenge.") and its TXT value.
    std::vector<std::pair<std::string, std::string>> challenges;
    // What is added to the file's serial, so a secondary sees a change of these.
    uint32_t serial_add{0};
};
inline constexpr uint32_t published_ttl = 300;
inline constexpr uint32_t challenge_ttl = 10;

// `x` added to `z`, where it falls within it; how many records that was.
size_t add_extra(zone& z, const extra_records& x);

// Every zone a runtime serves, found for a name by its longest suffix that is an apex.
struct zone_set
{
    std::vector<std::shared_ptr<const zone>> zones;
    // The zone `name` is in, or none.
    const zone* find(std::string_view name) const;
};

}   // namespace socketley::dns
