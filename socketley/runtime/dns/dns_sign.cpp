#include "dns_sign.h"

#include <openssl/bn.h>
#include <openssl/evp.h>

#include <algorithm>
#include <cstdio>
#include <map>

#include "dns_wire.h"
#include "../../shared/crypto/jws.h"

namespace socketley::dns
{

namespace
{

void put16(std::string& s, uint16_t v)
{
    s += static_cast<char>(v >> 8);
    s += static_cast<char>(v & 0xff);
}

void put32(std::string& s, uint32_t v)
{
    put16(s, static_cast<uint16_t>(v >> 16));
    put16(s, static_cast<uint16_t>(v & 0xffff));
}

// The labels of a wire name, the root left out, from the left.
std::vector<std::string_view> labels_of(std::string_view name)
{
    std::vector<std::string_view> out;
    for (size_t i = 0; i < name.size() && name[i];)
    {
        const size_t len = static_cast<uint8_t>(name[i]);
        out.push_back(name.substr(i + 1, len));
        i += 1 + len;
    }
    return out;
}

// RRSIG's Labels field: the owner's labels, a leading wildcard's not counted (RFC 4034 3.1.3).
uint8_t label_count(std::string_view owner)
{
    auto l = labels_of(owner);
    size_t n = l.size();
    if (n && l[0] == "*")
        --n;
    return static_cast<uint8_t>(n);
}

// NSEC's type bitmap (RFC 4034 4.1.2): the types present, a window of 256 at a time.
std::string type_bitmap(std::vector<uint16_t> types)
{
    std::sort(types.begin(), types.end());
    types.erase(std::unique(types.begin(), types.end()), types.end());
    std::string out;
    for (size_t i = 0; i < types.size();)
    {
        const uint8_t window = static_cast<uint8_t>(types[i] >> 8);
        uint8_t bits[32] = {};
        size_t len = 0;
        for (; i < types.size() && (types[i] >> 8) == window; ++i)
        {
            const uint8_t low = static_cast<uint8_t>(types[i] & 0xff);
            bits[low / 8] = static_cast<uint8_t>(bits[low / 8] | (0x80 >> (low % 8)));
            len = std::max<size_t>(len, low / 8 + 1);
        }
        out += static_cast<char>(window);
        out += static_cast<char>(len);
        out.append(reinterpret_cast<const char*>(bits), len);
    }
    return out;
}

// Whether `name` lies beneath a cut of `z`, where its records are glue and not the zone's own.
bool occluded(const zone& z, std::string_view name)
{
    if (!z.has_cuts)
        return false;
    for (std::string_view p = parent(name); p.size() > z.origin.size(); p = parent(p))
        if (const node* n = z.find(p); n && n->cut)
            return true;
    return false;
}

// The RRSIG of `s` at `owner`, its fields and the signature over them and the set in canonical form (RFC 4034 3.1.8.1).
bool sign_set(std::string_view owner, const rrset& s, std::string_view origin, const zone_key& key, uint32_t inception,
              uint32_t expiration, std::string& out)
{
    std::string rd;
    put16(rd, s.type);
    rd += static_cast<char>(13);
    rd += static_cast<char>(label_count(owner));
    put32(rd, s.ttl);
    put32(rd, expiration);
    put32(rd, inception);
    put16(rd, key.tag);
    rd.append(origin);
    std::vector<std::string> sorted = s.rdata;
    std::sort(sorted.begin(), sorted.end());
    sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());
    std::string data = rd;
    for (const auto& r : sorted)
    {
        data.append(owner);
        put16(data, s.type);
        put16(data, rclass::IN);
        put32(data, s.ttl);
        put16(data, static_cast<uint16_t>(r.size()));
        data += r;
    }
    const std::string sig = jws::es256(key.pkey.get(), data);
    if (sig.size() != 64)
        return false;
    out = rd + sig;
    return true;
}

}   // namespace

uint16_t key_tag(std::string_view rd)
{
    uint32_t ac = 0;
    for (size_t i = 0; i < rd.size(); ++i)
        ac += (i & 1) ? static_cast<uint8_t>(rd[i]) : static_cast<uint32_t>(static_cast<uint8_t>(rd[i])) << 8;
    ac += (ac >> 16) & 0xFFFF;
    return static_cast<uint16_t>(ac & 0xFFFF);
}

bool canonical_less(std::string_view a, std::string_view b)
{
    const auto la = labels_of(a), lb = labels_of(b);
    for (size_t i = 0; i < la.size() && i < lb.size(); ++i)
    {
        const std::string_view x = la[la.size() - 1 - i], y = lb[lb.size() - 1 - i];
        if (x != y)
            return std::lexicographical_compare(x.begin(), x.end(), y.begin(), y.end(),
                                                [](char p, char q) { return static_cast<uint8_t>(p) < static_cast<uint8_t>(q); });
    }
    return la.size() < lb.size();
}

std::string_view covering(const zone& z, std::string_view name)
{
    if (z.chain.empty())
        return {};
    auto it = std::upper_bound(z.chain.begin(), z.chain.end(), name,
                               [](std::string_view n, const std::string& c) { return canonical_less(n, c); });
    if (it == z.chain.begin())
        return z.chain.back();
    return *(it - 1);
}

bool load_or_make_key(const std::string& dir, std::string_view origin, zone_key& out, std::string& why)
{
    std::string text = to_text(origin);
    if (!text.empty() && text.back() == '.')
        text.pop_back();
    if (text.empty())
        text = "root";
    EVP_PKEY* k = jws::load_or_make_key(dir + "/" + text + ".pem", "the DNSSEC key", why);
    if (!k)
        return false;
    out.pkey = std::shared_ptr<EVP_PKEY>(k, EVP_PKEY_free);
    BIGNUM *x = nullptr, *y = nullptr;
    EVP_PKEY_get_bn_param(k, "qx", &x);
    EVP_PKEY_get_bn_param(k, "qy", &y);
    std::string point(64, '\0');
    const bool ok = x && y && BN_bn2binpad(x, reinterpret_cast<unsigned char*>(point.data()), 32) == 32 &&
                    BN_bn2binpad(y, reinterpret_cast<unsigned char*>(point.data()) + 32, 32) == 32;
    BN_free(x);
    BN_free(y);
    if (!ok)
    {
        why = "the DNSSEC key of " + to_text(origin) + " is no P-256 key";
        return false;
    }
    out.dnskey.clear();
    put16(out.dnskey, 257);
    out.dnskey += static_cast<char>(3);
    out.dnskey += static_cast<char>(13);
    out.dnskey += point;
    out.tag = key_tag(out.dnskey);
    return true;
}

bool sign_zone(zone& z, const zone_key& key, int64_t now_s)
{
    const int64_t epoch = sign_epoch(now_s);
    const uint32_t inception = static_cast<uint32_t>(epoch * sign_period_s - 3600);
    const uint32_t expiration = static_cast<uint32_t>(epoch * sign_period_s + int64_t(signature_days) * 86400);
    const rrset* soa = z.soa();
    if (!soa || soa->rdata.empty() || soa->rdata[0].size() < 20)
        return false;
    const uint32_t key_ttl = soa->ttl;
    // The serial raised by the week, which every shard counts alike, written into the SOA before it is signed.
    z.serial = static_cast<uint32_t>(z.serial + static_cast<uint32_t>(epoch));
    std::string& soa_rd = z.names[z.origin].sets[static_cast<size_t>(soa - z.names[z.origin].sets.data())].rdata[0];
    const size_t at = soa_rd.size() - 20;
    for (int i = 0; i < 4; ++i)
        soa_rd[at + static_cast<size_t>(i)] = static_cast<char>((z.serial >> (24 - 8 * i)) & 0xff);
    node& apex = z.names[z.origin];
    std::erase_if(apex.sets, [](const rrset& s) { return s.type == type_sec::DNSKEY; });
    apex.sets.push_back({type_sec::DNSKEY, key_ttl, {key.dnskey}});
    z.forget_lookups();
    // The owners of the chain: every name with records of the zone's own, a cut among them and glue not.
    std::vector<std::string> owners;
    for (auto& [name, nd] : z.names)
    {
        std::erase_if(nd.sets, [](const rrset& s) { return s.type == type_sec::NSEC || s.type == type_sec::RRSIG; });
        nd.sigs.clear();
        if (!nd.sets.empty() && !occluded(z, name))
            owners.push_back(name);
    }
    std::sort(owners.begin(), owners.end(), [](const std::string& a, const std::string& b) { return canonical_less(a, b); });
    for (size_t i = 0; i < owners.size(); ++i)
    {
        node& nd = z.names[owners[i]];
        std::vector<uint16_t> types{type_sec::RRSIG, type_sec::NSEC};
        for (const auto& s : nd.sets)
            types.push_back(s.type);
        std::string rd = owners[(i + 1) % owners.size()];
        rd += type_bitmap(std::move(types));
        nd.sets.push_back({type_sec::NSEC, z.negative_ttl, {std::move(rd)}});
    }
    // Every set signed but a cut's NS, which is the child's to sign.
    for (const auto& name : owners)
    {
        node& nd = z.names[name];
        for (const auto& s : nd.sets)
        {
            if (nd.cut && s.type != type::DS && s.type != type_sec::NSEC)
                continue;
            std::string sig;
            if (!sign_set(name, s, z.origin, key, inception, expiration, sig))
                return false;
            nd.sigs.push_back({s.type, s.ttl, {std::move(sig)}});
        }
    }
    // The apex's sets grew, so the SOA kept by soa() may have moved.
    z.forget_lookups();
    z.chain = std::move(owners);
    z.dnssec = true;
    z.sig_expires_s = expiration;
    z.sign_epoch = epoch;
    return true;
}

std::string ds_text(std::string_view origin, const zone_key& key)
{
    const std::string digest = jws::sha256(std::string(origin) + key.dnskey);
    std::string hex;
    char b[3];
    for (const unsigned char c : digest)
    {
        std::snprintf(b, sizeof b, "%02X", c);
        hex += b;
    }
    return to_text(origin) + " IN DS " + std::to_string(key.tag) + " 13 2 " + hex;
}

}   // namespace socketley::dns
