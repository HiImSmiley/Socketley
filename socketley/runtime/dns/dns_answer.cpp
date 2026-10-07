#include "dns_answer.h"

#include <algorithm>

namespace socketley::dns
{

void write_rr(writer& w, std::string_view owner, uint16_t t, uint32_t ttl, std::string_view rd)
{
    w.name(owner);
    w.put16(t);
    w.put16(rclass::IN);
    w.put32(ttl);
    const size_t len_at = w.size();
    w.put16(0);
    const size_t start = w.size();
    const auto* p = reinterpret_cast<const uint8_t*>(rd.data());
    // The length of the uncompressed name at `off` of the data.
    const auto name_len = [&](size_t off)
    {
        size_t i = off;
        while (i < rd.size() && p[i])
            i += 1 + p[i];
        return std::min(i + 1, rd.size()) - off;
    };
    switch (t)
    {
        case type::NS:
        case type::CNAME:
        case type::PTR:
            w.name(rd);
            break;
        case type::MX:
            w.put(p, 2);
            w.name(rd.substr(2));
            break;
        case type::SOA:
        {
            const size_t a = name_len(0);
            const size_t b = name_len(a);
            w.name(rd.substr(0, a));
            w.name(rd.substr(a, b));
            w.put(p + a + b, rd.size() - a - b);
            break;
        }
        case type::SRV:
            w.put(p, 6);
            w.name(rd.substr(6), /*compress=*/false);
            break;
        default:
            w.put(p, rd.size());
            break;
    }
    if (!w.overflowed())
        w.patch16(len_at, static_cast<uint16_t>(w.size() - start));
}

namespace
{

// The OPT record of a reply (RFC 6891): the size this server takes over UDP, and the upper bits of an extended rcode.
void write_opt(writer& w, uint8_t ext_rcode)
{
    w.put8(0);
    w.put16(type::OPT);
    w.put16(udp_payload);
    w.put8(ext_rcode);
    w.put8(0);   // version 0
    w.put16(0);  // no flags: no DNSSEC here
    w.put16(0);
}

struct lookup
{
    enum kind { found, nodata, nxdomain, referral, chain_out } k{nxdomain};
    const node* nd{nullptr};
    // The zone cut a referral hands the name to.
    std::string_view cut;
    const node* cut_node{nullptr};
    bool wildcard{false};
};

// Where `name` stands in `z`: below a cut, at a node, under a wildcard, or nowhere.
lookup find_name(const zone& z, std::string_view name, uint16_t qtype)
{
    lookup r;
    // The highest cut between the apex and the name, the name itself included -- except that DS is the parent's
    // record and is answered at the cut, not referred.
    const node* best_cut = nullptr;
    std::string_view best;
    for (std::string_view p = name; z.has_cuts && p.size() > z.origin.size(); p = parent(p))
    {
        const node* n = z.find(p);
        if (n && n->cut && !(p == name && qtype == type::DS))
        {
            best_cut = n;
            best = p;
        }
    }
    if (best_cut)
    {
        r.k = lookup::referral;
        r.cut = best;
        r.cut_node = best_cut;
        return r;
    }
    if (const node* n = z.find(name))
    {
        r.nd = n;
        r.k = n->sets.empty() ? lookup::nodata : lookup::found;
        return r;
    }
    // The closest encloser is the first ancestor that exists, and the wildcard is directly beneath it.
    for (std::string_view p = parent(name); p.size() >= z.origin.size(); p = parent(p))
    {
        if (!z.find(p))
            continue;
        std::string wild;
        wild.reserve(2 + p.size());
        wild += '\1';
        wild += '*';
        wild += p;
        if (const node* w = z.find(wild))
        {
            r.nd = w;
            r.wildcard = true;
            r.k = w->sets.empty() ? lookup::nodata : lookup::found;
            return r;
        }
        break;
    }
    r.k = lookup::nxdomain;
    return r;
}

struct counts
{
    uint16_t an{0}, ns{0}, ar{0};
};

void add_set(writer& w, std::string_view owner, const rrset& s, uint16_t& count)
{
    for (const auto& rd : s.rdata)
    {
        write_rr(w, owner, s.type, s.ttl, rd);
        ++count;
    }
}

void add_soa(writer& w, const zone& z, counts& c)
{
    if (const rrset* soa = z.soa(); soa && !soa->rdata.empty())
    {
        write_rr(w, z.origin, type::SOA, z.negative_ttl, soa->rdata[0]);
        ++c.ns;
    }
}

// The addresses of a server or mail host named in an answer, when this zone holds them: optional, so whatever does not
// fit is left out and nothing is truncated.
void add_addresses(writer& w, const zone& z, std::string_view target, counts& c)
{
    if (!is_subdomain(target, z.origin))
        return;
    const node* n = z.find(target);
    if (!n)
        return;
    for (uint16_t t : {type::A, type::AAAA})
        if (const rrset* s = n->find(t))
        {
            auto m = w.save();
            uint16_t added = 0;
            add_set(w, target, *s, added);
            if (w.overflowed())
            {
                w.restore(m);
                return;
            }
            c.ar = static_cast<uint16_t>(c.ar + added);
        }
}

// The names an rrset of `t` points at, whose addresses go in the additional section.
template <typename F>
void targets_of(const rrset& s, F&& f)
{
    for (const auto& rd : s.rdata)
    {
        if (s.type == type::NS)
            f(std::string_view(rd));
        else if (s.type == type::MX && rd.size() > 2)
            f(std::string_view(rd).substr(2));
        else if (s.type == type::SRV && rd.size() > 6)
            f(std::string_view(rd).substr(6));
    }
}

}   // namespace

size_t answer(const zone_set& zones, const uint8_t* q, size_t qlen, uint8_t* out, size_t cap, bool tcp,
              bool xfr_allowed, answer_meta& meta)
{
    meta = answer_meta{};
    if (qlen < header_len)
    {
        meta.dropped = true;
        return 0;
    }
    meta.id = rd16(q);
    const uint16_t flags = rd16(q + 2);
    const uint8_t op = static_cast<uint8_t>((flags >> 11) & 0xF);
    // A response is never answered, which is what keeps two servers from answering each other for ever; one to a
    // NOTIFY of ours is noted.
    if (flags & 0x8000)
    {
        meta.dropped = true;
        meta.notify_ack = op == opcode::NOTIFY;
        return 0;
    }

    writer w(out, std::min(cap, max_message));
    // The header is written last; its place is kept.
    w.put16(meta.id);
    w.put16(0);
    w.put16(0);
    w.put16(0);
    w.put16(0);
    w.put16(0);
    const uint16_t rd_bit = flags & 0x0100;
    const auto finish = [&](uint8_t rc, bool aa, uint16_t qd, const counts& c)
    {
        meta.rcode = rc;
        uint16_t f = static_cast<uint16_t>(0x8000 | (op << 11) | rd_bit | (rc & 0xF));
        if (aa)
            f |= 0x0400;
        if (meta.truncated)
            f |= 0x0200;
        w.patch16(2, f);
        w.patch16(4, qd);
        w.patch16(6, c.an);
        w.patch16(8, c.ns);
        w.patch16(10, c.ar);
        return w.size();
    };

    const uint16_t qd = rd16(q + 4);
    // ─── The question ───────────────────────────────────────────────────────
    size_t qend = 0;
    // The question's name is written out whole: there is nothing before it but the header for a pointer to point
    // at, and the reply copies it under a header of its own, where such a pointer would name something else
    // (found by fuzzing).
    if (qd != 1 || (meta.qname_len = read_name(q, qlen, header_len, meta.qname, qend)) == 0 || qend + 4 > qlen ||
        qend - header_len != meta.qname_len)
    {
        if (op != opcode::QUERY && op != opcode::NOTIFY)
            return finish(rcode::NOTIMP, false, 0, {});
        return finish(rcode::FORMERR, false, 0, {});
    }
    const std::string_view qname(reinterpret_cast<const char*>(meta.qname), meta.qname_len);
    const uint16_t qtype = rd16(q + qend);
    const uint16_t qclass = rd16(q + qend + 2);
    meta.qtype = qtype;
    const size_t question_end = qend + 4;
    meta.question_end = question_end;

    // ─── EDNS ───────────────────────────────────────────────────────────────
    // The OPT record is in the additional section; what comes before it is walked over, bounded at each step.
    size_t pos = question_end;
    const uint16_t ancount = rd16(q + 6), nscount = rd16(q + 8), arcount = rd16(q + 10);
    uint16_t client_udp = 512;
    uint8_t version = 0;
    bool bad = false;
    for (uint32_t i = 0, total = uint32_t(ancount) + nscount + arcount; i < total && !bad; ++i)
    {
        uint8_t tmp[max_name + 1];
        size_t next = 0;
        if (!read_name(q, qlen, pos, tmp, next) || next + 10 > qlen)
        {
            bad = true;
            break;
        }
        const uint16_t t = rd16(q + next);
        const uint16_t rdlen = rd16(q + next + 8);
        if (next + 10 + rdlen > qlen)
        {
            bad = true;
            break;
        }
        if (i >= uint32_t(ancount) + nscount && t == type::OPT)
        {
            // One OPT, owned by the root.
            if (meta.edns || tmp[0] != 0)
            {
                bad = true;
                break;
            }
            meta.edns = true;
            client_udp = std::max<uint16_t>(512, rd16(q + next + 2));
            version = q[next + 5];
        }
        pos = next + 10 + rdlen;
    }

    // The question goes back as it came, in the asker's own case.
    w.put(q + header_len, question_end - header_len);
    w.offer(qname, header_len);
    const auto question_mark = w.save();

    if (bad)
        return finish(rcode::FORMERR, false, 1, {});

    counts c;
    const auto close = [&](uint8_t rc, bool aa) -> size_t
    {
        if (meta.edns)
        {
            const auto m = w.save();
            write_opt(w, static_cast<uint8_t>(rc >> 4));
            if (w.overflowed())
                w.restore(m);
            else
                ++c.ar;
        }
        return finish(static_cast<uint8_t>(rc & 0xF), aa, 1, c);
    };

    // An answer over UDP is kept within what the asker said it takes, and never above the size that needs no
    // fragments; over TCP within a message.
    w.set_limit(tcp ? std::min(cap, max_message)
                    : std::min<size_t>(cap, meta.edns ? std::min<uint16_t>(client_udp, udp_payload) : 512));

    if (meta.edns && version != 0)
        return close(rcode::BADVERS, false);
    if (op == opcode::NOTIFY)
        return close(rcode::NOTIMP, false);   // a primary's own; this server is not anybody's secondary
    if (op != opcode::QUERY)
        return close(rcode::NOTIMP, false);
    // CHAOS and the rest carry the "version.bind" kind of question, whose answer helps nobody but an attacker.
    if (qclass != rclass::IN && qclass != rclass::ANY)
        return close(rcode::REFUSED, false);

    const zone* z = zones.find(qname);
    if (!z)
        return close(rcode::REFUSED, false);

    if (qtype == type::AXFR || qtype == type::IXFR)
    {
        if (!xfr_allowed || qname != z->origin)
            return close(rcode::REFUSED, false);
        if (tcp)
        {
            meta.xfr = z;
            meta.dropped = true;
            return 0;
        }
        // IXFR over UDP is answered with the SOA alone, which tells a secondary its serial and to come over TCP
        // (RFC 1995 section 2); AXFR has no UDP form.
        if (qtype == type::AXFR)
            return close(rcode::REFUSED, false);
        add_set(w, z->origin, *z->soa(), c.an);
        return close(rcode::NOERROR, true);
    }

    // ─── The lookup ─────────────────────────────────────────────────────────
    std::string_view name = qname;
    std::string chased;   // a CNAME's target, kept while the chain is followed
    uint8_t rc = rcode::NOERROR;
    bool aa = true;
    for (int hops = 0; hops < 8; ++hops)
    {
        const lookup l = find_name(*z, name, qtype);
        if (l.k == lookup::referral)
        {
            // Handed away: the cut's NS records in the authority section, and their addresses beneath as glue.
            if (hops == 0)
            {
                aa = false;
                meta.referral = true;
            }
            add_set(w, l.cut, *l.cut_node->find(type::NS), c.ns);
            if (w.overflowed())
                break;
            targets_of(*l.cut_node->find(type::NS), [&](std::string_view t) { add_addresses(w, *z, t, c); });
            break;
        }
        if (l.k == lookup::nxdomain)
        {
            rc = rcode::NXDOMAIN;
            add_soa(w, *z, c);
            break;
        }
        if (l.k == lookup::nodata)
        {
            add_soa(w, *z, c);
            break;
        }
        const node& nd = *l.nd;
        // RFC 8482: ANY is given one small record, not everything, so it amplifies nothing.
        if (qtype == type::ANY)
        {
            static const std::string rfc8482("\x07RFC8482\x00", 9);
            write_rr(w, name, type::HINFO, 3789, rfc8482);
            ++c.an;
            break;
        }
        if (const rrset* s = nd.find(qtype))
        {
            add_set(w, name, *s, c.an);
            if (!w.overflowed())
                targets_of(*s, [&](std::string_view t) { add_addresses(w, *z, t, c); });
            break;
        }
        const rrset* cname = nd.find(type::CNAME);
        if (!cname || qtype == type::CNAME)
        {
            add_soa(w, *z, c);
            break;
        }
        add_set(w, name, *cname, c.an);
        if (w.overflowed())
            break;
        // The alias is followed while its target is in this zone; outside it, the asker's resolver takes over.
        chased.assign(cname->rdata[0]);
        if (!is_subdomain(chased, z->origin))
            break;
        name = chased;
    }

    if (w.overflowed())
    {
        // What does not fit is not sent in part: the question alone with TC, so the asker comes back over TCP.
        w.restore(question_mark);
        c = counts{};
        meta.truncated = true;
    }
    return close(rc, aa);
}

size_t make_notify(const zone& z, uint16_t id, uint8_t* out, size_t cap)
{
    writer w(out, cap);
    w.put16(id);
    w.put16(static_cast<uint16_t>(opcode::NOTIFY << 11) | 0x0400);
    w.put16(1);
    w.put16(0);
    w.put16(0);
    w.put16(0);
    w.name(z.origin);
    w.put16(type::SOA);
    w.put16(rclass::IN);
    return w.overflowed() ? 0 : w.size();
}

}   // namespace socketley::dns
