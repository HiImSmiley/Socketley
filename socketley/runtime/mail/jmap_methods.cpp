// The JMAP methods for mail (RFC 8621) on the IMAP index: Mailbox/get, query and set, Email/get, query, set and
// import, Thread/get, Identity/get and EmailSubmission/set.  What they read is the index and the messages' bytes, what
// they change is changed as IMAP changes it, so the two see each other at once.
#include "jmap_session.h"

#include <algorithm>
#include <ctime>
#include <set>

#include "imap_utf7.h"
#include "mail_compose.h"
#include "mail_mime.h"
#include "mail_text.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/util/base64.h"
#include "../../shared/crypto/mac.h"
#include "../../shared/util/ascii.h"
#include "../../shared/util/random_id.h"
#include "../../shared/util/wall_clock.h"

namespace socketley::mail
{

using json::jvalue;

namespace
{

std::string q(std::string_view s)
{
    return json::quote(s);
}

// The state of an entry kept as one, a digest of what it holds.
std::string entry_state(const std::string* kept)
{
    uint64_t h = 1469598103934665603ull;
    for (const unsigned char c : kept ? std::string_view(*kept) : std::string_view())
        h = (h ^ c) * 1099511628211ull;
    return "s" + std::to_string(kept ? h : 0);
}

std::string utc(int64_t ms)
{
    std::tm tm{};
    const time_t t = static_cast<time_t>(ms / 1000);
    ::gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

// RFC 3339 with the zone the header was written in, as sentAt is.
std::string dated(int64_t t, int zone_min)
{
    std::tm tm{};
    const time_t local = static_cast<time_t>(t + zone_min * 60);
    ::gmtime_r(&local, &tm);
    char buf[40];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%S", &tm);
    const int z = zone_min < 0 ? -zone_min : zone_min;
    char off[16];
    std::snprintf(off, sizeof off, "%c%02d:%02d", zone_min < 0 ? '-' : '+', (z / 60) % 100, z % 60);
    return std::string(buf) + off;
}

// A UTCDate (RFC 3339, Z), as unix milliseconds; -1 where it is none.
int64_t utc_ms(std::string_view s)
{
    std::tm tm{};
    const std::string t(s);
    const char* end = ::strptime(t.c_str(), "%Y-%m-%dT%H:%M:%S", &tm);
    if (!end)
        return -1;
    while (*end == '.' || (*end >= '0' && *end <= '9'))
        ++end;
    if (*end != 'Z' && *end != 'z')
        return -1;
    return static_cast<int64_t>(::timegm(&tm)) * 1000;
}

const char* role_of(std::string_view folder)
{
    if (folder == "INBOX")
        return "inbox";
    if (folder == "Sent")
        return "sent";
    if (folder == "Drafts")
        return "drafts";
    if (folder == "Junk")
        return "junk";
    if (folder == "Trash")
        return "trash";
    return nullptr;
}

int sort_order(std::string_view folder)
{
    const char* r = role_of(folder);
    return !r ? 10 : r[0] == 'i' ? 1 : r[0] == 'd' ? 2 : r[0] == 's' ? 3 : r[0] == 'j' ? 4 : 5;
}

// A folder's last level, in UTF-8.
std::string leaf_of(const std::string& folder)
{
    const std::string leaf = folder.substr(folder.rfind('/') == std::string::npos ? 0 : folder.rfind('/') + 1);
    std::string text = imap_utf7::decode(leaf);
    return text.empty() && !leaf.empty() ? leaf : text;
}

// imap4flags and JMAP keywords: \Seen is $seen, a keyword is itself in lower case.
std::vector<std::string> keywords_of(const imap_message& m)
{
    std::vector<std::string> out;
    if (m.flags & flag_seen)
        out.emplace_back("$seen");
    if (m.flags & flag_answered)
        out.emplace_back("$answered");
    if (m.flags & flag_flagged)
        out.emplace_back("$flagged");
    if (m.flags & flag_draft)
        out.emplace_back("$draft");
    for (const auto& k : m.keywords)
    {
        std::string l = k;
        socketley::ascii::lower_in_place(l);
        out.push_back(std::move(l));
    }
    return out;
}

uint8_t flags_of(const std::vector<std::string>& keywords, std::vector<std::string>& words)
{
    uint8_t bits = 0;
    for (const auto& k : keywords)
    {
        if (k == "$seen")
            bits |= flag_seen;
        else if (k == "$answered")
            bits |= flag_answered;
        else if (k == "$flagged")
            bits |= flag_flagged;
        else if (k == "$draft")
            bits |= flag_draft;
        else if (!k.empty() && k.size() <= 255 && k.find_first_of(" ()[]{}%*\"\\") == std::string::npos)
            words.push_back(k);
    }
    return bits;
}

std::string keywords_json(const imap_message& m)
{
    std::string out = "{";
    for (const auto& k : keywords_of(m))
        out += (out.size() > 1 ? "," : "") + q(k) + ":true";
    return out + "}";
}

// A list of mailboxes as JMAP's EmailAddress objects.
std::string addresses_json(std::string_view value)
{
    std::string out = "[";
    bool quoted = false;
    int angle = 0;
    size_t start = 0;
    bool any = false;
    for (size_t i = 0; i <= value.size(); ++i)
    {
        const char c = i < value.size() ? value[i] : ',';
        if (c == '"' && (i == 0 || value[i - 1] != '\\'))
            quoted = !quoted;
        else if (!quoted && c == '<')
            ++angle;
        else if (!quoted && c == '>')
            angle = std::max(0, angle - 1);
        if (c != ',' || quoted || angle)
            continue;
        const std::string_view one = value.substr(start, i - start);
        start = i + 1;
        address a;
        std::string display;
        if (!parse_mailbox(one, a, &display))
            continue;
        out += std::string(any ? "," : "") + "{\"name\":" + (display.empty() ? "null" : q(mime::decode_words(display))) +
               ",\"email\":" + q(a.text()) + "}";
        any = true;
    }
    return any ? out + "]" : std::string("null");
}

// Message-IDs without their brackets, as messageId, inReplyTo and references are.
std::string ids_json(std::string_view value)
{
    std::string out = "[";
    bool any = false;
    for (size_t at = value.find('<'); at != std::string_view::npos; at = value.find('<', at + 1))
    {
        const size_t end = value.find('>', at);
        if (end == std::string_view::npos)
            break;
        out += std::string(any ? "," : "") + q(value.substr(at + 1, end - at - 1));
        any = true;
    }
    return any ? out + "]" : std::string("null");
}

bool listed(const jvalue* props, std::string_view name)
{
    if (!props || props->k != jvalue::kind::array)
        return true;
    return std::any_of(props->items.begin(), props->items.end(),
                       [&](const jvalue& v) { return v.k == jvalue::kind::string && v.s == name; });
}

// The parts of a message as JMAP numbers them, the sections IMAP gives them, and its text, HTML and attachments as
// RFC 8621 4.1.4 picks them.
struct body_part
{
    const mime::part* p{nullptr};
    std::string id;
    std::vector<body_part> sub;
};

body_part number_parts(const mime::part& p, const std::string& id)
{
    body_part out{&p, id, {}};
    if (p.multipart())
        for (size_t i = 0; i < p.children.size(); ++i)
            out.sub.push_back(number_parts(p.children[i], id.empty() ? std::to_string(i + 1) : id + "." + std::to_string(i + 1)));
    return out;
}

std::string type_of(const mime::part& p)
{
    std::string t = p.type + "/" + p.subtype;
    socketley::ascii::lower_in_place(t);
    return t;
}

bool inline_media(std::string_view t)
{
    return t.starts_with("image/") || t.starts_with("audio/") || t.starts_with("video/");
}

std::string name_of(const mime::part& p)
{
    std::string n = mime::param(p.disposition_params, "filename");
    if (n.empty())
        n = mime::param(p.params, "name");
    return mime::decode_words(n);
}

void pick(const std::vector<const body_part*>& parts, std::string_view multipart, bool in_alternative,
          std::vector<const body_part*>* html, std::vector<const body_part*>* text, std::vector<const body_part*>& att)
{
    const long text_len = text ? static_cast<long>(text->size()) : -1, html_len = html ? static_cast<long>(html->size()) : -1;
    for (size_t i = 0; i < parts.size(); ++i)
    {
        const body_part& bp = *parts[i];
        const std::string t = type_of(*bp.p);
        std::string disp = bp.p->disposition;
        socketley::ascii::lower_in_place(disp);
        const bool is_inline = disp != "attachment" && (t == "text/plain" || t == "text/html" || inline_media(t)) &&
                               (i == 0 || (multipart != "related" && (inline_media(t) || name_of(*bp.p).empty())));
        if (bp.p->multipart())
        {
            std::vector<const body_part*> sub;
            for (const auto& s : bp.sub)
                sub.push_back(&s);
            std::string st = bp.p->subtype;
            socketley::ascii::lower_in_place(st);
            pick(sub, st, in_alternative || st == "alternative", html, text, att);
        }
        else if (is_inline)
        {
            if (multipart == "alternative")
            {
                if (t == "text/plain" && text)
                    text->push_back(&bp);
                else if (t == "text/html" && html)
                    html->push_back(&bp);
                else
                    att.push_back(&bp);
                continue;
            }
            std::vector<const body_part*>* h = html;
            std::vector<const body_part*>* x = text;
            if (in_alternative)
            {
                if (t == "text/plain")
                    h = nullptr;
                if (t == "text/html")
                    x = nullptr;
            }
            if (x)
                x->push_back(&bp);
            if (h)
                h->push_back(&bp);
            if ((!x || !h) && inline_media(t))
                att.push_back(&bp);
        }
        else
            att.push_back(&bp);
    }
    if (multipart == "alternative" && text && html)
    {
        if (static_cast<long>(text->size()) == text_len && static_cast<long>(html->size()) != html_len)
            for (size_t i = static_cast<size_t>(html_len); i < html->size(); ++i)
                text->push_back((*html)[i]);
        if (static_cast<long>(html->size()) == html_len && static_cast<long>(text->size()) != text_len)
            for (size_t i = static_cast<size_t>(text_len); i < text->size(); ++i)
                html->push_back((*text)[i]);
    }
}

// A part's text, decoded and in UTF-8.
std::string text_of(std::string_view msg, const mime::part& p)
{
    std::string raw = mime::decoded_body(msg.substr(p.body_off, p.body_len), p.encoding);
    return mime::to_utf8(raw, mime::param(p.params, "charset"));
}

// At most `n` bytes of `s`, cut where a UTF-8 character begins.
std::string_view utf8_prefix(std::string_view s, size_t n)
{
    if (s.size() <= n)
        return s;
    while (n > 0 && (static_cast<unsigned char>(s[n]) & 0xC0) == 0x80)
        --n;
    return s.substr(0, n);
}

std::string part_json(std::string_view msg, const body_part& bp, const std::string& email, const jvalue* props)
{
    const mime::part& p = *bp.p;
    std::string out = "{";
    const auto add = [&](std::string_view k, const std::string& v) {
        if (!listed(props, k))
            return;
        out += (out.size() > 1 ? "," : "") + q(k) + ":" + v;
    };
    const bool multi = p.multipart();
    add("partId", multi ? "null" : q(bp.id));
    std::string blob_id = email + "_" + bp.id;
    std::replace(blob_id.begin(), blob_id.end(), '.', '-');
    add("blobId", multi ? "null" : q(blob_id));
    if (listed(props, "size"))
    {
        const std::string_view body = msg.substr(p.body_off, p.body_len);
        add("size", std::to_string(multi ? body.size() : mime::decoded_body(body, p.encoding).size()));
    }
    const std::string name = name_of(p);
    add("name", name.empty() ? "null" : q(name));
    add("type", q(type_of(p)));
    const std::string cs = mime::param(p.params, "charset");
    add("charset", p.type == "text" || p.type == "TEXT" ? q(cs.empty() ? "us-ascii" : cs) : cs.empty() ? "null" : q(cs));
    std::string disp = p.disposition;
    socketley::ascii::lower_in_place(disp);
    add("disposition", disp.empty() ? "null" : q(disp));
    std::string cid = p.id;
    if (cid.size() >= 2 && cid.front() == '<' && cid.back() == '>')
        cid = cid.substr(1, cid.size() - 2);
    add("cid", cid.empty() ? "null" : q(cid));
    add("language", p.language.empty() ? "null" : "[" + q(p.language) + "]");
    add("location", p.location.empty() ? "null" : q(p.location));
    if (multi && listed(props, "subParts"))
    {
        std::string subs = "[";
        for (const auto& s : bp.sub)
            subs += (subs.size() > 1 ? "," : "") + part_json(msg, s, email, props);
        add("subParts", subs + "]");
    }
    return out + "}";
}

std::vector<std::string> strings_of(const jvalue* v)
{
    std::vector<std::string> out;
    if (v && v->k == jvalue::kind::array)
        for (const auto& i : v->items)
            if (i.k == jvalue::kind::string)
                out.push_back(i.s);
    return out;
}

// The first mailbox of a mailboxIds object set true.
std::string first_true(const jvalue* v)
{
    if (v && v->k == jvalue::kind::object)
        for (const auto& [k, x] : v->members)
            if (x.k == jvalue::kind::boolean && x.b)
                return k;
    return {};
}

// An Email an Email/query looks at, and what of it the filter and the sort read.
struct query_cand
{
    std::string id;
    imap_message m;
    std::string mailbox;
    std::string head;
    bool hit{false};
};

// The strings a FilterCondition looks for in an Email, given to `take`.
template <typename F>
void needles_of(const jvalue& f, F&& take)
{
    for (const char* k : {"text", "body", "from", "to", "cc", "bcc", "subject"})
        if (const std::string_view v = json::string_of(f, k); !v.empty())
            take(v);
    if (const jvalue* hv = json::member(f, "header"); hv && hv->k == jvalue::kind::array && hv->items.size() > 1)
        take(std::string_view(hv->items[1].s));
}

// Whether a filter looks for a string a trigram filter can rule out.
bool filters_out(const jvalue& f, int depth = 0)
{
    bool any = false;
    needles_of(f, [&](std::string_view v) { any = any || v.size() >= 3; });
    if (const jvalue* conds = json::member(f, "conditions"); conds && conds->k == jvalue::kind::array && depth < 16)
        for (const auto& x : conds->items)
            any = any || filters_out(x, depth + 1);
    return any;
}

// Whether an Email whose trigram filter is `filter` may meet `f`: false only where it cannot.
bool may_meet(const jvalue& f, std::string_view filter, int depth = 0)
{
    if (const jvalue* conds = json::member(f, "conditions"); conds && conds->k == jvalue::kind::array)
    {
        const std::string_view op = json::string_of(f, "operator");
        // A NOT of what a filter says may be there cannot be ruled out by it.
        if (op == "NOT" || depth >= 16)
            return true;
        size_t may = 0;
        for (const auto& x : conds->items)
            may += may_meet(x, filter, depth + 1);
        return op == "OR" ? may > 0 : may == conds->items.size();
    }
    bool may = true;
    needles_of(f, [&](std::string_view v) { may = may && may_hold(filter, v); });
    return may;
}

// Whether an Email meets a FilterCondition or a FilterOperator, read off the index and what was read of it: `whole` its
// bytes and `root` their structure where a condition reads the body.
bool meets(const jvalue& f, const query_cand& c, std::string_view whole, const mime::part* root, int depth = 0)
{
    if (const jvalue* conds = json::member(f, "conditions"); conds && conds->k == jvalue::kind::array)
    {
        const std::string_view op = json::string_of(f, "operator");
        size_t yes = 0;
        for (const auto& x : conds->items)
            yes += depth < 16 && meets(x, c, whole, root, depth + 1);
        return op == "OR" ? yes > 0 : op == "NOT" ? yes == 0 : yes == conds->items.size();
    }
    if (const jvalue* v = json::member(f, "inMailbox"); v && v->k == jvalue::kind::string && v->s != c.mailbox)
        return false;
    if (const jvalue* v = json::member(f, "inMailboxOtherThan"); v && v->k == jvalue::kind::array)
        for (const auto& x : v->items)
            if (x.s == c.mailbox)
                return false;
    if (const std::string_view b = json::string_of(f, "before"); !b.empty() && !(c.m.date_ms < utc_ms(b)))
        return false;
    if (const std::string_view a = json::string_of(f, "after"); !a.empty() && !(c.m.date_ms >= utc_ms(a)))
        return false;
    if (json::member(f, "minSize") && c.m.size < static_cast<uint64_t>(json::int_of(f, "minSize")))
        return false;
    if (json::member(f, "maxSize") && c.m.size >= static_cast<uint64_t>(json::int_of(f, "maxSize")))
        return false;
    const auto kws = keywords_of(c.m);
    if (const std::string_view k = json::string_of(f, "hasKeyword"); !k.empty() && std::find(kws.begin(), kws.end(), k) == kws.end())
        return false;
    if (const std::string_view k = json::string_of(f, "notKeyword"); !k.empty() && std::find(kws.begin(), kws.end(), k) != kws.end())
        return false;
    for (const char* h : {"from", "to", "cc", "bcc", "subject"})
        if (const std::string_view want = json::string_of(f, h); !want.empty())
        {
            const std::string v = header_value(c.head, h);
            if (!contains_ci(mime::decode_words(v), want) && (std::string_view(h) == "subject" || !contains_ci(v, want)))
                return false;
        }
    if (const jvalue* hv = json::member(f, "header"); hv && hv->k == jvalue::kind::array && !hv->items.empty())
    {
        const std::string v = header_value(c.head, hv->items[0].s);
        if (v.empty() || (hv->items.size() > 1 && !contains_ci(v, hv->items[1].s)))
            return false;
    }
    if (const std::string_view b = json::string_of(f, "body"); !b.empty() && !body_has(whole, header_block(whole), root, b))
        return false;
    if (const std::string_view t = json::string_of(f, "text"); !t.empty() && !text_has(whole, header_block(whole), root, t))
        return false;
    if (const jvalue* a = json::member(f, "hasAttachment"); a && a->k == jvalue::kind::boolean)
    {
        // An Email that could not be read has no attachment.
        std::vector<const body_part*> text, html, att;
        if (root)
        {
            body_part tree = number_parts(*root, root->multipart() ? std::string() : std::string("1"));
            pick({&tree}, "mixed", false, &html, &text, att);
        }
        if (a->b != !att.empty())
            return false;
    }
    return true;
}

// What Email/get and Email/parse say of a message: its properties as `v` asks, from the index entry `m` where it is
// one of the account's, and from its bytes where they were read.
struct email_view
{
    std::vector<std::string> props;
    const jvalue* body_props{nullptr};
    bool whole{false}, text_values{false}, html_values{false}, all_values{false};
    size_t max_value{0};
};

std::string email_object(const email_view& view, const std::string& id, const imap_message* m, const std::string& mailbox,
                         const std::string* bytes)
{
    std::string o = "{";
    const auto add = [&](std::string_view k, const std::string& val) {
        o += (o.size() > 1 ? "," : "") + q(k) + ":" + val;
    };
    std::string_view msg = bytes ? std::string_view(*bytes) : std::string_view{};
    const std::string_view head = header_block(msg);
    mime::part root;
    body_part tree;
    std::vector<const body_part*> text, html, att;
    if (view.whole && bytes)
    {
        root = mime::parse(msg);
        tree = number_parts(root, root.multipart() ? std::string() : std::string("1"));
        pick({&tree}, "mixed", false, &html, &text, att);
    }
    for (const auto& p : view.props)
    {
        // A blob parsed as an Email is no Email of the account: it has no id, mailbox, keywords or arrival.
        if (p == "id")
            add(p, m ? q(id) : "null");
        else if (p == "blobId")
            add(p, q(id));
        else if (p == "threadId")
            add(p, m ? q("T" + id.substr(1)) : "null");
        else if (p == "mailboxIds")
            add(p, m ? "{" + q(mailbox) + ":true}" : "null");
        else if (p == "keywords")
            add(p, m ? keywords_json(*m) : "null");
        else if (p == "size")
            add(p, std::to_string(m ? m->size : bytes ? bytes->size() : 0));
        else if (p == "receivedAt")
            add(p, m ? q(utc(m->date_ms)) : "null");
        else if (p == "messageId" || p == "inReplyTo" || p == "references")
            add(p, ids_json(header_value(head, p == "messageId" ? "Message-ID" : p == "inReplyTo" ? "In-Reply-To" : "References")));
        else if (p == "sender" || p == "from" || p == "to" || p == "cc" || p == "bcc" || p == "replyTo")
            add(p, addresses_json(header_value(head, p == "replyTo" ? "Reply-To" : p)));
        else if (p == "subject")
        {
            const std::string s = header_value(head, "Subject");
            add(p, bytes && !s.empty() ? q(mime::decode_words(s)) : "null");
        }
        else if (p == "sentAt")
        {
            int64_t t = 0;
            int zone = 0;
            const std::string d = header_value(head, "Date");
            add(p, !d.empty() && mime::parse_date(d, t, zone) ? q(dated(t, zone)) : "null");
        }
        else if (p == "headers")
        {
            std::string hs = "[";
            for (const auto& [n, v] : split_headers(head))
                hs += (hs.size() > 1 ? "," : "") + std::string("{\"name\":") + q(n) + ",\"value\":" + q(v) + "}";
            add(p, hs + "]");
        }
        else if (p.starts_with("header:"))
        {
            // header:<name>[:asText], the first of its name.
            std::string_view rest = std::string_view(p).substr(7);
            const bool as_text = rest.ends_with(":asText");
            const bool as_addr = rest.ends_with(":asAddresses");
            if (as_text)
                rest.remove_suffix(7);
            if (as_addr)
                rest.remove_suffix(12);
            const std::string v = header_value(head, rest);
            add(p, v.empty() ? "null" : as_addr ? addresses_json(v) : q(as_text ? mime::decode_words(v) : " " + v));
        }
        else if (p == "hasAttachment")
            add(p, bytes ? (att.empty() ? "false" : "true") : "false");
        else if (p == "preview")
        {
            // The text with its runs of white space made one space, HTML's tags taken out, read only until it is
            // longer than the preview, which what follows cannot change.
            constexpr size_t preview_bytes = 256;
            std::string flat;
            const auto take = [&](const mime::part& part) {
                // A textBody holds the HTML of an Email that has no plain text.
                const bool tags = socketley::ascii::iequals(part.subtype, "html");
                const std::string s = text_of(msg, part);
                bool tag = false;
                for (size_t i = 0; i < s.size() && flat.size() <= preview_bytes; ++i)
                {
                    const char c = s[i];
                    if (tags && (c == '<' || c == '>'))
                        tag = c == '<';
                    else if (tag)
                        continue;
                    else if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
                    {
                        if (!flat.empty() && flat.back() != ' ')
                            flat += ' ';
                    }
                    else
                        flat += c;
                }
            };
            if (!text.empty())
                take(*text.front()->p);
            else if (!html.empty())
                take(*html.front()->p);
            add(p, q(utf8_prefix(flat, preview_bytes)));
        }
        else if (p == "bodyStructure")
            add(p, bytes ? part_json(msg, tree, id, view.body_props) : "null");
        else if (p == "textBody" || p == "htmlBody" || p == "attachments")
        {
            const auto& v = p == "textBody" ? text : p == "htmlBody" ? html : att;
            std::string arr = "[";
            for (const body_part* bp : v)
                arr += (arr.size() > 1 ? "," : "") + part_json(msg, *bp, id, view.body_props);
            add(p, arr + "]");
        }
        else if (p == "bodyValues")
        {
            std::string vals = "{";
            std::set<std::string> done_ids;
            const auto value_of = [&](const body_part* bp) {
                if (!done_ids.insert(bp->id).second || bp->p->type != "text")
                    return;
                std::string v = text_of(msg, *bp->p);
                const bool cut = view.max_value && v.size() > view.max_value;
                if (cut)
                    v = std::string(utf8_prefix(v, view.max_value));
                vals += (vals.size() > 1 ? "," : "") + q(bp->id) + ":{\"value\":" + q(v) +
                        ",\"isEncodingProblem\":false,\"isTruncated\":" + (cut ? "true" : "false") + "}";
            };
            if (view.text_values || view.all_values)
                for (const body_part* bp : text)
                    value_of(bp);
            if (view.html_values || view.all_values)
                for (const body_part* bp : html)
                    value_of(bp);
            if (view.all_values)
                for (const body_part* bp : att)
                    value_of(bp);
            add(p, vals + "}");
        }
        else
            add(p, "null");
    }
    return o + "}";
}

std::string set_error(std::string_view type, std::string_view description = {})
{
    std::string out = "{\"type\":" + q(type);
    if (!description.empty())
        out += ",\"description\":" + q(description);
    return out + "}";
}

}   // namespace

// ─── Mailbox ────────────────────────────────────────────────────────────────

void jmap_session::mailbox_get(const jvalue& args, std::function<void(answer)> done)
{
    const auto folders = m_store.known(m_user);
    std::unordered_map<std::string, std::shared_ptr<imap_folder>> by_name;
    for (const auto& f : folders)
        by_name[f->name] = f;
    const jvalue* ids = json::member(args, "ids");
    const jvalue* props = json::member(args, "properties");
    std::vector<std::shared_ptr<imap_folder>> chosen;
    std::string not_found = "[";
    if (ids && ids->k == jvalue::kind::array)
    {
        for (const auto& i : ids->items)
        {
            const auto it = std::find_if(folders.begin(), folders.end(), [&](const auto& f) { return f->id() == i.s; });
            if (it != folders.end())
                chosen.push_back(*it);
            else
                not_found += (not_found.size() > 1 ? "," : "") + q(i.s);
        }
    }
    else
        chosen = folders;
    std::string list = "[";
    for (const auto& f : chosen)
    {
        size_t total = 0, unread = 0;
        for (const auto& m : f->msgs)
        {
            ++total;
            unread += !(m.flags & flag_seen);
        }
        const size_t slash = f->name.rfind('/');
        const auto parent = slash == std::string::npos ? nullptr : by_name[f->name.substr(0, slash)];
        const char* role = role_of(f->name);
        std::string o = "{";
        const auto add = [&](std::string_view k, const std::string& v) {
            if (k == "id" || listed(props, k))
                o += (o.size() > 1 ? "," : "") + q(k) + ":" + v;
        };
        add("id", q(f->id()));
        add("name", q(f->name == "INBOX" ? "Inbox" : leaf_of(f->name)));
        add("parentId", parent ? q(parent->id()) : "null");
        add("role", role ? q(role) : "null");
        add("sortOrder", std::to_string(sort_order(f->name)));
        add("totalEmails", std::to_string(total));
        add("unreadEmails", std::to_string(unread));
        add("totalThreads", std::to_string(total));
        add("unreadThreads", std::to_string(unread));
        const bool special = role != nullptr;
        add("myRights", std::string("{\"mayReadItems\":true,\"mayAddItems\":true,\"mayRemoveItems\":true,\"maySetSeen\":true,"
                                    "\"maySetKeywords\":true,\"mayCreateChild\":true,\"mayRename\":") +
                            (special ? "false" : "true") + ",\"mayDelete\":" + (special ? "false" : "true") +
                            ",\"maySubmit\":true}");
        add("isSubscribed", f->subscribed ? "true" : "false");
        list += (list.size() > 1 ? "," : "") + o + "}";
    }
    done({{"Mailbox/get", "{\"accountId\":" + q(account_of(m_user)) + ",\"state\":" + q(mailbox_state(m_store, m_user)) +
                              ",\"list\":" + list + "],\"notFound\":" + not_found + "]}"}});
}

void jmap_session::mailbox_query(const jvalue& args, std::function<void(answer)> done)
{
    auto folders = m_store.known(m_user);
    std::unordered_map<std::string, std::string> id_of;
    for (const auto& f : folders)
        id_of[f->name] = f->id();
    if (const jvalue* filter = json::member(args, "filter"); filter && filter->k == jvalue::kind::object)
    {
        const jvalue* parent = json::member(*filter, "parentId");
        const jvalue* role = json::member(*filter, "role");
        const jvalue* any_role = json::member(*filter, "hasAnyRole");
        const jvalue* sub = json::member(*filter, "isSubscribed");
        const std::string name(json::string_of(*filter, "name"));
        std::erase_if(folders, [&](const std::shared_ptr<imap_folder>& f) {
            const size_t slash = f->name.rfind('/');
            const std::string pid = slash == std::string::npos ? std::string() : id_of[f->name.substr(0, slash)];
            if (parent && (parent->k == jvalue::kind::null ? !pid.empty() : pid != parent->s))
                return true;
            const char* r = role_of(f->name);
            if (role && (role->k == jvalue::kind::null ? r != nullptr : !r || role->s != r))
                return true;
            if (any_role && any_role->k == jvalue::kind::boolean && any_role->b != (r != nullptr))
                return true;
            if (sub && sub->k == jvalue::kind::boolean && sub->b != f->subscribed)
                return true;
            if (!name.empty())
            {
                std::string have = leaf_of(f->name), want = name;
                socketley::ascii::lower_in_place(have);
                socketley::ascii::lower_in_place(want);
                if (have.find(want) == std::string::npos)
                    return true;
            }
            return false;
        });
    }
    bool by_name = false, ascending = true;
    if (const jvalue* sort = json::member(args, "sort"); sort && sort->k == jvalue::kind::array && !sort->items.empty())
    {
        by_name = json::string_of(sort->items.front(), "property") == "name";
        if (const jvalue* asc = json::member(sort->items.front(), "isAscending"); asc && asc->k == jvalue::kind::boolean)
            ascending = asc->b;
    }
    std::stable_sort(folders.begin(), folders.end(), [&](const auto& a, const auto& b) {
        const auto ka = std::make_pair(by_name ? 0 : sort_order(a->name), leaf_of(a->name));
        const auto kb = std::make_pair(by_name ? 0 : sort_order(b->name), leaf_of(b->name));
        return ascending ? ka < kb : kb < ka;
    });
    const int64_t position = std::max<int64_t>(0, json::int_of(args, "position", 0));
    const int64_t limit = json::int_of(args, "limit", 100000);
    std::string ids = "[";
    for (size_t i = static_cast<size_t>(position); i < folders.size() && static_cast<int64_t>(i) < position + limit; ++i)
        ids += (ids.size() > 1 ? "," : "") + q(folders[i]->id());
    done({{"Mailbox/query", "{\"accountId\":" + q(account_of(m_user)) + ",\"queryState\":" +
                                q(mailbox_state(m_store, m_user)) + ",\"canCalculateChanges\":false,\"position\":" +
                                std::to_string(position) + ",\"ids\":" + ids + "],\"total\":" +
                                std::to_string(folders.size()) + "}"}});
}

void jmap_session::mailbox_set(const jvalue& args, const std::shared_ptr<call_state>& cs, std::function<void(answer)> done)
{
    struct job
    {
        std::string old_state;
        std::string created = "{", not_created = "{", updated = "{", not_updated = "{", destroyed = "[",
                    not_destroyed = "{";
        std::vector<std::pair<std::string, jvalue>> updates;
        std::vector<std::string> destroys;
        bool remove_emails{false};
        size_t at{0};
    };
    auto j = std::make_shared<job>();
    j->old_state = mailbox_state(m_store, m_user);
    const auto comma = [](std::string& s) {
        if (s.size() > 1)
            s += ",";
    };
    const auto name_of_id = [this, cs](std::string id) -> std::string {
        if (!id.empty() && id.front() == '#')
            id = cs->created.count(id.substr(1)) ? cs->created[id.substr(1)] : std::string();
        const auto f = mailbox_by_id(id);
        return f ? f->name : std::string();
    };
    // Creations are made at once, as CREATE is.
    if (const jvalue* create = json::member(args, "create"); create && create->k == jvalue::kind::object)
        for (const auto& [cid, obj] : create->members)
        {
            const std::string name(json::string_of(obj, "name"));
            const jvalue* parent = json::member(obj, "parentId");
            std::string under;
            if (parent && parent->k == jvalue::kind::string)
            {
                under = name_of_id(parent->s);
                if (under.empty())
                {
                    comma(j->not_created);
                    j->not_created += q(cid) + ":" + set_error("invalidProperties", "no such parentId");
                    continue;
                }
            }
            const std::string encoded = imap_utf7::encode(name);
            if (name.empty() || encoded.empty() || name.find('/') != std::string::npos)
            {
                comma(j->not_created);
                j->not_created += q(cid) + ":" + set_error("invalidProperties", "a name of one level is needed");
                continue;
            }
            const std::string full = under.empty() ? encoded : under + "/" + encoded;
            if (!m_store.create(m_user, full))
            {
                comma(j->not_created);
                j->not_created += q(cid) + ":" + set_error("invalidProperties", "a mailbox of that name is there");
                continue;
            }
            if (const jvalue* sub = json::member(obj, "isSubscribed"); sub && sub->k == jvalue::kind::boolean)
                m_store.set_subscribed(m_user, full, sub->b);
            const std::string id = m_store.mailbox_id(m_user, full);
            cs->created[cid] = id;
            comma(j->created);
            j->created += q(cid) + ":{\"id\":" + q(id) + ",\"totalEmails\":0,\"unreadEmails\":0,\"totalThreads\":0," +
                          "\"unreadThreads\":0,\"sortOrder\":10,\"role\":null}";
        }
    if (const jvalue* update = json::member(args, "update"); update && update->k == jvalue::kind::object)
        for (const auto& [id, patch] : update->members)
            j->updates.emplace_back(id, patch);
    for (const auto& id : strings_of(json::member(args, "destroy")))
        j->destroys.push_back(id);
    if (const jvalue* r = json::member(args, "onDestroyRemoveEmails"); r && r->k == jvalue::kind::boolean)
        j->remove_emails = r->b;
    // Then, one after the other, each rename and each removal, which go through the folder's messages.
    auto step = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak = step;
    *step = [this, j, weak, comma, name_of_id, done, alive = m_alive] {
        auto self = weak.lock();
        if (!*alive || !self)
            return;
        if (j->at < j->updates.size())
        {
            const auto& [id, patch] = j->updates[j->at++];
            const auto f = mailbox_by_id(id);
            if (!f)
            {
                comma(j->not_updated);
                j->not_updated += q(id) + ":" + set_error("notFound");
                return (*self)();
            }
            if (const jvalue* sub = json::member(patch, "isSubscribed"); sub && sub->k == jvalue::kind::boolean)
                m_store.set_subscribed(m_user, f->name, sub->b);
            const jvalue* name = json::member(patch, "name");
            const jvalue* parent = json::member(patch, "parentId");
            if (!name && !parent)
            {
                comma(j->updated);
                j->updated += q(id) + ":null";
                return (*self)();
            }
            const size_t slash = f->name.rfind('/');
            std::string under = slash == std::string::npos ? std::string() : f->name.substr(0, slash);
            if (parent)
                under = parent->k == jvalue::kind::string ? name_of_id(parent->s) : std::string();
            const std::string leaf = name && name->k == jvalue::kind::string ? imap_utf7::encode(name->s)
                                                                             : f->name.substr(slash + 1);
            if (leaf.empty() || (parent && parent->k == jvalue::kind::string && under.empty()))
            {
                comma(j->not_updated);
                j->not_updated += q(id) + ":" + set_error("invalidProperties");
                return (*self)();
            }
            const std::string to = under.empty() ? leaf : under + "/" + leaf;
            if (to == f->name)
            {
                comma(j->updated);
                j->updated += q(id) + ":null";
                return (*self)();
            }
            m_store.rename(m_user, f->name, to, [this, j, id, self, comma, alive](bool ok) {
                if (!*alive)
                    return;
                comma(ok ? j->updated : j->not_updated);
                (ok ? j->updated : j->not_updated) += q(id) + ":" + (ok ? std::string("null") : set_error("forbidden"));
                (*self)();
            });
            return;
        }
        if (j->at < j->updates.size() + j->destroys.size())
        {
            const std::string id = j->destroys[j->at++ - j->updates.size()];
            const auto f = mailbox_by_id(id);
            if (!f)
            {
                comma(j->not_destroyed);
                j->not_destroyed += q(id) + ":" + set_error("notFound");
                return (*self)();
            }
            const auto names = m_store.folder_names(m_user);
            if (std::any_of(names.begin(), names.end(), [&](const std::string& n) { return n.starts_with(f->name + "/"); }))
            {
                comma(j->not_destroyed);
                j->not_destroyed += q(id) + ":" + set_error("mailboxHasChild");
                return (*self)();
            }
            if (!f->msgs.empty() && !j->remove_emails)
            {
                comma(j->not_destroyed);
                j->not_destroyed += q(id) + ":" + set_error("mailboxHasEmail");
                return (*self)();
            }
            m_store.remove(m_user, f->name, [this, j, id, self, comma, alive](bool ok) {
                if (!*alive)
                    return;
                if (ok)
                {
                    comma(j->destroyed);
                    j->destroyed += q(id);
                }
                else
                {
                    comma(j->not_destroyed);
                    j->not_destroyed += q(id) + ":" + set_error("forbidden", "a mailbox every user has stays");
                }
                (*self)();
            });
            return;
        }
        done({{"Mailbox/set", "{\"accountId\":" + q(account_of(m_user)) + ",\"oldState\":" + q(j->old_state) +
                                  ",\"newState\":" + q(mailbox_state(m_store, m_user)) + ",\"created\":" + j->created +
                                  "},\"updated\":" + j->updated + "},\"destroyed\":" + j->destroyed +
                                  "],\"notCreated\":" + j->not_created + "},\"notUpdated\":" + j->not_updated +
                                  "},\"notDestroyed\":" + j->not_destroyed + "}}"}});
    };
    (*step)();
}

// ─── Email ──────────────────────────────────────────────────────────────────

void jmap_session::email_get(const jvalue& args, std::function<void(answer)> done)
{
    static const std::vector<std::string> defaults = {
        "id", "blobId", "threadId", "mailboxIds", "keywords", "size", "receivedAt", "messageId", "inReplyTo",
        "references", "sender", "from", "to", "cc", "bcc", "replyTo", "subject", "sentAt", "hasAttachment", "preview",
        "bodyValues", "textBody", "htmlBody", "attachments"};
    struct job
    {
        std::vector<std::string> ids, props;
        const jvalue* body_props{nullptr};
        jvalue args;
        bool text_values{false}, html_values{false}, all_values{false};
        size_t max_value{0};
        size_t at{0};
        std::string list = "[", not_found = "[";
        bool head{false}, whole{false};
        bool looping{false}, waiting{false};
    };
    auto j = std::make_shared<job>();
    j->args = args;
    const jvalue* ids = json::member(j->args, "ids");
    if (ids && ids->k == jvalue::kind::array)
        j->ids = strings_of(ids);
    else
        for (const auto& [id, at] : m_ids)
            if (j->ids.size() < 1000)
                j->ids.push_back(id);
    if (j->ids.size() > 1000)
        return done({{"error", set_error("requestTooLarge")}});
    const jvalue* props = json::member(j->args, "properties");
    j->props = props && props->k == jvalue::kind::array ? strings_of(props) : defaults;
    if (std::find(j->props.begin(), j->props.end(), "id") == j->props.end())
        j->props.insert(j->props.begin(), "id");
    j->body_props = json::member(j->args, "bodyProperties");
    const auto flag = [&](std::string_view k) {
        const jvalue* v = json::member(j->args, k);
        return v && v->k == jvalue::kind::boolean && v->b;
    };
    j->text_values = flag("fetchTextBodyValues");
    j->html_values = flag("fetchHTMLBodyValues");
    j->all_values = flag("fetchAllBodyValues");
    j->max_value = static_cast<size_t>(std::max<int64_t>(0, json::int_of(j->args, "maxBodyValueBytes", 0)));
    static const std::set<std::string> index_only = {"id", "blobId", "threadId", "mailboxIds", "keywords", "size",
                                                     "receivedAt"};
    static const std::set<std::string> header_props = {"messageId", "inReplyTo", "references", "sender", "from", "to",
                                                       "cc", "bcc", "replyTo", "subject", "sentAt", "headers"};
    for (const auto& p : j->props)
        if (!index_only.count(p))
        {
            if (header_props.count(p) || p.starts_with("header:"))
                j->head = true;
            else
                j->whole = true;
        }
    auto step = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak = step;
    *step = [this, j, weak, done, alive = m_alive] {
        auto self = weak.lock();
        if (!*alive || !self)
            return;
        j->looping = true;
        while (j->at < j->ids.size())
        {
            const std::string id = j->ids[j->at++];
            where w;
            if (!locate(id, w))
            {
                j->not_found += (j->not_found.size() > 1 ? "," : "") + q(id);
                continue;
            }
            const imap_message m = *w.m();
            const std::string mailbox = w.f->id();
            const email_view view{j->props, j->body_props, j->whole, j->text_values, j->html_values, j->all_values,
                                  j->max_value};
            const auto write = [j, view, id, m, mailbox](const std::string* bytes) {
                j->list += (j->list.size() > 1 ? "," : "") + email_object(view, id, &m, mailbox, bytes);
            };
            if (!j->head && !j->whole)
            {
                write(nullptr);
                continue;
            }
            j->waiting = true;
            const auto got = [j, self, write, alive](std::shared_ptr<const std::string> b) {
                if (!*alive)
                    return;
                write(b ? b.get() : nullptr);
                j->waiting = false;
                if (!j->looping)
                    (*self)();
            };
            if (j->whole)
                m_store.body(m.key, m.size, got);
            else
                m_store.head(m.key, m.size, got);
            if (j->waiting)
            {
                j->looping = false;
                return;
            }
        }
        j->looping = false;
        done({{"Email/get", "{\"accountId\":" + q(account_of(m_user)) + ",\"state\":" + q(email_state(m_store, m_user)) +
                                ",\"list\":" + j->list + "],\"notFound\":" + j->not_found + "]}"}});
    };
    (*step)();
}

void jmap_session::email_query(const jvalue& args, std::function<void(answer)> done)
{
    using cand = query_cand;
    struct job
    {
        jvalue args;
        std::vector<cand> all;
        size_t at{0};
        bool head{false}, whole{false};
        std::string sort_by{"receivedAt"};
        bool ascending{false};
        bool looping{false}, waiting{false};
        // Whether trigram filters may rule Emails out, and whether the one being read had none yet.
        bool filtering{false}, unfiltered{false};
    };
    auto j = std::make_shared<job>();
    j->args = args;
    const jvalue* filter = json::member(j->args, "filter");
    // What a filter needs of each Email beyond the index: its header, or all of it.
    std::function<void(const jvalue&)> needs = [&](const jvalue& f) {
        if (const jvalue* conds = json::member(f, "conditions"); conds && conds->k == jvalue::kind::array)
            for (const auto& c : conds->items)
                needs(c);
        for (const char* k : {"from", "to", "cc", "bcc", "subject", "header"})
            if (json::member(f, k))
                j->head = true;
        for (const char* k : {"text", "body", "hasAttachment"})
            if (json::member(f, k))
                j->whole = true;
    };
    if (filter)
        needs(*filter);
    if (const jvalue* sort = json::member(j->args, "sort"); sort && sort->k == jvalue::kind::array && !sort->items.empty())
    {
        j->sort_by = std::string(json::string_of(sort->items.front(), "property"));
        const jvalue* asc = json::member(sort->items.front(), "isAscending");
        j->ascending = asc && asc->k == jvalue::kind::boolean ? asc->b : true;
        if (j->sort_by != "receivedAt" && j->sort_by != "size" && j->sort_by != "subject" && j->sort_by != "from" &&
            j->sort_by != "to" && j->sort_by != "sentAt")
            return done({{"error", set_error("unsupportedSort")}});
        if (j->sort_by != "receivedAt" && j->sort_by != "size")
            j->head = true;
    }
    for (const auto& f : m_store.known(m_user))
        for (const auto& m : f->msgs)
            j->all.push_back({imap_store::email_id(m.key), m, f->id(), {}, false});
    j->filtering = j->whole && filter && filters_out(*filter);
    if (j->filtering)
        m_store.read_text_filters(m_user);
    auto step = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak = step;
    *step = [this, j, weak, done, alive = m_alive] {
        auto self = weak.lock();
        if (!*alive || !self)
            return;
        // What the filter or the sort reads is read for each Email, one after the other, and judged as it comes, so
        // only its header is kept; one the store holds goes on in this loop rather than a call deeper.
        const jvalue* filter = json::member(j->args, "filter");
        j->looping = true;
        while (j->at < j->all.size())
        {
            const size_t i = j->at++;
            cand& c = j->all[i];
            if (!j->head && !j->whole)
            {
                c.hit = !filter || meets(*filter, c, {}, nullptr);
                continue;
            }
            // An Email its trigram filter rules out is passed without being read; one without a filter is given one.
            if (j->filtering)
            {
                const std::string_view f = m_store.text_filter_of(m_user, c.id);
                j->unfiltered = f.empty();
                if (!j->unfiltered && !may_meet(*filter, f))
                    continue;
            }
            j->waiting = true;
            const auto got = [this, j, self, alive, i, filter](std::shared_ptr<const std::string> b) {
                if (!*alive)
                    return;
                cand& c = j->all[i];
                const std::string_view whole = b ? std::string_view(*b) : std::string_view{};
                c.head = std::string(header_block(whole));
                const std::shared_ptr<const mime::part> root =
                    j->whole && b && !b->empty() ? m_store.structure(c.m.key, b) : nullptr;
                // An Email read for want of a filter is given one first, which may spare it the filter itself.
                bool may = true;
                if (j->filtering && j->unfiltered && root)
                {
                    std::string tf = text_filter(whole, c.head, root.get());
                    may = may_meet(*filter, tf);
                    m_store.keep_text_filter(m_user, c.id, std::move(tf));
                }
                c.hit = may && (!filter || meets(*filter, c, whole, root.get()));
                // The header is kept only where the sort reads it.
                if (!c.hit || j->sort_by == "receivedAt" || j->sort_by == "size")
                    std::string().swap(c.head);
                j->waiting = false;
                if (!j->looping)
                    (*self)();
            };
            if (j->whole)
                m_store.body(c.m.key, c.m.size, got);
            else
                m_store.head(c.m.key, c.m.size, got);
            if (j->waiting)
            {
                j->looping = false;
                return;
            }
        }
        j->looping = false;
        std::vector<cand*> hits;
        for (auto& c : j->all)
            if (c.hit)
                hits.push_back(&c);
        const auto key = [&](const cand& c) -> std::string {
            if (j->sort_by == "subject")
            {
                std::string s = mime::decode_words(header_value(c.head, "Subject"));
                socketley::ascii::lower_in_place(s);
                return s;
            }
            if (j->sort_by == "from" || j->sort_by == "to")
            {
                std::string s = header_value(c.head, j->sort_by);
                socketley::ascii::lower_in_place(s);
                return s;
            }
            return {};
        };
        std::stable_sort(hits.begin(), hits.end(), [&](const cand* a, const cand* b) {
            bool less = false, more = false;
            if (j->sort_by == "size")
            {
                less = a->m.size < b->m.size;
                more = b->m.size < a->m.size;
            }
            else if (j->sort_by == "sentAt")
            {
                int64_t ta = 0, tb = 0;
                int za = 0, zb = 0;
                mime::parse_date(header_value(a->head, "Date"), ta, za);
                mime::parse_date(header_value(b->head, "Date"), tb, zb);
                less = ta < tb;
                more = tb < ta;
            }
            else if (j->sort_by == "receivedAt")
            {
                less = a->m.date_ms < b->m.date_ms;
                more = b->m.date_ms < a->m.date_ms;
            }
            else
            {
                const std::string ka = key(*a), kb = key(*b);
                less = ka < kb;
                more = kb < ka;
            }
            return j->ascending ? less : more;
        });
        int64_t position = json::int_of(j->args, "position", 0);
        if (const std::string_view anchor = json::string_of(j->args, "anchor"); !anchor.empty())
        {
            const auto it = std::find_if(hits.begin(), hits.end(), [&](const cand* c) { return c->id == anchor; });
            if (it == hits.end())
                return done({{"error", set_error("anchorNotFound")}});
            position = static_cast<int64_t>(it - hits.begin()) + json::int_of(j->args, "anchorOffset", 0);
        }
        if (position < 0)
            position = std::max<int64_t>(0, static_cast<int64_t>(hits.size()) + position);
        const int64_t limit = json::int_of(j->args, "limit", 1000);
        std::string ids = "[";
        for (int64_t i = position; i < static_cast<int64_t>(hits.size()) && i < position + limit; ++i)
            ids += (ids.size() > 1 ? "," : "") + q(hits[static_cast<size_t>(i)]->id);
        done({{"Email/query", "{\"accountId\":" + q(account_of(m_user)) + ",\"queryState\":" +
                                  q(email_state(m_store, m_user)) + ",\"canCalculateChanges\":false,\"position\":" +
                                  std::to_string(position) + ",\"collapseThreads\":false,\"ids\":" + ids + "],\"total\":" +
                                  std::to_string(hits.size()) + "}"}});
    };
    (*step)();
}

void jmap_session::thread_get(const jvalue& args, std::function<void(answer)> done)
{
    // Each Email is a Thread of its own, its id the Email's with T for M.
    std::string list = "[", missing = "[";
    for (const auto& id : strings_of(json::member(args, "ids")))
    {
        where w;
        if (id.size() > 1 && id[0] == 'T' && locate("M" + id.substr(1), w))
            list += (list.size() > 1 ? "," : "") + std::string("{\"id\":") + q(id) + ",\"emailIds\":[" + q("M" + id.substr(1)) + "]}";
        else
            missing += (missing.size() > 1 ? "," : "") + q(id);
    }
    done({{"Thread/get", "{\"accountId\":" + q(account_of(m_user)) + ",\"state\":" + q(email_state(m_store, m_user)) +
                             ",\"list\":" + list + "],\"notFound\":" + missing + "]}"}});
}

void jmap_session::identity_get(const jvalue&, std::function<void(answer)> done)
{
    // The one address the user sends as, with what they set of it.
    const std::string email = m_hooks.address_of(m_user);
    const std::string* kept = m_store.meta(m_user, {}, std::string(identity_entry));
    jvalue v;
    const bool have = kept && json::json_reader(*kept).document(v);
    const auto field = [&](std::string_view k, std::string_view otherwise) -> std::string {
        const jvalue* x = have ? json::member(v, k) : nullptr;
        return x ? json::written(*x) : std::string(otherwise);
    };
    done({{"Identity/get", "{\"accountId\":" + q(account_of(m_user)) + ",\"state\":" +
                               q(entry_state(kept)) + ",\"list\":[{\"id\":\"i0\",\"name\":" +
                               field("name", "\"\"") + ",\"email\":" + q(email) + ",\"replyTo\":" + field("replyTo", "null") +
                               ",\"bcc\":" + field("bcc", "null") + ",\"textSignature\":" + field("textSignature", "\"\"") +
                               ",\"htmlSignature\":" + field("htmlSignature", "\"\"") + ",\"mayDelete\":false}],\"notFound\":[]}"}});
}

void jmap_session::identity_set(const jvalue& args, std::function<void(answer)> done)
{
    // The address is the account's, so an Identity is neither made nor taken away here; the rest is the user's.
    std::string updated = "{", not_updated = "{", not_created = "{", not_destroyed = "{";
    const std::string* kept = m_store.meta(m_user, {}, std::string(identity_entry));
    const std::string old_state = entry_state(kept);
    jvalue v;
    if (!kept || !json::json_reader(*kept).document(v))
    {
        v = jvalue{};
        v.k = jvalue::kind::object;
    }
    if (const jvalue* c = json::member(args, "create"); c && c->k == jvalue::kind::object)
        for (const auto& [cid, obj] : c->members)
            not_created += (not_created.size() > 1 ? "," : "") + q(cid) + ":" +
                           set_error("forbiddenFrom", "the address a user sends as is the account's");
    for (const auto& id : strings_of(json::member(args, "destroy")))
        not_destroyed += (not_destroyed.size() > 1 ? "," : "") + q(id) + ":" + set_error("forbidden");
    if (const jvalue* u = json::member(args, "update"); u && u->k == jvalue::kind::object)
        for (const auto& [id, patch] : u->members)
        {
            bool fine = id == "i0" && patch.k == jvalue::kind::object;
            for (const auto& [k, x] : patch.members)
            {
                const bool text = k == "name" || k == "textSignature" || k == "htmlSignature";
                const bool list = k == "replyTo" || k == "bcc";
                fine = fine && ((text && x.k == jvalue::kind::string && x.s.size() <= 16384) ||
                                (list && (x.k == jvalue::kind::null || x.k == jvalue::kind::array)));
            }
            if (!fine)
            {
                not_updated += (not_updated.size() > 1 ? "," : "") + q(id) + ":" +
                               set_error(id == "i0" ? "invalidProperties" : "notFound");
                continue;
            }
            for (const auto& [k, x] : patch.members)
                if (jvalue* have = json::member(v, k))
                    *have = x;
                else
                    v.members.emplace_back(k, x);
            const std::string text = json::written(v);
            if (m_store.set_meta(m_user, {}, std::string(identity_entry), &text) != imap_store::meta_refusal::none)
            {
                not_updated += (not_updated.size() > 1 ? "," : "") + q(id) + ":" + set_error("tooLarge");
                continue;
            }
            updated += (updated.size() > 1 ? "," : "") + q(id) + ":null";
        }
    const std::string* now = m_store.meta(m_user, {}, std::string(identity_entry));
    done({{"Identity/set", "{\"accountId\":" + q(account_of(m_user)) + ",\"oldState\":" + q(old_state) +
                               ",\"newState\":" + q(entry_state(now)) +
                               ",\"created\":{},\"updated\":" + updated + "},\"destroyed\":[],\"notCreated\":" +
                               not_created + "},\"notUpdated\":" + not_updated + "},\"notDestroyed\":" + not_destroyed + "}}"}});
}

void jmap_session::email_set(const jvalue& args, const std::shared_ptr<call_state>& cs, std::function<void(answer)> done)
{
    struct job
    {
        jvalue args;
        std::string old_state;
        std::string created = "{", not_created = "{", updated = "{", not_updated = "{", destroyed = "[",
                    not_destroyed = "{";
        std::vector<std::pair<std::string, jvalue>> creates, updates;
        std::vector<std::string> destroys;
        size_t at{0};
    };
    auto j = std::make_shared<job>();
    j->args = args;
    j->old_state = email_state(m_store, m_user);
    if (const std::string_view if_in = json::string_of(args, "ifInState"); !if_in.empty() && if_in != j->old_state)
        return done({{"error", set_error("stateMismatch")}});
    if (const jvalue* c = json::member(j->args, "create"); c && c->k == jvalue::kind::object)
        j->creates = c->members;
    if (const jvalue* u = json::member(j->args, "update"); u && u->k == jvalue::kind::object)
        j->updates = u->members;
    j->destroys = strings_of(json::member(j->args, "destroy"));
    const auto comma = [](std::string& s) {
        if (s.size() > 1)
            s += ",";
    };
    const auto resolve = [cs](std::string id) {
        if (!id.empty() && id.front() == '#')
            return cs->created.count(id.substr(1)) ? cs->created[id.substr(1)] : std::string();
        return id;
    };
    auto step = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak = step;
    *step = [this, j, cs, weak, comma, resolve, done, alive = m_alive] {
        auto self = weak.lock();
        if (!*alive || !self)
            return;
        const size_t nc = j->creates.size(), nu = j->updates.size(), nd = j->destroys.size();
        if (j->at < nc)
        {
            const auto [cid, obj] = j->creates[j->at++];
            const std::string mbox = resolve(first_true(json::member(obj, "mailboxIds")));
            const auto f = mailbox_by_id(mbox);
            if (!f)
            {
                comma(j->not_created);
                j->not_created += q(cid) + ":" + set_error("invalidProperties", "mailboxIds names no mailbox");
                return (*self)();
            }
            // The message written from its parts, as socketley send writes one.
            compose c;
            const auto first_address = [&](std::string_view k, std::string* name) -> std::string {
                const jvalue* v = json::member(obj, k);
                if (!v || v->k != jvalue::kind::array || v->items.empty())
                    return {};
                if (name)
                    *name = std::string(json::string_of(v->items.front(), "name"));
                return std::string(json::string_of(v->items.front(), "email"));
            };
            std::string from_name;
            c.from = first_address("from", &from_name);
            if (c.from.empty())
                c.from = m_hooks.address_of(m_user);
            for (const char* k : {"to", "cc", "bcc"})
                if (const jvalue* v = json::member(obj, k); v && v->k == jvalue::kind::array)
                    for (const auto& a : v->items)
                        (std::string_view(k) == "to" ? c.to : std::string_view(k) == "cc" ? c.cc : c.bcc)
                            .emplace_back(json::string_of(a, "email"));
            c.reply_to = first_address("replyTo", nullptr);
            c.subject = std::string(json::string_of(obj, "subject"));
            const jvalue* values = json::member(obj, "bodyValues");
            const auto value_for = [&](std::string_view list) -> std::string {
                const jvalue* parts = json::member(obj, list);
                if (!parts || parts->k != jvalue::kind::array || parts->items.empty() || !values)
                    return {};
                const jvalue* v = json::member(*values, json::string_of(parts->items.front(), "partId"));
                return v ? std::string(json::string_of(*v, "value")) : std::string();
            };
            c.text = value_for("textBody");
            c.html = value_for("htmlBody");
            for (const auto& id : strings_of(json::member(obj, "messageId")))
                c.headers.push_back("Message-ID: <" + id + ">");
            for (const char* h : {"inReplyTo", "references"})
            {
                std::string v;
                for (const auto& id : strings_of(json::member(obj, h)))
                    v += (v.empty() ? "<" : " <") + id + ">";
                if (!v.empty())
                    c.headers.push_back(std::string(std::string_view(h) == "inReplyTo" ? "In-Reply-To: " : "References: ") + v);
            }
            std::vector<std::string> words;
            std::vector<std::string> kws;
            if (const jvalue* k = json::member(obj, "keywords"); k && k->k == jvalue::kind::object)
                for (const auto& [kw, on] : k->members)
                    if (on.k == jvalue::kind::boolean && on.b)
                        kws.push_back(kw);
            const uint8_t flags = flags_of(kws, words);
            const int64_t received = json::member(obj, "receivedAt") ? utc_ms(json::string_of(obj, "receivedAt")) : -1;
            // Attachments are blobs, read one after the other, then the message is written and put in.
            struct parts
            {
                compose c;
                std::vector<std::tuple<std::string, std::string, std::string>> blobs;
                size_t at{0};
            };
            auto pj = std::make_shared<parts>();
            pj->c = std::move(c);
            if (const jvalue* a = json::member(obj, "attachments"); a && a->k == jvalue::kind::array)
                for (const auto& x : a->items)
                    pj->blobs.emplace_back(json::string_of(x, "blobId"), json::string_of(x, "type"), json::string_of(x, "name"));
            auto more = std::make_shared<std::function<void()>>();
            std::weak_ptr<std::function<void()>> wmore = more;
            *more = [this, j, cs, self, pj, wmore, comma, cid, f, flags, words, received, from_name, alive] {
                auto me = wmore.lock();
                if (!*alive || !me)
                    return;
                if (pj->at < pj->blobs.size())
                {
                    const auto [blob_id, type, name] = pj->blobs[pj->at++];
                    blob(blob_id, [pj, me, type, name, alive, j, comma, cid, self](std::shared_ptr<const std::string> b) {
                        if (!*alive)
                            return;
                        if (!b)
                        {
                            comma(j->not_created);
                            j->not_created += q(cid) + ":" + set_error("blobNotFound");
                            return (*self)();
                        }
                        pj->c.attachments.push_back({name.empty() ? "attachment" : name,
                                                     type.empty() ? "application/octet-stream" : type, *b});
                        (*me)();
                    });
                    return;
                }
                address from;
                composed out;
                std::string why;
                const std::string msgid = socketley::random_hex(16) + "@" + m_cfg.hostname;
                if (!parse_address(pj->c.from, from, true) ||
                    !compose_message(pj->c, from, from_name, msgid, wall::now_ms(), out, why))
                {
                    comma(j->not_created);
                    j->not_created += q(cid) + ":" + set_error("invalidProperties", why);
                    return (*self)();
                }
                if (out.message.size() > m_cfg.max_size)
                {
                    comma(j->not_created);
                    j->not_created += q(cid) + ":" + set_error("tooLarge");
                    return (*self)();
                }
                const uint64_t size = out.message.size();
                m_store.append(m_user, f->name, std::move(out.message), flags, words,
                               received >= 0 ? received : wall::now_ms(),
                               [this, j, cs, self, comma, cid, f, size, alive](imap_store::refusal r, uint32_t, uint32_t uid) {
                                   if (!*alive)
                                       return;
                                   const imap_message* m = r == imap_store::refusal::none ? f->by_uid(uid) : nullptr;
                                   if (!m)
                                   {
                                       comma(j->not_created);
                                       j->not_created += q(cid) + ":" +
                                                         set_error(r == imap_store::refusal::quota ? "overQuota" : "forbidden");
                                       return (*self)();
                                   }
                                   const std::string id = imap_store::email_id(m->key);
                                   m_ids[id] = {f, uid};
                                   cs->created[cid] = id;
                                   comma(j->created);
                                   j->created += q(cid) + ":{\"id\":" + q(id) + ",\"blobId\":" + q(id) +
                                                 ",\"threadId\":" + q("T" + id.substr(1)) + ",\"size\":" +
                                                 std::to_string(size) + "}";
                                   m_hooks.acted(m_user, f->name, "APPEND", {uid});
                                   (*self)();
                               });
            };
            (*more)();
            return;
        }
        if (j->at < nc + nu)
        {
            const auto [given, patch] = j->updates[j->at++ - nc];
            const std::string id = resolve(given);
            where w;
            if (!locate(id, w))
            {
                comma(j->not_updated);
                j->not_updated += q(given) + ":" + set_error("notFound");
                return (*self)();
            }
            const imap_message m = *w.m();
            // The keywords as they are to be: set whole, or patched one by one.
            std::vector<std::string> kws = keywords_of(m);
            bool keywords_changed = false;
            std::string move_to;
            for (const auto& [k, v] : patch.members)
            {
                if (k == "keywords" && v.k == jvalue::kind::object)
                {
                    kws.clear();
                    for (const auto& [kw, on] : v.members)
                        if (on.k == jvalue::kind::boolean && on.b)
                        {
                            std::string l = kw;
                            socketley::ascii::lower_in_place(l);
                            kws.push_back(l);
                        }
                    keywords_changed = true;
                }
                else if (k.starts_with("keywords/"))
                {
                    std::string kw = k.substr(9);
                    socketley::ascii::lower_in_place(kw);
                    std::erase(kws, kw);
                    if (v.k == jvalue::kind::boolean && v.b)
                        kws.push_back(kw);
                    keywords_changed = true;
                }
                else if (k == "mailboxIds" && v.k == jvalue::kind::object)
                {
                    if (v.members.size() != 1)
                    {
                        comma(j->not_updated);
                        j->not_updated += q(given) + ":" + set_error("tooManyMailboxes", "an Email is in one mailbox");
                        return (*self)();
                    }
                    move_to = resolve(v.members.front().first);
                }
                else if (k.starts_with("mailboxIds/"))
                {
                    if (v.k == jvalue::kind::boolean && v.b)
                        move_to = resolve(k.substr(11));
                    else if (resolve(k.substr(11)) == w.f->id() && move_to.empty())
                    {
                        // Out of its one mailbox with nowhere else to be is no Email at all.
                        comma(j->not_updated);
                        j->not_updated += q(given) + ":" + set_error("invalidProperties", "an Email is in a mailbox");
                        return (*self)();
                    }
                }
                else
                {
                    comma(j->not_updated);
                    j->not_updated += q(given) + ":" + set_error("invalidProperties", "only keywords and mailboxIds change");
                    return (*self)();
                }
            }
            if (keywords_changed)
            {
                std::vector<std::string> words;
                const uint8_t bits = flags_of(kws, words);
                m_store.set_flags(m_user, w.f, {w.uid},
                                  [bits](uint8_t f) { return static_cast<uint8_t>((f & flag_deleted) | bits); },
                                  keyword_change{keyword_change::kind::set, std::move(words)});
            }
            const auto to = move_to.empty() || move_to == w.f->id() ? nullptr : mailbox_by_id(move_to);
            if (!move_to.empty() && move_to != w.f->id() && !to)
            {
                comma(j->not_updated);
                j->not_updated += q(given) + ":" + set_error("invalidProperties", "no such mailbox");
                return (*self)();
            }
            if (!to)
            {
                comma(j->updated);
                j->updated += q(given) + ":null";
                return (*self)();
            }
            // A move is a copy, keeping the object's name and so the id, and the original taken away.
            m_store.copy(m_user, w.f, {w.uid}, to->name, false,
                         [this, j, self, comma, given, w, to, id, alive](bool ok, uint32_t, std::vector<uint32_t> made) {
                             if (!*alive)
                                 return;
                             if (!ok || made.empty())
                             {
                                 comma(j->not_updated);
                                 j->not_updated += q(given) + ":" + set_error("forbidden");
                                 return (*self)();
                             }
                             if (const imap_message* nm = to->by_uid(made.front()))
                                 m_ids[imap_store::email_id(nm->key)] = {to, made.front()};
                             m_hooks.acted(m_user, to->name, "COPY", made);
                             m_store.expunge(m_user, w.f, {w.uid}, true, [j, self, comma, given, alive](std::vector<uint32_t>) {
                                 if (!*alive)
                                     return;
                                 comma(j->updated);
                                 j->updated += q(given) + ":null";
                                 (*self)();
                             });
                         });
            return;
        }
        if (j->at < nc + nu + nd)
        {
            const std::string given = j->destroys[j->at++ - nc - nu];
            where w;
            if (!locate(resolve(given), w))
            {
                comma(j->not_destroyed);
                j->not_destroyed += q(given) + ":" + set_error("notFound");
                return (*self)();
            }
            m_store.expunge(m_user, w.f, {w.uid}, true, [j, self, comma, given, alive](std::vector<uint32_t> gone) {
                if (!*alive)
                    return;
                if (gone.empty())
                {
                    comma(j->not_destroyed);
                    j->not_destroyed += q(given) + ":" + set_error("forbidden");
                }
                else
                {
                    comma(j->destroyed);
                    j->destroyed += q(given);
                }
                (*self)();
            });
            return;
        }
        done({{"Email/set", "{\"accountId\":" + q(account_of(m_user)) + ",\"oldState\":" + q(j->old_state) +
                                ",\"newState\":" + q(email_state(m_store, m_user)) + ",\"created\":" + j->created +
                                "},\"updated\":" + j->updated + "},\"destroyed\":" + j->destroyed +
                                "],\"notCreated\":" + j->not_created + "},\"notUpdated\":" + j->not_updated +
                                "},\"notDestroyed\":" + j->not_destroyed + "}}"}});
    };
    (*step)();
}

void jmap_session::email_import(const jvalue& args, const std::shared_ptr<call_state>& cs, std::function<void(answer)> done)
{
    struct job
    {
        std::vector<std::pair<std::string, jvalue>> emails;
        size_t at{0};
        std::string old_state, created = "{", not_created = "{";
    };
    auto j = std::make_shared<job>();
    j->old_state = email_state(m_store, m_user);
    if (const jvalue* e = json::member(args, "emails"); e && e->k == jvalue::kind::object)
        j->emails = e->members;
    const auto comma = [](std::string& s) {
        if (s.size() > 1)
            s += ",";
    };
    auto step = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak = step;
    *step = [this, j, cs, weak, comma, done, alive = m_alive] {
        auto self = weak.lock();
        if (!*alive || !self)
            return;
        if (j->at >= j->emails.size())
            return done({{"Email/import", "{\"accountId\":" + q(account_of(m_user)) + ",\"oldState\":" + q(j->old_state) +
                                              ",\"newState\":" + q(email_state(m_store, m_user)) + ",\"created\":" +
                                              j->created + "},\"notCreated\":" + j->not_created + "}}"}});
        const auto [cid, obj] = j->emails[j->at++];
        std::string mbox = first_true(json::member(obj, "mailboxIds"));
        if (!mbox.empty() && mbox.front() == '#')
            mbox = cs->created.count(mbox.substr(1)) ? cs->created[mbox.substr(1)] : std::string();
        const auto f = mailbox_by_id(mbox);
        if (!f)
        {
            comma(j->not_created);
            j->not_created += q(cid) + ":" + set_error("invalidProperties", "mailboxIds names no mailbox");
            return (*self)();
        }
        std::vector<std::string> kws, words;
        if (const jvalue* k = json::member(obj, "keywords"); k && k->k == jvalue::kind::object)
            for (const auto& [kw, on] : k->members)
                if (on.k == jvalue::kind::boolean && on.b)
                    kws.push_back(kw);
        const uint8_t flags = flags_of(kws, words);
        const int64_t received = json::member(obj, "receivedAt") ? utc_ms(json::string_of(obj, "receivedAt")) : -1;
        blob(std::string(json::string_of(obj, "blobId")),
             [this, j, cs, self, comma, cid, f, flags, words, received, alive](std::shared_ptr<const std::string> b) {
                 if (!*alive)
                     return;
                 if (!b)
                 {
                     comma(j->not_created);
                     j->not_created += q(cid) + ":" + set_error("blobNotFound");
                     return (*self)();
                 }
                 const uint64_t size = b->size();
                 m_store.append(m_user, f->name, crlf_lines(*b), flags, words, received >= 0 ? received : wall::now_ms(),
                                [this, j, cs, self, comma, cid, f, size, alive](imap_store::refusal r, uint32_t, uint32_t uid) {
                                    if (!*alive)
                                        return;
                                    const imap_message* m = r == imap_store::refusal::none ? f->by_uid(uid) : nullptr;
                                    if (!m)
                                    {
                                        comma(j->not_created);
                                        j->not_created += q(cid) + ":" +
                                                          set_error(r == imap_store::refusal::quota ? "overQuota" : "forbidden");
                                        return (*self)();
                                    }
                                    const std::string id = imap_store::email_id(m->key);
                                    m_ids[id] = {f, uid};
                                    cs->created[cid] = id;
                                    comma(j->created);
                                    j->created += q(cid) + ":{\"id\":" + q(id) + ",\"blobId\":" + q(id) +
                                                  ",\"threadId\":" + q("T" + id.substr(1)) + ",\"size\":" +
                                                  std::to_string(size) + "}";
                                    m_hooks.acted(m_user, f->name, "APPEND", {uid});
                                    (*self)();
                                });
             });
    };
    (*step)();
}

void jmap_session::email_parse(const jvalue& args, std::function<void(answer)> done)
{
    struct job
    {
        std::vector<std::string> blobs;
        email_view view;
        size_t at{0};
        std::string parsed = "{", not_parsable = "[", not_found = "[";
    };
    auto j = std::make_shared<job>();
    j->blobs = strings_of(json::member(args, "blobIds"));
    if (j->blobs.size() > 1000)
        return done({{"error", set_error("requestTooLarge")}});
    const jvalue* props = json::member(args, "properties");
    j->view.props = props && props->k == jvalue::kind::array
                        ? strings_of(props)
                        : std::vector<std::string>{"messageId", "inReplyTo", "references", "sender", "from", "to", "cc",
                                                   "bcc", "replyTo", "subject", "sentAt", "hasAttachment", "preview",
                                                   "bodyValues", "textBody", "htmlBody", "attachments"};
    // What a parsed blob's view reads is the whole of it, which is all it has.
    j->view.whole = true;
    const auto flag = [&](std::string_view k) {
        const jvalue* v = json::member(args, k);
        return v && v->k == jvalue::kind::boolean && v->b;
    };
    j->view.text_values = flag("fetchTextBodyValues");
    j->view.html_values = flag("fetchHTMLBodyValues");
    j->view.all_values = flag("fetchAllBodyValues");
    j->view.max_value = static_cast<size_t>(std::max<int64_t>(0, json::int_of(args, "maxBodyValueBytes", 0)));
    // A body property list given is kept by the request, which outlives this job.
    j->view.body_props = nullptr;
    auto step = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak = step;
    *step = [this, j, weak, done, alive = m_alive] {
        auto self = weak.lock();
        if (!*alive || !self)
            return;
        if (j->at >= j->blobs.size())
            return done({{"Email/parse", "{\"accountId\":" + q(account_of(m_user)) + ",\"parsed\":" + j->parsed +
                                             "},\"notParsable\":" + j->not_parsable + "],\"notFound\":" + j->not_found +
                                             "]}"}});
        const std::string id = j->blobs[j->at++];
        blob(id, [j, self, id, alive](std::shared_ptr<const std::string> b) {
            if (!*alive)
                return;
            if (!b)
                j->not_found += (j->not_found.size() > 1 ? "," : "") + q(id);
            // A blob is a message where it has a header of at least one field.
            else if (split_headers(header_block(*b)).empty())
                j->not_parsable += (j->not_parsable.size() > 1 ? "," : "") + q(id);
            else
                j->parsed += (j->parsed.size() > 1 ? "," : "") + q(id) + ":" + email_object(j->view, id, nullptr, {}, b.get());
            (*self)();
        });
    };
    (*step)();
}

// ─── VacationResponse ───────────────────────────────────────────────────────

void jmap_session::vacation_get(const jvalue&, std::function<void(answer)> done)
{
    // The one VacationResponse an account has, off until it is set.
    const std::string* kept = m_store.meta(m_user, {}, std::string(vacation_entry));
    jvalue v;
    json::json_policy policy;
    const bool have = kept && json::json_reader(*kept, policy).document(v);
    const auto field = [&](std::string_view k, std::string_view otherwise) -> std::string {
        const jvalue* x = have ? json::member(v, k) : nullptr;
        return x ? json::written(*x) : std::string(otherwise);
    };
    done({{"VacationResponse/get", "{\"accountId\":" + q(account_of(m_user)) + ",\"state\":" +
                                       q(entry_state(kept)) +
                                       ",\"list\":[{\"id\":\"singleton\",\"isEnabled\":" + field("isEnabled", "false") +
                                       ",\"fromDate\":" + field("fromDate", "null") + ",\"toDate\":" +
                                       field("toDate", "null") + ",\"subject\":" + field("subject", "null") +
                                       ",\"textBody\":" + field("textBody", "null") + ",\"htmlBody\":" +
                                       field("htmlBody", "null") + "}],\"notFound\":[]}"}});
}

void jmap_session::vacation_set(const jvalue& args, std::function<void(answer)> done)
{
    std::string updated = "{", not_updated = "{";
    const std::string* kept = m_store.meta(m_user, {}, std::string(vacation_entry));
    // Taken now, since a set replaces what `kept` points at.
    const std::string old_state = entry_state(kept);
    jvalue v;
    json::json_policy policy;
    if (!kept || !json::json_reader(*kept, policy).document(v))
    {
        v = jvalue{};
        v.k = jvalue::kind::object;
    }
    if (const jvalue* c = json::member(args, "create"); c && c->k == jvalue::kind::object && !c->members.empty())
        return done({{"error", set_error("invalidArguments", "a VacationResponse is a singleton: update it")}});
    if (const jvalue* u = json::member(args, "update"); u && u->k == jvalue::kind::object)
        for (const auto& [id, patch] : u->members)
        {
            if (id != "singleton" || patch.k != jvalue::kind::object)
            {
                not_updated += (not_updated.size() > 1 ? "," : "") + q(id) + ":" + set_error("notFound");
                continue;
            }
            bool fine = true;
            for (const auto& [k, x] : patch.members)
            {
                const bool known = k == "isEnabled" || k == "fromDate" || k == "toDate" || k == "subject" ||
                                   k == "textBody" || k == "htmlBody";
                const bool typed = k == "isEnabled" ? x.k == jvalue::kind::boolean
                                   : k == "fromDate" || k == "toDate"
                                       ? x.k == jvalue::kind::null || (x.k == jvalue::kind::string && utc_ms(x.s) >= 0)
                                       : x.k == jvalue::kind::null || x.k == jvalue::kind::string;
                fine = fine && known && typed;
            }
            if (!fine)
            {
                not_updated += (not_updated.size() > 1 ? "," : "") + q(id) + ":" + set_error("invalidProperties");
                continue;
            }
            for (const auto& [k, x] : patch.members)
            {
                if (jvalue* have = json::member(v, k))
                    *have = x;
                else
                    v.members.emplace_back(k, x);
            }
            const std::string text = json::written(v);
            if (m_store.set_meta(m_user, {}, std::string(vacation_entry), &text) != imap_store::meta_refusal::none)
            {
                not_updated += (not_updated.size() > 1 ? "," : "") + q(id) + ":" + set_error("tooLarge");
                continue;
            }
            updated += (updated.size() > 1 ? "," : "") + q(id) + ":null";
        }
    if (const jvalue* d = json::member(args, "destroy"); d && d->k == jvalue::kind::array && !d->items.empty())
        return done({{"error", set_error("invalidArguments", "a VacationResponse is not destroyed: turn it off")}});
    const std::string* now = m_store.meta(m_user, {}, std::string(vacation_entry));
    done({{"VacationResponse/set", "{\"accountId\":" + q(account_of(m_user)) + ",\"oldState\":" +
                                       q(old_state) + ",\"newState\":" + q(entry_state(now)) + ",\"updated\":" + updated +
                                       "},\"notUpdated\":" + not_updated + "}}"}});
}

// ─── PushSubscription ───────────────────────────────────────────────────────

namespace
{

// The user's subscriptions as kept, an empty array where there are none.
jvalue subscriptions_of(imap_store& store, const std::string& user)
{
    jvalue v;
    const std::string* kept = store.meta(user, {}, std::string(jmap_session::push_entry));
    if (kept && json::json_reader(*kept).document(v))
        if (const jvalue* subs = json::member(v, "subs"); subs && subs->k == jvalue::kind::array)
            return *subs;
    v = jvalue{};
    v.k = jvalue::kind::array;
    return v;
}

jvalue string_value(std::string s)
{
    jvalue v;
    v.k = jvalue::kind::string;
    v.s = std::move(s);
    return v;
}

void put(jvalue& obj, const std::string& k, jvalue x)
{
    if (jvalue* have = json::member(obj, k))
        *have = std::move(x);
    else
        obj.members.emplace_back(k, std::move(x));
}

}   // namespace

void jmap_session::push_get(const jvalue& args, std::function<void(answer)> done)
{
    // Neither its URL, its keys nor its code are said back: they are the push service's and the client's alone.
    const jvalue subs = subscriptions_of(m_store, m_user);
    const jvalue* ids = json::member(args, "ids");
    std::string list = "[", missing = "[";
    std::set<std::string> found;
    for (const auto& sub : subs.items)
    {
        const std::string id(json::string_of(sub, "id"));
        if (ids && ids->k == jvalue::kind::array &&
            std::none_of(ids->items.begin(), ids->items.end(), [&](const jvalue& x) { return x.s == id; }))
            continue;
        found.insert(id);
        const jvalue* types = json::member(sub, "types");
        list += (list.size() > 1 ? "," : "") + std::string("{\"id\":") + q(id) + ",\"deviceClientId\":" +
                q(json::string_of(sub, "deviceClientId")) + ",\"expires\":" + q(json::string_of(sub, "expires")) +
                ",\"types\":" + (types ? json::written(*types) : std::string("null")) + "}";
    }
    if (ids && ids->k == jvalue::kind::array)
        for (const auto& x : ids->items)
            if (!found.count(x.s))
                missing += (missing.size() > 1 ? "," : "") + q(x.s);
    done({{"PushSubscription/get", "{\"list\":" + list + "],\"notFound\":" + missing + "]}"}});
}

void jmap_session::push_set(const jvalue& args, const std::shared_ptr<call_state>& cs, std::function<void(answer)> done)
{
    jvalue subs = subscriptions_of(m_store, m_user);
    std::string created = "{", not_created = "{", updated = "{", not_updated = "{", destroyed = "[", not_destroyed = "{";
    const auto comma = [](std::string& s) {
        if (s.size() > 1)
            s += ",";
    };
    // A subscription lasts a week at most, and is renewed by setting its expires again (RFC 8620 7.2.2).
    const int64_t now = wall::now_ms();
    const auto capped = [now](const jvalue* asked) {
        const int64_t want = asked && asked->k == jvalue::kind::string ? utc_ms(asked->s) : -1;
        return utc(want > now && want < now + 7 * 86400000ll ? want : now + 7 * 86400000ll);
    };
    std::vector<std::tuple<std::string, std::string, std::string, std::string>> to_verify;
    if (const jvalue* c = json::member(args, "create"); c && c->k == jvalue::kind::object)
        for (const auto& [cid, obj] : c->members)
        {
            const std::string url(json::string_of(obj, "url"));
            const std::string device(json::string_of(obj, "deviceClientId"));
            std::string p256dh, auth;
            bool keys_ok = true;
            if (const jvalue* k = json::member(obj, "keys"); k && k->k == jvalue::kind::object)
                keys_ok = socketley::base64url::decode(json::string_of(*k, "p256dh"), p256dh) && p256dh.size() == 65 &&
                          p256dh[0] == '\x04' && socketley::base64url::decode(json::string_of(*k, "auth"), auth) &&
                          auth.size() == 16;
            // A push URL is the push service's, over HTTPS, without a fragment or white space.
            const bool url_ok = url.starts_with("https://") && url.size() <= 2048 &&
                                url.find_first_of(" \t\r\n#") == std::string::npos;
            if (!url_ok || device.empty() || device.size() > 255 || !keys_ok || subs.items.size() >= 50)
            {
                comma(not_created);
                not_created += q(cid) + ":" +
                               set_error(subs.items.size() >= 50 ? "overQuota" : "invalidProperties",
                                         !url_ok ? "url is an https:// URL" : !keys_ok ? "keys are a P-256 point and 16 bytes"
                                                                                       : "deviceClientId is needed");
                continue;
            }
            const std::string id = "P" + socketley::random_hex(8);
            const std::string code = socketley::random_hex(16);
            jvalue sub;
            sub.k = jvalue::kind::object;
            put(sub, "id", string_value(id));
            put(sub, "deviceClientId", string_value(device));
            put(sub, "url", string_value(url));
            put(sub, "p256dh", string_value(socketley::base64url::encode(p256dh)));
            put(sub, "auth", string_value(socketley::base64url::encode(auth)));
            put(sub, "verificationCode", string_value(code));
            put(sub, "verified", jvalue{});
            const std::string expires = capped(json::member(obj, "expires"));
            put(sub, "expires", string_value(expires));
            if (const jvalue* t = json::member(obj, "types"); t && t->k == jvalue::kind::array)
                put(sub, "types", *t);
            subs.items.push_back(std::move(sub));
            cs->created[cid] = id;
            comma(created);
            created += q(cid) + ":{\"id\":" + q(id) + ",\"keys\":null,\"expires\":" + q(expires) + "}";
            to_verify.emplace_back(url, p256dh, auth,
                                   "{\"@type\":\"PushVerification\",\"pushSubscriptionId\":" + q(id) +
                                       ",\"verificationCode\":" + q(code) + "}");
        }
    const auto find = [&subs, &cs](std::string id) -> jvalue* {
        if (!id.empty() && id.front() == '#')
            id = cs->created.count(id.substr(1)) ? cs->created[id.substr(1)] : std::string();
        for (auto& sub : subs.items)
            if (json::string_of(sub, "id") == id)
                return &sub;
        return nullptr;
    };
    if (const jvalue* u = json::member(args, "update"); u && u->k == jvalue::kind::object)
        for (const auto& [id, patch] : u->members)
        {
            jvalue* sub = find(id);
            if (!sub)
            {
                comma(not_updated);
                not_updated += q(id) + ":" + set_error("notFound");
                continue;
            }
            bool fine = true;
            std::string answer_expires;
            for (const auto& [k, v] : patch.members)
            {
                if (k == "verificationCode" && v.k == jvalue::kind::string)
                {
                    // The code the push service carried to the client, which proves the client reads that URL.
                    if (!socketley::crypto::secure_equal(v.s, json::string_of(*sub, "verificationCode")))
                        fine = false;
                    else
                    {
                        jvalue yes;
                        yes.k = jvalue::kind::boolean;
                        yes.b = true;
                        put(*sub, "verified", yes);
                    }
                }
                else if (k == "expires")
                {
                    answer_expires = capped(&v);
                    put(*sub, "expires", string_value(answer_expires));
                }
                else if (k == "types" && (v.k == jvalue::kind::array || v.k == jvalue::kind::null))
                    put(*sub, "types", v);
                else
                    fine = false;
            }
            comma(fine ? updated : not_updated);
            if (fine)
                updated += q(id) + ":" + (answer_expires.empty() ? std::string("null") : "{\"expires\":" + q(answer_expires) + "}");
            else
                not_updated += q(id) + ":" + set_error("invalidProperties", "the verificationCode is not the one pushed");
        }
    for (const auto& id : strings_of(json::member(args, "destroy")))
    {
        jvalue* sub = find(id);
        if (!sub)
        {
            comma(not_destroyed);
            not_destroyed += q(id) + ":" + set_error("notFound");
            continue;
        }
        const std::string real(json::string_of(*sub, "id"));
        std::erase_if(subs.items, [&](const jvalue& x) { return json::string_of(x, "id") == real; });
        comma(destroyed);
        destroyed += q(id);
    }
    // Kept with the states as they are now, from which the pushes begin, whenever the first look at them comes.
    jvalue entry;
    entry.k = jvalue::kind::object;
    put(entry, "state", string_value(email_state(m_store, m_user) + " " + mailbox_state(m_store, m_user)));
    put(entry, "subs", subs);
    const std::string text = json::written(entry);
    if (subs.items.empty())
        m_store.set_meta(m_user, {}, std::string(push_entry), nullptr);
    else if (m_store.set_meta(m_user, {}, std::string(push_entry), &text) != imap_store::meta_refusal::none)
        return done({{"error", set_error("serverFail", "the subscriptions could not be kept")}});
    m_store.note_push_user(m_user, !subs.items.empty());
    for (auto& [url, p256dh, auth, body] : to_verify)
        m_hooks.push(url, p256dh, auth, std::move(body));
    done({{"PushSubscription/set", "{\"created\":" + created + "},\"updated\":" + updated + "},\"destroyed\":" +
                                       destroyed + "],\"notCreated\":" + not_created + "},\"notUpdated\":" +
                                       not_updated + "},\"notDestroyed\":" + not_destroyed + "}}"}});
}

// ─── EmailSubmission ────────────────────────────────────────────────────────

void jmap_session::submission_set(const jvalue& args, const std::shared_ptr<call_state>& cs, std::function<void(answer)> done)
{
    struct job
    {
        jvalue args;
        std::vector<std::pair<std::string, jvalue>> creates;
        size_t at{0};
        std::string created = "{", not_created = "{";
        // The submissions sent, by creation id, and the Emails they sent, for onSuccess*.
        std::unordered_map<std::string, std::string> sent_email;
    };
    auto j = std::make_shared<job>();
    j->args = args;
    if (const jvalue* c = json::member(j->args, "create"); c && c->k == jvalue::kind::object)
        j->creates = c->members;
    const auto comma = [](std::string& s) {
        if (s.size() > 1)
            s += ",";
    };
    auto step = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak = step;
    *step = [this, j, cs, weak, comma, done, alive = m_alive] {
        auto self = weak.lock();
        if (!*alive || !self)
            return;
        if (j->at < j->creates.size())
        {
            const auto [cid, obj] = j->creates[j->at++];
            std::string email_id(json::string_of(obj, "emailId"));
            if (!email_id.empty() && email_id.front() == '#')
                email_id = cs->created.count(email_id.substr(1)) ? cs->created[email_id.substr(1)] : std::string();
            where w;
            if (!locate(email_id, w))
            {
                comma(j->not_created);
                j->not_created += q(cid) + ":" + set_error("invalidProperties", "emailId names no Email");
                return (*self)();
            }
            const imap_message m = *w.m();
            const jvalue* envelope = json::member(obj, "envelope");
            m_store.body(m.key, m.size, [this, j, self, comma, cid, email_id, envelope = envelope ? *envelope : jvalue{},
                                          alive](std::shared_ptr<const std::string> b) {
                if (!*alive)
                    return;
                if (!b)
                {
                    comma(j->not_created);
                    j->not_created += q(cid) + ":" + set_error("notFound", "the Email could not be read");
                    return (*self)();
                }
                const std::string_view head = header_block(*b);
                const std::string own = m_hooks.address_of(m_user);
                std::string from;
                std::vector<std::string> rcpts;
                if (const jvalue* mf = json::member(envelope, "mailFrom"))
                    from = std::string(json::string_of(*mf, "email"));
                if (const jvalue* rt = json::member(envelope, "rcptTo"); rt && rt->k == jvalue::kind::array)
                    for (const auto& r : rt->items)
                        rcpts.emplace_back(json::string_of(r, "email"));
                if (from.empty())
                {
                    address a;
                    std::string display;
                    from = parse_mailbox(header_value(head, "From"), a, &display) ? a.text() : own;
                }
                if (rcpts.empty())
                    for (const char* h : {"To", "Cc", "Bcc"})
                    {
                        std::vector<address> list;
                        if (parse_mailbox_list(header_value(head, h), list))
                            for (const auto& a : list)
                                rcpts.push_back(a.text());
                    }
                // A user sends as their own address, as submission holds them to.
                if (!socketley::ascii::iequals(from, own))
                {
                    comma(j->not_created);
                    j->not_created += q(cid) + ":" + set_error("forbiddenFrom", "the user sends as " + own);
                    return (*self)();
                }
                if (rcpts.empty())
                {
                    comma(j->not_created);
                    j->not_created += q(cid) + ":" + set_error("noRecipients");
                    return (*self)();
                }
                // The Bcc header does not go with the message (RFC 8621 7.5).
                std::string message;
                for (const auto& [n, v] : split_headers(head))
                    if (!socketley::ascii::iequals(n, "Bcc"))
                        message.append(n.data(), n.size()).append(":").append(v.data(), v.size()).append("\r\n");
                message += "\r\n";
                message.append(std::string_view(*b).substr(head.size()));
                m_hooks.submit(m_user, from, rcpts, std::move(message),
                               [j, self, comma, cid, email_id, alive](bool ok, std::string spool_id) {
                                   if (!*alive)
                                       return;
                                   if (!ok)
                                   {
                                       comma(j->not_created);
                                       j->not_created += q(cid) + ":" + set_error("forbidden", "the message could not be queued");
                                       return (*self)();
                                   }
                                   j->sent_email[cid] = email_id;
                                   comma(j->created);
                                   j->created += q(cid) + ":{\"id\":" + q("S" + spool_id) + ",\"sendAt\":" +
                                                 q(utc(wall::now_ms())) + ",\"undoStatus\":\"final\"}";
                                   (*self)();
                               });
            });
            return;
        }
        answer a{{"EmailSubmission/set", "{\"accountId\":" + q(account_of(m_user)) + ",\"oldState\":\"s0\",\"newState\":\"s0\"," +
                                             "\"created\":" + j->created + "},\"notCreated\":" + j->not_created + "}}"}};
        // What a submission's success asks of its Email is an Email/set, answered after it (RFC 8621 7.5).
        jvalue update, destroy;
        update.k = jvalue::kind::object;
        destroy.k = jvalue::kind::array;
        if (const jvalue* on = json::member(j->args, "onSuccessUpdateEmail"); on && on->k == jvalue::kind::object)
            for (const auto& [ref, patch] : on->members)
            {
                const std::string sub = ref.starts_with("#") ? ref.substr(1) : ref;
                if (const auto it = j->sent_email.find(sub); it != j->sent_email.end())
                    update.members.emplace_back(it->second, patch);
            }
        if (const jvalue* on = json::member(j->args, "onSuccessDestroyEmail"); on && on->k == jvalue::kind::array)
            for (const auto& ref : on->items)
            {
                const std::string sub = ref.s.starts_with("#") ? ref.s.substr(1) : ref.s;
                if (const auto it = j->sent_email.find(sub); it != j->sent_email.end())
                {
                    jvalue id;
                    id.k = jvalue::kind::string;
                    id.s = it->second;
                    destroy.items.push_back(std::move(id));
                }
            }
        if (update.members.empty() && destroy.items.empty())
            return done(std::move(a));
        jvalue set;
        set.k = jvalue::kind::object;
        jvalue acct;
        acct.k = jvalue::kind::string;
        acct.s = account_of(m_user);
        set.members.emplace_back("accountId", std::move(acct));
        set.members.emplace_back("update", std::move(update));
        set.members.emplace_back("destroy", std::move(destroy));
        email_set(set, cs, [a = std::move(a), done](answer more) mutable {
            for (auto& x : more)
                a.push_back(std::move(x));
            done(std::move(a));
        });
    };
    (*step)();
}

}   // namespace socketley::mail
