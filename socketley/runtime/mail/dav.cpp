#include "dav.h"

#include <algorithm>
#include <ctime>
#include <optional>
#include <utility>
#include <vector>

#include "dav_store.h"
#include "../../shared/util/xml_doc.h"

namespace socketley::mail
{

namespace
{

constexpr std::string_view ns_dav = "DAV:";
constexpr std::string_view ns_cal = "urn:ietf:params:xml:ns:caldav";
constexpr std::string_view ns_card = "urn:ietf:params:xml:ns:carddav";
constexpr std::string_view ns_cs = "http://calendarserver.org/ns/";
constexpr std::string_view ns_apple = "http://apple.com/ns/ical/";
constexpr std::string_view sync_prefix = "http://socketley.net/ns/sync/";
// An entry is one object the request channel carries whole.
constexpr size_t max_entry = 1u << 20;

std::string prefix_of(std::string_view ns)
{
    if (ns == ns_dav)
        return "d";
    if (ns == ns_cal)
        return "c";
    if (ns == ns_card)
        return "card";
    if (ns == ns_cs)
        return "cs";
    if (ns == ns_apple)
        return "a";
    return {};
}

// A property's element: `inner` inside it, or empty, in its namespace whether or not the document declares it.
std::string element(std::string_view ns, std::string_view name, std::string_view inner)
{
    const std::string p = prefix_of(ns);
    const std::string q = p.empty() ? "x:" + std::string(name) : p + ":" + std::string(name);
    const std::string decl = p.empty() ? " xmlns:x=\"" + xml::escape(ns) + "\"" : std::string();
    return inner.empty() ? "<" + q + decl + "/>" : "<" + q + decl + ">" + std::string(inner) + "</" + q + ">";
}

std::string href(std::string_view path)
{
    return "<d:href>" + xml::escape(path) + "</d:href>";
}

std::string pct(std::string_view s)
{
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    for (const char ch : s)
    {
        const auto c = static_cast<unsigned char>(ch);
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' ||
            c == '_' || c == '~' || c == '@' || c == '+' || c == '=')
            out += ch;
        else
        {
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 15];
        }
    }
    return out;
}

std::string unpct(std::string_view s)
{
    std::string out;
    for (size_t i = 0; i < s.size(); ++i)
    {
        if (s[i] == '%' && i + 2 < s.size() && std::isxdigit(static_cast<unsigned char>(s[i + 1])) &&
            std::isxdigit(static_cast<unsigned char>(s[i + 2])))
        {
            out += static_cast<char>(std::stoi(std::string(s.substr(i + 1, 2)), nullptr, 16));
            i += 2;
        }
        else
            out += s[i];
    }
    return out;
}

std::string http_date(int64_t ms)
{
    const time_t t = static_cast<time_t>(ms / 1000);
    std::tm tm{};
    ::gmtime_r(&t, &tm);
    char buf[64];
    std::strftime(buf, sizeof buf, "%a, %d %b %Y %H:%M:%S GMT", &tm);
    return buf;
}

std::string unquote(std::string_view etag)
{
    while (!etag.empty() && etag.front() == ' ')
        etag.remove_prefix(1);
    if (etag.starts_with("W/"))
        etag.remove_prefix(2);
    if (etag.size() >= 2 && etag.front() == '"' && etag.back() == '"')
        etag = etag.substr(1, etag.size() - 2);
    return std::string(etag);
}

enum class level { root, principal, home, collection, entry };

struct target
{
    level lv{level::root};
    std::string kind, coll, name;
};

// What a target is known by once looked up: a collection's properties and token, an entry's etag and bytes.
struct item
{
    target t;
    std::vector<std::pair<std::string, std::string>> props;
    uint64_t token{0};
    std::string etag;
    uint64_t size{0};
    int64_t mtime_ms{0};
    std::optional<std::string> data;
    bool missing{false};
    // The storage could not answer, so `missing` says nothing about the collection.
    bool failed{false};
};

struct prop_name
{
    std::string ns, name;
};

std::string_view prop_value(const std::vector<std::pair<std::string, std::string>>& props, std::string_view k)
{
    for (const auto& [n, v] : props)
        if (n == k)
            return v;
    return {};
}

std::string entry_type(std::string_view kind)
{
    return kind == "calendars" ? "text/calendar; charset=utf-8" : "text/vcard; charset=utf-8";
}

std::string multistatus(std::string_view responses, std::string_view tail = {})
{
    return "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<d:multistatus xmlns:d=\"DAV:\" xmlns:c=\"" +
           std::string(ns_cal) + "\" xmlns:card=\"" + std::string(ns_card) + "\" xmlns:cs=\"" + std::string(ns_cs) +
           "\" xmlns:a=\"" + std::string(ns_apple) + "\">" + std::string(responses) + std::string(tail) +
           "</d:multistatus>\n";
}

std::string response(std::string_view path, std::string_view found, std::string_view missing)
{
    std::string out = "<d:response>" + href(path);
    if (!found.empty())
        out += "<d:propstat><d:prop>" + std::string(found) + "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>";
    if (!missing.empty())
        out += "<d:propstat><d:prop>" + std::string(missing) +
               "</d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>";
    return out + "</d:response>";
}

std::string gone_response(std::string_view path)
{
    return "<d:response>" + href(path) + "<d:status>HTTP/1.1 404 Not Found</d:status></d:response>";
}

dav_reply error_reply(int code, std::string_view text)
{
    return {code, "text/plain; charset=utf-8", std::string(text) + "\n", {}};
}

dav_reply precondition(int code, std::string_view ns, std::string_view name)
{
    return {code, "application/xml; charset=utf-8",
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<d:error xmlns:d=\"DAV:\">" + element(ns, name, "") +
                "</d:error>\n",
            {}};
}

struct op : std::enable_shared_from_this<op>
{
    dav_store& store;
    std::shared_ptr<bool> alive;
    std::string user, address;
    dav_request rq;
    std::function<void(dav_reply)> done;
    target here;

    op(dav_store& s, std::shared_ptr<bool> a, std::string u, std::string addr, dav_request r,
       std::function<void(dav_reply)> d)
        : store(s), alive(std::move(a)), user(std::move(u)), address(std::move(addr)), rq(std::move(r)),
          done(std::move(d))
    {
    }

    std::string base() const { return "/dav/" + pct(user) + "/"; }

    std::string path_of(const target& t) const
    {
        switch (t.lv)
        {
            case level::root: return "/dav/";
            case level::principal: return base();
            case level::home: return base() + t.kind + "/";
            case level::collection: return base() + t.kind + "/" + pct(t.coll) + "/";
            case level::entry: return base() + t.kind + "/" + pct(t.coll) + "/" + pct(t.name);
        }
        return "/dav/";
    }

    // The target a path names; false for one no user's DAV has, or another user's.
    bool parse(std::string_view path, target& t, int& refusal) const
    {
        refusal = 404;
        if (const size_t q = path.find('?'); q != std::string_view::npos)
            path = path.substr(0, q);
        if (path == "/" || path == "/dav" || path == "/dav/")
        {
            t = {};
            return true;
        }
        if (!path.starts_with("/dav/"))
            return false;
        std::vector<std::string> seg;
        for (std::string_view rest = path.substr(5); !rest.empty();)
        {
            const size_t slash = rest.find('/');
            const std::string_view s = rest.substr(0, slash);
            rest = slash == std::string_view::npos ? std::string_view{} : rest.substr(slash + 1);
            if (!s.empty())
                seg.push_back(unpct(s));
        }
        if (seg.empty())
        {
            t = {};
            return true;
        }
        if (seg[0] != user)
        {
            refusal = 403;
            return false;
        }
        t = {};
        t.lv = level::principal;
        if (seg.size() == 1)
            return true;
        if (seg[1] != "calendars" && seg[1] != "contacts")
            return false;
        t.kind = seg[1];
        t.lv = level::home;
        if (seg.size() == 2)
            return true;
        if (!dav_store::collection_ok(seg[2]))
            return false;
        t.coll = seg[2];
        t.lv = level::collection;
        if (seg.size() == 3)
            return true;
        if (seg.size() != 4 || !dav_store::entry_ok(seg[3]))
            return false;
        t.name = seg[3];
        t.lv = level::entry;
        return true;
    }

    void reply(dav_reply r)
    {
        if (*alive)
            done(std::move(r));
    }

    void run()
    {
        int refusal = 404;
        if (!parse(rq.path, here, refusal))
            return reply(error_reply(refusal, refusal == 403 ? "that is another user's" : "nothing is here"));
        const std::string& m = rq.method;
        if (m == "OPTIONS")
            return reply({200, {}, {},
                          "DAV: " + std::string(dav_classes) + "\r\nAllow: " + std::string(dav_allow) + "\r\n"});
        if (m == "PROPFIND")
            return propfind();
        if (m == "PROPPATCH")
            return proppatch();
        if (m == "REPORT")
            return report();
        if (m == "MKCALENDAR" || m == "MKCOL")
            return mkcol(m == "MKCALENDAR");
        if ((m == "GET" || m == "HEAD") && here.lv == level::entry)
            return get(m == "HEAD");
        if (m == "PUT" && here.lv == level::entry)
            return put();
        if (m == "DELETE" && (here.lv == level::entry || here.lv == level::collection))
            return remove();
        reply({405, "text/plain; charset=utf-8", "not this method here\n", "Allow: " + std::string(dav_allow) + "\r\n"});
    }

    // ─── looking things up ──────────────────────────────────────────────────

    // A collection with its properties and token; `missing` where it is no default and has no .props.
    void collection(target t, std::function<void(item)> then)
    {
        auto self = shared_from_this();
        store.props(user, t.kind, t.coll, [self, t, then](bool ok, bool found, std::vector<std::pair<std::string, std::string>> props) {
            item it;
            it.t = t;
            it.props = std::move(props);
            it.token = self->store.token(self->user, t.kind, t.coll);
            it.failed = !ok;
            it.missing = !ok || (!found && t.coll != dav_store::default_of(t.kind));
            then(std::move(it));
        });
    }

    // Each of `ts` looked up in turn, collections with their properties and entries with their bytes.
    void lookup(std::shared_ptr<std::vector<target>> ts, size_t i, std::shared_ptr<std::vector<item>> out,
                bool with_data, std::function<void()> then)
    {
        if (i == ts->size())
            return then();
        auto self = shared_from_this();
        const target t = (*ts)[i];
        const auto next = [self, ts, i, out, with_data, then](item it) {
            if (!*self->alive)
                return;
            out->push_back(std::move(it));
            self->lookup(ts, i + 1, out, with_data, then);
        };
        if (t.lv == level::collection)
            return collection(t, next);
        if (t.lv == level::entry)
            return store.get(user, t.kind, t.coll, t.name,
                             [t, next, with_data](bool ok, bool found, std::string data, std::string etag) {
                                 item it;
                                 it.t = t;
                                 it.missing = !ok || !found;
                                 it.etag = std::move(etag);
                                 it.size = data.size();
                                 if (with_data && found)
                                     it.data = std::move(data);
                                 next(std::move(it));
                             });
        item it;
        it.t = t;
        next(std::move(it));
    }

    // ─── properties ─────────────────────────────────────────────────────────

    std::string privileges(std::string_view kind) const
    {
        std::string out;
        for (const char* p : {"read", "write", "write-properties", "write-content", "bind", "unbind", "all"})
            out += "<d:privilege><d:" + std::string(p) + "/></d:privilege>";
        if (kind == "calendars")
            out += "<d:privilege><c:read-free-busy/></d:privilege>";
        return out;
    }

    // A property's content for `it`, or none where it has no such property.
    std::optional<std::string> value(const item& it, std::string_view ns, std::string_view name) const
    {
        const target& t = it.t;
        const bool cal = t.kind == "calendars";
        if (ns == ns_dav)
        {
            if (name == "resourcetype")
            {
                switch (t.lv)
                {
                    case level::root:
                    case level::home: return "<d:collection/>";
                    case level::principal: return "<d:principal/>";
                    case level::collection: return cal ? "<d:collection/><c:calendar/>" : "<d:collection/><card:addressbook/>";
                    case level::entry: return "";
                }
            }
            if (name == "current-user-principal")
                return href(base());
            if (name == "principal-URL" && t.lv == level::principal)
                return href(base());
            if (name == "owner" && t.lv != level::root)
                return href(base());
            if (name == "displayname")
            {
                if (t.lv == level::collection)
                {
                    const std::string_view v = prop_value(it.props, "displayname");
                    return xml::escape(!v.empty() ? v : t.coll == "personal" ? std::string_view("Calendar")
                                                     : t.coll == "default"    ? std::string_view("Contacts")
                                                                              : std::string_view(t.coll));
                }
                if (t.lv == level::entry)
                    return std::nullopt;
                return xml::escape(t.lv == level::home ? (cal ? "Calendars" : "Contacts") : user);
            }
            if (name == "current-user-privilege-set" && t.lv != level::root)
                return privileges(t.kind);
            if (name == "supported-report-set" && t.lv == level::collection)
                return std::string("<d:supported-report><d:report>") + (cal ? "<c:calendar-multiget/>" : "<card:addressbook-multiget/>") +
                       "</d:report></d:supported-report><d:supported-report><d:report>" +
                       (cal ? "<c:calendar-query/>" : "<card:addressbook-query/>") +
                       "</d:report></d:supported-report><d:supported-report><d:report><d:sync-collection/></d:report>"
                       "</d:supported-report>";
            if (name == "sync-token" && t.lv == level::collection)
                return std::string(sync_prefix) + std::to_string(it.token);
            if (t.lv == level::entry)
            {
                if (name == "getetag")
                    return xml::escape("\"" + it.etag + "\"");
                if (name == "getcontenttype")
                    return entry_type(t.kind);
                if (name == "getcontentlength")
                    return std::to_string(it.size);
                if (name == "getlastmodified" && it.mtime_ms)
                    return http_date(it.mtime_ms);
            }
            return std::nullopt;
        }
        if (ns == ns_cs && name == "getctag" && t.lv == level::collection)
            return std::to_string(it.token);
        if (ns == ns_cal)
        {
            if (name == "calendar-home-set" && t.lv == level::principal)
                return href(base() + "calendars/");
            if (name == "calendar-user-address-set" && t.lv == level::principal)
                return href("mailto:" + address);
            if (!cal || t.lv != level::collection)
            {
                if (name == "calendar-data" && cal && t.lv == level::entry && it.data)
                    return xml::escape(*it.data);
                return std::nullopt;
            }
            if (name == "calendar-description")
                return xml::escape(prop_value(it.props, "description"));
            if (name == "supported-calendar-component-set")
            {
                std::string out;
                std::string_view comps = prop_value(it.props, "components");
                if (comps.empty())
                    comps = "VEVENT,VTODO";
                for (std::string_view rest = comps; !rest.empty();)
                {
                    const size_t comma = rest.find(',');
                    out += "<c:comp name=\"" + xml::escape(rest.substr(0, comma)) + "\"/>";
                    rest = comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
                }
                return out;
            }
            if (name == "max-resource-size")
                return std::to_string(max_entry);
            return std::nullopt;
        }
        if (ns == ns_card)
        {
            if (name == "addressbook-home-set" && t.lv == level::principal)
                return href(base() + "contacts/");
            if (name == "address-data" && !cal && t.lv == level::entry && it.data)
                return xml::escape(*it.data);
            if (cal || t.lv != level::collection)
                return std::nullopt;
            if (name == "addressbook-description")
                return xml::escape(prop_value(it.props, "description"));
            if (name == "supported-address-data")
                return std::string("<card:address-data-type content-type=\"text/vcard\" version=\"3.0\"/>"
                                   "<card:address-data-type content-type=\"text/vcard\" version=\"4.0\"/>");
            if (name == "max-resource-size")
                return std::to_string(max_entry);
            return std::nullopt;
        }
        if (ns == ns_apple && t.lv == level::collection && cal)
        {
            if (name == "calendar-color")
            {
                const std::string_view c = prop_value(it.props, "color");
                return xml::escape(c.empty() ? std::string_view("#7C5CFFFF") : c);
            }
            if (name == "calendar-order")
            {
                const std::string_view o = prop_value(it.props, "order");
                return std::string(o.empty() ? std::string_view("1") : o);
            }
        }
        return std::nullopt;
    }

    // What allprop gives: every property `it` has, but its data.
    std::vector<prop_name> all_of(const item& it) const
    {
        std::vector<prop_name> out = {{std::string(ns_dav), "resourcetype"}, {std::string(ns_dav), "displayname"},
                                      {std::string(ns_dav), "current-user-principal"}};
        const auto add = [&](std::string_view ns, std::string_view n) { out.push_back({std::string(ns), std::string(n)}); };
        switch (it.t.lv)
        {
            case level::principal:
                add(ns_dav, "principal-URL");
                add(ns_cal, "calendar-home-set");
                add(ns_card, "addressbook-home-set");
                add(ns_cal, "calendar-user-address-set");
                break;
            case level::collection:
                add(ns_dav, "sync-token");
                add(ns_cs, "getctag");
                add(ns_dav, "owner");
                add(ns_dav, "current-user-privilege-set");
                add(ns_dav, "supported-report-set");
                if (it.t.kind == "calendars")
                {
                    add(ns_cal, "supported-calendar-component-set");
                    add(ns_cal, "calendar-description");
                    add(ns_apple, "calendar-color");
                }
                else
                {
                    add(ns_card, "supported-address-data");
                    add(ns_card, "addressbook-description");
                }
                break;
            case level::entry:
                out = {{std::string(ns_dav), "resourcetype"}, {std::string(ns_dav), "getetag"},
                       {std::string(ns_dav), "getcontenttype"}, {std::string(ns_dav), "getcontentlength"}};
                if (it.mtime_ms)
                    add(ns_dav, "getlastmodified");
                break;
            default:
                break;
        }
        return out;
    }

    std::string render(const item& it, const std::vector<prop_name>* asked) const
    {
        const std::vector<prop_name> names = asked ? *asked : all_of(it);
        std::string found, missing;
        for (const auto& p : names)
        {
            if (const auto v = value(it, p.ns, p.name))
                found += element(p.ns, p.name, *v);
            else
                missing += element(p.ns, p.name, "");
        }
        return response(path_of(it.t), found, missing);
    }

    // The properties a body's <prop> asks for, none for allprop or no body.
    static bool asked_props(const xml::node* parent, std::vector<prop_name>& out, bool& data)
    {
        out.clear();
        data = false;
        const xml::node* p = parent ? parent->child("prop", ns_dav) : nullptr;
        if (!p)
            return false;
        for (const auto& k : p->kids)
        {
            out.push_back({k.ns, k.name});
            data = data || (k.name == "calendar-data" && k.ns == ns_cal) || (k.name == "address-data" && k.ns == ns_card);
        }
        return true;
    }

    bool read_body(xml::node& doc)
    {
        if (rq.body.find_first_not_of(" \t\r\n") == std::string::npos)
            return false;
        return xml::reader(rq.body).document(doc);
    }

    // ─── PROPFIND ───────────────────────────────────────────────────────────

    void propfind()
    {
        xml::node doc;
        const bool has_body = rq.body.find_first_not_of(" \t\r\n") != std::string::npos;
        if (has_body && (!xml::reader(rq.body).document(doc) || doc.name != "propfind" || doc.ns != ns_dav))
            return reply(error_reply(400, "the body is no propfind"));
        auto asked = std::make_shared<std::vector<prop_name>>();
        bool data = false;
        const bool some = has_body && asked_props(&doc, *asked, data);
        const std::string depth = rq.header("depth");
        const bool deep = depth == "1" || depth == "infinity" || (depth.empty() && here.lv != level::entry);
        auto ts = std::make_shared<std::vector<target>>(1, here);
        auto self = shared_from_this();
        const auto finish = [self, ts, asked, some, data] {
            auto items = std::make_shared<std::vector<item>>();
            self->lookup(ts, 0, items, data, [self, items, asked, some] {
                if (items->empty() || (*items)[0].missing)
                    return self->reply(error_reply(404, "nothing is here"));
                std::string body;
                for (const auto& it : *items)
                    if (!it.missing)
                        body += self->render(it, some ? asked.get() : nullptr);
                self->reply({207, "application/xml; charset=utf-8", multistatus(body), {}});
            });
        };
        if (!deep || here.lv == level::root || here.lv == level::entry)
            return finish();
        if (here.lv == level::principal)
        {
            for (const char* k : {"calendars", "contacts"})
                ts->push_back({level::home, k, {}, {}});
            return finish();
        }
        if (here.lv == level::home)
            return store.collections(user, here.kind, [self, ts, finish](bool ok, std::vector<std::string> names) {
                if (!ok)
                    return self->reply(error_reply(503, "the storage cannot be reached now"));
                for (auto& n : names)
                    ts->push_back({level::collection, self->here.kind, std::move(n), {}});
                finish();
            });
        // A collection's entries, their etags from the listing unless their data is asked for.
        store.entries(user, here.kind, here.coll, [self, ts, asked, some, data](bool ok, std::vector<dav_store::entry> all) {
            if (!ok)
                return self->reply(error_reply(503, "the storage cannot be reached now"));
            self->collection(self->here, [self, all = std::move(all), ts, asked, some, data](item coll) mutable {
                if (coll.missing)
                    return self->reply(error_reply(404, "nothing is here"));
                std::string body = self->render(coll, some ? asked.get() : nullptr);
                if (!data)
                {
                    for (auto& e : all)
                    {
                        item it;
                        it.t = {level::entry, self->here.kind, self->here.coll, e.name};
                        it.etag = e.etag;
                        it.size = e.size;
                        it.mtime_ms = e.mtime_ms;
                        body += self->render(it, some ? asked.get() : nullptr);
                    }
                    return self->reply({207, "application/xml; charset=utf-8", multistatus(body), {}});
                }
                auto entries = std::make_shared<std::vector<target>>();
                for (auto& e : all)
                    entries->push_back({level::entry, self->here.kind, self->here.coll, std::move(e.name)});
                auto items = std::make_shared<std::vector<item>>();
                self->lookup(entries, 0, items, true, [self, items, body, asked] {
                    std::string out = body;
                    for (const auto& it : *items)
                        if (!it.missing)
                            out += self->render(it, asked.get());
                    self->reply({207, "application/xml; charset=utf-8", multistatus(out), {}});
                });
            });
        });
    }

    // ─── PROPPATCH, MKCALENDAR, MKCOL ───────────────────────────────────────

    // The properties a <set> holds that a collection keeps, by their names in .props; the rest in `refused`.
    static void settable(const xml::node& set, std::vector<std::pair<std::string, std::string>>& props,
                         std::vector<prop_name>& taken, std::vector<prop_name>& refused)
    {
        const xml::node* p = set.child("prop", ns_dav);
        if (!p)
            return;
        for (const auto& k : p->kids)
        {
            std::string key;
            if (k.ns == ns_dav && k.name == "displayname")
                key = "displayname";
            else if (k.ns == ns_apple && k.name == "calendar-color")
                key = "color";
            else if (k.ns == ns_apple && k.name == "calendar-order")
                key = "order";
            else if ((k.ns == ns_cal && k.name == "calendar-description") ||
                     (k.ns == ns_card && k.name == "addressbook-description"))
                key = "description";
            else if (k.ns == ns_cal && k.name == "supported-calendar-component-set")
            {
                std::string comps;
                for (const auto& c : k.kids)
                    if (c.name == "comp" && (c.attr("name") == "VEVENT" || c.attr("name") == "VTODO" || c.attr("name") == "VJOURNAL"))
                        comps += (comps.empty() ? "" : ",") + std::string(c.attr("name"));
                if (!comps.empty())
                    props.emplace_back("components", comps);
                taken.push_back({k.ns, k.name});
                continue;
            }
            else if (k.ns == ns_dav && k.name == "resourcetype")
                continue;
            if (key.empty())
            {
                refused.push_back({k.ns, k.name});
                continue;
            }
            std::erase_if(props, [&](const auto& kv) { return kv.first == key; });
            props.emplace_back(key, k.text.substr(0, 512));
            taken.push_back({k.ns, k.name});
        }
    }

    void proppatch()
    {
        xml::node doc;
        if (!read_body(doc) || doc.name != "propertyupdate" || doc.ns != ns_dav)
            return reply(error_reply(400, "the body is no propertyupdate"));
        if (here.lv != level::collection)
            return reply(error_reply(403, "only a collection's properties are kept"));
        auto self = shared_from_this();
        collection(here, [self, doc](item it) {
            if (it.missing)
                return self->reply(error_reply(404, "nothing is here"));
            std::vector<prop_name> taken, refused;
            for (const auto& k : doc.kids)
            {
                if (k.ns == ns_dav && k.name == "set")
                    settable(k, it.props, taken, refused);
                else if (k.ns == ns_dav && k.name == "remove")
                {
                    std::vector<std::pair<std::string, std::string>> gone;
                    settable(k, gone, taken, refused);
                    for (const auto& [key, v] : gone)
                        std::erase_if(it.props, [&](const auto& kv) { return kv.first == key; });
                }
            }
            self->store.set_props(self->user, self->here.kind, self->here.coll, it.props, [self, taken, refused](bool ok) {
                if (!ok)
                    return self->reply(error_reply(503, "the storage cannot be reached now"));
                std::string found, no;
                for (const auto& p : taken)
                    found += element(p.ns, p.name, "");
                for (const auto& p : refused)
                    no += element(p.ns, p.name, "");
                std::string body = "<d:response>" + href(self->path_of(self->here));
                if (!found.empty())
                    body += "<d:propstat><d:prop>" + found + "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>";
                if (!no.empty())
                    body += "<d:propstat><d:prop>" + no + "</d:prop><d:status>HTTP/1.1 403 Forbidden</d:status></d:propstat>";
                body += "</d:response>";
                self->reply({207, "application/xml; charset=utf-8", multistatus(body), {}});
            });
        });
    }

    void mkcol(bool calendar)
    {
        if (here.lv != level::collection)
            return reply(error_reply(403, "a collection is made in a home"));
        xml::node doc;
        const bool has_body = rq.body.find_first_not_of(" \t\r\n") != std::string::npos;
        if (has_body && !xml::reader(rq.body).document(doc))
            return reply(error_reply(400, "the body is no XML"));
        // An extended MKCOL names what it makes; a plain one makes the kind its home holds.
        if (!calendar && has_body)
        {
            const xml::node* set = doc.child("set", ns_dav);
            const xml::node* p = set ? set->child("prop", ns_dav) : nullptr;
            const xml::node* type = p ? p->child("resourcetype", ns_dav) : nullptr;
            const bool book = type && type->child("addressbook", ns_card);
            const bool cal = type && type->child("calendar", ns_cal);
            if ((book && here.kind != "contacts") || (cal && here.kind != "calendars"))
                return reply(precondition(403, ns_dav, "valid-resourcetype"));
        }
        if (calendar != (here.kind == "calendars") && calendar)
            return reply(error_reply(403, "a calendar is made among the calendars"));
        auto self = shared_from_this();
        collection(here, [self, doc, has_body](item it) {
            if (it.failed)
                return self->reply(error_reply(503, "the storage cannot be reached now"));
            if (!it.missing)
                return self->reply(precondition(405, ns_dav, "resource-must-be-null"));
            std::vector<std::pair<std::string, std::string>> props;
            std::vector<prop_name> taken, refused;
            if (has_body)
                if (const xml::node* set = doc.child("set", ns_dav))
                    settable(*set, props, taken, refused);
            if (props.empty())
                props.emplace_back("displayname", self->here.coll);
            self->store.set_props(self->user, self->here.kind, self->here.coll, props, [self](bool ok) {
                self->reply(ok ? dav_reply{201, {}, {}, {}} : error_reply(503, "the storage cannot be reached now"));
            });
        });
    }

    // ─── REPORT ─────────────────────────────────────────────────────────────

    void report()
    {
        xml::node doc;
        if (!read_body(doc))
            return reply(error_reply(400, "the body is no report"));
        auto asked = std::make_shared<std::vector<prop_name>>();
        bool data = false;
        asked_props(&doc, *asked, data);
        const bool multiget = (doc.name == "calendar-multiget" && doc.ns == ns_cal) ||
                              (doc.name == "addressbook-multiget" && doc.ns == ns_card);
        const bool query = (doc.name == "calendar-query" && doc.ns == ns_cal) ||
                           (doc.name == "addressbook-query" && doc.ns == ns_card);
        const bool sync = doc.name == "sync-collection" && doc.ns == ns_dav;
        if (!multiget && !query && !sync)
            return reply(precondition(403, ns_dav, "supported-report"));
        if (here.lv != level::collection && !(multiget && here.lv == level::home))
            return reply(error_reply(403, "a report is of a collection"));
        if (asked->empty())
            *asked = {{std::string(ns_dav), "getetag"}};
        if (multiget)
            return multiget_report(doc, asked);
        if (query)
            return query_report(doc, asked, data);
        sync_report(doc, asked);
    }

    void multiget_report(const xml::node& doc, std::shared_ptr<std::vector<prop_name>> asked)
    {
        auto ts = std::make_shared<std::vector<target>>();
        auto gone = std::make_shared<std::vector<std::string>>();
        for (const auto& k : doc.kids)
        {
            if (k.name != "href" || k.ns != ns_dav || ts->size() >= 1000)
                continue;
            std::string path = k.text;
            // A client may give the whole URL rather than its path.
            if (const size_t scheme = path.find("://"); scheme != std::string::npos)
                path = path.substr(std::min(path.size(), path.find('/', scheme + 3)));
            target t;
            int refusal = 0;
            if (parse(path, t, refusal) && t.lv == level::entry && t.kind == here.kind)
                ts->push_back(t);
            else
                gone->push_back(path);
        }
        auto items = std::make_shared<std::vector<item>>();
        auto self = shared_from_this();
        lookup(ts, 0, items, true, [self, items, gone, asked] {
            std::string body;
            for (const auto& it : *items)
                body += it.missing ? gone_response(self->path_of(it.t)) : self->render(it, asked.get());
            for (const auto& g : *gone)
                body += gone_response(g);
            self->reply({207, "application/xml; charset=utf-8", multistatus(body), {}});
        });
    }

    // The component a calendar-query's filter asks for inside VCALENDAR, empty for any.
    static std::string wanted_component(const xml::node& doc)
    {
        const xml::node* filter = doc.child("filter", ns_cal);
        const xml::node* outer = filter ? filter->child("comp-filter", ns_cal) : nullptr;
        if (!outer || outer->attr("name") != "VCALENDAR")
            return {};
        const xml::node* inner = outer->child("comp-filter", ns_cal);
        return inner ? std::string(inner->attr("name")) : std::string();
    }

    void query_report(const xml::node& doc, std::shared_ptr<std::vector<prop_name>> asked, bool data)
    {
        const std::string comp = here.kind == "calendars" ? wanted_component(doc) : std::string();
        auto self = shared_from_this();
        store.entries(user, here.kind, here.coll, [self, asked, data, comp](bool ok, std::vector<dav_store::entry> all) {
            if (!ok)
                return self->reply(error_reply(503, "the storage cannot be reached now"));
            if (!data && comp.empty())
            {
                std::string body;
                for (auto& e : all)
                {
                    item it;
                    it.t = {level::entry, self->here.kind, self->here.coll, e.name};
                    it.etag = e.etag;
                    it.size = e.size;
                    it.mtime_ms = e.mtime_ms;
                    body += self->render(it, asked.get());
                }
                return self->reply({207, "application/xml; charset=utf-8", multistatus(body), {}});
            }
            // A component filter is read off each entry's text, which is fetched for it.
            auto ts = std::make_shared<std::vector<target>>();
            for (auto& e : all)
                ts->push_back({level::entry, self->here.kind, self->here.coll, std::move(e.name)});
            auto items = std::make_shared<std::vector<item>>();
            self->lookup(ts, 0, items, true, [self, items, asked, comp] {
                std::string body;
                for (const auto& it : *items)
                    if (!it.missing && (comp.empty() || (it.data && it.data->find("BEGIN:" + comp) != std::string::npos)))
                        body += self->render(it, asked.get());
                self->reply({207, "application/xml; charset=utf-8", multistatus(body), {}});
            });
        });
    }

    void sync_report(const xml::node& doc, std::shared_ptr<std::vector<prop_name>> asked)
    {
        const xml::node* tok = doc.child("sync-token", ns_dav);
        const std::string given = tok ? tok->text : std::string();
        uint64_t since = 0;
        bool initial = given.find_first_not_of(" \t\r\n") == std::string::npos;
        if (!initial)
        {
            if (!given.starts_with(sync_prefix) || given.size() == sync_prefix.size() ||
                given.find_first_not_of("0123456789", sync_prefix.size()) != std::string::npos)
                return reply(precondition(403, ns_dav, "valid-sync-token"));
            since = std::strtoull(given.c_str() + sync_prefix.size(), nullptr, 10);
        }
        std::vector<std::pair<std::string, bool>> changed;
        const uint64_t now = store.token(user, here.kind, here.coll);
        if (!initial && !store.changes_since(user, here.kind, here.coll, since, changed))
            return reply(precondition(403, ns_dav, "valid-sync-token"));
        auto self = shared_from_this();
        store.entries(user, here.kind, here.coll,
                      [self, asked, initial, changed = std::move(changed), now](bool ok, std::vector<dav_store::entry> all) {
                          if (!ok)
                              return self->reply(error_reply(503, "the storage cannot be reached now"));
                          std::string body;
                          const auto one = [&](const dav_store::entry& e) {
                              item it;
                              it.t = {level::entry, self->here.kind, self->here.coll, e.name};
                              it.etag = e.etag;
                              it.size = e.size;
                              it.mtime_ms = e.mtime_ms;
                              body += self->render(it, asked.get());
                          };
                          if (initial)
                              for (const auto& e : all)
                                  one(e);
                          else
                              for (const auto& [name, gone] : changed)
                              {
                                  const auto it = std::find_if(all.begin(), all.end(), [&](const auto& e) { return e.name == name; });
                                  if (gone || it == all.end())
                                      body += gone_response(self->path_of({level::entry, self->here.kind, self->here.coll, name}));
                                  else
                                      one(*it);
                              }
                          const std::string tail = "<d:sync-token>" + std::string(sync_prefix) + std::to_string(now) + "</d:sync-token>";
                          self->reply({207, "application/xml; charset=utf-8", multistatus(body, tail), {}});
                      });
    }

    // ─── GET, PUT, DELETE ───────────────────────────────────────────────────

    void get(bool head_only)
    {
        auto self = shared_from_this();
        store.get(user, here.kind, here.coll, here.name, [self, head_only](bool ok, bool found, std::string data, std::string etag) {
            if (!ok)
                return self->reply(error_reply(503, "the storage cannot be reached now"));
            if (!found)
                return self->reply(error_reply(404, "nothing is here"));
            self->reply({200, entry_type(self->here.kind), head_only ? std::string() : std::move(data),
                         "ETag: \"" + etag + "\"\r\n"});
        });
    }

    // Whether the request's If-Match and If-None-Match let it act on an entry whose etag is `cur`, empty for none.
    bool allowed(const std::string& cur) const
    {
        const std::string none = rq.header("if-none-match"), match = rq.header("if-match");
        if (!none.empty() && (none == "*" ? !cur.empty() : unquote(none) == cur && !cur.empty()))
            return false;
        if (!match.empty() && (cur.empty() || (match != "*" && unquote(match) != cur)))
            return false;
        return true;
    }

    void put()
    {
        if (rq.body.size() > max_entry)
            return reply(precondition(413, here.kind == "calendars" ? ns_cal : ns_card, "max-resource-size"));
        std::string_view text = rq.body;
        if (text.starts_with("\xEF\xBB\xBF"))
            text.remove_prefix(3);
        while (!text.empty() && (text.front() == ' ' || text.front() == '\r' || text.front() == '\n' || text.front() == '\t'))
            text.remove_prefix(1);
        const bool cal = here.kind == "calendars";
        if (!text.starts_with(cal ? "BEGIN:VCALENDAR" : "BEGIN:VCARD"))
            return reply(precondition(403, cal ? ns_cal : ns_card, cal ? "valid-calendar-data" : "valid-address-data"));
        auto self = shared_from_this();
        collection({level::collection, here.kind, here.coll, {}}, [self](item coll) {
            if (coll.missing)
                return self->reply(error_reply(409, "no such collection"));
            self->store.head(self->user, self->here.kind, self->here.coll, self->here.name, [self](bool ok, std::string cur) {
                if (!ok)
                    return self->reply(error_reply(503, "the storage cannot be reached now"));
                if (!self->allowed(cur))
                    return self->reply(error_reply(412, "the entry is not as the request supposes"));
                const bool fresh = cur.empty();
                self->store.put(self->user, self->here.kind, self->here.coll, self->here.name, std::move(self->rq.body),
                                entry_type(self->here.kind), [self, fresh](std::string etag) {
                                    if (etag.empty())
                                        return self->reply(error_reply(503, "the storage cannot be reached now"));
                                    self->reply({fresh ? 201 : 204, {}, {}, "ETag: \"" + etag + "\"\r\n"});
                                });
            });
        });
    }

    void remove()
    {
        auto self = shared_from_this();
        if (here.lv == level::collection)
            return collection(here, [self](item it) {
                if (it.failed)
                    return self->reply(error_reply(503, "the storage cannot be reached now"));
                if (it.missing)
                    return self->reply(error_reply(404, "nothing is here"));
                self->store.remove_collection(self->user, self->here.kind, self->here.coll, [self](bool ok) {
                    self->reply(ok ? dav_reply{204, {}, {}, {}} : error_reply(503, "the storage cannot be reached now"));
                });
            });
        store.head(user, here.kind, here.coll, here.name, [self](bool ok, std::string cur) {
            if (!ok)
                return self->reply(error_reply(503, "the storage cannot be reached now"));
            if (cur.empty())
                return self->reply(error_reply(404, "nothing is here"));
            if (!self->allowed(cur))
                return self->reply(error_reply(412, "the entry is not as the request supposes"));
            self->store.remove(self->user, self->here.kind, self->here.coll, self->here.name, [self](bool done) {
                self->reply(done ? dav_reply{204, {}, {}, {}} : error_reply(503, "the storage cannot be reached now"));
            });
        });
    }
};

}   // namespace

bool dav_path(std::string_view path, std::string_view method)
{
    return path == "/dav" || path.starts_with("/dav/") || (path == "/" && (method == "PROPFIND" || method == "REPORT"));
}

void dav_serve(dav_store& store, std::shared_ptr<bool> alive, std::string user, std::string address, dav_request rq,
               std::function<void(dav_reply)> done)
{
    std::make_shared<op>(store, std::move(alive), std::move(user), std::move(address), std::move(rq), std::move(done))->run();
}

}   // namespace socketley::mail
