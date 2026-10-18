#include "s3_website.h"

#include <cctype>
#include <charconv>

#include "s3_xml_tree.h"
#include "../../shared/util/number_parse.h"

namespace socketley::storage
{

namespace
{

constexpr size_t website_max_bytes = 128 * 1024;
constexpr size_t website_max_rules = 50;

bool refuse(s3_error& err, std::string_view code, std::string message)
{
    err         = make_error(code);
    err.message = std::move(message);
    return false;
}

bool leaf(const xml_node& n, std::string& out)
{
    if (!n.kids.empty())
        return false;
    out = n.text;
    return true;
}

bool number(const xml_node& n, int& out)
{
    return n.kids.empty() && socketley::parse_whole(n.text, out);
}

// A host a redirect may name, with its port: what goes into a Location header and nothing that would end or split it.
bool host_ok(const std::string& h)
{
    if (h.empty() || h.size() > 255)
        return false;
    for (const char c : h)
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-' && c != ':' && c != '[' && c != ']')
            return false;
    return true;
}

bool protocol_ok(const std::string& p)
{
    return p.empty() || p == "http" || p == "https";
}

bool redirect_of(const xml_node& n, website_redirect& r, s3_error& err)
{
    bool any = false;
    for (const xml_node& k : n.kids)
    {
        any = true;
        if (k.name == "HostName" && leaf(k, r.host) && host_ok(r.host))
            continue;
        if (k.name == "Protocol" && leaf(k, r.protocol) && protocol_ok(r.protocol))
            continue;
        if (k.name == "ReplaceKeyPrefixWith" && leaf(k, r.replace_key_prefix))
        {
            r.has_replace_prefix = true;
            continue;
        }
        if (k.name == "ReplaceKeyWith" && leaf(k, r.replace_key))
        {
            r.has_replace_key = true;
            continue;
        }
        if (k.name == "HttpRedirectCode" && number(k, r.code) && r.code >= 300 && r.code <= 399 && r.code != 300 &&
            r.code != 304)
            continue;
        return false;
    }
    if (!any)
        return refuse(err, "InvalidArgument", "A Redirect must name at least one of its elements.");
    if (r.has_replace_prefix && r.has_replace_key)
        return refuse(err, "InvalidArgument",
                      "You can only define ReplaceKeyPrefix or ReplaceKey but not both.");
    return true;
}

bool rule_of(const xml_node& n, website_rule& r, s3_error& err)
{
    bool has_redirect = false;
    for (const xml_node& k : n.kids)
    {
        if (k.name == "Condition")
        {
            for (const xml_node& c : k.kids)
            {
                std::string v;
                int code = 0;
                if (c.name == "KeyPrefixEquals" && leaf(c, v))
                    r.key_prefix = v;
                else if (c.name == "HttpErrorCodeReturnedEquals" && number(c, code) && code >= 400 && code <= 599)
                    r.error_code = code;
                else
                    return false;
            }
            if (!r.key_prefix && !r.error_code)
                return refuse(err, "InvalidArgument", "Condition cannot be empty.");
        }
        else if (k.name == "Redirect" && !has_redirect)
        {
            if (!redirect_of(k, r.redirect, err))
                return false;
            has_redirect = true;
        }
        else
            return false;
    }
    return has_redirect || refuse(err, "InvalidArgument", "A RoutingRule must have a Redirect.");
}

void text_element(std::string& x, std::string_view name, std::string_view v)
{
    x += "<";
    x += name;
    x += ">";
    xml_escape_to(x, v);
    x += "</";
    x += name;
    x += ">";
}

}   // namespace

bool parse_website_config(std::string_view xml, website_config& out, s3_error& err)
{
    err = make_error("MalformedXML");
    out = website_config{};
    xml_node root;
    if (xml.size() > website_max_bytes || !xml_reader(xml).document(root) || root.name != "WebsiteConfiguration")
        return false;
    bool redirect_all = false, others = false;
    for (const xml_node& c : root.kids)
    {
        if (c.name == "IndexDocument")
        {
            others = true;
            if (c.kids.size() != 1 || c.kids[0].name != "Suffix" || !leaf(c.kids[0], out.index_suffix))
                return false;
            if (out.index_suffix.empty() || out.index_suffix.find('/') != std::string::npos)
                return refuse(err, "InvalidArgument", "The IndexDocument Suffix is not well formed");
        }
        else if (c.name == "ErrorDocument")
        {
            others = true;
            if (c.kids.size() != 1 || c.kids[0].name != "Key" || !leaf(c.kids[0], out.error_key) || out.error_key.empty())
                return false;
        }
        else if (c.name == "RedirectAllRequestsTo")
        {
            redirect_all = true;
            for (const xml_node& k : c.kids)
                if (!(k.name == "HostName" && leaf(k, out.redirect_all_host) && host_ok(out.redirect_all_host)) &&
                    !(k.name == "Protocol" && leaf(k, out.redirect_all_protocol) && protocol_ok(out.redirect_all_protocol)))
                    return false;
            if (out.redirect_all_host.empty())
                return refuse(err, "InvalidArgument", "RedirectAllRequestsTo must name a HostName.");
        }
        else if (c.name == "RoutingRules")
        {
            others = true;
            for (const xml_node& k : c.kids)
            {
                if (k.name != "RoutingRule")
                    return false;
                if (out.rules.size() >= website_max_rules)
                    return refuse(err, "InvalidArgument", "A website configuration holds at most 50 routing rules.");
                website_rule r;
                if (!rule_of(k, r, err))
                    return false;
                out.rules.push_back(std::move(r));
            }
        }
        else
            return false;
    }
    if (redirect_all && others)
        return refuse(err, "InvalidArgument",
                      "RedirectAllRequestsTo cannot be provided in conjunction with other Routing/Redirect configurations.");
    if (!redirect_all && out.index_suffix.empty())
        return refuse(err, "InvalidArgument", "A value for IndexDocument Suffix must be provided if RedirectAllRequestsTo is empty");
    return true;
}

std::string website_config_xml(const website_config& c)
{
    std::string x = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<WebsiteConfiguration xmlns=\"";
    x += s3_xmlns;
    x += "\">";
    if (!c.redirect_all_host.empty())
    {
        x += "<RedirectAllRequestsTo>";
        text_element(x, "HostName", c.redirect_all_host);
        if (!c.redirect_all_protocol.empty())
            text_element(x, "Protocol", c.redirect_all_protocol);
        x += "</RedirectAllRequestsTo>";
    }
    if (!c.index_suffix.empty())
    {
        x += "<IndexDocument>";
        text_element(x, "Suffix", c.index_suffix);
        x += "</IndexDocument>";
    }
    if (!c.error_key.empty())
    {
        x += "<ErrorDocument>";
        text_element(x, "Key", c.error_key);
        x += "</ErrorDocument>";
    }
    if (!c.rules.empty())
    {
        x += "<RoutingRules>";
        for (const website_rule& r : c.rules)
        {
            x += "<RoutingRule>";
            if (r.key_prefix || r.error_code)
            {
                x += "<Condition>";
                if (r.key_prefix)
                    text_element(x, "KeyPrefixEquals", *r.key_prefix);
                if (r.error_code)
                    text_element(x, "HttpErrorCodeReturnedEquals", std::to_string(*r.error_code));
                x += "</Condition>";
            }
            x += "<Redirect>";
            if (!r.redirect.host.empty())
                text_element(x, "HostName", r.redirect.host);
            if (!r.redirect.protocol.empty())
                text_element(x, "Protocol", r.redirect.protocol);
            if (r.redirect.has_replace_prefix)
                text_element(x, "ReplaceKeyPrefixWith", r.redirect.replace_key_prefix);
            if (r.redirect.has_replace_key)
                text_element(x, "ReplaceKeyWith", r.redirect.replace_key);
            text_element(x, "HttpRedirectCode", std::to_string(r.redirect.code));
            x += "</Redirect></RoutingRule>";
        }
        x += "</RoutingRules>";
    }
    x += "</WebsiteConfiguration>";
    return x;
}

const website_rule* website_rule_for(const website_config& c, std::string_view key, int status)
{
    for (const website_rule& r : c.rules)
    {
        if (r.key_prefix && !key.starts_with(*r.key_prefix))
            continue;
        // A rule with an error code is asked only once the object was looked for, and one without only before.
        if (r.error_code ? *r.error_code != status : status != 0)
            continue;
        return &r;
    }
    return nullptr;
}

std::string website_location(const website_redirect& r, std::string_view matched_prefix, std::string_view key,
                             std::string_view scheme, std::string_view host)
{
    std::string target;
    if (r.has_replace_key)
        target = r.replace_key;
    else if (r.has_replace_prefix)
        target = r.replace_key_prefix + std::string(key.substr(std::min(matched_prefix.size(), key.size())));
    else
        target = std::string(key);
    std::string out = r.protocol.empty() ? std::string(scheme) : r.protocol;
    out += "://";
    out += r.host.empty() ? host : std::string_view(r.host);
    out += "/";
    url_encode_to(out, target, true);
    return out;
}

}   // namespace socketley::storage
