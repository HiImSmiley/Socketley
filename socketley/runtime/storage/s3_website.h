#pragma once
// A bucket's website configuration, S3's WebsiteConfiguration document, and what a request to the bucket's website
// comes to under it: an object to serve, a redirect, or an error page.
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "s3_xml.h"

namespace socketley::storage
{

struct website_redirect
{
    std::string host;
    // "http" or "https", empty for the request's own.
    std::string protocol;
    std::string replace_key_prefix;
    std::string replace_key;
    bool        has_replace_prefix{false};
    bool        has_replace_key{false};
    // 301 unless the rule names another 3xx.
    int         code{301};
};

struct website_rule
{
    std::optional<std::string> key_prefix;
    std::optional<int>         error_code;
    website_redirect           redirect;
};

struct website_config
{
    std::string index_suffix;
    std::string error_key;
    // Every request redirected to this host, and nothing else said, when it is set.
    std::string redirect_all_host;
    std::string redirect_all_protocol;
    std::vector<website_rule> rules;
};

// The document PutBucketWebsite takes; false with `err` for anything S3 would refuse.
bool parse_website_config(std::string_view xml, website_config& out, s3_error& err);

// The document GetBucketWebsite answers.
std::string website_config_xml(const website_config& c);

// The rule a request for `key` matches before its object is looked for (a key prefix alone), or after it was
// answered `status` (an error code), null for none.
const website_rule* website_rule_for(const website_config& c, std::string_view key, int status);

// Where a rule sends a request for `key` that came in over `scheme` to `host`: the Location header's value.
std::string website_location(const website_redirect& r, std::string_view matched_prefix, std::string_view key,
                             std::string_view scheme, std::string_view host);

}   // namespace socketley::storage
