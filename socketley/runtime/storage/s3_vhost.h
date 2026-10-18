#pragma once
// Virtual-hosted-style addressing: the domains a runtime is reached under, and
// the bucket a request's Host header names as `<bucket>.<domain>`.
#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

#include "s3_names.h"
#include "../../shared/util/ascii.h"

namespace socketley::storage
{

namespace vhost_detail
{

// A DNS name of labels of letters, digits and inner hyphens, at most 253 bytes.
inline bool valid_domain(std::string_view d)
{
    if (d.empty() || d.size() > 253)
        return false;
    size_t label = 0;
    for (size_t i = 0; i <= d.size(); ++i)
    {
        if (i == d.size() || d[i] == '.')
        {
            if (label == 0 || label > 63 || d[i - 1] == '-' || d[i - label] == '-')
                return false;
            label = 0;
            continue;
        }
        const char c = d[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return false;
        ++label;
    }
    return true;
}

}   // namespace vhost_detail

// A comma-separated list of domains, lowercased and without a trailing dot, into `out`; false with `err`
// for an empty list or a name that is not a DNS name.
inline bool parse_domains(std::string_view list, std::vector<std::string>& out, std::string& err)
{
    out.clear();
    while (true)
    {
        const size_t comma = list.find(',');
        std::string d(list.substr(0, comma));
        for (char& c : d)
            c = ascii::lower(c);
        if (!d.empty() && d.back() == '.')
            d.pop_back();
        if (!vhost_detail::valid_domain(d))
        {
            err = "--domain takes DNS names separated by commas, such as s3.example.com; \"" + d + "\" is not one";
            return false;
        }
        out.push_back(std::move(d));
        if (comma == std::string_view::npos)
            return true;
        list.remove_prefix(comma + 1);
    }
}

// True with the bucket in `bucket` when `host` is `<bucket>.<domain>[:port]` for one of `domains`, the
// longest that fits deciding; a host equal to a domain, an address or any other name is path style.
inline bool vhost_bucket(std::string_view host, const std::vector<std::string>& domains, std::string& bucket)
{
    if (host.empty() || host.front() == '[')
        return false;
    if (const size_t colon = host.rfind(':'); colon != std::string_view::npos)
        host = host.substr(0, colon);
    if (!host.empty() && host.back() == '.')
        host.remove_suffix(1);
    const auto ends_with = [host](std::string_view d)
    {
        if (host.size() < d.size())
            return false;
        for (size_t i = 0; i < d.size(); ++i)
            if (ascii::lower(host[host.size() - d.size() + i]) != d[i])
                return false;
        return true;
    };
    // The bucket is what is left in front of the domain, so the longest domain that fits gives the shortest.
    size_t bucket_len = std::string_view::npos;
    for (const std::string& d : domains)
    {
        // A host that is itself a domain, such as s3.example.com beside example.com, is that endpoint and no bucket.
        if (host.size() == d.size() && ends_with(d))
            return false;
        if (host.size() >= d.size() + 2 && host[host.size() - d.size() - 1] == '.' && ends_with(d))
            bucket_len = std::min(bucket_len, host.size() - d.size() - 1);
        // A domain of one label is a short name, which a dns runtime and the entrance place under each of their
        // zones: the host is then `<d>.<zone>` for the endpoint and `<bucket>.<d>.<zone>` for a bucket.
        if (d.find('.') != std::string::npos)
            continue;
        const auto label_at = [&](size_t at)
        {
            if (at + d.size() + 1 >= host.size() || host[at + d.size()] != '.')
                return false;
            for (size_t i = 0; i < d.size(); ++i)
                if (ascii::lower(host[at + i]) != d[i])
                    return false;
            return true;
        };
        if (label_at(0))
            return false;
        for (size_t dot = host.find('.'); dot != std::string_view::npos; dot = host.find('.', dot + 1))
            if (label_at(dot + 1))
            {
                bucket_len = std::min(bucket_len, dot);
                break;
            }
    }
    if (bucket_len == std::string_view::npos || bucket_len == 0)
        return false;
    bucket.assign(host.substr(0, bucket_len));
    for (char& c : bucket)
        c = ascii::lower(c);
    return true;
}

// Where a client reaches `key` of the request's bucket, spelled in the addressing style the request used.
inline std::string object_url(bool tls, std::string_view host, bool vhost, std::string_view bucket,
                              std::string_view key)
{
    std::string u(tls ? "https://" : "http://");
    u.append(host);
    if (!vhost)
    {
        u.push_back('/');
        url_encode_to(u, bucket);
    }
    u.push_back('/');
    url_encode_to(u, key);
    return u;
}

}   // namespace socketley::storage
