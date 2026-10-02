#pragma once
// S3 Object Lock's documents, read and written back with no I/O: a bucket's ObjectLockConfiguration, a version's
// Retention and LegalHold, and the dates they carry.
#include <charconv>
#include <cstdint>
#include <string>
#include <string_view>

#include "object_format.h"
#include "s3_names.h"
#include "s3_xml_tree.h"

namespace socketley::storage
{

// The most any of the three documents may be, which is far more than the few elements each has.
inline constexpr size_t object_lock_max_bytes = 4096;

// The longest default retention S3 takes, in either unit.
inline constexpr uint32_t max_lock_days  = 36500;
inline constexpr uint32_t max_lock_years = 100;

// A bucket's object lock: enabled, and the retention a new version is given when it asks for none.
struct lock_config
{
    // None when the configuration has no Rule.
    lock_mode mode{lock_mode::none};
    uint32_t  days{0};
    uint32_t  years{0};
};

inline std::string_view lock_mode_name(lock_mode m)
{
    return m == lock_mode::governance ? "GOVERNANCE" : m == lock_mode::compliance ? "COMPLIANCE" : "";
}

// GOVERNANCE or COMPLIANCE, spelled as S3 spells them and in no other case.
inline lock_mode lock_mode_of(std::string_view s)
{
    return s == "GOVERNANCE" ? lock_mode::governance : s == "COMPLIANCE" ? lock_mode::compliance : lock_mode::none;
}

// An ISO 8601 date and time in UTC, its fraction kept to the millisecond.
inline bool parse_lock_date(std::string_view s, int64_t& ms)
{
    bool midnight = false;
    if (s.size() < 20 || !parse_iso8601(s, ms, midnight))
        return false;
    if (s.size() > 20 && s[19] == '.')
    {
        int64_t frac = 0;
        int     digits = 0;
        for (size_t i = 20; i < s.size() && s[i] >= '0' && s[i] <= '9'; ++i)
            if (digits < 3)
            {
                frac = frac * 10 + (s[i] - '0');
                ++digits;
            }
        while (digits++ < 3)
            frac *= 10;
        ms += frac;
    }
    return true;
}

namespace detail
{

// A positive whole number of at most `max`; false with InvalidRetentionPeriod for zero, a negative or one past it,
// and MalformedXML for anything that is no number.
inline bool lock_period(const xml_node& n, uint32_t max, uint32_t& out, s3_error& err)
{
    if (!n.kids.empty())
        return false;
    std::string_view t = n.text;
    const bool negative = !t.empty() && t.front() == '-';
    if (negative)
        t.remove_prefix(1);
    uint64_t v = 0;
    const auto r = std::from_chars(t.data(), t.data() + t.size(), v);
    if (t.empty() || r.ec == std::errc::invalid_argument || r.ptr != t.data() + t.size())
        return false;
    if (negative || v == 0 || v > max || r.ec != std::errc{})
    {
        err = make_error("InvalidRetentionPeriod");
        return false;
    }
    out = static_cast<uint32_t>(v);
    return true;
}

}   // namespace detail

// False with `err` for a configuration S3 would refuse: ObjectLockEnabled other than Enabled, a Rule without one
// DefaultRetention of a mode and exactly one of Days and Years, or a period that is not a positive whole number.
inline bool parse_lock_config(std::string_view xml, lock_config& out, s3_error& err)
{
    err = make_error("MalformedXML");
    out = lock_config{};
    xml_node root;
    if (xml.size() > object_lock_max_bytes || !xml_reader(xml).document(root) || root.name != "ObjectLockConfiguration")
        return false;
    bool enabled = false, rule = false;
    for (const xml_node& k : root.kids)
    {
        if (k.name == "ObjectLockEnabled" && !enabled && k.kids.empty() && k.text == "Enabled")
        {
            enabled = true;
            continue;
        }
        if (k.name != "Rule" || rule || k.kids.size() != 1 || k.kids[0].name != "DefaultRetention")
            return false;
        rule = true;
        bool mode = false, days = false, years = false;
        for (const xml_node& d : k.kids[0].kids)
        {
            if (d.name == "Mode" && !mode && d.kids.empty())
            {
                out.mode = lock_mode_of(d.text);
                if (out.mode == lock_mode::none)
                    return false;
                mode = true;
            }
            else if (d.name == "Days" && !days)
                days = true;
            else if (d.name == "Years" && !years)
                years = true;
            else
                return false;
        }
        if (!mode || days == years)
            return false;
        for (const xml_node& d : k.kids[0].kids)
            if ((d.name == "Days" && !detail::lock_period(d, max_lock_days, out.days, err)) ||
                (d.name == "Years" && !detail::lock_period(d, max_lock_years, out.years, err)))
                return false;
    }
    return enabled;
}

// What GetObjectLockConfiguration answers, and what the bucket keeps.
inline std::string lock_config_xml(const lock_config& c)
{
    std::string x(xml_decl);
    x += "<ObjectLockConfiguration xmlns=\"";
    x += s3_xmlns;
    x += "\"><ObjectLockEnabled>Enabled</ObjectLockEnabled>";
    if (c.mode != lock_mode::none)
    {
        x += "<Rule><DefaultRetention><Mode>";
        x += lock_mode_name(c.mode);
        x += "</Mode>";
        x += c.days ? "<Days>" + std::to_string(c.days) + "</Days>" : "<Years>" + std::to_string(c.years) + "</Years>";
        x += "</DefaultRetention></Rule>";
    }
    x += "</ObjectLockConfiguration>";
    return x;
}

// The retain-until time the bucket's default gives a version written at `now_ms`, years counted on the calendar.
inline int64_t default_retain_until(const lock_config& c, int64_t now_ms)
{
    constexpr int64_t day_ms = 86400000;
    if (c.days)
        return now_ms + static_cast<int64_t>(c.days) * day_ms;
    const utc_fields f = utc_of(now_ms);
    const int64_t    y = f.year + static_cast<int64_t>(c.years);
    const bool       leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    const unsigned   d = f.month == 2 && f.day == 29 && !leap ? 28 : f.day;
    return days_from_civil(y, f.month, d) * day_ms + now_ms - days_from_civil(f.year, f.month, f.day) * day_ms;
}

// False with MalformedXML for a Retention that is not a mode and a date together, or nothing to remove it.
inline bool parse_retention_xml(std::string_view xml, retention& out, s3_error& err)
{
    err = make_error("MalformedXML");
    out = retention{};
    xml_node root;
    if (xml.size() > object_lock_max_bytes || !xml_reader(xml).document(root) || root.name != "Retention")
        return false;
    const xml_node* mode = nullptr;
    const xml_node* date = nullptr;
    for (const xml_node& k : root.kids)
    {
        if (!k.kids.empty())
            return false;
        if (k.name == "Mode" && !mode)
            mode = &k;
        else if (k.name == "RetainUntilDate" && !date)
            date = &k;
        else
            return false;
    }
    if (!mode && !date)
        return true;
    if (!mode || !date)
        return false;
    out.mode = lock_mode_of(mode->text);
    return out.mode != lock_mode::none && parse_lock_date(date->text, out.until_ms);
}

inline std::string retention_xml(const retention& r)
{
    std::string x(xml_decl);
    x += "<Retention xmlns=\"";
    x += s3_xmlns;
    x += "\"><Mode>";
    x += lock_mode_name(r.mode);
    x += "</Mode><RetainUntilDate>";
    append_iso8601(x, r.until_ms);
    x += "</RetainUntilDate></Retention>";
    return x;
}

// False with MalformedXML for a LegalHold whose Status is not ON or OFF.
inline bool parse_legal_hold_xml(std::string_view xml, std::string& status, s3_error& err)
{
    err = make_error("MalformedXML");
    xml_node root;
    if (xml.size() > object_lock_max_bytes || !xml_reader(xml).document(root) || root.name != "LegalHold" ||
        root.kids.size() != 1 || root.kids[0].name != "Status" || !root.kids[0].kids.empty() ||
        (root.kids[0].text != "ON" && root.kids[0].text != "OFF"))
        return false;
    status = root.kids[0].text;
    return true;
}

inline std::string legal_hold_xml(std::string_view status)
{
    std::string x(xml_decl);
    x += "<LegalHold xmlns=\"";
    x += s3_xmlns;
    x += "\"><Status>";
    x += status;
    x += "</Status></LegalHold>";
    return x;
}

}   // namespace socketley::storage
