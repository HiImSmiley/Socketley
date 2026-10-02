#pragma once
// A browser's upload by HTML form, S3's POST Object: the multipart/form-data
// fields in front of the file, the policy document they were signed with and
// its conditions, and the body stage that takes the file's bytes out of the form.
//
// Pure parsing and checking with no I/O, so a unit test reaches it without a ring.
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "s3_auth.h"

namespace socketley::storage
{

// S3 reads at most this much of a form in front of its file, and refuses a form whose fields are longer.
inline constexpr size_t post_max_fields_bytes = 20 * 1024;

struct post_form
{
    std::string boundary;
    // The fields in front of the file, each name lowercased since S3 compares them without case.
    std::vector<std::pair<std::string, std::string>> fields;
    // What the file part said of itself.
    std::string filename;
    std::string file_type;
    // Where the file's bytes begin in the body.
    size_t      file_at{0};
    // The bounds a policy's content-length-range puts on the file, when it has one.
    bool        has_range{false};
    uint64_t    range_min{0};
    uint64_t    range_max{0};
    // The fields as the request's headers name them, owned here for the views the request keeps.
    std::deque<std::string> held;

    const std::string* field(std::string_view lower_name) const;
};

enum class form_scan : uint8_t { more, ok, bad };

// Reads the fields of a multipart/form-data body up to the first byte of its file, from `in`, the body so far,
// which is all of it when `whole`.  `more` asks for more of the body; `bad` comes with S3's refusal.
form_scan scan_post_form(std::string_view content_type, std::string_view in, bool whole, post_form& out,
                         s3_error& err);

// The form's key, with ${filename} given the file's name as S3 does.
std::string post_key(const post_form& f);

// Checks the form's policy document, base64 JSON, against the form: not expired at `now_ms`, every condition
// met by the field it names, and every field but the exempt ones named by a condition.  It records the
// content-length-range in `f`, and is false with `err` S3's refusal.
bool check_post_policy(post_form& f, std::string_view bucket, int64_t now_ms, s3_error& err);

// The body stage of a form: it passes the file's bytes, stops at the boundary that ends them and drops what
// follows, as S3 ignores fields after the file, and refuses a file outside the policy's range.
class form_file_hook final : public body_hook
{
public:
    form_file_hook(std::string_view boundary, bool has_range, uint64_t min, uint64_t max);

    bool feed(std::string_view raw, std::string& out, s3_error& err) override;
    bool finish(std::string& out, s3_error& err) override;
    // The file ends where its boundary is found, short of the body's Content-Length.
    bool length_from_body() const override { return false; }

private:
    std::string m_delim;
    std::string m_held;
    uint64_t    m_given{0};
    bool        m_done{false};
    bool        m_has_range;
    uint64_t    m_min;
    uint64_t    m_max;
};

}   // namespace socketley::storage
