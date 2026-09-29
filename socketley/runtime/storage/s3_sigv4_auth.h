#pragma once
// The storage runtime's authenticator for AWS Signature Version 4: the
// credentials it accepts, the verification of each request's signature by the
// library in shared/s3_sigv4.h, and the body hooks that check a signed payload
// hash or decode and verify an aws-chunked stream on its way in.
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "s3_auth.h"
#include "../../shared/s3_sigv4.h"

namespace socketley::storage
{

// The access keys the runtime accepts, and the secret of each.
class credential_set
{
public:
    // False with `err` for a key or secret that cannot be used.
    bool add(std::string_view access_key, std::string_view secret, std::string& err);

    // Empty for an access key that is not here.
    std::string_view secret(std::string_view access_key) const;

    size_t size() const { return m_map.size(); }

private:
    std::map<std::string, std::string, std::less<>> m_map;
};

// One `access:secret` per line; blank lines and lines starting with '#' are
// skipped, and the secret is everything after the first ':' so it may hold one.
bool parse_credentials(std::string_view text, credential_set& out, std::string& err);

struct sigv4_config
{
    // One pair given on the command line.
    std::string access_key;
    std::string secret_key;
    // A file of pairs, re-read when it changes.
    std::string credentials_file;
    // A request that names no credentials at all is let through as anonymous.
    bool        anonymous{false};
};

// The empty string when the configuration can be served, and what is wrong
// with it otherwise.
std::string sigv4_config_error(const sigv4_config& cfg);

class sigv4_authenticator final : public authenticator
{
public:
    explicit sigv4_authenticator(sigv4_config cfg);

    // Reads the credentials; false with `err` when there are none to serve with.
    bool load(std::string& err);

    auth_verdict authorize(const request_view& req) override;

    size_t credential_count() const { return m_creds.size(); }

private:
    // Re-reads the file when it has changed, at most once a second.  A file
    // that has gone or no longer parses leaves the set as it was, because a
    // half-written edit must not lock every client out.
    void maybe_reload();
    bool rebuild(std::string& err);

    sigv4_config m_cfg;
    credential_set m_creds;
    s3::verify_options m_opts;
    std::vector<s3::header_field> m_fields;

    std::chrono::steady_clock::time_point m_last_check{};
    // What the file looked like when it was last read.
    int64_t m_stamp_mtime_ns{0};
    uint64_t m_stamp_size{0};
    uint64_t m_stamp_ino{0};
    bool m_have_stamp{false};
};

// The hook for a body that is aws-chunked with no signature, which a request
// with no credentials may still send.  Null when the request is not one.
std::unique_ptr<body_hook> unsigned_trailer_hook(const request_view& req);

}   // namespace socketley::storage
