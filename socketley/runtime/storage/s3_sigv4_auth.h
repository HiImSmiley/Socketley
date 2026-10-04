#pragma once
// The storage runtime's authenticator for AWS Signature Version 4: the
// credentials it accepts, the verification of each request's signature by the
// library in shared/s3_sigv4.h, and the body hooks that check a signed payload
// hash or decode and verify an aws-chunked stream on its way in.
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "s3_auth.h"
#include "s3_users.h"
#include "../../shared/s3_sigv4.h"

namespace socketley::storage
{

// The access keys the runtime accepts, the secret of each and the user it signs for.
class credential_set
{
public:
    // False with `err` for a key or secret that cannot be used; a null `user` is the default owner, an admin.
    bool add(std::string_view access_key, std::string_view secret, std::string& err,
             std::shared_ptr<const user_identity> user = nullptr);
    // False with `err` for a second user of the same id.
    bool add_user(std::shared_ptr<const user_identity> user, std::string& err);
    // Puts `user` in place of the user of its id, for that user's keys too.
    void replace_user(std::shared_ptr<const user_identity> user);

    // Empty for an access key that is not here.
    std::string_view secret(std::string_view access_key) const;
    // The user of an access key that is here.
    std::shared_ptr<const user_identity> user_of(std::string_view access_key) const;
    // The user of that id a section declared, null for none.
    const user_identity* find_user(std::string_view id) const;

    size_t size() const { return m_map.size(); }
    // The ids of the users declared.
    std::vector<std::string> user_ids() const
    {
        std::vector<std::string> out;
        for (const auto& [id, u] : m_users)
            out.push_back(id);
        return out;
    }
    size_t user_count() const { return m_users.size(); }

private:
    struct entry
    {
        std::string secret;
        std::shared_ptr<const user_identity> user;
    };
    std::map<std::string, entry, std::less<>> m_map;
    std::map<std::string, std::shared_ptr<const user_identity>, std::less<>> m_users;
};

// One `access:secret` per line; blank lines and lines starting with '#' are
// skipped, and the secret is everything after the first ':' so it may hold one.
// A line `[id]` begins a user, whose `name = ...`, `admin = true|false` and
// `policy = <inline JSON or a file>` lines and keys follow it; a key before any
// user is the default owner's.  A relative policy file is under `dir`, and every
// file read is added to `files`.
bool parse_credentials(std::string_view text, credential_set& out, std::string& err, std::string_view dir = {},
                       std::vector<std::string>* files = nullptr);

struct sigv4_config
{
    // One pair given on the command line.
    std::string access_key;
    std::string secret_key;
    // A file of pairs, re-read when it changes.
    std::string credentials_file;
    // A request that names no credentials at all is let through as anonymous.
    bool        anonymous{false};
    // The IAM API's document, beside the buckets, empty for none.
    std::string iam_file;
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
    auth_verdict authorize_post(const post_signature& sig) override;
    auth_verdict authorize_basic(std::string_view access_key, std::string_view secret) override;

    size_t credential_count() const { return m_creds.size(); }
    std::string display_name(std::string_view id) const override;
    uint64_t max_bytes_of(std::string_view id) const override;
    bool issue_session(std::string_view access_key, int64_t expires, std::string_view policy, std::string_view role,
                       session_credentials& out) override;
    int role_check(std::string_view role, std::string_view user_id, int64_t& max_session) override;
    std::string iam_file() const override { return m_cfg.iam_file; }
    void refresh() override;
    bool file_user(std::string_view id) const override { return m_file_users.count(std::string(id)) != 0; }

private:
    // The secret of the session `token` gives `access_key`, with its user, empty for a token that is not one this
    // runtime sealed for that key or that ended before `now`, which `expired` then says.
    std::string_view session_secret(std::string_view token, std::string_view access_key, int64_t now,
                                    std::shared_ptr<const user_identity>& user, bool& expired);

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
    // The policy files the users name, by what each looked like when it was read.
    struct file_stamp
    {
        std::string path;
        int64_t     mtime_ns{0};
        uint64_t    size{0};
        uint64_t    ino{0};
    };
    std::vector<file_stamp> m_policy_stamps;

    // The last session a request was signed for, which a client signs for again and again.
    struct session_entry
    {
        std::string token;
        std::string parent_secret;
        std::shared_ptr<const user_identity> parent_user;
        std::string secret;
        std::shared_ptr<const user_identity> user;
    };
    session_entry m_session;

    // The IAM file as last read, and its roles: each one's trust policy, longest session and identity.
    file_stamp m_iam_stamp;
    struct role_entry
    {
        std::string trust;
        int64_t     max_session{3600};
        std::shared_ptr<const user_identity> identity;
    };
    std::map<std::string, role_entry, std::less<>> m_roles;
    std::set<std::string> m_file_users;
    std::chrono::steady_clock::time_point m_last_iam_probe{};
    // Reads the IAM file into `set`, its roles into m_roles.
    void add_iam(credential_set& set);
    bool iam_changed();
};

// The hook for a body that is aws-chunked with no signature, which a request
// with no credentials may still send.  Null when the request is not one.
std::unique_ptr<body_hook> unsigned_trailer_hook(const request_view& req);

}   // namespace socketley::storage
