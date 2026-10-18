#include "s3_sigv4_auth.h"

#include "password_hash.h"

#include <cerrno>
#include <charconv>
#include <cstring>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <optional>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <openssl/hmac.h>

#include "checksum.h"
#include "digest.h"
#include "s3_iam.h"
#include "s3_names.h"
#include "s3_sts.h"
#include "../../shared/util/logging.h"
#include "../../shared/storage/s3_sigv4.h"
#include "../../shared/util/size_suffix.h"
#include "../../shared/util/wall_clock.h"

namespace socketley::storage
{

namespace
{

// The sha256 of nothing, which the payload hash of a request with no body is.
constexpr std::string_view empty_body_sha256 =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

s3_error to_error(const s3::error_info& e)
{
    return {e.code, e.message, e.http_status};
}

s3_error make_bad_request(std::string_view code, std::string_view message)
{
    return {std::string(code), std::string(message), 400};
}

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

bool valid_access_key(std::string_view k)
{
    if (k.empty() || k.size() > 127)
        return false;
    for (unsigned char c : k)
        if (c <= ' ' || c == '/' || c == ':' || c == '=' || c == ',' || c >= 0x7f)
            return false;
    return true;
}

bool query_names(std::string_view query, std::string_view name)
{
    while (!query.empty())
    {
        const size_t amp = query.find('&');
        const std::string_view part = query.substr(0, amp);
        query = amp == std::string_view::npos ? std::string_view{} : query.substr(amp + 1);
        const size_t eq = part.find('=');
        if (part.substr(0, eq) == name)
            return true;
    }
    return false;
}

// The declared length of an aws-chunked body once the framing is taken off,
// or UINT64_MAX when the request did not say.
uint64_t decoded_length_of(const request_view& req)
{
    const std::string_view v = trim(req.header("x-amz-decoded-content-length"));
    uint64_t n = 0;
    if (v.empty() || std::from_chars(v.data(), v.data() + v.size(), n).ec != std::errc{})
        return UINT64_MAX;
    return n;
}

// Carries a body whose bytes are signed as a whole to the check at its end.
class hex_hook final : public body_hook
{
public:
    explicit hex_hook(const uint8_t expected[32]) { std::memcpy(m_expected, expected, 32); }

    bool feed(std::string_view raw, std::string& out, s3_error&) override
    {
        m_hash.update(raw);
        out.append(raw);
        return true;
    }

    bool heavy() const override { return true; }

    bool finish(std::string&, s3_error& err) override
    {
        if (m_hash.matches(m_expected))
            return true;
        err = to_error(s3::payload_mismatch());
        return false;
    }

private:
    s3::payload_hasher m_hash;
    uint8_t            m_expected[32];
};

// Decodes aws-chunked framing, checking every chunk's signature when there is one.
class stream_hook final : public body_hook
{
public:
    explicit stream_hook(const s3::stream_context& ctx)
        : m_ctx_len(ctx.decoded_length),
          m_signed(ctx.kind == s3::payload_kind::streaming_signed ||
                   ctx.kind == s3::payload_kind::streaming_signed_trailer),
          m_stream(ctx)
    {
    }

    // Every chunk of a signed stream is hashed and its signature computed.
    bool heavy() const override { return m_signed; }

    bool feed(std::string_view raw, std::string& out, s3_error& err) override
    {
        while (!raw.empty())
        {
            const s3::feed_result r = m_stream.feed(raw);
            out.append(r.data);
            raw.remove_prefix(r.consumed);
            switch (r.status)
            {
                case s3::stream_status::need_more:
                    if (r.consumed == 0)
                        return true;
                    break;
                case s3::stream_status::done:
                    // Nothing follows the last chunk in a body the length of which was given.
                    if (!raw.empty())
                    {
                        err = make_bad_request("InvalidRequest", "The request body carries bytes after its last chunk.");
                        return false;
                    }
                    return true;
                default:
                    err = to_error(m_stream.error());
                    return false;
            }
        }
        return true;
    }

    bool finish(std::string&, s3_error& err) override
    {
        if (m_stream.status() == s3::stream_status::done)
            return true;
        if (m_stream.status() == s3::stream_status::need_more)
            err = to_error(s3::incomplete_body());
        else
            err = to_error(m_stream.error());
        return false;
    }

    std::optional<uint64_t> decoded_length() const override
    {
        if (m_ctx_len == UINT64_MAX)
            return std::nullopt;
        return m_ctx_len;
    }

    std::string trailer_value(std::string_view name) const override
    {
        return std::string(m_stream.trailer_value(name));
    }

private:
    uint64_t        m_ctx_len;
    bool            m_signed;
    s3::chunk_stream m_stream;
};

}   // namespace

auth_verdict anonymous_authenticator::authorize(const request_view& req)
{
    auth_verdict v;
    v.anonymous = true;
    v.hook = unsigned_trailer_hook(req);
    return v;
}

std::unique_ptr<body_hook> unsigned_trailer_hook(const request_view& req)
{
    if (req.payload_hash != "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
        return nullptr;
    return std::make_unique<stream_hook>(s3::stream_context::unsigned_trailer(decoded_length_of(req)));
}

// ─── Credentials ────────────────────────────────────────────────────────────

namespace
{

bool read_file(const std::string& path, std::string& out, std::string& err, struct stat* st_out = nullptr)
{
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        err = "cannot read " + path + ": " + std::strerror(errno);
        return false;
    }
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > (1 << 20))
    {
        ::close(fd);
        err = path + " is not a regular file of at most 1 MiB";
        return false;
    }
    out.resize(static_cast<size_t>(st.st_size));
    size_t got = 0;
    while (got < out.size())
    {
        const ssize_t n = ::read(fd, out.data() + got, out.size() - got);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        got += static_cast<size_t>(n);
    }
    ::close(fd);
    // Short of the size it had is a file being rewritten, which is read again next time and not taken in part.
    if (got != out.size())
    {
        err = path + " changed while it was read";
        return false;
    }
    if (st_out)
        *st_out = st;
    return true;
}

std::string dir_of(const std::string& path)
{
    const size_t slash = path.rfind('/');
    return slash == std::string::npos ? std::string(".") : slash == 0 ? std::string("/") : path.substr(0, slash);
}

// What a file looks like now, all zero for one that is not there.
bool stamp_of(const std::string& path, int64_t& mtime_ns, uint64_t& size, uint64_t& ino)
{
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0)
    {
        mtime_ns = 0;
        size = ino = 0;
        return false;
    }
    mtime_ns = static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
    size     = static_cast<uint64_t>(st.st_size);
    ino      = static_cast<uint64_t>(st.st_ino);
    return true;
}

const std::shared_ptr<const user_identity>& default_user()
{
    static const std::shared_ptr<const user_identity> u = []
    {
        auto p          = std::make_shared<user_identity>();
        p->id           = std::string(default_owner);
        p->display_name = std::string(default_owner);
        p->admin        = true;
        return std::shared_ptr<const user_identity>(std::move(p));
    }();
    return u;
}

// A user id goes into an ARN and an Owner element, so it is printable and has no character either gives a meaning.
bool valid_user_id(std::string_view id)
{
    if (id.empty() || id.size() > 128)
        return false;
    for (unsigned char c : id)
        if (c <= ' ' || c >= 0x7f || c == '/' || c == ':' || c == '*' || c == '?' || c == ',' || c == '=' ||
            c == '[' || c == ']' || c == '"' || c == '<' || c == '>' || c == '&')
            return false;
    return true;
}

}   // namespace

bool credential_set::add(std::string_view access_key, std::string_view secret, std::string& err,
                         std::shared_ptr<const user_identity> user)
{
    if (!valid_access_key(access_key))
    {
        err = "an access key must be 1 to 127 printable characters without '/', ':', '=' or ','";
        return false;
    }
    if (secret.empty())
    {
        err = "the secret of access key " + std::string(access_key) + " is empty";
        return false;
    }
    if (!user)
        user = default_user();
    if (const auto it = m_map.find(access_key); it != m_map.end() && it->second.user != user)
    {
        err = "access key " + std::string(access_key) + " is given to two users";
        return false;
    }
    m_map[std::string(access_key)] = {std::string(secret), std::move(user)};
    return true;
}

bool credential_set::add_user(std::shared_ptr<const user_identity> user, std::string& err)
{
    if (m_users.contains(user->id))
    {
        err = "user " + user->id + " is declared twice";
        return false;
    }
    m_users.emplace(user->id, std::move(user));
    return true;
}

std::string_view credential_set::secret(std::string_view access_key) const
{
    const auto it = m_map.find(access_key);
    return it == m_map.end() ? std::string_view{} : std::string_view(it->second.secret);
}

std::shared_ptr<const user_identity> credential_set::user_of(std::string_view access_key) const
{
    const auto it = m_map.find(access_key);
    return it == m_map.end() ? nullptr : it->second.user;
}

void credential_set::replace_user(std::shared_ptr<const user_identity> user)
{
    const auto it = m_users.find(user->id);
    if (it == m_users.end())
        return;
    for (auto& [k, e] : m_map)
        if (e.user == it->second)
            e.user = user;
    it->second = std::move(user);
}

const user_identity* credential_set::find_user(std::string_view id) const
{
    const auto it = m_users.find(id);
    return it == m_users.end() ? nullptr : it->second.get();
}

std::shared_ptr<const user_identity> credential_set::shared_user(std::string_view id) const
{
    const auto it = m_users.find(id);
    return it == m_users.end() ? nullptr : it->second;
}

std::string credential_set::user_of_email(std::string_view email) const
{
    for (const auto& [id, u] : m_users)
        if (!u->email.empty() && u->email == email)
            return id;
    return {};
}

std::string_view credential_set::key_of(std::string_view id) const
{
    for (const auto& [key, e] : m_map)
        if (e.user && e.user->id == id)
            return key;
    return {};
}

bool parse_credentials(std::string_view text, credential_set& out, std::string& err, std::string_view dir,
                       std::vector<std::string>* files)
{
    size_t line_no = 0;
    // The user being declared, which is complete once the next one begins or the text ends.
    std::shared_ptr<user_identity> user;
    std::vector<std::pair<std::string, std::string>> keys;
    bool named = false;
    auto finish_user = [&]() -> bool
    {
        if (!user)
            return true;
        if (!named)
            user->display_name = user->id;
        std::shared_ptr<const user_identity> done = std::move(user);
        user.reset();
        if (!out.add_user(done, err))
            return false;
        for (const auto& [k, s] : keys)
            if (!out.add(k, s, err, done))
                return false;
        keys.clear();
        return true;
    };
    while (!text.empty())
    {
        const size_t nl = text.find('\n');
        std::string_view line = trim(text.substr(0, nl));
        text = nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
        ++line_no;
        const std::string where = "line " + std::to_string(line_no);
        if (line.empty() || line.front() == '#')
            continue;
        if (line.front() == '[')
        {
            if (line.back() != ']' || !valid_user_id(trim(line.substr(1, line.size() - 2))))
            {
                err = where + ": a user is [id], an id of 1 to 128 printable characters without spaces or any of "
                              "/:*?,=[]\"<>&";
                return false;
            }
            if (!finish_user())
            {
                err = where + ": " + err;
                return false;
            }
            user     = std::make_shared<user_identity>();
            user->id = std::string(trim(line.substr(1, line.size() - 2)));
            user->configured = true;
            named = false;
            continue;
        }
        // A setting has its '=' before any ':', which an access key cannot hold.
        const size_t sep = line.find_first_of(":=");
        if (sep != std::string_view::npos && line[sep] == '=')
        {
            const std::string_view name  = trim(line.substr(0, sep));
            const std::string_view value = trim(line.substr(sep + 1));
            if (!user)
            {
                err = where + ": " + std::string(name) + " is a setting of a user, and no [id] line came before it";
                return false;
            }
            if (name == "name")
            {
                if (value.empty())
                {
                    err = where + ": the name of user " + user->id + " is empty";
                    return false;
                }
                user->display_name = std::string(value);
                named = true;
            }
            else if (name == "admin")
            {
                if (value != "true" && value != "false")
                {
                    err = where + ": admin is true or false";
                    return false;
                }
                user->admin = value == "true";
            }
            else if (name == "policy")
            {
                std::string doc;
                if (!value.starts_with('{'))
                {
                    std::string path(value);
                    if (!path.empty() && path.front() != '/' && !dir.empty())
                        path = std::string(dir) + "/" + path;
                    if (files)
                        files->push_back(path);
                    if (!read_file(path, doc, err))
                    {
                        err = where + ": " + err;
                        return false;
                    }
                }
                else
                    doc = std::string(value);
                s3_error e;
                if (!bucket_policy::compile_identity(doc, user->policy, e))
                {
                    err = where + ": the policy of user " + user->id + ": " + e.message;
                    return false;
                }
                user->has_policy = true;
            }
            else if (name == "email")
            {
                if (value.find('@') == std::string_view::npos)
                {
                    err = where + ": the email of user " + user->id + " has no @";
                    return false;
                }
                user->email = std::string(value);
            }
            else if (name == "max_bytes")
            {
                size_t bytes = 0;
                if (!parse_size_suffix(value, bytes) || bytes == 0)
                {
                    err = where + ": max_bytes is a size such as 10G, 500M or a count of bytes";
                    return false;
                }
                user->max_bytes = bytes;
            }
            else
            {
                err = where + ": " + std::string(name) + " is not a setting of a user (name, email, admin, policy, max_bytes)";
                return false;
            }
            continue;
        }
        if (sep == std::string_view::npos)
        {
            err = where + " is not access:secret";
            return false;
        }
        const std::string_view key = trim(line.substr(0, sep)), secret = trim(line.substr(sep + 1));
        if (user)
        {
            // Checked here so the line it is on is the one named.
            credential_set probe;
            if (!probe.add(key, secret, err))
            {
                err = where + ": " + err;
                return false;
            }
            keys.emplace_back(key, secret);
            continue;
        }
        std::string why;
        if (!out.add(key, secret, why))
        {
            err = where + ": " + why;
            return false;
        }
    }
    if (!finish_user())
    {
        err = "line " + std::to_string(line_no) + ": " + err;
        return false;
    }
    return true;
}

std::string sigv4_config_error(const sigv4_config& cfg)
{
    if (cfg.access_key.empty() != cfg.secret_key.empty())
        return "--access-key and --secret-key go together";
    credential_set set;
    std::string err;
    if (!cfg.access_key.empty() && !set.add(cfg.access_key, cfg.secret_key, err))
        return err;
    if (!cfg.credentials_file.empty())
    {
        std::string text;
        if (!read_file(cfg.credentials_file, text, err))
            return err;
        if (!parse_credentials(text, set, err, dir_of(cfg.credentials_file)))
            return cfg.credentials_file + ": " + err;
        if (set.size() == 0)
            return cfg.credentials_file + " holds no credentials";
    }
    return {};
}

// ─── The authenticator ──────────────────────────────────────────────────────

sigv4_authenticator::sigv4_authenticator(sigv4_config cfg) : m_cfg(std::move(cfg)) {}

bool sigv4_authenticator::rebuild(std::string& err)
{
    credential_set set;
    if (!m_cfg.access_key.empty() && !set.add(m_cfg.access_key, m_cfg.secret_key, err))
        return false;
    if (!m_cfg.cluster_key.empty())
    {
        static const auto node = []()
        {
            auto u = std::make_shared<user_identity>();
            u->id           = "socketley-cluster";
            u->display_name = "socketley-cluster";
            u->admin        = true;
            u->cluster      = true;
            return u;
        }();
        if (!set.add(m_cfg.cluster_key, m_cfg.cluster_secret, err, node))
        {
            err = "the cluster's key: " + err;
            return false;
        }
    }
    if (!m_cfg.credentials_file.empty())
    {
        std::string text;
        struct stat st{};
        if (!read_file(m_cfg.credentials_file, text, err, &st))
            return false;
        std::vector<std::string> files;
        const bool parsed = parse_credentials(text, set, err, dir_of(m_cfg.credentials_file), &files);
        // The policy files this text names are watched whether or not they compiled, so a fix to one is seen.
        m_policy_stamps.clear();
        for (std::string& f : files)
        {
            file_stamp fs;
            fs.path = std::move(f);
            stamp_of(fs.path, fs.mtime_ns, fs.size, fs.ino);
            m_policy_stamps.push_back(std::move(fs));
        }
        if (!parsed)
        {
            err = m_cfg.credentials_file + ": " + err;
            return false;
        }
        m_stamp_mtime_ns = static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
        m_stamp_size     = static_cast<uint64_t>(st.st_size);
        m_stamp_ino      = static_cast<uint64_t>(st.st_ino);
        m_have_stamp     = true;
    }
    // A refused rebuild leaves the authenticator as it was, the IAM parts add_iam() fills included.
    auto file_users = std::move(m_file_users);
    auto roles = m_roles;
    auto logins = m_logins;
    const auto iam_stamp = m_iam_stamp;
    m_file_users.clear();
    for (std::string& id : set.user_ids())
        m_file_users.insert(std::move(id));
    add_iam(set);
    if (set.size() == 0 && !m_cfg.anonymous)
    {
        m_file_users = std::move(file_users);
        m_roles = std::move(roles);
        m_logins = std::move(logins);
        m_iam_stamp = iam_stamp;
        err = "no credentials to serve with";
        return false;
    }
    m_creds = std::move(set);
    return true;
}

void sigv4_authenticator::add_iam(credential_set& set)
{
    m_roles.clear();
    m_logins.clear();
    if (m_cfg.iam_file.empty())
        return;
    std::string text, err;
    m_iam_stamp = file_stamp{m_cfg.iam_file};
    stamp_of(m_iam_stamp.path, m_iam_stamp.mtime_ns, m_iam_stamp.size, m_iam_stamp.ino);
    // No file is no IAM users yet.
    if (::access(m_cfg.iam_file.c_str(), F_OK) != 0)
        return;
    iam_state st;
    if (!read_file(m_cfg.iam_file, text, err) || !iam_parse(text, st, err))
    {
        LOG_WARN(("storage: the IAM file " + m_cfg.iam_file + " is not read: " + err).c_str());
        return;
    }
    // The policies a user or role holds, compiled into one identity policy; one that does not compile leaves it none.
    auto compiled = [](user_identity& u, const std::string& doc)
    {
        u.has_policy = true;
        s3_error e;
        if (!doc.empty() && !bucket_policy::compile_identity(doc, u.policy, e))
            LOG_WARN(("storage: the IAM policies of " + u.id + " do not compile: " + e.message).c_str());
    };
    // A login profile signs as the key "~<name>", which sorts after every other key a user has, so what a key seals
    // for it stays sealed under the same secret once it has another.
    const auto add_login = [&](const std::string& name, const iam_user& iu, std::shared_ptr<const user_identity> who)
    {
        if (iu.password.empty() || iu.login_secret.empty() || !who)
            return;
        if (!set.add("~" + name, iu.login_secret, err, std::move(who)))
        {
            LOG_WARN(("storage: the login profile of " + name + " is not taken: " + err).c_str());
            return;
        }
        m_logins[name] = login_entry{iu.password, iu.password_reset, iu.password_ms};
    };
    for (const auto& [name, iu] : st.users)
    {
        // A user the credentials file declares is that file's, with the IAM API's policies and login profile beside.
        if (const user_identity* fu = set.find_user(name))
        {
            const std::string doc = iam_user_policy(st, iu);
            auto extra = std::make_shared<bucket_policy>();
            s3_error e;
            if (!doc.empty() && bucket_policy::compile_identity(doc, *extra, e))
            {
                auto copy = std::make_shared<user_identity>(*fu);
                copy->iam_policy = std::move(extra);
                set.replace_user(std::move(copy));
            }
            // Disabled is no sign-in for a user of the file too; the keys the file holds stay the file's to revoke.
            if (const auto d = iu.tags.find(std::string(iam_tag_disabled)); d != iu.tags.end() && d->second == "true")
                continue;
            add_login(name, iu, set.shared_user(name));
            for (const auto& [id, k] : st.keys)
                if (k.user == name && k.active && !set.add(id, k.secret, err, set.shared_user(name)))
                    LOG_WARN(("storage: the IAM key " + id + " is not taken: " + err).c_str());
            continue;
        }
        if (iu.external)
            continue;
        const auto tag = [&iu](std::string_view k)
        {
            const auto it = iu.tags.find(std::string(k));
            return it == iu.tags.end() ? std::string() : it->second;
        };
        auto u = std::make_shared<user_identity>();
        u->id           = name;
        u->display_name = tag(iam_tag_display_name).empty() ? name : tag(iam_tag_display_name);
        u->email        = tag(iam_tag_email);
        u->max_bytes    = std::strtoull(tag(iam_tag_max_bytes).c_str(), nullptr, 10);
        u->admin        = std::find(iu.groups.begin(), iu.groups.end(), iam_admins_group) != iu.groups.end();
        u->configured   = true;
        u->iam_id       = iu.id;
        u->iam_path     = iu.path;
        const std::string doc = iam_user_policy(st, iu);
        if (!doc.empty())
            compiled(*u, doc);
        std::shared_ptr<const user_identity> done = u;
        if (!set.add_user(done, err))
            continue;
        // A user who may not sign in is still one, whose buckets keep their owner and whom a share can name.
        if (tag(iam_tag_disabled) == "true")
            continue;
        for (const auto& [id, k] : st.keys)
            if (k.user == name && k.active && !set.add(id, k.secret, err, done))
                LOG_WARN(("storage: the IAM key " + id + " is not taken: " + err).c_str());
        add_login(name, iu, done);
    }
    for (const auto& [name, r] : st.roles)
    {
        auto u = std::make_shared<user_identity>();
        u->id           = "role/" + name;
        u->display_name = name;
        u->configured   = true;
        // A role holds what its policies give and nothing else, none when it has none.
        compiled(*u, iam_role_policy(r));
        m_roles[name] = role_entry{r.trust, r.max_session, std::move(u)};
    }
}

bool sigv4_authenticator::iam_changed()
{
    if (m_cfg.iam_file.empty())
        return false;
    file_stamp now;
    stamp_of(m_cfg.iam_file, now.mtime_ns, now.size, now.ino);
    return now.mtime_ns != m_iam_stamp.mtime_ns || now.size != m_iam_stamp.size || now.ino != m_iam_stamp.ino;
}

void sigv4_authenticator::refresh()
{
    std::string err;
    if (!rebuild(err))
        LOG_WARN(("storage: credentials not reloaded, the old set stays: " + err).c_str());
}

int sigv4_authenticator::role_check(std::string_view role, std::string_view user_id, int64_t& max_session)
{
    if (iam_changed())
        refresh();
    const auto it = m_roles.find(role);
    if (it == m_roles.end())
        return -1;
    max_session = it->second.max_session;
    return iam_trusts(it->second.trust, user_id) ? 1 : 0;
}

std::string sigv4_authenticator::display_name(std::string_view id) const
{
    if (const user_identity* u = m_creds.find_user(id))
        return u->display_name;
    return std::string(id);
}

uint64_t sigv4_authenticator::max_bytes_of(std::string_view id) const
{
    const user_identity* u = id.empty() ? nullptr : m_creds.find_user(id);
    return u ? u->max_bytes : 0;
}

bool sigv4_authenticator::issue_session(std::string_view access_key, int64_t expires, std::string_view policy,
                                        std::string_view role, session_credentials& out)
{
    const std::string_view parent = m_creds.secret(access_key);
    if (parent.empty())
        return false;
    session_grant g;
    g.parent_key = access_key;
    g.access_key = sts_new_access_key();
    g.expires    = expires;
    g.policy     = policy;
    g.role       = role;
    if (g.access_key.empty())
        return false;
    out.access_key = g.access_key;
    out.secret     = sts_secret(g, parent);
    out.token      = sts_token(g, parent);
    out.expires    = expires;
    return true;
}

std::string sigv4_authenticator::seal_key(std::string_view user_id, std::string_view purpose) const
{
    const std::string_view key = m_creds.key_of(user_id);
    const std::string_view secret = key.empty() ? std::string_view{} : m_creds.secret(key);
    if (secret.empty())
        return {};
    unsigned char out[32];
    unsigned int n = 0;
    if (!HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()), reinterpret_cast<const unsigned char*>(purpose.data()),
              purpose.size(), out, &n) || n != 32)
        return {};
    return std::string(reinterpret_cast<char*>(out), n);
}

bool sigv4_authenticator::issue_session_as(std::string_view user_id, int64_t expires, std::string_view policy,
                                           std::string_view role, session_credentials& out)
{
    const std::string_view key = m_creds.key_of(user_id);
    return !key.empty() && issue_session(key, expires, policy, role, out);
}

std::string_view sigv4_authenticator::session_secret(std::string_view token, std::string_view access_key, int64_t now,
                                                     std::shared_ptr<const user_identity>& user, bool& expired)
{
    session_grant g;
    if (!sts_parse(token, g) || g.access_key != access_key)
        return {};
    if (g.expires <= now)
    {
        expired = true;
        return {};
    }
    const std::string_view parent = m_creds.secret(g.parent_key);
    std::shared_ptr<const user_identity> base = m_creds.user_of(g.parent_key);
    if (parent.empty() || !base)
        return {};
    // A session of a role signs as the role, while the role is there.
    if (!g.role.empty())
    {
        const auto r = m_roles.find(g.role);
        if (r == m_roles.end())
            return {};
        base = r->second.identity;
    }
    // The session last signed for is taken again while its key and its user are the ones it was sealed with.
    session_entry& e = m_session;
    if (e.token == token && e.parent_secret == parent && e.parent_user == base)
    {
        user = e.user;
        return e.secret;
    }
    if (!sts_sealed_by(token, parent))
        return {};
    std::shared_ptr<const user_identity> u = base;
    if (!g.policy.empty())
    {
        auto bound = std::make_shared<bucket_policy>();
        s3_error err;
        if (!bucket_policy::compile_identity(g.policy, *bound, err))
            return {};
        auto copy = std::make_shared<user_identity>(*base);
        copy->session_policy = std::move(bound);
        u = std::move(copy);
    }
    e.token         = std::string(token);
    e.parent_secret = std::string(parent);
    e.parent_user   = base;
    e.secret        = sts_secret(g, parent);
    e.user          = u;
    user = std::move(u);
    return e.secret;
}

bool sigv4_authenticator::load(std::string& err)
{
    m_last_check = std::chrono::steady_clock::now();
    return rebuild(err);
}

void sigv4_authenticator::maybe_reload()
{
    if (m_cfg.credentials_file.empty() && m_cfg.iam_file.empty())
        return;
    const auto now = std::chrono::steady_clock::now();
    // A change another shard's IAM call wrote is taken within 50 ms, which costs a stat at that rate.
    if (!m_cfg.iam_file.empty() && now - m_last_iam_probe >= std::chrono::milliseconds(50))
    {
        m_last_iam_probe = now;
        if (iam_changed())
        {
            refresh();
            return;
        }
    }
    if (now - m_last_check < std::chrono::seconds(1))
        return;
    m_last_check = now;
    // The IAM file another shard wrote is read again here too, beside the credentials file.
    if (m_cfg.credentials_file.empty())
    {
        if (iam_changed())
            refresh();
        return;
    }

    int64_t  mtime = 0;
    uint64_t size = 0, ino = 0;
    if (!stamp_of(m_cfg.credentials_file, mtime, size, ino))
        return;
    bool same = m_have_stamp && mtime == m_stamp_mtime_ns && size == m_stamp_size && ino == m_stamp_ino;
    for (size_t i = 0; same && i < m_policy_stamps.size(); ++i)
    {
        file_stamp now_fs;
        stamp_of(m_policy_stamps[i].path, now_fs.mtime_ns, now_fs.size, now_fs.ino);
        same = now_fs.mtime_ns == m_policy_stamps[i].mtime_ns && now_fs.size == m_policy_stamps[i].size &&
               now_fs.ino == m_policy_stamps[i].ino;
    }
    if (same && !iam_changed())
        return;

    std::string err;
    const size_t before = m_creds.size(), users_before = m_creds.user_count();
    if (rebuild(err))
    {
        LOG_INFO(("storage: credentials reloaded from " + m_cfg.credentials_file + " (" +
                  std::to_string(before) + " -> " + std::to_string(m_creds.size()) + " keys, " +
                  std::to_string(users_before) + " -> " + std::to_string(m_creds.user_count()) + " users)").c_str());
        return;
    }
    // Remembered, so files that stay broken are reported once and not every second.
    m_stamp_mtime_ns = mtime;
    m_stamp_size     = size;
    m_stamp_ino      = ino;
    m_have_stamp     = true;
    LOG_WARN(("storage: credentials not reloaded, the old set stays: " + err).c_str());
}

auth_verdict sigv4_authenticator::authorize(const request_view& req)
{
    maybe_reload();

    auth_verdict v;
    const bool attempted = !req.header("authorization").empty() || query_names(req.raw_query, "X-Amz-Algorithm") ||
                           (query_names(req.raw_query, "AWSAccessKeyId") && query_names(req.raw_query, "Signature"));
    v.anonymous = !attempted;
    if (!attempted && m_cfg.anonymous)
    {
        v.hook = unsigned_trailer_hook(req);
        return v;
    }

    m_fields.clear();
    if (req.headers)
        for (const header_ref& h : *req.headers)
            m_fields.push_back({h.name, h.value});

    s3::request_view sv;
    sv.method    = req.method;
    sv.raw_path  = req.raw_path;
    sv.raw_query = req.raw_query;
    sv.headers   = m_fields;
    sv.body_sha256_hex = req.body_sha256_hex;
    s3::verify_options opts = m_opts;
    opts.service = req.service;
    if (req.vhost)
        opts.v2_bucket = req.bucket;

    // Temporary credentials name their session in a token, as a header or in a presigned URL's query.
    std::string token(req.header("x-amz-security-token"));
    if (token.empty())
        for (std::string_view q = req.raw_query; !q.empty();)
        {
            const size_t amp = q.find('&');
            const std::string_view part = q.substr(0, amp);
            q = amp == std::string_view::npos ? std::string_view{} : q.substr(amp + 1);
            if (part.starts_with("X-Amz-Security-Token=") && !percent_decode(part.substr(21), token, false))
                token.clear();
        }
    std::shared_ptr<const user_identity> session_user;
    bool expired = false;
    const int64_t now = wall::now_sec();
    // A named object, because the lookup keeps a pointer to what it is built from.
    const auto lookup = [&](std::string_view access_key) -> std::string_view
    {
        if (token.empty())
        {
            std::string_view s = m_creds.secret(access_key);
            // A key the IAM API just made on another shard is looked for again in the file, at most every 20 ms.
            if (s.empty() && !m_cfg.iam_file.empty() &&
                std::chrono::steady_clock::now() - m_last_iam_probe > std::chrono::milliseconds(20))
            {
                m_last_iam_probe = std::chrono::steady_clock::now();
                if (iam_changed())
                {
                    refresh();
                    s = m_creds.secret(access_key);
                }
            }
            return s;
        }
        return session_secret(token, access_key, now, session_user, expired);
    };
    const s3::verify_result vr = s3::verify(sv, opts, lookup, now);
    if (!vr.ok())
    {
        v.allowed = false;
        v.error   = to_error(vr);
        if (expired)
            v.error = {"ExpiredToken", "The provided token has expired.", 400};
        else if (!token.empty() && v.error.code == "InvalidAccessKeyId")
            v.error = {"InvalidToken", "The provided token is malformed or otherwise invalid.", 400};
        return v;
    }
    v.principal = std::string(vr.access_key());
    v.user      = token.empty() ? m_creds.user_of(v.principal) : std::move(session_user);
    v.session   = !token.empty();

    switch (vr.payload)
    {
        case s3::payload_kind::unsigned_payload:
            break;
        case s3::payload_kind::hex:
        {
            // A request with nothing to carry has nothing to hash, and most of
            // the requests are that.
            const std::string_view len = trim(req.header("content-length"));
            const bool no_body = (len.empty() || len == "0") && req.header("transfer-encoding").empty();
            if (no_body && req.payload_hash == empty_body_sha256)
                break;
            v.hook = std::make_unique<hex_hook>(vr.payload_sha256);
            break;
        }
        case s3::payload_kind::streaming_signed:
        case s3::payload_kind::streaming_unsigned_trailer:
        case s3::payload_kind::streaming_signed_trailer:
            v.hook = std::make_unique<stream_hook>(vr.stream);
            break;
    }
    return v;
}

auth_verdict sigv4_authenticator::authorize_basic(std::string_view access_key, std::string_view secret)
{
    maybe_reload();
    auth_verdict v;
    std::string_view want = m_creds.secret(access_key);
    if (want.empty() && iam_changed())
    {
        refresh();
        want = m_creds.secret(access_key);
    }
    // Compared in constant time, as a signature is, so the secret is not guessed by how long a refusal takes.
    if (want.empty() || want.size() != secret.size() || CRYPTO_memcmp(want.data(), secret.data(), want.size()) != 0)
    {
        v.allowed = false;
        v.error   = {"AccessDenied", "The access key or secret given is not one of this runtime's.", 401};
        return v;
    }
    v.principal = std::string(access_key);
    v.user      = m_creds.user_of(access_key);
    return v;
}

auth_verdict sigv4_authenticator::authorize_password(std::string_view user, std::string_view password)
{
    maybe_reload();
    auth_verdict v;
    auto it = m_logins.find(user);
    if (it == m_logins.end() && iam_changed())
    {
        refresh();
        it = m_logins.find(user);
    }
    // A name without a profile costs what a wrong password does, so a refusal does not say which names are users.
    static const std::string none = password_hash("socketley: no such user");
    const auto now = std::chrono::steady_clock::now();
    const std::string given = sha256_hex(password);
    bool ok = false;
    if (it == m_logins.end())
        ok = (password_matches(none, password), false);
    else if (const auto seen = m_logins_seen.find(user); seen != m_logins_seen.end() && seen->second.until > now &&
             seen->second.hash == it->second.hash && CRYPTO_memcmp(seen->second.given.data(), given.data(), given.size()) == 0)
        ok = true;
    else if ((ok = password_matches(it->second.hash, password)))
    {
        if (m_logins_seen.size() > 1024)
            m_logins_seen.clear();
        m_logins_seen[std::string(user)] = login_seen{given, it->second.hash, now + std::chrono::minutes(5)};
    }
    const std::string key = "~" + std::string(user);
    v.user = ok ? m_creds.user_of(key) : nullptr;
    if (!v.user)
    {
        v.allowed = false;
        v.error   = {"AccessDenied", "The user or password given is not one of this runtime's.", 401};
        return v;
    }
    v.principal = key;
    return v;
}

auth_verdict sigv4_authenticator::authorize_identity(std::string_view id)
{
    maybe_reload();
    auto user = m_creds.shared_user(id);
    if (!user && iam_changed())
    {
        refresh();
        user = m_creds.shared_user(id);
    }
    auth_verdict v;
    if (!user || user->cluster)
    {
        v.allowed = false;
        v.error   = {"AccessDenied", "The account signed in is no user of this runtime.", 403};
        return v;
    }
    v.user      = std::move(user);
    v.principal = "~" + std::string(id);
    return v;
}

std::string sigv4_authenticator::ui_session_mac(std::string_view access_key, int64_t issued_ms, int64_t expires_ms) const
{
    const std::string_view secret = m_creds.secret(access_key);
    return secret.empty() ? std::string{} : hmac_sha256_hex(secret, ui_session_text(access_key, issued_ms, expires_ms));
}

std::string sigv4_authenticator::login_hash(std::string_view id) const
{
    const auto it = m_logins.find(id);
    return it == m_logins.end() ? std::string() : it->second.hash;
}

int sigv4_authenticator::login_state(std::string_view id) const
{
    const auto it = m_logins.find(id);
    return it == m_logins.end() ? -1 : it->second.reset ? 1 : 0;
}

bool sigv4_authenticator::admin_user(std::string_view id) const
{
    const user_identity* u = m_creds.find_user(id);
    return u && u->admin;
}

auth_verdict sigv4_authenticator::authorize_ui_session(std::string_view access_key, int64_t issued_ms,
                                                      int64_t expires_ms, std::string_view mac_hex)
{
    maybe_reload();
    auth_verdict v;
    // A password's session is good only from the time the password was set.
    if (access_key.starts_with('~'))
        if (const auto it = m_logins.find(access_key.substr(1)); it == m_logins.end() || issued_ms < it->second.set_ms)
        {
            v.allowed = false;
            v.error   = {"AccessDenied", "The session is not one of this runtime's.", 401};
            return v;
        }
    const std::string_view secret = m_creds.secret(access_key);
    const std::string want = secret.empty() ? std::string{} : hmac_sha256_hex(secret, ui_session_text(access_key, issued_ms, expires_ms));
    if (want.empty() || want.size() != mac_hex.size() || CRYPTO_memcmp(want.data(), mac_hex.data(), want.size()) != 0)
    {
        v.allowed = false;
        v.error   = {"AccessDenied", "The session is not one of this runtime's.", 401};
        return v;
    }
    v.principal = std::string(access_key);
    v.user      = m_creds.user_of(access_key);
    return v;
}

auth_verdict sigv4_authenticator::authorize_post(const post_signature& sig)
{
    maybe_reload();
    auth_verdict v;
    v.allowed = false;
    auto refuse = [&](std::string code, std::string message, int status)
    {
        v.error = {std::move(code), std::move(message), status};
        return std::move(v);
    };
    if (sig.algorithm.empty() && !sig.v2_access_key.empty())
    {
        const std::string_view key = m_creds.secret(sig.v2_access_key);
        if (key.empty())
            return refuse("InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records.", 403);
        unsigned char raw[20];
        unsigned int len = sizeof raw;
        HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()), reinterpret_cast<const unsigned char*>(sig.policy.data()),
             sig.policy.size(), raw, &len);
        const std::string want = base64_encode(std::string_view(reinterpret_cast<const char*>(raw), len));
        if (sig.v2_signature.size() != want.size() ||
            CRYPTO_memcmp(sig.v2_signature.data(), want.data(), want.size()) != 0)
            return refuse("SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided. Check your key and signing method.", 403);
        v.allowed   = true;
        v.principal = std::string(sig.v2_access_key);
        v.user      = m_creds.user_of(v.principal);
        return v;
    }
    if (sig.algorithm != "AWS4-HMAC-SHA256")
        return refuse("InvalidRequest", "The authorization mechanism you have provided is not supported. Please use AWS4-HMAC-SHA256.", 400);
    // AKID/20130524/us-east-1/s3/aws4_request, split from the right since the key may hold a slash.
    std::string_view rest = sig.credential;
    std::string_view parts[4];
    for (int i = 3; i >= 0; --i)
    {
        const size_t slash = rest.rfind('/');
        if (slash == std::string_view::npos)
            return refuse("InvalidArgument", "The x-amz-credential of the form is malformed.", 400);
        parts[i] = rest.substr(slash + 1);
        rest     = rest.substr(0, slash);
    }
    const std::string_view date = parts[0], region = parts[1], service = parts[2];
    if (rest.empty() || date.size() != 8 || parts[3] != "aws4_request" || service != "s3" || region.empty() ||
        !sig.amz_date.starts_with(date))
        return refuse("InvalidArgument", "The x-amz-credential or x-amz-date of the form is malformed.", 400);
    const std::string_view secret = m_creds.secret(rest);
    if (secret.empty())
        return refuse("InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records.", 403);
    auto mac = [](std::string_view key, std::string_view msg)
    {
        std::string out(32, '\0');
        unsigned int len = 32;
        HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), reinterpret_cast<const unsigned char*>(msg.data()),
             msg.size(), reinterpret_cast<unsigned char*>(out.data()), &len);
        return out;
    };
    const std::string signing = mac(mac(mac(mac("AWS4" + std::string(secret), date), region), service), "aws4_request");
    const std::string want = mac(signing, sig.policy);
    const std::string got_hex(sig.signature);
    const std::string want_hex = hex(reinterpret_cast<const uint8_t*>(want.data()), want.size());
    if (got_hex.size() != want_hex.size() || CRYPTO_memcmp(got_hex.data(), want_hex.data(), want_hex.size()) != 0)
        return refuse("SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided. Check your key and signing method.", 403);
    v.allowed   = true;
    v.principal = std::string(rest);
    v.user      = m_creds.user_of(v.principal);
    return v;
}

}   // namespace socketley::storage
