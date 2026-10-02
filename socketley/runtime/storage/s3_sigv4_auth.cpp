#include "s3_sigv4_auth.h"

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
#include "../../shared/logging.h"
#include "../../shared/s3_sigv4.h"

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

bool credential_set::add(std::string_view access_key, std::string_view secret, std::string& err)
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
    m_map[std::string(access_key)] = std::string(secret);
    return true;
}

std::string_view credential_set::secret(std::string_view access_key) const
{
    const auto it = m_map.find(access_key);
    return it == m_map.end() ? std::string_view{} : std::string_view(it->second);
}

bool parse_credentials(std::string_view text, credential_set& out, std::string& err)
{
    size_t line_no = 0;
    while (!text.empty())
    {
        const size_t nl = text.find('\n');
        std::string_view line = trim(text.substr(0, nl));
        text = nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
        ++line_no;
        if (line.empty() || line.front() == '#')
            continue;
        const size_t colon = line.find(':');
        if (colon == std::string_view::npos)
        {
            err = "line " + std::to_string(line_no) + " is not access:secret";
            return false;
        }
        std::string why;
        if (!out.add(trim(line.substr(0, colon)), trim(line.substr(colon + 1)), why))
        {
            err = "line " + std::to_string(line_no) + ": " + why;
            return false;
        }
    }
    return true;
}

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
        if (n <= 0)
            break;
        got += static_cast<size_t>(n);
    }
    ::close(fd);
    out.resize(got);
    if (st_out)
        *st_out = st;
    return true;
}

}   // namespace

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
        if (!parse_credentials(text, set, err))
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
    if (!m_cfg.credentials_file.empty())
    {
        std::string text;
        struct stat st{};
        if (!read_file(m_cfg.credentials_file, text, err, &st))
            return false;
        if (!parse_credentials(text, set, err))
        {
            err = m_cfg.credentials_file + ": " + err;
            return false;
        }
        m_stamp_mtime_ns = static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
        m_stamp_size     = static_cast<uint64_t>(st.st_size);
        m_stamp_ino      = static_cast<uint64_t>(st.st_ino);
        m_have_stamp     = true;
    }
    if (set.size() == 0 && !m_cfg.anonymous)
    {
        err = "no credentials to serve with";
        return false;
    }
    m_creds = std::move(set);
    return true;
}

bool sigv4_authenticator::load(std::string& err)
{
    m_last_check = std::chrono::steady_clock::now();
    return rebuild(err);
}

void sigv4_authenticator::maybe_reload()
{
    if (m_cfg.credentials_file.empty())
        return;
    const auto now = std::chrono::steady_clock::now();
    if (now - m_last_check < std::chrono::seconds(1))
        return;
    m_last_check = now;

    struct stat st{};
    if (::stat(m_cfg.credentials_file.c_str(), &st) != 0)
        return;
    const int64_t  mtime = static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
    const uint64_t size  = static_cast<uint64_t>(st.st_size);
    const uint64_t ino   = static_cast<uint64_t>(st.st_ino);
    if (m_have_stamp && mtime == m_stamp_mtime_ns && size == m_stamp_size && ino == m_stamp_ino)
        return;

    std::string err;
    const size_t before = m_creds.size();
    if (rebuild(err))
    {
        LOG_INFO(("storage: credentials reloaded from " + m_cfg.credentials_file + " (" +
                  std::to_string(before) + " -> " + std::to_string(m_creds.size()) + " keys)").c_str());
        return;
    }
    // Remembered, so a file that stays broken is reported once and not every second.
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
    const bool attempted = !req.header("authorization").empty() || query_names(req.raw_query, "X-Amz-Algorithm");
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

    // A named object, because the lookup keeps a pointer to what it is built from.
    const auto lookup = [this](std::string_view access_key) -> std::string_view
    {
        return m_creds.secret(access_key);
    };
    const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const s3::verify_result vr = s3::verify(sv, m_opts, lookup, now);
    if (!vr.ok())
    {
        v.allowed = false;
        v.error   = to_error(vr);
        return v;
    }
    v.principal = std::string(vr.access_key());

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
    return v;
}

}   // namespace socketley::storage
