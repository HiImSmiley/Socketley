#include "shared/s3_sigv4.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

namespace socketley::s3
{

namespace
{

constexpr std::string_view algorithm = "AWS4-HMAC-SHA256";
constexpr std::string_view empty_sha256_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const EVP_MD* sha256_md()
{
    static const EVP_MD* md = EVP_MD_fetch(nullptr, "SHA256", nullptr);
    return md;
}

// One EVP context per thread for the one-shot hashes, so a request costs no allocation for them.
EVP_MD_CTX* scratch_ctx()
{
    struct holder
    {
        EVP_MD_CTX* c = EVP_MD_CTX_new();
        ~holder() { EVP_MD_CTX_free(c); }
    };
    thread_local holder h;
    return h.c;
}

void hash_init(EVP_MD_CTX* c)
{
    if (EVP_DigestInit_ex(c, sha256_md(), nullptr) != 1)
        std::abort();
}

void hash_update(EVP_MD_CTX* c, std::string_view d)
{
    if (!d.empty() && EVP_DigestUpdate(c, d.data(), d.size()) != 1)
        std::abort();
}

void hash_final(EVP_MD_CTX* c, uint8_t out[32])
{
    unsigned len = 0;
    if (EVP_DigestFinal_ex(c, out, &len) != 1)
        std::abort();
}

void sha256_of(std::string_view d, uint8_t out[32])
{
    EVP_MD_CTX* c = scratch_ctx();
    hash_init(c);
    hash_update(c, d);
    hash_final(c, out);
}

std::string_view as_sv(const uint8_t* p, size_t n)
{
    return {reinterpret_cast<const char*>(p), n};
}

void hmac_sha256(std::string_view key, std::initializer_list<std::string_view> parts, uint8_t out[32]);

// The signing key is HMAC over date, region, service and the terminator, seeded with "AWS4" and the secret.
void derive_signing_key_uncached(std::string_view secret, std::string_view date, std::string_view region,
                                 std::string_view service, uint8_t key[32])
{
    std::string seed = "AWS4";
    seed.append(secret);
    uint8_t k_date[32], k_region[32], k_service[32];
    hmac_sha256(seed, {date}, k_date);
    hmac_sha256(as_sv(k_date, 32), {region}, k_region);
    hmac_sha256(as_sv(k_region, 32), {service}, k_service);
    hmac_sha256(as_sv(k_service, 32), {"aws4_request"}, key);
    OPENSSL_cleanse(seed.data(), seed.size());
    OPENSSL_cleanse(k_date, sizeof(k_date));
    OPENSSL_cleanse(k_region, sizeof(k_region));
    OPENSSL_cleanse(k_service, sizeof(k_service));
}

// A key depends on the secret, the day, the region and the service and on nothing else, and a client signs
// every request of a day with one of them, so the four HMACs of its derivation are done once per thread.
struct signing_key_cache
{
    static constexpr size_t slots = 4;
    struct slot
    {
        bool        used = false;
        std::string secret;
        std::string date;
        std::string region;
        std::string service;
        uint8_t     key[32] = {};
    };
    slot   s[slots];
    size_t next = 0;

    ~signing_key_cache()
    {
        for (slot& e : s)
        {
            OPENSSL_cleanse(e.key, sizeof(e.key));
            if (!e.secret.empty())
                OPENSSL_cleanse(e.secret.data(), e.secret.size());
        }
    }
};

void derive_signing_key(std::string_view secret, std::string_view date, std::string_view region,
                        std::string_view service, uint8_t key[32])
{
    thread_local signing_key_cache cache;
    for (auto& e : cache.s)
        if (e.used && e.date == date && e.region == region && e.service == service && e.secret == secret)
        {
            std::memcpy(key, e.key, 32);
            return;
        }
    derive_signing_key_uncached(secret, date, region, service, key);
    auto& e = cache.s[cache.next++ % signing_key_cache::slots];
    if (!e.secret.empty())
        OPENSSL_cleanse(e.secret.data(), e.secret.size());
    e.used    = true;
    e.secret  = std::string(secret);
    e.date    = std::string(date);
    e.region  = std::string(region);
    e.service = std::string(service);
    std::memcpy(e.key, key, 32);
}

void hmac_sha256(std::string_view key, std::initializer_list<std::string_view> parts, uint8_t out[32])
{
    uint8_t k[64] = {};
    if (key.size() > sizeof(k))
        sha256_of(key, k);
    else if (!key.empty())
        std::memcpy(k, key.data(), key.size());

    uint8_t pad[64];
    uint8_t inner[32];
    EVP_MD_CTX* c = scratch_ctx();

    for (size_t i = 0; i < sizeof(pad); i++)
        pad[i] = k[i] ^ 0x36;
    hash_init(c);
    hash_update(c, as_sv(pad, sizeof(pad)));
    for (std::string_view p : parts)
        hash_update(c, p);
    hash_final(c, inner);

    for (size_t i = 0; i < sizeof(pad); i++)
        pad[i] = k[i] ^ 0x5c;
    hash_init(c);
    hash_update(c, as_sv(pad, sizeof(pad)));
    hash_update(c, as_sv(inner, sizeof(inner)));
    hash_final(c, out);

    OPENSSL_cleanse(k, sizeof(k));
    OPENSSL_cleanse(pad, sizeof(pad));
}

// By table, since a branch per digit of a random hash is mispredicted half the time.
constexpr auto hex_table = []
{
    std::array<int8_t, 256> t{};
    for (int i = 0; i < 256; i++)
        t[static_cast<size_t>(i)] = i >= '0' && i <= '9' ? static_cast<int8_t>(i - '0')
                                  : i >= 'a' && i <= 'f' ? static_cast<int8_t>(i - 'a' + 10)
                                  : i >= 'A' && i <= 'F' ? static_cast<int8_t>(i - 'A' + 10) : int8_t{-1};
    return t;
}();

int hex_val(char c)
{
    return hex_table[static_cast<unsigned char>(c)];
}

bool hex_decode32(std::string_view hex, uint8_t out[32])
{
    if (hex.size() != 64)
        return false;
    int bad = 0;
    for (size_t i = 0; i < 32; i++)
    {
        const int hi = hex_val(hex[2 * i]);
        const int lo = hex_val(hex[2 * i + 1]);
        bad |= hi | lo;
        out[i] = static_cast<uint8_t>(hi << 4 | lo);
    }
    return bad >= 0;
}

void hex_encode32(const uint8_t in[32], char out[64])
{
    static constexpr char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++)
    {
        out[2 * i]     = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 15];
    }
}

char lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

bool ieq(std::string_view a, std::string_view b)
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); i++)
        if (lower(a[i]) != lower(b[i]))
            return false;
    return true;
}

bool is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

std::string_view trim(std::string_view s)
{
    while (!s.empty() && is_space(s.front())) s.remove_prefix(1);
    while (!s.empty() && is_space(s.back())) s.remove_suffix(1);
    return s;
}

constexpr auto unreserved_table = []
{
    std::array<bool, 256> t{};
    for (int c = 0; c < 256; c++)
        t[static_cast<size_t>(c)] = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                                    c == '-' || c == '_' || c == '.' || c == '~';
    return t;
}();

bool kept_as_is(unsigned char c, bool keep_slash)
{
    return unreserved_table[c] || (keep_slash && c == '/');
}

void uri_encode_append(std::string& out, std::string_view s, bool keep_slash)
{
    static constexpr char digits[] = "0123456789ABCDEF";
    out.reserve(out.size() + s.size());
    size_t i = 0;
    while (i < s.size())
    {
        size_t run = i;
        while (run < s.size() && kept_as_is(static_cast<unsigned char>(s[run]), keep_slash))
            ++run;
        out.append(s.data() + i, run - i);
        if (run == s.size())
            break;
        const auto c = static_cast<unsigned char>(s[run]);
        const char esc[3] = {'%', digits[c >> 4], digits[c & 15]};
        out.append(esc, 3);
        i = run + 1;
    }
}

// A path that decoding leaves alone and encoding gives back unchanged.
bool canonical_already(std::string_view path)
{
    for (unsigned char c : path)
        if (!kept_as_is(c, true))
            return false;
    return true;
}

// A malformed escape stays a literal '%', which the encoder then turns into %25.
std::string decode_component(std::string_view s, bool plus_is_space)
{
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); i++)
    {
        char c = s[i];
        if (c == '%' && i + 2 < s.size() && hex_val(s[i + 1]) >= 0 && hex_val(s[i + 2]) >= 0)
        {
            out.push_back(static_cast<char>(hex_val(s[i + 1]) << 4 | hex_val(s[i + 2])));
            i += 2;
        }
        else if (c == '+' && plus_is_space)
            out.push_back(' ');
        else
            out.push_back(c);
    }
    return out;
}

// Walks the raw query as name/value pairs without decoding; a parameter with no '=' has an empty value.
template <class F>
void for_each_param(std::string_view q, F&& f)
{
    while (!q.empty())
    {
        size_t amp = q.find('&');
        std::string_view part = q.substr(0, amp);
        q = amp == std::string_view::npos ? std::string_view{} : q.substr(amp + 1);
        if (part.empty())
            continue;
        size_t eq = part.find('=');
        if (eq == std::string_view::npos)
            f(part, std::string_view{});
        else
            f(part.substr(0, eq), part.substr(eq + 1));
    }
}

void canonical_query(std::string& out, std::string_view raw_query, std::string_view drop)
{
    std::vector<std::pair<std::string, std::string>> items;
    for_each_param(raw_query, [&](std::string_view n, std::string_view v) {
        std::string name = decode_component(n, true);
        if (!drop.empty() && name == drop)
            return;
        std::string en, ev;
        uri_encode_append(en, name, false);
        uri_encode_append(ev, decode_component(v, true), false);
        items.emplace_back(std::move(en), std::move(ev));
    });
    std::sort(items.begin(), items.end());
    bool first = true;
    for (auto& [n, v] : items)
    {
        if (!first)
            out.push_back('&');
        first = false;
        out += n;
        out.push_back('=');
        out += v;
    }
}

bool query_param(std::string_view raw_query, std::string_view name, std::string& out)
{
    bool found = false;
    for_each_param(raw_query, [&](std::string_view n, std::string_view v) {
        if (found || decode_component(n, true) != name)
            return;
        found = true;
        out = decode_component(v, true);
    });
    return found;
}

// A signed header missing from the request, or an empty name, makes the list unusable.
bool append_canonical_headers(std::string& out, std::span<const header_field> headers, std::string_view signed_list)
{
    std::string_view rest = signed_list;
    while (true)
    {
        size_t semi = rest.find(';');
        std::string_view name = rest.substr(0, semi);
        if (name.empty())
            return false;
        bool found = false;
        out.append(name);
        out.push_back(':');
        for (const header_field& h : headers)
        {
            if (!ieq(h.name, name))
                continue;
            if (found)
                out.push_back(',');
            found = true;
            // A value with no whitespace in it is its own canonical form.
            if (std::none_of(h.value.begin(), h.value.end(), is_space))
            {
                out.append(h.value);
                continue;
            }
            bool pending_space = false, started = false;
            for (char c : h.value)
            {
                if (is_space(c))
                {
                    pending_space = started;
                    continue;
                }
                if (pending_space)
                    out.push_back(' ');
                pending_space = false;
                started       = true;
                out.push_back(c);
            }
        }
        if (!found)
            return false;
        out.push_back('\n');
        if (semi == std::string_view::npos)
            break;
        rest.remove_prefix(semi + 1);
    }
    return true;
}

const header_field* find_header(std::span<const header_field> headers, std::string_view name)
{
    for (const header_field& h : headers)
        if (ieq(h.name, name))
            return &h;
    return nullptr;
}

bool list_contains(std::string_view list, std::string_view name)
{
    while (true)
    {
        size_t semi = list.find(';');
        if (list.substr(0, semi) == name)
            return true;
        if (semi == std::string_view::npos)
            return false;
        list.remove_prefix(semi + 1);
    }
}

int64_t days_from_civil(int64_t y, unsigned m, unsigned d)
{
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

bool valid_civil(int y, int mo, int d, int h, int mi, int s)
{
    static constexpr int mdays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (mo < 1 || mo > 12 || h < 0 || h > 23 || mi < 0 || mi > 59 || s < 0 || s > 59 || y < 1970 || y > 9999)
        return false;
    int dm = mdays[mo - 1] + (mo == 2 && (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)) ? 1 : 0);
    return d >= 1 && d <= dm;
}

struct stamp
{
    char amz[17] = {};
    int64_t unix = 0;
};

bool make_stamp(int y, int mo, int d, int h, int mi, int s, stamp& out)
{
    if (!valid_civil(y, mo, d, h, mi, s))
        return false;
    auto put = [&](size_t at, int v, int width) {
        for (int i = width - 1; i >= 0; i--, v /= 10)
            out.amz[at + static_cast<size_t>(i)] = static_cast<char>('0' + v % 10);
    };
    put(0, y, 4);
    put(4, mo, 2);
    put(6, d, 2);
    out.amz[8] = 'T';
    put(9, h, 2);
    put(11, mi, 2);
    put(13, s, 2);
    out.amz[15] = 'Z';
    out.amz[16] = '\0';
    out.unix = days_from_civil(y, static_cast<unsigned>(mo), static_cast<unsigned>(d)) * 86400 + h * 3600 + mi * 60 + s;
    return true;
}

bool digits_to_int(std::string_view s, int& out)
{
    if (s.empty() || s.size() > 9)
        return false;
    int v = 0;
    for (char c : s)
    {
        if (c < '0' || c > '9')
            return false;
        v = v * 10 + (c - '0');
    }
    out = v;
    return true;
}

// YYYYMMDDTHHMMSSZ.
bool parse_amz_date(std::string_view v, stamp& out)
{
    if (v.size() != 16 || v[8] != 'T' || v[15] != 'Z')
        return false;
    int y, mo, d, h, mi, s;
    if (!digits_to_int(v.substr(0, 4), y) || !digits_to_int(v.substr(4, 2), mo) || !digits_to_int(v.substr(6, 2), d) ||
        !digits_to_int(v.substr(9, 2), h) || !digits_to_int(v.substr(11, 2), mi) || !digits_to_int(v.substr(13, 2), s))
        return false;
    return make_stamp(y, mo, d, h, mi, s, out);
}

// The RFC 1123 form of the Date header, "Fri, 24 May 2013 00:00:00 GMT", or its RFC 2822 zone "+0000" or "-0000" that botocore sends.
bool parse_http_date(std::string_view v, stamp& out)
{
    v = trim(v);
    if (v.size() < 29 || v[3] != ',' || v[4] != ' ' || v[7] != ' ' || v[11] != ' ' || v[16] != ' ' || v[19] != ':' || v[22] != ':')
        return false;
    const std::string_view zone = v.substr(25);
    if (zone != " GMT" && zone != " UTC" && zone != " +0000" && zone != " -0000")
        return false;
    static constexpr std::string_view months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    int mo = 0;
    for (int i = 0; i < 12; i++)
        if (v.substr(8, 3) == months[i])
            mo = i + 1;
    int y, d, h, mi, s;
    if (!mo || !digits_to_int(v.substr(5, 2), d) || !digits_to_int(v.substr(12, 4), y) || !digits_to_int(v.substr(17, 2), h) ||
        !digits_to_int(v.substr(20, 2), mi) || !digits_to_int(v.substr(23, 2), s))
        return false;
    return make_stamp(y, mo, d, h, mi, s, out);
}

verify_result fail(sigv4_status st, int http, const char* code, const char* msg, auth_form form = auth_form::none)
{
    verify_result r;
    r.status      = st;
    r.http_status = http;
    r.code        = code;
    r.message     = msg;
    r.form        = form;
    return r;
}

verify_result malformed(auth_form form, const char* msg)
{
    return fail(sigv4_status::malformed, 400, form == auth_form::query ? "AuthorizationQueryParametersError" : "AuthorizationHeaderMalformed", msg, form);
}

struct parsed_auth
{
    auth_form form = auth_form::none;
    // Views into the Authorization header, or into verify's copies of the decoded query.
    std::string_view access_key;
    std::string_view date;
    std::string_view region;
    std::string_view service;
    std::string_view signed_headers;
    std::string_view signature_hex;
    std::string payload_from_query;
    bool has_payload_query = false;
    stamp when;
    int64_t expires_s = 0;
};

// "AKID/20130524/us-east-1/s3/aws4_request", split from the right so the key may contain a slash.
bool split_credential(std::string_view cred, parsed_auth& a)
{
    std::string_view rest = cred;
    std::string_view parts[4];
    for (int i = 3; i >= 0; i--)
    {
        size_t slash = rest.rfind('/');
        if (slash == std::string_view::npos)
            return false;
        parts[i] = rest.substr(slash + 1);
        rest     = rest.substr(0, slash);
    }
    if (rest.empty() || parts[3] != "aws4_request")
        return false;
    a.access_key = rest;
    a.date       = parts[0];
    a.region     = parts[1];
    a.service    = parts[2];
    return true;
}

constexpr std::string_view unsigned_payload_s   = "UNSIGNED-PAYLOAD";
constexpr std::string_view streaming_signed_s   = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
constexpr std::string_view streaming_unsigned_trailer_s = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
constexpr std::string_view streaming_signed_trailer_s   = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";

bool classify_payload(std::string_view v, payload_kind& kind, uint8_t hash[32])
{
    if (v == unsigned_payload_s) { kind = payload_kind::unsigned_payload; return true; }
    if (v == streaming_signed_s) { kind = payload_kind::streaming_signed; return true; }
    if (v == streaming_unsigned_trailer_s) { kind = payload_kind::streaming_unsigned_trailer; return true; }
    if (v == streaming_signed_trailer_s) { kind = payload_kind::streaming_signed_trailer; return true; }
    kind = payload_kind::hex;
    return hex_decode32(v, hash);
}

bool parse_u64(std::string_view s, uint64_t& out)
{
    s = trim(s);
    if (s.empty() || s.size() > 19)
        return false;
    uint64_t v = 0;
    for (char c : s)
    {
        if (c < '0' || c > '9')
            return false;
        v = v * 10 + static_cast<uint64_t>(c - '0');
    }
    out = v;
    return true;
}

void append(std::string& s, std::initializer_list<std::string_view> parts)
{
    for (std::string_view p : parts)
        s.append(p);
}

} // namespace

const char* default_code(sigv4_status s)
{
    switch (s)
    {
    case sigv4_status::ok: return "";
    case sigv4_status::missing_auth: return "AccessDenied";
    case sigv4_status::malformed: return "AuthorizationHeaderMalformed";
    case sigv4_status::unknown_access_key: return "InvalidAccessKeyId";
    case sigv4_status::signature_mismatch: return "SignatureDoesNotMatch";
    case sigv4_status::request_time_too_skewed: return "RequestTimeTooSkewed";
    case sigv4_status::expired: return "AccessDenied";
    }
    return "";
}

stream_context stream_context::unsigned_trailer(uint64_t decoded_length)
{
    stream_context c;
    c.kind           = payload_kind::streaming_unsigned_trailer;
    c.decoded_length = decoded_length;
    return c;
}

verify_result verify(const request_view& req, const verify_options& opts, const secret_lookup& secrets, int64_t now_unix)
{
    const header_field* auth_hdr = find_header(req.headers, "authorization");
    std::string algo_q;
    bool has_query_auth = query_param(req.raw_query, "X-Amz-Algorithm", algo_q);

    if (!auth_hdr && !has_query_auth)
        return fail(sigv4_status::missing_auth, 403, "AccessDenied", "Access Denied");
    if (auth_hdr && has_query_auth)
        return fail(sigv4_status::malformed, 400, "InvalidRequest", "Only one auth mechanism allowed; only the X-Amz-Algorithm query parameter, Signature query string parameter or the Authorization header should be specified");

    parsed_auth a;
    // The presigned parameters decoded, which `a` points into.
    std::string cred_q, date_q, signed_q, sig_q, exp_q;

    if (auth_hdr)
    {
        a.form = auth_form::header;
        std::string_view v = trim(auth_hdr->value);
        size_t sp = v.find(' ');
        std::string_view scheme = v.substr(0, sp);
        if (scheme != algorithm)
            return fail(sigv4_status::malformed, 400, "InvalidRequest", "The authorization mechanism you have provided is not supported. Please use AWS4-HMAC-SHA256.", auth_form::header);
        if (sp == std::string_view::npos)
            return malformed(a.form, "The authorization header is malformed; the credential is missing.");
        v.remove_prefix(sp + 1);

        std::string_view cred, signed_h, sig;
        bool has_cred = false, has_signed = false, has_sig = false;
        while (!v.empty())
        {
            size_t comma = v.find(',');
            std::string_view item = trim(v.substr(0, comma));
            v = comma == std::string_view::npos ? std::string_view{} : v.substr(comma + 1);
            size_t eq = item.find('=');
            if (eq == std::string_view::npos)
                return malformed(a.form, "The authorization header is malformed; a component has no value.");
            std::string_view k = item.substr(0, eq), val = item.substr(eq + 1);
            if (k == "Credential") { cred = val; has_cred = true; }
            else if (k == "SignedHeaders") { signed_h = val; has_signed = true; }
            else if (k == "Signature") { sig = val; has_sig = true; }
        }
        if (!has_cred || !has_signed || !has_sig)
            return malformed(a.form, "The authorization header is malformed; the Credential, SignedHeaders and Signature components are all required.");
        if (!split_credential(cred, a))
            return malformed(a.form, "The authorization header is malformed; the Credential is mal-formed; expecting \"<YOUR-AKID>/YYYYMMDD/REGION/SERVICE/aws4_request\".");
        a.signed_headers = signed_h;
        a.signature_hex  = sig;

        const header_field* xd = find_header(req.headers, "x-amz-date");
        if (xd)
        {
            if (!parse_amz_date(trim(xd->value), a.when))
                return malformed(a.form, "The x-amz-date header is not in ISO 8601 basic format.");
        }
        else if (const header_field* d = find_header(req.headers, "date"))
        {
            if (!parse_http_date(d->value, a.when) && !parse_amz_date(trim(d->value), a.when))
                return malformed(a.form, "The Date header is not a valid HTTP date.");
        }
        else
            return fail(sigv4_status::missing_auth, 403, "AccessDenied", "AWS authentication requires a valid Date or x-amz-date header", a.form);
    }
    else
    {
        a.form = auth_form::query;
        if (algo_q != algorithm)
            return malformed(a.form, "X-Amz-Algorithm only supports \"AWS4-HMAC-SHA256\".");
        if (!query_param(req.raw_query, "X-Amz-Credential", cred_q) || !query_param(req.raw_query, "X-Amz-Date", date_q) ||
            !query_param(req.raw_query, "X-Amz-SignedHeaders", signed_q) || !query_param(req.raw_query, "X-Amz-Signature", sig_q) ||
            !query_param(req.raw_query, "X-Amz-Expires", exp_q))
            return malformed(a.form, "Query-string authentication requires the X-Amz-Algorithm, X-Amz-Credential, X-Amz-Signature, X-Amz-Date, X-Amz-SignedHeaders, and X-Amz-Expires parameters.");
        if (!split_credential(cred_q, a))
            return malformed(a.form, "Error parsing the X-Amz-Credential parameter; the Credential is mal-formed.");
        if (!parse_amz_date(date_q, a.when))
            return malformed(a.form, "X-Amz-Date must be in the ISO8601 Long Format \"yyyyMMdd'T'HHmmss'Z'\".");
        uint64_t e;
        if (!parse_u64(exp_q, e))
            return malformed(a.form, "X-Amz-Expires should be a number.");
        if (e < 1)
            return malformed(a.form, "X-Amz-Expires must be non-negative.");
        if (e > static_cast<uint64_t>(opts.max_expires_seconds))
            return malformed(a.form, "X-Amz-Expires must be less than a week (in seconds); that is, the given X-Amz-Expires must be less than 604800 seconds.");
        a.expires_s      = static_cast<int64_t>(e);
        a.signed_headers = signed_q;
        a.signature_hex  = sig_q;
        a.has_payload_query = query_param(req.raw_query, "X-Amz-Content-Sha256", a.payload_from_query);
    }

    if (a.date.size() != 8 || a.date != std::string_view(a.when.amz, 8))
        return malformed(a.form, "The credential scope date does not match the request date.");
    if (a.service != opts.service)
        return malformed(a.form, "The credential scope names a different service than this one.");
    if (a.region.empty() || a.region.size() > 48 || a.service.size() > 24)
        return malformed(a.form, "The credential scope region is not valid.");
    if (!opts.region.empty() && a.region != opts.region)
        return malformed(a.form, "The authorization is for a region other than the one this server is in.");
    if (a.access_key.size() > 127)
        return malformed(a.form, "The access key is too long.");

    uint8_t claimed[32];
    if (!hex_decode32(a.signature_hex, claimed))
        return malformed(a.form, "The signature must be 64 hexadecimal characters.");

    std::string_view sh = a.signed_headers;
    if (sh.empty() || sh.size() > 1024 || !list_contains(sh, "host"))
        return malformed(a.form, "The signed headers must include host.");
    if (a.form == auth_form::header)
    {
        bool has_xd = find_header(req.headers, "x-amz-date") != nullptr;
        if (!list_contains(sh, has_xd ? "x-amz-date" : "date"))
            return malformed(a.form, "The date header the request uses must be signed.");
        if (find_header(req.headers, "x-amz-content-sha256") && !list_contains(sh, "x-amz-content-sha256"))
            return malformed(a.form, "x-amz-content-sha256 must be signed.");
    }

    std::string_view secret = secrets(a.access_key);
    if (secret.empty())
        return fail(sigv4_status::unknown_access_key, 403, "InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records.", a.form);

    int64_t age = now_unix - a.when.unix;
    if (a.form == auth_form::query)
    {
        if (age < -opts.skew_seconds)
            return fail(sigv4_status::request_time_too_skewed, 403, "RequestTimeTooSkewed", "The request is dated too far in the future.", a.form);
        if (age > a.expires_s)
            return fail(sigv4_status::expired, 403, "AccessDenied", "Request has expired", a.form);
    }
    else if (age > opts.skew_seconds || age < -opts.skew_seconds)
        return fail(sigv4_status::request_time_too_skewed, 403, "RequestTimeTooSkewed", "The difference between the request time and the current time is too large.", a.form);

    std::string_view payload_text;
    if (a.form == auth_form::header)
    {
        if (const header_field* h = find_header(req.headers, "x-amz-content-sha256"))
            payload_text = trim(h->value);
        else if (!req.body_sha256_hex.empty())
            payload_text = req.body_sha256_hex;
        else
            return fail(sigv4_status::malformed, 400, "InvalidRequest", "Missing required header for this request: x-amz-content-sha256", a.form);
    }
    else
        payload_text = a.has_payload_query ? std::string_view(a.payload_from_query) : unsigned_payload_s;

    verify_result r;
    r.form = a.form;
    if (!classify_payload(payload_text, r.payload, r.payload_sha256))
        return fail(sigv4_status::malformed, 400, "InvalidArgument", "x-amz-content-sha256 must be UNSIGNED-PAYLOAD, STREAMING-UNSIGNED-PAYLOAD-TRAILER, STREAMING-AWS4-HMAC-SHA256-PAYLOAD, STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER or a valid sha256 value.", a.form);
    if (a.form == auth_form::query && r.payload != payload_kind::unsigned_payload && r.payload != payload_kind::hex)
        return malformed(a.form, "A presigned request cannot use a streaming payload.");

    uint64_t decoded_length = UINT64_MAX;
    if (const header_field* h = find_header(req.headers, "x-amz-decoded-content-length"))
        if (!parse_u64(h->value, decoded_length))
            return fail(sigv4_status::malformed, 400, "InvalidArgument", "x-amz-decoded-content-length is not a number.", a.form);

    uint8_t key[32];
    derive_signing_key(secret, a.date, a.region, a.service, key);

    thread_local std::string scope;
    scope.clear();
    append(scope, {a.date, "/", a.region, "/", a.service, "/aws4_request"});

    thread_local std::string creq;
    thread_local std::string sts;
    std::string_view path_b = req.raw_path.empty() ? std::string_view("/") : req.raw_path;
    std::string path_a;
    if (!canonical_already(path_b))
        uri_encode_append(path_a, decode_component(path_b, false), true);
    std::string_view paths[2] = {path_a.empty() ? path_b : std::string_view(path_a), path_b};

    std::string query;
    canonical_query(query, req.raw_query, a.form == auth_form::query ? std::string_view("X-Amz-Signature") : std::string_view{});

    bool matched  = false;
    char sig_hex[64] = {};
    for (int attempt = 0; attempt < 2 && !matched; attempt++)
    {
        if (attempt == 1 && paths[1] == paths[0])
            break;
        creq.clear();
        append(creq, {req.method, "\n", paths[attempt], "\n", query, "\n"});
        if (!append_canonical_headers(creq, req.headers, sh))
            return fail(sigv4_status::signature_mismatch, 403, "SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided. A signed header is missing from the request.", a.form);
        append(creq, {"\n", sh, "\n", payload_text});

        uint8_t creq_hash[32];
        char creq_hex[64];
        sha256_of(creq, creq_hash);
        hex_encode32(creq_hash, creq_hex);
        sts.clear();
        append(sts, {algorithm, "\n", std::string_view(a.when.amz, 16), "\n", scope, "\n", std::string_view(creq_hex, 64)});

        uint8_t mac[32];
        hmac_sha256(as_sv(key, 32), {sts}, mac);
        matched = CRYPTO_memcmp(mac, claimed, 32) == 0;
        if (matched)
            hex_encode32(mac, sig_hex);
    }

    if (!matched)
    {
        OPENSSL_cleanse(key, sizeof(key));
        return fail(sigv4_status::signature_mismatch, 403, "SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided. Check your key and signing method.", a.form);
    }

    r.status      = sigv4_status::ok;
    r.http_status = 200;
    r.code        = "";
    r.message     = "";
    std::memcpy(r.access_key_buf, a.access_key.data(), a.access_key.size());
    r.access_key_len = static_cast<uint8_t>(a.access_key.size());

    stream_context& sc = r.stream;
    sc.kind = r.payload;
    std::memcpy(sc.signing_key, key, 32);
    std::memcpy(sc.amz_date, a.when.amz, 16);
    std::memcpy(sc.scope, scope.data(), scope.size());
    sc.scope_len = static_cast<uint8_t>(scope.size());
    std::memcpy(sc.prev_signature, sig_hex, 64);
    sc.decoded_length = decoded_length;
    OPENSSL_cleanse(key, sizeof(key));
    return r;
}

std::string sign(const sign_input& in)
{
    std::vector<std::string_view> names;
    names.reserve(in.headers.size());
    for (const header_field& h : in.headers)
        names.push_back(h.name);
    std::sort(names.begin(), names.end());
    std::string signed_list;
    for (std::string_view n : names)
    {
        if (!signed_list.empty())
            signed_list.push_back(';');
        signed_list.append(n);
    }

    const std::string_view raw = in.raw_path.empty() ? std::string_view("/") : in.raw_path;
    std::string path;
    if (canonical_already(raw))
        path = std::string(raw);
    else
        uri_encode_append(path, decode_component(raw, false), true);
    std::string query;
    canonical_query(query, in.raw_query, {});

    std::string creq;
    append(creq, {in.method, "\n", path, "\n", query, "\n"});
    if (!append_canonical_headers(creq, in.headers, signed_list))
        return {};
    append(creq, {"\n", signed_list, "\n", in.payload_hash});

    const std::string_view date = in.amz_date.substr(0, 8);
    std::string scope;
    append(scope, {date, "/", in.region, "/", in.service, "/aws4_request"});
    uint8_t creq_hash[32];
    char creq_hex[64];
    sha256_of(creq, creq_hash);
    hex_encode32(creq_hash, creq_hex);
    std::string sts;
    append(sts, {algorithm, "\n", in.amz_date, "\n", scope, "\n", std::string_view(creq_hex, 64)});

    uint8_t key[32];
    derive_signing_key(in.secret, date, in.region, in.service, key);
    uint8_t mac[32];
    hmac_sha256(as_sv(key, 32), {sts}, mac);
    OPENSSL_cleanse(key, sizeof(key));
    char sig[64];
    hex_encode32(mac, sig);

    std::string out;
    append(out, {algorithm, " Credential=", in.access_key, "/", scope, ", SignedHeaders=", signed_list,
                 ", Signature=", std::string_view(sig, 64)});
    return out;
}

// ---- payload_hasher ----

payload_hasher::payload_hasher() : ctx_(EVP_MD_CTX_new())
{
    if (!ctx_)
        std::abort();
    hash_init(ctx_);
}

payload_hasher::~payload_hasher()
{
    EVP_MD_CTX_free(ctx_);
}

void payload_hasher::update(std::string_view data)
{
    hash_update(ctx_, data);
}

void payload_hasher::reset()
{
    hash_init(ctx_);
}

void payload_hasher::finish(uint8_t out[32])
{
    hash_final(ctx_, out);
}

bool payload_hasher::matches(const uint8_t expected[32])
{
    uint8_t got[32];
    finish(got);
    return CRYPTO_memcmp(got, expected, 32) == 0;
}

error_info payload_mismatch()
{
    return {sigv4_status::signature_mismatch, 400, "XAmzContentSHA256Mismatch", "The provided 'x-amz-content-sha256' header does not match what was computed."};
}

error_info incomplete_body()
{
    return {sigv4_status::malformed, 400, "IncompleteBody", "You did not provide the number of bytes specified by the Content-Length HTTP header."};
}

// ---- chunk_stream ----

namespace
{

bool signed_kind(payload_kind k)
{
    return k == payload_kind::streaming_signed || k == payload_kind::streaming_signed_trailer;
}

} // namespace

chunk_stream::chunk_stream(const stream_context& ctx, uint64_t max_chunk_bytes)
    : ctx_(ctx), max_chunk_(max_chunk_bytes), hash_(EVP_MD_CTX_new())
{
    if (!hash_)
        std::abort();
    hash_init(hash_);
}

chunk_stream::~chunk_stream()
{
    OPENSSL_cleanse(ctx_.signing_key, sizeof(ctx_.signing_key));
    EVP_MD_CTX_free(hash_);
}

stream_status chunk_stream::fail(stream_status s)
{
    status_ = s;
    return s;
}

bool chunk_stream::bad(stream_status s)
{
    status_ = s;
    return false;
}

error_info chunk_stream::error() const
{
    switch (status_)
    {
    case stream_status::bad_signature:
        return {sigv4_status::signature_mismatch, 403, "SignatureDoesNotMatch", "The chunk signature we calculated does not match the signature you provided."};
    case stream_status::malformed:
        return {sigv4_status::malformed, 400, "InvalidRequest", "The aws-chunked body is malformed."};
    case stream_status::length_mismatch:
        return {sigv4_status::malformed, 400, "IncompleteBody", "The decoded body length is not the x-amz-decoded-content-length the request declared."};
    default:
        return {};
    }
}

// Signature of the chunk just hashed (or of the empty final chunk), chained from the previous one.
bool chunk_stream::sign_matches(bool final_chunk, const uint8_t claimed[32])
{
    char chunk_hex[64];
    if (final_chunk)
        std::memcpy(chunk_hex, empty_sha256_hex.data(), 64);
    else
    {
        uint8_t h[32];
        hash_final(hash_, h);
        hex_encode32(h, chunk_hex);
    }
    std::string sts;
    append(sts, {"AWS4-HMAC-SHA256-PAYLOAD\n", std::string_view(ctx_.amz_date, 16), "\n", std::string_view(ctx_.scope, ctx_.scope_len), "\n",
                 std::string_view(ctx_.prev_signature, 64), "\n", empty_sha256_hex, "\n", std::string_view(chunk_hex, 64)});
    uint8_t mac[32];
    hmac_sha256(as_sv(ctx_.signing_key, 32), {sts}, mac);
    if (CRYPTO_memcmp(mac, claimed, 32) != 0)
        return false;
    hex_encode32(mac, ctx_.prev_signature);
    return true;
}

// One header line without its CRLF: the chunk size in hex, then for signed streams ";chunk-signature=" and 64 hex digits.
bool chunk_stream::on_header()
{
    std::string_view line(hdr_, hdr_len_);
    uint64_t size = 0;
    size_t i = 0;
    while (i < line.size() && hex_val(line[i]) >= 0)
    {
        if (i >= 16)
            return bad(stream_status::malformed);
        size = size << 4 | static_cast<uint64_t>(hex_val(line[i]));
        i++;
    }
    if (i == 0)
        return bad(stream_status::malformed);
    std::string_view rest = line.substr(i);

    bool sgn = signed_kind(ctx_.kind);
    uint8_t claimed[32] = {};
    if (sgn)
    {
        constexpr std::string_view ext = ";chunk-signature=";
        if (rest.size() != ext.size() + 64 || rest.substr(0, ext.size()) != ext || !hex_decode32(rest.substr(ext.size()), claimed))
            return bad(stream_status::malformed);
    }
    else if (!rest.empty() && rest.front() != ';')
        return bad(stream_status::malformed);

    if (size == 0)
    {
        if (ctx_.decoded_length != UINT64_MAX && decoded_ != ctx_.decoded_length)
            return bad(stream_status::length_mismatch);
        if (sgn && !sign_matches(true, claimed))
            return bad(stream_status::bad_signature);
        state_ = state::trailer;
        return true;
    }
    if (size > max_chunk_)
        return bad(stream_status::malformed);
    if (ctx_.decoded_length != UINT64_MAX && size > ctx_.decoded_length - decoded_)
        return bad(stream_status::length_mismatch);
    std::memcpy(claimed_, claimed, 32);
    chunk_remaining_ = size;
    if (sgn)
        hash_init(hash_);
    state_ = state::data;
    return true;
}

bool chunk_stream::on_chunk_end()
{
    if (signed_kind(ctx_.kind) && !sign_matches(false, claimed_))
        return bad(stream_status::bad_signature);
    state_ = state::header;
    return true;
}

// The trailer is "name:value\r\n" lines then a blank line, and for signed streams the last line is x-amz-trailer-signature.
bool chunk_stream::on_trailer()
{
    std::string_view t(trailer_, trailer_len_);
    if (ctx_.kind == payload_kind::streaming_signed_trailer)
    {
        constexpr std::string_view name = "x-amz-trailer-signature:";
        // The buffer ends "sig\r\n\r\n", so the signature line is the last one before the blank line.
        if (t.size() < 4)
            return bad(stream_status::malformed);
        std::string_view body = t.substr(0, t.size() - 2);
        size_t line_start = body.size() >= 3 ? body.rfind("\r\n", body.size() - 3) : std::string_view::npos;
        line_start = line_start == std::string_view::npos ? 0 : line_start + 2;
        std::string_view sig_line = body.substr(line_start, body.size() - line_start - 2);
        if (sig_line.size() != name.size() + 64 || !ieq(sig_line.substr(0, name.size()), name))
            return bad(stream_status::malformed);
        uint8_t claimed[32];
        if (!hex_decode32(sig_line.substr(name.size()), claimed))
            return bad(stream_status::malformed);

        // The signed text is each trailer header line ended by a bare LF, whatever ended it on the wire.
        std::string canon;
        for (std::string_view headers = body.substr(0, line_start); !headers.empty();)
        {
            const size_t eol = headers.find('\n');
            std::string_view line = headers.substr(0, eol);
            headers = eol == std::string_view::npos ? std::string_view{} : headers.substr(eol + 1);
            if (!line.empty() && line.back() == '\r')
                line.remove_suffix(1);
            if (line.empty())
                continue;
            canon.append(line);
            canon.push_back('\n');
        }
        uint8_t h[32];
        char hex[64];
        sha256_of(canon, h);
        hex_encode32(h, hex);
        std::string sts;
        append(sts, {"AWS4-HMAC-SHA256-TRAILER\n", std::string_view(ctx_.amz_date, 16), "\n", std::string_view(ctx_.scope, ctx_.scope_len), "\n",
                     std::string_view(ctx_.prev_signature, 64), "\n", std::string_view(hex, 64)});
        uint8_t mac[32];
        hmac_sha256(as_sv(ctx_.signing_key, 32), {sts}, mac);
        if (CRYPTO_memcmp(mac, claimed, 32) != 0)
            return bad(stream_status::bad_signature);
    }
    state_  = state::finished;
    status_ = stream_status::done;
    return true;
}

std::string_view chunk_stream::trailer_value(std::string_view name) const
{
    if (status_ != stream_status::done)
        return {};
    std::string_view t(trailer_, trailer_len_);
    while (!t.empty())
    {
        size_t eol = t.find('\n');
        if (eol == std::string_view::npos)
            break;
        std::string_view line = t.substr(0, eol);
        t.remove_prefix(eol + 1);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        size_t colon = line.find(':');
        if (colon != std::string_view::npos && ieq(trim(line.substr(0, colon)), name))
            return trim(line.substr(colon + 1));
    }
    return {};
}

feed_result chunk_stream::feed(std::string_view in)
{
    if (status_ != stream_status::need_more)
        return {status_, 0, {}};

    size_t pos = 0;
    while (pos < in.size())
    {
        switch (state_)
        {
        case state::header:
        {
            char c = in[pos++];
            if (hdr_len_ == sizeof(hdr_))
                return {fail(stream_status::malformed), pos, {}};
            hdr_[hdr_len_++] = c;
            if (c == '\n')
            {
                if (hdr_len_ < 2 || hdr_[hdr_len_ - 2] != '\r')
                    return {fail(stream_status::malformed), pos, {}};
                hdr_len_ = static_cast<uint8_t>(hdr_len_ - 2);
                bool ok  = on_header();
                hdr_len_ = 0;
                if (!ok)
                    return {status_, pos, {}};
            }
            break;
        }
        case state::data:
        {
            size_t n = static_cast<size_t>(std::min<uint64_t>(chunk_remaining_, in.size() - pos));
            std::string_view span = in.substr(pos, n);
            if (signed_kind(ctx_.kind))
                hash_update(hash_, span);
            pos += n;
            chunk_remaining_ -= n;
            decoded_ += n;
            if (chunk_remaining_ == 0)
                state_ = state::data_cr;
            return {stream_status::need_more, pos, span};
        }
        case state::data_cr:
            if (in[pos++] != '\r')
                return {fail(stream_status::malformed), pos, {}};
            state_ = state::data_lf;
            break;
        case state::data_lf:
            if (in[pos++] != '\n')
                return {fail(stream_status::malformed), pos, {}};
            if (!on_chunk_end())
                return {status_, pos, {}};
            break;
        case state::trailer:
        {
            char c = in[pos++];
            if (trailer_len_ == sizeof(trailer_))
                return {fail(stream_status::malformed), pos, {}};
            trailer_[trailer_len_++] = c;
            if (c != '\n')
                break;
            // A line ends in CRLF, or in a bare LF that minio-go follows with one CRLF: before its trailer's
            // signature, or as the end of an unsigned trailer.  Otherwise the trailer ends at a CRLF after a CRLF.
            const bool crlf     = trailer_len_ >= 2 && trailer_[trailer_len_ - 2] == '\r';
            const bool after_lf = trailer_len_ >= 3 && trailer_[trailer_len_ - 3] == '\n';
            const bool after_crlf = after_lf && trailer_len_ >= 4 && trailer_[trailer_len_ - 4] == '\r';
            bool blank = crlf && (trailer_len_ == 2 || after_crlf ||
                                  (after_lf && ctx_.kind == payload_kind::streaming_unsigned_trailer));
            if (!blank)
                break;
            if (ctx_.kind == payload_kind::streaming_signed)
            {
                if (trailer_len_ != 2)
                    return {fail(stream_status::malformed), pos, {}};
                state_  = state::finished;
                status_ = stream_status::done;
                return {status_, pos, {}};
            }
            if (!on_trailer())
                return {status_, pos, {}};
            return {status_, pos, {}};
        }
        case state::finished:
            return {status_, pos, {}};
        }
    }
    return {status_, pos, {}};
}

} // namespace socketley::s3
