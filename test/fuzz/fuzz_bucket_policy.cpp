// Fuzz target: a storage bucket's policy, the JSON reader and the compiler behind PutBucketPolicy
// (socketley/runtime/storage/bucket_policy.h).
//
// Reachable by any holder of an access key, who can put any bytes as a policy, and by whoever can write the
// bucket's directory, since a stored policy is compiled again at every start.
//
// The input is the document, compiled for the bucket "pub".
//
// Properties checked, beyond "did it crash":
//   * compiling is deterministic: the same bytes give the same verdict, error and judgements twice;
//   * a refusal is 400 MalformedPolicy with a message, and anything over 20 KiB is refused;
//   * an accepted document is kept byte for byte and is valid UTF-8, since GetBucketPolicy hands it back as JSON;
//   * the flags the runtime skips work by hold: a policy without has_deny() never denies, so a signed request may
//     skip it, and one without needs_ip() judges a request the same whatever its address, so getpeername may be skipped;
//   * a policy GetBucketPolicyStatus calls not public lets no anonymous request in that has no address to be judged by;
//   * a refusing policy, what a stored document that stops compiling becomes, denies every request;
//   * a part or a completion of an upload, which takes the encryption its creation chose, is judged as though
//     no statement conditioned on the encryption were there, so changing its header changes nothing.
//
// WHAT THIS TARGET DOES NOT COVER: the order the runtime applies a verdict in (authentication, policy, on_request),
// which the integration test reads off the wire, and whether a policy means what its author wanted.

#include "fuzz_common.h"
#include "runtime/storage/bucket_policy.h"

#include <arpa/inet.h>

#include <array>
#include <string>
#include <string_view>

namespace sp = socketley::storage;

namespace {

bool valid_utf8(std::string_view s)
{
    size_t i = 0;
    while (i < s.size())
    {
        const auto c = static_cast<unsigned char>(s[i]);
        size_t n = c < 0x80 ? 0 : c >= 0xC2 && c <= 0xDF ? 1 : c >= 0xE0 && c <= 0xEF ? 2 : c >= 0xF0 && c <= 0xF4 ? 3 : 9;
        if (n == 9 || i + n >= s.size() + (n == 0 ? 1 : 0))
            return false;
        uint32_t cp = n == 0 ? c : n == 1 ? (c & 0x1Fu) : n == 2 ? (c & 0x0Fu) : (c & 0x07u);
        for (size_t k = 1; k <= n; ++k)
        {
            const auto b = static_cast<unsigned char>(s[i + k]);
            if ((b & 0xC0) != 0x80)
                return false;
            cp = (cp << 6) | (b & 0x3Fu);
        }
        if ((n == 2 && cp < 0x800) || (n == 3 && cp < 0x10000) || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
            return false;
        i += n + 1;
    }
    return true;
}

sp::client_ip ip_of(const char* text)
{
    sp::client_ip ip;
    if (::inet_pton(AF_INET, text, ip.addr) == 1)
        ip.family = 4;
    else if (::inet_pton(AF_INET6, text, ip.addr) == 1)
        ip.family = 6;
    return ip;
}

constexpr std::array<std::string_view, 7> keys = {"", "public/a", "private/b", "v1/x", "zz/q", "a*b?c", "public/"};
constexpr std::array<std::string_view, 3> principals = {"AKIAPOLICYKEYONE0001", "AKIAPOLICYKEYTWO0002", "other"};
constexpr std::array<std::string_view, 4> methods = {"AES256", "aws:kms", "", "aes256"};

// Every judgement a fixed set of requests gets, packed two bits each.
std::string judgements(const sp::bucket_policy& p, uint64_t pick)
{
    static const std::array<sp::client_ip, 4> ips = {sp::client_ip{}, ip_of("127.0.0.1"), ip_of("10.1.2.3"), ip_of("::1")};
    std::string out;
    for (int a = 1; a < static_cast<int>(sp::s3_action::count); ++a)
    {
        for (int i = 0; i < 4; ++i)
        {
            pick = pick * 6364136223846793005ull + 1442695040888963407ull;
            sp::policy_request r;
            r.action    = static_cast<sp::s3_action>(a);
            r.key       = keys[(pick >> 33) % keys.size()];
            r.anonymous = (pick >> 40) & 1;
            r.principal = r.anonymous ? std::string_view() : principals[(pick >> 41) % principals.size()];
            r.tls       = (pick >> 45) & 1;
            const sp::client_ip& ip = ips[(pick >> 46) % ips.size()];
            r.ip        = (pick >> 48) & 1 ? nullptr : &ip;
            r.every_key = r.action == sp::s3_action::delete_object && ((pick >> 49) & 1);
            r.sse_sent  = (pick >> 50) & 1;
            r.sse       = r.sse_sent ? methods[(pick >> 51) % methods.size()] : std::string_view();
            r.sse_inherited = r.action == sp::s3_action::put_object && ((pick >> 54) & 1);
            const sp::policy_effect e = p.evaluate(r);
            if (r.sse_inherited)
                for (const std::string_view m : methods)
                {
                    sp::policy_request q = r;
                    q.sse_sent = !m.empty();
                    q.sse      = m;
                    FUZZ_CHECK(p.evaluate(q) == e, "a part was judged by the encryption header it does not choose");
                }
            out += static_cast<char>('0' + static_cast<int>(e));

            if (!p.has_deny())
                FUZZ_CHECK(e != sp::policy_effect::deny, "a policy without a Deny denied");
            if (!p.needs_ip())
                for (const sp::client_ip& other : ips)
                {
                    sp::policy_request q = r;
                    q.ip = &other;
                    FUZZ_CHECK(p.evaluate(q) == e, "a policy that names no address judged by one");
                }
            if (!p.broken().empty())
                FUZZ_CHECK(e == sp::policy_effect::deny, "a refusing policy let a request through");
            if (!p.is_public() && r.anonymous && !r.ip)
                FUZZ_CHECK(e != sp::policy_effect::allow, "a policy that is not public let in an anonymous request");
        }
    }
    return out;
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz::set_current(data, size);
    const std::string_view doc(reinterpret_cast<const char*>(data), size);

    sp::bucket_policy p;
    sp::s3_error err;
    const bool ok = sp::bucket_policy::compile(doc, "pub", p, err);

    sp::bucket_policy again;
    sp::s3_error err2;
    FUZZ_CHECK(sp::bucket_policy::compile(doc, "pub", again, err2) == ok, "two compiles disagree");
    FUZZ_CHECK(err2.code == err.code && err2.message == err.message, "two compiles refuse differently");

    if (!ok)
    {
        FUZZ_CHECK(err.code == "MalformedPolicy", "a refusal that is not MalformedPolicy");
        FUZZ_CHECK(err.status == 400, "a refusal that is not 400");
        FUZZ_CHECK(!err.message.empty(), "a refusal without a message");
        const sp::bucket_policy refusing = sp::bucket_policy::refusing(doc, err.message);
        FUZZ_CHECK(refusing.text() == doc, "a refusing policy lost the stored text");
        FUZZ_CHECK(refusing.has_deny() && !refusing.is_public() && !refusing.broken().empty(), "a refusing policy's flags");
        static_cast<void>(judgements(refusing, size));
        return 0;
    }

    FUZZ_CHECK(size <= sp::policy_max_bytes, "a document over the limit was accepted");
    FUZZ_CHECK(p.text() == doc, "the accepted document was not kept as given");
    FUZZ_CHECK(p.broken().empty(), "an accepted document is refusing");
    FUZZ_CHECK(valid_utf8(doc), "an accepted document is not UTF-8");
    const uint64_t seed = 0x9E3779B97F4A7C15ull ^ size;
    FUZZ_CHECK(judgements(p, seed) == judgements(again, seed), "two compiles judge differently");
    return 0;
}
