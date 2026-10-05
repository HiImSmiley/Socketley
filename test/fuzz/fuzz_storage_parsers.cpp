// Fuzz target: the storage runtime's parsers of what a client or the disk hands it whole -- an LZ4 block and a
// compressed body's table, a SelectObjectContent request and the records it reads, an ACL document and grant
// headers, and a JWT and the JWK Set it is checked against.
//
// The first input byte picks the parser, and the rest is its input:
//   0  an LZ4 block opened into a buffer of the size the next two bytes say
//   1  a compressed body: a size of two bytes, then the bytes after the header as they lie on disk
//   2  a select: a request document up to the first NUL, then the object's bytes
//   3  an ACL: an AccessControlPolicy document up to the first NUL, then grant headers, one a line
//   4  a token: a JWK Set up to the first NUL, then a JWT
//
// Properties checked, beyond "did it crash":
//   * any bytes compressed open back to themselves, and a block opens to no more than the room it is given;
//   * a select fed its object whole gives the records it gives fed a byte at a time;
//   * an ACL that parses encodes and decodes back to itself, and grants nothing a grantee it does not name.

#include "fuzz_common.h"
#include "runtime/storage/compression.h"
#include "runtime/storage/lz4_block.h"
#include "runtime/storage/s3_acl.h"
#include "runtime/storage/s3_federation.h"
#include "runtime/storage/s3_select.h"

#include <string>
#include <string_view>
#include <vector>

using namespace socketley::storage;

namespace
{

void lz4(std::string_view in)
{
    if (in.size() < 2)
        return;
    const size_t cap = static_cast<size_t>(static_cast<uint8_t>(in[0])) << 8 | static_cast<uint8_t>(in[1]);
    in.remove_prefix(2);
    std::string out(cap, '\0');
    const long n = lz4_decompress(reinterpret_cast<const uint8_t*>(in.data()), in.size(),
                                  reinterpret_cast<uint8_t*>(out.data()), out.size());
    FUZZ_CHECK(n <= static_cast<long>(cap), "a block opened to more than the room it was given");
    std::string packed(lz4_bound(in.size()), '\0');
    packed.resize(lz4_compress(reinterpret_cast<const uint8_t*>(in.data()), in.size(),
                               reinterpret_cast<uint8_t*>(packed.data())));
    FUZZ_CHECK(packed.size() <= lz4_bound(in.size()), "a block compressed past its bound");
    std::string back(in.size(), '\0');
    const long b = lz4_decompress(reinterpret_cast<const uint8_t*>(packed.data()), packed.size(),
                                  reinterpret_cast<uint8_t*>(back.data()), back.size());
    FUZZ_CHECK(b == static_cast<long>(in.size()) && back == in, "bytes compressed did not open back to themselves");
}

void body(std::string_view in)
{
    if (in.size() < 2)
        return;
    object_meta m;
    m.size = static_cast<uint64_t>(static_cast<uint8_t>(in[0])) << 10 | static_cast<uint8_t>(in[1]);
    in.remove_prefix(2);
    // The record says the table follows the chunks, wherever the input puts the end of them.
    const uint64_t chunks = lz4_chunks_of(m.size);
    const uint64_t table  = chunks * 4;
    if (m.size == 0 || in.size() < table)
        return;
    const lz4_record r{in.size() - table, chunks};
    set_lz4_record(m, &r);
    std::string plain;
    if (lz4_open_body(m, in, plain))
        FUZZ_CHECK(plain.size() == m.size, "a compressed body opened to another size than its own");
}

void select(std::string_view in)
{
    const size_t nul = in.find('\0');
    if (nul == std::string_view::npos)
        return;
    select_request req;
    s3_error err;
    if (!parse_select_request(in.substr(0, nul), req, err))
        return;
    const std::string_view object = in.substr(nul + 1);
    select_engine whole, piecewise;
    if (!whole.init(req, err, object.size()) || !piecewise.init(req, err, object.size()))
        return;
    whole.feed(object);
    whole.finish();
    std::string a = whole.take_output();
    std::string b;
    for (size_t i = 0; i < object.size() && !piecewise.done(); ++i)
    {
        piecewise.feed(object.substr(i, 1));
        b += piecewise.take_output();
    }
    piecewise.finish();
    b += piecewise.take_output();
    if (!whole.failed() && !piecewise.failed())
        FUZZ_CHECK(a == b, "a select fed in pieces gave other records than fed whole");
}

void acl(std::string_view in)
{
    const size_t nul = in.find('\0');
    if (nul == std::string_view::npos)
        return;
    acl_resolver res;
    res.has_user      = [](std::string_view id) { return id == "owner" || id == "alice"; };
    res.user_of_email = [](std::string_view e) { return e == "alice@example.org" ? std::string("alice") : std::string(); };
    acl_list a;
    s3_error err;
    if (parse_acl_xml(in.substr(0, nul), "owner", res, a, err))
    {
        acl_list back;
        FUZZ_CHECK(decode_acl(encode_acl(a), back) && back == a, "an ACL did not encode and decode to itself");
        FUZZ_CHECK(acl_grants(a, "mallory", true, true) == 0, "an ACL granted a user it does not name");
        (void)acl_xml(a, [](std::string_view id) { return std::string(id); });
    }
    std::string_view rest = in.substr(nul + 1);
    acl_request rq;
    for (size_t i = 0; i < 5 && !rest.empty(); ++i)
    {
        const size_t nl = rest.find('\n');
        rq.grant[i] = rest.substr(0, nl);
        rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
    }
    acl_list h;
    if (acl_from_request(rq, false, "owner", "owner", res, h, err))
    {
        acl_list back;
        FUZZ_CHECK(decode_acl(encode_acl(h), back) && back == h, "grant headers' ACL did not encode and decode to itself");
    }
    acl_list d;
    if (decode_acl(rest, d))
        (void)encode_acl(d);
}

void token(std::string_view in)
{
    const size_t nul = in.find('\0');
    if (nul == std::string_view::npos)
        return;
    jwks_keys keys;
    std::string why;
    if (!parse_jwks(in.substr(0, nul), keys, why))
        keys = jwks_keys{};
    federation_oidc cfg;
    cfg.issuer = "https://idp.example";
    cfg.clients.push_back("storage");
    oidc_identity id;
    const bool ok = oidc_verify(cfg, keys, in.substr(nul + 1), 1790683200, id, why);
    // Nothing a fuzzer writes is signed by a key it does not hold.
    FUZZ_CHECK(!ok || !keys.keys.empty(), "a token verified with no key to verify it");
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz::set_current(data, size);
    if (size == 0)
        return 0;
    const std::string_view in(reinterpret_cast<const char*>(data) + 1, size - 1);
    switch (data[0] % 5)
    {
        case 0: lz4(in); break;
        case 1: body(in); break;
        case 2: select(in); break;
        case 3: acl(in); break;
        default: token(in); break;
    }
    return 0;
}
