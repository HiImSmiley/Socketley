// Fuzz target: the OpenSSH key and certificate reader (socketley/shared/crypto/ssh_cert.h), which an idp with
// --ssh-ca runs on every public key a signed-in person sends it to certify.
//
// The first input byte picks what the rest is: even a certificate blob, odd an authorized_keys line.
//
// Properties checked, beyond "did it crash":
//   * a certificate read whole was read from every byte of its input, the signed part a prefix of it;
//   * a key line read writes back to a line that reads to the same key.
//
// WHAT THIS TARGET DOES NOT COVER: the signature's mathematics, which OpenSSL owns, and the idp's checks of the
// account and the token before a key is read.

#include "fuzz_common.h"
#include "shared/crypto/ssh_cert.h"

#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    data = ::fuzz::never_null(data);
    ::fuzz::set_current(data, size);
    if (size < 1 || size > 64 * 1024)
        return 0;
    const std::string_view in(reinterpret_cast<const char*>(data) + 1, size - 1);
    std::string why;
    if ((data[0] & 1) == 0)
    {
        socketley::ssh::cert c;
        if (socketley::ssh::parse_cert(in, c, why))
        {
            FUZZ_CHECK(in.starts_with(c.signed_part), "the signed part is not the front of the certificate");
            FUZZ_CHECK(c.signed_part.size() < in.size(), "a certificate with no signature after its signed part");
            socketley::ssh::verify_cert(c);
        }
        else
            FUZZ_CHECK(!why.empty(), "a certificate refused without saying why");
        return 0;
    }
    socketley::ssh::public_key k;
    if (!socketley::ssh::parse_public_key(in, k, why))
        return 0;
    socketley::ssh::public_key again;
    FUZZ_CHECK(socketley::ssh::parse_public_key(socketley::ssh::line_of(k.blob, k.comment), again, why),
               "a key read does not read again from the line it writes");
    FUZZ_CHECK(again.blob == k.blob && again.type == k.type, "a key written and read again is another key");
    socketley::ssh::fingerprint(k.blob);
    return 0;
}
