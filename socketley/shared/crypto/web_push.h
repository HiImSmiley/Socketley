#pragma once
// A Web Push message's body encrypted for its subscriber (RFC 8291) in the aes128gcm content coding (RFC 8188): an
// ECDH of a key made for the message and the subscriber's P-256 key, mixed with their auth secret, keys AES-128-GCM
// over the payload, sent as one record behind a header that carries the salt and the message's public key.  JMAP's
// PushSubscription (RFC 8620 7.2) sends its StateChange so where the client gave keys.
#include <string>
#include <string_view>

namespace socketley::crypto::web_push
{

// `payload` encrypted for `ua_public` (the 65-byte uncompressed point) and `auth` (16 bytes) into `out`; false where a
// key is not one or OpenSSL fails.  The payload is one record, so at most 3993 bytes.
bool encrypt(std::string_view payload, std::string_view ua_public, std::string_view auth, std::string& out);

// The same with the message's key pair (32 bytes and its 65-byte point) and the salt (16) given, so a test can check
// a known answer.
bool encrypt_with(std::string_view payload, std::string_view ua_public, std::string_view auth,
                  std::string_view as_private, std::string_view as_public, std::string_view salt, std::string& out);

}   // namespace socketley::crypto::web_push
