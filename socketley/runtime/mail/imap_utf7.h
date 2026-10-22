#pragma once
// Mailbox names as IMAP4rev1 writes them, modified UTF-7 (RFC 3501 5.1.3), and as a client that enabled UTF8=ACCEPT
// (RFC 6855) writes them, UTF-8; the index keeps the first, so a folder is one folder whichever a client speaks.
#include <string>
#include <string_view>

namespace socketley::mail::imap_utf7
{

// `utf8` as modified UTF-7; empty where it is not UTF-8.
std::string encode(std::string_view utf8);
// `mutf7` as UTF-8; empty where it is not modified UTF-7.
std::string decode(std::string_view mutf7);

}   // namespace socketley::mail::imap_utf7
