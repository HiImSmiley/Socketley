#pragma once
// A message's MIME structure, as IMAP tells it: the parts a multipart holds and a message/rfc822 encloses, each part's
// type, parameters and where its header and body lie, and from that the ENVELOPE, BODY and BODYSTRUCTURE of RFC 3501
// and the bytes of a section a FETCH names.  Offsets into the message, so a part is read where it lies.
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace socketley::mail::mime
{

struct part
{
    std::string type{"text"}, subtype{"plain"};
    std::vector<std::pair<std::string, std::string>> params;
    std::string id, description, encoding{"7BIT"}, md5;
    std::string disposition;
    std::vector<std::pair<std::string, std::string>> disposition_params;
    std::string language, location;
    size_t header_off{0}, header_len{0};
    size_t body_off{0}, body_len{0};
    size_t lines{0};
    // A multipart's parts, or the one message a message/rfc822 encloses.
    std::vector<part> children;
    bool multipart() const { return type == "multipart"; }
    bool message() const { return type == "message" && subtype == "rfc822"; }
};

// The structure of `message`, its root the whole of it; a part nested deeper than 32 is taken as text.
part parse(std::string_view message);

// An IMAP string: quoted where it can be, a literal where it holds a line's end or a byte past ASCII, NIL when null.
std::string imap_string(std::string_view s, bool nil_if_empty = true);
// The ENVELOPE of a header block.
std::string envelope(std::string_view headers);
// BODYSTRUCTURE, or BODY without the extension data.
std::string structure(const part& p, std::string_view message, bool extended);
// The bytes of the section `spec` names ("", "1.2", "HEADER", "1.TEXT", "HEADER.FIELDS (FROM TO)", "2.MIME"); false
// when the message has no such section.
bool section(std::string_view message, const part& root, std::string_view spec, std::string& out);
// The same, as `got`: a stretch of `message` where the section is one, else a view of `built`.
bool section_of(std::string_view message, const part& root, std::string_view spec, std::string_view& got,
                std::string& built);

// A part's body with its Content-Transfer-Encoding undone: quoted-printable and base64 decoded, any other as it is.
std::string decoded_body(std::string_view body, std::string_view encoding);
// `text` of `charset` in UTF-8 where the charset is ISO-8859-1, as it is where it is any other.
std::string to_utf8(std::string_view text, std::string_view charset);
// A header's value with its RFC 2047 encoded words decoded where their charset is UTF-8, US-ASCII or ISO-8859-1, and
// the space between two of them dropped; a word of another charset is left as it is.
std::string decode_words(std::string_view value);

}   // namespace socketley::mail::mime
