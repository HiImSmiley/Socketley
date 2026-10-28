#pragma once
// A message written from its parts, as `socketley send`, a script and a notification ask for one: headers encoded by
// RFC 2047 where they are not ASCII, text as quoted-printable, an HTML part beside it, attachments in base64.  And the
// reading of a message's headers back, which a bounce, DKIM and IMAP's ENVELOPE need.
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "mail_command.h"
#include "smtp_session.h"

namespace socketley::mail
{

// The Date of RFC 5322, in UTC.
std::string rfc5322_date(int64_t unix_ms);

// "Name <a@b>", "<a@b>" or "a@b": the address, and the name where one is given.
bool parse_mailbox(std::string_view in, address& out, std::string* display = nullptr);
// A list of those, separated by commas outside quotes and brackets.
bool parse_mailbox_list(std::string_view in, std::vector<address>& out);

// A header's value encoded as RFC 2047 encoded words where it is not printable ASCII, folded under 78 columns.
std::string encode_header_value(std::string_view name, std::string_view value);
std::string quoted_printable(std::string_view text);
// Base64 in lines of 76 characters, each ended by CRLF.
std::string base64_lines(std::string_view data);
// Every line ended by CRLF, a bare LF or a CR alone included.
std::string crlf_lines(std::string_view text);

struct composed
{
    std::string from;
    std::vector<std::string> rcpts;
    std::string message;
};

// `c` written as a message from `from` (the address, its display name in `from_name`), with `msgid` and `now`; false
// with `why` when a recipient or the sender is no address.
bool compose_message(const compose& c, const address& from, std::string_view from_name, std::string_view msgid,
                     int64_t now_ms, composed& out, std::string& why);

// The header block of a message, up to and with the empty line that ends it; the whole of it when there is none.
std::string_view header_block(std::string_view message);
// The value of the first header named `name`, unfolded, without its leading space; empty when absent.
std::string header_value(std::string_view headers, std::string_view name);
// Each header as name and raw value (folding kept), in order.
std::vector<std::pair<std::string_view, std::string_view>> split_headers(std::string_view headers);
// How many From headers a block has, each name trimmed as header_value reads it and a bare LF ending a line as some
// readers take it, with header_value's value in `first`; the one place DMARC, submission and signing count them.
size_t from_headers(std::string_view headers, std::string* first = nullptr);
// Whether a submitted header block's From names only addresses `own` takes: true where there is no From, false for two
// or for one that does not read; SMTP submission and JMAP's EmailSubmission both ask it.
bool authors_owned(std::string_view headers, const std::function<bool(const address&)>& own);

}   // namespace socketley::mail
