#pragma once
// Text found in a message as IMAP SEARCH and JMAP's filters look for it: the header as written and with its encoded
// words decoded, the text parts as written and with their transfer encoding and charset undone, and nothing of a part
// that is not text, an attachment.  A filter of each message's trigrams says which messages cannot hold a string, so a
// search reads only those that may.
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "mail_mime.h"

namespace socketley::mail
{

// Whether `hay` holds `needle`, letters of either case alike.
bool contains_ci(std::string_view hay, std::string_view needle);
// Whether a header of `head` named `name`, any header where `name` is empty, holds `needle` as written or decoded; every
// header of the name, not only the first (RFC 3501 6.4.4).
bool header_has(std::string_view head, std::string_view name, std::string_view needle);
// Whether the body of `msg`, whose header is `head` and whose structure is `root` where it was parsed, holds `needle`.
bool body_has(std::string_view msg, std::string_view head, const mime::part* root, std::string_view needle);
// Whether its header or its body holds `needle`.
bool text_has(std::string_view msg, std::string_view head, const mime::part* root, std::string_view needle);

// A message's trigram filter, of every string the functions above can find in it.
std::string text_filter(std::string_view msg, std::string_view head, const mime::part* root);
// Whether a message whose filter is `filter` may hold `needle`: false only where it cannot.
bool may_hold(std::string_view filter, std::string_view needle);
// A needle's trigrams hashed once, for the filters of the many messages a search tries it on.
std::vector<uint64_t> trigrams_of(std::string_view needle);
// Each text part of `msg`, whose structure is `root`, with its transfer encoding and charset undone.
void each_text(std::string_view msg, const mime::part& root,
               const std::function<void(const std::string& text, const mime::part& part)>& take);
// Whether a message whose filter is `filter` may hold the needle whose trigrams are `grams`.
bool may_hold(std::string_view filter, const std::vector<uint64_t>& grams);

}   // namespace socketley::mail
