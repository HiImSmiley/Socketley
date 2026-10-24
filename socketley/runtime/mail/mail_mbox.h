#pragma once
// A mailbox as mbox (mboxrd): what `socketley mail export` writes of a folder, a file of its messages each after a
// "From " line, and what `import` reads back, its own files and those Thunderbird or Google Takeout write.  The flags
// travel as mutt's Status and X-Status, keywords as Dovecot's X-Keywords, and a Takeout's labels say the folder.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace socketley::mail::mbox
{

// A message as an mbox holds it: its "From " line with the internal date, its flags and keywords as headers, lines
// that end in LF and those that begin with ">*From " given one '>' more.
std::string entry(std::string_view message, uint8_t flags, const std::vector<std::string>& keywords, int64_t date_ms);

struct message
{
    // Lines ending in CRLF, the headers that carried flags, keywords and labels taken out.
    std::string bytes;
    uint8_t flags{0};
    std::vector<std::string> keywords;
    // From the "From " line, 0 where it says none.
    int64_t date_ms{0};
    // The folder X-Gmail-Labels names, empty where it has none.
    std::string folder;
};

// The next message of `text` from `at`, `at` moved past it; false where none begins there, or where its end may lie
// past what is read and `whole` says more is to come.
bool next(std::string_view text, size_t& at, bool whole, message& out);

// The folder a Takeout's labels put a message in, and its flags, from X-Gmail-Labels' value.
std::string folder_of_labels(std::string_view labels, uint8_t& flags);

}   // namespace socketley::mail::mbox
