#pragma once
// The orders IMAP's SORT and THREAD answer in (RFC 5256, with DISPLAYFROM and DISPLAYTO of RFC 5957): what a message
// is ordered by, read from its header once; its base subject, without the Re: and Fwd: a reply adds; the keys a
// client names, each a tie the next breaks and the message's number the last; and threads by subject alone or by
// the References and Message-IDs that tie a reply to what it answers.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace socketley::mail::imap_order
{

struct entry
{
    // What it is answered as, a UID or a sequence number, and its place in the folder.
    uint32_t number{0};
    size_t seq{0};
    int64_t arrival_ms{0};
    uint64_t size{0};
    // The Date header's time, the arrival where it says none that reads.
    int64_t sent_s{0};
    std::string subject;
    // Its subject was a reply's or a forward's, a Re: or a Fwd: taken off it.
    bool reply{false};
    std::string from, to, cc, display_from, display_to;
    std::string message_id;
    std::vector<std::string> references;
};

// The subject with its reply and forward markers taken off, decoded and its white space made single spaces.
std::string base_subject(std::string_view raw, bool* reply = nullptr);
// `e`'s keys from the message's header block.
void read(entry& e, std::string_view header);

struct key
{
    enum class kind : uint8_t { arrival, cc, date, from, size, subject, to, display_from, display_to };
    kind k{kind::arrival};
    bool reverse{false};
};
// SORT's criteria, false for a word that is none or a REVERSE with nothing after it.
bool parse_keys(const std::vector<std::string>& words, std::vector<key>& out);
void sort(std::vector<entry>& v, const std::vector<key>& keys);

// THREAD's answers, the parenthesized threads after "THREAD ".
std::string ordered_subject(std::vector<entry> v);
std::string references(std::vector<entry> v);

}   // namespace socketley::mail::imap_order
