#pragma once
// Sieve (RFC 5228), the language a user filters the mail delivered to them with, and the extensions ManageSieve
// offers: fileinto, reject and ereject, envelope, encoded-character, imap4flags, copy, vacation and vacation-seconds,
// subaddress, body, relational with i;ascii-numeric, variables, date and mailbox.  A script is compiled once and run
// against each message, which decides the actions and touches nothing itself: the caller files, forwards and answers.
// Every bound a hostile script or message could push on is fixed here, so a run costs at most its step budget.
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace socketley::mail::sieve
{

// What a script is run against.
struct message
{
    // The whole message, header block then body, with CRLF line ends.
    std::string_view bytes;
    // The reverse-path without its brackets, empty for the null sender.
    std::string_view envelope_from;
    // The recipient as RCPT TO named it.
    std::string_view envelope_to;
};

struct context
{
    // The user's own addresses, which vacation looks for among a message's recipients.
    std::vector<std::string> own;
    // Unix time and the local zone's offset in minutes, for currentdate and for the date test's default zone.
    int64_t now_s{0};
    int32_t zone_min{0};
    // Whether a mailbox exists, for mailboxexists; every one does when this is unset.
    std::function<bool(std::string_view folder)> mailbox_exists;
};

// An answer vacation decided to send, the memory of whom was answered within `seconds` being the caller's.
struct vacation
{
    std::string handle, subject, from, reason;
    bool mime{false};
    uint32_t seconds{7 * 86400};
    std::vector<std::string> addresses;
    // Who is answered: the envelope sender.
    std::string to;
};

struct action
{
    enum class kind : uint8_t { keep, fileinto, redirect, discard, reject, vacation };
    kind k{kind::keep};
    // The folder, the address or the reason.
    std::string arg;
    bool copy{false}, create{false}, ereject{false};
    // The imap4flags a keep or a fileinto stores the message with.
    std::vector<std::string> flags;
    std::optional<struct vacation> v;
};

// The actions of a run, the implicit keep among them, and why the run failed where it did.
struct outcome
{
    std::vector<action> actions;
    std::string error;
};

class script
{
public:
    // The script of `text`, or null with `err` saying where it is wrong ("line 3: ...").
    static std::shared_ptr<const script> compile(std::string_view text, std::string& err);
    // What the script decides for `m`; a run that fails has its error set and keeps the message.
    outcome run(const message& m, const context& c) const;

    struct program;
    ~script();

private:
    script();
    std::unique_ptr<program> p_;
};

// The extensions supported, space separated, as ManageSieve's SIEVE capability lists them.
std::string_view extensions();

}   // namespace socketley::mail::sieve
