#pragma once
// Sieve (RFC 5228), the language a user filters the mail delivered to them with, and the extensions ManageSieve
// offers: fileinto, reject and ereject, envelope, encoded-character, imap4flags, copy, vacation and vacation-seconds,
// subaddress, body, relational with i;ascii-numeric, variables, date and index, mailbox, regex, editheader,
// duplicate, include, environment, spamtest, spamtestplus and virustest, enotify with mailto, ihave and imapsieve.  A script is
// compiled once and run against each message, which decides the actions and touches nothing itself: the caller
// files, forwards, answers, notifies and keeps what duplicate saw.
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
    // Whether a mailbox exists, for mailboxexists and a fileinto without :create; every one does when this is unset.
    std::function<bool(std::string_view folder)> mailbox_exists;
    // Whether duplicate saw this key within the time it was kept for; none was when this is unset.
    std::function<bool(std::string_view key)> seen;
    // What environment tells: this host's name and domain, and the client the message came from.
    std::string host, domain, remote_host, remote_ip;
    // What a spam and a virus scanner said, 0 where none looked: spamtest 1 to 10, spamtestplus a percentage, and
    // virustest 1 (clean) to 5 (infected).
    int spam{0}, spam_percent{0}, virus{0};
    // A run for what an IMAP client did to a message in a folder (RFC 6785): APPEND, COPY or FLAG, the folder, the
    // user and their address, the flags it changed, and the flags the message has, which imap4flags starts from.
    struct imap_event
    {
        std::string cause, mailbox, user, email, changed;
        std::vector<std::string> flags;
    };
    std::optional<imap_event> imap;
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

// A notification enotify decided to send, by the mailto method (RFC 5436).
struct notification
{
    std::string method, from, importance, message;
    std::vector<std::string> options;
};

struct action
{
    enum class kind : uint8_t { keep, fileinto, redirect, discard, reject, vacation, notify };
    kind k{kind::keep};
    // The folder, the address or the reason.
    std::string arg;
    bool copy{false}, create{false}, ereject{false};
    // The imap4flags a keep or a fileinto stores the message with.
    std::vector<std::string> flags;
    std::optional<struct vacation> v;
    std::optional<notification> n;
};

// The actions of a run, the implicit keep among them, and why the run failed where it did.
struct outcome
{
    std::vector<action> actions;
    std::string error;
    // The header block editheader left, its blank line ending it, where it changed the message's.
    std::optional<std::string> header;
    // What duplicate saw, to be kept for that many seconds once the actions are taken.
    std::vector<std::pair<std::string, uint32_t>> seen;
};

// The text of a script include names, :global or personal; false where there is none.
using loader = std::function<bool(bool global, std::string_view name, std::string& text)>;

class script
{
public:
    // The script of `text`, or null with `err` saying where it is wrong ("line 3: ..."); the scripts it includes
    // are read by `load` and compiled with it, and one not there fails the run that reaches it.
    static std::shared_ptr<const script> compile(std::string_view text, std::string& err, const loader& load = {});
    // The scripts this one included, as `load` was asked for them, so a cache knows what to look at for a change.
    const std::vector<std::pair<bool, std::string>>& included() const;
    // What the script decides for `m`; a run that fails has its error set and keeps the message.
    outcome run(const message& m, const context& c) const;

    struct program;
    ~script();

private:
    script();
    std::unique_ptr<program> p_;
};

// The recipients, subject and body of a mailto URI (RFC 6068) as notify sends to it; false where it names none.
bool parse_mailto(std::string_view uri, std::vector<std::string>& to, std::string& subject, std::string& body);

// The extensions supported, space separated, as ManageSieve's SIEVE capability lists them.
std::string_view extensions();

}   // namespace socketley::mail::sieve
