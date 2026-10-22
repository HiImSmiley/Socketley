#pragma once
// A message scored by Rspamd before it is taken: its HTTP protocol (POST /checkv2, the envelope in headers), the
// score, the score its rules reject at, and the action they name.  Blocking, so it runs on a check lane beside SPF and
// DKIM; a scanner that does not answer leaves the message unscored, never refused.
#include <string>
#include <string_view>
#include <vector>

namespace socketley::mail
{

struct spam_verdict
{
    bool scored{false};
    double score{0}, required{0};
    // no action, greylist, add header, rewrite subject, soft reject or reject.
    std::string action;
    std::string why;
    // spamtest's 1 to 10 and spamtestplus's percentage (RFC 5235), 0 where it was not scored.
    int level() const;
    int percent() const;
};

spam_verdict rspamd_check(const std::string& url, std::string_view message, const std::string& ip,
                          const std::string& helo, const std::string& from, const std::vector<std::string>& rcpts,
                          const std::string& user, int timeout_s = 10);

// The value of `key` in the top level of a JSON object, as its text: a number's digits, a string's contents without
// its quotes; empty where the object has no such member.
std::string json_member(std::string_view json, std::string_view key);

}   // namespace socketley::mail
