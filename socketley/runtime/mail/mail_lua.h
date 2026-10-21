#pragma once
// A mail runtime's script: on_rcpt(rcpt, default) decides a recipient as it is said, true taking it (one no mailbox
// has is then the script's alone) and false refusing it, nil keeping the default; on_message(msg) is told each
// message taken.
#include <functional>
#include <string>
#include <vector>

#include "mail_spool.h"

class mail_instance;

namespace socketley::mail
{

class mail_lua
{
public:
    explicit mail_lua(mail_instance& owner) : m_owner(owner) {}

    bool wants_rcpt() const;
    // `done(take)` with the script's answer, `fallback` when it has none.
    void rcpt(const std::string& to, const std::string& from, const std::string& peer, const std::string& user,
              bool fallback, std::function<void(bool)> done);
    void message(const spool_entry& e);

private:
    mail_instance& m_owner;
};

}   // namespace socketley::mail
