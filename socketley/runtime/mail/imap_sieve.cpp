// imapsieve (RFC 6785): the Sieve script a folder's /shared/imapsieve/script names, run for each message a client
// put into that folder or changed the flags of there.  It is run on a thread like a delivery's; what it decides is
// done to the message where it lies: its flags set, a copy filed elsewhere, one sent on, or it taken out of the folder
// where nothing keeps it.  What the script's own actions put into another folder runs no script there.
#include "mail_run.h"

#include <ctime>
#include <set>

#include "imap_store.h"
#include "mail_sieve.h"
#include "mail_sieve_store.h"
#include "../../shared/util/ascii.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/wall_clock.h"

namespace socketley::mail
{

namespace
{

constexpr std::pair<uint8_t, const char*> system_flags[] = {
    {flag_seen, "\\Seen"}, {flag_answered, "\\Answered"}, {flag_flagged, "\\Flagged"},
    {flag_deleted, "\\Deleted"}, {flag_draft, "\\Draft"}};

// What imap4flags' list of flags is in the index: the system flags as bits, the rest as keywords.
uint8_t split_flags(const std::vector<std::string>& flags, std::vector<std::string>& words)
{
    uint8_t bits = 0;
    for (const auto& f : flags)
    {
        bool system = false;
        for (const auto& [bit, name] : system_flags)
            if (socketley::ascii::iequals(f, name))
            {
                bits |= bit;
                system = true;
            }
        if (!system && !f.empty() && f.front() != '\\' &&
            std::none_of(words.begin(), words.end(), [&](const std::string& w) { return socketley::ascii::iequals(w, f); }))
            words.push_back(f);
    }
    return bits;
}

}   // namespace

void mail_run::imap_sieve(const std::string& user, const std::string& folder, std::string cause,
                          std::vector<uint32_t> uids, std::string changed)
{
    imap_store* store = m_imap.get();
    sieve_store* scripts = m_sieve.get();
    if (!store || !scripts || uids.empty())
        return;
    const std::string* named = store->meta(user, folder, "/shared/imapsieve/script");
    if (!named || named->empty())
        return;
    // A bound on the messages one command has filtered.
    if (uids.size() > 1000)
        uids.resize(1000);
    struct job
    {
        std::string user, folder, cause, changed, script;
        std::vector<uint32_t> uids;
        size_t at{0};
        std::shared_ptr<imap_folder> f;
    };
    auto j = std::make_shared<job>();
    j->user = user;
    j->folder = folder;
    j->cause = std::move(cause);
    j->changed = std::move(changed);
    j->script = *named;
    j->uids = std::move(uids);
    auto step = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak = step;
    *step = [this, j, store, scripts, weak, alive = m_alive] {
        auto self = weak.lock();
        if (!*alive || !self || j->at >= j->uids.size())
            return;
        const uint32_t uid = j->uids[j->at++];
        const imap_message* m = j->f->by_uid(uid);
        if (!m)
            return (*self)();
        sieve::context ctx;
        ctx.now_s = wall::now_ms() / 1000;
        std::tm tm{};
        const time_t now = static_cast<time_t>(ctx.now_s);
        if (::localtime_r(&now, &tm))
            ctx.zone_min = static_cast<int32_t>(tm.tm_gmtoff / 60);
        ctx.host = m_hostname;
        ctx.domain = m_domains.empty() ? std::string() : m_domains.front();
        const std::string own = j->user.find('@') != std::string::npos || ctx.domain.empty() ? j->user
                                                                                             : j->user + "@" + ctx.domain;
        ctx.own.push_back(own);
        sieve::context::imap_event ev{j->cause, j->folder, j->user, own, j->changed, {}};
        for (const auto& [bit, name] : system_flags)
            if (m->flags & bit)
                ev.flags.emplace_back(name);
        ev.flags.insert(ev.flags.end(), m->keywords.begin(), m->keywords.end());
        ctx.imap = std::move(ev);
        const std::vector<std::string> known = store->folder_names(j->user);
        auto names = std::make_shared<const std::set<std::string>>(known.begin(), known.end());
        ctx.mailbox_exists = [names](std::string_view f) {
            return socketley::ascii::iequals(f, "INBOX") || names->count(std::string(f)) > 0;
        };
        ctx.seen = [scripts, user = j->user, now_s = ctx.now_s](std::string_view key) {
            return scripts->seen(user, key, now_s);
        };
        store->body(m->key, m->size, [this, j, self, scripts, uid, ctx = std::move(ctx), own, alive = m_alive](
                                         std::shared_ptr<const std::string> bytes) mutable {
            if (!*alive)
                return;
            if (!bytes)
                return (*self)();
            auto out = std::make_shared<sieve::outcome>();
            m_pool.submit(
                cpu_lane(),
                [scripts, j, bytes, out, ctx = std::move(ctx)] {
                    const auto script = scripts->named(j->user, j->script);
                    if (!script)
                    {
                        out->error = "the script " + j->script + " is not there or does not compile";
                        return;
                    }
                    *out = script->run(sieve::message{*bytes, {}, {}}, ctx);
                },
                [this, j, self, uid, bytes, out, own, alive] {
                    if (!*alive)
                        return;
                    imap_sieve_apply(j->user, j->f, uid, *bytes, *out, own);
                    (*self)();
                });
        });
    };
    store->open(user, folder, [j, step, alive = m_alive](std::shared_ptr<imap_folder> f) {
        if (!*alive || !f)
            return;
        j->f = std::move(f);
        (*step)();
    });
}

void mail_run::imap_sieve_apply(const std::string& user, const std::shared_ptr<imap_folder>& f, uint32_t uid,
                                std::string_view bytes, const sieve::outcome& out, const std::string& own)
{
    imap_store* store = m_imap.get();
    if (!store)
        return;
    if (!out.error.empty())
    {
        LOG_WARN(("mail: the imapsieve script of " + user + "'s " + f->name + " failed, and the message stays as it is: " +
                  out.error)
                     .c_str());
        return;
    }
    bool kept = false;
    std::vector<std::pair<std::string, std::vector<std::string>>> filed;
    for (const auto& a : out.actions)
        switch (a.k)
        {
            case sieve::action::kind::keep:
            {
                kept = true;
                // The flags the script left are the message's from now on.
                std::vector<std::string> words;
                const uint8_t bits = split_flags(a.flags, words);
                if (const imap_message* m = f->by_uid(uid); m && (m->flags != bits || m->keywords != words))
                    store->set_flags(user, f, {uid}, [bits](uint8_t) { return bits; },
                                     keyword_change{keyword_change::kind::set, std::move(words)});
                break;
            }
            case sieve::action::kind::fileinto:
                if (a.arg != f->name && !(socketley::ascii::iequals(a.arg, "INBOX") &&
                                          socketley::ascii::iequals(f->name, "INBOX")) &&
                    (a.create || !store->mailbox_id(user, a.arg).empty() || socketley::ascii::iequals(a.arg, "INBOX")))
                    filed.emplace_back(a.arg, a.flags);
                else
                    kept = true;   // A fileinto that files nowhere leaves the message where it is.
                break;
            case sieve::action::kind::redirect:
                queue_message(own, {a.arg}, "Delivered-To: " + own + "\r\n" + std::string(bytes), false, {},
                              [](bool, std::string) {});
                break;
            default:
                break;
        }
    // The copies are made first, and the message leaves its folder only once they are all in, where nothing kept it.
    auto left = std::make_shared<size_t>(filed.size() + 1);
    auto failed = std::make_shared<bool>(false);
    const auto one_done = [this, user, f, uid, kept, left, failed, alive = m_alive] {
        if (!*alive || --*left != 0 || kept || *failed)
            return;
        if (imap_store* s = m_imap.get())
            s->expunge(user, f, {uid}, true, [](std::vector<uint32_t>) {});
    };
    for (auto& [to, flags] : filed)
    {
        if (!store->mailbox_id(user, to).empty() || store->create(user, to)) {}
        store->copy(user, f, {uid}, to, true,
                    [this, user, to, flags, one_done, failed, alive = m_alive](bool ok, uint32_t,
                                                                               std::vector<uint32_t> made) {
                        if (!*alive)
                            return;
                        *failed = *failed || !ok;
                        imap_store* s = m_imap.get();
                        // A fileinto with :flags gives the copy those flags.
                        if (ok && s && !flags.empty() && !made.empty())
                            s->open(user, to, [this, user, flags, made, one_done, alive](std::shared_ptr<imap_folder> t) {
                                if (!*alive)
                                    return;
                                if (t)
                                    if (imap_store* s2 = m_imap.get())
                                    {
                                        std::vector<std::string> words;
                                        const uint8_t bits = split_flags(flags, words);
                                        s2->set_flags(user, t, made, [bits](uint8_t) { return bits; },
                                                      keyword_change{keyword_change::kind::set, std::move(words)});
                                    }
                                one_done();
                            });
                        else
                            one_done();
                    });
    }
    one_done();
}

}   // namespace socketley::mail
