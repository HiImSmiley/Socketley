// JMAP push (RFC 8620 7.2): each second the users with a PushSubscription have their states looked at, by the one
// shard their name falls to, and a StateChange is posted to every verified, unexpired subscription whose types
// changed; a push goes from the pool, over HTTPS to a public address alone, encrypted (RFC 8291) where the client
// gave keys.
#include "mail_run.h"

#include <ctime>

#include <sys/stat.h>

#include "imap_store.h"
#include "jmap_session.h"
#include "mail_instance.h"
#include "../../shared/crypto/web_push.h"
#include "../../shared/http/https_client.h"
#include "../../shared/json/json_doc.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/util/base64.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/settings.h"
#include "../../shared/util/wall_clock.h"

namespace socketley::mail
{

void mail_run::push_send(const std::string& url, const std::string& p256dh, const std::string& auth, std::string body)
{
    const char* ca = settings::text("SOCKETLEY_MAIL_PUSH_CA");
    const char* to = settings::text("SOCKETLEY_MAIL_PUSH_CONNECT");
    auto ok = std::make_shared<bool>(false);
    m_pool.submit(
        0,
        [url, p256dh, auth, body = std::move(body), ok, ca = std::string(ca ? ca : ""), to = std::string(to ? to : "")] {
            std::string why, payload = body;
            std::vector<std::pair<std::string, std::string>> headers = {{"TTL", "86400"}};
            std::string type = "application/json";
            if (!p256dh.empty())
            {
                if (!socketley::crypto::web_push::encrypt(body, p256dh, auth, payload))
                    return;
                headers.emplace_back("Content-Encoding", "aes128gcm");
                type = "application/octet-stream";
            }
            https_client::client cl;
            if (!cl.init(why, ca))
                return;
            if (!to.empty())
                cl.connect_to(to);
            // The URL is a client's to name anywhere, so it is dialled only where it is public.
            cl.public_only(true);
            https_client::reply rep;
            *ok = cl.request("POST", url, type, payload, rep, why, 10, 65536, headers) && rep.status / 100 == 2;
        },
        [this, ok, alive = m_alive] {
            if (!*alive)
                return;
            ++(*ok ? m_pushes_sent : m_pushes_failed);
        });
}

namespace
{

// When a subscription stops taking pushes: its expiry if the push service proved it reads the URL, else at once.
int64_t live_until(const socketley::json::jvalue& sub)
{
    const auto* verified = socketley::json::member(sub, "verified");
    if (!verified || verified->k != socketley::json::jvalue::kind::boolean || !verified->b)
        return 0;
    std::tm tm{};
    const std::string ex(socketley::json::string_of(sub, "expires"));
    return ::strptime(ex.c_str(), "%Y-%m-%dT%H:%M:%S", &tm) ? static_cast<int64_t>(::timegm(&tm)) * 1000 : 0;
}

// A user's kept PushSubscriptions, null where there are none.
const socketley::json::jvalue* subscriptions(imap_store& store, const std::string& user, socketley::json::jvalue& entry)
{
    const std::string* kept = store.meta(user, {}, std::string(jmap_session::push_entry));
    if (!kept || !socketley::json::json_reader(*kept).document(entry))
        return nullptr;
    const auto* subs = socketley::json::member(entry, "subs");
    return subs && subs->k == socketley::json::jvalue::kind::array ? subs : nullptr;
}

}   // namespace

void mail_run::push_tick()
{
    if (!m_imap)
        return;
    const size_t shards = std::max<size_t>(1, m_owner.get_shards());
    const auto mine = [&](const std::string& user) {
        uint64_t h = 1469598103934665603ull;
        for (const unsigned char c : user)
            h = (h ^ c) * 1099511628211ull;
        return shards <= 1 || h % shards == shard();
    };
    // The list is read again only when it changed, and every PushSubscription/set writes it, so how long each of this
    // shard's users has a subscription to push to is read then, and a user with none has its index left alone.
    struct stat st{};
    const std::string list = m_imap->list_path(".push-users");
    const bool there = ::stat(list.c_str(), &st) == 0;
    const int64_t mtime = there ? static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec : 0;
    const int64_t size = there ? static_cast<int64_t>(st.st_size) : -1;
    if (mtime != m_push_list_mtime || size != m_push_list_size)
    {
        m_push_list_mtime = mtime;
        m_push_list_size = size;
        m_push_live.clear();
        for (const auto& user : m_imap->push_users())
        {
            if (!mine(user))
                continue;
            m_imap->refresh(user);
            socketley::json::jvalue entry;
            int64_t until = 0;
            if (const auto* subs = subscriptions(*m_imap, user, entry))
                for (const auto& sub : subs->items)
                    until = std::max(until, live_until(sub));
            m_push_live[user] = until;
        }
    }
    const int64_t now = wall::now_ms();
    for (const auto& [user, until] : m_push_live)
    {
        // A user's next look after a time with nothing to push to begins from the states last set, as a first does.
        if (until <= now)
        {
            m_push_seen.erase(user);
            continue;
        }
        const std::string es = jmap_session::email_state(*m_imap, user), ms = jmap_session::mailbox_state(*m_imap, user);
        socketley::json::jvalue entry;
        const auto* subs_v = subscriptions(*m_imap, user, entry);
        if (!subs_v)
            continue;
        const auto& subs = *subs_v;
        // A shard's first look begins from the states the subscriptions were last set at, so what came between
        // their making and this look is told too.
        auto& seen = m_push_seen[user];
        if (seen.empty())
            seen = std::string(socketley::json::string_of(entry, "state"));
        if (seen == es + " " + ms)
            continue;
        const bool email = seen.substr(0, seen.find(' ')) != es, mailbox = seen.substr(seen.find(' ') + 1) != ms;
        seen = es + " " + ms;
        std::string changed;
        const auto add = [&](std::string_view type, const std::string& state) {
            changed += std::string(changed.empty() ? "" : ",") + socketley::json::quote(type) + ":" +
                       socketley::json::quote(state);
        };
        for (const auto& sub : subs.items)
        {
            if (live_until(sub) <= now)
                continue;
            // Only the types the subscription asked for, every one where it named none.
            const auto* types = socketley::json::member(sub, "types");
            const auto wants = [&](std::string_view t) {
                if (!types || types->k != socketley::json::jvalue::kind::array)
                    return true;
                for (const auto& x : types->items)
                    if (x.s == t || x.s == "*")
                        return true;
                return false;
            };
            changed.clear();
            if (email && wants("Email"))
                add("Email", es);
            if (email && wants("Thread"))
                add("Thread", es);
            if (mailbox && wants("Mailbox"))
                add("Mailbox", ms);
            if (changed.empty())
                continue;
            std::string p256dh, auth;
            socketley::base64url::decode(socketley::json::string_of(sub, "p256dh"), p256dh);
            socketley::base64url::decode(socketley::json::string_of(sub, "auth"), auth);
            push_send(std::string(socketley::json::string_of(sub, "url")), p256dh, auth,
                      "{\"@type\":\"StateChange\",\"changed\":{" + socketley::json::quote(jmap_session::account_of(user)) +
                          ":{" + changed + "}}}");
        }
    }
}

}   // namespace socketley::mail
