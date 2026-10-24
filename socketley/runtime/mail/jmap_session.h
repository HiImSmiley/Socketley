#pragma once
// JMAP (RFC 8620) for mail (RFC 8621) over one HTTP/1.1 connection without a socket: the session resource, the API
// with its methods for Mailbox, Email, Thread, Identity and EmailSubmission, uploads and downloads of blobs, and an
// EventSource that tells of state changes.  A user signs in with HTTP Basic or an idp bearer token on each request;
// their account is their mailboxes as the IMAP index keeps them, so a client of either sees what the other did.
// Mailbox ids are MAILBOXIDs and Email ids EMAILIDs (RFC 8474), each Email its own Thread, and a state is a digest of
// the index, the same on every shard, so */changes says cannotCalculateChanges whenever it is not the client's.
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "imap_store.h"
#include "mail_account.h"
#include "../../shared/json/json_doc.h"

namespace socketley::mail
{

struct jmap_config
{
    std::string hostname;
    bool tls_active{false};
    // A password may go in the clear: this machine's own client.
    bool login_in_clear{false};
    // The largest upload, and the largest message an Email/set or an import makes.
    uint64_t max_size{25ull << 20};
    // The port the entrance reaches on 127.0.0.1: the webmail page at /, the idp's session cookie, and the client and
    // scheme the entrance forwards.
    bool web{false};
};

class jmap_session
{
public:
    struct hooks
    {
        virtual ~hooks() = default;
        virtual void reply(std::string_view bytes) = 0;
        virtual void close() = 0;
        virtual void login(std::string user, std::string password, std::function<void(account, std::string)> done) = 0;
        // An idp bearer token, the user it was given to.
        virtual void bearer(std::string token, std::function<void(account, std::string)> done) = 0;
        // The user the idp's session cookie among a request's Cookie fields names.
        virtual void cookie(std::string /*cookies*/, std::function<void(account, std::string)> done)
        {
            done(account::no, {});
        }
        // Where a browser signs in at the idp, or out, and is sent back to `back`; empty without one.
        virtual std::string idp_login(const std::string& /*back*/) { return {}; }
        virtual std::string idp_logout(const std::string& /*back*/) { return {}; }
        // The client the entrance forwards, whose failed sign-ins count against it.
        virtual void forward(std::string /*client*/) {}
        // An advertisement's recipient unsubscribed by the token its link carries, false where the token is none.
        virtual bool unsubscribe(const std::string& /*token*/) { return false; }
        // The address a signed-in user sends as.
        virtual std::string address_of(const std::string& user) = 0;
        // A message queued to go from `from` to `rcpts`, answered with its spool id.
        virtual void submit(const std::string& user, const std::string& from, std::vector<std::string> rcpts,
                            std::string message, std::function<void(bool, std::string)> done) = 0;
        // What was put into a folder, for imapsieve.
        virtual void acted(const std::string& /*user*/, const std::string& /*folder*/, std::string /*cause*/,
                           std::vector<uint32_t> /*uids*/) {}
        // A push to a PushSubscription's URL, encrypted for its keys where they are given (RFC 8620 7.2).
        virtual void push(const std::string& /*url*/, const std::string& /*p256dh*/, const std::string& /*auth*/,
                          std::string /*body*/) {}
    };

    jmap_session(const jmap_config& cfg, hooks& h, imap_store& store);
    ~jmap_session();
    jmap_session(const jmap_session&)            = delete;
    jmap_session& operator=(const jmap_session&) = delete;

    void input(std::string_view bytes);
    // An EventSource looked at, once a second: a state change told, and a ping where one is due.
    void poll();
    bool streaming() const { return m_stream; }
    size_t buffered() const { return m_in.size(); }

    static constexpr size_t max_head = 16u << 10;
    static constexpr size_t max_request = 10u << 20;

    // The account id of a user, their name in base64url, and back.
    static std::string account_of(const std::string& user);
    // The state of a user's Emails and of their Mailboxes as the index has them now.
    static std::string email_state(imap_store& store, const std::string& user);
    // Where a user's VacationResponse is kept: a server entry of their METADATA, as JSON.
    static constexpr std::string_view vacation_entry = "/private/vendor/socketley/vacation";
    // And their PushSubscriptions, {"state": the states when they last changed, "subs": [...]}, at most 50.
    static constexpr std::string_view push_entry = "/private/vendor/socketley/push";
    // And what they set of their one Identity: its name, replyTo, bcc and signatures.
    static constexpr std::string_view identity_entry = "/private/vendor/socketley/identity";
    static std::string mailbox_state(imap_store& store, const std::string& user);

    struct request
    {
        std::string method, target, path, query;
        std::vector<std::pair<std::string, std::string>> headers;
        std::string body;
        bool keep_alive{true};
        std::string header(std::string_view name) const;
    };
    // One call of the API, done with its answers: one or more, each a method name and its arguments as JSON.
    using answer = std::vector<std::pair<std::string, std::string>>;

private:
    void run();
    void handle(request rq);
    void respond(int code, std::string_view type, std::string_view body, std::string_view extra = {});
    void fail(int code, std::string_view type, std::string_view detail);
    void finished();
    std::string base_url(const request& rq) const;
    std::string session_json(const request& rq) const;
    void api(const request& rq);
    void upload(const request& rq, const std::string& account);
    void download(const request& rq, const std::string& account, const std::string& blob, const std::string& type,
                  const std::string& name);
    void eventsource(const request& rq);
    // The webmail page, and who it is signed in as.
    void page(const request& rq);
    // An advertisement's link to unsubscribe: a page asking to, and its POST, as a provider's one click sends it.
    void unsubscribe_page(const request& rq);
    void web_session(const request& rq);

    // The calls of a request, one after the other, each with what came before it to refer back to.
    struct call_state
    {
        json::jvalue req;
        size_t at{0};
        std::string out;
        // Each answer said so far, its method name, arguments and call id, for a later call to refer back to.
        struct said
        {
            std::string name;
            json::jvalue args;
            std::string id;
        };
        std::vector<said> answers;
        // What the request created, by its creation id.
        std::unordered_map<std::string, std::string> created;
        // The request's own createdIds, given back with what it made added.
        bool echo_created{false};
    };
    void next_call(const std::shared_ptr<call_state>& cs);
    void method(const std::string& name, const json::jvalue& args, const std::shared_ptr<call_state>& cs,
                std::function<void(answer)> done);

    // Methods (jmap_methods.cpp).
    void mailbox_get(const json::jvalue& args, std::function<void(answer)> done);
    void mailbox_query(const json::jvalue& args, std::function<void(answer)> done);
    void mailbox_set(const json::jvalue& args, const std::shared_ptr<call_state>& cs, std::function<void(answer)> done);
    void email_get(const json::jvalue& args, std::function<void(answer)> done);
    void email_query(const json::jvalue& args, std::function<void(answer)> done);
    void email_set(const json::jvalue& args, const std::shared_ptr<call_state>& cs, std::function<void(answer)> done);
    void email_import(const json::jvalue& args, const std::shared_ptr<call_state>& cs, std::function<void(answer)> done);
    void email_parse(const json::jvalue& args, std::function<void(answer)> done);
    void vacation_get(const json::jvalue& args, std::function<void(answer)> done);
    void vacation_set(const json::jvalue& args, std::function<void(answer)> done);
    void push_get(const json::jvalue& args, std::function<void(answer)> done);
    void identity_set(const json::jvalue& args, std::function<void(answer)> done);
    void push_set(const json::jvalue& args, const std::shared_ptr<call_state>& cs, std::function<void(answer)> done);
    void thread_get(const json::jvalue& args, std::function<void(answer)> done);
    void identity_get(const json::jvalue& args, std::function<void(answer)> done);
    void submission_set(const json::jvalue& args, const std::shared_ptr<call_state>& cs,
                        std::function<void(answer)> done);
    void changes(const std::string& type, const json::jvalue& args, std::function<void(answer)> done);

    // Where an Email is now, by its id: its folder and UID.
    struct where
    {
        std::shared_ptr<imap_folder> f;
        uint32_t uid{0};
        const imap_message* m() const { return f ? f->by_uid(uid) : nullptr; }
    };
    bool locate(const std::string& id, where& out);
    std::shared_ptr<imap_folder> mailbox_by_id(const std::string& id);
    // A blob's bytes: an Email whole, a part of one (<email>_<part>), or an upload (U...).
    void blob(const std::string& id, std::function<void(std::shared_ptr<const std::string>)> done);

    jmap_config m_cfg;
    hooks& m_hooks;
    imap_store& m_store;
    std::string m_in;
    bool m_busy{false};
    bool m_closed{false};
    bool m_keep{true};
    std::string m_user;
    // The Authorization header the last request was signed in with, which the next one need not check again.
    std::string m_auth_seen;
    // The request being answered came over HTTPS to the entrance, from the webmail page, signed in by its cookie.
    bool m_https{false};
    bool m_from_page{false};
    // Where its browser signs in, for a 401 the page answers by going there.
    std::string m_login;
    // Every message of the user has its conversation known for this request, read once where one was not.
    bool m_threads_ready{false};
    // `then` once every message of the user has its conversation.
    void with_threads(std::function<void()> then);
    // The EventSource this connection is: what it was last told, how often to ping, and whether to stop after a state.
    bool m_stream{false};
    std::string m_stream_state;
    int64_t m_ping_s{0};
    int64_t m_last_sent_ms{0};
    bool m_close_after_state{false};
    // Emails by id, built once a request from the index.
    std::unordered_map<std::string, std::pair<std::shared_ptr<imap_folder>, uint32_t>> m_ids;
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
};

}   // namespace socketley::mail
