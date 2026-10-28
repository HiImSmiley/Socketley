#pragma once
// The identity provider's running half: its listener, its connections and the HTTP it speaks on them, the accounts
// it keeps, the keys it signs with, and the commands `socketley idp-user` sends it.
#include <optional>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <sys/socket.h>
#include <time.h>

#include "idp_accounts.h"
#include "idp_logic.h"
#include "idp_shard.h"
#include "../../shared/http/conn_server.h"
#include "../../shared/loop/event_loop.h"
#include "../../shared/loop/event_loop_definitions.h"
#include "../../shared/loop/file_io.h"
#include "../../shared/loop/hash_pool.h"
#include "../../shared/ipc/request_channel.h"
#include "../../shared/persist/file_stamp.h"

class idp_instance;

namespace socketley::idp
{

// What marks a request channel payload as a `socketley idp-user` command, its arguments a line each after it.
inline constexpr std::string_view command_marker = "\x02skl-idp\n";

class idp_run : public io_handler, public request_origin, public socketley::http::conn_hooks
{
public:
    idp_run(idp_instance& owner, event_loop& loop);
    ~idp_run() override;

    bool start(std::string& why);
    void stop();
    void on_loop_turn();
    void on_cqe(struct io_uring_cqe* cqe) override;
    bool drained() const;
    size_t conn_count() const { return m_http.size(); }
    std::string stats() const;

    // A `socketley idp-user` command, answered through the request channel under `ticket`.
    void command(uint64_t ticket, std::string_view payload);
    // Another shard's question, answered under `ticket`.
    void shard_answer(uint64_t ticket, std::string_view payload);
    void on_request_reply(uint64_t cookie, request_status st, std::string_view reply) override;

private:
    using conn = socketley::http::server_conn;

    // One request, read whole.
    struct request
    {
        std::string method;
        std::string path;
        std::string query;
        std::string body;
        std::string cookie;
        std::string authorization;
        std::string forwarded_for;
        // The page a browser says sent the request, Origin and else Referer, for a form posted from another site.
        std::string origin;
        std::string referer;
    };


    // Who has failed to sign in from where, for the bar after five failures in fifteen minutes.
    struct misses
    {
        std::vector<int64_t> at;
    };

    std::shared_ptr<socketley::http::server_conn> make_conn() override;
    void accepted(const std::shared_ptr<conn>& c) override;
    void serve(const std::shared_ptr<conn>& c) override;
    void arm_tick();
    void tick();

    // The request at the front of `in`: 1 taken, 0 not whole yet, -1 malformed.
    int take_request(conn& c, request& rq, int& refusal);
    void handle(const std::shared_ptr<conn>& c, request& rq);
    void respond(const std::shared_ptr<conn>& c, int status, std::string_view type, std::string_view body,
                 std::string_view extra_headers = {});
    void redirect(const std::shared_ptr<conn>& c, std::string_view location, std::string_view extra_headers = {});
    void json_error(const std::shared_ptr<conn>& c, int status, std::string_view error, std::string_view description,
                    std::string_view extra_headers = {});

    void discovery(const std::shared_ptr<conn>& c);
    void jwks(const std::shared_ptr<conn>& c);
    void authorize(const std::shared_ptr<conn>& c, const request& rq);
    void sign_in(const std::shared_ptr<conn>& c, const request& rq);
    void token(const std::shared_ptr<conn>& c, const request& rq);
    void userinfo(const std::shared_ptr<conn>& c, const request& rq);
    void logout(const std::shared_ptr<conn>& c, const request& rq);
    void home(const std::shared_ptr<conn>& c, const request& rq);
    void account_page(const std::shared_ptr<conn>& c, const request& rq, std::string_view note, std::string_view error,
                      int status);
    void account_post(const std::shared_ptr<conn>& c, const request& rq);
    void password_post(const std::shared_ptr<conn>& c, const request& rq);

    // The device grant (RFC 8628): a client asks for a pair of codes, a person allows the user code on /device, and
    // the client polls the token endpoint with the device code until that person has.
    void device_authorization(const std::shared_ptr<conn>& c, const request& rq);
    void device_page(const std::shared_ptr<conn>& c, const request& rq, std::string_view note, std::string_view error,
                     int status);
    void device_post(const std::shared_ptr<conn>& c, const request& rq);
    void device_token(const std::shared_ptr<conn>& c, const client& cl, std::string device_code);
    void device_answered(const std::shared_ptr<conn>& c, const client& cl, device_poll what, const device_entry& e);
    // This shard's own grants: a user code decided, and a device code polled.
    bool decide_device(const std::string& user_code, bool allow, const std::string& sub, int64_t at);
    device_poll poll_device(const std::string& device_code, std::string_view client_id, int64_t now,
                            device_entry& out);
    // The client a token or device request names, authenticated; null with the error already sent.
    const client* requesting_client(const std::shared_ptr<conn>& c, const request& rq, const params& p);
    // A sign-in that went through, counted and said in the log with who and from where.
    void signed_in(const account& who, std::string_view ip, std::string_view how);

    // The SSH certificate authority (--ssh-ca): its public key, and a user certificate for the account an access
    // token names, for a key the token's holder sends.
    void ssh_ca_pub(const std::shared_ptr<conn>& c);
    void ssh_user_cert(const std::shared_ptr<conn>& c, const request& rq);
    // The principals a user certificate names: the username, root for the admins group, and <p> for each ssh:<p>.
    static std::vector<std::string> ssh_principals(const account& who);
    // A host certificate for `key_line` naming `names`, holding `days`; the certificate line, or `error: ...`.
    std::string ssh_host_cert(std::string_view key_line, std::string_view names, uint32_t days);

    // What an authorize request asks, checked: the client and its redirect, or an error page when there is no
    // address to send the error to.
    const client* checked_client(const std::shared_ptr<conn>& c, const params& p);
    // The code for a signed-in account, sent to the client's redirect, or the browser sent on.
    void grant(const std::shared_ptr<conn>& c, const params& p, const account& who, std::string_view set_cookie);
    void login_page(const std::shared_ptr<conn>& c, const params& p, std::string_view error, int status);
    void reset_page(const std::shared_ptr<conn>& c, const std::string& token, std::string_view error, int status);
    // A sign-in whose password, and code where the account has one, were right, sent to set its password again.
    void reset_after_sign_in(const std::shared_ptr<conn>& c, const account& a, const params& p, bool remember);
    void issue_tokens(const std::shared_ptr<conn>& c, const client& cl, const code_entry& e, const account& who);
    // An authorization code exchanged, once the shard that gave it has handed over its entry.
    void redeemed(const std::shared_ptr<conn>& c, const client& cl, const params& p, bool found, const code_entry& e);

    // Whether `password` is the account's, on the hash pool, with `then` called on the loop.
    void check_password(const account* who, std::string_view password, std::function<void(bool)> then);
    // `password` against one hash, `real` false for a hash that stands for no account, so the time says nothing.
    void check_hash(std::string hash, bool real, std::string_view password, std::function<void(bool)> then);
    // A mail app's sign-in: the account's password unless its second step is on, and each of its app passwords.
    void check_mail_password(const account* who, std::string password, std::function<void(bool)> then);
    // The app passwords' hashes from the `i`th on, each tried in turn until one is the password.
    void check_app_passwords(std::shared_ptr<const std::vector<std::string>> hashes, size_t i, std::string password,
                             std::function<void(bool)> then);
    // The second step of a web sign-in, its password already right: what it carries until the code comes.
    struct pending_sign_in
    {
        std::string id;
        bool remember{false};
        params p;
        int64_t until_s{0};
        // The proof a forced reset carries: the sign-in passed every step, and only its password is still to be set.
        bool reset{false};
    };
    std::unordered_map<std::string, pending_sign_in> m_pending;
    // The last step of each account's codes taken, so one code is taken once; and a secret an account is enrolling.
    std::unordered_map<std::string, uint64_t> m_totp_used;
    std::unordered_map<std::string, std::pair<std::string, int64_t>> m_enrolling;
    void code_page(const std::shared_ptr<conn>& c, const std::string& pending, std::string_view error, int status);
    void second_step(const std::shared_ptr<conn>& c, const request& rq, params p);
    void security_post(const std::shared_ptr<conn>& c, const request& rq);
    std::string security_html(const account& who);
    bool code_right(const account& a, std::string_view code);
    // A scrypt hash of `password` made on the hash pool, empty when it could not be.
    void hash_password(std::string_view password, std::function<void(std::string)> then);

    // The signed-in account the request's cookie names, null when there is none, it does not verify, or the
    // account has since been disabled, removed or signed out everywhere.
    const account* session_of(const request& rq) const;
    std::string session_cookie(const account& who, bool remember) const;
    std::string clear_cookie() const;
    std::string client_ip(const conn& c, const request& rq) const;
    bool barred(const std::string& ip, int64_t now);
    // A failed sign-in from `ip`, with `then` called once every shard bars by it.
    void missed(const std::string& ip, int64_t now, std::function<void()> then);
    const client* find_client(std::string_view id);
    void load_clients();
    // The profile claims every token of the account carries.
    std::string profile_claims(const account& who) const;
    // Whether a token given at `issued`, in milliseconds, still holds: the account was not signed out everywhere since.
    static bool still_signed_in(const account& who, int64_t issued);

    // Fields of an account set by shard 0, here or asked of it, with `then` called once this shard reads the change.
    void update_account(const std::string& id, field_list fields, std::function<void(bool, const std::string&)> then);
    // Asks shard `shard`, with `then` called on its answer, or with false when it gave none.
    bool cross(uint32_t shard, const shard_call& call, std::function<void(bool, std::string_view)> then);
    // Shard 0's journal as far as it has written it: said to the other shards, which read it before every answer.
    void publish_accounts();
    void catch_up();

    void answer_command(uint64_t ticket, std::string_view text);
    // One page of a storage's users, as its request channel answers `users`, taken in as accounts.
    void import_page(uint64_t ticket, std::string_view reply);

    idp_instance& m_owner;
    event_loop& m_loop;
    file_io m_io;
    socketley::http::conn_server m_http;
    // A thread a core the process may run on, up to four, as each sign-in's scrypt is one core's milliseconds.
    hash_pool m_hash;
    // Password checks waiting for a hashing thread, which takes up to four at once.
    struct password_checks
    {
        struct check
        {
            std::string hash;
            std::string password;
            bool real{false};
            std::function<void(bool)> then;
        };
        std::mutex mu;
        std::deque<check> waiting;
    };
    std::shared_ptr<password_checks> m_checks{std::make_shared<password_checks>()};
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
    std::string m_issuer;
    std::string m_issuer_json;
    std::string m_cookie_domain;
    bool m_secure_cookie{true};


    io_request m_tick_req{};
    __kernel_timespec m_tick_ts{};
    bool m_tick_armed{false};

    EVP_PKEY* m_key{nullptr};
    std::string m_kid;
    std::string m_jwk;
    // What signs the refresh tokens, which only this provider reads back.
    std::string m_secret;
    // What signs SSH certificates under --ssh-ca, null without it, and its public key as authorized_keys writes it.
    EVP_PKEY* m_ssh_ca{nullptr};
    std::string m_ssh_ca_line;
    uint32_t m_ssh_hours{0};
    // Session cookies and access tokens already verified, so one sent again is not verified again.
    mutable verified_tokens m_verified;

    account_store m_accounts;
    std::vector<client> m_clients;
    std::string m_clients_error;
    std::optional<socketley::file_stamp> m_clients_stamp;
    int64_t m_clients_checked{0};

    std::unordered_map<std::string, code_entry> m_codes;
    // Device grants by device code, and each one's device code by its user code in normal form.
    std::unordered_map<std::string, device_entry> m_devices;
    std::unordered_map<std::string, std::string> m_user_codes;
    std::unordered_map<std::string, misses> m_misses;

    bool m_stopped{false};

    // This shard's place among the runtime's: shard 0 writes the accounts, every other reads its journal.
    uint32_t m_shard{0};
    uint32_t m_shards{1};
    bool m_reader{false};
    uint64_t m_told_id{0}, m_told_end{0};
    std::string m_follow_error;
    std::unordered_map<uint64_t, std::function<void(bool, std::string_view)>> m_crossed;
    uint64_t m_next_cookie{1};

    struct counters
    {
        uint64_t sign_ins{0}, refused{0}, barred{0}, codes{0}, tokens{0}, refreshes{0}, userinfo{0}, devices{0}, ssh_certs{0};
        uint64_t crossed{0}, crossings_served{0}, reopened{0};
    } m_c;
};

}   // namespace socketley::idp
