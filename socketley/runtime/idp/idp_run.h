#pragma once
// The identity provider's running half: its listener, its connections and the HTTP it speaks on them, the accounts
// it keeps, the keys it signs with, and the commands `socketley idp-user` sends it.
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <sys/socket.h>
#include <time.h>

#include "idp_accounts.h"
#include "idp_logic.h"
#include "../../shared/event_loop.h"
#include "../../shared/event_loop_definitions.h"
#include "../../shared/file_io.h"
#include "../../shared/hash_pool.h"
#include "../../shared/request_channel.h"

class idp_instance;

namespace socketley::idp
{

// What marks a request channel payload as a `socketley idp-user` command, its arguments a line each after it.
inline constexpr std::string_view command_marker = "\x02skl-idp\n";

class idp_run : public io_handler
{
public:
    idp_run(idp_instance& owner, event_loop& loop);
    ~idp_run() override;

    bool start(std::string& why);
    void stop();
    void on_loop_turn();
    void on_cqe(struct io_uring_cqe* cqe) override;
    bool drained() const;
    size_t conn_count() const { return m_conns.size(); }
    std::string stats() const;

    // A `socketley idp-user` command, answered through the request channel under `ticket`.
    void command(uint64_t ticket, std::string_view payload);

private:
    struct conn
    {
        uint64_t id{0};
        int fd{-1};
        sockaddr_storage peer{};
        io_request rd{}, wr{};
        bool rd_pending{false}, wr_pending{false}, dead{false};
        // An answer is being made on a later turn, so nothing more is read off this connection meanwhile.
        bool waiting{false};
        bool keep_alive{true};
        std::string in;
        std::string out;
        size_t out_off{0};
        int64_t last{0};
        char rbuf[16384];
    };

    // One request, read whole.
    struct request
    {
        std::string method;
        std::string path;
        std::string query;
        std::string body;
        std::string cookie;
        std::string authorization;
        std::string content_type;
        std::string forwarded_for;
        std::string host;
    };

    // An authorization code, good once for a minute.
    struct code_entry
    {
        std::string client_id;
        std::string redirect;
        std::string sub;
        std::string nonce;
        std::string scope;
        std::string challenge;
        int64_t auth_time{0};
        int64_t expires{0};
    };


    // Who has failed to sign in from where, for the bar after five failures in fifteen minutes.
    struct misses
    {
        std::vector<int64_t> at;
    };

    void arm_accept();
    void accept_done(struct io_uring_cqe* cqe);
    std::shared_ptr<conn> conn_of(io_request* req);
    void arm_read(const std::shared_ptr<conn>& c);
    void read_done(const std::shared_ptr<conn>& c, int res);
    void serve(const std::shared_ptr<conn>& c);
    // A connection whose answer waited on a later turn takes up its requests again.
    void resume(const std::shared_ptr<conn>& c);
    void flush(const std::shared_ptr<conn>& c);
    void write_done(const std::shared_ptr<conn>& c, int res);
    void close_conn(const std::shared_ptr<conn>& c);
    void arm_tick();
    void tick();

    // The request at the front of `in`: 1 taken, 0 not whole yet, -1 malformed.
    int take_request(conn& c, request& rq, std::string& refusal);
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

    // What an authorize request asks, checked: the client and its redirect, or an error page when there is no
    // address to send the error to.
    const client* checked_client(const std::shared_ptr<conn>& c, const params& p, bool& answered);
    // The code for a signed-in account, sent to the client's redirect, or the browser sent on.
    void grant(const std::shared_ptr<conn>& c, const params& p, const account& who, std::string_view set_cookie);
    void login_page(const std::shared_ptr<conn>& c, const params& p, std::string_view error, int status);
    void reset_page(const std::shared_ptr<conn>& c, const params& p, std::string_view error, int status);
    void issue_tokens(const std::shared_ptr<conn>& c, const client& cl, const code_entry& e, const account& who);

    // Whether `password` is the account's, on the hash pool, with `then` called on the loop.
    void check_password(const account* who, std::string_view password, std::function<void(bool)> then);
    // A scrypt hash of `password` made on the hash pool, empty when it could not be.
    void hash_password(std::string_view password, std::function<void(std::string)> then);

    // The signed-in account the request's cookie names, null when there is none, it does not verify, or the
    // account has since been disabled, removed or signed out everywhere.
    const account* session_of(const request& rq) const;
    std::string session_cookie(const account& who, bool remember) const;
    std::string clear_cookie() const;
    std::string client_ip(const conn& c, const request& rq) const;
    bool barred(const std::string& ip, int64_t now);
    void missed(const std::string& ip, int64_t now);
    const client* find_client(std::string_view id);
    void load_clients();
    // The profile claims every token of the account carries.
    std::string profile_claims(const account& who) const;
    // Whether a token given at `issued`, in milliseconds, still holds: the account was not signed out everywhere since.
    static bool still_signed_in(const account& who, int64_t issued);

    void answer_command(uint64_t ticket, std::string_view text);
    // One page of a storage's users, as its request channel answers `users`, taken in as accounts.
    void import_page(uint64_t ticket, std::string_view reply);

    idp_instance& m_owner;
    event_loop& m_loop;
    file_io m_io;
    // A thread a core the process may run on, as each sign-in's scrypt is one core's tens of milliseconds.
    hash_pool m_hash;
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
    std::string m_issuer;
    std::string m_cookie_domain;
    bool m_secure_cookie{true};

    int m_listen_fd{-1};
    io_request m_accept_req{};
    bool m_accept_pending{false};
    std::unordered_map<uint64_t, std::shared_ptr<conn>> m_conns;
    std::vector<std::shared_ptr<conn>> m_closing;
    uint64_t m_next_id{1};

    io_request m_tick_req{};
    __kernel_timespec m_tick_ts{};
    bool m_tick_armed{false};

    EVP_PKEY* m_key{nullptr};
    std::string m_kid;
    std::string m_jwk;
    // What signs the refresh tokens, which only this provider reads back.
    std::string m_secret;
    // Session cookies and access tokens already verified, so one sent again is not verified again.
    mutable verified_tokens m_verified;

    account_store m_accounts;
    std::vector<client> m_clients;
    std::string m_clients_error;
    int64_t m_clients_mtime{-1};
    int64_t m_clients_checked{0};

    std::unordered_map<std::string, code_entry> m_codes;
    std::unordered_map<std::string, misses> m_misses;

    bool m_stopped{false};

    struct counters
    {
        uint64_t sign_ins{0}, refused{0}, barred{0}, codes{0}, tokens{0}, refreshes{0}, userinfo{0};
    } m_c;
};

}   // namespace socketley::idp
