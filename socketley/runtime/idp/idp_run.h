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
#include <unordered_set>
#include <vector>

#include <sys/socket.h>
#include <time.h>

#include "idp_accounts.h"
#include "idp_logic.h"
#include "idp_ssh_certs.h"
#include "idp_shard.h"
#include "../../shared/http/conn_server.h"
#include "../../shared/loop/event_loop.h"
#include "../../shared/runtime/latency_histogram.h"
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
        // Where a browser says the request came from: same-origin, same-site, cross-site or none.
        std::string fetch_site;
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
    // `fetched` once the metadata document of the client it names has been asked for.
    void authorize(const std::shared_ptr<conn>& c, const request& rq, bool fetched = false);
    void sign_in(const std::shared_ptr<conn>& c, const request& rq);
    void token(const std::shared_ptr<conn>& c, const request& rq, bool fetched = false);
    // What an application known by its address asks of a signed-in person, and the person's answer.
    void consent_page(const std::shared_ptr<conn>& c, const params& p, const account& who, const client& cl,
                      std::string_view set_cookie);
    void consent_post(const std::shared_ptr<conn>& c, const request& rq);
    void userinfo(const std::shared_ptr<conn>& c, const request& rq);
    void logout(const std::shared_ptr<conn>& c, const request& rq);
    void home(const std::shared_ptr<conn>& c, const request& rq);
    void account_page(const std::shared_ptr<conn>& c, const request& rq, std::string_view note, std::string_view error,
                      int status);
    void account_post(const std::shared_ptr<conn>& c, const request& rq);
    void password_post(const std::shared_ptr<conn>& c, const request& rq);
    void password_form(const std::shared_ptr<conn>& c, const request& rq, params p);

    // The device grant (RFC 8628): a client asks for a pair of codes, a person allows the user code on /device, and
    // the client polls the token endpoint with the device code until that person has.
    void device_authorization(const std::shared_ptr<conn>& c, const request& rq);
    void device_page(const std::shared_ptr<conn>& c, const request& rq, std::string_view note, std::string_view error,
                     int status);
    void device_post(const std::shared_ptr<conn>& c, const request& rq);
    // What allowing the grant `e` gives, said before it is allowed, with the password or code asked for where it
    // reaches the account's servers.
    void device_confirm(const std::shared_ptr<conn>& c, const account& who, const std::string& user_code,
                        const device_entry& e, std::string_view error, int status);
    // Whether allowing the grant `e` asks the person to prove again who they are: a client marked ssh, which can
    // get SSH certificates naming root for an admin.
    bool device_needs_proof(const device_entry& e) const;
    // The waiting grant the user code `normal` names, from the shard that keeps it, `then` told whether there is one.
    void find_device(const std::string& normal, int64_t now, std::function<void(bool, const device_entry&)> then);
    // The grant decided at the shard that keeps it, `then` told whether it was waiting.
    void decide_at(const std::string& normal, bool allow, const std::string& sub, int64_t now,
                   std::function<void(bool)> then);
    void device_token(const std::shared_ptr<conn>& c, const client& cl, std::string device_code);
    void device_answered(const std::shared_ptr<conn>& c, const client& cl, device_poll what, const device_entry& e);
    // A grant of this shard's let go of, with its user code and its count at the address that asked; the next one after.
    using device_map = std::unordered_map<std::string, device_entry>;
    device_map::iterator forget_device(device_map::iterator it);
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
    // The revocation list sshd's RevokedKeys reads, for a server that fetches it rather than reading the file.
    void ssh_krl(const std::shared_ptr<conn>& c);
    // Every current SSH certificate `which` picks revoked, how many; -1 with `why` when the list cannot be written.
    int revoke_ssh(const std::function<bool(const socketley::idp::issued_cert&)>& which, std::string& why);
    // The principals a user certificate names: the username, root for the admins group, and <p> for each ssh:<p>.
    static std::vector<std::string> ssh_principals(const account& who);
    // A host certificate for `key_line` naming `names`, holding `days`; the certificate line, or `error: ...`.
    std::string ssh_host_cert(std::string_view key_line, std::string_view names, uint32_t days);

    // What an authorize request asks, checked: the client and its redirect, or an error page when there is no
    // address to send the error to.
    const client* checked_client(const std::shared_ptr<conn>& c, const params& p);
    // The code for a signed-in account, sent to the client's redirect, or the browser sent on; an application known
    // by its address is first allowed by the person, `consented` once they have.
    void grant(const std::shared_ptr<conn>& c, const params& p, const account& who, std::string_view set_cookie,
               int64_t auth_time = 0, bool consented = false);
    // The resource server a request names, as tokens name it, empty for none; `bad` when it names one this provider
    // gives no tokens for, or more than one.
    std::string requested_resource(const params& p, bool& bad) const;
    void login_page(const std::shared_ptr<conn>& c, const params& p, std::string_view error, int status);
    void reset_page(const std::shared_ptr<conn>& c, const std::string& token, std::string_view error, int status);
    // A sign-in whose password, and code where the account has one, were right, sent to set its password again.
    void reset_after_sign_in(const std::shared_ptr<conn>& c, const account& a, const params& p, bool remember);
    // The tokens of a sign-in, its refresh token, where it gets one, the first of a family kept with the account.
    void issue_tokens(const std::shared_ptr<conn>& c, const client& cl, const code_entry& e, const account& who);
    // The tokens answered, the refresh token of the family `family` at its `generation`, none for an empty family.
    void send_tokens(const std::shared_ptr<conn>& c, const client& cl, const code_entry& e, const account& who,
                     std::string_view family, uint64_t generation);
    // A refresh token exchanged: the next of its family given, and the family ended when one before the newest comes.
    void refresh_grant(const std::shared_ptr<conn>& c, const client& cl, const claims& r, const account& who);
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
        // Wrong codes given for it, three of which end it.
        int misses{0};
    };
    std::unordered_map<std::string, pending_sign_in> m_pending;
    std::string pending_token() const;
    bool take_pending(const std::shared_ptr<conn>& c, const request& rq, params& p, std::string_view field,
                      void (idp_run::*step)(const std::shared_ptr<conn>&, const request&, params));
    static std::string encode_pending(const pending_sign_in* e);
    static bool decode_pending(std::string_view in, bool& found, pending_sign_in& out);
    // A secret an account is enrolling, until a code of it proves the app has it.
    std::unordered_map<std::string, std::pair<std::string, int64_t>> m_enrolling;
    void code_page(const std::shared_ptr<conn>& c, const std::string& pending, std::string_view error, int status);
    void second_step(const std::shared_ptr<conn>& c, const request& rq, params p);
    void security_post(const std::shared_ptr<conn>& c, const request& rq);
    std::string security_html(const account& who);
    // Whether the person at `c` is `who` again, before a change a stolen session must not make alone: the code where
    // the account has a second step, its password otherwise, counted against the account and the address like a
    // sign-in; `then` given 0 when they are, else the status to answer and why.
    void prove_again(const std::shared_ptr<conn>& c, const request& rq, const account& who, const params& p,
                     std::function<void(int, std::string_view)> then);
    // Whether `code` is the account's now and of a later step than the last it took, that step kept with the account
    // by shard 0, so a code is taken once at every shard and across a restart.
    void check_code(const account& a, std::string_view code, std::function<void(bool)> then);
    // A scrypt hash of `password` made on the hash pool, empty when it could not be.
    void hash_password(std::string_view password, std::function<void(std::string)> then);

    // The signed-in account the request's cookie names, null when there is none, it does not verify, or the
    // account has since been disabled, removed or signed out everywhere.
    const account* session_of(const request& rq, int64_t* auth_time = nullptr) const;
    std::string session_cookie(const account& who, bool remember) const;
    std::string clear_cookie() const;
    std::string client_ip(const conn& c, const request& rq) const;
    bool barred(const std::string& ip, int64_t now);
    // A failed sign-in from `ip`, and at the account keyed `acct` unless it is empty, with `then` called once every
    // shard counts it.
    void missed(const std::string& ip, const std::string& acct, int64_t now, std::function<void()> then);
    // A failure at each of `keys`, told to every shard, `then` called once all of them count it.
    void count_failed(std::vector<std::string> keys, int64_t now, std::function<void()> then);
    // The keys an attempt from `ip` at `acct` counts in flight under while it is checked, and their release after.
    std::vector<std::string> hold(const std::string& ip, const std::string& acct);
    void hold_keys(const std::vector<std::string>& keys);
    void release(const std::vector<std::string>& keys);
    // Every other shard told of attempts at `keys` begun or ended here, so a burst spread over them is counted as one.
    void tell_shards(shard_call::op_t op, const std::vector<std::string>& keys);
    // What failures at the account `who` (or the username `user` where there is none) count under: its own key for
    // a browser it signed in on before, so guesses from elsewhere never hold that one up, and the account's otherwise.
    std::string account_key(const request& rq, std::string_view prefix, const account* who, std::string_view user) const;
    // Whether the request comes from a browser `who` signed in on before, which the address's bar does not hold up.
    bool known_device(const request& rq, const account* who) const;
    // The cookie a browser keeps once an account has signed in on it, which account_key() reads.
    std::string known_cookie(const account& who) const;
    // Whether every hashing thread has as much waiting as the bound, so a sign-in is turned away rather than queued.
    bool hashing_full() const { return m_hashing >= 64; }
    const client* find_client(std::string_view id);
    void load_clients();
    // Whether `id` is a client known by its metadata document, not fetched lately.
    bool needs_fetch(std::string_view id) const;
    // The document of `id` fetched off the loop, and `then` run once it was taken or refused; at once, finding no
    // client, when too many are being fetched.
    void fetch_client(const std::shared_ptr<conn>& c, const std::string& id,
                      std::function<void(const std::shared_ptr<conn>&)> then);
    // The profile claims every token of the account carries.
    std::string profile_claims(const account& who) const;
    // Whether `who`'s e-mail is one an admin gave them, or their own username on a domain of this provider's: what a
    // mail runtime, a proxy and a token's email_verified may take as theirs.
    bool email_trusted(const account& who) const;
    std::string_view trusted_email(const account& who) const { return email_trusted(who) ? who.field("email") : std::string_view{}; }
    // Why `who` may not give themselves `email`: no plain address, or one another account has or could have.
    std::string self_email_problem(const account& who, std::string_view email) const;
    // Whether `domain` is this provider's host or its cookie domain.
    bool own_domain(std::string_view domain) const;
    // Whether a token given at `issued`, in milliseconds, still holds: the account was not signed out everywhere since.
    static bool still_signed_in(const account& who, int64_t issued);

    // Fields of an account set by shard 0, here or asked of it, with `then` called once this shard reads the change; a
    // field named ?<name> sets nothing and makes the change wait on <name> still holding that value.
    void update_account(const std::string& id, field_list fields, std::function<void(bool, const std::string&)> then);
    // The change update_account() asks, made here at shard 0.
    bool write_account(const std::string& id, const field_list& fields, std::string& why);
    // Asks shard `shard`, with `then` called on its answer, or with false when it gave none.
    bool cross(uint32_t shard, const shard_call& call, std::function<void(bool, std::string_view)> then);
    // Shard 0's journal as far as it has written it: said to the other shards, which read it before every answer, and
    // the accounts' standing written beside the key once a change has altered it.
    // `then` runs once the standing is on the disk as of every change made so far.
    void publish_accounts(std::function<void()> then = {});
    // Each account's standing where the runtimes that verify its sessions alone read it, by shard 0 alone, as it
    // writes the accounts; false when it could not be written, which the next change tries again. In line, at start.
    bool publish_standing();
    // The same off the loop, the waiters each run once a write covering their change has ended.
    void write_standing();
    // The lines of the accounts whose standing changed, made again here, since only the loop reads the accounts:
    // every account's when `all`, and none for an account gone.
    struct standing_update
    {
        bool all{false};
        std::vector<std::pair<std::string, std::optional<std::string>>> lines;
    };
    standing_update standing_changed();
    using standing_lines = std::unordered_map<std::string, std::string>;
    // The lines updated and the whole file made from every one of them, by whoever holds the lines: the loop in line,
    // or the write under way, as there is only ever one.
    static std::string standing_doc(standing_lines& lines, standing_update u);
    void catch_up();

    void answer_command(uint64_t ticket, std::string_view text);
    // The same once every account change made so far is on the disk, and told to the other shards.
    void answer_durable(uint64_t ticket, std::string text);
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
    std::string m_ssh_ca_blob;
    uint32_t m_ssh_hours{0};
    // Session cookies and access tokens already verified, so one sent again is not verified again.
    mutable verified_tokens m_verified;

    account_store m_accounts;
    std::vector<client> m_clients;
    // The resource servers of --resources, as each names itself.
    std::vector<std::string> m_resources;
    // Clients known by the address of their metadata document, kept as its Cache-Control says.
    struct fetched_client
    {
        client cl;
        int64_t fresh_until{0};
    };
    std::unordered_map<std::string, fetched_client> m_fetched;
    // The requests waiting on a document being fetched, by its address.
    std::unordered_map<std::string, std::vector<std::function<void()>>> m_fetching;
    // Addresses whose document was refused, each said once in the log.
    std::unordered_set<std::string> m_fetch_said;
    // The threads documents are fetched on, apart from the sign-ins' hashing, which a slow host would hold up.
    hash_pool m_fetch_pool{2};
    bool m_fetch_attached{false};
    std::string m_clients_error;
    std::optional<socketley::file_stamp> m_clients_stamp;
    int64_t m_clients_checked{0};

    std::unordered_map<std::string, code_entry> m_codes;
    // Device grants by device code, and each one's device code by its user code in normal form.
    device_map m_devices;
    std::unordered_map<std::string, std::string> m_user_codes;
    // The grants waiting by the address or IPv6 site that asked for them, so one cannot take every one there is.
    std::unordered_map<std::string, uint32_t> m_devices_from;
    // Failures by address and by account, and the attempts at each being checked.
    attempt_limits m_limits;
    // Mail's password checks for an account waiting for one of its own in flight to end, the oldest first.
    std::unordered_map<std::string, std::deque<std::function<void()>>> m_mail_waiting;
    void wake_mail(const std::string& acct);
    // Password checks given to the hashing threads and not answered yet.
    uint32_t m_hashing{0};

    bool m_stopped{false};

    // This shard's place among the runtime's: shard 0 writes the accounts, every other reads its journal.
    uint32_t m_shard{0};
    uint32_t m_shards{1};
    bool m_reader{false};
    uint64_t m_told_id{0}, m_told_end{0};
    std::string m_follow_error;
    // The accounts' change count the standing was last written at, each account's line of it by id, the write under
    // way, and who waits for one as of which change count.
    uint64_t m_standing_at{UINT64_MAX};
    std::shared_ptr<standing_lines> m_standing_lines{std::make_shared<standing_lines>()};
    bool m_standing_writing{false};
    std::vector<std::pair<uint64_t, std::function<void()>>> m_standing_waiters;
    // The thread the standing is written and synced on, apart from the sign-ins' hashing, which it would wait behind.
    hash_pool m_standing_pool{1};
    bool m_standing_attached{false};
    std::unordered_map<uint64_t, std::function<void(bool, std::string_view)>> m_crossed;
    uint64_t m_next_cookie{1};

    struct counters
    {
        uint64_t sign_ins{0}, refused{0}, barred{0}, codes{0}, tokens{0}, refreshes{0}, userinfo{0}, devices{0}, ssh_certs{0};
        uint64_t consents{0}, client_fetches{0}, client_fetch_failures{0};
        uint64_t crossed{0}, crossings_served{0}, reopened{0};
    } m_c;
    // A password sign-in from its form to its answer, the hash and a refusal's record included, in loop turns.
    socketley::latency_histogram m_lat_sign_in;
    std::string latency_line() const;
};

}   // namespace socketley::idp
