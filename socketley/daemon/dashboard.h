#pragma once
// The daemon's dashboard, served by the metrics endpoint's thread: the page, its sign-in, and the commands it sends
// the daemon. A command goes over the daemon's own control socket as the CLI's does, so the page can do what the
// CLI can and nothing the CLI cannot.
//
// Signing in takes an access key and secret of an admin of the credentials file the daemon configuration names
// (daemon.dashboard_credentials, a storage runtime's format), checked as a proxy's --auth basic: checks them, five
// failures from one address barring it for fifteen minutes. A session is a cookie sealed with a key this process
// draws at start, HttpOnly and SameSite=Strict, good for twelve hours unless signed out or its key's secret changes or
// goes; a change also carries the page's own header, which no other site's request can. Without the credentials the
// page shows the figures, not the log or a zone, and changes nothing.
#include "../runtime/idp/idp_session.h"
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

class proxy_auth;
class runtime_instance;
class runtime_manager;

namespace dashboard
{

struct request
{
    std::string method, path, query, body, peer;
    std::unordered_map<std::string, std::string> headers;   // names lower case
    std::string_view header(std::string_view name) const;
    // Who sent it: the peer, or behind a proxy on this machine the address that proxy put last in X-Forwarded-For.
    std::string client() const;
};

// What the bytes of a connection so far are: a whole request, the start of one, or none that will be.
enum class parse_state { more, done, bad };
// The request `in` holds, its head and a body of at most `max_body`, put in `r` (whose peer is kept) once whole.
parse_state parse_request(std::string_view in, request& r, size_t max_body = 1 << 20);
// What a certificate file says of itself; false when it holds none.
// The certificate file a runtime serves with, its --cert or the one --acme keeps for its first name; empty for none.
std::string served_cert(const runtime_instance& rt);

// One query field's value, undecoded but for %XX and '+'.
std::string query_field(std::string_view query, std::string_view name);
// One answer, closing the connection.
void send(int fd, int status, std::string_view type, std::string_view body, std::string_view extra_headers = {});

class server
{
public:
    server(std::string credentials, std::string idp, runtime_manager& manager);
    ~server();

    bool configured() const { return !m_credentials.empty() || m_idp.enabled(); }
    // The access key of the request's session, empty for none.
    std::string session_of(const request& r) const;
    // Whether a read of the figures is let through: a session, or, without credentials, anyone the endpoint serves.
    bool may_read(const request& r) const { return !configured() || !session_of(r).empty(); }

    // The page and /api/session, /api/run, /api/schema and /api/logs; false for a path that is none of them.
    bool handle(int fd, const request& r);

private:
    void session(int fd, const request& r);
    void run(int fd, const request& r);
    // GET /api/logs?since=&max=&runtime=&level=: the daemon's recent log, as log_ring.h keeps it.
    void logs(int fd, const request& r);
    // GET /api/edge: the entrances, their routes and zones, every certificate a runtime serves with what it is for and
    // when it ends, and the zone files of the dns runtimes.
    void edge(int fd, const request& r);
    // GET /api/zone?runtime=&path=: a dns runtime's zone file; PUT the same with its new text, checked as the runtime
    // would read it before it is written.
    void zone(int fd, const request& r);
    std::string seal(std::string_view user, std::string_view sid, int64_t expires) const;
    // The user and session id a skl_dash value seals; false when its seal does not hold or it has ended.
    bool unseal(std::string_view value, std::string& user, std::string& sid) const;
    // Whether a session is still open: not signed out, and its key still an admin's with the secret it signed in by.
    bool live(const std::string& sid) const;

    std::string m_credentials;

    // The idp runtime's sessions, of whose accounts an admin signs in; verifying keeps a cache, so it is mutable.

    mutable socketley::idp::session_verifier m_idp;
    std::string m_key;
    std::unique_ptr<proxy_auth> m_auth;

    // The sessions signed in by the credentials file, by id: the access key and a MAC of the secret they were made with.
    struct open_session
    {
        std::string key, mark;
        int64_t expires{0};
    };
    mutable std::mutex m_sessions_mutex;
    mutable std::unordered_map<std::string, open_session> m_sessions;
    runtime_manager& m_manager;
};

}   // namespace dashboard
