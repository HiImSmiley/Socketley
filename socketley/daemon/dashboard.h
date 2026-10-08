#pragma once
// The daemon's dashboard, served by the metrics endpoint's thread: the page, its sign-in, and the commands it sends
// the daemon. A command goes over the daemon's own control socket as the CLI's does, so the page can do what the
// CLI can and nothing the CLI cannot.
//
// Signing in takes an access key and secret of an admin of the credentials file the daemon configuration names
// (daemon.dashboard_credentials, a storage runtime's format), checked as a proxy's --auth basic: checks them, five
// failures from one address barring it for fifteen minutes. A session is a cookie sealed with a key this process
// draws at start, HttpOnly and SameSite=Strict, good for twelve hours; a change also carries the page's own header,
// which no other site's request can. Without the credentials the page shows and changes nothing.
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

class proxy_auth;
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

// One request read from `fd`, its head and a body of at most `max_body`; false for none or a malformed one.
bool read_request(int fd, request& r, size_t max_body = 1 << 20);
// One query field's value, undecoded but for %XX and '+'.
std::string query_field(std::string_view query, std::string_view name);
// One answer, closing the connection.
void send(int fd, int status, std::string_view type, std::string_view body, std::string_view extra_headers = {});

class server
{
public:
    server(std::string credentials, runtime_manager& manager);
    ~server();

    bool configured() const { return !m_credentials.empty(); }
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
    std::string seal(std::string_view user, int64_t expires) const;

    std::string m_credentials;
    std::string m_key;
    std::unique_ptr<proxy_auth> m_auth;
    runtime_manager& m_manager;
};

}   // namespace dashboard
