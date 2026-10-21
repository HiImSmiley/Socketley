#pragma once
// A blocking HTTP client, one request per connection, for the few places that call out: an ACME server and an alert
// webhook. https:// is verified against the system's roots or a CA file; http:// is sent as it is.
#include <functional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

namespace https_client
{

struct reply
{
    int status{0};
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    std::string header(std::string_view name) const;
};

class client
{
public:
    client() = default;
    client(const client&) = delete;
    client& operator=(const client&) = delete;
    ~client();

    // Where every request connects, a host:port in place of the URL's, which is still the name sent and verified.
    void connect_to(std::string hostport) { m_connect = std::move(hostport); }

    // Trusts `ca_file`, or the system's roots when it is empty; false with `err` when they do not load.
    bool init(std::string& err, const std::string& ca_file = {}, std::string user_agent = "socketley");

    // `method` `url` with `body` of `type`; a reply that came is true whatever its status. Each wait is bounded by
    // `timeout_s` seconds.
    bool request(std::string_view method, const std::string& url, std::string_view type, std::string_view body, reply& out,
                 std::string& err, int timeout_s = 30);

    // A GET whose answer is a stream that does not end, as an event stream: `on_status` is told the status once the
    // head arrives and says whether to read on; `on_data` is given the body as it comes, unchunked, and an empty piece
    // whenever `idle_s` seconds pass with none, and says whether to go on. True when the far end closed the stream.
    bool stream(const std::string& url, const std::vector<std::pair<std::string, std::string>>& headers,
                const std::function<bool(int status)>& on_status, const std::function<bool(std::string_view)>& on_data,
                std::string& err, int idle_s = 1);

private:
    // A connection to the URL's host, TLS when it is https; -1 with `err` when there is none.
    int dial(const std::string& url, std::string& path, std::string& hostport, SSL*& ssl, std::string& err,
             int timeout_s);

    SSL_CTX* m_ctx{nullptr};
    std::string m_agent;
    std::string m_connect;
};

}   // namespace https_client
