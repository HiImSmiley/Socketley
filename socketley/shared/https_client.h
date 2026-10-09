#pragma once
// A blocking HTTP client, one request per connection, for the few places that call out: an ACME server and an alert
// webhook. https:// is verified against the system's roots or a CA file; http:// is sent as it is.
#include <string>
#include <string_view>
#include <utility>
#include <vector>

typedef struct ssl_ctx_st SSL_CTX;

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

    // Trusts `ca_file`, or the system's roots when it is empty; false with `err` when they do not load.
    bool init(std::string& err, const std::string& ca_file = {}, std::string user_agent = "socketley");

    // `method` `url` with `body` of `type`; a reply that came is true whatever its status. Each wait is bounded by
    // `timeout_s` seconds.
    bool request(std::string_view method, const std::string& url, std::string_view type, std::string_view body, reply& out,
                 std::string& err, int timeout_s = 30);

private:
    SSL_CTX* m_ctx{nullptr};
    std::string m_agent;
};

}   // namespace https_client
