#pragma once
// FastCGI (the 1996 specification, version 1), the client half: what a proxy writes to an application server such as
// php-fpm for one HTTP request, and what it reads back.  A request is a BEGIN_REQUEST, its CGI variables as PARAMS
// records, its body as STDIN records, each stream ended by an empty record; the answer is STDOUT records holding a
// CGI response -- header lines, a blank line, the body -- STDERR records for the server's log, and an END_REQUEST.
// One request at a time on a connection, as php-fpm takes them, so every record here carries request id 1.
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace socketley::fastcgi
{

enum class record_type : uint8_t
{
    begin_request = 1,
    abort_request = 2,
    end_request = 3,
    params = 4,
    stdin_data = 5,
    stdout_data = 6,
    stderr_data = 7,
    data = 8,
    get_values = 9,
    get_values_result = 10,
    unknown_type = 11,
};

inline constexpr uint16_t request_id = 1;
inline constexpr size_t header_size = 8;
inline constexpr size_t max_content = 65535;

// A BEGIN_REQUEST for the responder role, asking the server to keep the connection when `keep_conn`.
void append_begin(std::string& out, bool keep_conn);
// The CGI variables as PARAMS records of at most max_content each, and the empty one that ends them.
void append_params(std::string& out, const std::vector<std::pair<std::string, std::string>>& params);
// Body bytes as STDIN records; empty, the record that ends the body.
void append_stdin(std::string& out, std::string_view data);
// An ABORT_REQUEST, for a client gone before the answer.
void append_abort(std::string& out);

struct record
{
    record_type type{};
    uint16_t id{0};
    std::string_view content;
};

enum class take : uint8_t { record, need_more, bad };

// The record at the front of `buf`, its content a view into it and `consumed` its length with the padding; bad for a
// version other than 1, need_more until the whole record is there.
take next_record(std::string_view buf, record& out, size_t& consumed);

// END_REQUEST's body: the application's exit status and the protocol status, 0 for a request completed.
bool parse_end_request(std::string_view content, uint32_t& app_status, uint8_t& protocol_status);

// What a CGI response's header lines say (RFC 3875 6.2): its status, the fields to pass on, and the two a proxy acts on
// itself -- Location without a Status, which is a 302, and X-Accel-Redirect, a file under the root to send instead.
struct cgi_head
{
    int status{200};
    std::string reason;
    std::vector<std::pair<std::string, std::string>> fields;
    std::string location;
    std::string accel_redirect;
    bool has_length{false};
};

enum class head_result : uint8_t { done, need_more, bad };

// The header lines at the front of `stdout_bytes`, `head_len` the bytes up to and with the blank line; bad for a line
// without a colon, a field name a header may not hold, a Status that is not a code from 100 to 999, or no blank line
// within `max_head` bytes.  A line ends at LF, a CR before it dropped, as servers end them either way.
head_result parse_cgi_head(std::string_view stdout_bytes, size_t& head_len, cgi_head& out, size_t max_head = 65536);

// One HTTP request as the CGI variables describe it.
struct request_info
{
    std::string_view method;
    std::string_view target;          // the request target as sent, path and query
    std::string_view path;            // decoded path, without the query
    std::string_view query;
    std::string_view protocol;        // "HTTP/1.1"
    std::string script_name;          // the script under the root, as a URL path: /shop/cart.php
    std::string script_filename;      // and as the application server finds it on disk
    std::string path_info;            // what of the path follows the script: /extra of /shop/cart.php/extra
    std::string_view document_root;   // the root as the application server sees it
    std::string_view server_name;
    std::string_view server_port;
    std::string_view remote_addr;
    std::string_view remote_port;
    bool https{false};
    std::vector<std::pair<std::string_view, std::string_view>> headers;
    uint64_t content_length{0};
    bool has_body{false};
};

// The CGI/1.1 variables of `r`, each header as HTTP_<NAME>, Content-Type and Content-Length as their own; a header
// named Proxy is left out (httpoxy, CVE-2016-5385) and so is any whose name holds an underscore, which a server
// would otherwise read as the dash of another header's.
std::vector<std::pair<std::string, std::string>> cgi_params(const request_info& r);

}   // namespace socketley::fastcgi
