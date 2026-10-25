#pragma once
// CalDAV (RFC 4791) and CardDAV (RFC 6352) for a mail runtime's users on its JMAP and webmail ports: a user's
// principal at /dav/<user>/, their calendars under /dav/<user>/calendars/ and address books under
// /dav/<user>/contacts/, each a collection of entries a client puts and reads whole, kept by dav_store.  What a
// client of either asks is answered: PROPFIND, PROPPATCH, MKCALENDAR and extended MKCOL, the multiget and query
// REPORTs and sync-collection (RFC 6578), GET, PUT with its preconditions, and DELETE.
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace socketley::mail
{

class dav_store;

struct dav_request
{
    std::string method, path;
    std::function<std::string(std::string_view)> header;
    std::string body;
};

struct dav_reply
{
    int code{200};
    std::string type;
    std::string body;
    // Header lines beyond the type, each ended by CRLF.
    std::string headers;
};

// Whether a request is DAV's: under /dav/, or a PROPFIND of the root, where a client looks for its principal.
bool dav_path(std::string_view path, std::string_view method);

// The methods the DAV paths take, and the classes they are of, as OPTIONS and a 405 say them.
inline constexpr std::string_view dav_allow =
    "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, REPORT, MKCOL, MKCALENDAR";
inline constexpr std::string_view dav_classes = "1, 3, calendar-access, addressbook, extended-mkcol";

// One request of `user`, whose calendar address is `address`, answered by `done`.
void dav_serve(dav_store& store, std::shared_ptr<bool> alive, std::string user, std::string address, dav_request rq,
               std::function<void(dav_reply)> done);

}   // namespace socketley::mail
