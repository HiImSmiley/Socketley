#pragma once
// The webmail: one page of markup, style and script, in the storage interface's look, that reads and sends a user's
// mail with JMAP on the port the entrance reaches, signed in through the idp.
#include <string>

namespace socketley::mail
{

struct web_page
{
    // The page whole, its ETag, and a Content-Security-Policy that lets its one script run by its hash alone.
    std::string html;
    std::string etag;
    std::string csp;
    // The page gzipped once, and its own ETag, for a browser that takes gzip.
    std::string gz;
    std::string gz_etag;
};

const web_page& webmail_page();

}   // namespace socketley::mail
