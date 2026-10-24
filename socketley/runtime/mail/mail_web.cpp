#include "mail_web.h"

#include <openssl/sha.h>

#include <string_view>

#include "../storage/storage_ui_kit.h"
#include "../../shared/util/base64.h"

namespace socketley::mail
{

namespace
{

#include "mail_web_page.inc"

std::string sha256_of(std::string_view s)
{
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), md);
    return std::string(reinterpret_cast<const char*>(md), sizeof md);
}

}   // namespace

const web_page& webmail_page()
{
    static const web_page p = [] {
        web_page w;
        w.html = std::string(mail_web_page);
        // The storage interface's stylesheet and helpers go in where the page marks them, so the two look as one.
        for (const auto& [mark, text] : {std::pair<std::string_view, std::string>{"/*STYLE*/", std::string(socketley::storage::storage_ui_style())},
                                         {"/*KIT*/", socketley::storage::storage_ui_kit()}})
            if (const size_t at = w.html.find(mark); at != std::string::npos)
                w.html.replace(at, mark.size(), text);
        static constexpr char hex[] = "0123456789abcdef";
        const std::string digest = sha256_of(w.html);
        w.etag = "\"";
        for (size_t i = 0; i < 8; ++i)
        {
            w.etag += hex[static_cast<unsigned char>(digest[i]) >> 4];
            w.etag += hex[static_cast<unsigned char>(digest[i]) & 15];
        }
        w.etag += "\"";
        const size_t from = w.html.find("<script>") + 8, to = w.html.find("</script>", from);
        // Mail's own HTML is shown in a frame of the page's, sandboxed and without scripts, its remote images only once
        // the reader asks for them; nothing else is fetched from anywhere but here.
        w.csp = "default-src 'self'; script-src 'sha256-" +
                socketley::base64::encode(sha256_of(std::string_view(w.html).substr(from, to - from))) +
                "'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; connect-src 'self'; "
                "frame-src 'self' blob:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
        return w;
    }();
    return p;
}

}   // namespace socketley::mail
