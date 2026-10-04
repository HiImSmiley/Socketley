// The web interface at /~ui/: one page, served from the binary, that browses, uploads to, shares from and plays
// what the runtime holds, through /~dav/ and /~share/ with the user's access key and secret.
#include "storage_run.h"

namespace socketley::storage
{

namespace
{

#include "storage_ui_page.inc"

}   // namespace

void storage_run::op_ui(const std::shared_ptr<conn>& c)
{
    const s3_request& r = c->req;
    if (r.method != "GET" && r.method != "HEAD")
    {
        app_reply(c, 405, "The interface is read only.\n");
        return;
    }
    response resp;
    resp.headers.emplace_back("Content-Type", "text/html; charset=utf-8");
    resp.headers.emplace_back("Cache-Control", "no-cache");
    resp.headers.emplace_back("Content-Security-Policy",
                              "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                              "media-src 'self' blob:; img-src 'self' blob: data:");
    resp.body_view = ui_page;
    resp.head_only = r.method == "HEAD";
    send_response(c, std::move(resp));
}

}   // namespace socketley::storage
