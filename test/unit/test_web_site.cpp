// What a web runtime reads off a request's path and a file's name: the path it names under --root, which it refuses,
// and which files a build stamped so a browser may keep them a year.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <string>

#include "shared/http/site_path.h"
#include "runtime/web/web_site.h"

namespace
{
std::string plain(std::string_view raw)
{
    std::string out;
    return socketley::http::site_path(raw, out) ? out : std::string("REFUSED");
}
}   // namespace

TEST_CASE("a path is decoded and made plain, its trailing slash kept")
{
    CHECK(plain("/") == "/");
    CHECK(plain("//") == "/");
    CHECK(plain("/a/b") == "/a/b");
    CHECK(plain("/a//b///") == "/a/b/");
    CHECK(plain("/guide/") == "/guide/");
    CHECK(plain("/caf%C3%A9.html") == "/caf\xC3\xA9.html");
    CHECK(plain("/a%2Fb") == "/a/b");
    CHECK(plain("/100%") == "/100%");
    // A double slash at the front is a path here, never another host.
    CHECK(plain("//evil.example/x") == "/evil.example/x");
}

TEST_CASE("a path that would leave the root, or holds a NUL, names nothing")
{
    for (const char* raw : {"/..", "/../etc/passwd", "/a/../../b", "/%2e%2e/x", "/%2E%2E/x", "/a/%2e%2e/%2e%2e/x",
                            "/..%2fetc", "/.", "/a/./b", "/a%00.html", "x", "", "*", "http://h/x"})
        CHECK_MESSAGE(plain(raw) == "REFUSED", raw);
}

TEST_CASE("a hidden segment is hidden anywhere in the path, and .well-known is not")
{
    using socketley::http::hidden_path;
    CHECK(hidden_path("/.env"));
    CHECK(hidden_path("/.git/config"));
    CHECK(hidden_path("/a/.htpasswd"));
    CHECK(hidden_path("/a/.ssh/"));
    CHECK_FALSE(hidden_path("/.well-known/security.txt"));
    CHECK_FALSE(hidden_path("/a.b/c.d"));
    CHECK_FALSE(hidden_path("/"));
}

TEST_CASE("a name a build stamped with a hash is told from a name with a word or a date in it")
{
    using socketley::web::hashed_name;
    for (const char* stamped : {"main.3f9a1c2b.js", "index-B_x3-9Qa.js", "/_astro/page.Cx8kd2Lq.css",
                                "app.min.9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08.css",
                                "chunks/pages/index-a1b2c3d4e5f6a7b8.js", "font-4Kq9Zp2X.woff2", "vendor.0a1b2c3d.mjs"})
        CHECK_MESSAGE(hashed_name(stamped), stamped);
    for (const char* named : {"holiday-2024-beach.jpg", "logo-v2-final2.png", "jquery-3.7.1.min.js", "app.js",
                              "report-2024-final.pdf", "index.html", "style.css", "photo-12345678.jpg",
                              "abcdefgh.js", ".hidden12345678ab.js", "noext", "x.3f9a.js"})
        CHECK_FALSE_MESSAGE(hashed_name(named), named);
}

TEST_CASE("only a stamped asset is kept a year; a page and a document are always asked about")
{
    using socketley::web::cache_control;
    CHECK(cache_control("/a/main.3f9a1c2b.js", "application/javascript; charset=utf-8") ==
          "public, max-age=31536000, immutable");
    CHECK(cache_control("/a/style.3f9a1c2b.css", "text/css; charset=utf-8") == "public, max-age=31536000, immutable");
    CHECK(cache_control("/img/hero.3f9a1c2b.webp", "image/webp") == "public, max-age=31536000, immutable");
    CHECK(cache_control("/index.3f9a1c2b.html", "text/html; charset=utf-8") == "no-cache");
    CHECK(cache_control("/report.3f9a1c2b.pdf", "application/pdf") == "no-cache");
    CHECK(cache_control("/main.js", "application/javascript; charset=utf-8") == "no-cache");
}
