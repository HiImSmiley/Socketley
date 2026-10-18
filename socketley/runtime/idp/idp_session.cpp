#include "idp_session.h"

#include <charconv>
#include <chrono>
#include <fstream>
#include <sstream>

#include <sys/stat.h>

#include "idp_instance.h"
#include "idp_logic.h"
#include "../../shared/util/logging.h"
#include "../../shared/json/json_doc.h"
#include "../storage/s3_federation.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/util/wall_clock.h"
#include "../../shared/http/cookie.h"

namespace socketley::idp
{


session_verifier::session_verifier() = default;
session_verifier::~session_verifier() = default;

void session_verifier::configure(std::string_view idp_runtime)
{
    m_path = idp_runtime.empty() ? std::string() : idp_jwks_path(idp_runtime);
    m_issuer.clear();
    m_keys.reset();
    m_stamp.reset();
    m_checked = 0;
    m_seen.clear();
}

void session_verifier::reload()
{
    // The provider's file, looked at once a second, and read again only when it changed.
    const int64_t now = wall::now_sec();
    if (m_stamp && now == m_checked)
        return;
    m_checked = now;
    const socketley::file_stamp stamp = socketley::file_stamp::of(m_path);
    if (stamp == m_stamp)
        return;
    m_stamp = stamp;
    std::string text;
    const bool read = socketley::read_whole_file(m_path, text);
    socketley::json::jvalue doc;
    std::string issuer, err;
    if (read && socketley::json::json_reader(text).document(doc))
        for (const auto& [k, v] : doc.members)
            if (k == "issuer" && v.k == socketley::json::jvalue::kind::string)
                issuer = v.s;
    auto keys = std::make_unique<socketley::storage::jwks_keys>();
    if (issuer.empty() || !socketley::storage::parse_jwks(text, *keys, err))
    {
        // Kept as it was: a provider being restarted rewrites its file, and its sessions are no less valid meanwhile.
        if (!m_keys)
            LOG_WARN(("idp: " + m_path + " holds no provider's key yet; no session is taken until it does").c_str());
        return;
    }
    if (issuer != m_issuer)
        m_seen.clear();
    m_issuer = std::move(issuer);
    m_keys = std::move(keys);
}

bool session_verifier::verified(std::string_view token, bool bearer, int64_t now, who& out)
{
    for (const auto& k : m_keys->keys)
    {
        claims c;
        std::string why;
        // An access token is never taken as a session, nor a session as one: each is verified for its typ.
        if (!m_seen.verify(k.key.get(), k.kid, bearer ? "at+jwt" : "session+jwt", m_issuer, token, now, c, why) ||
            (!bearer && c["aud"] != "session") || c["sub"].empty())
            continue;
        out = who{c["sub"], c["preferred_username"], c["email"], c["admin"] == "true"};
        return true;
    }
    return false;
}

bool session_verifier::check(std::string_view cookies, who& out)
{
    if (!enabled())
        return false;
    reload();
    if (!m_keys)
        return false;
    const int64_t now = wall::now_sec();
    return http::for_each_cookie(cookies, session_cookie_name,
                                 [&](std::string_view v) { return verified(v, false, now, out); });
}

bool session_verifier::check_bearer(std::string_view token, who& out)
{
    if (!enabled())
        return false;
    reload();
    return m_keys && !token.empty() && verified(token, true, wall::now_sec(), out);
}

std::string session_verifier::login_url(std::string_view return_to)
{
    if (!enabled())
        return {};
    reload();
    if (m_issuer.empty())
        return {};
    return m_issuer + "/login?rd=" + url_encode(return_to);
}

std::string session_verifier::logout_url(std::string_view return_to)
{
    if (!enabled())
        return {};
    reload();
    if (m_issuer.empty())
        return {};
    return m_issuer + "/logout?post_logout_redirect_uri=" + url_encode(return_to);
}

}   // namespace socketley::idp
