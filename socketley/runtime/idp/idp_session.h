#pragma once
// A sign-in an idp runtime of this daemon gave, verified where it is used -- a proxy, a storage, the dashboard --
// against the key the provider publishes beside its state, with no request to the provider.
#include <optional>
#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include <string_view>

#include "idp_logic.h"
#include "../../shared/persist/file_stamp.h"

namespace socketley::storage
{
struct jwks_keys;
}

namespace socketley::idp
{

class session_verifier
{
public:
    session_verifier();
    ~session_verifier();
    session_verifier(const session_verifier&) = delete;
    session_verifier& operator=(const session_verifier&) = delete;

    // The idp runtime whose sessions are taken, by name; empty takes none.  `audiences` names, comma-separated, the
    // clients whose access tokens are taken as well, since a token the provider gave any other application is that
    // application's and not a key to this runtime.
    void configure(std::string_view idp_runtime, std::string_view audiences = {});
    bool enabled() const { return !m_path.empty(); }

    struct who
    {
        // The account's id, which never changes, and its username, which may.
        std::string sub;
        std::string username;
        std::string email;
        bool admin{false};
    };

    // The signed-in account a request's Cookie fields name, false when none does.
    bool check(std::string_view cookies, who& out);
    // The account an access token names, for an `Authorization: Bearer`, when the client it was given to is one of
    // the audiences configure() named.
    bool check_bearer(std::string_view token, who& out);

    // Where a browser signs in and is sent back to `return_to` from, empty while the provider's key is not known.
    std::string login_url(std::string_view return_to);
    // Where it signs out, and back to `return_to`.
    std::string logout_url(std::string_view return_to);

private:
    void reload();

    std::string m_path;
    std::string m_issuer;
    std::vector<std::string> m_audiences;
    // The clients a refused token was given to, each said once in the log.
    std::set<std::string> m_refused;
    std::unique_ptr<socketley::storage::jwks_keys> m_keys;
    std::optional<socketley::file_stamp> m_stamp;
    int64_t m_checked{0};
    bool verified(std::string_view token, bool bearer, int64_t now, who& out);
    // Sessions already verified, so a signature is checked once a session and not once a request.
    verified_tokens m_seen;
};

}   // namespace socketley::idp
