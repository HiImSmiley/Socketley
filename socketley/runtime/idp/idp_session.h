#pragma once
// A sign-in an idp runtime of this daemon gave, verified where it is used -- a proxy, a storage, the dashboard --
// against the key the provider publishes beside its state, with no request to the provider, and against its account's
// standing published beside the key, so a sign-in the provider no longer holds is refused here as well.
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
        // From the account's groups as they are now, not as the token was signed.
        bool admin{false};
        // When the sign-in was given, in milliseconds, for holds() to ask about again.
        int64_t issued_ms{0};
    };

    // The signed-in account a request's Cookie fields name, false when none does.
    bool check(std::string_view cookies, who& out);
    // The account an access token names, for an `Authorization: Bearer`, when the client it was given to is one of
    // the audiences configure() named.
    bool check_bearer(std::string_view token, who& out);
    // Whether a sign-in check() or check_bearer() took, the account `sub` given it at `given_ms`, still holds by its
    // account's standing now, and with `admin` whether the account is an admin now; for what lives past one request.
    bool holds(const std::string& sub, int64_t given_ms, bool& admin);

    // The provider's issuer, where a CLI signs in, empty while its key is not known.
    std::string issuer();
    // Where a browser signs in and is sent back to `return_to` from, empty while the provider's key is not known.
    std::string login_url(std::string_view return_to);
    // Where it signs out, and back to `return_to`.
    std::string logout_url(std::string_view return_to);

private:
    void reload();
    // The provider's standing file read again when it changed.
    void reload_standing();
    // The account's standing, the file looked at again for an id it does not hold, since one just made is new to it.
    const standing* standing_of(const std::string& sub);

    std::string m_path;
    std::string m_issuer;
    std::vector<std::string> m_audiences;
    // The clients a refused token was given to, each said once in the log.
    std::set<std::string> m_refused;
    std::unique_ptr<socketley::storage::jwks_keys> m_keys;
    std::optional<socketley::file_stamp> m_stamp;
    int64_t m_checked{0};
    // Every account's standing; empty, so every session is refused, until the file has been read once.
    std::string m_standing_path;
    standing_table m_standing;
    std::optional<socketley::file_stamp> m_standing_stamp;
    bool m_standing_read{false};
    bool verified(std::string_view token, bool bearer, int64_t now, who& out);
    // Sessions already verified, so a signature is checked once a session and not once a request; the standing is
    // looked up on every request, so a remembered session never outlives its account's sign-out.
    verified_tokens m_seen;
};

}   // namespace socketley::idp
