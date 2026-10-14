#pragma once
// A proxy's --auth: who may send a request through it, asked before anything of the request reaches a backend.
//
//   bearer:<file>   `Authorization: Bearer <token>`, with a token one line of the file
//   basic:<file>    HTTP Basic with an access key and its secret key, from a storage runtime's credentials file, of
//                   a user who is an admin there (a key outside any [user] is the default owner's, an admin)
//   idp:<runtime>   the sign-in cookie of an idp runtime of this daemon, verified here against the key it publishes
//                   beside its state; a browser without one is sent to sign in and back
//
// Either file is read again when it changes, at most once a second; one that has gone or no longer parses refuses
// everybody until it is whole again. An address that keeps failing is refused even the right answer for a while,
// so guessing costs it the window and tells it nothing.
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace socketley::storage { class credential_set; }
namespace socketley::idp { class session_verifier; }

class proxy_auth
{
public:
    proxy_auth();
    ~proxy_auth();

    // Why `spec` is no --auth, empty when it is one.
    static std::string spec_error(std::string_view spec);

    // Takes up `spec`; an empty one lets everybody through.
    void configure(std::string_view spec, std::string_view runtime);
    bool enabled() const { return m_kind != kind::none; }

    enum class verdict { pass, refuse, barred };
    // The request's Authorization field (empty for none) from `client`; `retry_after` is set when barred.
    verdict check(std::string_view authorization, std::string_view client, int64_t& retry_after);

    // The id of the user an access key of the basic file signs for, empty for the default owner or no such key.
    std::string user_of(std::string_view access_key) const;

    // Whether this is an idp:<runtime> --auth, which a request's cookies answer rather than its Authorization.
    bool idp() const { return m_kind == kind::idp; }
    // The signed-in account the request's Cookie fields name: pass with its id, username and email set, or refuse.
    verdict check_session(std::string_view cookies, std::string& sub, std::string& username, std::string& email);
    // Where a browser signs in and is sent back to `return_to` from, empty while the provider's key is not known.
    std::string login_url(std::string_view return_to);

    // The WWW-Authenticate field a refusal carries, with its line end.
    const std::string& challenge() const { return m_challenge; }

    // Failures from one address that bar it, and for how long from the first of them.
    static constexpr uint32_t tries = 5;
    static constexpr std::chrono::minutes window{15};

private:
    enum class kind { none, bearer, basic, idp };
    void reload(std::chrono::steady_clock::time_point now);
    bool admit(std::string_view authorization) const;
    void missed(const std::string& key, std::chrono::steady_clock::time_point now);

    kind m_kind{kind::none};
    std::string m_file, m_runtime, m_challenge;
    std::chrono::steady_clock::time_point m_checked{};
    int64_t m_stamp{-1};
    bool m_loaded{false};
    std::vector<std::string> m_tokens;
    std::unique_ptr<socketley::storage::credential_set> m_keys;
    std::unique_ptr<socketley::idp::session_verifier> m_sessions;

    struct misses
    {
        uint32_t count{0};
        std::chrono::steady_clock::time_point first{};
    };
    std::unordered_map<std::string, misses> m_misses;
};
