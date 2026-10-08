#pragma once
// A proxy's --auth: who may send a request through it, asked before anything of the request reaches a backend.
//
//   bearer:<file>   `Authorization: Bearer <token>`, with a token one line of the file
//   basic:<file>    HTTP Basic with an access key and its secret key, from a storage runtime's credentials file, of
//                   a user who is an admin there (a key outside any [user] is the default owner's, an admin)
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

    // The WWW-Authenticate field a refusal carries, with its line end.
    const std::string& challenge() const { return m_challenge; }

    // Failures from one address that bar it, and for how long from the first of them.
    static constexpr uint32_t tries = 5;
    static constexpr std::chrono::minutes window{15};

private:
    enum class kind { none, bearer, basic };
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

    struct misses
    {
        uint32_t count{0};
        std::chrono::steady_clock::time_point first{};
    };
    std::unordered_map<std::string, misses> m_misses;
};
