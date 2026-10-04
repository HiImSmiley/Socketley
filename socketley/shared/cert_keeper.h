#pragma once
// Certificates that change under a running listener: every server context's files are looked at again every few
// seconds and taken up when replaced, by an ACME renewal or by anyone, and a runtime given --acme has its
// certificate issued and renewed by `socketley acme issue`, run as a child of its worker.
#include <string>
#include <string_view>
#include <vector>

class tls_context;

namespace cert_keeper
{

// A server context's certificate and key, watched from tick() until the context goes.
void watch(tls_context* ctx, std::string_view cert_path, std::string_view key_path);
void unwatch(tls_context* ctx);

// This process's runtime's names; a short-lived self-signed certificate stands in until one is issued, so the
// listener starts and can answer the CA's challenge. False, with the reason, when the files cannot be written.
// A runtime on 443 proves its names over TLS-ALPN-01 on its own listener, and any other over HTTP-01.
bool prepare_acme(const std::vector<std::string>& domains, std::string_view email, std::string_view cert_path,
                  std::string_view key_path, bool on_443, std::string& err);

// Once per turn of the worker's loop; one clock read when nothing is due.
void tick();

// Where the answers to HTTP-01 challenges are kept, for every HTTP runtime to serve.
std::string challenge_dir();
// The answer to the challenge `token`, empty when there is none.
std::string challenge_answer(std::string_view token);
// The TLS-ALPN-01 certificate and key, PEM, for `name`, empty when none is waiting.
std::string tls_alpn_answer(std::string_view name);
std::string tls_alpn_path(std::string_view name);
inline constexpr std::string_view challenge_prefix = "/.well-known/acme-challenge/";

// Where --acme keeps the certificate and key of a runtime's first name.
std::string acme_cert_path(std::string_view domain);
std::string acme_key_path(std::string_view domain);

// A self-signed certificate for `domains`, valid `days`, written with its new key; false when it cannot be.
bool write_self_signed(const std::vector<std::string>& domains, int days, std::string_view cert_path,
                       std::string_view key_path);

}   // namespace cert_keeper
