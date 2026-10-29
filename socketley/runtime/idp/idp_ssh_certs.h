#pragma once
// The SSH certificates an idp signed for people: each serial, whose it is, until when, and whether it is revoked, in
// <state>/idp/<name>.ssh-certs under a lock every shard takes, and beside it the KRL of the revoked ones that sshd's
// RevokedKeys reads, written again with every change and at start, so sshd always finds one.
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace socketley::idp
{

struct issued_cert
{
    uint64_t serial{0};
    // The account's id, which a new username does not change.
    std::string sub;
    uint64_t valid_before{0};
    bool revoked{false};
};

std::string ssh_certs_path(std::string_view idp);
std::string ssh_krl_path(std::string_view idp);

// `serial sub valid_before issued|revoked` a line; false for anything else, which is kept rather than overwritten.
bool parse_ssh_certs(std::string_view text, std::vector<issued_cert>& out);
std::string render_ssh_certs(const std::vector<issued_cert>& certs);

// The certificates read, changed by `change`, those past their time forgotten, and the file and the KRL of the
// authority `ca_blob` written again, under the lock; false with `why` when either cannot be read or written.
bool update_ssh_certs(std::string_view idp, std::string_view ca_blob, uint64_t now,
                      const std::function<void(std::vector<issued_cert>&)>& change, std::string& why);

}   // namespace socketley::idp
