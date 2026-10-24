#pragma once
// What a mail client is told when it asks how to reach a mailbox: Thunderbird's autoconfig (config-v1.1.xml),
// Outlook's autodiscover (the POX schema, and the JSON that points at it), and an Apple configuration profile.
#include <cstdint>
#include <string>
#include <string_view>

namespace socketley::mail
{

// The host and ports a mailbox is reached on, 0 for a port the runtime does not open.
struct client_settings
{
    std::string hostname, email, domain;
    uint16_t imap{0}, imaps{0}, pop3{0}, pop3s{0}, submission{0}, submissions{0};
};

std::string thunderbird_autoconfig(const client_settings& s);
std::string outlook_autodiscover(const client_settings& s);
// The address Outlook's JSON lookup is sent on to, the POX document of the host it asked.
std::string outlook_autodiscover_json(std::string_view host);
// Unsigned, so a phone says it is not verified; its UUIDs made of the address, so a second download replaces the first.
std::string apple_mobileconfig(const client_settings& s);

// The address an autodiscover request's body names, empty for none.
std::string autodiscover_address(std::string_view body);

}   // namespace socketley::mail
