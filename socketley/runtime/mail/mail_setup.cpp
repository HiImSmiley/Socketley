#include "mail_setup.h"

#include <cstdio>

namespace socketley::mail
{

namespace
{

std::string xml(std::string_view s)
{
    std::string out;
    for (const char c : s)
        switch (c)
        {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default: out += c;
        }
    return out;
}

// A UUID made of a name, the same each time it is made (an FNV-1a of it, laid out as UUID version 8).
std::string uuid_of(std::string_view name)
{
    uint64_t a = 14695981039346656037ull, b = 1099511628211ull ^ 0x5bd1e995;
    for (const unsigned char c : name)
    {
        a = (a ^ c) * 1099511628211ull;
        b = (b ^ c) * 14695981039346656037ull + 0x9e3779b97f4a7c15ull;
    }
    char out[40];
    std::snprintf(out, sizeof out, "%08X-%04X-8%03X-%04X-%012llX", static_cast<unsigned>(a >> 32),
                  static_cast<unsigned>((a >> 16) & 0xffff), static_cast<unsigned>(a & 0xfff),
                  static_cast<unsigned>(0x8000 | ((b >> 48) & 0x3fff)),
                  static_cast<unsigned long long>(b & 0xffffffffffffull));
    return out;
}

}   // namespace

std::string thunderbird_autoconfig(const client_settings& s)
{
    std::string out = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<clientConfig version=\"1.1\">\n  <emailProvider id=\"" +
                      xml(s.domain) + "\">\n    <domain>" + xml(s.domain) + "</domain>\n    <displayName>" +
                      xml(s.domain) + "</displayName>\n";
    const auto server = [&](const char* dir, const char* type, uint16_t port, const char* socket) {
        if (!port)
            return;
        out += std::string("    <") + dir + " type=\"" + type + "\">\n      <hostname>" + xml(s.hostname) +
               "</hostname>\n      <port>" + std::to_string(port) + "</port>\n      <socketType>" + socket +
               "</socketType>\n      <authentication>password-cleartext</authentication>\n"
               "      <username>%EMAILADDRESS%</username>\n    </" + dir + ">\n";
    };
    // The TLS ports first, which a client takes before the ones that begin in the clear.
    server("incomingServer", "imap", s.imaps, "SSL");
    server("incomingServer", "imap", s.imap, "STARTTLS");
    server("incomingServer", "pop3", s.pop3s, "SSL");
    server("incomingServer", "pop3", s.pop3, "STARTTLS");
    server("outgoingServer", "smtp", s.submissions, "SSL");
    server("outgoingServer", "smtp", s.submission, "STARTTLS");
    return out + "  </emailProvider>\n</clientConfig>\n";
}

std::string outlook_autodiscover(const client_settings& s)
{
    std::string out = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                      "<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\">\n"
                      "  <Response xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a\">\n"
                      "    <Account>\n      <AccountType>email</AccountType>\n      <Action>settings</Action>\n";
    const auto protocol = [&](const char* type, uint16_t port, bool tls_first) {
        if (!port)
            return;
        out += std::string("      <Protocol>\n        <Type>") + type + "</Type>\n        <Server>" + xml(s.hostname) +
               "</Server>\n        <Port>" + std::to_string(port) + "</Port>\n        <LoginName>" + xml(s.email) +
               "</LoginName>\n        <SPA>off</SPA>\n        <SSL>on</SSL>\n" +
               (tls_first ? "" : "        <Encryption>TLS</Encryption>\n") +
               "        <AuthRequired>on</AuthRequired>\n      </Protocol>\n";
    };
    if (s.imaps)
        protocol("IMAP", s.imaps, true);
    else
        protocol("IMAP", s.imap, false);
    if (!s.imaps && !s.imap)
    {
        if (s.pop3s)
            protocol("POP3", s.pop3s, true);
        else
            protocol("POP3", s.pop3, false);
    }
    if (s.submissions)
        protocol("SMTP", s.submissions, true);
    else
        protocol("SMTP", s.submission, false);
    return out + "    </Account>\n  </Response>\n</Autodiscover>\n";
}

std::string outlook_autodiscover_json(std::string_view host)
{
    std::string h;
    for (const char c : host)
        if (c != '"' && c != '\\' && static_cast<unsigned char>(c) >= 0x20)
            h += c;
    return "{\"Protocol\":\"AutodiscoverV1\",\"Url\":\"https://" + h + "/autodiscover/autodiscover.xml\"}";
}

std::string apple_mobileconfig(const client_settings& s)
{
    const bool imap = s.imaps || s.imap;
    const uint16_t in = s.imaps ? s.imaps : s.imap ? s.imap : s.pop3s ? s.pop3s : s.pop3;
    const bool in_tls = s.imaps || (!s.imap && s.pop3s);
    const uint16_t out_port = s.submissions ? s.submissions : s.submission;
    const std::string id = "online.socketley.mail." + s.email;
    const std::string b = "<true/>", n = "<false/>";
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
           "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
           "<plist version=\"1.0\">\n<dict>\n"
           "  <key>PayloadContent</key>\n  <array>\n    <dict>\n"
           "      <key>EmailAccountDescription</key><string>" + xml(s.email) + "</string>\n"
           "      <key>EmailAccountType</key><string>" + (imap ? "EmailTypeIMAP" : "EmailTypePOP") + "</string>\n"
           "      <key>EmailAddress</key><string>" + xml(s.email) + "</string>\n"
           "      <key>IncomingMailServerAuthentication</key><string>EmailAuthPassword</string>\n"
           "      <key>IncomingMailServerHostName</key><string>" + xml(s.hostname) + "</string>\n"
           "      <key>IncomingMailServerPortNumber</key><integer>" + std::to_string(in) + "</integer>\n"
           "      <key>IncomingMailServerUseSSL</key>" + (in_tls ? b : n) + "\n"
           "      <key>IncomingMailServerUsername</key><string>" + xml(s.email) + "</string>\n"
           "      <key>OutgoingMailServerAuthentication</key><string>EmailAuthPassword</string>\n"
           "      <key>OutgoingMailServerHostName</key><string>" + xml(s.hostname) + "</string>\n"
           "      <key>OutgoingMailServerPortNumber</key><integer>" + std::to_string(out_port) + "</integer>\n"
           "      <key>OutgoingMailServerUseSSL</key>" + (s.submissions ? b : n) + "\n"
           "      <key>OutgoingMailServerUsername</key><string>" + xml(s.email) + "</string>\n"
           "      <key>OutgoingPasswordSameAsIncomingPassword</key><true/>\n"
           "      <key>PayloadDisplayName</key><string>" + xml(s.email) + "</string>\n"
           "      <key>PayloadIdentifier</key><string>" + xml(id) + ".account</string>\n"
           "      <key>PayloadType</key><string>com.apple.mail.managed</string>\n"
           "      <key>PayloadUUID</key><string>" + uuid_of(id + ".account") + "</string>\n"
           "      <key>PayloadVersion</key><integer>1</integer>\n"
           "    </dict>\n  </array>\n"
           "  <key>PayloadDisplayName</key><string>Mail at " + xml(s.domain) + "</string>\n"
           "  <key>PayloadIdentifier</key><string>" + xml(id) + "</string>\n"
           "  <key>PayloadType</key><string>Configuration</string>\n"
           "  <key>PayloadUUID</key><string>" + uuid_of(id) + "</string>\n"
           "  <key>PayloadVersion</key><integer>1</integer>\n"
           "</dict>\n</plist>\n";
}

std::string autodiscover_address(std::string_view body)
{
    const size_t open = body.find("<EMailAddress>");
    if (open == std::string_view::npos)
        return {};
    const size_t from = open + 14, close = body.find("</EMailAddress>", from);
    if (close == std::string_view::npos || close - from > 320)
        return {};
    std::string a(body.substr(from, close - from));
    while (!a.empty() && (a.back() == ' ' || a.back() == '\n' || a.back() == '\r' || a.back() == '\t'))
        a.pop_back();
    while (!a.empty() && (a.front() == ' ' || a.front() == '\n' || a.front() == '\r' || a.front() == '\t'))
        a.erase(a.begin());
    return a.find_first_of("<>\"& ") == std::string::npos ? a : std::string();
}

}   // namespace socketley::mail
