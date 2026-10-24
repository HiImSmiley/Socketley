#pragma once

#include <memory>
#include <string>
#include <string_view>

#include "../shared/json/json_doc.h"

namespace socketley::mail
{

// The Lua of a template: its text as it is, {{ x }} the value of x, {{{ x }}} unescaped, {% code %} run where it
// stands; false with `why` where a {% is never closed. {{unsubscribe}} is kept for the runtime where `keep_unsubscribe`.
bool compile_template(std::string_view t, std::string_view name, bool keep_unsubscribe, std::string& code,
                      std::string& why);

// A campaign's templates and its script, filled in Lua for one recipient at a time.
class campaign
{
public:
    enum class part { subject, html, text };
    enum class result { written, skipped, failed, missing };
    struct message
    {
        std::string email, name, subject, html, text;
    };

    // {{unsubscribe}} is left to the runtime where `ad`; include() reads a file of a relative name from `dir`.
    campaign(bool ad, std::string dir);
    ~campaign();
    campaign(const campaign&) = delete;
    campaign& operator=(const campaign&) = delete;

    // false with `why` where a template or the script does not load, or the script fails as it runs.
    bool script(const std::string& path, std::string& why);
    bool add(part p, std::string_view name, std::string_view text, std::string& why);

    // A recipient's message: skipped with why where on_recipient says so, failed with why where Lua fails, and
    // missing with the name where `strict` and a name has no value.
    result fill(const json::jvalue& recipient, bool strict, message& out, std::string& why);

private:
    struct impl;
    std::unique_ptr<impl> m;
};

}   // namespace socketley::mail
