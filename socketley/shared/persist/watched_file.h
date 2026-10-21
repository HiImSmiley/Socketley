#pragma once
// A file read again whenever its stamp says it changed, kept as what it last parsed to: a runtime's users, rules and
// aliases, looked at each tick and read only when they changed.
#include <optional>
#include <string>

#include "file_stamp.h"
#include "read_file.h"

namespace socketley
{

template <class T>
class watched
{
public:
    void set_path(std::string path) { m_path = std::move(path); m_stamp.reset(); }
    const std::string& path() const { return m_path; }
    bool configured() const { return !m_path.empty(); }
    const T& value() const { return m_value; }

    // Read again if it changed since the last look; false with `why` when the new content is refused, the old
    // value then kept.
    template <class Parse>
    bool refresh(Parse&& parse, std::string& why);

private:
    std::string m_path;
    std::optional<socketley::file_stamp> m_stamp;
    T m_value;
};

template <class T>
template <class Parse>
bool watched<T>::refresh(Parse&& parse, std::string& why)
{
    if (m_path.empty())
        return true;
    const auto stamp = socketley::file_stamp::of(m_path);
    if (m_stamp && *m_stamp == stamp)
        return true;
    // Looked at once per change, refused or not, so a broken file is said once and not at every tick.
    m_stamp = stamp;
    std::string text;
    if (!socketley::read_file(m_path, text, {.missing_ok = false, .max_bytes = 16u << 20}, &why))
        return false;
    T next;
    if (!parse(next, text, why))
    {
        why = m_path + ": " + why;
        return false;
    }
    m_value = std::move(next);
    return true;
}

}   // namespace socketley
