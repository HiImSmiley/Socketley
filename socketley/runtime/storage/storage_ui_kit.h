#pragma once
// The storage interface's look and helpers, which the daemon's dashboard and the webmail take as their own.
#include <string>
#include <string_view>

namespace socketley::storage
{

// The page's stylesheet.
std::string_view storage_ui_style();
// Its helpers -- elements, icons, themes, toasts, menus and dialogs -- as one block of script.
std::string storage_ui_kit();

}   // namespace socketley::storage
