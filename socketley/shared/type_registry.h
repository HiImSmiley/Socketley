#pragma once
// Runtime types beyond the built-in five, keyed by name, because the numeric
// id is assigned in registration order and is meaningless outside this
// process -- the name is what crosses a process boundary.
#include <cstdint>
#include <functional>
#include <memory>
#include <string_view>
#include "runtime_definitions.h"

class runtime_instance;

namespace type_registry
{

using factory = std::function<std::unique_ptr<runtime_instance>(std::string_view name)>;

// Everything below this id is a built-in whose value is fixed for ever.
inline constexpr uint8_t first_registered = 9;

// Claims a local id for `name`, refusing a built-in name, a name already
// holding a factory, and a name the id space cannot fit.
bool register_type(std::string_view name, factory make, runtime_type& out);

// Resolves a name to this process's id for it, built-ins included.
bool lookup(std::string_view name, runtime_type& out);

// lookup(), assigning a factory-less id on first sight, so a replica map can
// name a type this process cannot build.
bool intern(std::string_view name, runtime_type& out);

// register_type() for a name that may already hold one, which only the
// daemon's manifest loader does: a daemon holds a placeholder and must not
// build the caller's object even when the same binary registered one.
bool adopt(std::string_view name, factory make, runtime_type& out);

// Builds an instance from the registered factory, nullptr when `t` has none.
std::unique_ptr<runtime_instance> make(runtime_type t, std::string_view name);

// Whether `t` names a registered type rather than a built-in.
bool is_registered(runtime_type t);

} // namespace type_registry
