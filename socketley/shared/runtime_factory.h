#pragma once
#include <memory>
#include <string_view>

#include "runtime_definitions.h"

class runtime_instance;

std::unique_ptr<runtime_instance> create_runtime(runtime_type type, std::string_view name);
