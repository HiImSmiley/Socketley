#pragma once
#include <string>
#include <random>
#include <sstream>
#include <iomanip>

inline std::string generate_runtime_id()
{
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFF);

    uint32_t id = dist(gen);

    std::ostringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(6) << id;
    return ss.str();
}
