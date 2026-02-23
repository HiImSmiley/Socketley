cmake_minimum_required(VERSION 3.20)
project(socketley_sdk CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "Socketley requires Linux (io_uring, kernel 5.11+)")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Optional: disable Lua/LuaJIT ─────────────────────────────────────────────
option(SOCKETLEY_NO_LUA "Build without LuaJIT/sol2 support" OFF)

# ── Collect sources ───────────────────────────────────────────────────────────
file(GLOB_RECURSE SDK_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/../socketley/shared/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../socketley/runtime/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../socketley/runtime/**/*.cpp"
)

add_library(socketley_sdk STATIC ${SDK_SOURCES})

# ── Include directories ───────────────────────────────────────────────────────
target_include_directories(socketley_sdk PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/../include/linux"
    "${CMAKE_CURRENT_SOURCE_DIR}/.."                    # repo root (socketley/...)
    "${CMAKE_CURRENT_SOURCE_DIR}/../thirdparty/sol2"
    "${CMAKE_CURRENT_SOURCE_DIR}/../thirdparty/luajit"
)

# ── Compile definitions ───────────────────────────────────────────────────────
if(SOCKETLEY_NO_LUA)
    target_compile_definitions(socketley_sdk PUBLIC SOCKETLEY_NO_LUA)
endif()

# ── Link libraries ────────────────────────────────────────────────────────────
find_library(LIBURING uring REQUIRED)
find_library(LIBSSL   ssl   REQUIRED)
find_library(LIBCRYPTO crypto REQUIRED)

target_link_libraries(socketley_sdk PUBLIC ${LIBURING} ${LIBSSL} ${LIBCRYPTO})

if(NOT SOCKETLEY_NO_LUA)
    find_library(LIBLUAJIT luajit
        PATHS "${CMAKE_CURRENT_SOURCE_DIR}/../thirdparty/luajit"
        NO_DEFAULT_PATH
    )
    if(NOT LIBLUAJIT)
        find_library(LIBLUAJIT luajit-5.1 luajit)
    endif()
    if(LIBLUAJIT)
        target_link_libraries(socketley_sdk PUBLIC ${LIBLUAJIT})
    else()
        message(WARNING "LuaJIT not found. Pass -DSOCKETLEY_NO_LUA=ON to build without Lua support.")
    endif()
endif()

# ── Install rules ─────────────────────────────────────────────────────────────
include(GNUInstallDirs)

install(TARGETS socketley_sdk
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../include/linux/socketley/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/socketley"
    FILES_MATCHING PATTERN "*.h"
)

# ── Examples ──────────────────────────────────────────────────────────────────
option(SOCKETLEY_BUILD_EXAMPLES "Build SDK examples" OFF)

if(SOCKETLEY_BUILD_EXAMPLES)
    # Header-only daemon control (no library needed)
    add_executable(daemon_control examples/daemon_control.cpp)
    target_include_directories(daemon_control PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/../include/linux"
    )

    # Engine examples (need libsocketley_sdk)
    add_executable(standalone_server examples/standalone_server.cpp)
    target_link_libraries(standalone_server PRIVATE socketley_sdk)

    if(NOT SOCKETLEY_NO_LUA)
        add_executable(standalone_server_lua examples/standalone_server_lua.cpp)
        target_link_libraries(standalone_server_lua PRIVATE socketley_sdk)
    endif()
endif()
