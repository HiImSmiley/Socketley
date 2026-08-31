cmake_minimum_required(VERSION 3.20)
project(socketley_sdk CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "Socketley requires Linux (io_uring, kernel 5.19+)")
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
    "${CMAKE_CURRENT_SOURCE_DIR}/../socketley/daemon/*.cpp"
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
    # ── Basic examples ───────────────────────────────────────────────

    # Header-only daemon control (no library needed)
    add_executable(daemon_control examples/basic/daemon_control.cpp)
    target_include_directories(daemon_control PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/../include/linux"
    )

    # Engine examples (need libsocketley_sdk)
    add_executable(echo_server examples/basic/echo_server.cpp)
    target_link_libraries(echo_server PRIVATE socketley_sdk)

    add_executable(client examples/basic/client.cpp)
    target_link_libraries(client PRIVATE socketley_sdk)

    add_executable(tcp_proxy examples/basic/tcp_proxy.cpp)
    target_link_libraries(tcp_proxy PRIVATE socketley_sdk)

    add_executable(redis_cache examples/basic/redis_cache.cpp)
    target_link_libraries(redis_cache PRIVATE socketley_sdk)

    if(NOT SOCKETLEY_NO_LUA)
        add_executable(echo_server_lua examples/basic/echo_server_lua.cpp)
        target_link_libraries(echo_server_lua PRIVATE socketley_sdk)
    endif()

    # ── Custom runtime type (worker binary + manifest) ───────────────

    add_executable(greeter_worker examples/custom-type/greeter_worker.cpp)
    target_link_libraries(greeter_worker PRIVATE socketley_sdk)

    # ── Advanced examples ────────────────────────────────────────────

    add_executable(chat_server examples/advanced/chat_server.cpp)
    target_link_libraries(chat_server PRIVATE socketley_sdk)

    add_executable(reconnecting_client examples/advanced/reconnecting_client.cpp)
    target_link_libraries(reconnecting_client PRIVATE socketley_sdk)

    add_executable(heartbeat_server examples/advanced/heartbeat_server.cpp)
    target_link_libraries(heartbeat_server PRIVATE socketley_sdk)

    add_executable(tls_server examples/advanced/tls_server.cpp)
    target_link_libraries(tls_server PRIVATE socketley_sdk)

    add_executable(http_file_server examples/advanced/http_file_server.cpp)
    target_link_libraries(http_file_server PRIVATE socketley_sdk)

    # ── Project examples (sdk/examples/projects/) ────────────────────
    # Each directory is a small runnable project; see its README.md.

    add_executable(jobqueue_jobd examples/projects/jobqueue/jobd.cpp)
    target_link_libraries(jobqueue_jobd PRIVATE socketley_sdk)

    # cross-platform: needs only the client header
    add_executable(jobqueue_worker examples/projects/jobqueue/worker.cpp)
    target_include_directories(jobqueue_worker PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/../include/linux")

    add_executable(chatroom_chatd examples/projects/chatroom/chatd.cpp)
    target_link_libraries(chatroom_chatd PRIVATE socketley_sdk)

    add_executable(chatroom_cli examples/projects/chatroom/chat_cli.cpp)
    target_include_directories(chatroom_cli PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/../include/linux")
    find_package(Threads REQUIRED)
    target_link_libraries(chatroom_cli PRIVATE Threads::Threads)

    add_executable(edge_app examples/projects/edge/app.cpp)
    target_link_libraries(edge_app PRIVATE socketley_sdk)

    add_executable(edge_gateway examples/projects/edge/gateway.cpp)
    target_link_libraries(edge_gateway PRIVATE socketley_sdk)
endif()
