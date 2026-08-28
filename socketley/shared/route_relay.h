#pragma once
// The verbs one runtime performs on another's routing state, over the one test
// of whether that runtime is in this process.
#include <string>
#include <string_view>

#include "conn_identity.h"
#include "worker_protocol.h"

class runtime_manager;
class server_instance;

namespace route_relay
{

// Installed by whoever can reach another process: the daemon resolves a name to
// a supervisor, a worker sends everything up.
struct sink
{
    virtual ~sink() = default;

    // data, close, write, drop and broadcast; nothing is answered.
    virtual void post(std::string_view to, std::string_view from,
                      worker_proto::route_op op, const conn_ref& ref,
                      std::string_view payload) = 0;

    // The one that waits; `err` is what the script is shown.
    virtual bool open(std::string_view target, const conn_ref& ref,
                      std::string_view origin, std::string& err) = 0;

    // `gone` has stopped; every other runtime must let go of its routes.
    virtual void forget(std::string_view gone) = 0;
};

// The server behind `name` if this process holds it, else null -- a placeholder
// answers as_server() with itself, so as_server() alone is not this question.
server_instance* local_server(runtime_manager* mgr, std::string_view name);

// Each verb takes the runtime it is performed ON, then the one asking.

// accept_routed on the target; true means it exists, is a running server and
// has been told, not that its on_connect ran.
bool open(runtime_manager* mgr, std::string_view to, std::string_view from,
          const conn_ref& ref, std::string& err);

// deliver_routed on the target.
void data(runtime_manager* mgr, std::string_view to, std::string_view from,
          const conn_ref& ref, std::string_view msg);

// release_routed on the target.
void close(runtime_manager* mgr, std::string_view to, std::string_view from,
           const conn_ref& ref);

// write_to_ref on the origin; "queued", the same contract send_to() has.
bool write(runtime_manager* mgr, std::string_view to, std::string_view from,
           const conn_ref& ref, std::string_view msg);

// drop_route on the origin.
void drop(runtime_manager* mgr, std::string_view to, std::string_view from,
          const conn_ref& ref);

// lua_broadcast on the origin; the one verb naming no connection.
bool broadcast(runtime_manager* mgr, std::string_view to, std::string_view from,
               std::string_view msg);

// Called from runtime_manager::stop and ::remove, which every departure goes
// through; both refuse in a replica, so this is the daemon by construction.
void forget(runtime_manager* mgr, std::string_view gone);

}   // namespace route_relay
