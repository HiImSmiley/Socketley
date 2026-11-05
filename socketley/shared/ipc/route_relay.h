#pragma once
// The verbs one runtime performs on another's routing state, over the one test
// of whether that runtime is in this process.
#include <string>
#include <string_view>

#include "../net/conn_identity.h"
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

    // open, data, close, write, drop and broadcast; nothing is answered, and
    // open arrives here as well as at open() because a sink may send it down
    // the connection's own path.
    virtual void post(std::string_view to, std::string_view from,
                      worker_proto::route_op op, const conn_ref& ref,
                      std::string_view payload) = 0;

    // `write` to each of `n` connections of `to`, the message the same for all; a sink that can carry them in one
    // frame per path overrides it.
    virtual void post_many(std::string_view to, std::string_view from, const conn_ref* refs, size_t n,
                           std::string_view msg)
    {
        for (size_t i = 0; i < n; ++i)
            post(to, from, worker_proto::route_op::write, refs[i], msg);
    }

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

// write_to_ref on the origin; "queued", the same contract queue_send() has.
bool write(runtime_manager* mgr, std::string_view to, std::string_view from,
           const conn_ref& ref, std::string_view msg);

// write_to_ref on the origin for each of `n` refs, which a broadcast reaching many of one origin's connections sends
// as one frame per path rather than one per connection.
void write_many(runtime_manager* mgr, std::string_view to, std::string_view from,
                const conn_ref* refs, size_t n, std::string_view msg);

// drop_route on the origin.
void drop(runtime_manager* mgr, std::string_view to, std::string_view from,
          const conn_ref& ref);

// broadcast on the origin; the one verb naming no connection, and false when the map says it does not run.
bool broadcast(runtime_manager* mgr, std::string_view to, std::string_view from,
               std::string_view msg);

// Called from runtime_manager::stop and ::remove, which every departure goes
// through; both refuse in a replica, so this is the daemon by construction.
void forget(runtime_manager* mgr, std::string_view gone);

}   // namespace route_relay
