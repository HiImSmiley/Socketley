#include "route_relay.h"

#include "runtime_manager.h"
#include "runtime_instance.h"
#include "../runtime/server/server_instance.h"

namespace route_relay
{

server_instance* local_server(runtime_manager* mgr, std::string_view name)
{
    if (!mgr)
        return nullptr;

    auto* rt = mgr->get(name);
    if (!rt)
        return nullptr;

    // The whole point of the file, in one line.  A placeholder for a runtime
    // living in a worker IS a server_instance and answers as_server() with
    // itself, so as_server() alone is not the question "may I call into this".
    // Without this test the daemon's half of every verb below runs against an
    // object with no connections, no script and no ring, and reports that it
    // worked.
    if (rt->is_out_of_process())
        return nullptr;

    return rt->as_server();
}

namespace
{

// One place that turns "not here" into either a posted frame or nothing at all,
// so the four fire-and-forget verbs are four lines each and cannot disagree
// about the order of the two tests.
void post_or_drop(runtime_manager* mgr, std::string_view to, std::string_view from,
                  worker_proto::route_op op, const conn_ref& ref,
                  std::string_view payload)
{
    if (auto* sink = mgr ? mgr->route_sink() : nullptr)
        sink->post(to, from, op, ref, payload);
    // No sink is a manager with no daemon around it -- a unit test, or a
    // process that genuinely holds every runtime there is.  Dropping is then
    // the correct answer and the same one this code gave before the sink
    // existed, which is what makes installing it a strictly additive change.
}

}   // namespace

bool open(runtime_manager* mgr, std::string_view to, std::string_view from,
          const conn_ref& ref, std::string& err)
{
    if (auto* srv = local_server(mgr, to))
    {
        if (srv->accept_routed(ref, from) >= 0)
            return true;
        err = "\"" + std::string(to) + "\" refused the connection";
        return false;
    }

    auto* sink = mgr ? mgr->route_sink() : nullptr;
    if (!sink)
    {
        // Reached when the target is in another process and this one has no way
        // to speak to it.  Says which of the two it is, because "there is no
        // runtime called x" would be a different and wrong diagnosis.
        err = "\"" + std::string(to) + "\" is not in this process and there is "
              "no channel to reach it";
        return false;
    }
    return sink->open(to, ref, from, err);
}

void data(runtime_manager* mgr, std::string_view to, std::string_view from,
          const conn_ref& ref, std::string_view msg)
{
    if (auto* srv = local_server(mgr, to))
    {
        srv->deliver_routed(ref, msg);
        return;
    }
    post_or_drop(mgr, to, from, worker_proto::route_op::data, ref, msg);
}

void close(runtime_manager* mgr, std::string_view to, std::string_view from,
           const conn_ref& ref)
{
    if (auto* srv = local_server(mgr, to))
    {
        srv->release_routed(ref);
        return;
    }
    post_or_drop(mgr, to, from, worker_proto::route_op::close, ref, {});
}

bool write(runtime_manager* mgr, std::string_view to, std::string_view from,
           const conn_ref& ref, std::string_view msg)
{
    if (auto* srv = local_server(mgr, to))
        return srv->write_to_ref(ref, msg);

    if (auto* sink = mgr ? mgr->route_sink() : nullptr)
    {
        sink->post(to, from, worker_proto::route_op::write, ref, msg);
        // "Queued", which is what a write answers on this tree's in-process
        // path too: send_to() can still drop the connection for exceeding its
        // write-queue bound, and the caller learns that from the connection
        // going away rather than from this call.  Upgrading the remote answer
        // would make it stronger than the local one.
        return true;
    }
    return false;
}

void drop(runtime_manager* mgr, std::string_view to, std::string_view from,
          const conn_ref& ref)
{
    if (auto* srv = local_server(mgr, to))
    {
        srv->drop_route(ref);
        return;
    }
    post_or_drop(mgr, to, from, worker_proto::route_op::drop, ref, {});
}

}   // namespace route_relay
