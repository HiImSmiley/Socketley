#include "route_relay.h"

#include "../runtime/runtime_manager.h"
#include "../runtime/runtime_instance.h"
#include "../../runtime/server/server_instance.h"

namespace route_relay
{

server_instance* local_server(runtime_manager* mgr, std::string_view name)
{
    if (!mgr)
        return nullptr;

    auto* rt = mgr->get(name);
    if (!rt)
        return nullptr;

    // A placeholder IS a server_instance and answers as_server() with itself,
    // so as_server() alone is not the question "may I call into this".
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
    // No sink means no daemon around it, where dropping is the right answer.
}

}   // namespace

bool open(runtime_manager* mgr, std::string_view to, std::string_view from,
          const conn_ref& ref, std::string& err)
{
    if (auto* srv = local_server(mgr, to))
    {
        if (srv->accept_routed(ref, from) >= 0)
            return true;
        err.assign(1, '"').append(to).append("\" refused the connection");
        return false;
    }

    auto* sink = mgr ? mgr->route_sink() : nullptr;
    if (!sink)
    {
        // Says which of the two it is, because "there is no runtime called x"
        // would be a different and wrong diagnosis.
        err.assign(1, '"').append(to).append("\" is not in this process and there is "
                                             "no channel to reach it");
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
        // "Queued", as the in-process path answers: upgrading the remote one
        // would make it stronger than the local.
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

bool broadcast(runtime_manager* mgr, std::string_view to, std::string_view from,
               std::string_view msg)
{
    if (auto* srv = local_server(mgr, to))
    {
        srv->broadcast(msg);
        return true;
    }
    if (auto* sink = mgr ? mgr->route_sink() : nullptr)
    {
        sink->post(to, from, worker_proto::route_op::broadcast, conn_ref{}, msg);
        return true;
    }
    return false;
}

void forget(runtime_manager* mgr, std::string_view gone)
{
    if (auto* sink = mgr ? mgr->route_sink() : nullptr)
        sink->forget(gone);
}

}   // namespace route_relay
