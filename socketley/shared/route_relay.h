#pragma once
// The five things one runtime does to another's routing state, and the single
// place that decides whether the other runtime can be reached by a call or only
// by a frame.
//
// ─── WHY THIS FILE EXISTS AT ALL ────────────────────────────────────────────
//
// server_instance resolves a runtime by name and then reaches for the object
// behind it in six places -- routing a connection out, releasing one, dropping
// one, delivering a message in, writing one back, and the broadcast that walks
// every connection routed here.  Every one of them is spelled
//
//     auto* rt = mgr->get(name);
//     if (auto* srv = rt ? rt->as_server() : nullptr) srv->VERB(...);
//
// and every one of them treats a null as "do nothing".  That was correct while
// a name that resolved to nothing meant a runtime that was not there.  It stops
// being correct the moment the runtime IS there and is merely somewhere else,
// which is now the DEFAULT: since 2313c26 a runtime gets its own worker process
// unless told otherwise, so the ordinary case walks into the branch written for
// the absent one and the route silently does nothing.
//
// Two different objects produce that null, and it is worth naming both because
// only one of them was ever documented:
//
//   IN A WORKER, `mgr->get(other)` is a replica_instance -- six fields and none
//   of the storage -- and as_server() answers null on purpose.  See the comment
//   on as_server(); this is the case it was written for.
//
//   IN THE DAEMON, `mgr->get(other)` for a runtime that lives in a worker is a
//   PLACEHOLDER, and a placeholder is a real server_instance.  as_server()
//   returns it, the call goes through, and it runs against an object holding no
//   connections and no script.  That one is worse than the null: it does
//   nothing and reports success while doing it.  as_server()'s own comment
//   flags it -- "whether calling into a placeholder is the right thing is a
//   separate question this does not touch" -- and this is that question,
//   answered.  A --daemon-process server routing to a worker server has been
//   silently dropping the route since the split landed; it predates every
//   change in this file's own branch.
//
// So the test is not "is there a server behind this name" but "is there one IN
// THIS PROCESS", and it is one function rather than six sites remembering it.
// Six sites is how the half-close hold got fixed four times.
//
// ─── WHAT IS SENT, AND WHAT IS ASKED ────────────────────────────────────────
//
// Four of the five verbs answer nothing and are posted as route_up/route_down
// frames.  `open` owes its script a true answer -- it is written `if
// self.route(fd, "other") then` -- so it is a question, and sink::open() is the
// one blocking call in this file.  worker_protocol.h's route_op comment gives
// the per-verb reasoning; it is not repeated here.
//
// ─── WHAT open() PROMISES, STATED EXACTLY ───────────────────────────────────
//
// True means: the target exists, is a server, is running, and has been told.
// It does NOT mean the target's on_connect has run, because the answer comes
// from the daemon's map rather than from the target process.
//
// That is deliberate and it is the cheaper half of a real choice.  Asking the
// target would make the daemon block on worker B while worker A blocks on the
// daemon, and a B that is itself mid-ask is then a deadlock -- bounded by two
// timeouts, so it would fail safe and fail badly.  The residual is a target
// that accepts the frame and cannot mint a handle, which unwinds by sending
// `drop` back and is indistinguishable, to a script, from a target that died
// one millisecond after answering yes.  A call cannot rule that out and this
// one does not pretend to.
#include <string>
#include <string_view>

#include "conn_identity.h"
#include "worker_protocol.h"

class runtime_manager;
class server_instance;

namespace route_relay
{

// What a process installs to reach runtimes it does not hold.  The daemon's
// implementation resolves a name to a supervisor; a worker's sends everything
// up and lets the daemon resolve it.  Neither is in this header, because the
// point of the seam is that server_instance does not know which one it has.
struct sink
{
    virtual ~sink() = default;

    // data, close, write and drop.  Nothing is answered; see route_op.
    virtual void post(std::string_view to, std::string_view from,
                      worker_proto::route_op op, const conn_ref& ref,
                      std::string_view payload) = 0;

    // The one that waits.  `err` is filled when this answers false, and is
    // what a script is shown -- so it names the runtime and the reason, in the
    // wording the in-process path uses for the same refusal.
    virtual bool open(std::string_view target, const conn_ref& ref,
                      std::string_view origin, std::string& err) = 0;

    // `gone` has stopped or been removed.  Told to every OTHER runtime, by
    // whoever knows -- see route_op::forget for why that cannot be the runtime
    // that is leaving.  A process that holds only its own runtime implements
    // this as nothing: it never stops another one.
    virtual void forget(std::string_view gone) = 0;
};

// The runtime behind `name`, if this process holds it and it is a server.
//
// Null covers all three of "no such runtime", "not a server" and "in another
// process", which is right because the caller does the same thing for the
// first two and hands the last to the sink.  Callers below make that split;
// nothing outside this file should have to.
server_instance* local_server(runtime_manager* mgr, std::string_view name);

// The five verbs.  Each takes the manager, the name of the runtime the verb is
// performed ON, and the name of the runtime asking -- in that order, so a call
// site reads as "do this to `to`, on behalf of `from`".
//
// `from` is not decoration on the four posted ones: the frame has to name it
// for the far end to have anything to put in accept_routed's origin_name, and
// for the daemon to refuse a worker addressing a runtime it has no business
// addressing.

// accept_routed on the target.  See what open() promises, above.
bool open(runtime_manager* mgr, std::string_view to, std::string_view from,
          const conn_ref& ref, std::string& err);

// deliver_routed on the target.
void data(runtime_manager* mgr, std::string_view to, std::string_view from,
          const conn_ref& ref, std::string_view msg);

// release_routed on the target.
void close(runtime_manager* mgr, std::string_view to, std::string_view from,
           const conn_ref& ref);

// write_to_ref on the origin.  Answers whether the write was accepted, which
// for a remote origin is whether the frame was posted -- the same "queued, not
// delivered" contract send_to() has in process, and send_ref's comment gives
// the argument for not upgrading it across a boundary.
bool write(runtime_manager* mgr, std::string_view to, std::string_view from,
           const conn_ref& ref, std::string_view msg);

// drop_route on the origin.
void drop(runtime_manager* mgr, std::string_view to, std::string_view from,
          const conn_ref& ref);

// "This runtime is going away."  Called from runtime_manager::stop and
// ::remove, which is the chokepoint every departure already goes through --
// including the cascade, which reaches it once per runtime it takes down.
// Both refuse outright in a replica, so this is the daemon by construction and
// does not need to ask which process it is in.
void forget(runtime_manager* mgr, std::string_view gone);

}   // namespace route_relay
