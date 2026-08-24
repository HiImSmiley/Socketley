#include "runtime_manager.h"
#include <algorithm>
#include "runtime_factory.h"
#include "event_loop.h"
#include "cluster_discovery.h"
#include "lua_context.h"
#include "route_table.h"
#include "logging.h"
#include <cctype>
#include <map>
#include <mutex>
#include <shared_mutex>

namespace
{

// ─── What stands in for a runtime this process does not hold ────────────────
//
// The daemon's placeholder for an out-of-process runtime is a real instance of
// the real type, and that is right there: it is persisted, inspected, cascaded
// and started, so it has to answer everything a runtime answers.
//
// A replica in a worker is not that.  It answers six fields and is never
// started, never persisted and never asked for a connection — and building it
// out of the real type would cost what the real type costs.  proxy_instance
// carries three fd-indexed tables of 65536 entries, about two megabytes before
// it has taken a connection, and a worker would hold one per proxy in the
// daemon, in every worker.  Ten workers and ten proxies is two hundred
// megabytes of tables nothing will ever index into.
//
// So the replica is the base class and a type tag.  Deliberately file-local:
// nothing outside this function can name the class, so nothing can be written
// that reaches past runtime_instance's interface into it — which is the same
// protection the daemon's placeholder gets from being a real instance, arrived
// at from the other direction.
//
// The three pure virtuals are the whole of the implementation.  setup() answers
// false because a replica cannot be started, and nothing calls it: start() on an
// out-of-process instance returns before setup(), which is what
// mark_out_of_process() is for.
class replica_instance final : public runtime_instance
{
public:
    replica_instance(runtime_type type, std::string_view name)
        : runtime_instance(type, name)
    {
        // Every read that distinguishes a runtime elsewhere from one here goes
        // through this flag — socketley.send routes on it, cmd_send routes on
        // it, and start()/stop() return before touching a ring because of it.
        // A replica is out of process by definition: it is the record of a
        // runtime in another one.
        mark_out_of_process();
    }

    void on_cqe(struct io_uring_cqe*) override {}
    bool setup(event_loop&) override { return false; }
    void teardown(event_loop&) override {}
};

} // namespace

void runtime_manager::mark_replica()
{
    m_replica = true;
}

void runtime_manager::install_replica(const std::vector<replica_entry>& entries)
{
    // Never under a script frame.  A replica the snapshot has dropped is freed
    // below, and a Lua callback is entitled to be holding the pointer get()
    // handed it — socketley.get and socketley.send both take one and use it
    // unlocked, on the rule that removal happens on this same thread.
    //
    // True today by construction: the only caller is the worker's control pump,
    // which runs between turns of its event loop with nothing of the script's on
    // the stack.  This is the belt for the day something calls it from inside a
    // callback instead, and the cost of taking it is that the replica is one
    // push interval older than it could be — which is the contract anyway.
    if (script_frame_live())
        return;

    // Freed with the lock released, like every other instance destruction in
    // this file: the map's mutex does not nest, and a destructor is entitled to
    // reach back in.  A replica holds no fds, no ring registration and no
    // interpreter, so this is a deallocation and nothing more.
    std::vector<std::unique_ptr<runtime_instance>> dropped;
    {
        std::unique_lock lock(mutex);

        for (const auto& e : entries)
        {
            auto it = runtimes.find(e.name);

            // A type change under one name means the daemon removed a runtime
            // and created another with the same name between two pushes.  The
            // object is rebuilt rather than re-tagged: get_type() is fixed at
            // construction, and a replica reporting the old type would be the
            // confidently-wrong answer this whole file is written against.
            if (it != runtimes.end() && it->second->get_type() != e.type)
            {
                dropped.push_back(std::move(it->second));
                runtimes.erase(it);
                it = runtimes.end();
            }

            if (it == runtimes.end())
            {
                auto inst = std::make_unique<replica_instance>(e.type, e.name);
                it = runtimes.emplace(e.name, std::move(inst)).first;
            }

            // Updated in place, so a pointer taken out of get() one statement
            // ago still names this object.  The state is stored straight rather
            // than through start()/stop(): those are transitions this process
            // is not making, and this is a report of one somebody else made.
            runtime_instance* inst = it->second.get();
            inst->set_port(e.port);
            inst->set_owner(e.owner);
            inst->set_group(e.group);
            inst->set_replicated_state(e.state);

            // The same two fields the daemon writes into ITS placeholder from a
            // stats frame, so reported_connection_count() answers the pushed
            // figure here for the same reason it does there.  The detail text is
            // empty because a replica has none: `stats` is a command the daemon
            // serves, not something a script reads off the map.
            inst->set_worker_stats({}, e.connections);
        }

        // Whatever the daemon no longer has.  Collected first because erasing
        // from a map while walking it is the one thing this loop must not get
        // wrong, and because the frees happen outside the lock.
        for (auto it = runtimes.begin(); it != runtimes.end();)
        {
            const bool still_there =
                std::any_of(entries.begin(), entries.end(),
                            [&](const replica_entry& e) { return e.name == it->first; });
            if (still_there)
            {
                ++it;
                continue;
            }
            dropped.push_back(std::move(it->second));
            it = runtimes.erase(it);
        }
    }

    dropped.clear();
}

// ─── ONE PLACE THAT DECIDES WHAT A RUNTIME MAY BE CALLED ────────────────────
//
// The rule was written out inside create() and nowhere else, so rename() -- the
// other way a runtime acquires a name, and the one `import` uses -- enforced
// nothing at all.  A name reaches the filesystem (state_persistence::config_path),
// a JSON document (cmd_ls, cmd_ps), a command line (the IPC protocol is one
// command per line) and a cluster file name.  This character set is what all
// four can carry without escaping.
//
// Restored here during the merge of fix/p0-crashes: it lived between create()
// and try_create(), and removing the duplicate create() took it with it.
bool runtime_manager::valid_name(std::string_view name)
{
    // A leading '-' is refused for the same class of reason as a leading '.':
    // not because the string is malformed, but because the CLI can never
    // address it again.  `create client --help` made a runtime called
    // "--help", and then `remove --help` parses as a flag and `remove <id>`
    // does not exist -- so it could be created and never deleted, and it sat
    // in `ls` until its state file was removed by hand.
    if (name.empty() || name.size() > 128 || name[0] == '.' || name[0] == '-')
        return false;
    for (char c : name)
    {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_' && c != '.')
            return false;
    }
    return true;
}

runtime_manager::create_result
runtime_manager::try_create(runtime_type type, std::string_view name)
{
    // ─── A replica's map is read-only, and this is where that is enforced ───
    //
    // A runtime built here would exist in this worker and in no other process:
    // not persisted, not listed by `ls`, not reachable by name from anywhere
    // else, and gone at the next snapshot.  Worse, it would be built against
    // this worker's ring by a manager whose map the daemon overwrites every
    // couple of seconds.
    //
    // Unreachable today -- socketley.create is one of the calls a worker
    // refuses, and it stays refused until there is a way to carry the request to
    // the daemon and bring an answer back.  This is the guard for the day
    // somebody removes the refusal without building that.
    //
    // It sits in try_create rather than in create(): create() is now a wrapper
    // over this, so a guard in the wrapper would be a guard one caller could
    // walk around.
    if (m_replica)
    {
        LOG_WARN("runtime_manager::create in a worker process: the map here is a "
                 "replica of the daemon's and cannot be written; nothing created");
        return create_result::internal;
    }

    std::unique_lock lock(mutex);

    if (!valid_name(name))
        return create_result::invalid_name;

    if (runtimes.find(name) != runtimes.end())
        return create_result::name_taken;

    auto instance = create_runtime(type, name);
    if (!instance)
        return create_result::internal;

    runtimes.emplace(std::string(name), std::move(instance));
    lock.unlock();

    // A name that can be routed to exists now, even if it has no port yet.
    publish_endpoints();
    return create_result::ok;
}

bool runtime_manager::start(std::string_view name, event_loop& loop)
{
    // See create().  Starting a replica would move a copy's state and bind
    // nothing anywhere.
    if (m_replica)
    {
        LOG_WARN("runtime_manager::start in a worker process: the map here is a "
                 "replica of the daemon's; nothing started");
        return false;
    }

    // Before, because a proxy resolves its backends inside setup(): the table
    // has to be in its hands by the time start() below reaches that code.
    publish_endpoints();

    // ─── The lock covers the lookup, and stops there ────────────────────────
    //
    // runtime_instance::start() runs the script's on_start, and a script is
    // entitled to call socketley.create / .start / .stop / .remove from it —
    // bringing a sub-server up as its parent starts is the obvious thing to
    // write.  Every one of those reaches back into this manager and asks for
    // this same mutex, create() and remove() in unique mode; `mutex` is a
    // std::shared_mutex, which is not recursive.  Holding it across the
    // callback therefore deadlocked the daemon's only event-loop thread against
    // itself: measured, both threads parked in futex_do_wait, the IPC socket
    // still accepting connections and answering none, which reads as a hang
    // rather than a crash and takes every other runtime the daemon serves with
    // it.  `create` never returned, and the operator's evidence was a daemon
    // that had to be killed.
    //
    // Taking the pointer out and calling through it unlocked is not a weakening
    // of the invariant: get() has always handed raw runtime_instance* to callers
    // that use them outside any lock — socketley.get, socketley.send and the
    // whole cross-runtime Lua surface are written that way — because removal
    // happens on this same thread, so nothing can free the object between these
    // two statements.  What changes is only that the callback is no longer
    // executed underneath a lock it is allowed to reach for.
    runtime_instance* inst = nullptr;
    {
        std::shared_lock lock(mutex);

        auto it = runtimes.find(name);
        if (it == runtimes.end())
            return false;

        inst = it->second.get();
    }

    const bool started = inst->start(loop);

    // And after, because this runtime is now a member others may route to.
    if (started)
        publish_endpoints();

    return started;
}

// ─── WHY EVERY CASCADE CARRIES A SET OF WHERE IT HAS BEEN ───────────────────
//
// `owner` is a plain string on the instance and nothing validates it:
// set_owner() is a bare setter, `attach --owner` writes whatever it is given,
// a script's socketley.create writes the creating runtime's name, and the
// daemon's restore writes back whatever the state file says.  So the ownership
// relation is a directed GRAPH, and it is free to contain a cycle — including
// the shortest one, a runtime that names itself.
//
// The three functions below walk that graph, and they used to walk it with no
// memory of where they had been.  A runtime that owns itself is its own child,
// so the recursion had no bottom.  Measured on the parent commit, two commands
// and no traffic at all:
//
//     socketley attach server selfown 18760 --owner selfown
//     socketley stop selfown
//     failed to connect to daemon          <- SIGSEGV, core dumped
//
// Every other runtime that daemon was holding went with it.  A two-runtime
// cycle (a owns b, b owns a) did the same, and `remove` on either shape did not
// crash but stopped answering — remove_children() recurses without exhausting
// the stack, so the daemon kept its socket and had to be killed.
//
// The owner is persisted and restored, so a cycle survives a restart: a daemon
// that met one was permanently one command away from dying again.  That is why
// the fix is here and not only at the setters — validating set_owner() would
// leave every cycle already written to disk arriving exactly as before.
//
// The set is threaded through rather than being a member because a cascade is
// one call tree: two of them must not share state, and a script's on_stop is
// entitled to start a second one from inside the first.
//
// It also makes the double walk below harmless.  The loop in stop_cascading()
// descends into a child's subtree and then calls stop_cascading() on the child,
// which descends into the same subtree again; without the set that was
// redundant work on every stop, and with it the second pass finds everything
// already marked and returns immediately.
bool runtime_manager::stop(std::string_view name, event_loop& loop)
{
    // See create().
    if (m_replica)
    {
        LOG_WARN("runtime_manager::stop in a worker process: the map here is a "
                 "replica of the daemon's; nothing stopped");
        return false;
    }

    cascade_seen seen;
    return stop_cascading(name, loop, seen);
}

bool runtime_manager::stop_cascading(std::string_view name, event_loop& loop,
                                     cascade_seen& seen)
{
    // The same shape as start(), for the same reason and with the same
    // reasoning: stop() runs the script's on_stop, which may call back in here.
    runtime_instance* inst = nullptr;
    {
        std::shared_lock lock(mutex);
        auto it = runtimes.find(name);
        if (it == runtimes.end())
            return false;
        inst = it->second.get();
    }
    if (!inst->stop(loop))
        return false;

    // Marked before descending, and the answer is what decides whether to
    // descend at all: a name already on this path has had its children walked
    // by the frame that put it there.
    if (!seen.insert(std::string(name)).second)
    {
        publish_endpoints();
        return true;
    }

    // Cascade to children based on child_policy
    auto children = get_children(name);
    for (const auto& child : children)
    {
        if (seen.count(child))
            continue;

        auto* child_inst = get(child);
        if (!child_inst) continue;

        if (child_inst->get_child_policy() == runtime_instance::child_policy::remove)
            remove_children_cascading(child, loop, seen);
        else
            stop_children_cascading(child, loop, seen);

        // Re-resolved: the walk above ran on_stop for a whole subtree, and a
        // script there is entitled to have removed this child.
        child_inst = get(child);
        if (!child_inst) continue;

        if (child_inst->get_child_policy() == runtime_instance::child_policy::remove)
        {
            if (child_inst->get_state() == runtime_running)
                stop_cascading(child, loop, seen);
            remove(child);
        }
        else
        {
            if (child_inst->get_state() == runtime_running)
                stop_cascading(child, loop, seen);
        }
    }

    // This runtime is no longer a routable group member, nor are any children
    // that went down with it.  One publish covers the lot.
    publish_endpoints();
    return true;
}

// A runtime instance is the storage for its own io_requests: the accept
// request, the timers, and — through the connection structs it owns — one set
// per connection.  io_uring keeps whatever addresses we hand it, so destroying
// an instance while any of its completions is still queued leaves the event
// loop reading freed memory; that is the segfault in event_loop::run() on
// `req->owner`.  Nulling req->owner in teardown() does not save us, because
// that convention only carries while there is still an object there to read the
// null out of.
//
// So removal never destroys.  The instance leaves the map — which is what ps,
// stats, start, rename and the rest look at, so it is gone as far as anyone can
// tell, and its name is free again — and lands here instead, to be freed once
// the loop reports that nothing it submitted is still in the ring.
void runtime_manager::retire(std::unique_ptr<runtime_instance> inst)
{
    if (!inst)
        return;

    // An instance that never reached setup() never put an io_request of its own
    // into the ring, so nothing in the RING can point into it and it goes now.
    // That covers create-then-reject-a-flag, and external runtimes, which do no
    // I/O of their own — and which have to keep being dropped untouched, the way
    // removal has always treated them, rather than being handed the SIGTERM
    // that stopping one sends.
    //
    // ─── The ring is not the only holder ───────────────────────────────────
    //
    // The C++ stack is another, and it is reachable from a script.
    // socketley.remove is bound in the interpreter every callback runs in, and a
    // subscriber calling it on its OWN runtime is standing on frames inside the
    // very lua_context this `return` would destroy — the unique_ptr is by value,
    // so returning here IS the free.  dispatch_publish re-resolves each name
    // before it delivers, which protects the other runtimes in its loop and
    // cannot protect the one that is executing.
    //
    // The reachable case is a script's TOP LEVEL removing its own runtime.  It
    // runs inside `create`, before the runtime has started and so before it has
    // armed anything; register_bindings() runs before the chunk, so
    // socketley.remove is already bound; and the top level runs inside a
    // lua_deadline::scope, so a frame is live for all of it.  Measured with
    // this line's guard deleted — the log's last word, then nothing:
    //
    //     [lua selfrm_top] TOP: about to remove myself
    //     Segmentation fault (core dumped)
    //
    // It was first found through a never-started runtime reached by a PUBLISH.
    // That way in is closed now — delivery requires a running runtime — and the
    // test moved to the top level rather than being deleted with it.  A running
    // runtime was never at risk and still is not: it has armed io, so it takes
    // the graveyard below.
    //
    // The deferral costs one health tick.  The instance is out of the map here
    // exactly as before — ps, stats, start and rename cannot see it and its name
    // is free — and reap_retired() frees it on the next sweep, with the stack
    // empty.
    if (!inst->has_armed_io() && !script_frame_live())
        return;

    // Every caller that can reach a running runtime stops it first, so this is
    // a backstop rather than a path.  It has to be here all the same: retiring
    // a runtime that is still armed would turn the old crash into something
    // quieter and worse — a runtime nobody can see or name that keeps serving
    // traffic for the rest of the daemon's life.  Done with the map lock
    // released, because on_stop may run Lua that calls back into the manager.
    if (inst->get_state() == runtime_running)
    {
        if (event_loop* loop = inst->get_event_loop())
            inst->stop(*loop);
        else
            LOG_WARN("removed a running runtime that has no event loop: "
                     "its fds stay open until the daemon exits");
    }

    // Read before the instance is handed on: this is the loop that can say when
    // the graveyard's older residents are finished with.
    event_loop* reap_loop = inst->get_event_loop();

    size_t retired = 0;
    {
        std::unique_lock lock(mutex);
        m_retired.push_back(std::move(inst));
        if (m_retired.size() >= m_retired_warn_at)
        {
            retired = m_retired.size();
            m_retired_warn_at = retired * 2;
        }
    }

    // Clear out whatever the ring has finished with.  This can never reach the
    // instance being retired right now — it has only just stopped, and its last
    // completions are still in the ring — which is why the daemon's periodic
    // timer reaps as well.  Without that second caller the most recently
    // removed runtime waits for the next removal, and the last one a daemon
    // ever removes waits for shutdown.
    if (reap_loop)
        retired -= std::min(retired, reap_retired(*reap_loop));

    // The warning below says nothing until 32 instances are waiting, and a
    // graveyard far below that already costs whole runtimes — a proxy is two
    // megabytes of fd-indexed tables before it has taken a single connection,
    // six once its connection pools are counted.  Nothing has ever read
    // retired_count(), so the size was unobservable between "empty" and "32";
    // this makes it readable for anyone who turns debug logging on.
    if (logger::g_level <= log_debug)
    {
        std::string waiting = "retired runtime instances waiting: "
                            + std::to_string(retired_count());
        LOG_DEBUG(waiting.c_str());
    }

    if (retired > 0)
    {
        std::string msg = "retired runtime instances the ring has not finished with: "
                        + std::to_string(retired);
        LOG_WARN(msg.c_str());
    }
}

// See the declaration.  One question, asked in the two places that would
// otherwise run a runtime_instance's destructor on the spot.
//
// Conservative on purpose: it says "a callback is running somewhere on this
// thread", not "a callback belonging to THIS instance is running".  The narrow
// question cannot be asked — a subscriber may publish, which runs another
// runtime's subscriber, which may remove the first one, so the instance whose
// frames are live is not always the instance being freed — and the cost of the
// broad answer is one health tick of deferral for a free that was going to
// happen anyway.
bool runtime_manager::script_frame_live()
{
#ifndef SOCKETLEY_NO_LUA
    return lua_deadline::in_callback();
#else
    // No interpreter in this build, so no callback can be on the stack and
    // nothing can reach remove() from inside one.
    return false;
#endif
}

void runtime_manager::enable_offthread_stats()
{
    m_offthread_stats.store(true, std::memory_order_relaxed);
}

void runtime_manager::publish_offthread_stats()
{
    if (!m_offthread_stats.load(std::memory_order_relaxed))
        return;

    // A shared lock, never an exclusive one.  Everything that mutates the map
    // runs on this same thread, so a shared lock is enough to keep the map
    // stable here, and taking it exclusively would make the event-loop thread
    // wait on whatever a reader is in the middle of.  Each instance guards its
    // own published text, and holds that guard for one move.
    std::shared_lock lock(mutex);
    for (auto& [name, instance] : runtimes)
        instance->publish_offthread_stats();
}

size_t runtime_manager::reap_retired(const event_loop& loop)
{
    // The daemon's health timer is the only fixed-period call the manager gets
    // on the event-loop thread, and the published figures have to be refreshed
    // from that thread or not at all — see
    // runtime_instance::publish_offthread_stats().  Hanging the sweep here
    // rather than adding a second timer keeps it on the one caller that already
    // ticks (every 2 s), and it costs nothing at all when nothing off-thread is
    // reading.  Before the graveyard lock, because shared_mutex does not nest.
    publish_offthread_stats();

    if (loop.owner_table_full())
        return 0;

    // Not from inside a callback.  retire() calls this on its way out, and
    // retire() is reachable from socketley.remove — so on that path this sweep
    // runs with Lua frames underneath it, and an instance those frames belong
    // to could be sitting in the graveyard.  The health timer calls this with
    // an empty stack and takes it then.
    //
    // ─── This half has no case anyone has managed to reach ──────────────────
    //
    // Said plainly so the next reader does not take it for proved.  The
    // shortcut in retire() above IS reachable and has a test that dies without
    // it; this one is the same rule applied two lines later, and the case it
    // would catch needs an instance that is in the graveyard, owes the ring
    // nothing, and has a live frame — all at once.  It could not be built:
    // inflight only falls when event_loop::run() dispatches completions, and it
    // is not dispatching while a Lua frame is on the stack, so an instance
    // stopped inside a callback still owes the ring whatever its teardown
    // submitted.  Two attempts are on record — a subscriber removing itself and
    // then a second runtime to force the sweep, and the same with a client whose
    // target refuses — and neither crashed with both guards deleted.
    //
    // It stays because it costs one predicated load on a path that runs every
    // two seconds, and because the rule it enforces is the one the class is
    // written around rather than the one instance that happens to reach it.
    // Removing it would mean re-deriving that argument the next time the
    // ordering changes.
    if (script_frame_live())
        return 0;

    std::vector<std::unique_ptr<runtime_instance>> doomed;
    {
        std::unique_lock lock(mutex);
        for (auto it = m_retired.begin(); it != m_retired.end(); )
        {
#ifdef SOCKETLEY_INVARIANTS
            // What this number is doing is the whole question when a graveyard
            // stops draining: anything but zero means the ring still owes this
            // instance a completion, and it cannot be freed until that lands.
            if (*it)
            {
                uint32_t by_type[op_type_count];
                loop.owner_inflight_breakdown(it->get(), by_type);
                std::string dbg = "reap: instance still owes the ring "
                                + std::to_string(loop.owner_inflight(it->get()))
                                + " completion(s):";
                for (uint8_t t = 0; t < op_type_count; ++t)
                    if (by_type[t])
                        dbg += " " + std::string(io_op_name(t)) + "=" + std::to_string(by_type[t]);
                LOG_DEBUG(dbg.c_str());
            }
#endif
            if (*it && loop.owner_inflight(it->get()) == 0)
            {
                doomed.push_back(std::move(*it));
                it = m_retired.erase(it);
            }
            else
            {
                ++it;
            }
        }
        // Let the warning threshold fall again, or a graveyard that grew once
        // would stay silent through every later growth up to that mark.
        if (m_retired.size() * 2 < m_retired_warn_at)
            m_retired_warn_at = std::max<size_t>(32, m_retired.size() * 2);
    }

    // Destructors out here: a runtime unwinding through Lua can reach back into
    // the manager, and this mutex does not nest.
    size_t freed = doomed.size();
    doomed.clear();
    return freed;
}

bool runtime_manager::remove(std::string_view name)
{
    // See create().  Removing a replica takes the copy out of this worker's map
    // and leaves the runtime running in the daemon, until the next snapshot puts
    // the copy back — an answer that is wrong twice.
    if (m_replica)
    {
        LOG_WARN("runtime_manager::remove in a worker process: the map here is a "
                 "replica of the daemon's; nothing removed");
        return false;
    }

    std::unique_ptr<runtime_instance> inst;
    {
        std::unique_lock lock(mutex);

        auto it = runtimes.find(name);
        if (it == runtimes.end())
            return false;

        inst = std::move(it->second);
        runtimes.erase(it);
    }

    retire(std::move(inst));

    // The name is free and the endpoint is gone; a proxy still routing to it
    // would otherwise keep the old port until the next membership change.
    publish_endpoints();
    return true;
}

void runtime_manager::free_retired()
{
    std::vector<std::unique_ptr<runtime_instance>> doomed;
    {
        std::unique_lock lock(mutex);
        doomed.swap(m_retired);
    }

    // The destructors run out here, with the map lock released: a runtime that
    // unwinds through Lua can reach back into the manager, and this mutex does
    // not nest.
    doomed.clear();
}

size_t runtime_manager::retired_count() const
{
    std::shared_lock lock(mutex);
    return m_retired.size();
}

bool runtime_manager::rename(std::string_view old_name, std::string_view new_name)
{
    // See create().  Nothing in the Lua API renames, so this is the guard for a
    // call site that does not exist yet.
    if (m_replica)
    {
        LOG_WARN("runtime_manager::rename in a worker process: the map here is a "
                 "replica of the daemon's; nothing renamed");
        return false;
    }

    std::unique_lock lock(mutex);

    // The same rule create() enforces, and it was missing here — see
    // valid_name().  This is the door `import` comes through.
    if (!valid_name(new_name))
        return false;

    auto it = runtimes.find(old_name);
    if (it == runtimes.end())
        return false;

    if (runtimes.find(new_name) != runtimes.end())
        return false;

    auto instance = std::move(it->second);
    runtimes.erase(it);
    instance->set_name(new_name);
    runtimes.emplace(std::string(new_name), std::move(instance));
    lock.unlock();

    publish_endpoints();
    return true;
}

std::vector<std::string> runtime_manager::get_children(std::string_view parent_name) const
{
    std::shared_lock lock(mutex);
    std::vector<std::string> children;
    for (const auto& [name, instance] : runtimes)
    {
        if (instance->get_owner() == parent_name)
            children.push_back(name);
    }
    return children;
}

// The public spellings start a fresh walk.  See the note above stop() for why
// every walk carries a set of the names it has already descended into.
void runtime_manager::stop_children(std::string_view parent_name, event_loop& loop)
{
    cascade_seen seen;
    seen.insert(std::string(parent_name));
    stop_children_cascading(parent_name, loop, seen);
}

void runtime_manager::remove_children(std::string_view parent_name, event_loop& loop)
{
    cascade_seen seen;
    seen.insert(std::string(parent_name));
    remove_children_cascading(parent_name, loop, seen);
}

void runtime_manager::stop_children_cascading(std::string_view parent_name,
                                              event_loop& loop, cascade_seen& seen)
{
    auto children = get_children(parent_name);
    for (const auto& child : children)
    {
        // Marked on the way in.  Without this a child that owns its own parent
        // sends the next line straight back here with the same argument.
        if (!seen.insert(child).second)
            continue;

        // Recurse: stop grandchildren first
        stop_children_cascading(child, loop, seen);
        stop_cascading(child, loop, seen);
    }
}

void runtime_manager::remove_children_cascading(std::string_view parent_name,
                                                event_loop& loop, cascade_seen& seen)
{
    auto children = get_children(parent_name);
    for (const auto& child : children)
    {
        if (!seen.insert(child).second)
            continue;

        // Recurse: remove grandchildren first
        remove_children_cascading(child, loop, seen);
        auto* inst = get(child);
        if (inst && inst->get_state() == runtime_running)
            stop_cascading(child, loop, seen);
        remove(child);
    }
}

void runtime_manager::stop_all(event_loop& loop)
{
    // Names, not pointers, and the lock released before any of them is stopped
    // — the same shape as dispatch_publish() below and for a superset of its
    // reason.  stop() runs on_stop, a script is entitled to call
    // socketley.create / .remove from there, and both take this mutex in unique
    // mode; holding it across the callback deadlocked the daemon against itself
    // in start(), and this is the same call one level up.  Here it would do it
    // while the daemon was trying to exit, which is a shutdown that never
    // completes and a process that needs SIGKILL.
    //
    // Names rather than pointers because this one is a loop: an on_stop that
    // removes another runtime erases it from the map, and a pointer collected
    // before that would be stopped afterwards.  get() re-checks, and answers
    // null for anything that has since gone.
    std::vector<std::string> names;
    {
        std::unique_lock lock(mutex);
        names.reserve(runtimes.size());
        for (auto& [name, instance] : runtimes)
            if (instance->get_state() == runtime_running)
                names.emplace_back(name);
    }

    for (const auto& name : names)
    {
        auto* inst = get(name);
        if (inst && inst->get_state() == runtime_running)
            inst->stop(loop);
    }
}

void runtime_manager::dispatch_publish(std::string_view cache_name, std::string_view channel, std::string_view message)
{
    // Names, not pointers — the same shape as dispatch_cluster_events() below,
    // for the same reason.  This used to snapshot a raw runtime_instance* for
    // every runtime and then call on_publish_dispatch() on each with the lock
    // released, on the strength of a comment asserting that subscribe callbacks
    // do not modify the map.  Nothing enforced that, and socketley.remove is
    // bound in the very VM those callbacks run in: one subscriber calling it
    // left every pointer behind it in the snapshot naming an instance the
    // manager had already taken out of the map, and a second removal — or the
    // daemon's next reap — is all it takes for that storage to go.  Re-resolving
    // the name means a runtime that left mid-dispatch is skipped rather than
    // dereferenced.
    //
    // Only runtimes that have a Lua VM are collected.  on_publish_dispatch()'s
    // whole body is "if (m_lua) m_lua->dispatch_publish(...)", so a runtime
    // without one has nowhere to deliver to, and a PUBLISH on a daemon of plain
    // C++ runtimes now costs one lock and a pointer test each instead of a
    // string copy and a virtual call each.  If on_publish_dispatch() is ever
    // overridden to do something that is not Lua, this filter has to go with it.
    // Out of this address space first, and before any Lua runs.  A subscriber is
    // allowed to call straight back into the manager — socketley.remove is bound
    // in the very VM these run in — and a frame already written to a socket
    // cannot be affected by what it does.
    if (m_publish_sink)
        m_publish_sink(cache_name, channel, message);

    // A runtime that lives in a worker process is skipped here on purpose; see
    // set_publish_sink().  The frame goes to the process that is serving the
    // traffic, and its subscribers run there.
    //
    // This used to say the placeholder "holds a fully loaded copy of the same
    // script, so it answers lua()".  It does not: load_lua_script() only asks
    // whether the file parses when the runtime is out of process, and builds no
    // interpreter at all.  The skip is still right; the reason given for it was
    // not.
    // ─── And only a runtime that is running ─────────────────────────────────
    //
    // A runtime that is not running executes no script.  That is the sentence
    // ebb6897 established for the timers and that severing subscriptions at
    // `stop` extended to this API — but severing at `stop` can only answer for
    // a runtime that stopped, and there is a second way to be not-running with
    // live registrations: never having started.  A script's top level runs when
    // the script is LOADED, which is `create`, so a top-level
    // socketley.subscribe is a live handler on a runtime `ls` reports as
    // Created.  Measured on the parent commit, one PUBLISH on the linked cache:
    //
    //     [lua] CREATED-STATE HIT msg=m1 state=created
    //
    // There is no event to sever at — nothing happened to that runtime between
    // the load and the publish — so this half is decided here, where the
    // delivery is, rather than where the registration is made.  self.send from
    // such a handler reaches the clients of a listener that was never opened.
    //
    // `failed` is covered by the same test and wants to be: a runtime whose
    // setup() refused is not serving anything either.
    std::vector<std::string> names;
    {
        std::shared_lock lock(mutex);
        names.reserve(runtimes.size());
        for (auto& [n, inst] : runtimes)
        {
            if (inst->get_state() != runtime_running)
                continue;
            if (inst->lua() && !inst->is_out_of_process())
                names.push_back(n);
        }
    }

    for (const auto& n : names)
    {
        // Re-resolve, then drop the lock again before the callback runs: a
        // subscriber can call straight back into the manager, and remove() takes
        // this same mutex exclusively — holding it across the callback would
        // deadlock rather than dangle, which is not an improvement.
        //
        // The state is re-read here as well as filtered above, and for the same
        // reason the name is re-resolved: socketley.stop is bound in the very VM
        // these run in, so one subscriber can take another down in the middle of
        // this fan-out.  Deciding once, before the loop, would deliver to it
        // afterwards anyway.
        runtime_instance* inst;
        {
            std::shared_lock lock(mutex);
            auto it = runtimes.find(n);
            if (it == runtimes.end()) continue;
            inst = it->second.get();
            if (inst->get_state() != runtime_running) continue;
        }

        inst->on_publish_dispatch(cache_name, channel, message);
    }
}

void runtime_manager::dispatch_cluster_events([[maybe_unused]] const std::vector<cluster_event>& events)
{
    // A remote daemon joined, left, or its groups changed — which is exactly
    // when the remote half of the endpoint table is stale.  Republish before
    // any Lua runs, so a callback that opens a connection routes on the new
    // membership rather than the one that just expired.
    publish_endpoints();

    // Snapshot names under read lock — same pattern as dispatch_publish().
    // Re-lookup each name before invoking callbacks so that if a prior callback
    // removed/stopped a runtime, we safely skip it instead of dereferencing
    // a dangling pointer.
    //
    // "or stopped" is what the state test below makes true.  The comment above
    // has always claimed it and only the map was ever checked, so a runtime a
    // previous callback stopped went on receiving the rest of the batch — and,
    // with no state test at all, so did one that had never been started: a
    // cluster callback is a callback, and dispatch_publish's sentence is not
    // about publishes.  A runtime that is not running executes no script.
    std::vector<std::string> names;
    {
        std::shared_lock lock(mutex);
        names.reserve(runtimes.size());
        for (auto& [n, _] : runtimes)
            names.push_back(n);
    }

#ifndef SOCKETLEY_NO_LUA
    for (auto& n : names)
    {
        runtime_instance* inst;
        {
            std::shared_lock lock(mutex);
            auto it = runtimes.find(n);
            if (it == runtimes.end()) continue;
            inst = it->second.get();
            if (inst->get_state() != runtime_running) continue;
        }

        auto* lua = inst->lua();
        if (!lua) continue;

        for (const auto& ev : events)
        {
            // Re-validate: a previous event callback may have removed this
            // runtime, or stopped it.  Both end this runtime's batch.
            {
                std::shared_lock lock(mutex);
                auto it = runtimes.find(n);
                if (it == runtimes.end()) break;
                if (it->second->get_state() != runtime_running) break;
            }

            switch (ev.kind)
            {
                case cluster_event::daemon_join:
                    if (lua->has_on_cluster_join())
                    {
                        sol::table dt = lua->state().create_table();
                        dt["name"] = ev.daemon_name;
                        // Look up host from remote daemons
                        if (m_cluster)
                        {
                            auto daemons = m_cluster->get_all_daemons();
                            for (const auto& rd : daemons)
                            {
                                if (rd.name == ev.daemon_name)
                                {
                                    dt["host"] = rd.host;
                                    break;
                                }
                            }
                        }
                        sol::protected_function_result r = lua->on_cluster_join()(dt);
                        if (SOCKETLEY_UNLIKELY(!r.valid()))
                        {
                            sol::error e = r;
                            fprintf(stderr, "%s on_cluster_join error: %s\n",
                                    lua_diag::tag(n).c_str(), e.what());
                        }
                    }
                    break;

                case cluster_event::daemon_leave:
                    if (lua->has_on_cluster_leave())
                    {
                        sol::table dt = lua->state().create_table();
                        dt["name"] = ev.daemon_name;
                        sol::protected_function_result r = lua->on_cluster_leave()(dt);
                        if (SOCKETLEY_UNLIKELY(!r.valid()))
                        {
                            sol::error e = r;
                            fprintf(stderr, "%s on_cluster_leave error: %s\n",
                                    lua_diag::tag(n).c_str(), e.what());
                        }
                    }
                    break;

                case cluster_event::group_change:
                    if (lua->has_on_group_change())
                    {
                        // Build members table
                        sol::table members = lua->state().create_table();
                        int mi = 1;
                        if (m_cluster)
                        {
                            // Local group members
                            {
                                std::shared_lock lock(mutex);
                                for (const auto& [_, rinst] : runtimes)
                                {
                                    if (rinst->get_group() == ev.group_name &&
                                        rinst->get_state() == runtime_running &&
                                        rinst->get_port() > 0)
                                    {
                                        sol::table m = lua->state().create_table();
                                        m["daemon"] = std::string(m_cluster->get_daemon_name());
                                        m["host"] = std::string(m_cluster->get_cluster_addr());
                                        m["port"] = rinst->get_port();
                                        members[mi++] = m;
                                    }
                                }
                            }
                            // Remote group members
                            auto daemons = m_cluster->get_all_daemons();
                            for (const auto& rd : daemons)
                            {
                                for (const auto& rt : rd.runtimes)
                                {
                                    if (rt.group == ev.group_name &&
                                        rt.state == "running" && rt.port > 0)
                                    {
                                        sol::table m = lua->state().create_table();
                                        m["daemon"] = rt.daemon_name;
                                        m["host"] = rt.host;
                                        m["port"] = rt.port;
                                        members[mi++] = m;
                                    }
                                }
                            }
                        }
                        sol::protected_function_result r = lua->on_group_change()(ev.group_name, members);
                        if (SOCKETLEY_UNLIKELY(!r.valid()))
                        {
                            sol::error e = r;
                            fprintf(stderr, "%s on_group_change error: %s\n",
                                    lua_diag::tag(n).c_str(), e.what());
                        }
                    }
                    break;
            }
        }
    }
#endif
}

void runtime_manager::publish_endpoints()
{
    // Never from a replica.  This function's whole job is to build the
    // authoritative answer to "where is every runtime" out of the local map and
    // push it into everything that routes — and in a worker the local map is a
    // copy, the authoritative answer arrives as a frame, and the copy is missing
    // the half of it that comes from the cluster.  See mark_replica().
    //
    // Guarded here rather than only at the five callers, because it is the
    // callers that make it hard: create/start/stop/remove/rename each call this
    // on their way out, and every one of them is already refused above — so this
    // line is unreachable through them, and is here for the sixth caller.
    if (m_replica)
        return;

    auto tbl = std::make_shared<endpoint_table>();

    // Every running member of every group, and what it declares — null when it
    // declares nothing, which is a fact about that group and not a member to be
    // skipped over.  Folded into one declaration per group below, once here
    // rather than once inside every proxy that forwards to the group.
    //
    // Ordered by member name, and by std::map rather than by sorting later,
    // because the fold decides the order of the Allow header a client is given
    // and that must not change with the order a hash map is walked in.
    std::map<std::string, std::map<std::string, std::shared_ptr<const route_table>>> group_members;

    {
        std::shared_lock lock(mutex);
        for (const auto& [name, inst] : runtimes)
        {
            const uint16_t port = inst->get_port();
            // A runtime listening on a unix socket has no port, and publishes
            // its socket path in the host field with the port left at 0.  That
            // is the same (path, 0) shape the proxy keys a unix backend by, and
            // it cannot be mistaken for a network endpoint for the same reason:
            // the path is absolute and no hostname is.
            const std::string_view listen_path = inst->get_listen_path();
            if (port == 0 && listen_path.empty())
                continue;

            // By name: no state filter, because this is what a backend given as
            // a bare runtime name resolves to, and that resolution happens while
            // the proxy itself is starting — before the target may have.
            tbl->set_name(name, listen_path.empty()
                                    ? runtime_endpoint{"127.0.0.1", port}
                                    : runtime_endpoint{std::string(listen_path), 0});

            // By group: running only, which is what get_by_group() filtered on.
            // A member that is merely configured has nothing listening.
            //
            // And `running` is not the whole of that question.  For a runtime
            // that binds in a worker, this side sets `running` when the child is
            // forked, not when it binds — so `running` alone put an address into
            // every gateway's group while nothing was accepting on it.  See
            // runtime_instance::endpoint_live(), which is the rest of the
            // question and is answered by whoever owns the child.  Always true
            // for a runtime that binds here, so nothing about the in-process
            // case changes.
            //
            // A unix listener is deliberately NOT offered as a group member.
            // The group path resolves a member to an AF_INET address per
            // request and has no route for anything else, so an entry it cannot
            // dial would take a turn of the round-robin and answer 503 with it.
            // This is what a unix runtime already got before it could be
            // published at all — a group has never carried one — and it is said
            // here so the exclusion is a decision rather than a leftover.  By
            // name and by explicit `unix:` path, both of which name exactly one
            // peer, it works.
            const std::string_view group = inst->get_group();
            const bool running = (inst->get_state() == runtime_running) &&
                                 inst->endpoint_live();
            if (!group.empty() && running && listen_path.empty())
                tbl->add_to_group(group, runtime_endpoint{"127.0.0.1", port});

            // And what this runtime says it will answer, if its script says so
            // at all.  The declaration belongs to the handler and is published
            // to whoever routes to it — see shared/route_table.h.  A runtime
            // that declares nothing gets no entry, and a proxy in front of it
            // forwards exactly as it did before this existed.
            // The worker's copy first: a runtime in another process has no
            // interpreter here, so lua() is null and the declaration can only
            // have come up the control socket.
            std::shared_ptr<const route_table> decl = inst->worker_routes();
            if (!decl)
            {
                const auto* lctx = inst->lua();
                if (lctx && lctx->has_routes())
                    decl = std::make_shared<const route_table>(lctx->declared_routes());
            }
            if (decl && !decl->empty())
                tbl->set_name_routes(name, decl);
            if (!group.empty() && running)
                group_members[std::string(group)][name] = std::move(decl);
        }
    }

    // One declaration per group, describing every member at once: a path only
    // some of them declare is dropped and a path all of them declare keeps the
    // union of their methods.  A single member that declares nothing therefore
    // leaves the group with nothing — which is the point, because a request to
    // the group may land on that member and it has told us nothing about what
    // it answers.  See route_table::merge_alternative.
    for (const auto& [group, members] : group_members)
    {
        route_table merged;
        bool started = false;
        for (const auto& [member, decl] : members)
        {
            if (!decl)
            {
                started = false;
                break;
            }
            if (!started)
            {
                merged = *decl;
                started = true;
            }
            else
            {
                merged.merge_alternative(*decl);
            }
        }
        if (started && !merged.empty())
            tbl->set_group_routes(group, std::make_shared<const route_table>(std::move(merged)));
    }

    // Remote members, from the cluster's last scan.  Same filter as
    // cluster_discovery::get_remote_group(), which this replaces on the
    // connection path: running, with a port, and reached at the host the remote
    // daemon advertised.
    if (m_cluster)
    {
        for (const auto& daemon : m_cluster->get_all_daemons())
        {
            for (const auto& rt : daemon.runtimes)
            {
                if (!rt.group.empty() && rt.state == "running" && rt.port > 0)
                    tbl->add_to_group(rt.group, runtime_endpoint{rt.host, rt.port});
            }
        }
    }

    // Hand the finished table out.  Immutable from here on, so every runtime
    // holds the same one and none of them copies it.
    {
        std::shared_lock lock(mutex);
        for (const auto& [_, inst] : runtimes)
            inst->set_endpoints(tbl);
    }

    // The other half of the same snapshot: not where a runtime is, but who
    // answers a request addressed to its name.  Rebuilt wholesale for the same
    // reason and at the same moments — a name that has just been taken, freed
    // or renamed must not still resolve to the object it used to mean.
    //
    // Running only.  A cache that is merely configured has no store loaded, and
    // a request that arrives for it is better answered "no such target" than
    // served out of an empty one.
    //
    // A worker's placeholder answers with its supervisor, which is a sink that
    // cannot serve inline: the request is parked and put on the control socket
    // instead of being computed on this thread.  Before that existed the
    // placeholder answered null and a runtime in another process was simply
    // unreachable by name.
    {
        std::shared_lock lock(mutex);
        m_requests.clear_sinks();
        for (const auto& [name, inst] : runtimes)
        {
            if (inst->get_state() != runtime_running)
                continue;
            if (auto* sink = inst->as_request_sink())
                m_requests.register_sink(name, sink);
        }
    }

    // The per-shard entries, from the one side that knows how many processes a
    // name has.  Outside the lock above for the reason the endpoint sink is:
    // this walks the daemon's supervisor map, and holding the runtime map
    // across that is how one runtime ends up waiting on another's child.
    //
    // After the by-name pass and never instead of it: a request that names the
    // runtime still goes to shard 0, which is what a caller asking for the
    // RUNTIME means.  See shared/shard_target.h.
    if (m_shard_sink_publisher)
        m_shard_sink_publisher(m_requests);

    // And to whatever lives outside this address space.  Last, and outside the
    // lock: the sink writes to sockets, and holding the runtime map across a
    // write to a process that may not be reading is how an unrelated runtime
    // ends up waiting on a proxy's child.
    if (m_endpoint_sink)
        m_endpoint_sink(*tbl);
}

void runtime_manager::set_endpoint_sink(std::function<void(const endpoint_table&)> sink)
{
    m_endpoint_sink = std::move(sink);
}

void runtime_manager::set_shard_sink_publisher(std::function<void(request_channel&)> sink)
{
    m_shard_sink_publisher = std::move(sink);
}

void runtime_manager::set_publish_sink(
    std::function<void(std::string_view, std::string_view, std::string_view)> sink)
{
    m_publish_sink = std::move(sink);
}

void runtime_manager::set_deliver_sink(
    std::function<bool(std::string_view, std::string_view)> sink)
{
    m_deliver_sink = std::move(sink);
}

bool runtime_manager::deliver_out_of_process(std::string_view name,
                                             std::string_view message) const
{
    return m_deliver_sink ? m_deliver_sink(name, message) : false;
}

void runtime_manager::set_worker_release_sink(std::function<void()> sink)
{
    m_worker_release_sink = std::move(sink);
}

void runtime_manager::release_workers() const
{
    if (m_worker_release_sink)
        m_worker_release_sink();
}

const runtime_manager::runtime_map& runtime_manager::list() const
{
    return runtimes;
}

runtime_instance* runtime_manager::get(std::string_view name)
{
    std::shared_lock lock(mutex);

    auto it = runtimes.find(name);
    if (it != runtimes.end())
        return it->second.get();
    return nullptr;
}

void runtime_manager::set_cluster_discovery(cluster_discovery* cd)
{
    m_cluster = cd;
}

cluster_discovery* runtime_manager::get_cluster_discovery() const
{
    return m_cluster;
}
