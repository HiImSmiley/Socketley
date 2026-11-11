#include "../../sdk/include/linux/socketley/capi.h"

#include <cstring>
#include <future>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <pthread.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "../cli/runtime_type_parser.h"
#include "../daemon/flag_handlers.h"
#include "../runtime/client/client_instance.h"
#include "../runtime/mcp/mcp_instance.h"
#include "../runtime/cache/cache_instance.h"
#include "../runtime/server/server_instance.h"
#include "../runtime/web/web_instance.h"
#include "../shared/json/json_doc.h"
#include "../shared/json/json_escape.h"
#include "../shared/loop/event_loop.h"
#include "../shared/loop/eventfd_wake.h"
#include "../shared/runtime/runtime_instance.h"
#include "../shared/runtime/runtime_manager.h"
#include "../shared/util/version.h"

namespace
{
char* dup_text(std::string_view s)
{
    char* out = static_cast<char*>(::malloc(s.size() + 1));
    if (out)
    {
        std::memcpy(out, s.data(), s.size());
        out[s.size()] = 0;
    }
    return out;
}

void set_err(char** err, std::string_view why)
{
    if (err)
        *err = dup_text(why);
}

// What the thread and its callers share, and what a reply still in the program's hands keeps alive.
struct engine_state final : io_handler
{
    event_loop loop;
    runtime_manager manager;
    std::thread::id thread;

    std::mutex mu;
    std::vector<std::function<void()>> queue;
    bool closed{false};

    int wake{-1};
    uint64_t wake_buf{0};
    io_request wake_req{};

    ~engine_state() override
    {
        if (wake >= 0)
            ::close(wake);
    }

    bool here() const { return std::this_thread::get_id() == thread; }

    bool arm() { return loop.submit_read(wake, reinterpret_cast<char*>(&wake_buf), sizeof(wake_buf), &wake_req); }

    void on_cqe(struct io_uring_cqe*) override
    {
        drain();
        manager.reap_retired(loop);
        if (!arm())
            loop.request_stop();
    }

    void drain()
    {
        std::vector<std::function<void()>> now;
        {
            const std::lock_guard<std::mutex> lock(mu);
            now.swap(queue);
        }
        for (auto& f : now)
            f();
    }

    // False once the engine has ended, and `f` then never runs.
    bool post(std::function<void()> f)
    {
        {
            const std::lock_guard<std::mutex> lock(mu);
            if (closed)
                return false;
            queue.push_back(std::move(f));
        }
        socketley::eventfd_bump(wake);
        return true;
    }

    // `f` on the engine's thread, waited for; false when the engine has ended.
    bool call(const std::function<void()>& f)
    {
        if (here())
        {
            f();
            return true;
        }
        std::promise<void> done;
        if (!post([&] { f(); done.set_value(); }))
            return false;
        done.get_future().wait();
        return true;
    }

    void main(std::promise<std::string>& started)
    {
        thread = std::this_thread::get_id();
        // A process's signals are its own: a thread that takes one of these from the host would end it or steal it.
        sigset_t set;
        sigemptyset(&set);
        for (const int s : {SIGPIPE, SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGCHLD, SIGWINCH, SIGUSR1, SIGUSR2})
            sigaddset(&set, s);
        pthread_sigmask(SIG_BLOCK, &set, nullptr);

        wake = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (wake < 0 || !loop.init())
        {
            started.set_value("this kernel gave no io_uring");
            return;
        }
        wake_req = {this, reinterpret_cast<char*>(&wake_buf), wake, sizeof(wake_buf), op_read};
        if (!arm())
        {
            loop.shutdown_ring();
            started.set_value("the ring took no first read");
            return;
        }
        started.set_value({});
        loop.run();
        // What was asked before the engine ended still runs, with the ring standing, as its callers are waiting.
        {
            const std::lock_guard<std::mutex> lock(mu);
            closed = true;
        }
        drain();
        manager.stop_all(loop);
        loop.deregister_owner(this);
        loop.shutdown_ring();
    }
};

}

struct skl_engine
{
    std::shared_ptr<engine_state> s;
    std::thread th;
};

struct skl_runtime
{
    std::shared_ptr<engine_state> s;
    std::string name;
};

struct skl_web_request
{
    std::shared_ptr<engine_state> s;
    web_answer answer;
};

struct skl_mcp_call
{
    std::shared_ptr<engine_state> s;
    socketley::mcp::tool_done done;
};

extern "C" {

const char* skl_version(void)
{
    return SOCKETLEY_VERSION;
}

void skl_free(char* text)
{
    ::free(text);
}

skl_engine* skl_engine_new(char** err)
{
    auto s = std::make_shared<engine_state>();
    std::promise<std::string> started;
    auto ready = started.get_future();
    std::thread th([s, &started] { s->main(started); });
    if (const std::string why = ready.get(); !why.empty())
    {
        th.join();
        set_err(err, why);
        return nullptr;
    }
    return new skl_engine{std::move(s), std::move(th)};
}

void skl_engine_free(skl_engine* engine)
{
    if (!engine)
        return;
    engine->s->loop.request_stop();
    engine->th.join();
    delete engine;
}

skl_runtime* skl_runtime_create(skl_engine* engine, const char* type, const char* name, const char* flags, char** err)
{
    if (!engine || !type || !name)
    {
        set_err(err, "engine, type and name are required");
        return nullptr;
    }
    engine_state& s = *engine->s;
    std::string why;
    bool made = false;
    const bool ran = s.call([&] {
        runtime_type t;
        if (!parse_runtime_type(type, t))
        {
            why = std::string("unknown runtime type: ") + type;
            return;
        }
        switch (s.manager.try_create(t, name))
        {
            case runtime_manager::create_result::ok: break;
            case runtime_manager::create_result::name_taken: why = std::string("name taken: ") + name; return;
            case runtime_manager::create_result::invalid_name: why = std::string("invalid name: ") + name; return;
            default: why = std::string("this library has no runtime of type ") + type; return;
        }
        runtime_instance* rt = s.manager.get(name);
        rt->set_runtime_manager(&s.manager);
        rt->set_event_loop(&s.loop);
        std::ostringstream text;
        {
            const flag_out_capture capture(text);
            made = apply_create_flags(rt, s.manager, flags ? flags : "");
        }
        if (!made)
        {
            why = text.str();
            while (!why.empty() && why.back() == '\n')
                why.pop_back();
            s.manager.remove(name);
        }
    });
    if (!ran || !made)
    {
        set_err(err, ran ? why : "the engine has ended");
        return nullptr;
    }
    return new skl_runtime{engine->s, name};
}

int skl_runtime_start(skl_runtime* runtime, char** err)
{
    if (!runtime)
        return -1;
    engine_state& s = *runtime->s;
    std::string why;
    const bool ran = s.call([&] {
        std::string refusal;
        runtime_instance* rt = s.manager.get(runtime->name);
        if (!rt)
            why = "the runtime is gone";
        else if (!s.manager.start(runtime->name, s.loop, &refusal) || rt->get_state() != runtime_running)
            why = refusal.empty() ? "it did not reach running; the reason is in the log" : refusal;
    });
    if (!ran || !why.empty())
    {
        set_err(err, ran ? why : "the engine has ended");
        return -1;
    }
    return 0;
}

int skl_runtime_stop(skl_runtime* runtime)
{
    if (!runtime)
        return -1;
    engine_state& s = *runtime->s;
    bool stopped = false;
    s.call([&] { stopped = s.manager.stop(runtime->name, s.loop); });
    return stopped ? 0 : -1;
}

char* skl_runtime_stats(skl_runtime* runtime)
{
    if (!runtime)
        return nullptr;
    engine_state& s = *runtime->s;
    char* out = nullptr;
    s.call([&] {
        if (runtime_instance* rt = s.manager.get(runtime->name))
            out = dup_text(rt->get_stats());
    });
    return out;
}

void skl_runtime_free(skl_runtime* runtime)
{
    if (!runtime)
        return;
    engine_state& s = *runtime->s;
    s.call([&] {
        s.manager.stop(runtime->name, s.loop);
        s.manager.remove(runtime->name);
    });
    delete runtime;
}

int skl_mcp_tool(skl_runtime* runtime, const char* name, const char* description, const char* input_schema_json,
                 skl_mcp_tool_fn fn, void* user, char** err)
{
    if (!runtime || !name || !fn)
    {
        set_err(err, "runtime, name and fn are required");
        return -1;
    }
    namespace mcp = socketley::mcp;
    engine_state& s = *runtime->s;
    std::string why;
    const bool ran = s.call([&] {
        runtime_instance* rt = s.manager.get(runtime->name);
        if (!rt || rt->get_type() != runtime_mcp)
        {
            why = "not a runtime of type mcp";
            return;
        }
        mcp::lua_tool t;
        t.def.name = name;
        t.def.description = description ? description : "";
        if (input_schema_json)
            t.def.input_schema = input_schema_json;
        t.kept = true;
        t.call = [state = runtime->s, fn, user](const socketley::json::jvalue& args, const mcp::caller& who,
                                                mcp::tool_done done) {
            auto* call = new skl_mcp_call{state, std::move(done)};
            std::string text;
            socketley::json::write_into(text, args);
            fn(user, call, text.c_str(), who.name.c_str());
        };
        static_cast<mcp_instance*>(rt)->declare_tool(std::move(t));
    });
    if (!ran || !why.empty())
    {
        set_err(err, ran ? why : "the engine has ended");
        return -1;
    }
    return 0;
}

namespace
{
// `set` on the engine's thread, for a runtime that has connections to tell of.
int on_connected_runtime(skl_runtime* runtime, char** err, const std::function<void(runtime_instance*, bool)>& set)
{
    if (!runtime)
    {
        set_err(err, "a runtime is required");
        return -1;
    }
    engine_state& s = *runtime->s;
    std::string why;
    const bool ran = s.call([&] {
        runtime_instance* rt = s.manager.get(runtime->name);
        if (!rt || (rt->get_type() != runtime_server && rt->get_type() != runtime_client))
            why = "not a runtime of type server or client";
        else
            set(rt, rt->get_type() == runtime_server);
    });
    if (!ran || !why.empty())
    {
        set_err(err, ran ? why : "the engine has ended");
        return -1;
    }
    return 0;
}

skl_connection connection_of(runtime_instance* rt, bool server, int fd)
{
    return server ? static_cast<server_instance*>(rt)->ref_for_fd(fd).serial : 1;
}
}

int skl_on_connect(skl_runtime* runtime, skl_connection_fn fn, void* user, char** err)
{
    return on_connected_runtime(runtime, err, [&](runtime_instance* rt, bool server) {
        rt->set_on_connect([rt, server, fn, user](int fd) { fn(user, connection_of(rt, server, fd)); });
    });
}

int skl_on_disconnect(skl_runtime* runtime, skl_connection_fn fn, void* user, char** err)
{
    return on_connected_runtime(runtime, err, [&](runtime_instance* rt, bool server) {
        rt->set_on_disconnect([rt, server, fn, user](int fd) { fn(user, connection_of(rt, server, fd)); });
    });
}

int skl_on_message(skl_runtime* runtime, skl_message_fn fn, void* user, char** err)
{
    return on_connected_runtime(runtime, err, [&](runtime_instance* rt, bool server) {
        if (server)
            rt->set_on_client_message([rt, fn, user](int fd, std::string_view m) {
                fn(user, connection_of(rt, true, fd), m.data(), m.size());
            });
        else
            rt->set_on_message([fn, user](std::string_view m) { fn(user, 1, m.data(), m.size()); });
    });
}

int skl_send(skl_runtime* runtime, skl_connection connection, const char* data, size_t length)
{
    if (!runtime || (!data && length))
        return -1;
    const std::shared_ptr<engine_state> state = runtime->s;
    auto send = [state, name = runtime->name, connection, body = std::string(data ? data : "", length)] {
        runtime_instance* rt = state->manager.get(name);
        if (!rt)
            return;
        if (rt->get_type() == runtime_server)
        {
            auto* srv = static_cast<server_instance*>(rt);
            if (srv->write_to_ref(conn_ref{conn_owner_key(srv->get_id()), connection}, body)) {}
        }
        else if (rt->get_type() == runtime_client)
        {
            if (static_cast<client_instance*>(rt)->lua_send(body)) {}
        }
    };
    if (state->here())
    {
        send();
        return 0;
    }
    return state->post(send) ? 0 : -1;
}

char* skl_cache_command(skl_runtime* runtime, const char* line, char** err)
{
    if (!runtime || !line)
    {
        set_err(err, "runtime and line are required");
        return nullptr;
    }
    engine_state& s = *runtime->s;
    std::string why;
    char* out = nullptr;
    const bool ran = s.call([&] {
        runtime_instance* rt = s.manager.get(runtime->name);
        if (!rt || rt->get_type() != runtime_cache)
            why = "not a runtime of type cache";
        else if (rt->get_state() != runtime_running)
            why = "the cache is not running";
        else
            out = dup_text(static_cast<cache_instance*>(rt)->execute(line));
    });
    if (!ran || !why.empty())
    {
        set_err(err, ran ? why : "the engine has ended");
        return nullptr;
    }
    return out;
}

int skl_web_handler(skl_runtime* runtime, const char* prefix, skl_web_fn fn, void* user, char** err)
{
    if (!runtime || !prefix || !fn || prefix[0] != '/')
    {
        set_err(err, "runtime, a prefix starting with / and fn are required");
        return -1;
    }
    engine_state& s = *runtime->s;
    std::string why;
    const bool ran = s.call([&] {
        runtime_instance* rt = s.manager.get(runtime->name);
        if (!rt || rt->get_type() != runtime_web)
        {
            why = "not a runtime of type web";
            return;
        }
        std::string p(prefix);
        while (p.size() > 1 && p.back() == '/')
            p.pop_back();
        static_cast<web_instance*>(rt)->add_handler(std::move(p), [state = runtime->s, fn, user](const web_handler_request& q, web_answer answer) {
            auto* request = new skl_web_request{state, std::move(answer)};
            fn(user, request, q.method.c_str(), q.path.c_str(), q.query.c_str(), q.headers.c_str(), q.body.data(), q.body.size());
        });
    });
    if (!ran || !why.empty())
    {
        set_err(err, ran ? why : "the engine has ended");
        return -1;
    }
    return 0;
}

void skl_web_reply(skl_web_request* request, int status, const char* headers, const char* body, size_t length)
{
    if (!request)
        return;
    const std::shared_ptr<engine_state> state = request->s;
    std::vector<std::pair<std::string, std::string>> fields;
    for (std::string_view left = headers ? headers : ""; !left.empty();)
    {
        const size_t end = left.find('\n');
        std::string_view line = left.substr(0, end);
        left = end == std::string_view::npos ? std::string_view{} : left.substr(end + 1);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        const size_t colon = line.find(':');
        if (colon == std::string_view::npos)
            continue;
        std::string_view value = line.substr(colon + 1);
        while (!value.empty() && value.front() == ' ')
            value.remove_prefix(1);
        fields.emplace_back(line.substr(0, colon), value);
    }
    auto answer = [request, status, fields = std::move(fields), text = std::string(body ? body : "", body ? length : 0)]() mutable {
        request->answer(status, std::move(fields), std::move(text));
        delete request;
    };
    if (state->here())
    {
        answer();
    }
    else
    {
        // A std::function wants a copyable callable, and the fields move only once it runs.
        auto held = std::make_shared<decltype(answer)>(std::move(answer));
        if (!state->post([held] { (*held)(); }))
            delete request;
    }
}

void skl_mcp_reply(skl_mcp_call* call, const char* text, int is_error)
{
    if (!call)
        return;
    const std::shared_ptr<engine_state> state = call->s;
    // A call whose client or runtime has gone hears this too: the reply path holds the connection weakly and drops it.
    auto answer = [call, body = std::string(text ? text : ""), is_error] {
        socketley::mcp::tool_result out;
        out.content = "[{\"type\":\"text\",\"text\":" + socketley::json::quote(body) + "}]";
        out.is_error = is_error != 0;
        call->done(true, std::move(out), {});
        delete call;
    };
    if (state->here())
        answer();
    else if (!state->post(answer))
        delete call;
}

}   // extern "C"
