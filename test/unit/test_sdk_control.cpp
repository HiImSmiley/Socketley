// SDK compile test: control.h + attach.h (header-only, no library deps)
#include "socketley/control.h"
#include "socketley/attach.h"

// Verify all API symbols compile. We don't call them (no daemon running).
// Using decltype to verify function signatures exist without overload ambiguity.

static void verify_ctl_api()
{
    // These would call the daemon — just verify they compile
    if (false)
    {
        socketley::result r = socketley::ctl::command("test");
        r = socketley::ctl::command("/tmp/test.sock", "test");
        r = socketley::ctl::create("server", "test", "-p 9000");
        r = socketley::ctl::start("test");
        r = socketley::ctl::stop("test");
        r = socketley::ctl::remove("test");
        r = socketley::ctl::send("test", "msg");
        r = socketley::ctl::ls();
        r = socketley::ctl::ps();
        r = socketley::ctl::stats("test");
        r = socketley::ctl::show("test");
        r = socketley::ctl::reload("test");
        r = socketley::ctl::reload_lua("test");
        r = socketley::ctl::edit("test", "-p 9001");
        r = socketley::ctl::restart("test");
        r = socketley::ctl::ping();
        r = socketley::ctl::version();
        r = socketley::ctl::import_runtime("test", "{}");
        r = socketley::ctl::cluster_status();
        r = socketley::ctl::cluster_ls();
        r = socketley::ctl::cluster_show("peer");
        r = socketley::ctl::cache_mget("cache", {"a", "b"});
        r = socketley::ctl::cache_mset("cache", {{"a", "1"}, {"b", "2"}});
        (void)r.ok();
        r = socketley::ctl::cache_get("cache", "key");
        r = socketley::ctl::cache_set("cache", "key", "val");
        r = socketley::ctl::cache_del("cache", "key");
        r = socketley::ctl::cache_flush("cache");
        (void)r;
    }
}

static void verify_attach_api()
{
    if (false)
    {
        bool ok = socketley::daemon_attach("test", "server", 8080);
        ok = socketley::daemon_attach("test", "server", 8080, "owner-rt");
        (void)ok;
        (void)socketley::attach_error();
        socketley::daemon_detach("test");
    }
}

int main()
{
    verify_ctl_api();
    verify_attach_api();
    return 0;
}
