#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "shared/runtime_factory.h"
#include "shared/runtime_instance.h"
#include "shared/state_persistence.h"
#include "shared/event_loop.h"

#include <filesystem>
#include <sys/wait.h>
#include <unistd.h>

// ─── Flag behavior ───

TEST_CASE("managed runtime flags")
{
    auto inst = create_runtime(runtime_server, "test-managed");
    REQUIRE(inst);

    SUBCASE("default state is not managed and not external")
    {
        CHECK_FALSE(inst->is_managed());
        CHECK_FALSE(inst->is_external());
        CHECK(inst->get_exec_path().empty());
    }

    SUBCASE("mark_managed sets managed, external, and exec_path")
    {
        inst->mark_managed("/usr/bin/test");
        CHECK(inst->is_managed());
        CHECK(inst->is_external());
        CHECK(inst->get_exec_path() == "/usr/bin/test");
    }

    SUBCASE("mark_external alone is not managed")
    {
        inst->mark_external();
        CHECK_FALSE(inst->is_managed());
        CHECK(inst->is_external());
        CHECK(inst->get_exec_path().empty());
    }

    SUBCASE("managed with empty exec_path")
    {
        inst->mark_managed("");
        CHECK(inst->is_managed());
        CHECK(inst->is_external());
        CHECK(inst->get_exec_path().empty());
    }
}

// ─── State persistence round-trip ───

TEST_CASE("managed runtime persistence")
{
    namespace fs = std::filesystem;

    char tmpdir[] = "/tmp/socketley-test-XXXXXX";
    REQUIRE(mkdtemp(tmpdir) != nullptr);
    fs::path tmp_path(tmpdir);

    state_persistence sp(tmp_path);

    SUBCASE("managed config JSON round-trip")
    {
        runtime_config cfg;
        cfg.name = "myapp";
        cfg.id = "abc123";
        cfg.type = runtime_server;
        cfg.port = 8080;
        cfg.was_running = true;
        cfg.external_runtime = true;
        cfg.managed = true;
        cfg.exec_path = "/usr/local/bin/myapp";
        cfg.pid = 12345;

        std::string json = sp.format_json_pretty(cfg);

        // Verify JSON contains managed fields
        CHECK(json.find("\"managed\": true") != std::string::npos);
        CHECK(json.find("\"exec_path\": \"/usr/local/bin/myapp\"") != std::string::npos);
        CHECK(json.find("\"was_running\": true") != std::string::npos);
        CHECK(json.find("\"external_runtime\": true") != std::string::npos);

        // Parse back
        runtime_config parsed;
        CHECK(sp.parse_json_string(json, parsed));
        CHECK(parsed.name == "myapp");
        CHECK(parsed.id == "abc123");
        CHECK(parsed.type == runtime_server);
        CHECK(parsed.port == 8080);
        CHECK(parsed.was_running == true);
        CHECK(parsed.external_runtime == true);
        CHECK(parsed.managed == true);
        CHECK(parsed.exec_path == "/usr/local/bin/myapp");
        CHECK(parsed.pid == 12345);
    }

    SUBCASE("plain external config has managed=false")
    {
        runtime_config cfg;
        cfg.name = "ext";
        cfg.id = "def456";
        cfg.type = runtime_server;
        cfg.port = 9000;
        cfg.external_runtime = true;
        cfg.managed = false;
        cfg.pid = 999;

        std::string json = sp.format_json_pretty(cfg);

        // Should NOT contain managed fields
        CHECK(json.find("\"managed\"") == std::string::npos);
        CHECK(json.find("\"exec_path\"") == std::string::npos);

        runtime_config parsed;
        CHECK(sp.parse_json_string(json, parsed));
        CHECK(parsed.external_runtime == true);
        CHECK(parsed.managed == false);
        CHECK(parsed.exec_path.empty());
    }

    SUBCASE("read_from_instance: plain external forces was_running=false")
    {
        auto inst = create_runtime(runtime_server, "plain-ext");
        REQUIRE(inst);
        inst->mark_external();
        inst->set_port(9000);

        auto cfg = sp.read_from_instance(inst.get());
        CHECK(cfg.external_runtime == true);
        CHECK(cfg.managed == false);
        CHECK(cfg.was_running == false);
    }

    SUBCASE("read_from_instance: managed preserves was_running semantics")
    {
        auto inst = create_runtime(runtime_server, "managed-ext");
        REQUIRE(inst);
        inst->mark_managed("/usr/bin/test");
        inst->set_port(9000);
        inst->set_pid(99999);

        auto cfg = sp.read_from_instance(inst.get());
        CHECK(cfg.external_runtime == true);
        CHECK(cfg.managed == true);
        CHECK(cfg.exec_path == "/usr/bin/test");
        CHECK(cfg.pid == 99999);
        // State is created (not running), so was_running = false
        // but it's NOT force-overwritten like plain external
        CHECK(cfg.was_running == false);
    }

    SUBCASE("save and load managed runtime from disk")
    {
        auto inst = create_runtime(runtime_server, "saved-managed");
        REQUIRE(inst);
        inst->mark_managed("/opt/bin/myapp");
        inst->set_port(7070);
        inst->set_pid(54321);

        sp.save_runtime(inst.get());

        auto configs = sp.load_all();
        REQUIRE(configs.size() == 1);
        CHECK(configs[0].name == "saved-managed");
        CHECK(configs[0].managed == true);
        CHECK(configs[0].exec_path == "/opt/bin/myapp");
        CHECK(configs[0].external_runtime == true);
        CHECK(configs[0].port == 7070);
        CHECK(configs[0].pid == 54321);
    }

    SUBCASE("exec_path with special characters round-trips")
    {
        runtime_config cfg;
        cfg.name = "special";
        cfg.id = "sp1";
        cfg.type = runtime_server;
        cfg.external_runtime = true;
        cfg.managed = true;
        cfg.exec_path = "/opt/my app/bin/serv\"er";

        std::string json = sp.format_json_pretty(cfg);
        runtime_config parsed;
        CHECK(sp.parse_json_string(json, parsed));
        CHECK(parsed.exec_path == "/opt/my app/bin/serv\"er");
    }

    fs::remove_all(tmp_path);
}

// ─── Fork+exec lifecycle ───

TEST_CASE("managed runtime fork+exec")
{
    auto inst = create_runtime(runtime_server, "fork-test");
    REQUIRE(inst);
    inst->mark_managed("/bin/true");

    CHECK(inst->get_state() == runtime_created);

    // event_loop is passed by reference but never used in the external path
    event_loop loop;

    SUBCASE("start forks and sets pid")
    {
        CHECK(inst->start(loop));
        CHECK(inst->get_state() == runtime_running);
        CHECK(inst->get_pid() > 0);

        pid_t child = inst->get_pid();

        // /bin/true exits immediately — wait for it
        int status = 0;
        pid_t ret = waitpid(child, &status, 0);
        CHECK(ret == child);
        CHECK(WIFEXITED(status));
        CHECK(WEXITSTATUS(status) == 0);

        // Clean up
        inst->stop(loop);
    }

    SUBCASE("stop on dead process is graceful")
    {
        CHECK(inst->start(loop));
        pid_t child = inst->get_pid();

        // Wait for /bin/true to exit
        waitpid(child, nullptr, 0);

        // stop sends SIGTERM to dead pid (ESRCH) — should not crash
        CHECK(inst->stop(loop));
        CHECK(inst->get_state() == runtime_stopped);
    }

    SUBCASE("stop+start cycle reaps zombie")
    {
        CHECK(inst->start(loop));
        pid_t first_child = inst->get_pid();

        // Wait for /bin/true to exit (becomes zombie until reaped)
        waitpid(first_child, nullptr, 0);

        CHECK(inst->stop(loop));
        CHECK(inst->get_state() == runtime_stopped);

        // Start again — should reap old zombie, fork new child
        CHECK(inst->start(loop));
        CHECK(inst->get_state() == runtime_running);
        CHECK(inst->get_pid() > 0);

        pid_t second_child = inst->get_pid();
        waitpid(second_child, nullptr, 0);

        inst->stop(loop);
    }

    SUBCASE("start with empty exec_path skips fork")
    {
        auto inst2 = create_runtime(runtime_server, "no-exec");
        REQUIRE(inst2);
        inst2->mark_managed("");

        CHECK(inst2->start(loop));
        CHECK(inst2->get_state() == runtime_running);
        // No fork happened — pid stays at 0
        CHECK(inst2->get_pid() == 0);

        inst2->stop(loop);
    }

    SUBCASE("start from stopped state works")
    {
        CHECK(inst->start(loop));
        pid_t c = inst->get_pid();
        waitpid(c, nullptr, 0);
        CHECK(inst->stop(loop));

        // Second start from stopped state
        CHECK(inst->start(loop));
        CHECK(inst->get_state() == runtime_running);
        CHECK(inst->get_pid() > 0);

        c = inst->get_pid();
        waitpid(c, nullptr, 0);
        inst->stop(loop);
    }

    SUBCASE("cannot start from running state")
    {
        CHECK(inst->start(loop));

        // Try starting again while running
        CHECK_FALSE(inst->start(loop));

        pid_t c = inst->get_pid();
        waitpid(c, nullptr, 0);
        inst->stop(loop);
    }

    SUBCASE("cannot stop from stopped state")
    {
        CHECK(inst->start(loop));
        pid_t c = inst->get_pid();
        waitpid(c, nullptr, 0);
        CHECK(inst->stop(loop));

        // Try stopping again
        CHECK_FALSE(inst->stop(loop));
    }
}

TEST_CASE("managed runtime env vars in child")
{
    // Fork+exec a shell snippet that writes env vars to a temp file
    namespace fs = std::filesystem;

    char tmpfile[] = "/tmp/socketley-env-test-XXXXXX";
    int fd = mkstemp(tmpfile);
    REQUIRE(fd >= 0);
    close(fd);

    // Create a small shell script that dumps the env vars
    std::string script_path = std::string(tmpfile) + ".sh";
    {
        FILE* f = fopen(script_path.c_str(), "w");
        REQUIRE(f);
        fprintf(f, "#!/bin/sh\necho \"$SOCKETLEY_MANAGED|$SOCKETLEY_NAME\" > %s\n", tmpfile);
        fclose(f);
        chmod(script_path.c_str(), 0755);
    }

    auto inst = create_runtime(runtime_server, "env-test");
    REQUIRE(inst);
    inst->mark_managed(script_path);

    event_loop loop;
    CHECK(inst->start(loop));
    CHECK(inst->get_pid() > 0);

    // Wait for child to finish
    pid_t c = inst->get_pid();
    int status = 0;
    waitpid(c, &status, 0);
    CHECK(WIFEXITED(status));

    // Read output
    FILE* f = fopen(tmpfile, "r");
    REQUIRE(f);
    char buf[256] = {};
    if (fgets(buf, sizeof(buf), f) == nullptr) { buf[0] = '\0'; }
    fclose(f);

    std::string output(buf);
    // Strip trailing newline
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r'))
        output.pop_back();

    CHECK(output == "1|env-test");

    inst->stop(loop);

    // Cleanup
    unlink(tmpfile);
    unlink(script_path.c_str());
}
