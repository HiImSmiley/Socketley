#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "../../socketley/shared/name_resolver.h"
#include "../../socketley/cli/arg_parser.h"

#include <algorithm>
#include <map>

// Transparent comparator map — mirrors runtime_manager::list() semantics
using name_map = std::map<std::string, int, std::less<>>;

static name_map make_names(std::initializer_list<std::string> ns)
{
    name_map m;
    int i = 0;
    for (const auto& n : ns)
        m[n] = i++;
    return m;
}

static std::vector<std::string> resolve(const char* cmdline, const name_map& names, size_t start = 1)
{
    parsed_args pa;
    pa.parse(cmdline);
    return resolve_names_impl(pa.args, pa.count, names, start);
}

static std::vector<std::string> sorted(std::vector<std::string> v)
{
    std::sort(v.begin(), v.end());
    return v;
}

// ─── Exact name matching ───

TEST_CASE("exact name matching")
{
    auto names = make_names({"api", "db", "worker"});

    SUBCASE("single name found")
    {
        auto r = resolve("stop api", names);
        CHECK(r == std::vector<std::string>{"api"});
    }

    SUBCASE("single name not found")
    {
        auto r = resolve("stop unknown", names);
        CHECK(r.empty());
    }

    SUBCASE("multiple names all found")
    {
        auto r = resolve("stop api db worker", names);
        CHECK(r == std::vector<std::string>{"api", "db", "worker"});
    }

    SUBCASE("multiple names some missing")
    {
        auto r = resolve("stop api ghost db", names);
        CHECK(r == std::vector<std::string>{"api", "db"});
    }

    SUBCASE("duplicate arg returned twice")
    {
        auto r = resolve("stop api api", names);
        CHECK(r == std::vector<std::string>{"api", "api"});
    }
}

// ─── Glob pattern matching ───

TEST_CASE("glob pattern matching")
{
    auto names = make_names({"srv1", "srv2", "srv10", "client1", "api-prod", "api-dev", "db-prod"});

    SUBCASE("star matches all")
    {
        auto r = sorted(resolve("stop *", names));
        auto expected = sorted({"api-dev", "api-prod", "client1", "db-prod", "srv1", "srv10", "srv2"});
        CHECK(r == expected);
    }

    SUBCASE("prefix glob")
    {
        auto r = sorted(resolve("stop srv*", names));
        CHECK(r == sorted({"srv1", "srv2", "srv10"}));
    }

    SUBCASE("suffix glob")
    {
        auto r = sorted(resolve("stop *-prod", names));
        CHECK(r == sorted({"api-prod", "db-prod"}));
    }

    SUBCASE("question mark single char")
    {
        auto r = sorted(resolve("stop srv?", names));
        CHECK(r == sorted({"srv1", "srv2"}));
    }

    SUBCASE("bracket range")
    {
        auto r = sorted(resolve("stop srv[12]", names));
        CHECK(r == sorted({"srv1", "srv2"}));
    }

    SUBCASE("glob matching nothing")
    {
        auto r = resolve("stop xyz*", names);
        CHECK(r.empty());
    }
}

// ─── Flag skipping ───

TEST_CASE("flag skipping")
{
    auto names = make_names({"api", "db", "worker"});

    SUBCASE("short flag skipped")
    {
        auto r = resolve("start api -i", names);
        CHECK(r == std::vector<std::string>{"api"});
    }

    SUBCASE("long flag skipped")
    {
        auto r = resolve("start api --verbose", names);
        CHECK(r == std::vector<std::string>{"api"});
    }

    SUBCASE("flags interleaved with names")
    {
        auto r = resolve("start api -i db --drain worker", names);
        CHECK(r == std::vector<std::string>{"api", "db", "worker"});
    }

    SUBCASE("all flags no names")
    {
        auto r = resolve("start -i --drain", names);
        CHECK(r.empty());
    }
}

// ─── Start parameter ───

TEST_CASE("start parameter")
{
    auto names = make_names({"stop", "api", "db"});

    SUBCASE("start=1 skips command name")
    {
        auto r = resolve("stop api db", names, 1);
        CHECK(r == std::vector<std::string>{"api", "db"});
    }

    SUBCASE("start=0 includes command name")
    {
        auto r = resolve("stop api", names, 0);
        CHECK(r == std::vector<std::string>{"stop", "api"});
    }

    SUBCASE("start beyond count")
    {
        auto r = resolve("stop api", names, 10);
        CHECK(r.empty());
    }
}

// ─── Edge cases ───

TEST_CASE("edge cases")
{
    SUBCASE("no args")
    {
        name_map names = make_names({"api"});
        auto r = resolve("", names);
        CHECK(r.empty());
    }

    SUBCASE("empty known names")
    {
        name_map names;
        auto r = resolve("stop api", names);
        CHECK(r.empty());
    }

    SUBCASE("both empty")
    {
        name_map names;
        auto r = resolve("", names);
        CHECK(r.empty());
    }
}

// ─── Full command line integration ───

TEST_CASE("full command line integration")
{
    auto names = make_names({"api-v1", "api-v2", "db", "worker"});

    SUBCASE("stop with glob")
    {
        auto r = sorted(resolve("stop api-*", names));
        CHECK(r == sorted({"api-v1", "api-v2"}));
    }

    SUBCASE("mixed exact and glob")
    {
        auto r = sorted(resolve("reload db api-*", names));
        CHECK(r == sorted({"db", "api-v1", "api-v2"}));
    }

    SUBCASE("glob with flag")
    {
        auto r = sorted(resolve("start api-* -i", names));
        CHECK(r == sorted({"api-v1", "api-v2"}));
    }
}
