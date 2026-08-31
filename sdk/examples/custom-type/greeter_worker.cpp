// Socketley SDK — a registered runtime type's worker binary
//
// A custom type is a manifest the daemon reads plus this binary, which the
// daemon forks and execs like any other worker; no code of yours runs in the
// daemon's process.
//
// Build:
//   g++ -std=c++23 sdk/examples/custom-type/greeter_worker.cpp \
//       $(sdk/socketley-config --cflags --libs) -o /usr/local/lib/socketley/greeter-worker
//
// Install the manifest (greeter.toml beside this file) into the daemon's
// types directory, point its `exec` at the binary above, then:
//   socketley create greeter hi -p 9000 --greeting hello --repeat 2 -s
//   echo hi | nc -q1 127.0.0.1 9000        # -> hellohello

#include <socketley/worker.h>

#include <cctype>
#include <cstdint>
#include <memory>
#include <string>

#include <socketley/runtime/server.h>

namespace
{

// Deriving from server_instance buys the listener, TLS-free accept loop and
// connection tables; the type's own behaviour is this class.
class greeter final : public server_instance
{
public:
    explicit greeter(std::string_view name) : server_instance(name)
    {
        set_on_client_message([this](int fd, std::string_view)
        {
            std::string out;
            for (int i = 0; i < m_repeat; ++i)
                out += m_greeting;
            if (m_shout)
                for (char& c : out)
                    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            out += "\n";
            send_to(fd, out);
            ++m_greetings;
        });
    }

    // The daemon validated every key against the manifest schema, so this
    // side only has to read them.
    void apply_config(const std::vector<std::pair<std::string, std::string>>& in) override
    {
        m_extra = in;
        for (const auto& [k, v] : in)
        {
            if (k == "greeting")
                m_greeting = v;
            else if (k == "repeat")
                m_repeat = std::stoi(v);
            else if (k == "shout")
                m_shout = (v == "true");
        }
    }

    void capture_config(std::vector<std::pair<std::string, std::string>>& out) const override
    {
        out = m_extra;
    }

    // Travels to the daemon in the stats frame's free-text detail, so
    // `socketley stats` prints it beside the counters.
    std::string stats_lines() const override
    {
        return "greetings:" + std::to_string(m_greetings) + "\n";
    }

private:
    std::vector<std::pair<std::string, std::string>> m_extra;
    std::string m_greeting = "hello";
    int         m_repeat   = 1;
    bool        m_shout    = false;
    uint64_t    m_greetings = 0;
};

} // namespace

int main(int argc, char** argv)
{
    socketley::worker::register_type("greeter",
        [](std::string_view name) -> std::unique_ptr<runtime_instance>
        {
            return std::make_unique<greeter>(name);
        });

    return socketley::worker::run(argc, argv);
}
