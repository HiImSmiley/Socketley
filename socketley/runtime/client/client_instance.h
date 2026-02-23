#pragma once
#include <string>
#include <string_view>
#include <netinet/in.h>
#include <linux/time_types.h>

#include "../../shared/runtime_instance.h"
#include "../../shared/event_loop_definitions.h"

struct client_tcp_connection
{
    int fd;
    io_request read_req;
    io_request write_req;
    char read_buf[4096];
    std::string write_buf;
    std::string partial;

    static constexpr size_t MAX_PARTIAL_SIZE = 1 * 1024 * 1024;

    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};
};

enum client_mode : uint8_t
{
    client_mode_inout = 0,
    client_mode_in    = 1,
    client_mode_out   = 2
};

class client_instance : public runtime_instance
{
public:
    client_instance(std::string_view name);
    ~client_instance() override;

    void set_mode(client_mode mode);
    client_mode get_mode() const;

    void set_udp(bool udp);
    bool is_udp() const override;

    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;

    size_t get_connection_count() const override;

    // Lua actions
    void lua_send(std::string_view msg) override;

private:
    void handle_read(struct io_uring_cqe* cqe);
    void handle_write(struct io_uring_cqe* cqe);
    void handle_timeout(struct io_uring_cqe* cqe);

    void process_message(std::string_view msg);
    void send_to_server(std::string_view msg);
    void schedule_reconnect();
    bool try_connect();

    client_mode m_mode;
    bool m_udp{false};
    client_tcp_connection m_conn;
    event_loop* m_loop;
    bool m_connected;

    // Reconnect state
    int m_reconnect_attempt{0};
    bool m_reconnect_pending{false};
    io_request m_timeout_req{};
    struct __kernel_timespec m_timeout_ts{};

    // Provided buffer ring
    static constexpr uint16_t BUF_GROUP_ID = 4;
    static constexpr uint32_t BUF_COUNT = 64;
    static constexpr uint32_t BUF_SIZE = 4096;
    bool m_use_provided_bufs{false};
};
