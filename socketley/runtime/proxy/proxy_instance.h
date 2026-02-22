#pragma once
#include <string>
#include <string_view>
#include <unordered_map>
#include <memory>
#include <vector>
#include <queue>
#include <random>
#include <netinet/in.h>
#include <sys/uio.h>

#include "../../shared/runtime_instance.h"
#include "../../shared/event_loop_definitions.h"

class runtime_manager;

enum proxy_protocol : uint8_t { protocol_http = 0, protocol_tcp = 1 };
enum proxy_strategy : uint8_t { strategy_round_robin = 0, strategy_random = 1, strategy_lua = 2 };

struct backend_info
{
    std::string address;
    std::string resolved_host;
    uint16_t resolved_port = 0;
};

struct proxy_client_connection
{
    static constexpr size_t MAX_WRITE_BATCH = 16;

    int fd;
    io_request read_req;
    io_request write_req;
    char read_buf[8192];
    std::string partial;
    int backend_fd = -1;
    bool header_parsed = false;
    std::string method;
    std::string path;
    std::string version;

    std::queue<std::shared_ptr<const std::string>> write_queue;
    std::shared_ptr<const std::string> write_batch[MAX_WRITE_BATCH];
    struct iovec write_iovs[MAX_WRITE_BATCH];
    uint32_t write_batch_count{0};

    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};
};

struct proxy_backend_connection
{
    static constexpr size_t MAX_WRITE_BATCH = 16;

    int fd;
    io_request read_req;
    io_request write_req;
    char read_buf[8192];
    std::string partial;
    int client_fd;

    std::queue<std::shared_ptr<const std::string>> write_queue;
    std::shared_ptr<const std::string> write_batch[MAX_WRITE_BATCH];
    struct iovec write_iovs[MAX_WRITE_BATCH];
    uint32_t write_batch_count{0};

    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};
};

class proxy_instance : public runtime_instance
{
public:
    proxy_instance(std::string_view name);
    ~proxy_instance() override;

    void add_backend(std::string_view addr);
    void clear_backends();
    void set_protocol(proxy_protocol p);
    void set_strategy(proxy_strategy s);
    void set_runtime_manager(runtime_manager* mgr);

    proxy_protocol get_protocol() const;
    proxy_strategy get_strategy() const;
    const std::vector<backend_info>& get_backends() const;

    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;

    size_t get_connection_count() const override;

    // Stats
    std::string get_stats() const override;

private:
    void handle_accept(struct io_uring_cqe* cqe);
    void handle_client_read(struct io_uring_cqe* cqe, io_request* req);
    void handle_backend_read(struct io_uring_cqe* cqe, io_request* req);
    void handle_client_write(struct io_uring_cqe* cqe, io_request* req);
    void handle_backend_write(struct io_uring_cqe* cqe, io_request* req);

    bool parse_http_request_line(proxy_client_connection* conn);
    std::string rewrite_http_request(proxy_client_connection* conn,
                                     std::string_view new_path);

    bool resolve_backend(backend_info& b);
    size_t select_backend(proxy_client_connection* conn);
    bool connect_to_backend(proxy_client_connection* conn, size_t idx);
    void close_pair(int client_fd, int backend_fd);

    void forward_to_backend(proxy_client_connection* conn, std::string_view data);
    void forward_to_client(proxy_backend_connection* conn, std::string_view data);
    void send_error(proxy_client_connection* conn, std::string_view status, std::string_view body);
    void flush_client_write_queue(proxy_client_connection* conn);
    void flush_backend_write_queue(proxy_backend_connection* conn);

    proxy_protocol m_protocol = protocol_http;
    proxy_strategy m_strategy = strategy_round_robin;
    std::vector<backend_info> m_backends;
    std::string m_prefix;  // pre-built "/<name>/" to avoid repeated allocation

    int m_listen_fd = -1;
    sockaddr_in m_accept_addr{};
    socklen_t m_accept_addrlen = sizeof(sockaddr_in);
    io_request m_accept_req{};
    event_loop* m_loop = nullptr;
    bool m_multishot_active = false;

    std::unordered_map<int, std::unique_ptr<proxy_client_connection>> m_clients;
    std::unordered_map<int, std::unique_ptr<proxy_backend_connection>> m_backend_conns;

    size_t m_rr_index = 0;
    std::mt19937 m_rng{std::random_device{}()};

    // Provided buffer ring
    static constexpr uint16_t BUF_GROUP_ID = 2;
    static constexpr uint32_t BUF_COUNT = 256;
    static constexpr uint32_t BUF_SIZE = 8192;
    bool m_use_provided_bufs{false};
};
