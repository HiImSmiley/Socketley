#pragma once
// The web runtime's running half: its listener and connections, what an address resolves to under --root, the files it
// keeps and the descriptors it sends the rest from, the compressed copies a helper thread makes, and inotify, which
// tells it the site changed so nothing is asked of the disk per request.
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <sys/types.h>
#include <time.h>

#include "../../shared/http/conn_server.h"
#include "../../shared/loop/event_loop.h"
#include "../../shared/loop/event_loop_definitions.h"
#include "../../shared/loop/file_io.h"
#include "../../shared/loop/hash_pool.h"
#include "../../shared/util/transparent_string.h"

class web_instance;

namespace socketley::web
{

// What every body alive holds, counted by the bodies themselves, since the helper thread may drop the last of one.
struct kept_count
{
    std::atomic<uint64_t> bytes{0};
    std::atomic<uint64_t> fds{0};
};

// One representation of a file: its head fields made once, and its bytes or the descriptor they are sent from.
struct body
{
    // Content-Type through the last fixed field, each ending in CRLF, without the length.
    std::string fields;
    std::string etag;
    int64_t mtime_s{0};
    uint64_t size{0};
    // The whole of it, when it is small enough to go out in the write that carries the head.
    std::string bytes;
    bool in_memory{false};
    int fd{-1};
    std::shared_ptr<kept_count> kept;
    uint64_t counted_bytes{0};

    body() = default;
    body(const body&) = delete;
    body& operator=(const body&) = delete;
    ~body();
};

// What an address resolves to, kept until inotify says the site changed.
struct entry
{
    enum class kind : uint8_t { file, redirect, missing, unavailable };
    kind what{kind::missing};
    // 200, or 404 for the site's 404.html.
    int status{200};
    // The 404 page or the fallback, which every address nothing answers shares, so none is kept per address.
    bool shared{false};
    std::shared_ptr<const body> plain;
    // The .gz beside the file, or the copy the helper made; and the .br beside it.
    std::shared_ptr<const body> gzip;
    std::shared_ptr<const body> br;
    bool compressible{false};
    bool compress_asked{false};
    std::string location;
    // Without inotify, the file is looked at again on each use: its path under --root and what it and its copies were.
    std::string rel;
    int64_t mtime_ns{0};
    uint64_t ino{0};
    uint64_t copies{0};
};

// The fields of a request a file's answer depends on.
struct request_fields
{
    std::string if_match, if_none_match, if_modified_since, if_unmodified_since, range, if_range, accept_encoding;
};

struct web_conn : socketley::http::server_conn
{
    // The body being sent from a descriptor, held so it outlives an answer the cache has let go.
    std::shared_ptr<const body> sending_body;
    uint64_t file_off{0};
    uint64_t file_left{0};
    int sock_flags{-1};
    // The request being answered is a HEAD, or an HTTP/1.0 one.
    bool head{false};
    bool http10{false};
};

class web_run : public io_handler, public socketley::http::conn_hooks
{
public:
    web_run(web_instance& owner, event_loop& loop);
    ~web_run() override;

    bool start(std::string& why);
    void stop();
    void on_loop_turn();
    void on_cqe(struct io_uring_cqe* cqe) override;
    bool drained() const;
    size_t conn_count() const { return m_http.size(); }
    std::string stats() const;

private:
    enum class pump_result { done, waiting, failed };

    std::shared_ptr<socketley::http::server_conn> make_conn() override;
    void accepted(const std::shared_ptr<socketley::http::server_conn>& c) override;
    void serve(const std::shared_ptr<socketley::http::server_conn>& c) override;
    bool written(const std::shared_ptr<socketley::http::server_conn>& c) override;
    void closing(const std::shared_ptr<socketley::http::server_conn>& c) override;

    // One request answered into the connection; false when a body now goes from a descriptor and the rest waits.
    bool answer_request(const std::shared_ptr<web_conn>& c, std::string_view method, std::string_view raw_path,
                        std::string_view query, const request_fields& f);
    void answer_plain(const std::shared_ptr<web_conn>& c, int status, std::string_view text, std::string_view extra = {});
    // The file's answer, its head and as much of its body as goes with it; false when the rest is sent from its
    // descriptor.
    bool answer_file(const std::shared_ptr<web_conn>& c, const entry& e, const request_fields& f);
    // The Connection field this answer needs, if any.
    static std::string_view connection_field(const web_conn& c);
    pump_result pump(const std::shared_ptr<web_conn>& c);
    void pump_later(const std::shared_ptr<web_conn>& c);

    // What `path` is now, from the cache or the disk.
    std::shared_ptr<entry> lookup(const std::string& path);
    std::shared_ptr<entry> resolve(const std::string& path);
    // The page every address nothing answers gets: the fallback for one with no dot in its last part, else 404.html.
    std::shared_ptr<entry> missing(bool has_ext);
    // `rel` under --root opened as a file or a directory; -1 when it is neither, or not there, and m_transient set
    // when that is for want of a resource rather than of the file.
    int open_beneath(const std::string& rel, bool& is_dir, struct stat& st);
    // The entry for the file `rel`, opened as `fd`, which it takes.
    std::shared_ptr<entry> file_entry(const std::string& rel, int fd, const struct stat& st, int status);
    std::shared_ptr<const body> make_body(const std::string& rel, int fd, const struct stat& st,
                                          std::string_view coding, std::string_view type);
    // A small file that was not in the page cache when it was first asked for, read now that it is.
    void warm(entry& e);
    // The helper's gzip of a text file the build left no copy of, put in place once it is made.
    void ask_compress(const std::shared_ptr<entry>& e);
    bool still_current(const entry& e) const;
    uint64_t copies_of(const std::string& rel) const;
    void forget_all();
    bool keep_bytes(uint64_t n);

    // inotify: every directory below --root, and every one above it, any of which a deploy may swap a release into.
    void watch_tree(const std::string& rel, int depth);
    void watch_above();
    void rewatch();
    void arm_watch();
    void on_watch(int64_t res);
    void lose_watching();
    // Whether the directory --root names is another than the one open, and if so, that one opened.
    bool root_swapped();
    bool open_root(std::string& why);
    void arm_tick();
    void on_tick();
    const std::string& date_field();

    web_instance& m_owner;
    event_loop& m_loop;
    file_io m_io;
    socketley::http::conn_server m_http;
    hash_pool m_pool{1};

    int m_root_fd{-1};
    std::string m_root;
    std::string m_index;
    std::string m_fallback;
    std::unordered_map<std::string, std::shared_ptr<entry>, string_hash, string_equal> m_entries;
    std::shared_ptr<entry> m_not_found;
    std::shared_ptr<entry> m_fallback_entry;
    std::shared_ptr<kept_count> m_kept{std::make_shared<kept_count>()};
    size_t m_jobs{0};
    bool m_transient{false};

    int m_inotify{-1};
    bool m_watching{false};
    std::unordered_map<int, std::string> m_watches;
    // A directory above --root, by its watch, and the name below it on the way to --root.
    std::unordered_map<int, std::string> m_above;
    std::unique_ptr<char[]> m_watch_buf;
    bool m_watch_armed{false};
    // The directory --root names, by device and inode, so a swap of what the name holds is told from a write in it.
    dev_t m_root_dev{0};
    ino_t m_root_ino{0};
    int64_t m_root_checked{-1};

    int64_t m_date_sec{-1};
    std::string m_date;

    io_request m_tick_req{};
    __kernel_timespec m_tick_ts{};
    bool m_tick_armed{false};
    bool m_stopped{false};

    struct counters
    {
        uint64_t requests{0}, not_modified{0}, not_found{0}, redirects{0}, refused{0}, ranges{0}, unavailable{0};
        uint64_t from_memory{0}, zero_copy{0}, compressed{0}, compress_jobs{0}, reloads{0}, stalled{0};
    } m_c;
};

}   // namespace socketley::web
