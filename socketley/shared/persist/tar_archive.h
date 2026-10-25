#pragma once
// A tar archive (POSIX ustar, with pax records for a name past 100 bytes and a file past 8 GiB) written as it goes
// and read back as it goes, gzip around it or not, so a backup of many gigabytes is never held whole; what `socketley
// export --full` writes and `socketley restore` reads, and what `tar` reads too.
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include <sys/stat.h>

namespace socketley
{

class deflater;
class inflater;

class tar_writer
{
public:
    enum class compression : uint8_t { none, fast, best };

    tar_writer();
    ~tar_writer();
    tar_writer(const tar_writer&) = delete;
    tar_writer& operator=(const tar_writer&) = delete;

    // `path` made anew, 0600; false with why; more than one of `threads` compress beside the caller, which reads.
    bool open(const std::string& path, compression c, std::string& why, unsigned threads = 1);
    // An entry of the archive: `name` relative, without a leading slash; owner and times from `st`.
    bool add_dir(std::string_view name, const struct stat& st, std::string& why);
    // The file at `source`, read as it is written; a file that grew or shrank meanwhile is taken as far as it was read
    // when it was opened, so the entry says the size it holds.
    bool add_file(std::string_view name, const std::string& source, std::string& why);
    bool add_bytes(std::string_view name, std::string_view data, uint32_t mode, std::string& why);
    // A symbolic link to `target`, which is kept as it is written, absolute or not.
    bool add_link(std::string_view name, std::string_view target, const struct stat& st, std::string& why);
    // The two empty blocks that end a tar, and gzip's trailer.
    bool close(std::string& why);

    uint64_t files() const { return m_files; }
    // What went in, and what the file holds.
    uint64_t raw_bytes() const { return m_raw; }
    uint64_t written_bytes() const { return m_written; }

private:
    bool header(std::string_view name, char type, uint64_t size, const struct stat& st, std::string& why,
                std::string_view link = {});
    bool put(std::string_view bytes, std::string& why);
    bool flush(bool last, std::string& why);

    struct workers;

    int m_fd{-1};
    compression m_c{compression::none};
    std::unique_ptr<deflater> m_z;
    std::unique_ptr<workers> m_pool;
    // The last 32 KiB handed to the pool, which the next piece is compressed against.
    std::string m_dict;
    std::string m_buf, m_out;
    uint32_t m_crc{0};
    uint64_t m_raw{0}, m_written{0}, m_files{0};
};

class tar_reader
{
public:
    tar_reader();
    ~tar_reader();
    tar_reader(const tar_reader&) = delete;
    tar_reader& operator=(const tar_reader&) = delete;

    // gzip or plain, told by its first bytes.
    bool open(const std::string& path, std::string& why);

    struct entry
    {
        std::string name, uname, gname, link;
        char type{'0'};
        uint32_t mode{0644};
        uint32_t uid{0}, gid{0};
        uint64_t size{0};
        int64_t mtime{0};
    };
    enum class status : uint8_t { entry, end, bad };
    // The next entry's header; what it holds is read with read() or passed over by the next call.
    status next(entry& e, std::string& why);
    // At most `max` more bytes of the entry's content appended to `out`; false where the archive ended inside it.
    bool read(std::string& out, size_t max, std::string& why);
    uint64_t left() const { return m_left; }

private:
    bool fill(size_t n, std::string& why);
    bool take(std::string& out, size_t n, std::string& why);
    bool skip_rest(std::string& why);

    int m_fd{-1};
    bool m_gzip{false};
    std::unique_ptr<inflater> m_z;
    std::string m_raw, m_plain;
    size_t m_at{0};
    uint64_t m_left{0}, m_pad{0};
};

}   // namespace socketley
