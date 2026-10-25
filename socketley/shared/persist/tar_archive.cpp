#include "tar_archive.h"

#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <unordered_map>

#include "../util/crc.h"
#include "../util/deflate.h"
#include "../util/inflate.h"

namespace socketley
{

namespace
{

constexpr size_t block = 512;
// What is handed to the compressor, and read from the file, at a time.
constexpr size_t piece = 1u << 20;
// The largest size an ustar header's eleven octal digits hold.
constexpr uint64_t ustar_max = 077777777777ull;

// `v` in `width - 1` octal digits and a NUL, as ustar writes a number; the callers keep it within them.
void octal(char* field, size_t width, uint64_t v)
{
    field[width - 1] = '\0';
    for (size_t i = width - 1; i-- > 0; v >>= 3)
        field[i] = static_cast<char>('0' + (v & 7));
}

uint64_t number(const char* field, size_t width)
{
    // A field whose first byte has its top bit set is a big-endian binary number (GNU's base-256).
    if (static_cast<unsigned char>(field[0]) & 0x80)
    {
        uint64_t v = static_cast<unsigned char>(field[0]) & 0x7f;
        for (size_t i = 1; i < width; ++i)
            v = (v << 8) | static_cast<unsigned char>(field[i]);
        return v;
    }
    uint64_t v = 0;
    for (size_t i = 0; i < width && field[i]; ++i)
    {
        if (field[i] == ' ')
            continue;
        if (field[i] < '0' || field[i] > '7')
            break;
        v = v * 8 + static_cast<uint64_t>(field[i] - '0');
    }
    return v;
}

std::string text(const char* field, size_t width)
{
    return std::string(field, strnlen(field, width));
}

// A pax record, "<length> <key>=<value>\n", its length counting itself.
std::string pax_record(std::string_view key, std::string_view value)
{
    const size_t body = key.size() + value.size() + 3;
    size_t len = body + 1;
    while (std::to_string(len).size() + body != len)
        ++len;
    return std::to_string(len) + " " + std::string(key) + "=" + std::string(value) + "\n";
}

const std::string& user_name(uid_t uid)
{
    static std::unordered_map<uid_t, std::string> names;
    auto it = names.find(uid);
    if (it == names.end())
    {
        const passwd* pw = ::getpwuid(uid);
        it = names.emplace(uid, pw ? pw->pw_name : "").first;
    }
    return it->second;
}

const std::string& group_name(gid_t gid)
{
    static std::unordered_map<gid_t, std::string> names;
    auto it = names.find(gid);
    if (it == names.end())
    {
        const group* gr = ::getgrgid(gid);
        it = names.emplace(gid, gr ? gr->gr_name : "").first;
    }
    return it->second;
}

bool write_all(int fd, std::string_view s)
{
    while (!s.empty())
    {
        const ssize_t w = ::write(fd, s.data(), s.size());
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0)
            return false;
        s.remove_prefix(static_cast<size_t>(w));
    }
    return true;
}

void le32(std::string& out, uint32_t v)
{
    for (int i = 0; i < 4; ++i)
        out += static_cast<char>((v >> (8 * i)) & 0xff);
}

}   // namespace

// ─── writing ────────────────────────────────────────────────────────────────

tar_writer::tar_writer() = default;

tar_writer::~tar_writer()
{
    if (m_fd >= 0)
        ::close(m_fd);
}

bool tar_writer::open(const std::string& path, compression c, std::string& why)
{
    m_fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (m_fd < 0)
    {
        why = path + " could not be written: " + std::strerror(errno);
        return false;
    }
    m_c = c;
    if (c != compression::none)
    {
        m_z = std::make_unique<deflater>(c == compression::best ? deflater::effort::best : deflater::effort::fast);
        // gzip's header (RFC 1952): no name, no time, the slowest or the fastest level, made on Unix.
        m_out.assign("\x1f\x8b\x08\x00\x00\x00\x00\x00", 8);
        m_out += static_cast<char>(c == compression::best ? 2 : 4);
        m_out += '\x03';
    }
    return true;
}

bool tar_writer::put(std::string_view bytes, std::string& why)
{
    m_buf.append(bytes);
    m_raw += bytes.size();
    if (m_z)
        m_crc = crc::crc32(bytes, m_crc);
    return m_buf.size() < piece || flush(false, why);
}

bool tar_writer::flush(bool last, std::string& why)
{
    if (m_z)
    {
        m_z->compress(m_buf, m_out);
        if (last)
        {
            m_z->finish(m_out);
            le32(m_out, m_crc);
            le32(m_out, static_cast<uint32_t>(m_raw & 0xffffffffu));
        }
    }
    else
        m_out.append(m_buf);
    m_buf.clear();
    if (!write_all(m_fd, m_out))
    {
        why = std::string("the archive could not be written: ") + std::strerror(errno);
        return false;
    }
    m_written += m_out.size();
    m_out.clear();
    return true;
}

bool tar_writer::header(std::string_view name, char type, uint64_t size, const struct stat& st, std::string& why,
                        std::string_view link)
{
    std::string pax;
    if (name.size() > 100)
        pax += pax_record("path", name);
    if (link.size() > 100)
        pax += pax_record("linkpath", link);
    if (size > ustar_max)
        pax += pax_record("size", std::to_string(size));
    if (!pax.empty())
    {
        struct stat none{};
        none.st_mode = 0644;
        none.st_mtime = st.st_mtime;
        if (!header("PaxHeader", 'x', pax.size(), none, why) || !put(pax, why) ||
            !put(std::string((block - pax.size() % block) % block, '\0'), why))
            return false;
    }
    char h[block] = {};
    std::memcpy(h, name.data(), std::min<size_t>(name.size(), 100));
    octal(h + 100, 8, st.st_mode & 07777);
    octal(h + 108, 8, st.st_uid <= 07777777 ? st.st_uid : 0);
    octal(h + 116, 8, st.st_gid <= 07777777 ? st.st_gid : 0);
    octal(h + 124, 12, size > ustar_max ? 0 : size);
    octal(h + 136, 12, st.st_mtime > 0 ? static_cast<uint64_t>(st.st_mtime) : 0);
    std::memset(h + 148, ' ', 8);
    h[156] = type;
    if (!link.empty())
        std::memcpy(h + 157, link.data(), std::min<size_t>(link.size(), 100));
    std::memcpy(h + 257, "ustar\0" "00", 8);
    const std::string& u = user_name(st.st_uid);
    const std::string& g = group_name(st.st_gid);
    std::memcpy(h + 265, u.data(), std::min<size_t>(u.size(), 31));
    std::memcpy(h + 297, g.data(), std::min<size_t>(g.size(), 31));
    unsigned sum = 0;
    for (const char c : h)
        sum += static_cast<unsigned char>(c);
    std::snprintf(h + 148, 8, "%06o", sum);
    h[155] = ' ';
    return put(std::string_view(h, block), why);
}

bool tar_writer::add_dir(std::string_view name, const struct stat& st, std::string& why)
{
    std::string n(name);
    if (n.empty() || n.back() != '/')
        n += '/';
    return header(n, '5', 0, st, why);
}

bool tar_writer::add_file(std::string_view name, const std::string& source, std::string& why)
{
    const int fd = ::open(source.c_str(), O_RDONLY | O_CLOEXEC);
    struct stat st{};
    if (fd < 0 || ::fstat(fd, &st) != 0)
    {
        why = source + " could not be read: " + std::strerror(errno);
        if (fd >= 0)
            ::close(fd);
        return false;
    }
    const uint64_t size = static_cast<uint64_t>(st.st_size);
    bool ok = header(name, '0', size, st, why);
    std::string chunk;
    uint64_t done = 0;
    while (ok && done < size)
    {
        chunk.resize(static_cast<size_t>(std::min<uint64_t>(piece, size - done)));
        const ssize_t n = ::read(fd, chunk.data(), chunk.size());
        if (n < 0 && errno == EINTR)
            continue;
        // A file cut short while it was read keeps the size its header said, the rest zeros.
        if (n <= 0)
            chunk.assign(chunk.size(), '\0');
        else
            chunk.resize(static_cast<size_t>(n));
        done += chunk.size();
        ok = put(chunk, why);
    }
    ::close(fd);
    if (ok)
    {
        ++m_files;
        ok = put(std::string((block - size % block) % block, '\0'), why);
    }
    return ok;
}

bool tar_writer::add_bytes(std::string_view name, std::string_view data, uint32_t mode, std::string& why)
{
    struct stat st{};
    st.st_mode = mode;
    st.st_uid = ::geteuid();
    st.st_gid = ::getegid();
    st.st_mtime = ::time(nullptr);
    ++m_files;
    return header(name, '0', data.size(), st, why) && put(data, why) &&
           put(std::string((block - data.size() % block) % block, '\0'), why);
}

bool tar_writer::add_link(std::string_view name, std::string_view target, const struct stat& st, std::string& why)
{
    ++m_files;
    return header(name, '2', 0, st, why, target);
}

bool tar_writer::close(std::string& why)
{
    if (!put(std::string(2 * block, '\0'), why) || !flush(true, why))
        return false;
    const bool synced = ::fsync(m_fd) == 0;
    const bool closed = ::close(m_fd) == 0;
    m_fd = -1;
    if (!synced || !closed)
    {
        why = std::string("the archive could not be written: ") + std::strerror(errno);
        return false;
    }
    return true;
}

// ─── reading ────────────────────────────────────────────────────────────────

tar_reader::tar_reader() = default;

tar_reader::~tar_reader()
{
    if (m_fd >= 0)
        ::close(m_fd);
}

bool tar_reader::open(const std::string& path, std::string& why)
{
    m_fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (m_fd < 0)
    {
        why = path + " could not be read: " + std::strerror(errno);
        return false;
    }
    char head[10];
    const ssize_t n = ::read(m_fd, head, sizeof head);
    if (n == 10 && head[0] == '\x1f' && head[1] == '\x8b')
    {
        if (head[2] != 8)
        {
            why = path + " is gzip of a method other than DEFLATE";
            return false;
        }
        m_gzip = true;
        m_z = std::make_unique<inflater>();
        // What follows the fixed part as its flags say: extra field, name, comment, header CRC.
        const uint8_t flags = static_cast<uint8_t>(head[3]);
        const auto skip = [&](size_t len) {
            std::string tmp(len, '\0');
            return len == 0 || ::read(m_fd, tmp.data(), len) == static_cast<ssize_t>(len);
        };
        bool whole = true;
        if (flags & 4)
        {
            unsigned char x[2];
            whole = ::read(m_fd, x, 2) == 2 && skip(static_cast<size_t>(x[0]) | static_cast<size_t>(x[1]) << 8);
        }
        for (const uint8_t f : {uint8_t(8), uint8_t(16)})
            if (whole && (flags & f))
                for (char c = 1; whole && c != 0;)
                    whole = ::read(m_fd, &c, 1) == 1;
        if (whole && (flags & 2))
            whole = skip(2);
        if (!whole)
        {
            why = path + " ends inside its gzip header";
            return false;
        }
    }
    else if (n > 0)
        m_raw.assign(head, static_cast<size_t>(n));
    return true;
}

bool tar_reader::fill(size_t n, std::string& why)
{
    if (m_at > piece)
    {
        m_plain.erase(0, m_at);
        m_at = 0;
    }
    while (m_plain.size() - m_at < n)
    {
        if (!m_gzip)
        {
            if (!m_raw.empty())
            {
                m_plain += m_raw;
                m_raw.clear();
                continue;
            }
            std::string chunk(piece, '\0');
            const ssize_t r = ::read(m_fd, chunk.data(), chunk.size());
            if (r < 0 && errno == EINTR)
                continue;
            if (r <= 0)
            {
                why = "the archive ends inside an entry";
                return false;
            }
            m_plain.append(chunk.data(), static_cast<size_t>(r));
            continue;
        }
        const inflater::result res = m_z->run(m_plain, piece);
        if (res == inflater::result::bad)
        {
            why = "the archive's gzip stream is damaged";
            return false;
        }
        if (res == inflater::result::done && m_plain.size() - m_at < n)
        {
            why = "the archive ends inside an entry";
            return false;
        }
        if (res == inflater::result::need_input)
        {
            std::string chunk(piece, '\0');
            const ssize_t r = ::read(m_fd, chunk.data(), chunk.size());
            if (r < 0 && errno == EINTR)
                continue;
            if (r <= 0)
                m_z->end();
            else
                m_z->feed(reinterpret_cast<const uint8_t*>(chunk.data()), static_cast<size_t>(r));
        }
    }
    return true;
}

bool tar_reader::take(std::string& out, size_t n, std::string& why)
{
    if (!fill(n, why))
        return false;
    out.append(m_plain, m_at, n);
    m_at += n;
    return true;
}

bool tar_reader::skip_rest(std::string& why)
{
    for (uint64_t left = m_left + m_pad; left > 0;)
    {
        const size_t n = static_cast<size_t>(std::min<uint64_t>(left, piece));
        if (!fill(n, why))
            return false;
        m_at += n;
        left -= n;
    }
    m_left = m_pad = 0;
    return true;
}

tar_reader::status tar_reader::next(entry& e, std::string& why)
{
    if (!skip_rest(why))
        return status::bad;
    std::string pax_path, pax_size, pax_link, long_name;
    for (;;)
    {
        std::string h;
        if (!take(h, block, why))
            return status::bad;
        if (h.find_first_not_of('\0') == std::string::npos)
            return status::end;
        unsigned sum = 0;
        for (size_t i = 0; i < block; ++i)
            sum += (i >= 148 && i < 156) ? ' ' : static_cast<unsigned char>(h[i]);
        if (sum != number(h.data() + 148, 8))
        {
            why = "an entry's header does not add up (no tar, or a damaged one)";
            return status::bad;
        }
        const char type = h[156] ? h[156] : '0';
        uint64_t size = number(h.data() + 124, 12);
        if (type == 'x' || type == 'g' || type == 'L')
        {
            if (size > (1u << 20))
            {
                why = "an entry's extended header is too long";
                return status::bad;
            }
            std::string body;
            if (!take(body, static_cast<size_t>(size), why))
                return status::bad;
            std::string pad;
            if (!take(pad, static_cast<size_t>((block - size % block) % block), why))
                return status::bad;
            if (type == 'L')
                long_name = body.substr(0, body.find('\0'));
            else if (type == 'x')
                for (size_t at = 0; at < body.size();)
                {
                    const size_t sp = body.find(' ', at);
                    if (sp == std::string::npos)
                        break;
                    const size_t len = std::strtoull(body.c_str() + at, nullptr, 10);
                    if (len == 0 || at + len > body.size())
                        break;
                    const std::string rec = body.substr(sp + 1, at + len - sp - 2);
                    const size_t eq = rec.find('=');
                    if (eq != std::string::npos)
                    {
                        if (rec.compare(0, eq, "path") == 0)
                            pax_path = rec.substr(eq + 1);
                        else if (rec.compare(0, eq, "size") == 0)
                            pax_size = rec.substr(eq + 1);
                        else if (rec.compare(0, eq, "linkpath") == 0)
                            pax_link = rec.substr(eq + 1);
                    }
                    at += len;
                }
            continue;
        }
        e = {};
        e.type = type;
        const std::string prefix = h.compare(257, 5, "ustar") == 0 ? text(h.data() + 345, 155) : std::string();
        e.name = !pax_path.empty() ? pax_path
               : !long_name.empty() ? long_name
               : prefix.empty()     ? text(h.data(), 100)
                                    : prefix + "/" + text(h.data(), 100);
        if (!pax_size.empty())
            size = std::strtoull(pax_size.c_str(), nullptr, 10);
        e.mode = static_cast<uint32_t>(number(h.data() + 100, 8) & 07777);
        e.uid = static_cast<uint32_t>(number(h.data() + 108, 8));
        e.gid = static_cast<uint32_t>(number(h.data() + 116, 8));
        e.mtime = static_cast<int64_t>(number(h.data() + 136, 12));
        e.link = !pax_link.empty() ? pax_link : text(h.data() + 157, 100);
        e.uname = text(h.data() + 265, 32);
        e.gname = text(h.data() + 297, 32);
        // Only a file holds bytes; a link's or a directory's size is none, whatever its header says.
        e.size = (type == '0' || type == '7') ? size : 0;
        m_left = e.size;
        m_pad = (block - e.size % block) % block;
        return status::entry;
    }
}

bool tar_reader::read(std::string& out, size_t max, std::string& why)
{
    const size_t n = static_cast<size_t>(std::min<uint64_t>(max, m_left));
    if (!take(out, n, why))
        return false;
    m_left -= n;
    return true;
}

}   // namespace socketley
