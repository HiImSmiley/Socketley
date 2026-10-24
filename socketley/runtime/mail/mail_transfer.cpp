#include "mail_transfer.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <deque>
#include <filesystem>
#include <utility>
#include <vector>

#include "imap_store.h"
#include "mail_mbox.h"
#include "../../shared/util/ascii.h"
#include "../../shared/util/wall_clock.h"

namespace socketley::mail
{

namespace
{

namespace fs = std::filesystem;

// A message larger than this with no "From " after it is taken for a file that is no mbox.
constexpr size_t max_message = 64u << 20;
// What is read of a file, and written of a folder, at a time.
constexpr size_t piece = 4u << 20;

std::string plural(uint64_t n, const char* one)
{
    return std::to_string(n) + " " + one + (n == 1 ? "" : "s");
}

// The folder a file's name says, INBOX for any case of it.
std::string folder_of_file(std::string name)
{
    if (name.ends_with(".mbox"))
        name.resize(name.size() - 5);
    return socketley::ascii::iequals(name, "inbox") ? std::string("INBOX") : name;
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

// Calls `step` until it says it is waiting, so an answer that comes in line does not deepen the stack.
struct trampoline
{
    bool running{false}, again{false};
    template <class F>
    void run(F&& step)
    {
        if (running)
        {
            again = true;
            return;
        }
        running = true;
        do
        {
            again = false;
            step();
        } while (again);
        running = false;
    }
};

struct exporter : std::enable_shared_from_this<exporter>
{
    imap_store& store;
    hash_pool& pool;
    std::shared_ptr<bool> alive;
    std::string user, dir;
    std::shared_ptr<transfer_status> status;
    struct one
    {
        std::string folder, key;
        uint64_t size{0};
        uint8_t flags{0};
        std::vector<std::string> keywords;
        int64_t date_ms{0};
    };
    std::vector<std::string> folders;
    std::vector<one> msgs;
    size_t at{0}, unread{0};
    std::string buffer, buffer_folder;
    uint32_t lane{0};
    trampoline t;

    exporter(imap_store& s, hash_pool& p, std::shared_ptr<bool> a, std::string u, std::string d,
             std::shared_ptr<transfer_status> st)
        : store(s), pool(p), alive(std::move(a)), user(std::move(u)), dir(std::move(d)), status(std::move(st))
    {
    }

    void fail(std::string why)
    {
        status->done = true;
        status->text = "error: " + why;
    }

    void start()
    {
        lane = pool.next_lane();
        auto self = shared_from_this();
        store.folders(user, [self](std::vector<std::string> names) {
            if (!*self->alive)
                return;
            // What the other shards delivered and changed read in, and each folder listed from the bucket now.
            self->store.refresh(self->user);
            std::sort(names.begin(), names.end());
            self->folders = std::move(names);
            self->open_next(0);
        });
    }

    void open_next(size_t i)
    {
        if (i == folders.size())
            return make_dir();
        auto self = shared_from_this();
        store.open(user, folders[i], [self, i](std::shared_ptr<imap_folder> f) {
            if (!*self->alive)
                return;
            if (f)
                for (const auto& m : f->msgs)
                    self->msgs.push_back({self->folders[i], m.key, m.size, m.flags, m.keywords, m.date_ms});
            self->open_next(i + 1);
        }, true);
    }

    void make_dir()
    {
        status->total = msgs.size();
        auto self = shared_from_this();
        auto why = std::make_shared<std::string>();
        std::vector<std::string> names = folders;
        pool.submit(lane,
                    [self, why, names] {
                        std::error_code ec;
                        if (fs::exists(self->dir, ec) && !fs::is_empty(self->dir, ec))
                        {
                            *why = self->dir + " holds files already";
                            return;
                        }
                        fs::create_directories(self->dir, ec);
                        if (ec)
                        {
                            *why = "the daemon cannot make " + self->dir + ": " + ec.message();
                            return;
                        }
                        fs::permissions(self->dir, fs::perms::owner_all, ec);
                        // Every folder gets its file, an empty one where it holds nothing.
                        for (const auto& n : names)
                        {
                            const fs::path file = fs::path(self->dir) / (n + ".mbox");
                            fs::create_directories(file.parent_path(), ec);
                            const int fd = ::open(file.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
                            if (fd < 0)
                            {
                                *why = "the daemon cannot write " + file.string() + ": " + std::strerror(errno);
                                return;
                            }
                            ::close(fd);
                        }
                    },
                    [self, why] {
                        if (!*self->alive)
                            return;
                        if (!why->empty())
                            return self->fail(*why);
                        self->pump();
                    });
    }

    void pump()
    {
        auto self = shared_from_this();
        t.run([self] { self->step(); });
    }

    void step()
    {
        if (at == msgs.size() || (!buffer.empty() && (msgs[at].folder != buffer_folder || buffer.size() >= piece)))
            return flush();
        auto self = shared_from_this();
        const one& m = msgs[at];
        store.body(m.key, m.size, [self](std::shared_ptr<const std::string> bytes) {
            if (!*self->alive)
                return;
            const one& m = self->msgs[self->at++];
            if (bytes)
            {
                self->buffer_folder = m.folder;
                self->buffer += mbox::entry(*bytes, m.flags, m.keywords, m.date_ms);
                ++self->status->count;
            }
            else
                ++self->unread;
            self->pump();
        }, false);
    }

    void flush()
    {
        auto self = shared_from_this();
        if (buffer.empty())
        {
            status->done = true;
            status->text = "exported " + plural(status->count, "message") + " of " + user + "'s " +
                           plural(folders.size(), "folder") + " to " + dir;
            if (unread)
                status->text = "error: " + status->text + ", " + plural(unread, "message") + " could not be read";
            return;
        }
        auto data = std::make_shared<std::string>(std::exchange(buffer, {}));
        auto why = std::make_shared<std::string>();
        const fs::path file = fs::path(dir) / (buffer_folder + ".mbox");
        pool.submit(lane,
                    [data, why, file] {
                        const int fd = ::open(file.c_str(), O_WRONLY | O_APPEND | O_CLOEXEC);
                        if (fd < 0 || !write_all(fd, *data))
                            *why = "the daemon cannot write " + file.string() + ": " + std::strerror(errno);
                        if (fd >= 0)
                            ::close(fd);
                    },
                    [self, why] {
                        if (!*self->alive)
                            return;
                        if (!why->empty())
                            return self->fail(*why);
                        self->pump();
                    });
    }
};

struct importer : std::enable_shared_from_this<importer>
{
    imap_store& store;
    hash_pool& pool;
    std::shared_ptr<bool> alive;
    std::string user, path;
    std::shared_ptr<transfer_status> status;
    // Each file and the folder its name says.
    std::vector<std::pair<std::string, std::string>> files;
    size_t file{0};
    uint64_t offset{0};
    bool eof{false};
    std::string carry;
    std::deque<mbox::message> ready;
    std::vector<std::string> made;
    uint32_t lane{0};
    trampoline t;
    bool storing{false};

    importer(imap_store& s, hash_pool& p, std::shared_ptr<bool> a, std::string u, std::string pth,
             std::shared_ptr<transfer_status> st)
        : store(s), pool(p), alive(std::move(a)), user(std::move(u)), path(std::move(pth)), status(std::move(st))
    {
    }

    void fail(std::string why)
    {
        status->done = true;
        status->text = "error: " + why;
    }

    void start()
    {
        lane = pool.next_lane();
        // The user's index read in first, so a folder it has is not made again.
        auto self = shared_from_this();
        store.freshen(user, [self] {
            if (*self->alive)
                self->find_files();
        });
    }

    void find_files()
    {
        auto self = shared_from_this();
        auto why = std::make_shared<std::string>();
        auto found = std::make_shared<std::vector<std::pair<std::string, std::string>>>();
        auto empties = std::make_shared<std::vector<std::string>>();
        pool.submit(lane,
                    [self, why, found, empties] {
                        std::error_code ec;
                        const fs::path p(self->path);
                        if (fs::is_regular_file(p, ec))
                        {
                            found->emplace_back(p.string(), folder_of_file(p.filename().string()));
                            return;
                        }
                        if (!fs::is_directory(p, ec))
                        {
                            *why = "the daemon cannot read " + self->path + (ec ? ": " + ec.message() : "");
                            return;
                        }
                        for (fs::recursive_directory_iterator it(p, ec), end; !ec && it != end; it.increment(ec))
                            if (it->is_regular_file(ec) && it->path().extension() == ".mbox")
                            {
                                std::string folder = folder_of_file(fs::relative(it->path(), p, ec).string());
                                // An empty file is a folder that held nothing, made all the same.
                                if (it->file_size(ec) == 0)
                                    empties->push_back(std::move(folder));
                                else
                                    found->emplace_back(it->path().string(), std::move(folder));
                            }
                        std::sort(found->begin(), found->end());
                        if (found->empty() && empties->empty())
                            *why = self->path + " holds no .mbox file";
                    },
                    [self, why, found, empties] {
                        if (!*self->alive)
                            return;
                        if (!why->empty())
                            return self->fail(*why);
                        for (const auto& f : *empties)
                            self->store.create(self->user, f);
                        self->files = std::move(*found);
                        self->pump();
                    });
    }

    void pump()
    {
        auto self = shared_from_this();
        t.run([self] { self->step(); });
    }

    void step()
    {
        if (storing)
            return;
        if (!ready.empty())
            return store_one();
        if (file == files.size())
        {
            status->done = true;
            status->text = "imported " + plural(status->count, "message") + " into " + user + "'s mailbox";
            return;
        }
        if (eof)
        {
            if (!carry.empty())
                return fail(files[file].first + " ends in what is no message");
            ++file;
            offset = 0;
            eof = false;
            return pump();
        }
        read_more();
    }

    void read_more()
    {
        auto self = shared_from_this();
        auto got = std::make_shared<std::string>();
        auto why = std::make_shared<std::string>();
        auto end = std::make_shared<bool>(false);
        const std::string name = files[file].first;
        const uint64_t from = offset;
        pool.submit(lane,
                    [got, why, end, name, from] {
                        const int fd = ::open(name.c_str(), O_RDONLY | O_CLOEXEC);
                        if (fd < 0)
                        {
                            *why = "the daemon cannot read " + name + ": " + std::strerror(errno);
                            return;
                        }
                        got->resize(piece);
                        const ssize_t n = ::pread(fd, got->data(), piece, static_cast<off_t>(from));
                        ::close(fd);
                        if (n < 0)
                        {
                            *why = "the daemon cannot read " + name + ": " + std::strerror(errno);
                            return;
                        }
                        got->resize(static_cast<size_t>(n));
                        *end = static_cast<size_t>(n) < piece;
                    },
                    [self, got, why, end] {
                        if (!*self->alive)
                            return;
                        if (!why->empty())
                            return self->fail(*why);
                        self->offset += got->size();
                        self->eof = *end;
                        self->carry += *got;
                        self->split();
                    });
    }

    void split()
    {
        size_t at = 0;
        mbox::message m;
        while (mbox::next(carry, at, eof, m))
        {
            if (m.bytes.empty())
                continue;
            if (m.folder.empty())
                m.folder = files[file].second;
            ready.push_back(std::move(m));
        }
        // What is left before the first "From " is no mbox's, unless it is the start of one still being read.
        while (at < carry.size() && (carry[at] == '\n' || carry[at] == '\r'))
            ++at;
        carry.erase(0, at);
        if (!carry.empty() && !std::string_view(carry).starts_with("From ") && carry.size() >= 5)
            return fail(files[file].first + " is no mbox: a message begins with a \"From \" line");
        if (carry.size() > max_message)
            return fail(files[file].first + " holds a message larger than 64 MiB");
        if (eof && !carry.empty() && ready.empty())
            return fail(files[file].first + " ends in what is no message");
        pump();
    }

    void store_one()
    {
        mbox::message m = std::move(ready.front());
        ready.pop_front();
        if (std::find(made.begin(), made.end(), m.folder) == made.end())
        {
            store.create(user, m.folder);
            made.push_back(m.folder);
        }
        storing = true;
        auto self = shared_from_this();
        const std::string folder = m.folder;
        const int64_t date = m.date_ms ? m.date_ms : socketley::wall::now_ms();
        store.append(user, folder, std::move(m.bytes), m.flags, std::move(m.keywords), date,
                     [self, folder](imap_store::refusal why, uint32_t, uint32_t) {
                         if (!*self->alive)
                             return;
                         self->storing = false;
                         if (why == imap_store::refusal::quota)
                             return self->fail(self->user + "'s mailbox is full after " +
                                               plural(self->status->count, "message"));
                         if (why != imap_store::refusal::none)
                             return self->fail("the storage refused a message for " + folder + " after " +
                                               plural(self->status->count, "message"));
                         ++self->status->count;
                         self->pump();
                     });
    }
};

}   // namespace

void start_export(imap_store& store, hash_pool& pool, std::shared_ptr<bool> alive, std::string user, std::string dir,
                  std::shared_ptr<transfer_status> status)
{
    auto job = std::make_shared<exporter>(store, pool, std::move(alive), std::move(user), std::move(dir), std::move(status));
    job->start();
}

void start_import(imap_store& store, hash_pool& pool, std::shared_ptr<bool> alive, std::string user, std::string path,
                  std::shared_ptr<transfer_status> status)
{
    auto job = std::make_shared<importer>(store, pool, std::move(alive), std::move(user), std::move(path), std::move(status));
    job->start();
}

}   // namespace socketley::mail
