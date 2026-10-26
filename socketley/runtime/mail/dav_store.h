#pragma once
// The calendars and address books of a mail runtime's users (CalDAV, CardDAV): each entry an object of the storage
// runtime's bucket at .dav/<user>/<kind>/<collection>/<name>, apart from every user's mail folders, a collection's
// name and colour beside its entries in .props, and what changed in each collection a line of a journal under the
// runtime's state, whose length is the collection's sync token (RFC 6578).
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace socketley::mail
{

class mailboxes;

class dav_store
{
public:
    dav_store(mailboxes& boxes, std::string journal_dir, std::shared_ptr<bool> alive)
        : m_boxes(boxes), m_dir(std::move(journal_dir)), m_alive(std::move(alive))
    {
    }

    // The collection every user has of each kind, which exists before anything is put into it.
    static std::string_view default_of(std::string_view kind) { return kind == "calendars" ? "personal" : "default"; }
    // A collection's name: letters, digits, '.', '_' and '-', at most 64, not beginning with a dot.
    static bool collection_ok(std::string_view name);
    // An entry's name: what a client picks, a UID and .ics or .vcf mostly; no '/', no leading dot, at most 255.
    static bool entry_ok(std::string_view name);

    struct entry
    {
        std::string name, etag;
        uint64_t size{0};
        int64_t mtime_ms{0};
    };
    // The collections of a kind, the default first; false where the storage did not answer.
    void collections(const std::string& user, const std::string& kind, std::function<void(bool, std::vector<std::string>)> done);
    // The entries of a collection, at most 10000.
    void entries(const std::string& user, const std::string& kind, const std::string& coll,
                 std::function<void(bool, std::vector<entry>)> done);
    // An entry's bytes and etag, `found` false where it is not there; `ok` false where the storage did not answer.
    void get(const std::string& user, const std::string& kind, const std::string& coll, const std::string& name,
             std::function<void(bool ok, bool found, std::string data, std::string etag)> done);
    // Its etag alone, empty where it is not there.
    void head(const std::string& user, const std::string& kind, const std::string& coll, const std::string& name,
              std::function<void(bool ok, std::string etag)> done);
    // Written, and noted in the journal; the etag the storage gave it, empty where it could not be written.
    void put(const std::string& user, const std::string& kind, const std::string& coll, const std::string& name,
             std::string data, std::string type, std::function<void(std::string etag)> done);
    void remove(const std::string& user, const std::string& kind, const std::string& coll, const std::string& name,
                std::function<void(bool)> done);
    // A collection and every entry of it gone.
    void remove_collection(const std::string& user, const std::string& kind, const std::string& coll,
                           std::function<void(bool)> done);

    // The collection's .props: its displayname, colour and description, a line each of name, tab and value.
    void props(const std::string& user, const std::string& kind, const std::string& coll,
               std::function<void(bool ok, bool found, std::vector<std::pair<std::string, std::string>>)> done);
    void set_props(const std::string& user, const std::string& kind, const std::string& coll,
                   const std::vector<std::pair<std::string, std::string>>& props, std::function<void(bool)> done);

    // The sync token: how many changes the journal holds, those let go of counted.
    uint64_t token(const std::string& user, const std::string& kind, const std::string& coll) const;
    // The entries changed since `since`, each name once and whether it is gone; false where the journal no longer
    // reaches back to `since`, or never reached it.
    bool changes_since(const std::string& user, const std::string& kind, const std::string& coll, uint64_t since,
                       std::vector<std::pair<std::string, bool>>& out) const;

private:
    std::string key_of(const std::string& user, const std::string& kind, const std::string& coll,
                       const std::string& name) const;
    std::string journal_of(const std::string& user, const std::string& kind, const std::string& coll) const;
    void note(const std::string& user, const std::string& kind, const std::string& coll, const std::string& name,
              bool gone);
    // The journal read: its base, what came before its first line, and its lines.
    void read_journal(const std::string& path, uint64_t& base, std::vector<std::pair<std::string, bool>>& lines) const;
    void remove_each(const std::string& user, const std::string& kind, const std::string& coll,
                     std::shared_ptr<std::vector<std::string>> names, size_t i, bool all_ok, std::function<void(bool)> done);
    void list_page(std::string prefix, std::string after, std::shared_ptr<std::vector<entry>> got,
                   std::shared_ptr<std::vector<std::string>> prefixes, bool folders, std::function<void(bool)> done);

    mailboxes& m_boxes;
    std::string m_dir;
    std::shared_ptr<bool> m_alive;
};

}   // namespace socketley::mail
