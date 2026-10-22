#pragma once
// One IMAP4rev1 conversation (RFC 3501, with LITERAL+, SASL-IR, IDLE, NAMESPACE, UIDPLUS, MOVE, UNSELECT, SPECIAL-USE,
// ID, ENABLE, CONDSTORE and QRESYNC, ESEARCH, LIST-EXTENDED, LIST-STATUS, STATUS=SIZE, QUOTA, SORT and THREAD), without
// a socket: bytes in, replies out through its hooks, the mailboxes read and written through an
// imap_store.  Commands are taken one after the other, one that waits for the store holding the ones behind it.
//
// A session keeps its own numbering of the folder it has selected, which changes only where it is told: new messages
// as EXISTS at the end of a command, and messages gone as EXPUNGE, so a client's message numbers mean what it thinks.
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "mail_account.h"
#include "imap_store.h"

namespace socketley::mail
{

struct imap_config
{
    std::string hostname;
    bool tls_offered{false};
    bool tls_active{false};
    // A password may be said in the clear: this machine's own client.
    bool login_in_clear{false};
    uint64_t max_append{25ull << 20};
    // The ManageSieve URL imapsieve's scripts are put at, where there is one (RFC 6785 2).
    std::string imapsieve;
};

class imap_session
{
public:
    struct hooks
    {
        virtual ~hooks() = default;
        virtual void reply(std::string_view bytes) = 0;
        virtual void start_tls() = 0;
        virtual void close() = 0;
        // A password for `user`; `done(true, name)` signs the session in as `name`, whose mailbox it then reads.
        virtual void login(std::string user, std::string password, std::function<void(account, std::string)> done) = 0;
        // What came acknowledged at once, for a client whose Nagle holds back a literal's line end until it is.
        virtual void acknowledge() {}
        // A stretch of `bytes` said without copying it, for a body the store holds.
        virtual void reply_shared(const std::shared_ptr<const std::string>& bytes, size_t off, size_t len)
        {
            reply(std::string_view(*bytes).substr(off, len));
        }
        // How much said is not yet written.
        virtual size_t backlog() const { return 0; }
        // `f` once what is said is written down to a little.
        virtual void when_drained(std::function<void()> f) { f(); }
        // The OK to COMPRESS is out: what comes and goes after it is DEFLATE (RFC 4978); false where it cannot be.
        virtual bool start_compress() { return false; }
        // `f` at the loop's next turn, so a long SEARCH or SORT lets the others on the shard go between its stretches.
        virtual void later(std::function<void()> f) { f(); }
        // What the client did to messages of a folder, APPEND, COPY or FLAG and the flags it changed, as imapsieve is
        // told of it (RFC 6785).
        virtual void imap_acted(const std::string& /*user*/, const std::string& /*folder*/, std::string /*cause*/,
                                std::vector<uint32_t> /*uids*/, std::string /*changed*/) {}
    };

    imap_session(const imap_config& cfg, hooks& h, imap_store& store);
    ~imap_session();
    imap_session(const imap_session&)            = delete;
    imap_session& operator=(const imap_session&) = delete;

    void greet();
    void input(std::string_view bytes);
    void tls_started();
    void gone();
    // The selected folder looked at again, for IDLE, once a second.
    void poll();
    bool idling() const { return m_idle; }
    // What came and is not taken yet, the command being gathered included.
    size_t buffered() const { return m_in.size() + m_cmd.size(); }
    const std::string& user() const { return m_user; }

    static constexpr size_t max_line = 65536;
    // A FETCH waits for its client past this much unwritten, so a mailbox is not read into memory faster than it goes.
    static constexpr size_t max_backlog = 1u << 20;
    // A body this long goes out as the store holds it; a shorter one is copied into the line around it.
    static constexpr size_t shared_from = 4096;

private:
    struct token
    {
        enum kind : uint8_t { atom, string, open, close } k{atom};
        std::string text;
    };
    enum class state : uint8_t { not_auth, auth, selected, logout };

    void run();
    void command(std::string tag, std::vector<token> args);
    void finish(const std::string& tag, std::string_view status, std::string_view text);
    void untagged(std::string_view line);
    bool tokenize(std::string_view s, std::vector<token>& out) const;
    void resume();

    void cmd_login(const std::string& tag, const std::vector<token>& a);
    void cmd_authenticate(const std::string& tag, const std::vector<token>& a);
    void cmd_select(const std::string& tag, const std::vector<token>& a, bool readonly);
    void cmd_list(const std::string& tag, const std::vector<token>& a, bool lsub);
    void cmd_status(const std::string& tag, const std::vector<token>& a);
    void cmd_append(const std::string& tag, const std::vector<token>& a);
    // GETMETADATA and SETMETADATA (RFC 5464), the server's entries under the mailbox "".
    void cmd_metadata(const std::string& tag, const std::vector<token>& a, bool set);
    void cmd_fetch(const std::string& tag, const std::vector<token>& a, size_t from, bool uid);
    void cmd_store(const std::string& tag, const std::vector<token>& a, size_t from, bool uid);
    void cmd_search(const std::string& tag, const std::vector<token>& a, size_t from, bool uid);
    void cmd_copy(const std::string& tag, const std::vector<token>& a, size_t from, bool uid, bool move);
    // SORT, or THREAD where `thread` says, over what the search criteria find.
    void cmd_order(const std::string& tag, const std::vector<token>& a, size_t from, bool uid, bool thread);
    // Those of `only` with \Deleted expunged, or with `moved` every one of them, as MOVE takes what it copied.
    void cmd_expunge(const std::string& tag, const std::vector<uint32_t>& only, bool moved, std::string_view done_text);

    // The messages of a sequence set, as indexes into the view; false for one that is not a set.
    bool parse_set(std::string_view set, bool uid, std::vector<size_t>& out) const;
    // EXISTS and EXPUNGE for what changed in the folder since the session last looked.
    // The bytes of the message at `idx` asked for ahead of its turn, unless they are held or large.
    void read_ahead(size_t idx, bool whole);
    void update_view();
    std::string flags_text(uint8_t f, bool recent) const;
    // A message's flags and its keywords.
    std::string flags_text(const imap_message& m, bool recent) const;
    // A folder's STATUS line with the items asked.
    std::string status_text(const imap_folder& f, const std::vector<std::string>& items) const;
    void sign_in(const std::string& tag, std::string user, std::string password);
    // A mailbox name as the client wrote it, as the index keeps it; and one the index keeps, as the client reads it.
    std::string box(std::string_view given) const;
    std::string shown(std::string_view kept) const;

    imap_config m_cfg;
    hooks& m_hooks;
    imap_store& m_store;
    state m_state{state::not_auth};
    std::string m_user;
    // The selected folder, and the UIDs of what the session has been told of, in its order.
    std::shared_ptr<imap_folder> m_folder;
    bool m_readonly{false};
    std::vector<uint32_t> m_view;
    uint64_t m_seen_version{0};
    // CONDSTORE and QRESYNC enabled (RFC 7162), and the mod-sequence of the last flags the session was told.
    bool m_compressing{false};
    bool m_condstore{false};
    bool m_qresync{false};
    // ENABLE UTF8=ACCEPT: mailbox names come and go as UTF-8, kept in the index as modified UTF-7 (RFC 6855 3).
    bool m_utf8{false};
    uint64_t m_told_modseq{0};
    // Input: what is not yet a whole command, the command being gathered with its literals, and how much of a literal
    // is still to come.
    std::string m_in;
    std::string m_cmd;
    size_t m_literal{0};
    bool m_waiting{false};
    bool m_running{false};
    bool m_idle{false};
    std::string m_idle_tag;
    std::string m_auth_tag;
    bool m_auth_continue{false};
    std::shared_ptr<bool> m_alive;
};

}   // namespace socketley::mail
