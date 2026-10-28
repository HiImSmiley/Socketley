// IAM over the S3 endpoint: an admin's requests, and another user's its own policies allow, change the users, keys,
// groups and roles kept in the IAM file, one change at a time under the file's lock, which every shard's
// authenticator then reads.
#include "storage_run.h"

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>

#include "s3_iam.h"
#include "../../shared/util/logging.h"
#include "../../shared/persist/replaced_file.h"
#include "../../shared/persist/read_file.h"

namespace socketley::storage
{

namespace
{

// The revision of the IAM document the file holds, the time it was changed, 0 for a file never changed in a cluster.
int64_t read_rev(const std::string& file)
{
    std::string text;
    return socketley::read_file(file + ".rev", text, {.missing_ok = true}) ? std::atoll(text.c_str()) : 0;
}

}   // namespace

bool storage_run::iam_read(iam_state& out)
{
    const std::string file = m_auth ? m_auth->iam_file() : std::string();
    std::string text, err;
    out = iam_state{};
    return file.empty() || (socketley::read_file(file, text, {.missing_ok = true}) && iam_parse(text, out, err));
}

std::string storage_run::iam_record()
{
    const std::string file = m_auth ? m_auth->iam_file() : std::string();
    std::string text;
    if (file.empty() || !socketley::read_file(file, text, {.missing_ok = true}) || text.empty())
        return {};
    return encode_cluster_record({'i', std::to_string(read_rev(file)), 0, std::move(text), {}});
}

st storage_run::iam_take(int64_t rev, const std::string& json)
{
    const std::string file = m_auth ? m_auth->iam_file() : std::string();
    iam_state st;
    std::string err;
    if (file.empty())
        return st::ok;
    if (!iam_parse(json, st, err))
        return st::invalid_bucket_state;
    const int lfd = ::open((file + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lfd < 0 || ::flock(lfd, LOCK_EX) < 0)
    {
        if (lfd >= 0)
            ::close(lfd);
        return st::io_error;
    }
    // The document changed last on any node is every node's.
    bool ok = true, written = false;
    const bool newer = rev > read_rev(file);
    if (newer)
    {
        written = replace_file(file, json, durability::data_and_dir);
        ok = written && replace_file(file + ".rev", std::to_string(rev), durability::data_and_dir);
    }
    ::flock(lfd, LOCK_UN);
    ::close(lfd);
    // The document on disk is what is enforced, so a revision that failed to follow it still refreshes.
    if (written)
        m_auth->refresh();
    return ok ? st::ok : st::io_error;
}

void storage_run::op_iam(const std::shared_ptr<conn>& c, const std::vector<std::pair<std::string, std::string>>& fields,
                         std::string_view action, const auth_verdict& v, bool system)
{
    auto answer = [this, &c](int status, std::string body)
    {
        response resp;
        resp.status = status;
        resp.headers.emplace_back("Content-Type", "text/xml");
        resp.body = std::move(body);
        send_response(c, std::move(resp));
    };
    auto fail = [&](int status, std::string_view code, std::string_view message)
    {
        count_error(*c, code);
        answer(status, iam_error_xml(code, message, c->req.request_id));
    };
    const std::string file = m_auth->iam_file();
    if (file.empty())
    {
        fail(400, "InvalidAction", "This runtime has no IAM: it was started without credentials.");
        return;
    }
    // IAM is no session's: an admin may do all of it, another user what its own policies allow and what IAM's console
    // lets every user do to itself, and the runtime's own actions are an admin's -- or, `system`, the runtime's.
    const user_identity* u = v.user.get();
    const auto may_call = [](const user_identity& who)
    { return (who.has_policy && who.policy.allows_iam()) || (who.iam_policy && who.iam_policy->allows_iam()); };
    if (!system && (!u || v.session ||
                    (!u->admin && (iam_own_action(action) || (!may_call(*u) && !iam_self_service(action))))))
    {
        fail(403, "AccessDenied", "User: " + (u ? u->id : std::string("anonymous")) +
                                      " is not authorized to perform: iam:" + std::string(action));
        return;
    }
    // A request that names no user acts on its caller's, as IAM reads it, and a password is only ever changed by its
    // own user.
    iam_fields own;
    const iam_fields* f = &fields;
    const bool names_user = std::any_of(fields.begin(), fields.end(), [](const auto& kv) { return kv.first == "UserName"; });
    if (u && ((iam_defaults_to_caller(action) && !names_user) || action == "ChangePassword"))
    {
        own = fields;
        std::erase_if(own, [](const auto& kv) { return kv.first == "UserName"; });
        own.emplace_back("UserName", u->id);
        f = &own;
    }

    // The change is read, judged, made and written under the file's lock, which another shard's change waits for; an
    // IAM call is rare, so the loop waits the few milliseconds with it.
    const int lfd = ::open((file + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lfd < 0 || ::flock(lfd, LOCK_EX) < 0)
    {
        if (lfd >= 0)
            ::close(lfd);
        fail(500, "ServiceFailure", "The IAM file could not be locked.");
        return;
    }
    std::string text, err, doc;
    iam_state st;
    iam_result res;
    int64_t rev = 0;
    if (!socketley::read_file(file, text, {.missing_ok = true}) || !iam_parse(text, st, err))
    {
        LOG_WARN(("storage: the IAM file " + file + " is not read: " + err).c_str());
        res.ok = false;
        res.status = 500;
        res.code = "ServiceFailure";
        res.message = "The IAM file could not be read.";
    }
    else
    {
        const int64_t now_ms = static_cast<int64_t>(m_store.now_ms());
        auto refuse = [&](std::string message)
        {
            res.ok      = false;
            res.status  = 403;
            res.code    = "AccessDenied";
            res.message = "User: " + (u ? u->id : std::string("anonymous")) + " is not authorized to perform: iam:" +
                          std::string(action) + message;
        };
        // Any other user is judged by its own policies on every resource the request acts on -- but for what it may do
        // to itself without one -- and may change no admin.
        const std::vector<std::string> targets = iam_users_of(st, action, *f);
        const bool on_self = u && !targets.empty() &&
                             std::all_of(targets.begin(), targets.end(), [&](const std::string& t) { return t == u->id; });
        if (!system && !u->admin && !(on_self && iam_self_service(action)))
        {
            if (!may_call(*u))
                refuse({});
            const int index = iam_action_index(action);
            for (const std::string& resource : res.ok ? iam_resources(st, action, *f) : std::vector<std::string>{})
            {
                const policy_effect e = iam_access(c, *u, v.principal, index, resource);
                if (e == policy_effect::allow)
                    continue;
                refuse((resource.empty() ? std::string() : " on resource: arn:aws:iam::" + std::string(iam_account) +
                                                               ":" + resource) +
                       (e == policy_effect::deny ? " with an explicit deny" : ""));
                break;
            }
            // Only an admin gives an identity the right to call IAM, so no delegate widens its own.
            if (res.ok && iam_grants_iam(st, action, *f))
                refuse(" with a policy, group or tag that grants IAM actions or what a user may hold, which only an admin "
                       "may give");
            for (const std::string& t : targets)
                if (res.ok && t != u->id && m_auth->admin_user(t))
                    refuse(" on " + t + ", an admin, whom only an admin may change");
        }
        if (res.ok)
            res = iam_apply(
                st, action, *f, now_ms, c->req.request_id,
                [](void* a, std::string_view id) { return static_cast<storage_run*>(a)->m_auth->file_user(id); },
                [](void* a, std::string_view id)
                {
                    for (const bucket_info& b : static_cast<storage_run*>(a)->m_store.buckets())
                        if (b.owner == id)
                            return true;
                    return false;
                },
                this);
        // A node of a cluster notes when the document changed, so the one changed last is every node's.
        if (res.ok && res.changed)
        {
            doc = iam_json(st);
            rev = std::max(now_ms, read_rev(file) + 1);
            // The revision first: a document written beside a revision that failed was in force on this node alone,
            // while the admin was told it was not made.
            if ((m_repl.has_nodes() && !replace_file(file + ".rev", std::to_string(rev), durability::data_and_dir)) ||
                !replace_file(file, doc, durability::data_and_dir))
            {
                res.ok = false;
                res.status = 500;
                res.code = "ServiceFailure";
                res.message = "The IAM file could not be written.";
            }
        }
    }
    ::flock(lfd, LOCK_UN);
    ::close(lfd);
    if (res.ok && res.changed)
        m_auth->refresh();
    if (!res.ok)
    {
        fail(res.status, res.code, res.message);
        return;
    }
    if (!res.changed || !m_repl.enqueue_nodes({'i', {}, {}, {}, {}, encode_cluster_record({'i', std::to_string(rev), 0,
                                                                                            std::move(doc), {}})}))
    {
        answer(200, std::move(res.xml));
        return;
    }
    // The other nodes' copy is durable before the admin hears the change was made.
    std::weak_ptr<conn> weak = c;
    m_repl.sync([this, weak, xml = std::move(res.xml)]() mutable
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        response resp;
        resp.headers.emplace_back("Content-Type", "text/xml");
        resp.body = std::move(xml);
        send_response(cc, std::move(resp));
    });
}

}   // namespace socketley::storage
