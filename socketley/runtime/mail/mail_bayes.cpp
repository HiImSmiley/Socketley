#include "mail_bayes.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <unordered_set>

#include "mail_compose.h"
#include "mail_mime.h"
#include "mail_text.h"
#include "../../shared/util/ascii.h"

namespace socketley::mail
{

namespace
{

constexpr size_t max_tokens = 3000;
// Of a message's text, what is scored: a newsletter's first screens say what it is.
constexpr size_t max_text = 200 * 1024;
// The words that say most, and how much a word seen in few messages is held to say nothing.
constexpr size_t max_clues = 150;
constexpr double unknown_strength = 0.45, unknown_prob = 0.5, min_distance = 0.1;
constexpr uint32_t prune_at = 1'000'000;
constexpr char magic[] = "SKLBAYES1\n";

uint32_t fnv32(std::string_view prefix, std::string_view word)
{
    uint32_t h = 2166136261u;
    for (const std::string_view s : {prefix, word})
        for (const unsigned char c : s)
            h = (h ^ c) * 16777619u;
    return h;
}

struct tokenizer
{
    std::vector<uint32_t> out;
    std::unordered_set<uint32_t> seen;

    void put(std::string_view prefix, std::string_view word)
    {
        if (out.size() >= max_tokens)
            return;
        if (const uint32_t h = fnv32(prefix, word); seen.insert(h).second)
            out.push_back(h);
    }

    // Letters and digits, a byte past ASCII a letter, so a word of any script is one; 3 to 24 of them, not all digits.
    void words(std::string_view prefix, std::string_view text)
    {
        std::string w;
        bool digits = true;
        const auto end_word = [&] {
            if (w.size() >= 3 && w.size() <= 24 && !digits)
                put(prefix, w);
            w.clear();
            digits = true;
        };
        for (const char ch : text)
        {
            const auto u = static_cast<unsigned char>(ch);
            if (std::isalnum(u) || u >= 0x80 || ch == '\'' || ch == '$')
            {
                w += static_cast<char>(u < 0x80 ? std::tolower(u) : u);
                digits = digits && std::isdigit(u);
            }
            else
                end_word();
            if (out.size() >= max_tokens)
                return;
        }
        end_word();
    }

    // The host of each link, which a sender changes less easily than its words.
    void links(std::string_view text)
    {
        for (size_t at = text.find("://"); at != std::string_view::npos; at = text.find("://", at + 3))
        {
            size_t b = at + 3, e = b;
            while (e < text.size() && e - b < 253 && (std::isalnum(static_cast<unsigned char>(text[e])) || text[e] == '.' || text[e] == '-'))
                ++e;
            std::string host(text.substr(b, e - b));
            socketley::ascii::lower_in_place(host);
            if (host.find('.') != std::string::npos)
                put("u:", host);
        }
    }
};

// An HTML part's text: its tags gone, a style or a script with them, the commonest entities read.
std::string html_text(std::string_view h)
{
    std::string out;
    for (size_t i = 0; i < h.size();)
    {
        if (h[i] == '<')
        {
            const size_t close = h.find('>', i);
            if (close == std::string_view::npos)
                break;
            std::string tag(h.substr(i + 1, std::min<size_t>(close - i - 1, 7)));
            socketley::ascii::lower_in_place(tag);
            size_t next = close + 1;
            for (const std::string_view skip : {std::string_view("style"), std::string_view("script")})
                if (tag.starts_with(skip))
                {
                    std::string rest(h.substr(close));
                    socketley::ascii::lower_in_place(rest);
                    const size_t end = rest.find("</" + std::string(skip));
                    next = end == std::string::npos ? h.size() : close + end;
                }
            out += ' ';
            i = next;
            continue;
        }
        if (h[i] == '&')
        {
            static constexpr std::pair<std::string_view, char> named[] = {
                {"&amp;", '&'}, {"&lt;", '<'}, {"&gt;", '>'}, {"&quot;", '"'}, {"&#39;", '\''}, {"&nbsp;", ' '}};
            bool hit = false;
            for (const auto& [n, c] : named)
                if (h.substr(i, n.size()) == n)
                {
                    out += c;
                    i += n.size();
                    hit = true;
                    break;
                }
            if (hit)
                continue;
        }
        out += h[i++];
    }
    return out;
}

// The upper tail of chi-square with an even `v` degrees of freedom, at `x2`.
double chi2q(double x2, size_t v)
{
    const double m = x2 / 2.0;
    double term = std::exp(-m), sum = term;
    for (size_t i = 1; i < v / 2; ++i)
    {
        term *= m / static_cast<double>(i);
        sum += term;
    }
    return std::min(sum, 1.0);
}

}   // namespace

std::vector<uint32_t> spam_tokens(std::string_view message)
{
    tokenizer t;
    const std::string_view head = header_block(message);
    t.words("s:", mime::decode_words(header_value(head, "Subject")));
    std::string from = header_value(head, "From");
    if (const size_t at = from.rfind('@'); at != std::string::npos)
    {
        std::string domain = from.substr(at + 1);
        domain.erase(std::find_if(domain.begin(), domain.end(), [](char c) { return c == '>' || c == ' ' || c == '"'; }),
                     domain.end());
        socketley::ascii::lower_in_place(domain);
        t.put("f:", domain);
    }
    const mime::part root = mime::parse(message);
    size_t taken = 0;
    each_text(message, root, [&](const std::string& text, const mime::part& p) {
        if (taken >= max_text || socketley::ascii::iequals(p.disposition, "attachment"))
            return;
        const std::string body = socketley::ascii::iequals(p.subtype, "html") ? html_text(text) : text;
        const std::string_view part = std::string_view(body).substr(0, max_text - taken);
        taken += part.size();
        t.links(socketley::ascii::iequals(p.subtype, "html") ? std::string_view(text).substr(0, max_text) : part);
        t.words("", part);
    });
    return t.out;
}

uint64_t message_identity(std::string_view message)
{
    uint64_t h = 14695981039346656037ull;
    for (const unsigned char c : message.substr(0, 64 * 1024))
        h = (h ^ c) * 1099511628211ull;
    return h ^ message.size();
}

void bayes::add(const std::vector<uint32_t>& tokens, bool spam, int by)
{
    for (const uint32_t t : tokens)
    {
        counts& c = m_tokens[t];
        uint32_t& n = spam ? c.spam : c.ham;
        n = by > 0 ? n + 1 : (n ? n - 1 : 0);
        if (!c.spam && !c.ham)
            m_tokens.erase(t);
    }
    uint32_t& total = spam ? m_spam : m_ham;
    total = by > 0 ? total + 1 : (total ? total - 1 : 0);
    // A table past its bound loses the words seen once, which say least.
    if (m_tokens.size() > prune_at)
        std::erase_if(m_tokens, [](const auto& e) { return e.second.spam + e.second.ham <= 1; });
}

bool bayes::learn(uint64_t message, bool spam, const std::vector<uint32_t>& tokens)
{
    uint8_t& was = m_learned[message];
    const uint8_t now = spam ? 1 : 2;
    if (was == now)
        return false;
    if (was)
        add(tokens, was == 1, -1);
    add(tokens, spam, 1);
    was = now;
    return true;
}

double bayes::score(const std::vector<uint32_t>& tokens) const
{
    if (!trained())
        return 0.5;
    std::vector<double> clues;
    clues.reserve(tokens.size());
    for (const uint32_t t : tokens)
    {
        const auto it = m_tokens.find(t);
        if (it == m_tokens.end())
            continue;
        const double s = std::min<double>(1.0, it->second.spam / static_cast<double>(m_spam));
        const double h = std::min<double>(1.0, it->second.ham / static_cast<double>(m_ham));
        if (s + h <= 0)
            continue;
        const double p = s / (s + h);
        const double n = static_cast<double>(it->second.spam + it->second.ham);
        const double f = (unknown_strength * unknown_prob + n * p) / (unknown_strength + n);
        if (std::fabs(f - 0.5) >= min_distance)
            clues.push_back(f);
    }
    if (clues.empty())
        return 0.5;
    if (clues.size() > max_clues)
    {
        std::nth_element(clues.begin(), clues.begin() + max_clues, clues.end(),
                         [](double a, double b) { return std::fabs(a - 0.5) > std::fabs(b - 0.5); });
        clues.resize(max_clues);
    }
    double ln_spam = 0, ln_ham = 0;
    for (const double f : clues)
    {
        ln_ham += std::log(f);
        ln_spam += std::log(1.0 - f);
    }
    const size_t v = 2 * clues.size();
    const double s = 1.0 - chi2q(-2.0 * ln_spam, v);
    const double h = 1.0 - chi2q(-2.0 * ln_ham, v);
    return (s - h + 1.0) / 2.0;
}

std::string bayes::line(uint64_t message, bool spam, const std::vector<uint32_t>& tokens)
{
    std::string out(spam ? "s " : "h ");
    char buf[24];
    std::snprintf(buf, sizeof buf, "%016llx", static_cast<unsigned long long>(message));
    out += buf;
    for (const uint32_t t : tokens)
    {
        std::snprintf(buf, sizeof buf, " %08x", t);
        out += buf;
    }
    return out + "\n";
}

size_t bayes::apply(std::string_view text)
{
    size_t used = 0;
    while (used < text.size())
    {
        const size_t nl = text.find('\n', used);
        if (nl == std::string_view::npos)
            break;
        const std::string_view l = text.substr(used, nl - used);
        used = nl + 1;
        if (l.size() < 19 || (l[0] != 's' && l[0] != 'h') || l[1] != ' ')
            continue;
        const uint64_t message = std::strtoull(std::string(l.substr(2, 16)).c_str(), nullptr, 16);
        std::vector<uint32_t> tokens;
        for (size_t at = 19; at + 8 <= l.size(); at += 9)
            tokens.push_back(static_cast<uint32_t>(std::strtoul(std::string(l.substr(at, 8)).c_str(), nullptr, 16)));
        learn(message, l[0] == 's', tokens);
    }
    return used;
}

bool bayes::save(const std::string& path, std::string& why) const
{
    const std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        const auto put = [&f](const auto& v) { f.write(reinterpret_cast<const char*>(&v), sizeof v); };
        f.write(magic, sizeof magic - 1);
        put(m_spam);
        put(m_ham);
        put(static_cast<uint64_t>(m_tokens.size()));
        for (const auto& [t, c] : m_tokens)
        {
            put(t);
            put(c.spam);
            put(c.ham);
        }
        put(static_cast<uint64_t>(m_learned.size()));
        for (const auto& [m, cls] : m_learned)
        {
            put(m);
            put(cls);
        }
        f.flush();
        if (!f)
        {
            why = tmp + " could not be written";
            return false;
        }
    }
    std::error_code ec;
    std::filesystem::rename(tmp, path, ec);
    if (ec)
        why = tmp + " could not take the place of " + path + ": " + ec.message();
    return !ec;
}

bool bayes::load(const std::string& path, std::string& why)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return true;
    char head[sizeof magic - 1];
    const auto get = [&f](auto& v) { return static_cast<bool>(f.read(reinterpret_cast<char*>(&v), sizeof v)); };
    uint64_t n = 0;
    if (!f.read(head, sizeof head) || std::memcmp(head, magic, sizeof head) != 0 || !get(m_spam) || !get(m_ham) ||
        !get(n) || n > 64 * uint64_t(prune_at))
    {
        why = path + " is no table of this filter's";
        return false;
    }
    m_tokens.reserve(n);
    for (uint64_t i = 0; i < n; ++i)
    {
        uint32_t t = 0;
        counts c;
        if (!get(t) || !get(c.spam) || !get(c.ham))
        {
            why = path + " ends inside its words";
            return false;
        }
        m_tokens[t] = c;
    }
    if (!get(n) || n > 64 * uint64_t(prune_at))
    {
        why = path + " ends before its messages";
        return false;
    }
    for (uint64_t i = 0; i < n; ++i)
    {
        uint64_t m = 0;
        uint8_t cls = 0;
        if (!get(m) || !get(cls))
        {
            why = path + " ends inside its messages";
            return false;
        }
        m_learned[m] = cls;
    }
    return true;
}

}   // namespace socketley::mail
