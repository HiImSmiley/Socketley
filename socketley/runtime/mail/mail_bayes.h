#pragma once
// A spam filter that learns: each message as the words it is made of, and a word's share of the spam and of the rest
// the mailboxes' users said it was in, combined as Robinson's chi-square of Fisher (SpamBayes' classifier).  Learned
// from what a user moves into Junk and out of it, on any shard, as lines of a journal the first shard reads into the
// one table it scores with.
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace socketley::mail
{

// The words a message is scored by, hashed: its subject's, its text parts' (an HTML part's text), the domain of its
// From and of its links, each once, at most 3000.
std::vector<uint32_t> spam_tokens(std::string_view message);

// Which message a line is about, so one learned twice is learned once and one said otherwise is learned again.
uint64_t message_identity(std::string_view message);

class bayes
{
public:
    // Scored from this many of each learned on, unscored below.
    static constexpr uint32_t trained_at = 20;
    // A score from which a message is spam, Junk where it is not already.
    static constexpr double spam_at = 0.9;

    // Learned as spam or not, what it was learned as before unlearned first; false where it was learned so already.
    bool learn(uint64_t message, bool spam, const std::vector<uint32_t>& tokens);
    bool trained() const { return m_spam >= trained_at && m_ham >= trained_at; }
    // 0 for none of it spam to 1 for all of it, 0.5 where its words say nothing.
    double score(const std::vector<uint32_t>& tokens) const;

    uint32_t spam_learned() const { return m_spam; }
    uint32_t ham_learned() const { return m_ham; }
    size_t words() const { return m_tokens.size(); }

    // The table as a file, written whole beside and renamed over it; a file missing is a table empty.
    bool save(const std::string& path, std::string& why) const;
    bool load(const std::string& path, std::string& why);

    // A journal line, "s|h <message> <token>...", and the lines of `text` taken, the bytes of whole lines answered.
    static std::string line(uint64_t message, bool spam, const std::vector<uint32_t>& tokens);
    size_t apply(std::string_view text);

private:
    struct counts
    {
        uint32_t spam{0}, ham{0};
    };
    void add(const std::vector<uint32_t>& tokens, bool spam, int by);

    std::unordered_map<uint32_t, counts> m_tokens;
    // 1 for spam, 2 for not.
    std::unordered_map<uint64_t, uint8_t> m_learned;
    uint32_t m_spam{0}, m_ham{0};
};

}   // namespace socketley::mail
