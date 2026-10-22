#include "doctest.h"

#include <chrono>
#include <map>
#include <string>
#include <vector>

#include "runtime/mail/mail_compose.h"
#include "runtime/mail/mail_mime.h"
#include "runtime/mail/mail_sieve.h"

using namespace socketley::mail;
using sieve::action;
using sieve::outcome;
using kind = sieve::action::kind;

namespace
{

constexpr std::string_view plain = R"(From: Alice <alice@example.org>
To: Me <me@example.com>
Subject: Hello there
Date: Tue, 21 Feb 2023 14:42:51 -0800
Message-ID: <1@example.org>

Body text here.
)";

std::shared_ptr<const sieve::script> must(std::string_view text)
{
    std::string err;
    auto s = sieve::script::compile(text, err);
    INFO(err);
    REQUIRE(s);
    return s;
}

std::string compile_error(std::string_view text)
{
    std::string err;
    const auto s = sieve::script::compile(text, err);
    CHECK_FALSE(s);
    return err;
}

outcome run(std::string_view text, std::string_view lf_message = plain, const sieve::context& c = {},
            std::string_view from = "alice@example.org", std::string_view to = "me@example.com")
{
    const auto s = must(text);
    const std::string bytes = crlf_lines(lf_message);
    return s->run({bytes, from, to}, c);
}

// The actions in one line: "keep", "fileinto:x", "redirect:a@b", "discard", "reject:why", "vacation".
std::string summary(const outcome& o)
{
    std::string out;
    for (const auto& a : o.actions)
    {
        if (!out.empty())
            out += ",";
        switch (a.k)
        {
            case kind::keep: out += "keep"; break;
            case kind::fileinto: out += "fileinto:" + a.arg; break;
            case kind::redirect: out += "redirect:" + a.arg; break;
            case kind::discard: out += "discard"; break;
            case kind::reject: out += (a.ereject ? "ereject:" : "reject:") + a.arg; break;
            case kind::vacation: out += "vacation"; break;
            case kind::notify: out += "notify:" + a.arg; break;
        }
    }
    return out;
}

std::string summary_of(std::string_view text, std::string_view lf_message = plain)
{
    const outcome o = run(text, lf_message);
    INFO(o.error);
    CHECK(o.error.empty());
    return summary(o);
}

// The value `set` leaves in "b", read back through fileinto.
std::string set_value(std::string_view sets)
{
    const outcome o = run("require [\"variables\", \"fileinto\"];\n" + std::string(sets) + "\nfileinto \"${b}\";");
    REQUIRE(o.actions.size() >= 1);
    return o.actions.front().arg;
}

const action* find(const outcome& o, kind k)
{
    for (const auto& a : o.actions)
        if (a.k == k)
            return &a;
    return nullptr;
}

}   // namespace

TEST_CASE("sieve: an empty script and the base actions")
{
    CHECK(summary_of("") == "keep");
    CHECK(summary_of("# nothing but a comment\n/* and a\n bracketed one */") == "keep");
    CHECK(summary_of("discard;") == "discard");
    CHECK(summary_of("keep;") == "keep");
    CHECK(summary_of("stop; discard;") == "keep");
    CHECK(summary_of("discard; keep;") == "discard,keep");
    CHECK(summary_of("redirect \"bob@example.net\";") == "redirect:bob@example.net");
    CHECK(summary_of("redirect \"Bob <bob@Example.NET>\"; redirect \"bob@example.net\";") ==
          "redirect:bob@example.net");
    CHECK(summary_of("if true { discard; } else { keep; }") == "discard");
    CHECK(summary_of("if false { discard; } elsif not true { discard; } else { keep; }") == "keep");
    CHECK(sieve::extensions().find("vacation-seconds") != std::string_view::npos);
    CHECK(sieve::extensions().find("comparator-i;ascii-numeric") != std::string_view::npos);
}

TEST_CASE("sieve: RFC 5228's complex example files each kind of message where it says")
{
    const std::string_view script = R"S(#
# Example Sieve Filter
# Declare any optional features or extension used by the script
#
require ["fileinto"];

#
# Handle messages from known mailing lists
# Move messages from IETF filter discussion list to filter mailbox
#
if header :is "Sender" "owner-ietf-mta-filters@imc.org"
        {
        fileinto "filter";  # move to "filter" mailbox
        }
#
# Keep all messages to or from people in my company
#
elsif address :DOMAIN :is ["From", "To"] "example.com"
        {
        keep;               # keep in "In" mailbox
        }

#
# Try and catch unsolicited email.  If a message is not to me,
# or it contains a subject known to be spam, file it away.
#
elsif anyof (NOT address :all :contains
               ["To", "Cc", "Bcc"] "me@example.com",
             header :matches "subject"
               ["*make*money*fast*", "*university*dipl*mas*"])
        {
        fileinto "spam";   # move to "spam" mailbox
        }
else
        {
        # Move all other (non-company) mail to "personal"
        # mailbox.
        fileinto "personal";
        }
)S";
    CHECK(summary_of(script, "Sender: owner-ietf-mta-filters@imc.org\nTo: x@y.test\n\nb\n") == "fileinto:filter");
    CHECK(summary_of(script, "From: boss@example.com\nTo: x@y.test\n\nb\n") == "keep");
    CHECK(summary_of(script, "From: a@b.test\nTo: other@c.test\n\nb\n") == "fileinto:spam");
    CHECK(summary_of(script, "From: a@b.test\nTo: me@example.com\nSubject: MAKE your MONEY FAST\n\nb\n") ==
          "keep");
    CHECK(summary_of(script, "From: a@b.test\nCc: me@example.com\nSubject: make some money fast\n\nb\n") ==
          "fileinto:spam");
    CHECK(summary_of(script, "From: a@b.test\nCc: me@example.com\nSubject: lunch\n\nb\n") == "fileinto:personal");
}

TEST_CASE("sieve: strings, multi-line text with dot-stuffing and escapes")
{
    outcome o = run("require \"reject\";\nreject text: # a comment\n..dot\nline two\n.\n;");
    REQUIRE(o.actions.size() == 1);
    CHECK(o.actions[0].arg == ".dot\r\nline two\r\n");
    o = run("require \"reject\"; reject \"say \\\"hi\\\" \\\\ \\q\";");
    CHECK(o.actions[0].arg == "say \"hi\" \\ q");
    o = run("require \"fileinto\"; if header :is \"Subject\" \"Hello there\" { fileinto \"a\"; }");
    CHECK(summary(o) == "fileinto:a");
    CHECK(summary_of("if header :is \"subject\" \"hello THERE\" { discard; }") == "discard");
    CHECK(summary_of("if header :comparator \"i;octet\" :is \"subject\" \"hello THERE\" { discard; }") == "keep");
    CHECK(summary_of("if header :contains \"subject\" \"\" { discard; }") == "discard");
    CHECK(summary_of("if header :contains \"x-none\" \"\" { discard; }") == "keep");
    CHECK(summary_of("if exists [\"From\", \"Date\"] { discard; }") == "discard");
    CHECK(summary_of("if exists [\"From\", \"X-Nope\"] { discard; }") == "keep");
}

TEST_CASE("sieve: size with K, M and G")
{
    CHECK(summary_of("if size :over 100 { discard; }") == "discard");
    CHECK(summary_of("if size :over 1K { discard; }") == "keep");
    CHECK(summary_of("if size :under 1M { discard; }") == "discard");
    CHECK(summary_of("if size :under 1g { discard; }") == "discard");
    CHECK(compile_error("if size 10 { discard; }").starts_with("line 1:"));
}

TEST_CASE("sieve: compile errors say the line")
{
    CHECK(compile_error("frobnicate;") == "line 1: unknown command \"frobnicate\"");
    CHECK(compile_error("keep;\nfileinto \"x\";").starts_with("line 2: fileinto needs require"));
    CHECK(compile_error("keep;\nrequire \"fileinto\";").starts_with("line 2: require comes before"));
    CHECK(compile_error("elsif true { keep; }").starts_with("line 1: elsif that follows no if"));
    CHECK(compile_error("if true { keep; } keep; else { keep; }").starts_with("line 1: else that follows no if"));
    CHECK(compile_error("\n\nkeep").starts_with("line 3:"));
    CHECK(compile_error("reject \"x\";").find("needs require \"reject\"") != std::string::npos);
    CHECK(compile_error("require \"nonsense\";") == "line 1: unsupported extension \"nonsense\"");
    CHECK(compile_error("keep \"x\";").starts_with("line 1: too many arguments"));
    CHECK(compile_error("if header :frob \"a\" \"b\" { keep; }").find("unknown tag :frob") != std::string::npos);
    CHECK(compile_error("if header :is :contains \"a\" \"b\" { keep; }").find("more than one match type") !=
          std::string::npos);
    CHECK(compile_error("redirect \"not an address\";").find("no address") != std::string::npos);
    CHECK(compile_error("\"open").starts_with("line 1: a string that is never closed"));
    CHECK(compile_error("/* open").starts_with("line 1: a comment"));
    CHECK(compile_error("require \"fileinto\"; fileinto \"\";").find("no mailbox") != std::string::npos);
    CHECK(compile_error("if header :comparator \"i;frob\" :is \"a\" \"b\" { keep; }").find("unknown comparator") !=
          std::string::npos);
    CHECK(compile_error("keep; }").find("closes no block") != std::string::npos);
}

TEST_CASE("sieve: the address test reads RFC 5322 address lists")
{
    const std::string_view m = R"(From: "Joe Q. Public" <john.q.public@example.com>
To: Mary Smith <mary@x.test>, jdoe@example.org, Who? <one@y.test>
Cc: <boss@nil.test>, "Giant; \"Big\" Box" <sysservices@example.net>
Bcc: A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>;
Resent-To: Pete(A nice \) chap) <pete(his account)@silly.test(his host)>
Reply-To: Undisclosed recipients:;
Sender: "very.unusual.@.unusual.com"@example.com

b
)";
    CHECK(summary_of("if address :is \"from\" \"john.q.public@example.com\" { discard; }", m) == "discard");
    CHECK(summary_of("if address :localpart :is \"from\" \"john.q.public\" { discard; }", m) == "discard");
    CHECK(summary_of("if address :domain :is \"to\" \"y.test\" { discard; }", m) == "discard");
    CHECK(summary_of("if address :is \"to\" \"Who?\" { discard; }", m) == "keep");
    CHECK(summary_of("if address :is \"cc\" \"sysservices@example.net\" { discard; }", m) == "discard");
    CHECK(summary_of("if address :is \"bcc\" \"joe@where.test\" { discard; }", m) == "discard");
    CHECK(summary_of("if address :is \"bcc\" \"jdoe@one.test\" { discard; }", m) == "discard");
    CHECK(summary_of("if address :is \"resent-to\" \"pete@silly.test\" { discard; }", m) == "discard");
    CHECK(summary_of("if address :localpart :is \"sender\" \"very.unusual.@.unusual.com\" { discard; }", m) ==
          "discard");
    CHECK(summary_of("if address :matches \"reply-to\" \"*\" { discard; }", m) == "keep");
    CHECK(summary_of("require \"relational\"; if address :count \"eq\" \"bcc\" \"3\" { discard; }", m) ==
          "discard");
    CHECK(summary_of("require \"relational\"; if address :count \"eq\" [\"to\", \"cc\"] \"5\" { discard; }", m) ==
          "discard");
}

TEST_CASE("sieve: envelope, and subaddress's :user and :detail")
{
    const auto s = must("require [\"envelope\", \"subaddress\", \"fileinto\"];\n"
                        "if envelope :detail \"to\" \"mta-filters\" { fileinto \"lists\"; }\n"
                        "elsif envelope :user :is \"to\" \"ken\" { fileinto \"ken\"; }\n"
                        "elsif envelope :all \"from\" \"\" { fileinto \"bounces\"; }");
    const std::string bytes = crlf_lines(plain);
    CHECK(summary(s->run({bytes, "a@b.test", "ken+mta-filters@example.org"}, {})) == "fileinto:lists");
    CHECK(summary(s->run({bytes, "a@b.test", "ken@example.org"}, {})) == "fileinto:ken");
    CHECK(summary(s->run({bytes, "a@b.test", "ken+other@example.org"}, {})) == "fileinto:ken");
    CHECK(summary(s->run({bytes, "", "bob@example.org"}, {})) == "fileinto:bounces");
    const auto d = must("require [\"envelope\", \"subaddress\"]; if envelope :detail \"to\" \"\" { discard; }");
    CHECK(summary(d->run({bytes, "a@b.test", "ken+@example.org"}, {})) == "discard");
    CHECK(summary(d->run({bytes, "a@b.test", "ken@example.org"}, {})) == "keep");
    CHECK(compile_error("require \"envelope\"; if envelope \"auth\" \"x\" { keep; }").find("envelope part") !=
          std::string::npos);
    CHECK(compile_error("if address :detail \"to\" \"x\" { keep; }").find("subaddress") != std::string::npos);
}

TEST_CASE("sieve: encoded-character")
{
    outcome o = run("require [\"encoded-character\", \"fileinto\"]; fileinto \"${hex: 42 43}${unicode:263a}x\";");
    CHECK(o.actions.at(0).arg == "BC\xe2\x98\xba" "x");
    o = run("require [\"fileinto\"]; fileinto \"${hex:42}\";");
    CHECK(o.actions.at(0).arg == "${hex:42}");
    o = run("require [\"encoded-character\", \"fileinto\"]; fileinto \"${hex:4G}\";");
    CHECK(o.actions.at(0).arg == "${hex:4G}");
    CHECK(compile_error("require \"encoded-character\"; keep :x \"${unicode:D800}\";")
              .find("no Unicode code point") != std::string::npos);
}

TEST_CASE("sieve: :matches wildcards and escapes")
{
    CHECK(summary_of("if header :matches \"subject\" \"Hel?o*\" { discard; }") == "discard");
    CHECK(summary_of("if header :matches \"subject\" \"*there\" { discard; }") == "discard");
    CHECK(summary_of("if header :matches \"subject\" \"Hello\" { discard; }") == "keep");
    CHECK(summary_of("if header :matches \"subject\" \"Hello\\\\*\" { discard; }") == "keep");
    CHECK(summary_of("if header :matches \"subject\" \"Hello\\\\*\" { discard; }", "Subject: Hello*\n\nb\n") ==
          "discard");
    CHECK(summary_of("if header :matches \"subject\" \"?\" { discard; }", "Subject: \xc3\xa4\n\nb\n") == "discard");
    CHECK(summary_of("if header :comparator \"i;octet\" :matches \"subject\" \"?\" { discard; }",
                     "Subject: \xc3\xa4\n\nb\n") == "keep");
    CHECK(summary_of("if header :matches \"subject\" \"\" { discard; }", "Subject:\n\nb\n") == "discard");
}

TEST_CASE("sieve: :matches is quadratic at worst, never exponential")
{
    std::string pattern;
    for (int i = 0; i < 40; ++i)
        pattern += "*a";
    pattern += "*b";
    const std::string message = "Subject: " + std::string(20000, 'a') + "\n\nb\n";
    const auto start = std::chrono::steady_clock::now();
    const outcome o = run("if header :matches \"subject\" \"" + pattern + "\" { discard; }", message);
    const auto took = std::chrono::steady_clock::now() - start;
    CHECK(o.error.empty());
    CHECK(summary(o) == "keep");
    CHECK(took < std::chrono::seconds(2));
}

TEST_CASE("sieve: variables, RFC 5229's examples")
{
    CHECK(summary_of("require [\"variables\", \"fileinto\"];\n"
                     "if header :matches \"List-ID\" \"*<*@*\" { fileinto \"INBOX.lists.${2}\"; stop; }",
                     "List-ID: Coyote list <coyote-list@lists.example.org>\n\nb\n") ==
          "fileinto:INBOX.lists.coyote-list");
    CHECK(summary_of("require [\"variables\", \"fileinto\"];\n"
                     "if header :matches \"Subject\" \"[*] *\" { fileinto \"${1}/${2}\"; }",
                     "Subject: [acme-users] [fwd] version 1.0 is out\n\nb\n") ==
          "fileinto:acme-users/[fwd] version 1.0 is out");
    CHECK(summary_of("require [\"variables\", \"fileinto\"];\n"
                     "if address :matches \"from\" \"*@*\" { fileinto \"${0}|${1}|${2}|${3}|${100}\"; }") ==
          "fileinto:alice@example.org|alice|example.org||");
    const outcome o = run(R"(require ["variables", "reject"];
set "honorific"  "Mr";
set "first_name" "Wile";
set "last_name"  "Coyote";
set "vacation" text:
Dear ${HONORIFIC} ${last_name},
I'm out, please leave a message after the meep.
.
;
reject "${vacation}${unknown}${ not a name }";)");
    CHECK(o.actions.at(0).arg ==
          "Dear Mr Coyote,\r\nI'm out, please leave a message after the meep.\r\n${ not a name }");
    CHECK(set_value("set \"a\" \"juMBlEd lETteRS\"; set \"b\" \"${a}\";") == "juMBlEd lETteRS");
    CHECK(set_value("set \"a\" \"juMBlEd lETteRS\"; set :length \"b\" \"${a}\";") == "15");
    CHECK(set_value("set \"a\" \"juMBlEd lETteRS\"; set :lower \"b\" \"${a}\";") == "jumbled letters");
    CHECK(set_value("set \"a\" \"juMBlEd lETteRS\"; set :upperfirst \"b\" \"${a}\";") == "JuMBlEd lETteRS");
    CHECK(set_value("set \"a\" \"juMBlEd lETteRS\"; set :upperfirst :lower \"b\" \"${a}\";") == "Jumbled letters");
    CHECK(set_value("set :quotewildcard \"b\" \"Rock*\";") == "Rock\\*");
    CHECK(set_value("set :length \"b\" \"\xc3\xa4\xc3\xb6\";") == "2");
    CHECK(compile_error("require \"variables\"; set :lower :upper \"b\" \"x\";").find("precedence") !=
          std::string::npos);
    CHECK(compile_error("require \"variables\"; set \"1b\" \"x\";").find("no variable name") != std::string::npos);
    CHECK(summary_of("require \"variables\"; if string :is \"${nothing}\" \"\" { discard; }") == "discard");
    CHECK(summary_of("require [\"variables\", \"relational\"]; set \"a\" \"x\";\n"
                     "if string :count \"eq\" [\"${a}\", \"\", \"y\"] \"2\" { discard; }") == "discard");
    // A pattern taken from a variable is matched as a pattern, and :quotewildcard makes it a literal.
    CHECK(summary_of("require \"variables\"; set \"p\" \"H*\"; if header :matches \"subject\" \"${p}\" { discard; "
                     "}") == "discard");
    CHECK(summary_of("require \"variables\"; set :quotewildcard \"p\" \"H*\"; if header :matches \"subject\" "
                     "\"${p}\" { discard; }") == "keep");
}

TEST_CASE("sieve: relational, RFC 5231's example")
{
    const std::string_view script = R"(require ["relational", "comparator-i;ascii-numeric", "fileinto"];
if header :value "lt" :comparator "i;ascii-numeric" ["x-priority"] ["3"] { fileinto "Priority"; }
elsif address :count "gt" :comparator "i;ascii-numeric" ["to"] ["5"] { fileinto "Mailing List"; }
elsif address :value "gt" :comparator "i;ascii-casemap" ["from"] ["M"] { fileinto "From N-Z"; }
else { fileinto "From A-M"; })";
    CHECK(summary_of(script, "X-Priority: 1\nFrom: zed@x.test\n\nb\n") == "fileinto:Priority");
    CHECK(summary_of(script, "X-Priority: 4\nTo: a@x, b@x, c@x, d@x, e@x, f@x\nFrom: a@x.test\n\nb\n") ==
          "fileinto:Mailing List");
    CHECK(summary_of(script, "From: Nobody <nobody@x.test>\n\nb\n") == "fileinto:From N-Z");
    CHECK(summary_of(script, "From: alice@x.test\n\nb\n") == "fileinto:From A-M");
    // A value that is no number sorts after every number, and equals any other that is none.
    CHECK(summary_of(script, "X-Priority: high\nFrom: alice@x.test\n\nb\n") == "fileinto:From A-M");
    CHECK(summary_of("require [\"comparator-i;ascii-numeric\"];\n"
                     "if header :is :comparator \"i;ascii-numeric\" \"x-a\" \"007\" { discard; }",
                     "X-A: 7 apples\n\nb\n") == "discard");
    CHECK(compile_error("require [\"comparator-i;ascii-numeric\"];\n"
                        "if header :contains :comparator \"i;ascii-numeric\" \"x\" \"1\" { keep; }")
              .starts_with("line 2:"));
    CHECK(compile_error("if header :count \"gt\" \"x\" \"1\" { keep; }").find("relational") != std::string::npos);
    CHECK(compile_error("require \"relational\"; if header :value \"bigger\" \"x\" \"1\" { keep; }")
              .find("relational operator") != std::string::npos);
}

TEST_CASE("sieve: imap4flags, on fileinto, keep and the implicit keep")
{
    outcome o = run(R"(require ["imap4flags", "fileinto"];
if header :contains "from" "alice@example.org" {
    setflag "\\Flagged";
    fileinto "INBOX.From Alice";
})");
    REQUIRE(o.actions.size() == 1);
    CHECK(o.actions[0].flags == std::vector<std::string>{"\\Flagged"});
    o = run("require \"imap4flags\"; addflag \"\\\\Seen\"; addflag [\"\\\\Seen \\\\Answered\", \"Junk\"];"
            "removeflag \"junk\";");
    REQUIRE(o.actions.size() == 1);
    CHECK(o.actions[0].k == kind::keep);
    CHECK(o.actions[0].flags == std::vector<std::string>{"\\Seen", "\\Answered"});
    o = run("require [\"imap4flags\", \"fileinto\"]; addflag \"\\\\Seen\"; fileinto :flags \"\\\\Deleted\" \"t\";"
            "keep;");
    REQUIRE(o.actions.size() == 2);
    CHECK(o.actions[0].flags == std::vector<std::string>{"\\Deleted"});
    CHECK(o.actions[1].flags == std::vector<std::string>{"\\Seen"});
    CHECK(summary_of("require [\"imap4flags\", \"relational\"]; addflag \"a b c\";"
                     "if allof (hasflag :count \"ge\" \"3\", hasflag \"B\", not hasflag \"d\") { discard; }") ==
          "discard");
    CHECK(summary_of("require [\"imap4flags\", \"variables\"]; setflag \"mine\" \"\\\\Deleted\";"
                     "if allof (hasflag \"mine\" \"\\\\deleted\", not hasflag \"\\\\deleted\") { discard; }") ==
          "discard");
    o = run("require [\"imap4flags\", \"variables\", \"fileinto\"]; addflag \"v\" \"x\"; addflag \"v\" \"y x\";"
            "fileinto \"${v}\";");
    CHECK(o.actions.at(0).arg == "x y");
    CHECK(compile_error("keep :flags \"x\";").find("imap4flags") != std::string::npos);
}

TEST_CASE("sieve: copy keeps the implicit keep")
{
    CHECK(summary_of("require \"copy\"; redirect :copy \"bob@example.net\";") == "redirect:bob@example.net,keep");
    CHECK(summary_of("require [\"copy\", \"fileinto\"]; fileinto :copy \"Archive\";") == "fileinto:Archive,keep");
    CHECK(summary_of("require [\"copy\", \"fileinto\"]; fileinto :copy \"A\"; fileinto \"A\";") == "fileinto:A");
}

TEST_CASE("sieve: reject and ereject, and what they cannot stand beside")
{
    CHECK(summary_of("require \"reject\"; reject \"go away\";") == "reject:go away");
    CHECK(summary_of("require \"ereject\"; ereject \"no\";") == "ereject:no");
    CHECK(summary_of("require \"reject\"; discard; reject \"no\";") == "discard,reject:no");
    CHECK(compile_error("require \"reject\"; reject \"no\"; keep;").find("cannot be used") != std::string::npos);
    CHECK(compile_error("require [\"reject\", \"ereject\"]; reject \"no\"; ereject \"no\";").find("second") !=
          std::string::npos);
    CHECK(compile_error("require [\"reject\", \"fileinto\"]; fileinto \"x\";\nreject \"no\";")
              .starts_with("line 2:"));
    // Only a run can tell that both are reached when one stands in a branch.
    const outcome o = run("require [\"reject\", \"fileinto\"];\nif true { reject \"no\"; }\nfileinto \"x\";");
    CHECK(o.error.starts_with("line 3:"));
    CHECK(summary(o) == "keep");
    CHECK(summary_of("require \"reject\"; reject \"no\"; stop; keep;") == "reject:no");
}

TEST_CASE("sieve: vacation answers only mail a person sent to this user")
{
    const std::string_view script = R"(require "vacation";
if header :contains "subject" "cyrus" {
    vacation "I'm out -- send mail to cyrus-bugs";
} else {
    vacation "I'm out -- call me at +1 304 555 0123";
})";
    outcome o = run(script);
    const action* v = find(o, kind::vacation);
    REQUIRE(v);
    REQUIRE(v->v);
    CHECK(v->v->reason == "I'm out -- call me at +1 304 555 0123");
    CHECK(v->v->subject == "Auto: Hello there");
    CHECK(v->v->to == "alice@example.org");
    CHECK(v->v->seconds == 7 * 86400);
    CHECK(v->v->handle.size() == 16);
    CHECK(find(o, kind::keep));
    const std::string handle = v->v->handle;
    o = run(script, "From: a@b.test\nTo: me@example.com\nSubject: cyrus is down\n\nb\n");
    REQUIRE(find(o, kind::vacation));
    CHECK(find(o, kind::vacation)->v->handle != handle);
    CHECK(run(script).actions.front().v->handle == handle);

    const auto answered = [&](std::string_view message, std::string_view from = "alice@example.org",
                              const sieve::context& c = {}) {
        return find(run("require \"vacation\"; vacation \"away\";", message, c, from), kind::vacation) != nullptr;
    };
    CHECK(answered(plain));
    CHECK_FALSE(answered(plain, ""));
    CHECK_FALSE(answered(plain, "MAILER-DAEMON@example.org"));
    CHECK_FALSE(answered(plain, "owner-list@example.org"));
    CHECK_FALSE(answered(plain, "list-request@example.org"));
    CHECK_FALSE(answered(plain, "me@example.com"));
    CHECK_FALSE(answered("Auto-Submitted: auto-replied\nTo: me@example.com\n\nb\n"));
    CHECK(answered("Auto-Submitted: no (a person)\nTo: me@example.com\n\nb\n"));
    CHECK_FALSE(answered("List-Id: <x.example.org>\nTo: me@example.com\n\nb\n"));
    CHECK_FALSE(answered("List-Unsubscribe: <mailto:x@example.org>\nTo: me@example.com\n\nb\n"));
    CHECK_FALSE(answered("Precedence: Bulk\nTo: me@example.com\n\nb\n"));
    CHECK_FALSE(answered("To: list@example.org\n\nb\n"));
    CHECK(answered("To: list@example.org\nBcc: ME@example.com\n\nb\n"));
    CHECK(answered("Resent-To: me@example.com\n\nb\n"));
    sieve::context own;
    own.own = {"alias@example.com"};
    CHECK(answered("To: Alias <alias@example.com>\n\nb\n", "alice@example.org", own));
    CHECK(find(run("require \"vacation\"; vacation :addresses [\"alt@example.com\"] \"away\";",
                   "To: alt@example.com\n\nb\n"),
               kind::vacation));

    o = run(R"(require ["vacation", "vacation-seconds"];
vacation :seconds 0 :subject "Gone" :from "me@example.com" :handle "h1" :mime text:
Content-Type: text/plain

Back soon.
.
;)");
    v = find(o, kind::vacation);
    REQUIRE(v);
    CHECK(v->v->seconds == 3600);
    CHECK(v->v->subject == "Gone");
    CHECK(v->v->from == "me@example.com");
    CHECK(v->v->handle == "h1");
    CHECK(v->v->mime);
    o = run("require \"vacation\"; vacation :handle \"\" \"x\";");
    CHECK(find(o, kind::vacation)->v->handle.size() == 16);
    o = run("require \"vacation\"; vacation :days 14 \"x\";");
    CHECK(find(o, kind::vacation)->v->seconds == 14 * 86400);
    o = run("require \"vacation\"; vacation :days 0 \"x\";");
    CHECK(find(o, kind::vacation)->v->seconds == 86400);
    CHECK(compile_error("require \"vacation\"; vacation :seconds 5 \"x\";").find("vacation-seconds") !=
          std::string::npos);
    CHECK(compile_error("require [\"vacation\", \"reject\"]; vacation \"x\"; reject \"y\";").find("cannot") !=
          std::string::npos);
}

TEST_CASE("sieve: body, RFC 5173")
{
    const std::string_view mixed = R"(From: a@b.test
Subject: offer
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="XX"

prologue words
--XX
Content-Type: text/plain; charset=iso-8859-1
Content-Transfer-Encoding: quoted-printable

Caf=E9 MAKE MONEY=
 FAST
--XX
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: base64

PGI+Ym9sZDwvYj4=
--XX
Content-Type: application/octet-stream
Content-Transfer-Encoding: base64

c2VjcmV0IHdvcmQ=
--XX--
)";
    CHECK(summary_of("require \"body\"; if body :raw :contains \"MAKE MONEY=\" { discard; }", mixed) == "discard");
    CHECK(summary_of("require \"body\"; if body :contains \"make money fast\" { discard; }", mixed) == "discard");
    CHECK(summary_of("require \"body\"; if body :text :contains \"caf\xc3\xa9\" { discard; }", mixed) == "discard");
    CHECK(summary_of("require \"body\"; if body :text :contains \"<b>bold</b>\" { discard; }", mixed) == "discard");
    CHECK(summary_of("require \"body\"; if body :text :contains \"secret\" { discard; }", mixed) == "keep");
    CHECK(summary_of("require \"body\"; if body :content \"application\" :contains \"secret word\" { discard; }",
                     mixed) == "discard");
    CHECK(summary_of("require \"body\"; if body :content \"text/html\" :contains \"MONEY\" { discard; }", mixed) ==
          "keep");
    CHECK(summary_of("require \"body\"; if body :content \"multipart\" :contains \"prologue\" { discard; }",
                     mixed) == "discard");
    CHECK(summary_of("require \"body\"; if body :contains \"Body text\" { discard; }") == "discard");
    CHECK(compile_error("require [\"body\", \"relational\"]; if body :count \"gt\" \"1\" { keep; }").find("count") !=
          std::string::npos);
}

TEST_CASE("sieve: date and currentdate, RFC 5260")
{
    const std::string_view boss = R"(require ["date", "relational", "fileinto"];
if allof(header :is "from" "boss@example.com",
         date :value "ge" :originalzone "date" "hour" "09",
         date :value "lt" :originalzone "date" "hour" "17")
{ fileinto "urgent"; })";
    CHECK(summary_of(boss, "From: boss@example.com\nDate: Tue, 21 Feb 2023 14:42:51 -0800\n\nb\n") ==
          "fileinto:urgent");
    CHECK(summary_of(boss, "From: boss@example.com\nDate: Tue, 21 Feb 2023 18:42:51 -0800\n\nb\n") == "keep");
    const auto part = [](std::string_view zone, std::string_view p) {
        const outcome o = run("require [\"date\", \"variables\", \"fileinto\"];\n"
                              "if date " + std::string(zone) + " :matches \"date\" \"" + std::string(p) +
                              "\" \"*\" { fileinto \"${1}\"; }");
        return o.actions.at(0).arg;
    };
    CHECK(part(":zone \"+0000\"", "hour") == "22");
    CHECK(part(":originalzone", "hour") == "14");
    CHECK(part(":originalzone", "zone") == "-0800");
    CHECK(part(":zone \"+0100\"", "date") == "2023-02-21");
    CHECK(part(":zone \"+0200\"", "date") == "2023-02-22");
    CHECK(part(":originalzone", "weekday") == "2");
    CHECK(part(":originalzone", "julian") == "59996");
    CHECK(part(":originalzone", "iso8601") == "2023-02-21T14:42:51-08:00");
    CHECK(part(":zone \"+0000\"", "std11") == "Tue, 21 Feb 2023 22:42:51 +0000");
    CHECK(part(":originalzone", "time") == "14:42:51");
    sieve::context c;
    c.now_s = 1700000000;   // 2023-11-14T22:13:20Z
    c.zone_min = 60;
    CHECK(summary(run("require \"date\"; if currentdate :is \"date\" \"2023-11-14\" { discard; }", plain, c)) ==
          "discard");
    CHECK(summary(run("require \"date\"; if currentdate :is \"hour\" \"23\" { discard; }", plain, c)) == "discard");
    CHECK(summary(run("require \"date\"; if currentdate :zone \"-0500\" :is \"time\" \"17:13:20\" { discard; }",
                      plain, c)) == "discard");
    // The date test's default zone is the local one.
    CHECK(summary(run("require \"date\"; if date :is \"date\" \"hour\" \"23\" { discard; }", plain, c)) ==
          "discard");
    CHECK(summary_of("require \"date\"; if date :is \"date\" \"year\" \"2023\" { discard; }",
                     "Date: 21 Feb 23 14:42 EST\n\nb\n") == "discard");
    CHECK(summary_of("require \"date\"; if date :matches \"date\" \"year\" \"*\" { discard; }",
                     "Date: someday\n\nb\n") == "keep");
    CHECK(compile_error("require \"date\"; if date \"date\" \"fortnight\" \"1\" { keep; }").find("date part") !=
          std::string::npos);
    CHECK(compile_error("require \"date\"; if date :zone \"CET\" \"date\" \"hour\" \"1\" { keep; }")
              .find("zone") != std::string::npos);
    CHECK(compile_error("require \"date\"; if currentdate :originalzone \"hour\" \"1\" { keep; }")
              .find("unknown tag") != std::string::npos);
}

TEST_CASE("sieve: mailbox, mailboxexists and fileinto :create")
{
    sieve::context c;
    c.mailbox_exists = [](std::string_view f) { return f == "INBOX" || f == "Lists"; };
    const std::string_view script = R"(require ["mailbox", "fileinto"];
if mailboxexists "Lists" { fileinto "Lists"; }
if mailboxexists ["Lists", "Gone"] { fileinto "Gone"; }
fileinto :create "New";)";
    const outcome o = run(script, plain, c);
    CHECK(summary(o) == "fileinto:Lists,fileinto:New");
    CHECK_FALSE(o.actions[0].create);
    CHECK(o.actions[1].create);
    CHECK(summary(run(script)) == "fileinto:Lists,fileinto:Gone,fileinto:New");
}

TEST_CASE("sieve: header values are unfolded and RFC 2047 decoded")
{
    const std::string_view m = "Subject: =?UTF-8?B?w6RiYw==?= =?ISO-8859-1?Q?_Andr=E9?=\n"
                               "X-Folded: one\n two\n"
                               "X-Other: =?KOI8-R?B?9MXT1A==?=\n\nb\n";
    CHECK(summary_of("if header :is \"subject\" \"\xc3\xa4" "bc Andr\xc3\xa9\" { discard; }", m) == "discard");
    CHECK(summary_of("if header :is \"x-folded\" \"one two\" { discard; }", m) == "discard");
    CHECK(summary_of("if header :is \"x-other\" \"=?KOI8-R?B?9MXT1A==?=\" { discard; }", m) == "discard");
    CHECK(mime::decode_words("a =?utf-8?q?b?= c") == "a b c");
    CHECK(mime::decoded_body("a=3Db=\r\nc", "quoted-printable") == "a=bc");
    CHECK(mime::decoded_body("aGVs\r\nbG8=\r\n", "BASE64") == "hello");
}

TEST_CASE("sieve: the bounds a hostile script meets")
{
    CHECK(compile_error(std::string(64 * 1024 + 1, ' ')).find("64 KiB") != std::string::npos);
    std::string deep, close;
    for (int i = 0; i < 32; ++i)
    {
        deep += "if true {";
        close += "}";
    }
    std::string err;
    CHECK(sieve::script::compile(deep + "discard;" + close, err) != nullptr);
    CHECK_FALSE(sieve::script::compile("if true {" + deep + "discard;" + close + "}", err));
    CHECK(err.find("nested deeper than 32") != std::string::npos);
    std::string nots = "if ";
    for (int i = 0; i < 40; ++i)
        nots += "not ";
    CHECK(compile_error(nots + "true { keep; }").find("nested deeper than 32") != std::string::npos);
    CHECK(compile_error("if " + std::string(5000, '(') + "true" + std::string(5000, ')') + " {}").starts_with("line 1:"));

    std::string redirects;
    for (int i = 0; i < 4; ++i)
        redirects += "redirect \"u" + std::to_string(i) + "@example.net\";\n";
    CHECK(summary_of(redirects).find("u3@example.net") != std::string::npos);
    const outcome five = run(redirects + "redirect \"u9@example.net\";");
    CHECK(five.error == "line 5: more than 4 redirects");
    CHECK(summary(five) == "keep");

    std::string keys = "[";
    for (int i = 0; i < 12000; ++i)
        keys += std::string(i ? "," : "") + "\"k\"";
    keys += "]";
    std::string many;
    for (int i = 0; i < 100; ++i)
        many += "Subject: s\n";
    const outcome slow = run("if header :is \"subject\" " + keys + " { discard; }", many + "\nb\n");
    CHECK(slow.error.find("1,000,000 steps") != std::string::npos);
    CHECK(summary(slow) == "keep");

    std::string vars = "require \"variables\";\n";
    for (int i = 0; i < 129; ++i)
        vars += "set \"v" + std::to_string(i) + "\" \"x\";\n";
    CHECK(run(vars).error == "line 130: more than 128 variables");
    CHECK(set_value("set \"a\" \"" + std::string(5000, 'x') + "\"; set :length \"b\" \"${a}\";") == "4096");
    std::string refs;
    for (int i = 0; i < 20; ++i)
        refs += "${a}";
    const outcome big = run("require [\"variables\", \"fileinto\"]; set \"a\" \"" + std::string(4096, 'x') +
                            "\"; fileinto \"" + refs + "\";");
    CHECK(big.error.find("64 KiB") != std::string::npos);
}

TEST_CASE("sieve: a run never fails on what a message holds")
{
    const auto s = must("require [\"body\", \"date\", \"envelope\", \"vacation\"];\n"
                        "if anyof (body :contains \"x\", date :is \"date\" \"year\" \"2000\","
                        " address :domain :is \"to\" \"x\", envelope :is \"from\" \"\") { keep; }\n"
                        "vacation \"away\";");
    for (const std::string_view m : {std::string_view{}, std::string_view{"\r\n"}, std::string_view{"no colon"},
                                     std::string_view{"To: <<<@@@>>>, \"\r\n\r\n"},
                                     std::string_view{"Content-Type: multipart/mixed; boundary=a\r\n\r\n--a\r\n"}})
    {
        const outcome o = s->run({m, "", ""}, {});
        CHECK(o.error.empty());
        CHECK_FALSE(o.actions.empty());
    }
}

TEST_CASE("sieve: regex matches an extended expression and gives its groups")
{
    CHECK(summary_of(R"S(require ["regex", "variables", "fileinto"];
if header :regex "subject" "^hel+o (t[a-z]*)" { fileinto "${1}"; })S") == "fileinto:there");
    CHECK(summary_of(R"(require ["regex", "fileinto"];
if header :regex :comparator "i;octet" "subject" "^hello" { fileinto "x"; })") == "keep");
    CHECK(compile_error(R"(require "regex"; if header :regex "subject" "(a)\\1" { keep; })").find("refers back") !=
          std::string::npos);
    CHECK(compile_error(R"(require "regex"; if header :regex "subject" "a(" { keep; })").find("does not compile") !=
          std::string::npos);
    CHECK(compile_error(R"(if header :regex "subject" "a" { keep; })").find("regex") != std::string::npos);
    CHECK(set_value("require \"regex\"; set :quoteregex \"b\" \"a.b*(c)\";") == "a\\.b\\*\\(c\\)");
}

TEST_CASE("sieve: index picks one occurrence of a header, counted from either end")
{
    constexpr std::string_view two = "Received: from a.example\nReceived: from b.example\nSubject: x\n\nbody\n";
    CHECK(summary_of(R"(require ["index", "fileinto"];
if header :index 2 :contains "received" "b.example" { fileinto "second"; })", two) == "fileinto:second");
    CHECK(summary_of(R"(require ["index", "fileinto"];
if header :index 1 :last :contains "received" "a.example" { fileinto "x"; })", two) == "keep");
    CHECK(summary_of(R"(require ["index", "fileinto"];
if header :index 3 :contains "received" "example" { fileinto "x"; })", two) == "keep");
    CHECK(compile_error(R"(require "index"; if header :last "a" "b" { keep; })").find(":last needs :index") !=
          std::string::npos);
}

TEST_CASE("sieve: editheader changes the header later tests read and the message kept")
{
    sieve::outcome o = run(R"(require ["editheader", "fileinto"];
addheader "X-Filtered" "by sieve";
deleteheader "Subject";
deleteheader "Received";
addheader :last "X-Tail" "end";
if header :is "x-filtered" "by sieve" { fileinto "seen"; }
if exists "subject" { fileinto "no"; })");
    CHECK(o.error.empty());
    CHECK(summary(o) == "fileinto:seen");
    REQUIRE(o.header);
    CHECK(o.header->starts_with("X-Filtered: by sieve\r\n"));
    CHECK(o.header->find("Subject:") == std::string::npos);
    CHECK(o.header->ends_with("X-Tail: end\r\n\r\n"));
    CHECK_FALSE(run("keep;").header);
    o = run(R"(require "editheader"; deleteheader :contains "subject" "nothing";)");
    CHECK_FALSE(o.header);
    o = run(R"(require "editheader"; deleteheader :contains "subject" "hello";)");
    REQUIRE(o.header);
    CHECK(o.header->find("Subject") == std::string::npos);
    // A value's line ends are no way to write a header of one's own.
    o = run(R"(require ["editheader", "variables"]; set "v" "a${unicode:0d}${unicode:0a}Bcc: x@y"; addheader "X-A" "${v}";)");
    REQUIRE(o.header);
    CHECK(o.header->find("\r\nBcc:") == std::string::npos);
    CHECK(compile_error(R"(require "editheader"; addheader "Bad Name" "x";)").find("no header name") !=
          std::string::npos);
}

TEST_CASE("sieve: duplicate asks what was seen and tells what to keep")
{
    sieve::context c;
    std::string asked;
    c.seen = [&](std::string_view key) {
        asked = std::string(key);
        return false;
    };
    sieve::outcome o = run(R"(require ["duplicate", "fileinto"]; if duplicate { fileinto "dup"; })", plain, c);
    CHECK(summary(o) == "keep");
    CHECK(asked == std::string("\0<1@example.org>", 16));
    REQUIRE(o.seen.size() == 1);
    CHECK(o.seen[0].second == 12 * 3600);
    c.seen = [](std::string_view) { return true; };
    o = run(R"(require ["duplicate", "fileinto"]; if duplicate :seconds 60 :handle "h" { fileinto "dup"; })", plain, c);
    CHECK(summary(o) == "fileinto:dup");
    CHECK(o.seen.empty());
    o = run(R"(require ["duplicate", "fileinto"]; if duplicate :last :uniqueid "u" { fileinto "dup"; })", plain, c);
    REQUIRE(o.seen.size() == 1);
    CHECK(o.seen[0].first == std::string("\0u", 2));
    // A message without the ID is no duplicate, and nothing of it is kept.
    o = run(R"(require "duplicate"; if duplicate :header "X-None" { discard; })", plain, c);
    CHECK(summary(o) == "keep");
    CHECK(o.seen.empty());
}

TEST_CASE("sieve: include runs another script with its own variables and the global ones shared")
{
    const std::map<std::string, std::string> scripts = {
        {"lib", "require \"fileinto\"; fileinto \"Lib\";"},
        {"sub", "require [\"include\", \"variables\", \"fileinto\"]; global \"x\"; fileinto \"${x}${y}\";"},
        {"ret", "require [\"include\", \"fileinto\"]; return; fileinto \"no\";"},
        {"loop", "require \"include\"; include \"loop\";"},
    };
    const sieve::loader load = [&](bool global, std::string_view name, std::string& text) {
        const auto it = scripts.find((global ? "g:" : "") + std::string(name));
        if (it == scripts.end())
            return false;
        text = it->second;
        return true;
    };
    const auto with = [&](std::string_view text) {
        std::string err;
        const auto s = sieve::script::compile(text, err, load);
        INFO(err);
        REQUIRE(s);
        const std::string bytes = crlf_lines(plain);
        return s->run({bytes, "alice@example.org", "me@example.com"}, {});
    };
    CHECK(summary(with("require \"include\"; include \"lib\";")) == "fileinto:Lib");
    CHECK(summary(with("require \"include\"; include :once \"lib\"; include :once \"lib\";")) == "fileinto:Lib");
    CHECK(summary(with(R"(require ["include", "variables"]; global "x"; set "x" "v"; set "y" "local"; include "sub";)")) ==
          "fileinto:v");
    CHECK(summary(with(R"(require ["include", "variables", "fileinto"]; include "ret"; fileinto "after";)")) ==
          "fileinto:after");
    const sieve::outcome missing = with("require \"include\"; include \"nowhere\";");
    CHECK(missing.error.find("not there") != std::string::npos);
    CHECK(summary(with("require \"include\"; include :optional \"nowhere\";")) == "keep");
    std::string err;
    CHECK_FALSE(sieve::script::compile("require \"include\"; include \"loop\";", err, load));
    CHECK(err.find("includes itself") != std::string::npos);
    const auto s = sieve::script::compile("require \"include\"; include :global \"x\"; include \"lib\";", err, load);
    REQUIRE(s);
    CHECK(s->included().size() == 2);
}

TEST_CASE("sieve: environment, spamtest and virustest read what the server says")
{
    sieve::context c;
    c.host = "mx.example.com";
    c.remote_ip = "192.0.2.7";
    c.spam = 8;
    c.spam_percent = 75;
    c.virus = 1;
    const auto go = [&](std::string_view t) { return summary(run(t, plain, c)); };
    CHECK(go(R"(require ["environment", "fileinto"]; if environment "host" "mx.example.com" { fileinto "h"; })") ==
          "fileinto:h");
    CHECK(go(R"(require ["environment", "fileinto"]; if environment :matches "remote-ip" "192.0.2.*" { fileinto "ip"; })") ==
          "fileinto:ip");
    CHECK(go(R"(require ["environment", "fileinto"]; if environment "no-such-item" "" { fileinto "x"; })") == "keep");
    CHECK(go(R"(require ["spamtest", "relational", "comparator-i;ascii-numeric", "fileinto"];
if spamtest :value "ge" :comparator "i;ascii-numeric" "6" { fileinto "Junk"; })") == "fileinto:Junk");
    CHECK(go(R"(require ["spamtestplus", "relational", "comparator-i;ascii-numeric", "fileinto"];
if spamtest :percent :value "gt" :comparator "i;ascii-numeric" "70" { fileinto "Junk"; })") == "fileinto:Junk");
    CHECK(go(R"(require ["virustest", "fileinto"]; if virustest "1" { fileinto "clean"; })") == "fileinto:clean");
    CHECK(summary_of(R"(require ["spamtest", "fileinto"]; if spamtest "0" { fileinto "untested"; })") == "fileinto:untested");
    CHECK(compile_error(R"(require "spamtest"; if spamtest :percent "1" { keep; })").find("spamtestplus") !=
          std::string::npos);
}

TEST_CASE("sieve: enotify sends by mailto, and not about a message a machine sent")
{
    sieve::outcome o = run(R"(require ["enotify", "variables"];
set :encodeurl "s" "a b&c";
notify :importance "1" :message "New mail" "mailto:me@example.com?subject=${s}";)");
    CHECK(o.error.empty());
    CHECK(summary(o) == "notify:mailto:me@example.com?subject=a%20b%26c,keep");
    REQUIRE(o.actions[0].n);
    CHECK(o.actions[0].n->importance == "1");
    CHECK(o.actions[0].n->message == "New mail");
    std::vector<std::string> to;
    std::string subject, body;
    CHECK(sieve::parse_mailto(o.actions[0].arg, to, subject, body));
    CHECK(to == std::vector<std::string>{"me@example.com"});
    CHECK(subject == "a b&c");
    constexpr std::string_view automatic = "From: a@b.example\nAuto-Submitted: auto-replied\nSubject: x\n\nbody\n";
    CHECK(summary_of(R"(require "enotify"; notify "mailto:me@example.com";)", automatic) == "keep");
    CHECK(summary_of(R"(require ["enotify", "fileinto"];
if valid_notify_method ["mailto:a@b.example", "mailto:c@d.example"] { fileinto "ok"; }
if valid_notify_method "xmpp:a@b.example" { fileinto "no"; }
if notify_method_capability "mailto:a@b.example" "online" "maybe" { fileinto "maybe"; })") ==
          "fileinto:ok,fileinto:maybe");
    CHECK(compile_error(R"(require "enotify"; notify "xmpp:me@example.com";)").find("mailto") != std::string::npos);
}

TEST_CASE("sieve: ihave lets a block use what it names, and skips one naming what is not here")
{
    CHECK(summary_of(R"(require "ihave";
if ihave "fileinto" { fileinto "has"; })") == "fileinto:has");
    CHECK(summary_of(R"(require "ihave";
if ihave "x-unknown" { x_command :weird ["a"] { nested; } } else { discard; })") == "discard");
    const sieve::outcome o = run(R"(require "ihave"; error "no way";)");
    CHECK(o.error.find("no way") != std::string::npos);
    CHECK(compile_error(R"(if true { fileinto "x"; })").find("fileinto") != std::string::npos);
}

TEST_CASE("sieve: a text: line's single leading dot is its stuffing, and an unclosed one says where it began")
{
    CHECK(set_value("set \"b\" text:\n.note\n..two\n.\n;") == "note\r\n.two\r\n");
    CHECK(compile_error("require \"variables\";\nset \"b\" text:\nnever ended\n").starts_with("line 2:"));
}

TEST_CASE("sieve: vacation answers no message any Auto-Submitted makes automatic, and :from is a mailbox")
{
    constexpr std::string_view second = "From: Alice <alice@example.org>\nTo: me@example.com\nAuto-Submitted: no\n"
                                        "Auto-Submitted: auto-generated\nSubject: x\n\nbody\n";
    CHECK(summary_of(R"(require "vacation"; vacation "away";)", second) == "keep");
    const sieve::outcome o = run(R"(require ["vacation", "variables"];
set "f" "Me <me@example.com>${unicode:0d}${unicode:0a}Bcc: x@y.example";
vacation :from "${f}" "away";)");
    const auto* v = find(o, kind::vacation);
    REQUIRE(v);
    CHECK(v->v->from.find('\n') == std::string::npos);
    CHECK(v->v->from.find("Bcc") == std::string::npos);
}

TEST_CASE("sieve: a zone a variable gives that is no zone fails the run")
{
    const sieve::outcome o = run(R"(require ["date", "variables"]; set "z" "nowhere";
if currentdate :zone "${z}" "year" "2020" { discard; })");
    CHECK(o.error.find("zone") != std::string::npos);
}
