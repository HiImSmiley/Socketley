#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "runtime/storage/s3_select.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// S3 SelectObjectContent without a daemon: the request document and its refusals, the SQL subset over CSV and JSON
// fed in pieces split at every byte, the output encodings, ScanRange, the record size bound, and the event stream
// decoded and checked against a CRC-32 computed here bit by bit.

using namespace socketley::storage;

namespace {

std::string xml_text(std::string_view s)
{
    std::string out;
    for (const char c : s)
    {
        if (c == '<')
            out += "&lt;";
        else if (c == '>')
            out += "&gt;";
        else if (c == '&')
            out += "&amp;";
        else
            out.push_back(c);
    }
    return out;
}

std::string request(std::string_view expr, std::string_view input, std::string_view output = "<CSV/>",
                    std::string_view tail = "")
{
    std::string x = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    "<SelectObjectContentRequest xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Expression>";
    x += xml_text(expr);
    x += "</Expression><ExpressionType>SQL</ExpressionType><InputSerialization>";
    x += input;
    x += "</InputSerialization><OutputSerialization>";
    x += output;
    x += "</OutputSerialization>";
    x += tail;
    x += "</SelectObjectContentRequest>";
    return x;
}

constexpr std::string_view csv_none   = "<CSV><FileHeaderInfo>NONE</FileHeaderInfo></CSV>";
constexpr std::string_view csv_use    = "<CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV>";
constexpr std::string_view csv_ignore = "<CSV><FileHeaderInfo>IGNORE</FileHeaderInfo></CSV>";
constexpr std::string_view csv_quoted =
    "<CSV><FileHeaderInfo>NONE</FileHeaderInfo><AllowQuotedRecordDelimiter>TRUE</AllowQuotedRecordDelimiter></CSV>";
constexpr std::string_view json_lines = "<JSON><Type>LINES</Type></JSON>";
constexpr std::string_view json_doc   = "<JSON><Type>DOCUMENT</Type></JSON>";
constexpr std::string_view json_out   = "<JSON/>";

select_request req_of(std::string_view expr, std::string_view input, std::string_view output = "<CSV/>",
                      std::string_view tail = "")
{
    select_request r;
    s3_error e;
    const bool ok = parse_select_request(request(expr, input, output, tail), r, e);
    INFO(expr << " -> " << e.code << ": " << e.message);
    REQUIRE(ok);
    return r;
}

struct outcome
{
    bool        ok{false};
    std::string out;
    s3_error    err;
    uint64_t    scanned{0};
    uint64_t    returned{0};
    bool        done{false};
};

// The query over `data` fed `piece` bytes at a time, output taken after every piece as the runtime would.
outcome run_pieces(const select_request& req, std::string_view data, size_t piece, uint64_t object_size = 0)
{
    outcome o;
    select_engine e;
    s3_error err;
    if (!e.init(req, err, object_size))
    {
        o.err = err;
        return o;
    }
    piece = std::max<size_t>(piece, 1);
    for (size_t i = 0; i < data.size() && !e.done(); i += piece)
    {
        e.feed(data.substr(i, piece));
        o.out += e.take_output();
    }
    o.ok = e.finish();
    o.out += e.take_output();
    o.err      = e.error();
    o.scanned  = e.bytes_scanned();
    o.returned = e.bytes_returned();
    o.done     = e.done();
    CHECK(e.bytes_processed() == e.bytes_scanned());
    return o;
}

std::string run(std::string_view expr, std::string_view input, std::string_view data,
                std::string_view output = "<CSV/>")
{
    const outcome o = run_pieces(req_of(expr, input, output), data, data.size());
    INFO(expr << " -> " << o.err.code << ": " << o.err.message);
    CHECK(o.ok);
    CHECK(o.returned == o.out.size());
    return o.out;
}

// The code a query that compiles fails with while it runs.
std::string run_failure(std::string_view expr, std::string_view input, std::string_view data,
                        std::string_view output = "<CSV/>")
{
    const outcome o = run_pieces(req_of(expr, input, output), data, data.size());
    INFO(expr);
    CHECK_FALSE(o.ok);
    return o.err.code;
}

// The output of the query over `data` whole, then checked equal when the data is cut at every byte into two pieces
// and when it is fed one byte at a time.
std::string run_split(std::string_view expr, std::string_view input, std::string_view data,
                      std::string_view output = "<CSV/>")
{
    const select_request req = req_of(expr, input, output);
    const outcome whole = run_pieces(req, data, data.size());
    REQUIRE(whole.ok);
    for (size_t cut = 1; cut < data.size(); ++cut)
    {
        outcome o;
        select_engine e;
        s3_error err;
        REQUIRE(e.init(req, err));
        e.feed(data.substr(0, cut));
        o.out += e.take_output();
        e.feed(data.substr(cut));
        o.ok = e.finish();
        o.out += e.take_output();
        INFO("cut at " << cut);
        CHECK(o.ok);
        CHECK(o.out == whole.out);
    }
    const outcome bytes = run_pieces(req, data, 1);
    CHECK(bytes.ok);
    CHECK(bytes.out == whole.out);
    return whole.out;
}

std::string refusal(std::string_view xml)
{
    select_request r;
    s3_error e;
    const bool ok = parse_select_request(xml, r, e);
    INFO(xml);
    CHECK_FALSE(ok);
    return e.code;
}

std::string sql_refusal(std::string_view expr, std::string_view input = csv_none)
{
    select_request r;
    s3_error e;
    const bool ok = parse_select_request(request(expr, input), r, e);
    INFO(expr);
    CHECK_FALSE(ok);
    CHECK(e.status == 400);
    return e.code;
}

// ─── The event stream, decoded independently of the code under test ───

uint32_t crc32_ref(std::string_view s)
{
    uint32_t c = 0xFFFFFFFFu;
    for (const char ch : s)
    {
        c ^= static_cast<unsigned char>(ch);
        for (int k = 0; k < 8; ++k)
            c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    }
    return ~c;
}

uint32_t be32(std::string_view s, size_t at)
{
    uint32_t v = 0;
    for (size_t i = 0; i < 4; ++i)
        v = v << 8 | static_cast<unsigned char>(s[at + i]);
    return v;
}

void put32(std::string& out, uint32_t v)
{
    for (int i = 3; i >= 0; --i)
        out.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
}

struct message
{
    std::vector<std::pair<std::string, std::string>> headers;
    std::string payload;

    std::string header(std::string_view name) const
    {
        for (const auto& h : headers)
            if (h.first == name)
                return h.second;
        return "<absent>";
    }
};

// Walks one message, checking both lengths, both CRCs and that the headers end exactly where the prelude says.
bool decode(std::string_view m, message& out)
{
    if (m.size() < 16)
        return false;
    const uint32_t total = be32(m, 0);
    const uint32_t hlen  = be32(m, 4);
    if (total != m.size() || 12 + static_cast<size_t>(hlen) + 4 > m.size())
        return false;
    if (be32(m, 8) != crc32_ref(m.substr(0, 8)))
        return false;
    if (be32(m, m.size() - 4) != crc32_ref(m.substr(0, m.size() - 4)))
        return false;
    size_t at = 12;
    const size_t end = 12 + hlen;
    while (at < end)
    {
        const size_t nlen = static_cast<unsigned char>(m[at++]);
        if (at + nlen + 3 > end)
            return false;
        std::string name(m.substr(at, nlen));
        at += nlen;
        if (m[at++] != 7)
            return false;
        const size_t vlen = static_cast<size_t>(static_cast<unsigned char>(m[at]) << 8 | static_cast<unsigned char>(m[at + 1]));
        at += 2;
        if (at + vlen > end)
            return false;
        out.headers.emplace_back(std::move(name), std::string(m.substr(at, vlen)));
        at += vlen;
    }
    if (at != end)
        return false;
    out.payload = std::string(m.substr(end, m.size() - 4 - end));
    return true;
}

const std::string fruit = "1,apple,3.5\n2,banana,\n10,cherry,7\n";
const std::string people = "name,age,city\nalice,30,Oslo\nbob,25,\"Bergen, NO\"\ncarol,41,Tromso\n";

}   // namespace

// ─── The request document ───

TEST_CASE("a request document is read into every field it names")
{
    select_request r;
    s3_error e;
    const std::string x = request(
        "SELECT s._1 FROM S3Object s",
        "<CompressionType>NONE</CompressionType><CSV><FileHeaderInfo>ignore</FileHeaderInfo><Comments>;</Comments>"
        "<QuoteEscapeCharacter>\\</QuoteEscapeCharacter><RecordDelimiter>&#13;&#10;</RecordDelimiter>"
        "<FieldDelimiter>&#9;</FieldDelimiter><QuoteCharacter>&apos;</QuoteCharacter>"
        "<AllowQuotedRecordDelimiter>TRUE</AllowQuotedRecordDelimiter></CSV>",
        "<JSON><RecordDelimiter>;</RecordDelimiter></JSON>", "<RequestProgress><Enabled>true</Enabled></RequestProgress>");
    REQUIRE(parse_select_request(x, r, e));
    CHECK(r.expression == "SELECT s._1 FROM S3Object s");
    CHECK(r.progress);
    CHECK(r.input == select_format::csv);
    CHECK(r.csv_in.header == select_header::ignore);
    CHECK(r.csv_in.comments == ";");
    CHECK(r.csv_in.quote_escape == '\\');
    CHECK(r.csv_in.record_delimiter == "\r\n");
    CHECK(r.csv_in.field_delimiter == '\t');
    CHECK(r.csv_in.quote == '\'');
    CHECK(r.csv_in.allow_quoted_record_delimiter);
    CHECK(r.output == select_format::json);
    CHECK(r.json_record_delimiter == ";");
    CHECK_FALSE(r.has_scan_start);

    REQUIRE(parse_select_request(request("SELECT * FROM S3Object", json_lines,
                                         "<CSV><QuoteFields>ALWAYS</QuoteFields><FieldDelimiter>|</FieldDelimiter>"
                                         "<QuoteCharacter>'</QuoteCharacter><QuoteEscapeCharacter>\\</QuoteEscapeCharacter>"
                                         "<RecordDelimiter>;</RecordDelimiter></CSV>",
                                         "<ScanRange><Start>5</Start><End>9</End></ScanRange>"),
                                 r, e));
    CHECK(r.input == select_format::json);
    CHECK(r.json_type == select_json_type::lines);
    CHECK(r.output == select_format::csv);
    CHECK(r.csv_out.quote_always);
    CHECK(r.csv_out.field_delimiter == '|');
    CHECK(r.csv_out.quote == '\'');
    CHECK(r.csv_out.quote_escape == '\\');
    CHECK(r.csv_out.record_delimiter == ";");
    CHECK(r.has_scan_start);
    CHECK(r.has_scan_end);
    CHECK(r.scan_start == 5);
    CHECK(r.scan_end == 9);

    // The defaults, as a request that names none of them gets.
    REQUIRE(parse_select_request(request("SELECT * FROM S3Object", "<CSV/>"), r, e));
    CHECK(r.csv_in.header == select_header::none);
    CHECK(r.csv_in.comments == "#");
    CHECK(r.csv_in.record_delimiter == "\n");
    CHECK(r.csv_in.field_delimiter == ',');
    CHECK(r.csv_in.quote == '"');
    CHECK_FALSE(r.csv_in.allow_quoted_record_delimiter);
    CHECK_FALSE(r.csv_out.quote_always);
    CHECK_FALSE(r.progress);
    REQUIRE(parse_select_request(request("SELECT * FROM S3Object", "<JSON/>"), r, e));
    CHECK(r.json_type == select_json_type::document);
}

TEST_CASE("each malformed or unsupported request is refused with the code S3 uses")
{
    const std::string head = "<SelectObjectContentRequest>";
    const std::string io   = "<InputSerialization><CSV/></InputSerialization><OutputSerialization><CSV/></OutputSerialization>";
    CHECK(refusal("not xml") == "MalformedXML");
    CHECK(refusal("<Other/>") == "MalformedXML");
    CHECK(refusal(request("SELECT * FROM S3Object", "<CSV/>", "<CSV/>", "<Bogus/>")) == "MalformedXML");
    CHECK(refusal(request("SELECT * FROM S3Object", "<CSV><Unknown/></CSV>")) == "MalformedXML");
    CHECK(refusal(request("SELECT * FROM S3Object", "<CSV>text</CSV>")) == "MalformedXML");
    CHECK(refusal(head + "<ExpressionType>SQL</ExpressionType>" + io + "</SelectObjectContentRequest>") ==
          "MissingRequiredParameter");
    CHECK(refusal(head + "<Expression>SELECT * FROM S3Object</Expression>" + io + "</SelectObjectContentRequest>") ==
          "MissingRequiredParameter");
    CHECK(refusal(head + "<Expression>SELECT * FROM S3Object</Expression><ExpressionType>PLSQL</ExpressionType>" + io +
                  "</SelectObjectContentRequest>") == "InvalidExpressionType");

    select_request r;
    s3_error e;
    CHECK_FALSE(parse_select_request(
        request("SELECT * FROM S3Object", "<CompressionType>GZIP</CompressionType><CSV/>"), r, e));
    CHECK(e.code == "NotImplemented");
    CHECK(e.status == 501);
    CHECK(refusal(request("SELECT * FROM S3Object", "<CompressionType>BZIP2</CompressionType><CSV/>")) ==
          "NotImplemented");
    CHECK(refusal(request("SELECT * FROM S3Object", "<CompressionType>ZSTD</CompressionType><CSV/>")) ==
          "InvalidCompressionFormat");
    CHECK(refusal(request("SELECT * FROM S3Object", "<Parquet/>")) == "NotImplemented");
    CHECK(refusal(request("SELECT * FROM S3Object", "<CSV/><JSON/>")) == "ObjectSerializationConflict");
    CHECK(refusal(request("SELECT * FROM S3Object", "<CompressionType>NONE</CompressionType>")) ==
          "MissingRequiredParameter");
    CHECK(refusal(request("SELECT * FROM S3Object", "<CSV/>", "<CSV/><JSON/>")) == "ObjectSerializationConflict");
    CHECK(refusal(request("SELECT * FROM S3Object", "<CSV/>", "")) == "MissingRequiredParameter");
    CHECK(refusal(request("SELECT * FROM S3Object", "<CSV><FileHeaderInfo>SOMETIMES</FileHeaderInfo></CSV>")) ==
          "InvalidFileHeaderInfo");
    CHECK(refusal(request("SELECT * FROM S3Object", "<JSON><Type>ARRAY</Type></JSON>")) == "InvalidJsonType");
    CHECK(refusal(request("SELECT * FROM S3Object", "<CSV/>", "<CSV><QuoteFields>NEVER</QuoteFields></CSV>")) ==
          "InvalidQuoteFields");
    CHECK(refusal(request("SELECT * FROM S3Object", "<CSV><FieldDelimiter>::</FieldDelimiter></CSV>")) ==
          "InvalidRequestParameter");
    CHECK(refusal(request("SELECT * FROM S3Object", "<CSV><RecordDelimiter>abc</RecordDelimiter></CSV>")) ==
          "InvalidRequestParameter");
    CHECK(refusal(request("SELECT * FROM S3Object",
                          "<CSV><AllowQuotedRecordDelimiter>maybe</AllowQuotedRecordDelimiter></CSV>")) ==
          "InvalidRequestParameter");
    CHECK(refusal(request("SELECT * FROM S3Object", "<CSV/>", "<CSV/>",
                          "<ScanRange><Start>10</Start><End>5</End></ScanRange>")) == "InvalidRequestParameter");
    CHECK(refusal(request("SELECT * FROM S3Object", "<CSV/>", "<CSV/>", "<ScanRange><Start>x</Start></ScanRange>")) ==
          "InvalidRequestParameter");
    CHECK(refusal(request("SELECT * FROM S3Object", "<CSV/>", "<CSV/>", "<ScanRange></ScanRange>")) ==
          "InvalidRequestParameter");
    CHECK(refusal(request("SELECT * FROM S3Object", json_doc, "<CSV/>", "<ScanRange><Start>0</Start></ScanRange>")) ==
          "UnsupportedScanRangeInput");
    CHECK(refusal(request("SELECT * FROM S3Object", csv_quoted, "<CSV/>", "<ScanRange><Start>0</Start></ScanRange>")) ==
          "UnsupportedScanRangeInput");
    CHECK(refusal(request("SELECT * FROM S3Object", csv_use, "<CSV/>", "<ScanRange><Start>5</Start></ScanRange>")) ==
          "UnsupportedScanRangeInput");
    CHECK(refusal(request("SELECT * FROM S3Object WHERE _1 = '" + std::string(select_max_expression, 'a') + "'",
                          "<CSV/>")) == "ExpressionTooLong");
}

TEST_CASE("an expression that does not compile is refused with the parser's code before a byte is read")
{
    CHECK(sql_refusal("UPDATE S3Object") == "ParseExpectedKeyword");
    CHECK(sql_refusal("SELECT FROM S3Object") == "ParseEmptySelect");
    CHECK(sql_refusal("SELECT * S3Object") == "ParseSelectMissingFrom");
    CHECK(sql_refusal("SELECT * FROM S3Object WHERE") == "ParseExpectedExpression");
    CHECK(sql_refusal("SELECT * FROM S3Object LIMIT ten") == "ParseExpectedNumber");
    CHECK(sql_refusal("SELECT * FROM S3Object LIMIT -1") == "ParseExpectedNumber");
    CHECK(sql_refusal("SELECT 'open FROM S3Object") == "LexerInvalidLiteral");
    CHECK(sql_refusal("SELECT 12abc FROM S3Object") == "LexerInvalidLiteral");
    CHECK(sql_refusal("SELECT # FROM S3Object") == "LexerInvalidChar");
    CHECK(sql_refusal("SELECT _1 ! _2 FROM S3Object") == "LexerInvalidOperator");
    CHECK(sql_refusal("SELECT *, _1 FROM S3Object") == "ParseAsteriskIsNotAloneInSelectList");
    CHECK(sql_refusal("SELECT _1, * FROM S3Object") == "ParseAsteriskIsNotAloneInSelectList");
    CHECK(sql_refusal("SELECT CAST(_1 AS BLOB) FROM S3Object") == "ParseExpectedTypeName");
    CHECK(sql_refusal("SELECT CAST(_1 INT) FROM S3Object") == "ParseExpectedKeyword");
    CHECK(sql_refusal("SELECT CAST(_1 AS INT FROM S3Object") == "ParseExpectedRightParenBuiltinFunctionCall");
    CHECK(sql_refusal("SELECT SUM(*) FROM S3Object") == "ParseUnsupportedCallWithStar");
    CHECK(sql_refusal("SELECT NULLIF(_1) FROM S3Object") == "EvaluatorInvalidArguments");
    CHECK(sql_refusal("SELECT FOO(_1) FROM S3Object") == "UnsupportedSqlOperation");
    CHECK(sql_refusal("SELECT _1, COUNT(*) FROM S3Object") == "UnsupportedSqlStructure");
    CHECK(sql_refusal("SELECT SUM(COUNT(_1)) FROM S3Object") == "UnsupportedSqlStructure");
    CHECK(sql_refusal("SELECT _1 FROM S3Object WHERE COUNT(*) > 1") == "UnsupportedSqlOperation");
    CHECK(sql_refusal("SELECT _1 AS FROM S3Object") == "ParseExpectedIdentForAlias");
    CHECK(sql_refusal("SELECT * FROM Bucket") == "InvalidDataSource");
    CHECK(sql_refusal("SELECT * FROM S3Object WHERE _1 = 1 _2") == "ParseUnexpectedToken");
    CHECK(sql_refusal("SELECT x.* FROM S3Object s") == "InvalidTableAlias");
    CHECK(sql_refusal("SELECT _0 FROM S3Object") == "InvalidColumnIndex");
    CHECK(sql_refusal("SELECT name FROM S3Object") == "MissingHeaders");
    CHECK(sql_refusal("SELECT name FROM S3Object", csv_ignore) == "MissingHeaders");
    CHECK(sql_refusal("SELECT s.a FROM S3Object[*].x s") == "UnsupportedSqlStructure");
    CHECK(sql_refusal("SELECT * FROM S3Object WHERE _1 LIKE 'a' ESCAPE 'xy'") == "LikeInvalidInputs");
    CHECK(sql_refusal("SELECT * FROM S3Object WHERE _1 LIKE 'a!' ESCAPE '!'") == "LikeInvalidInputs");
    CHECK(sql_refusal("SELECT " + std::string(200, '(') + "1" + std::string(200, ')') + " FROM S3Object") ==
          "UnsupportedSqlStructure");
    std::string chain = "SELECT 1";
    for (int i = 0; i < 300; ++i)
        chain += " + 1";
    CHECK(sql_refusal(chain + " FROM S3Object") == "UnsupportedSqlStructure");

    // Keywords are read whatever their case, and a trailing semicolon is allowed.
    select_request r;
    s3_error e;
    CHECK(parse_select_request(request("select _1 from s3object where _1 is not null limit 1;", csv_none), r, e));
}

// ─── CSV ───

TEST_CASE("CSV with a header row: USE names the columns, IGNORE skips it, NONE reads it as data")
{
    CHECK(run("SELECT name, city FROM S3Object WHERE CAST(age AS INT) > 26", csv_use, people) ==
          "alice,Oslo\ncarol,Tromso\n");
    CHECK(run("SELECT s.NAME FROM S3Object s WHERE s.\"age\" < 30", csv_use, people) == "bob\n");
    CHECK(run("SELECT city FROM S3Object WHERE name = 'bob'", csv_use, people) == "\"Bergen, NO\"\n");
    CHECK(run("SELECT * FROM S3Object s LIMIT 1", csv_use, people, json_out) ==
          "{\"name\":\"alice\",\"age\":\"30\",\"city\":\"Oslo\"}\n");
    CHECK(run("SELECT name AS who, _2 FROM S3Object LIMIT 1", csv_use, people, json_out) ==
          "{\"who\":\"alice\",\"_2\":\"30\"}\n");
    CHECK(run("SELECT _1 FROM S3Object", csv_ignore, people) == "alice\nbob\ncarol\n");
    CHECK(run("SELECT _1 FROM S3Object", csv_none, people) == "name\nalice\nbob\ncarol\n");
    CHECK(run("SELECT * FROM S3Object LIMIT 2", csv_none, people, json_out) ==
          "{\"_1\":\"name\",\"_2\":\"age\",\"_3\":\"city\"}\n{\"_1\":\"alice\",\"_2\":\"30\",\"_3\":\"Oslo\"}\n");
    // A quoted name must match the header exactly, which "NAME" does not.
    CHECK(run_failure("SELECT s.\"NAME\" FROM S3Object s", csv_use, people) == "MissingHeaders");
}

TEST_CASE("quoted fields hold delimiters, newlines and doubled quotes wherever the pieces are cut")
{
    const std::string data = "a,\"b,c\",\"line1\nline2\",\"say \"\"hi\"\"\"\n#skip,me\n2,,x,\"\"\n";
    CHECK(run_split("SELECT * FROM S3Object", csv_quoted, data, json_out) ==
          "{\"_1\":\"a\",\"_2\":\"b,c\",\"_3\":\"line1\\nline2\",\"_4\":\"say \\\"hi\\\"\"}\n"
          "{\"_1\":\"2\",\"_2\":\"\",\"_3\":\"x\",\"_4\":\"\"}\n");
    CHECK(run_split("SELECT * FROM S3Object", csv_quoted, data) ==
          "a,\"b,c\",\"line1\nline2\",\"say \"\"hi\"\"\"\n2,,x,\n");

    // A two-byte record delimiter, inside quotes and out.
    const std::string crlf = "1,\"x\r\ny\"\r\n2,z\r\n";
    CHECK(run_split("SELECT _2 FROM S3Object",
                    "<CSV><RecordDelimiter>&#13;&#10;</RecordDelimiter>"
                    "<AllowQuotedRecordDelimiter>TRUE</AllowQuotedRecordDelimiter></CSV>",
                    crlf, json_out) == "{\"_2\":\"x\\r\\ny\"}\n{\"_2\":\"z\"}\n");

    // Without AllowQuotedRecordDelimiter the delimiter ends a record even inside quotes.
    CHECK(run("SELECT COUNT(*) FROM S3Object", csv_none, "1,\"a\nb\"\n") == "2\n");

    // CRLF lines under the default "\n" lose their '\r', and a blank line is no record.
    CHECK(run_split("SELECT _2 FROM S3Object", csv_none, "1,a\r\n\r\n2,b\r\n") == "a\nb\n");

    // A different quote, escape and field delimiter in, and others out.
    const std::string_view custom_in = "<CSV><FieldDelimiter>&#9;</FieldDelimiter><QuoteCharacter>'</QuoteCharacter>"
                                       "<QuoteEscapeCharacter>\\</QuoteEscapeCharacter></CSV>";
    CHECK(run_split("SELECT _2 FROM S3Object", custom_in, "x\t'it\\'s, \\q'\n", json_out) ==
          "{\"_2\":\"it's, \\\\q\"}\n");
    CHECK(run("SELECT _1, _2 FROM S3Object", custom_in, "x\t'it\\'s'\n",
              "<CSV><QuoteFields>ALWAYS</QuoteFields><FieldDelimiter>|</FieldDelimiter></CSV>") == "\"x\"|\"it's\"\n");
    CHECK(run("SELECT _1 FROM S3Object", csv_none, "\"say \"\"hi\"\"\"\n",
              "<CSV><QuoteEscapeCharacter>\\</QuoteEscapeCharacter><RecordDelimiter>;</RecordDelimiter></CSV>") ==
          "\"say \\\"hi\\\"\";");

    // The last record needs no delimiter after it.
    CHECK(run_split("SELECT _1 FROM S3Object", csv_none, "a\nb") == "a\nb\n");
}

TEST_CASE("WHERE compares numbers as numbers and strings as strings, with LIKE, IN, BETWEEN and IS NULL")
{
    CHECK(run("SELECT _2 FROM S3Object WHERE _1 > 2", csv_none, fruit) == "cherry\n");
    CHECK(run("SELECT _2 FROM S3Object WHERE _1 = '2'", csv_none, fruit) == "banana\n");
    CHECK(run("SELECT _2 FROM S3Object WHERE _1 = 2.0", csv_none, fruit) == "banana\n");
    CHECK(run("SELECT _2 FROM S3Object WHERE _2 >= 'banana'", csv_none, fruit) == "banana\ncherry\n");
    CHECK(run("SELECT _2 FROM S3Object WHERE _2 LIKE 'b%'", csv_none, fruit) == "banana\n");
    CHECK(run("SELECT _2 FROM S3Object WHERE _2 LIKE '_pple'", csv_none, fruit) == "apple\n");
    CHECK(run("SELECT _2 FROM S3Object WHERE _2 NOT LIKE '%an%'", csv_none, fruit) == "apple\ncherry\n");
    CHECK(run("SELECT _2 FROM S3Object WHERE _2 LIKE '%e%r%'", csv_none, fruit) == "cherry\n");
    CHECK(run("SELECT _2 FROM S3Object WHERE _2 IN ('apple', 'cherry')", csv_none, fruit) == "apple\ncherry\n");
    CHECK(run("SELECT _2 FROM S3Object WHERE _1 NOT IN (1, 10)", csv_none, fruit) == "banana\n");
    CHECK(run("SELECT _2 FROM S3Object WHERE _1 BETWEEN 2 AND 9", csv_none, fruit) == "banana\n");
    CHECK(run("SELECT _2 FROM S3Object WHERE _1 NOT BETWEEN 2 AND 9", csv_none, fruit) == "apple\ncherry\n");
    CHECK(run("SELECT _2 FROM S3Object WHERE _3 = ''", csv_none, fruit) == "banana\n");
    CHECK(run("SELECT _2 FROM S3Object WHERE _4 IS NULL", csv_none, fruit) == "apple\nbanana\ncherry\n");
    CHECK(run("SELECT _2 FROM S3Object WHERE _4 IS MISSING", csv_none, fruit) == "apple\nbanana\ncherry\n");
    CHECK(run("SELECT _2 FROM S3Object WHERE _3 IS NOT NULL", csv_none, fruit) == "apple\nbanana\ncherry\n");
    CHECK(run("SELECT _2 FROM S3Object WHERE _1 > 1 AND _2 <> 'cherry'", csv_none, fruit) == "banana\n");
    CHECK(run("SELECT _2 FROM S3Object WHERE _1 = 1 OR _1 = 10", csv_none, fruit) == "apple\ncherry\n");
    CHECK(run("SELECT _2 FROM S3Object WHERE NOT (_1 = 1) AND _2 != 'banana'", csv_none, fruit) == "cherry\n");
    CHECK(run("SELECT _2 FROM S3Object WHERE _4 = 1 OR _1 = 1", csv_none, fruit) == "apple\n");
    CHECK(run("SELECT _1 FROM S3Object WHERE _1 LIKE '50!%' ESCAPE '!'", csv_none, "50%\n50x\n") == "50%\n");
    CHECK(run("SELECT _1 FROM S3Object WHERE _1 LIKE _2", csv_none, "abc,a%\nabc,b%\n") == "abc\n");
    CHECK(run("SELECT _1 FROM S3Object WHERE _1 LIKE '_'", csv_none, "\xC3\xA9\nab\n") == "\xC3\xA9\n");
    CHECK(run_failure("SELECT _1 FROM S3Object WHERE _1", csv_none, "abc\n") == "InvalidDataType");
}

TEST_CASE("expressions: arithmetic, CAST, string functions, COALESCE and NULLIF")
{
    CHECK(run("SELECT _1 * 2 + 1, _1 / 4, _1 % 3, -_1 FROM S3Object", csv_none, fruit) ==
          "3,0,1,-1\n5,0,2,-2\n21,2,1,-10\n");
    CHECK(run("SELECT CAST(_3 AS FLOAT) * 2, CAST(_3 AS INT), CAST(_1 AS STRING) || '!' FROM S3Object WHERE _1 = 1",
              csv_none, fruit) == "7,3,1!\n");
    CHECK(run("SELECT CAST('TRUE' AS BOOL), CAST(0 AS BOOLEAN), 1.5 + 1, 7 / 2.0 FROM S3Object LIMIT 1", csv_none,
              fruit) == "true,false,2.5,3.5\n");
    CHECK(run("SELECT _2 || '-' || _1, UPPER(_2), LOWER('ABC'), CHAR_LENGTH(_2), CHARACTER_LENGTH('\xC3\xA9') "
              "FROM S3Object WHERE _1 = 1",
              csv_none, fruit) == "apple-1,APPLE,abc,5,1\n");
    CHECK(run("SELECT TRIM('  x  '), TRIM(LEADING 'x' FROM 'xxaxx'), TRIM(TRAILING FROM 'a  '), "
              "TRIM(BOTH 'ab' FROM 'abxba') FROM S3Object LIMIT 1",
              csv_none, fruit) == "x,axx,a,x\n");
    CHECK(run("SELECT SUBSTRING(_2 FROM 2 FOR 3), SUBSTRING(_2, 2), SUBSTRING(_2, 0, 2), SUBSTRING(_2, 9) "
              "FROM S3Object WHERE _1 = 1",
              csv_none, fruit) == "ppl,pple,a,\n");
    CHECK(run("SELECT COALESCE(_9, _2), NULLIF(_2, 'apple'), NULLIF(_2, 'x') FROM S3Object WHERE _1 = 1", csv_none,
              fruit) == "apple,,apple\n");
    CHECK(run("SELECT NULLIF(_2, 'apple') AS n, _9 AS gone FROM S3Object WHERE _1 = 1", csv_none, fruit, json_out) ==
          "{\"n\":null}\n");
    CHECK(run_failure("SELECT CAST(_2 AS INT) FROM S3Object", csv_none, fruit) == "CastFailed");
    CHECK(run_failure("SELECT _1 / 0 FROM S3Object", csv_none, fruit) == "InvalidRequest");
    CHECK(run_failure("SELECT 9223372036854775807 + _1 FROM S3Object", csv_none, fruit) == "IntegerOverflow");
    CHECK(run_failure("SELECT _2 + 1 FROM S3Object", csv_none, fruit) == "InvalidDataType");
    CHECK(run_failure("SELECT UPPER(5) FROM S3Object", csv_none, fruit) == "IncorrectSqlFunctionArgumentType");
    CHECK(run_failure("SELECT _1 FROM S3Object WHERE 5 LIKE 'a'", csv_none, fruit) == "LikeInvalidInputs");
}

TEST_CASE("aggregates return one record, over the rows WHERE keeps")
{
    CHECK(run("SELECT COUNT(*), SUM(_1), MIN(_1), MAX(_1), MIN(_2), MAX(_2) FROM S3Object", csv_none, fruit) ==
          "3,13,1,10,apple,cherry\n");
    CHECK(run("SELECT AVG(_1) FROM S3Object WHERE _1 < 5", csv_none, fruit) == "1.5\n");
    CHECK(run("SELECT SUM(CAST(_3 AS FLOAT)) FROM S3Object WHERE _3 <> ''", csv_none, fruit) == "10.5\n");
    // Ceph's INT() and FLOAT() are the casts by another name.
    CHECK(run("SELECT SUM(FLOAT(_3)) FROM S3Object WHERE _3 <> ''", csv_none, fruit) == "10.5\n");
    CHECK(run("SELECT MIN(INT(_3)) FROM S3Object WHERE _3 <> ''", csv_none, fruit) ==
          run("SELECT MIN(CAST(_3 AS INT)) FROM S3Object WHERE _3 <> ''", csv_none, fruit));
    CHECK(run("SELECT COUNT(_3), COUNT(_9) FROM S3Object", csv_none, fruit) == "3,0\n");
    CHECK(run("SELECT COUNT(*), SUM(_1) FROM S3Object WHERE _1 > 100", csv_none, fruit) == "0,\n");
    CHECK(run("SELECT SUM(_1) / COUNT(*) AS mean FROM S3Object", csv_none, fruit, json_out) == "{\"mean\":4}\n");
    CHECK(run("SELECT COUNT(*) FROM S3Object", csv_none, fruit, json_out) == "{\"_1\":3}\n");
    CHECK(run("SELECT COUNT(*) FROM S3Object LIMIT 0", csv_none, fruit).empty());
    CHECK(run("SELECT COUNT(*) FROM S3Object", csv_use, "") == "0\n");
    CHECK(run_failure("SELECT SUM(_2) FROM S3Object", csv_none, fruit) == "InvalidDataType");
    CHECK(run_split("SELECT COUNT(*), MAX(_1) FROM S3Object", csv_none, fruit) == "3,10\n");
}

TEST_CASE("LIMIT stops the scan at the record that reaches it")
{
    const select_request req = req_of("SELECT _2 FROM S3Object LIMIT 2", csv_none);
    const outcome o = run_pieces(req, fruit, 1);
    CHECK(o.ok);
    CHECK(o.out == "apple\nbanana\n");
    CHECK(o.done);
    // "1,apple,3.5\n" and "2,banana,\n" are the 22 bytes read.
    CHECK(o.scanned == 22);

    const outcome none = run_pieces(req_of("SELECT * FROM S3Object LIMIT 0", csv_none), fruit, 4);
    CHECK(none.ok);
    CHECK(none.out.empty());
    CHECK(none.scanned == 0);

    // Feeding more after done() changes nothing.
    select_engine e;
    s3_error err;
    REQUIRE(e.init(req, err));
    e.feed(fruit);
    CHECK(e.done());
    const std::string first = e.take_output();
    e.feed(fruit);
    CHECK(e.take_output().empty());
    CHECK(e.finish());
    CHECK(first == "apple\nbanana\n");
}

// ─── JSON ───

TEST_CASE("JSON LINES: one value per line, nested paths, NULL and MISSING")
{
    const std::string lines = "{\"a\":{\"b\":1},\"arr\":[10,20],\"name\":\"x\"}\n"
                              "{\"a\":{\"b\":2},\"arr\":[30],\"name\":null}\n"
                              "\n"
                              "{\"a\":{\"b\":3}}";
    CHECK(run_split("SELECT s.a.b, s.arr[1] FROM S3Object s", json_lines, lines, json_out) ==
          "{\"b\":1,\"_2\":20}\n{\"b\":2}\n{\"b\":3}\n");
    CHECK(run("SELECT s.a.b FROM S3Object s WHERE s.name IS NULL", json_lines, lines) == "2\n3\n");
    CHECK(run("SELECT s.a.b FROM S3Object s WHERE s.name IS MISSING", json_lines, lines) == "3\n");
    CHECK(run("SELECT s.arr FROM S3Object s WHERE s.a.b = 1", json_lines, lines, json_out) ==
          "{\"arr\":[10,20]}\n");
    CHECK(run("SELECT s.arr FROM S3Object s WHERE s.a.b = 1", json_lines, lines) == "\"[10,20]\"\n");
    CHECK(run("SELECT s.\"name\", s.A.B FROM S3Object s WHERE s.a.\"b\" = 1", json_lines, lines) == "x,1\n");
    CHECK(run("SELECT COUNT(*), SUM(s.a.b), COUNT(s.name), MAX(s.a.b) FROM S3Object s", json_lines, lines) ==
          "3,6,1,3\n");
    CHECK(run_failure("SELECT * FROM S3Object", json_lines, "{\"a\":}\n") == "JSONParsingError");
}

TEST_CASE("JSON DOCUMENT: top-level values one after another, each spanning any number of pieces")
{
    const std::string doc = "{\"x\":1, \"y\":\"a}\\\"b\"}\n  {\"x\":2,\n \"nested\":{\"k\":[1,{\"z\":\"q\"}]}}[1,2]";
    CHECK(run_split("SELECT * FROM S3Object", json_doc, doc, json_out) ==
          "{\"x\":1,\"y\":\"a}\\\"b\"}\n{\"x\":2,\"nested\":{\"k\":[1,{\"z\":\"q\"}]}}\n{\"_1\":[1,2]}\n");
    CHECK(run_split("SELECT s.nested.k[1].z FROM S3Object s WHERE s.x = 2", json_doc, doc, json_out) ==
          "{\"z\":\"q\"}\n");
    CHECK(run("SELECT i.n FROM S3Object[*].items[*] i", json_doc,
              "{\"items\":[{\"n\":1},{\"n\":2},{\"m\":3}]}", json_out) == "{\"n\":1}\n{\"n\":2}\n{}\n");
    CHECK(run("SELECT * FROM S3Object", json_doc, "{\"a\":1,\"b\":\"x,y\",\"c\":null,\"d\":true,\"e\":{\"f\":[]}}") ==
          // A nested value is written as its JSON, quoted with its quotes doubled as a field holding one must be.
          "1,\"x,y\",,true,\"{\"\"f\"\":[]}\"\n");
    CHECK(run("SELECT s.s, CHAR_LENGTH(s.s) FROM S3Object s", json_doc, "{\"s\":\"\\u00e9\\ud83d\\ude00\"}") ==
          "\xC3\xA9\xF0\x9F\x98\x80,2\n");
    CHECK(run("SELECT s.v * 2, s.f FROM S3Object s", json_doc, "{\"v\":21,\"f\":1.25e2}", json_out) ==
          "{\"_1\":42,\"f\":125}\n");
    CHECK(run_failure("SELECT * FROM S3Object", json_doc, "{\"x\":1") == "JSONParsingError");
    CHECK(run_failure("SELECT * FROM S3Object", json_doc, "{\"x\":}") == "JSONParsingError");
    CHECK(run_failure("SELECT * FROM S3Object", json_doc, "5") == "JSONParsingError");
    CHECK(run_failure("SELECT * FROM S3Object", json_doc, "{\"x\":\"\\ud800\"}") == "JSONParsingError");
}

TEST_CASE("JSON records are data: a name given twice, raw bytes and deep nesting are taken as written")
{
    CHECK(run("SELECT * FROM S3Object", json_doc, "{\"a\":1,\"a\":2}", json_out) == "{\"a\":1,\"a\":2}\n");
    CHECK(run("SELECT s.t FROM S3Object s", json_doc, "{\"t\":\"\xC0\xAF\"}") == "\xC0\xAF\n");
    const std::string deep = std::string(40, '[') + "1" + std::string(40, ']');
    CHECK(run("SELECT COUNT(*) FROM S3Object", json_doc, "{\"d\":" + deep + "}") == "1\n");
    CHECK(run_failure("SELECT * FROM S3Object", json_doc, "{\"t\":\"a\x01\"}") == "JSONParsingError");
}

// ─── Bounds ───

TEST_CASE("a record of more than 1 MiB fails the query, and one of exactly 1 MiB does not")
{
    const select_request csv  = req_of("SELECT _1 FROM S3Object", csv_none);
    const std::string    full = std::string(select_max_record, 'a') + "\n";
    const outcome ok = run_pieces(csv, full, 65536);
    CHECK(ok.ok);
    CHECK(ok.out.size() == select_max_record + 1);

    const outcome over = run_pieces(csv, std::string(select_max_record + 1, 'a'), 65536);
    CHECK_FALSE(over.ok);
    CHECK(over.err.code == "OverMaxRecordSize");

    const std::string big = "{\"v\":\"" + std::string(select_max_record, 'b') + "\"}\n";
    const outcome lines = run_pieces(req_of("SELECT * FROM S3Object", json_lines), big, 65536);
    CHECK_FALSE(lines.ok);
    CHECK(lines.err.code == "OverMaxRecordSize");
    const outcome document = run_pieces(req_of("SELECT * FROM S3Object", json_doc), big, 65536);
    CHECK_FALSE(document.ok);
    CHECK(document.err.code == "OverMaxRecordSize");

    // A record within the bound whose output is past it.
    const std::string half = std::string(select_max_record / 2 + 1, 'c') + "\n";
    CHECK(run_failure("SELECT _1 || _1 FROM S3Object", csv_none, half) == "OverMaxRecordSize");
}

TEST_CASE("ScanRange reads the records that start inside it, from the offset the engine asks for")
{
    const std::string data = "aa\nbb\ncc\ndd\n";
    struct range_case
    {
        std::string tail;
        uint64_t    object_size;
        uint64_t    first;
        std::string expect;
    };
    const range_case cases[] = {
        {"<ScanRange><Start>4</Start><End>6</End></ScanRange>", 0, 3, "cc\n"},
        {"<ScanRange><Start>3</Start><End>3</End></ScanRange>", 0, 2, "bb\n"},
        {"<ScanRange><Start>0</Start><End>0</End></ScanRange>", 0, 0, "aa\n"},
        {"<ScanRange><Start>1</Start></ScanRange>", 0, 0, "bb\ncc\ndd\n"},
        {"<ScanRange><End>6</End></ScanRange>", 12, 5, "cc\ndd\n"},
        {"<ScanRange><Start>11</Start></ScanRange>", 0, 10, ""},
    };
    for (const range_case& c : cases)
    {
        INFO(c.tail);
        const select_request req = req_of("SELECT _1 FROM S3Object", csv_none, "<CSV/>", c.tail);
        select_engine e;
        s3_error err;
        REQUIRE(e.init(req, err, c.object_size));
        CHECK(e.first_offset() == c.first);
        for (size_t piece : {size_t{1}, size_t{2}, data.size()})
        {
            const outcome o = run_pieces(req, std::string_view(data).substr(c.first), piece, c.object_size);
            CHECK(o.ok);
            CHECK(o.out == c.expect);
        }
    }

    // The scan stops once a record starts past End: bytes 3 to 8 are read, the delimiter before "cc" and "cc\n".
    const outcome o = run_pieces(req_of("SELECT _1 FROM S3Object", csv_none, "<CSV/>",
                                        "<ScanRange><Start>4</Start><End>6</End></ScanRange>"),
                                 std::string_view(data).substr(3), 1);
    CHECK(o.done);
    CHECK(o.scanned == 6);

    const select_request lines = req_of("SELECT s.v FROM S3Object s", json_lines, "<CSV/>",
                                        "<ScanRange><Start>9</Start></ScanRange>");
    const std::string jl = "{\"v\":1}\n{\"v\":2}\n{\"v\":3}\n";
    const outcome j = run_pieces(lines, std::string_view(jl).substr(8), 3);
    CHECK(j.ok);
    CHECK(j.out == "3\n");

    // End alone is the object's last bytes, which with a header to read the engine refuses.
    select_engine e;
    s3_error err;
    CHECK_FALSE(e.init(req_of("SELECT * FROM S3Object", csv_use, "<CSV/>", "<ScanRange><End>6</End></ScanRange>"),
                       err, 12));
    CHECK(err.code == "UnsupportedScanRangeInput");
}

TEST_CASE("the counters: scanned and processed are the bytes fed, returned the bytes of records written")
{
    const outcome o = run_pieces(req_of("SELECT _2 FROM S3Object WHERE _1 < 5", csv_none), fruit, 5);
    CHECK(o.ok);
    CHECK(o.scanned == fruit.size());
    CHECK(o.out == "apple\nbanana\n");
    CHECK(o.returned == o.out.size());
}

// ─── The event stream ───

TEST_CASE("the reference CRC is CRC-32 as zlib computes it")
{
    CHECK(crc32_ref("123456789") == 0xCBF43926u);
    CHECK(crc32_ref("") == 0u);
}

TEST_CASE("an End message is exactly the bytes the event-stream format gives it")
{
    std::string expect;
    put32(expect, 56);
    put32(expect, 40);
    put32(expect, crc32_ref(expect));
    expect.push_back(13);
    expect += ":message-type";
    expect.push_back(7);
    expect.push_back(0);
    expect.push_back(5);
    expect += "event";
    expect.push_back(11);
    expect += ":event-type";
    expect.push_back(7);
    expect.push_back(0);
    expect.push_back(3);
    expect += "End";
    put32(expect, crc32_ref(expect));
    const std::string got = select_end_event();
    CHECK(got.size() == 56);
    CHECK(got == expect);

    message m;
    REQUIRE(decode(got, m));
    CHECK(m.headers.size() == 2);
    CHECK(m.header(":message-type") == "event");
    CHECK(m.header(":event-type") == "End");
    CHECK(m.payload.empty());
}

TEST_CASE("Records, Stats, Progress, Cont and error messages decode with their headers and payloads")
{
    message rec;
    const std::string records = select_records_event("a,b\n");
    REQUIRE(decode(records, rec));
    CHECK(rec.header(":message-type") == "event");
    CHECK(rec.header(":event-type") == "Records");
    CHECK(rec.header(":content-type") == "application/octet-stream");
    CHECK(rec.payload == "a,b\n");
    CHECK(be32(records, 0) == records.size());

    const std::string xml = select_details_xml("Stats", 100, 100, 7);
    // The counters stand in the element itself, as the event's payload is S3's Stats or Progress type.
    CHECK(xml.find("<Stats><BytesScanned>100</BytesScanned><BytesProcessed>100</BytesProcessed>"
                   "<BytesReturned>7</BytesReturned></Stats>") != std::string::npos);
    message stats;
    REQUIRE(decode(select_stats_event(100, 100, 7), stats));
    CHECK(stats.header(":event-type") == "Stats");
    CHECK(stats.header(":content-type") == "text/xml");
    CHECK(stats.payload == xml);

    message progress;
    REQUIRE(decode(select_progress_event(1, 2, 3), progress));
    CHECK(progress.header(":event-type") == "Progress");
    CHECK(progress.payload == select_details_xml("Progress", 1, 2, 3));
    CHECK(progress.payload.find("<Progress><BytesScanned>1</BytesScanned>") != std::string::npos);

    message cont;
    REQUIRE(decode(select_cont_event(), cont));
    CHECK(cont.header(":event-type") == "Cont");
    CHECK(cont.header(":content-type") == "<absent>");
    CHECK(cont.payload.empty());

    message err;
    REQUIRE(decode(select_error_event("CastFailed", "Attempt to convert failed."), err));
    CHECK(err.header(":message-type") == "error");
    CHECK(err.header(":error-code") == "CastFailed");
    CHECK(err.header(":error-message") == "Attempt to convert failed.");
    CHECK(err.header(":event-type") == "<absent>");
    CHECK(err.payload.empty());

    // A header value is at most 65535 bytes, so a longer message is cut there and the stream stays decodable.
    message longer;
    REQUIRE(decode(select_error_event("InternalError", std::string(70000, 'm')), longer));
    CHECK(longer.header(":error-message").size() == 65535);

    // A flipped payload byte breaks the message CRC, which is what the decoder above is checking.
    std::string broken = records;
    broken[broken.size() - 6] ^= 1;
    message bad;
    CHECK_FALSE(decode(broken, bad));

    // Messages concatenated are walked one after another by their prelude lengths.
    const std::string stream = select_records_event("x\n") + select_stats_event(2, 2, 2) + select_end_event();
    std::vector<std::string> types;
    for (size_t at = 0; at < stream.size();)
    {
        const uint32_t len = be32(stream, at);
        message one;
        REQUIRE(decode(std::string_view(stream).substr(at, len), one));
        types.push_back(one.header(":event-type"));
        at += len;
    }
    CHECK(types == std::vector<std::string>{"Records", "Stats", "End"});
}
