// The QR encoder: a code another implementation draws bit for bit, the version each length needs, and none past ten.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <string>
#include <vector>

#include "shared/util/qr_code.h"

using socketley::qr::encode;

TEST_CASE("HELLO in byte mode at level M is the code a reference encoder draws")
{
    // From python-qrcode 8 in byte mode at level M with the same mask, and read back by OpenCV.
    const std::vector<std::string> want{
        "111111101001001111111",
        "100000101111001000001",
        "101110100010101011101",
        "101110101010101011101",
        "101110100001001011101",
        "100000100001101000001",
        "111111101010101111111",
        "000000001001100000000",
        "101101110101101001011",
        "011011010111111001100",
        "100010100101000000011",
        "101100010001001111010",
        "010111111000100100101",
        "000000001111001000101",
        "111111101001100100000",
        "100000101010000111110",
        "101110100000111111011",
        "101110101011001011110",
        "101110101100101100100",
        "100000100010010110001",
        "111111101010010100000"};
    const auto m = encode("HELLO");
    REQUIRE(m.size() == want.size());
    for (size_t y = 0; y < m.size(); ++y)
    {
        std::string row;
        for (const bool d : m[y])
            row += d ? '1' : '0';
        CHECK(row == want[y]);
    }
}

TEST_CASE("the smallest version the text fits in, and nothing past version ten")
{
    CHECK(encode(std::string(14, 'x')).size() == 21);
    CHECK(encode(std::string(15, 'x')).size() == 25);
    CHECK(encode(std::string(213, 'x')).size() == 57);
    CHECK(encode(std::string(214, 'x')).empty());
    // An authenticator key's address of 116 bytes is version 7, the first with version blocks drawn.
    CHECK(encode("otpauth://totp/auth.smileygames.online:smiley?secret=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567&issuer=auth."
                 "smileygames.online")
              .size() == 45);
    CHECK(encode(std::string(106, 'x')).size() == 41);
}

TEST_CASE("the svg holds the quiet zone and one square per dark module")
{
    const auto m = encode("HELLO");
    size_t dark = 0;
    for (const auto& row : m)
        for (const bool d : row)
            dark += d;
    const std::string s = socketley::qr::svg("HELLO");
    CHECK(s.find("viewBox=\"0 0 29 29\"") != std::string::npos);
    size_t squares = 0;
    for (size_t at = s.find("h1v1h-1z"); at != std::string::npos; at = s.find("h1v1h-1z", at + 1))
        ++squares;
    CHECK(squares == dark);
    CHECK(socketley::qr::svg(std::string(214, 'x')).empty());
}
