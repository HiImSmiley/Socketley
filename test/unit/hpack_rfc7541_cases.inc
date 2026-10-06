// RFC 7541 Appendix C, as the RFC's text gives it: each sequence decoded by one decoder, in order.
struct rfc_block { const char* hex; std::vector<std::pair<std::string, std::string>> fields; };
struct rfc_sequence { const char* name; size_t table; std::vector<rfc_block> blocks; };
static const rfc_sequence rfc7541_cases[] = {
    {"C.3.", 4096, {
        {"828684410f7777772e6578616d706c652e636f6d", {{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "www.example.com"}}},
        {"828684be58086e6f2d6361636865", {{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "www.example.com"}, {"cache-control", "no-cache"}}},
        {"828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565", {{":method", "GET"}, {":scheme", "https"}, {":path", "/index.html"}, {":authority", "www.example.com"}, {"custom-key", "custom-value"}}},
    }},
    {"C.4.", 4096, {
        {"828684418cf1e3c2e5f23a6ba0ab90f4ff", {{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "www.example.com"}}},
        {"828684be5886a8eb10649cbf", {{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "www.example.com"}, {"cache-control", "no-cache"}}},
        {"828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf", {{":method", "GET"}, {":scheme", "https"}, {":path", "/index.html"}, {":authority", "www.example.com"}, {"custom-key", "custom-value"}}},
    }},
    {"C.5.", 256, {
        {"4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d", {{":status", "302"}, {"cache-control", "private"}, {"date", "Mon, 21 Oct 2013 20:13:21 GMT"}, {"location", "https://www.example.com"}}},
        {"4803333037c1c0bf", {{":status", "307"}, {"cache-control", "private"}, {"date", "Mon, 21 Oct 2013 20:13:21 GMT"}, {"location", "https://www.example.com"}}},
        {"88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31", {{":status", "200"}, {"cache-control", "private"}, {"date", "Mon, 21 Oct 2013 20:13:22 GMT"}, {"location", "https://www.example.com"}, {"content-encoding", "gzip"}, {"set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"}}},
    }},
    {"C.6.", 256, {
        {"488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3", {{":status", "302"}, {"cache-control", "private"}, {"date", "Mon, 21 Oct 2013 20:13:21 GMT"}, {"location", "https://www.example.com"}}},
        {"4883640effc1c0bf", {{":status", "307"}, {"cache-control", "private"}, {"date", "Mon, 21 Oct 2013 20:13:21 GMT"}, {"location", "https://www.example.com"}}},
        {"88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007", {{":status", "200"}, {"cache-control", "private"}, {"date", "Mon, 21 Oct 2013 20:13:22 GMT"}, {"location", "https://www.example.com"}, {"content-encoding", "gzip"}, {"set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"}}},
    }},
};
