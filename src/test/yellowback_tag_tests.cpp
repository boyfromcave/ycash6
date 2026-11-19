// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The coinbase tag reader (plan §3.2, TAG-1..5) against pool-shaped
// scriptSigs: the byte scan must find a tag wherever a pool put it after the
// BIP34 height push and must never read past what is there.

#include "yellowback/tag.h"

#include "crypto/pq/scheme.h"
#include "script/script.h"
#include "streams.h"
#include "test/data/yellowback_tag_vectors.json.h"
#include "test/test_bitcoin.h"
#include "util/strencodings.h"
#include "version.h"

#include <boost/test/unit_test.hpp>
#include <univalue.h>

#include <algorithm>
#include <functional>

using namespace yellowback;

namespace {

CoinbaseTag QuoteTag(uint64_t price = 50000, uint8_t flags = 0x01)
{
    CoinbaseTag t;
    t.flags = flags;
    t.priceMicroUsd = price;
    t.sourceMask = 0x0007;
    t.payee = Payee::FromKeyID(CKeyID(uint160(std::vector<unsigned char>(20, 0xAB))));
    return t;
}

/** Raw bytes appended to a script without push encoding (what a pool's extranonce looks like). */
CScript Raw(CScript s, const std::vector<unsigned char>& bytes)
{
    s.insert(s.end(), bytes.begin(), bytes.end());
    return s;
}

std::vector<unsigned char> Bytes(const std::string& hex) { return ParseHex(hex); }

std::vector<unsigned char> Text(const std::string& s) { return std::vector<unsigned char>(s.begin(), s.end()); }

std::vector<unsigned char> Cat(std::vector<unsigned char> a, const std::vector<unsigned char>& b)
{
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(yellowback_tag_tests, BasicTestingSetup)

// Rule: TAG-1
BOOST_AUTO_TEST_CASE(tag1_encoding_is_36_bytes_one_direct_push)
{
    CoinbaseTag t = QuoteTag();
    std::vector<unsigned char> enc = EncodeTag(t);
    BOOST_REQUIRE_EQUAL(enc.size(), TAG_SIZE);
    BOOST_CHECK_EQUAL(HexStr(enc.begin(), enc.begin() + 4), "59454421");   // "YED!"
    BOOST_CHECK_EQUAL(enc[4], TAG_VERSION);
    BOOST_CHECK_EQUAL(enc[5], 0x01);
    BOOST_CHECK_EQUAL(HexStr(enc.begin() + 6, enc.begin() + 14), "50c3000000000000"); // 50,000 LE
    BOOST_CHECK_EQUAL(HexStr(enc.begin() + 14, enc.begin() + 16), "0700");
    BOOST_CHECK_EQUAL(HexStr(enc.begin() + 16, enc.end()), "abababababababababababababababababababab");
    CScript push = TagPush(t);
    BOOST_REQUIRE_EQUAL(push.size(), TAG_SIZE + 1);
    BOOST_CHECK_EQUAL(push[0], 0x24);
    BOOST_CHECK(std::equal(enc.begin(), enc.end(), push.begin() + 1));
    BOOST_CHECK(t.IsQuote());
    BOOST_CHECK(t.Signal());
}

// Rule: TAG-1
// Rule: TAG-2
// Rule: TAG-3
// Rule: TAG-5
BOOST_AUTO_TEST_CASE(tag1_to_5_table)
{
    const int height = 1234567;
    const CScript prefix = CScript() << height;
    const CoinbaseTag quote = QuoteTag();
    const CoinbaseTag other = QuoteTag(60000);
    const CoinbaseTag signalOnly = QuoteTag(TAG_PRICE_SIGNAL_ONLY);
    const std::vector<unsigned char> body = EncodeTag(quote);
    const std::vector<unsigned char> extranonce = Bytes("0011223344556677");
    const std::vector<unsigned char> magicOnly = Bytes("59454421");

    auto bad = [&](std::function<void(std::vector<unsigned char>&)> mutate) {
        std::vector<unsigned char> b = body;
        mutate(b);
        return b;
    };

    struct Case {
        const char* name;
        CScript scriptSig;
        std::optional<CoinbaseTag> expected;
    };
    const std::vector<Case> cases = {
        // TAG-1: right after the height
        { "after_height", prefix + TagPush(quote), quote },
        // TAG-1: after an 8-byte raw extranonce
        { "after_extranonce", Raw(prefix, extranonce) + TagPush(quote), quote },
        // TAG-1: after pool text pushed as data, then extranonce after the tag
        { "after_pool_text", Raw(Raw(prefix, Text("/YcashPool/")) + TagPush(quote), extranonce), quote },
        // TAG-1: raw tag bytes (not push-encoded) still carry the push opcode byte, so a pool appending 0x24‖tag raw is found too
        { "raw_push_byte", Raw(Raw(prefix, extranonce), Cat(Bytes("24"), body)), quote },
        // P10: the magic without its push opcode is not a tag
        { "magic_without_push_opcode", Raw(Raw(prefix, magicOnly), std::vector<unsigned char>(body.begin() + 4, body.end())), std::nullopt },
        // TAG-5: the first occurrence has too few bytes after it, a later full tag is ignored
        { "first_occurrence_short_then_full", Raw(Raw(prefix, Cat(Bytes("24"), magicOnly)), Bytes("0100")) + TagPush(quote), std::nullopt },
        // TAG-5: two tags: the first decides
        { "two_tags", prefix + TagPush(quote) + TagPush(other), quote },
        // TAG-5: an invalid first tag is no tag even though a valid one follows
        { "invalid_first_then_valid", prefix + (CScript() << bad([](std::vector<unsigned char>& b) { b[4] = 2; })) + TagPush(quote), std::nullopt },
        // TAG-2: version
        { "bad_version", prefix + (CScript() << bad([](std::vector<unsigned char>& b) { b[4] = 0; })), std::nullopt },
        // TAG-2: reserved flag bit
        { "reserved_flag_bit", prefix + (CScript() << bad([](std::vector<unsigned char>& b) { b[5] = 0x03; })), std::nullopt },
        { "reserved_flag_bit7", prefix + (CScript() << bad([](std::vector<unsigned char>& b) { b[5] = 0x80; })), std::nullopt },
        // TAG-2: price out of range
        { "price_below_min", prefix + TagPush(QuoteTag(PRICE_MIN - 1)), std::nullopt },
        { "price_above_max", prefix + TagPush(QuoteTag(PRICE_MAX + 1)), std::nullopt },
        { "price_at_min", prefix + TagPush(QuoteTag(PRICE_MIN)), QuoteTag(PRICE_MIN) },
        { "price_at_max", prefix + TagPush(QuoteTag(PRICE_MAX)), QuoteTag(PRICE_MAX) },
        // TAG-3: signal-only
        { "signal_only", prefix + TagPush(signalOnly), signalOnly },
        // TAG-3: any 20 bytes is a payout key
        { "zero_payout_key", prefix + TagPush([] { CoinbaseTag t = QuoteTag(); t.payee.hash.SetNull(); return t; }()), [] { CoinbaseTag t = QuoteTag(); t.payee.hash.SetNull(); return t; }() },
        // TAG-1: the height prefix must be the exact minimal push
        { "wrong_height", (CScript() << (height + 1)) + TagPush(quote), std::nullopt },
        { "no_prefix", TagPush(quote), std::nullopt },
        { "empty", CScript(), std::nullopt },
        { "prefix_only", prefix, std::nullopt },
        // TAG-1: 31 bytes after the pattern
        { "truncated_by_one", Raw(prefix, Cat(Bytes("24"), std::vector<unsigned char>(body.begin(), body.end() - 1))), std::nullopt },
    };
    for (const Case& c : cases) {
        std::optional<CoinbaseTag> got = FindTag(c.scriptSig, height);
        BOOST_CHECK_MESSAGE(got.has_value() == c.expected.has_value(), std::string(c.name) + ": presence");
        if (got.has_value() && c.expected.has_value()) {
            BOOST_CHECK_MESSAGE(got.value() == c.expected.value(), std::string(c.name) + ": fields");
        }
    }
    // TAG-3: kinds
    BOOST_CHECK(quote.IsQuote());
    BOOST_CHECK(!signalOnly.IsQuote());
    BOOST_CHECK(signalOnly.Signal());
    BOOST_CHECK(!QuoteTag(50000, 0).Signal());
}

// Rule: TAG-1
// Rule: TAG-5
BOOST_AUTO_TEST_CASE(tag5_pattern_inside_extranonce_with_too_few_bytes_following)
{
    // A pool's extranonce happens to contain 24 59 45 44 21 near the end of the
    // scriptSig: fewer than 32 bytes follow, so there is no tag, and the scan
    // stops there (TAG-5) rather than finding anything else.
    const int height = 100;
    CScript s = Raw(CScript() << height, Bytes("aabbccdd" "2459454421" "0102030405"));
    BOOST_CHECK(!FindTag(s, height).has_value());
    // Exactly 32 bytes after: version byte 1, flags 0, price 0 => signal-only tag from "random" bytes.
    CScript t = Raw(CScript() << height, Bytes("2459454421" "0100" "0000000000000000" "0000" "0000000000000000000000000000000000000000"));
    auto got = FindTag(t, height);
    BOOST_REQUIRE(got.has_value());
    BOOST_CHECK(!got->IsQuote());
}

// Rule: TAG-1
// Rule: P10
BOOST_AUTO_TEST_CASE(tag1_magic_without_push_opcode_is_no_tag)
{
    const int height = 42;
    std::vector<unsigned char> body = EncodeTag(QuoteTag());
    // The 36 bytes pushed with OP_PUSHDATA1 (4c 24 59 45 44 21 ...) contain the
    // 5-byte pattern at offset 1: the scan is byte-level, not a script parse
    // (V4), so a non-minimal push of the tag is still a tag.
    CScript s = Raw(CScript() << height, Cat(Bytes("4c24"), body));
    BOOST_CHECK(FindTag(s, height).has_value());
    // Raw, no opcode at all.
    BOOST_CHECK(!FindTag(Raw(CScript() << height, body), height).has_value());
    // With the direct push it is.
    BOOST_CHECK(FindTag(Raw(CScript() << height, Cat(Bytes("24"), body)), height).has_value());
}

// Rule: TAG-1
BOOST_AUTO_TEST_CASE(tag1_byte_budget_at_every_height_push_width)
{
    // bad-cb-length: 2 <= scriptSig.size() <= 100 (ref/ycash/src/main.cpp:1456-1458).
    // The height push grows from 1 byte (OP_1..OP_16) to 5 bytes (>= 2^23);
    // prefix + 37-byte tag push must leave >= 58 bytes for the pool at every width.
    const std::vector<std::pair<int, size_t>> heights = {
        { 1, 1 }, { 16, 1 }, { 17, 2 }, { 65535, 4 }, { 16777215, 5 }, { 16777216, 5 },
    };
    const CoinbaseTag quote = QuoteTag();
    for (const auto& h : heights) {
        const CScript prefix = CScript() << h.first;
        BOOST_CHECK_MESSAGE(prefix.size() == h.second, "height " + std::to_string(h.first) + " push width");
        const CScript tagged = prefix + TagPush(quote);
        BOOST_CHECK(tagged.size() <= 42);
        BOOST_CHECK(100 - tagged.size() >= 58);
        BOOST_CHECK(FindTag(tagged, h.first).has_value());
        // A realistic pool coinbase: prefix, 8-byte extranonce1/2, tag, pool text, filling to 100 bytes exactly.
        CScript full = Raw(prefix, Bytes("0011223344556677")) + TagPush(quote);
        full = Raw(full, std::vector<unsigned char>(100 - full.size(), 0x2F));
        BOOST_CHECK_EQUAL(full.size(), 100u);
        auto got = FindTag(full, h.first);
        BOOST_REQUIRE_MESSAGE(got.has_value(), "height " + std::to_string(h.first) + " full coinbase");
        BOOST_CHECK(got.value() == quote);
        // And at 101 bytes the block is invalid regardless (consensus), which the reader does not judge (TAG-4).
        BOOST_CHECK(FindTag(Raw(full, Bytes("00")), h.first).has_value());
    }
}

// Rule: TAG-4
BOOST_AUTO_TEST_CASE(tag4_reader_never_judges_the_block)
{
    // FindTag has one output: a tag or nullopt. Garbage of every shape is nullopt, never an error.
    const int height = 7;
    for (size_t n = 0; n < 120; n++) {
        CScript s = Raw(CScript() << height, std::vector<unsigned char>(n, 0x24));
        BOOST_CHECK(!FindTag(s, height).has_value());
    }
    // Any prefix of a valid tagged script is nullopt or the tag itself, never anything else.
    const CScript tagged = (CScript() << height) + TagPush(QuoteTag());
    for (size_t n = 0; n <= tagged.size(); n++) {
        CScript p(tagged.begin(), tagged.begin() + n);
        auto got = FindTag(p, height);
        BOOST_CHECK(!got.has_value() || got.value() == QuoteTag());
        BOOST_CHECK_EQUAL(got.has_value(), n == tagged.size());
    }
}

// ---------------------------------------------------------------------------
// Tag v2 (docs/plans/beta4/price-feed.md §4.3, beta4 P1 spec §1, §2, §7)

namespace {

CoinbaseTag V2Tag(uint8_t scheme, uint64_t price = 50000)
{
    return MakeTag(0x01, price, 0x0005, Payee::FromPQ(CPQKeyID(scheme, uint256(std::vector<unsigned char>(32, 0xCD)))));
}

} // namespace

// Rule: TAG-1
BOOST_AUTO_TEST_CASE(tag_v2_layout_and_roundtrip)
{
    const int height = 1000;
    for (uint8_t scheme : { pq::SCHEME_SLH_DSA_SHA2_128S, pq::SCHEME_FN_DSA_512 }) {
        const CoinbaseTag t = V2Tag(scheme);
        BOOST_CHECK_EQUAL(t.version, TAG_VERSION_V2);
        const std::vector<unsigned char> body = EncodeTag(t);
        BOOST_CHECK_EQUAL(body.size(), TAG_SIZE_V2);
        BOOST_CHECK_EQUAL(HexStr(body.begin(), body.begin() + 5), "5945442102");
        BOOST_CHECK_EQUAL(body[16], scheme);
        const CScript push = TagPush(t);
        BOOST_CHECK_EQUAL(push.size(), 50u);
        BOOST_CHECK_EQUAL(push[0], 0x31);
        auto got = FindTag((CScript() << height << OP_0) + push, height);
        BOOST_REQUIRE(got.has_value());
        BOOST_CHECK(got.value() == t);
        BOOST_CHECK(IsValidTag(t));
    }
    // v1 for a P2PKH payee, unchanged byte for byte
    const CoinbaseTag v1 = MakeTag(0x01, 50000, 0x0007, QuoteTag().payee);
    BOOST_CHECK(v1 == QuoteTag());
    BOOST_CHECK_EQUAL(EncodeTag(v1).size(), TAG_SIZE);
}

// Rule: TAG-2
// Rule: TAG-5
BOOST_AUTO_TEST_CASE(tag_v2_bad_scheme_truncation_and_pattern_order)
{
    const int height = 1000;
    const CScript prefix = CScript() << height;
    std::vector<unsigned char> v2 = EncodeTag(V2Tag(pq::SCHEME_FN_DSA_512));
    std::vector<unsigned char> bad = v2;
    bad[16] = 0x03;                                                        // unknown scheme
    BOOST_CHECK(!FindTag(prefix + (CScript() << bad), height).has_value());
    bad[16] = 0x00;                                                        // P2PKH is not a v2 scheme
    BOOST_CHECK(!FindTag(prefix + (CScript() << bad), height).has_value());
    // truncated: 48 bytes after the 0x31 push opcode
    BOOST_CHECK(!FindTag(Raw(prefix, Cat(Bytes("31"), std::vector<unsigned char>(v2.begin(), v2.end() - 1))), height).has_value());
    // a v2 pattern with version 1, a v1 pattern with version 2
    std::vector<unsigned char> v2as1 = v2;
    v2as1[4] = 0x01;
    BOOST_CHECK(!FindTag(prefix + (CScript() << v2as1), height).has_value());
    std::vector<unsigned char> v1as2 = EncodeTag(QuoteTag());
    v1as2[4] = 0x02;
    BOOST_CHECK(!FindTag(prefix + (CScript() << v1as2), height).has_value());
    // first by position decides
    const CScript v1push = TagPush(QuoteTag()), v2push = TagPush(V2Tag(pq::SCHEME_SLH_DSA_SHA2_128S));
    BOOST_CHECK_EQUAL(FindTag(prefix + v1push + v2push, height)->version, TAG_VERSION);
    BOOST_CHECK_EQUAL(FindTag(prefix + v2push + v1push, height)->version, TAG_VERSION_V2);
    BOOST_CHECK(!FindTag(prefix + (CScript() << bad) + v1push, height).has_value());
}

// Rule: FEE-2
BOOST_AUTO_TEST_CASE(payee_script_order_and_serialisation)
{
    const Payee p2pkh = QuoteTag().payee;
    const Payee fn = V2Tag(pq::SCHEME_FN_DSA_512).payee, slh = V2Tag(pq::SCHEME_SLH_DSA_SHA2_128S).payee;
    BOOST_CHECK_EQUAL(p2pkh.Script().size(), 25u);
    BOOST_CHECK(fn.Script() == GetScriptForPQKey(CPQKeyID(pq::SCHEME_FN_DSA_512, fn.hash)));
    BOOST_CHECK_EQUAL(fn.Script().size(), 35u);
    for (const Payee& p : { p2pkh, fn, slh }) {
        BOOST_CHECK(Payee::FromScript(p.Script()) == p);
        BOOST_CHECK(Payee::FromDestination(p.Destination()) == p);
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        ss << p;
        BOOST_CHECK_EQUAL(ss.size(), 1 + p.HashSize());
        BOOST_CHECK_EQUAL(ss[0], (char)p.kind);
        Payee back;
        ss >> back;
        BOOST_CHECK(back == p);
    }
    // nothing else is a payee: a P2SH, a trailing byte, an unknown scheme, a bare key
    BOOST_CHECK(!Payee::FromScript(GetScriptForDestination(CScriptID(CScript() << OP_1))).has_value());
    CScript longer = fn.Script();
    longer << OP_0;
    BOOST_CHECK(!Payee::FromScript(longer).has_value());
    CScript scheme3 = CScript() << ToByteVector(fn.hash) << OP_3 << OP_CHECKPQSIG;
    BOOST_CHECK(!Payee::FromScript(scheme3).has_value());
    CDataStream bad(ParseHex("03" + std::string(64, '0')), SER_DISK, CLIENT_VERSION);
    Payee junk;
    BOOST_CHECK_THROW(bad >> junk, std::ios_base::failure);
    // order: kind, then the hash bytes
    BOOST_CHECK(p2pkh < slh && slh < fn);
    BOOST_CHECK_EQUAL(p2pkh.SchemeName(), "p2pkh");
    BOOST_CHECK_EQUAL(slh.SchemeName(), "slh-dsa-sha2-128s");
    BOOST_CHECK_EQUAL(fn.SchemeName(), "fn-dsa-512");
}

// Rule: TAG-1
// Rule: TAG-5
BOOST_AUTO_TEST_CASE(tag_vectors_cross_line)
{
    // src/test/data/yellowback_tag_vectors.json (D-T4): generated by the Python model, carried byte for byte by the 6.20.0 line and kogany.
    UniValue doc;
    BOOST_REQUIRE(doc.read(std::string(json_tests::yellowback_tag_vectors, json_tests::yellowback_tag_vectors + sizeof(json_tests::yellowback_tag_vectors))));
    const UniValue& cases = doc["cases"];
    BOOST_REQUIRE(cases.size() >= 11);
    int found = 0;
    for (size_t i = 0; i < cases.size(); i++) {
        const UniValue& c = cases[i];
        const std::string name = c["name"].get_str();
        const std::vector<unsigned char> raw = ParseHex(c["scriptSig"].get_str());
        const CScript scriptSig(raw.begin(), raw.end());
        BOOST_CHECK_EQUAL((int)scriptSig.size(), c["scriptSigSize"].get_int());
        std::optional<CoinbaseTag> got = FindTag(scriptSig, c["height"].get_int());
        BOOST_CHECK_MESSAGE(got.has_value() == !c["tag"].isNull(), name);
        if (!got.has_value() || c["tag"].isNull()) continue;
        found++;
        const UniValue& t = c["tag"];
        BOOST_CHECK_MESSAGE(got->version == t["version"].get_int(), name + ": version");
        BOOST_CHECK_MESSAGE(got->flags == t["flags"].get_int(), name + ": flags");
        BOOST_CHECK_MESSAGE((int64_t)got->priceMicroUsd == t["priceMicroUsd"].get_int64(), name + ": price");
        BOOST_CHECK_MESSAGE(got->sourceMask == t["sourceMask"].get_int(), name + ": sourceMask");
        BOOST_CHECK_MESSAGE(got->payee.kind == t["payeeKind"].get_int(), name + ": kind");
        BOOST_CHECK_MESSAGE(got->payee.SchemeName() == t["payoutScheme"].get_str(), name + ": scheme");
        BOOST_CHECK_MESSAGE(HexStr(got->payee.hash.begin(), got->payee.hash.begin() + got->payee.HashSize()) == t["payoutHash"].get_str(), name + ": hash");
        const CScript script = got->payee.Script();
        BOOST_CHECK_MESSAGE(HexStr(script.begin(), script.end()) == c["payeeScript"].get_str(), name + ": payee script");
        // the push re-encodes to the bytes found
        const CScript push = TagPush(got.value());
        BOOST_CHECK_MESSAGE(std::search(scriptSig.begin(), scriptSig.end(), push.begin(), push.end()) != scriptSig.end(), name + ": re-encode");
    }
    BOOST_CHECK_EQUAL(found, 6);
}

BOOST_AUTO_TEST_SUITE_END()
