// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// TX_PQPKH and CPQKeyID (docs/plans/yellowback-quantum-spec.md §2, §4): the 35-byte script
// <keyHash:32> OP_1|OP_2 OP_CHECKPQSIG, its Solver/ExtractDestination/GetScriptForDestination
// round trip, and the PQ Yellowback address (versions 0x56BF / 0x571E / 0x5710, 53 characters).

#include "base58.h"
#include "crypto/pq/scheme.h"
#include "key_io.h"
#include "script/script.h"
#include "script/standard.h"
#include "streams.h"
#include "test/test_bitcoin.h"
#include "util/strencodings.h"
#include "version.h"
#include "yellowback/address.h"
#include "yellowback/params.h"

#include <variant>

#include <boost/test/unit_test.hpp>

namespace {

uint256 Hash32(unsigned char fill)
{
    return uint256(std::vector<unsigned char>(32, fill));
}

CScript RawPQPKH(const uint256& h, opcodetype schemeOp)
{
    CScript s;
    s << ToByteVector(h) << schemeOp << OP_CHECKPQSIG;
    return s;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_standard_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pqpkh_solver_success)
{
    for (uint8_t scheme : {pq::SCHEME_SLH_DSA_SHA2_128S, pq::SCHEME_FN_DSA_512}) {
        const uint256 h = Hash32(0x40 + scheme);
        const CPQKeyID id(scheme, h);
        const CScript s = GetScriptForDestination(id);
        BOOST_CHECK_EQUAL(s.size(), 35U);
        BOOST_CHECK(s == GetScriptForPQKey(id));
        BOOST_CHECK(s == RawPQPKH(h, CScript::EncodeOP_N(scheme)));
        BOOST_CHECK_EQUAL(s[0], 0x20);
        BOOST_CHECK_EQUAL(s[33], 0x50 + scheme);
        BOOST_CHECK_EQUAL(s[34], 0xc2);

        txnouttype type;
        std::vector<std::vector<unsigned char>> sol;
        BOOST_CHECK(Solver(s, type, sol));
        BOOST_CHECK_EQUAL(type, TX_PQPKH);
        BOOST_REQUIRE_EQUAL(sol.size(), 2U);
        BOOST_CHECK(sol[0] == std::vector<unsigned char>{scheme});
        BOOST_CHECK(sol[1] == ToByteVector(h));
        BOOST_CHECK_EQUAL(ScriptSigArgsExpected(type, sol), -1);
        BOOST_CHECK_EQUAL(std::string(GetTxnOutputType(type)), "pqpubkeyhash");

        CTxDestination dest;
        BOOST_CHECK(ExtractDestination(s, dest));
        BOOST_CHECK(IsPQKeyDestination(dest));
        BOOST_CHECK(!IsKeyDestination(dest));
        BOOST_CHECK(std::get<CPQKeyID>(dest) == id);

        std::vector<CTxDestination> dests;
        int nRequired;
        BOOST_CHECK(ExtractDestinations(s, type, dests, nRequired));
        BOOST_CHECK_EQUAL(type, TX_PQPKH);
        BOOST_REQUIRE_EQUAL(dests.size(), 1U);
        BOOST_CHECK(std::get<CPQKeyID>(dests[0]) == id);
        BOOST_CHECK_EQUAL(nRequired, 1);

        // no plain-YEC encoding (quantum spec §2.4)
        KeyIO keyIO(Params());
        BOOST_CHECK_EQUAL(keyIO.EncodeDestination(dest), "");
    }
}

BOOST_AUTO_TEST_CASE(pqpkh_solver_failure)
{
    const uint256 h = Hash32(0x11);
    txnouttype type;
    std::vector<std::vector<unsigned char>> sol;

    // unregistered scheme bytes: OP_0, OP_3, OP_16
    for (opcodetype op : {OP_0, OP_3, OP_16}) {
        BOOST_CHECK(!Solver(RawPQPKH(h, op), type, sol));
        BOOST_CHECK_EQUAL(type, TX_NONSTANDARD);
    }
    // the scheme as a one-byte push (01 01) is not the template (F-1: unspendable under MINIMALDATA)
    {
        CScript s;
        s << ToByteVector(h) << std::vector<unsigned char>{0x01} << OP_CHECKPQSIG;
        BOOST_CHECK_EQUAL(s.size(), 36U);
        BOOST_CHECK(!Solver(s, type, sol));
    }
    // a 31- or 33-byte hash
    {
        CScript s;
        s << std::vector<unsigned char>(31, 0x22) << OP_1 << OP_CHECKPQSIG;
        BOOST_CHECK(!Solver(s, type, sol));
        CScript t;
        t << std::vector<unsigned char>(33, 0x22) << OP_1 << OP_CHECKPQSIG;
        BOOST_CHECK(!Solver(t, type, sol));
    }
    // OP_CHECKSIG / OP_CHECKSETSIG in place of OP_CHECKPQSIG, a trailing byte, a PUSHDATA1 hash
    {
        CScript s;
        s << ToByteVector(h) << OP_1 << OP_CHECKSIG;
        BOOST_CHECK(!Solver(s, type, sol));
        CScript t;
        t << ToByteVector(h) << OP_1 << OP_CHECKSETSIG;
        BOOST_CHECK(!Solver(t, type, sol));
        CScript u = RawPQPKH(h, OP_1);
        u << OP_NOP;
        BOOST_CHECK(!Solver(u, type, sol));
        std::vector<unsigned char> raw = {OP_PUSHDATA1, 0x20};
        raw.insert(raw.end(), h.begin(), h.end());
        raw.push_back(OP_1);
        raw.push_back(OP_CHECKPQSIG);
        BOOST_CHECK(!Solver(CScript(raw.begin(), raw.end()), type, sol));
    }
    // GetScriptForDestination / GetScriptForPQKey of an unregistered scheme is empty (review A F6),
    // including the OP_n-encodable 3..16
    for (int scheme : {0, 3, 4, 16, 17, 255}) {
        BOOST_CHECK(GetScriptForDestination(CPQKeyID((uint8_t)scheme, h)).empty());
        BOOST_CHECK(GetScriptForPQKey(CPQKeyID((uint8_t)scheme, h)).empty());
    }
}

BOOST_AUTO_TEST_CASE(pqkeyid_order_and_serialization)
{
    const CPQKeyID a(1, Hash32(0x02)), b(1, Hash32(0x03)), c(2, Hash32(0x01));
    BOOST_CHECK(a < b && b < c && a < c);
    BOOST_CHECK(!(b < a) && !(a < a));
    BOOST_CHECK(a == CPQKeyID(1, Hash32(0x02)));
    BOOST_CHECK(a != b && a != CPQKeyID(2, Hash32(0x02)));

    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << c;
    BOOST_CHECK_EQUAL(ss.size(), 33U);
    BOOST_CHECK_EQUAL((unsigned char)ss[0], 0x02);
    CPQKeyID d;
    ss >> d;
    BOOST_CHECK(d == c);

    std::map<CTxDestination, int> m;
    m[CTxDestination(a)] = 1;
    m[CTxDestination(c)] = 2;
    BOOST_CHECK_EQUAL(m.size(), 2U);
}

BOOST_AUTO_TEST_CASE(pq_yellowback_address)
{
    const uint256 set = uint256S("5e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e7");
    const yellowback::Params& main = yellowback::MainParams();
    const yellowback::Params& test = yellowback::TestParams();
    const yellowback::Params regtest = yellowback::RegtestParams(1, 0, 0, set);
    for (uint8_t scheme : {pq::SCHEME_SLH_DSA_SHA2_128S, pq::SCHEME_FN_DSA_512}) {
        for (unsigned char fill : {0x00, 0x5a, 0xff}) {
            const CPQKeyID id(scheme, Hash32(fill));
            const std::string m = yellowback::EncodeAddress(id, main);
            const std::string t = yellowback::EncodeAddress(id, test);
            const std::string r = yellowback::EncodeAddress(id, regtest);
            BOOST_CHECK_EQUAL(m.size(), 53U);
            BOOST_CHECK_EQUAL(t.size(), 53U);
            BOOST_CHECK_EQUAL(r.size(), 53U);
            BOOST_CHECK_EQUAL(m.substr(0, 2), "ye");
            BOOST_CHECK_EQUAL(t.substr(0, 2), "yt");
            BOOST_CHECK_EQUAL(r.substr(0, 2), "yr");
            CPQKeyID back;
            BOOST_CHECK(yellowback::DecodeAddress(m, main, back) && back == id);
            BOOST_CHECK(!yellowback::DecodeAddress(m, test, back));
            BOOST_CHECK(!yellowback::DecodeAddress(r, main, back));
            CKeyID k;
            BOOST_CHECK(!yellowback::DecodeAddress(m, main, k)); // the 20-byte decoder refuses 33 bytes
            CTxDestination dest;
            BOOST_CHECK(yellowback::DecodeAddress(r, regtest, dest));
            BOOST_CHECK(std::get<CPQKeyID>(dest) == id);
        }
    }
    // the either-form decoder still yields a CKeyID for a 35-character address
    const CKeyID kid(uint160(std::vector<unsigned char>(20, 0x33)));
    CTxDestination dest;
    BOOST_CHECK(yellowback::DecodeAddress(yellowback::EncodeAddress(kid, main), main, dest));
    BOOST_CHECK(std::get<CKeyID>(dest) == kid);
    // an unregistered scheme neither encodes nor decodes
    BOOST_CHECK_EQUAL(yellowback::EncodeAddress(CPQKeyID(3, Hash32(1)), main), "");
    std::vector<unsigned char> raw = main.pqAddressVersion;
    raw.push_back(0x03);
    raw.insert(raw.end(), 32, 0x01);
    CPQKeyID back;
    BOOST_CHECK(!yellowback::DecodeAddress(EncodeBase58Check(raw), main, back));
    // the spec's extreme mainnet encodings (quantum spec §4)
    std::vector<unsigned char> lo = main.pqAddressVersion, hi = main.pqAddressVersion;
    lo.insert(lo.end(), 33, 0x00);
    hi.insert(hi.end(), 33, 0xff);
    BOOST_CHECK_EQUAL(EncodeBase58Check(lo).substr(0, 2), "ye");
    BOOST_CHECK_EQUAL(EncodeBase58Check(hi).substr(0, 2), "ye");
    BOOST_CHECK_EQUAL(EncodeBase58Check(lo).size(), 53U);
    BOOST_CHECK_EQUAL(EncodeBase58Check(hi).size(), 53U);
}

BOOST_AUTO_TEST_SUITE_END()
