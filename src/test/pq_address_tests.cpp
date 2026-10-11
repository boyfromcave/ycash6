// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The plain-YEC post-quantum address (owner decision D-Q-20): sq… / tq… / rq…, Base58Check(4DD9 / 4F61 / 4C51 ||
// scheme || keyHash), 53 characters, decoded chain-wide by KeyIO; and the address index key of a TX_PQPKH output.

#include "base58.h"
#include "chainparams.h"
#include "crypto/pq/scheme.h"
#include "hash.h"
#include "key.h"
#include "key_io.h"
#include "random.h"
#include "script/script.h"
#include "script/standard.h"
#include "test/test_bitcoin.h"
#include "util/strencodings.h"
#include "yellowback/address.h"
#include "yellowback/params.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pq_address_tests, BasicTestingSetup)

namespace {
CPQKeyID RandomPQId(uint8_t scheme)
{
    return CPQKeyID(scheme, GetRandHash());
}

std::string RawBase58(const std::vector<unsigned char>& version, uint8_t scheme, const uint256& hash, size_t hashLen = 32)
{
    std::vector<unsigned char> data = version;
    data.push_back(scheme);
    data.insert(data.end(), hash.begin(), hash.begin() + hashLen);
    return EncodeBase58Check(data);
}
} // namespace

BOOST_AUTO_TEST_CASE(sq_roundtrip_per_network)
{
    const struct { std::string chain; std::string prefix; std::vector<unsigned char> version; } nets[] = {
        { CBaseChainParams::MAIN, "sq", {0x4D, 0xD9} },
        { CBaseChainParams::TESTNET, "tq", {0x4F, 0x61} },
        { CBaseChainParams::REGTEST, "rq", {0x4C, 0x51} },
    };
    for (const auto& n : nets) {
        SelectParams(n.chain);
        KeyIO keyIO(Params());
        BOOST_CHECK(PlainPQAddressVersion(Params().NetworkIDString()) == n.version);
        for (uint8_t scheme : {pq::SCHEME_SLH_DSA_SHA2_128S, pq::SCHEME_FN_DSA_512}) {
            for (int i = 0; i < 20; i++) {
                const CPQKeyID id = i == 0 ? CPQKeyID(scheme, uint256()) : RandomPQId(scheme);
                const std::string a = keyIO.EncodeDestination(id);
                BOOST_CHECK_EQUAL(a.size(), 53U);
                BOOST_CHECK_EQUAL(a.substr(0, 2), n.prefix);
                const CTxDestination d = keyIO.DecodeDestination(a);
                BOOST_REQUIRE(std::get_if<CPQKeyID>(&d));
                BOOST_CHECK(std::get<CPQKeyID>(d) == id);
                BOOST_CHECK(keyIO.IsValidDestinationString(a));
                BOOST_CHECK(GetScriptForDestination(d) == GetScriptForPQKey(id));
                // The raw layout: version || scheme || keyHash.
                BOOST_CHECK_EQUAL(a, RawBase58(n.version, scheme, id.hash));
            }
        }
    }
    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_CASE(sq_refusals)
{
    SelectParams(CBaseChainParams::REGTEST);
    KeyIO regIO(Params());
    const uint256 h = GetRandHash();
    // An unregistered scheme encodes to "" and decodes to nothing.
    for (uint8_t scheme : {(uint8_t)0x00, (uint8_t)0x03, (uint8_t)0xff}) {
        BOOST_CHECK_EQUAL(regIO.EncodeDestination(CPQKeyID(scheme, h)), "");
        BOOST_CHECK(!IsValidDestination(regIO.DecodeDestination(RawBase58({0x4C, 0x51}, scheme, h))));
    }
    // Wrong length (31-byte hash), and a checksum error.
    BOOST_CHECK(!IsValidDestination(regIO.DecodeDestination(RawBase58({0x4C, 0x51}, 1, h, 31))));
    std::string good = regIO.EncodeDestination(CPQKeyID(1, h));
    std::string bad = good;
    bad[10] = bad[10] == 'a' ? 'b' : 'a';
    BOOST_CHECK(!IsValidDestination(regIO.DecodeDestination(bad)));
    // Another network's form is refused.
    SelectParams(CBaseChainParams::MAIN);
    KeyIO mainIO(Params());
    const std::string sq = mainIO.EncodeDestination(CPQKeyID(1, h));
    BOOST_CHECK(IsValidDestination(mainIO.DecodeDestination(sq)));
    BOOST_CHECK(!IsValidDestination(regIO.DecodeDestination(sq)));   // regIO is bound to the regtest parameters
    BOOST_CHECK(!IsValidDestination(mainIO.DecodeDestination(good)));
    BOOST_CHECK(!IsValidDestination(regIO.DecodeDestination(good.substr(0, 52))));
    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_CASE(sq_and_yed_forms_are_distinct)
{
    // A PQ YED address (yb…/yr…) is not a KeyIO destination, and an sq… is not a YED address: the same key, two
    // namespaces (yed_listtokens and the address index accept both on purpose, by trying each decoder).
    SelectParams(CBaseChainParams::MAIN);
    KeyIO keyIO(Params());
    const CPQKeyID id = RandomPQId(1);
    const yellowback::Params& yp = yellowback::MainParams();
    const std::string yb = yellowback::EncodeAddress(id, yp);
    const std::string sq = keyIO.EncodeDestination(id);
    BOOST_CHECK(yb != sq);
    BOOST_CHECK(!IsValidDestination(keyIO.DecodeDestination(yb)));
    CPQKeyID back;
    BOOST_CHECK(!yellowback::DecodeAddress(sq, yp, back));
    BOOST_CHECK(yellowback::DecodeAddress(yb, yp, back) && back == id);
}

BOOST_AUTO_TEST_CASE(legacy_destinations_unchanged)
{
    // P2PKH / P2SH decode exactly as before (the PQ form is 35 bytes of payload, the others 22).
    SelectParams(CBaseChainParams::MAIN);
    KeyIO keyIO(Params());
    CKey k = CKey::TestOnlyRandomKey(true);   // 6.20.0: no CKey::MakeNewKey
    const CKeyID kid = k.GetPubKey().GetID();
    const CTxDestination d1 = keyIO.DecodeDestination(keyIO.EncodeDestination(kid));
    BOOST_CHECK(std::get_if<CKeyID>(&d1) && std::get<CKeyID>(d1) == kid);
    const CScriptID sid(GetScriptForDestination(kid));
    const CTxDestination d2 = keyIO.DecodeDestination(keyIO.EncodeDestination(sid));
    BOOST_CHECK(std::get_if<CScriptID>(&d2) && std::get<CScriptID>(d2) == sid);
    // The founders' reward script at a pre-Ycash height still decodes (a validation-time KeyIO caller).
    BOOST_CHECK(!Params().GetFoundersRewardScriptAtHeight(1).empty());
}

BOOST_AUTO_TEST_CASE(pqpkh_address_index_key)
{
    for (uint8_t scheme : {pq::SCHEME_SLH_DSA_SHA2_128S, pq::SCHEME_FN_DSA_512}) {
        const CPQKeyID id = RandomPQId(scheme);
        const CScript s = GetScriptForPQKey(id);
        BOOST_CHECK_EQUAL(s.GetType(), CScript::P2PQPKH);
        std::vector<unsigned char> raw(1, scheme);
        raw.insert(raw.end(), id.hash.begin(), id.hash.end());
        BOOST_CHECK(s.AddressHash() == Hash160(raw.begin(), raw.end()));
        // Another scheme over the same hash is another index key.
        BOOST_CHECK(GetScriptForPQKey(CPQKeyID(scheme == 1 ? 2 : 1, id.hash)).AddressHash() != s.AddressHash());
    }
    // A near-miss (wrong final opcode) stays UNKNOWN; P2PKH stays P2PKH.
    CScript near = GetScriptForPQKey(RandomPQId(1));
    near[34] = OP_CHECKSIG;
    BOOST_CHECK_EQUAL(near.GetType(), CScript::UNKNOWN);
    CKey k = CKey::TestOnlyRandomKey(true);   // 6.20.0: no CKey::MakeNewKey
    BOOST_CHECK_EQUAL(GetScriptForDestination(k.GetPubKey().GetID()).GetType(), CScript::P2PKH);
}

BOOST_AUTO_TEST_SUITE_END()
