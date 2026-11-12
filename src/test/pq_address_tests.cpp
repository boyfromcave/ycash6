// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The plain-YEC post-quantum address (owner decision D-Q-20, D-9): sqf…/sqs…, tqf…/tqs…, rqf…/rqs…,
// Base58Check(3-byte version per network and scheme || keyHash), 53 characters, decoded chain-wide by KeyIO; the
// YED form the same way (ybf…/ybs…, ytf…/yts…, yrf…/yrs…); the shared vectors (src/test/data/pq_address_vectors.json);
// and the address index key of a TX_PQPKH output.

#include "base58.h"
#include "chainparams.h"
#include "crypto/pq/scheme.h"
#include "hash.h"
#include "key.h"
#include "key_io.h"
#include "random.h"
#include "script/script.h"
#include "script/standard.h"
#include "test/data/pq_address_vectors.json.h"
#include "test/test_bitcoin.h"
#include "util/strencodings.h"
#include "yellowback/address.h"
#include "yellowback/params.h"

#include <univalue.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pq_address_tests, BasicTestingSetup)

namespace {
CPQKeyID RandomPQId(uint8_t scheme)
{
    return CPQKeyID(scheme, GetRandHash());
}

std::string RawBase58(const std::vector<unsigned char>& version, const uint256& hash, size_t hashLen = 32)
{
    std::vector<unsigned char> data = version;
    data.insert(data.end(), hash.begin(), hash.begin() + hashLen);
    return EncodeBase58Check(data);
}

/** The pre-D-9 form: 2-byte version || scheme || keyHash. */
std::string OldBase58(const std::vector<unsigned char>& version, uint8_t scheme, const uint256& hash)
{
    std::vector<unsigned char> data = version;
    data.push_back(scheme);
    data.insert(data.end(), hash.begin(), hash.end());
    return EncodeBase58Check(data);
}

const std::string& ChainOf(const std::string& network)
{
    static const std::string main = CBaseChainParams::MAIN, test = CBaseChainParams::TESTNET, reg = CBaseChainParams::REGTEST;
    return network == "main" ? main : network == "test" ? test : reg;
}

UniValue ReadAddressVectors()
{
    UniValue doc;
    const std::string text(json_tests::pq_address_vectors, json_tests::pq_address_vectors + sizeof(json_tests::pq_address_vectors));
    if (!doc.read(text) || doc["format"].get_str() != "ycash-pq-address-vectors-1")
        throw std::runtime_error("src/test/data/pq_address_vectors.json does not parse");
    return doc;
}
} // namespace

BOOST_AUTO_TEST_CASE(sq_roundtrip_per_network)
{
    // D-9: the 3-byte version names network and scheme; the third character shows the scheme.
    const struct { std::string chain; std::string prefix; uint8_t scheme; std::vector<unsigned char> version; } nets[] = {
        { CBaseChainParams::MAIN, "sqf", pq::SCHEME_FN_DSA_512, {0x4D, 0xDD, 0x04} },
        { CBaseChainParams::MAIN, "sqs", pq::SCHEME_SLH_DSA_SHA2_128S, {0x4D, 0xDE, 0x6A} },
        { CBaseChainParams::TESTNET, "tqf", pq::SCHEME_FN_DSA_512, {0x4F, 0x65, 0x19} },
        { CBaseChainParams::TESTNET, "tqs", pq::SCHEME_SLH_DSA_SHA2_128S, {0x4F, 0x66, 0x7F} },
        { CBaseChainParams::REGTEST, "rqf", pq::SCHEME_FN_DSA_512, {0x4C, 0x54, 0xEF} },
        { CBaseChainParams::REGTEST, "rqs", pq::SCHEME_SLH_DSA_SHA2_128S, {0x4C, 0x56, 0x55} },
    };
    for (const auto& n : nets) {
        SelectParams(n.chain);
        KeyIO keyIO(Params());
        BOOST_CHECK(PlainPQAddressVersions(Params().NetworkIDString()).at(n.scheme) == n.version);
        for (int i = 0; i < 20; i++) {
            const CPQKeyID id = i == 0 ? CPQKeyID(n.scheme, uint256()) : RandomPQId(n.scheme);
            const std::string a = keyIO.EncodeDestination(id);
            BOOST_CHECK_EQUAL(a.size(), 53U);
            BOOST_CHECK_EQUAL(a.substr(0, 3), n.prefix);
            const CTxDestination d = keyIO.DecodeDestination(a);
            BOOST_REQUIRE(std::get_if<CPQKeyID>(&d));
            BOOST_CHECK(std::get<CPQKeyID>(d) == id);
            BOOST_CHECK(keyIO.IsValidDestinationString(a));
            BOOST_CHECK(GetScriptForDestination(d) == GetScriptForPQKey(id));
            // The raw layout: version || keyHash.
            BOOST_CHECK_EQUAL(a, RawBase58(n.version, id.hash));
        }
    }
    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_CASE(sq_refusals)
{
    SelectParams(CBaseChainParams::REGTEST);
    KeyIO regIO(Params());
    const uint256 h = GetRandHash();
    // An unregistered scheme encodes to "".
    for (uint8_t scheme : {(uint8_t)0x00, (uint8_t)0x03, (uint8_t)0xff})
        BOOST_CHECK_EQUAL(regIO.EncodeDestination(CPQKeyID(scheme, h)), "");
    // The pre-D-9 form (4c51 || scheme || keyHash, "rq…" + a digit) is refused for every scheme byte, and a
    // version next to a registered one (the same "rqf" prefix) is refused.
    for (uint8_t scheme : {(uint8_t)0x00, (uint8_t)0x01, (uint8_t)0x02, (uint8_t)0x03, (uint8_t)0xff})
        BOOST_CHECK(!IsValidDestination(regIO.DecodeDestination(OldBase58({0x4C, 0x51}, scheme, h))));
    const std::string neighbour = RawBase58({0x4C, 0x54, 0xF0}, h);
    BOOST_CHECK_EQUAL(neighbour.substr(0, 3), "rqf");
    BOOST_CHECK(!IsValidDestination(regIO.DecodeDestination(neighbour)));
    // Wrong length (31- and 33-byte hash), and a checksum error.
    BOOST_CHECK(!IsValidDestination(regIO.DecodeDestination(RawBase58({0x4C, 0x54, 0xEF}, h, 31))));
    {
        std::vector<unsigned char> data = {0x4C, 0x54, 0xEF};
        data.insert(data.end(), h.begin(), h.end());
        data.push_back(0);
        BOOST_CHECK(!IsValidDestination(regIO.DecodeDestination(EncodeBase58Check(data))));
    }
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

BOOST_AUTO_TEST_CASE(shared_address_vectors)
{
    // src/test/data/pq_address_vectors.json, the file every component consumes (quantum spec §4, D-9).
    const UniValue doc = ReadAddressVectors();
    const UniValue& valid = doc["valid"];
    const UniValue& invalid = doc["invalid"];
    BOOST_CHECK_EQUAL(valid.size(), 72U);
    BOOST_CHECK(invalid.size() >= 60U);
    for (size_t i = 0; i < valid.size(); i++) {
        const UniValue& v = valid[i];
        const std::string net = v["network"].get_str(), coin = v["coin"].get_str(), addr = v["address"].get_str();
        const uint8_t scheme = (uint8_t)v["scheme"].get_int();
        const CPQKeyID id(scheme, uint256(ParseHex(v["keyhash"].get_str())));
        BOOST_CHECK_EQUAL(addr.size(), 53U);
        SelectParams(ChainOf(net));
        KeyIO keyIO(Params());
        const yellowback::Params& yp = yellowback::ParamsForNetwork(net);
        const std::vector<unsigned char> ver = ParseHex(v["version"].get_str());
        CPQKeyID back;
        if (coin == "yec") {
            BOOST_CHECK(PlainPQAddressVersions(net).at(scheme) == ver);
            BOOST_CHECK_EQUAL(keyIO.EncodeDestination(id), addr);
            const CTxDestination d = keyIO.DecodeDestination(addr);
            BOOST_CHECK(std::get_if<CPQKeyID>(&d) && std::get<CPQKeyID>(d) == id);
            BOOST_CHECK(!yellowback::DecodeAddress(addr, yp, back));   // not a YED address
        } else {
            BOOST_CHECK(yp.pqAddressVersions.at(scheme) == ver);
            BOOST_CHECK_EQUAL(yellowback::EncodeAddress(id, yp), addr);
            BOOST_CHECK(yellowback::DecodeAddress(addr, yp, back) && back == id);
            BOOST_CHECK(!IsValidDestination(keyIO.DecodeDestination(addr)));   // not a plain-YEC address
        }
        // No other network takes it, as either coin.
        for (const std::string other : {"main", "test", "regtest"}) {
            if (other == net) continue;
            SelectParams(ChainOf(other));
            KeyIO otherIO(Params());
            BOOST_CHECK(!IsValidDestination(otherIO.DecodeDestination(addr)));
            BOOST_CHECK(!yellowback::DecodeAddress(addr, yellowback::ParamsForNetwork(other), back));
        }
    }
    for (size_t i = 0; i < invalid.size(); i++) {
        const UniValue& v = invalid[i];
        const std::string net = v["network"].get_str(), addr = v["address"].get_str();
        SelectParams(ChainOf(net));
        KeyIO keyIO(Params());
        CPQKeyID back;
        BOOST_CHECK_MESSAGE(!IsValidDestination(keyIO.DecodeDestination(addr)), v["reason"].get_str() + " " + addr);
        BOOST_CHECK_MESSAGE(!yellowback::DecodeAddress(addr, yellowback::ParamsForNetwork(net), back), v["reason"].get_str() + " " + addr);
        CTxDestination dest;
        BOOST_CHECK(!yellowback::DecodeAddress(addr, yellowback::ParamsForNetwork(net), dest));
    }
    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_CASE(legacy_pq_form_for_wallet_records_only)
{
    // The pre-D-9 form is read only by the wallet (an address-book record or a key-dump line written before D-9).
    const uint256 h = GetRandHash();
    for (const std::string net : {"main", "test", "regtest"}) {
        for (uint8_t scheme : {pq::SCHEME_SLH_DSA_SHA2_128S, pq::SCHEME_FN_DSA_512}) {
            const std::vector<unsigned char> yec = net == "main" ? std::vector<unsigned char>{0x4D, 0xD9} : net == "test" ? std::vector<unsigned char>{0x4F, 0x61} : std::vector<unsigned char>{0x4C, 0x51};
            const std::vector<unsigned char> yed = net == "main" ? std::vector<unsigned char>{0x56, 0xAB} : net == "test" ? std::vector<unsigned char>{0x57, 0x1E} : std::vector<unsigned char>{0x57, 0x10};
            CPQKeyID back;
            BOOST_CHECK(DecodeLegacyPQAddress(OldBase58(yec, scheme, h), net, false, back) && back == CPQKeyID(scheme, h));
            BOOST_CHECK(DecodeLegacyPQAddress(OldBase58(yed, scheme, h), net, true, back) && back == CPQKeyID(scheme, h));
            BOOST_CHECK(!DecodeLegacyPQAddress(OldBase58(yec, scheme, h), net, true, back));
            BOOST_CHECK(!DecodeLegacyPQAddress(OldBase58(yec, 3, h), net, false, back));
            // and never the new form
            BOOST_CHECK(!DecodeLegacyPQAddress(EncodePQAddress(CPQKeyID(scheme, h), PlainPQAddressVersions(net)), net, false, back));
        }
    }
}

BOOST_AUTO_TEST_CASE(sq_and_yed_forms_are_distinct)
{
    // A PQ YED address (ybf…/ybs…) is not a KeyIO destination, and an sqf…/sqs… is not a YED address: the same key, two
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
