// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Attestation bundles (v3 plan §3.4, §3.8 BUNDLE-1, W2, W8): the codec and
// its sizes, extraction from every input position and both carrier modes,
// VerifyBundle's check order with every reason string reachable, the
// signature cache contract, and the bundle statistic. The attestations are
// the known-answer vectors of src/test/data/yellowback_attest_vectors.json.

#include "yellowback/attest.h"
#include "yellowback/bundle.h"
#include "yellowback/script.h"

#include "crypto/sha256.h"
#include "key.h"
#include "primitives/transaction.h"
#include "test/data/yellowback_attest_vectors.json.h"
#include "test/test_bitcoin.h"
#include "univalue.h"
#include "util/strencodings.h"

#include <boost/test/unit_test.hpp>

#include <map>

using namespace yellowback;

namespace {

struct Fixture
{
    std::vector<Attestation> atts;                    // the first six valid vectors: seq 0..5, one each
    std::vector<Attestation> extra;                   // the two later re-attestations of seq 0 (at 1002) and seq 1 (at 1003)
    std::map<uint16_t, CPubKey> keys;                 // seq -> pubkey
    std::map<int, uint256> blockHashes;               // citedHeight -> internal block hash
    BundleLimits limits;
    std::vector<uint16_t> selected;
    int R;

    Fixture()
    {
        UniValue doc;
        BOOST_REQUIRE(doc.read(std::string(json_tests::yellowback_attest_vectors, json_tests::yellowback_attest_vectors + sizeof(json_tests::yellowback_attest_vectors))));
        for (const UniValue& k : doc["keys"].getValues()) keys[k["seq"].get_int()] = CPubKey(ParseHex(k["pubkey"].get_str()));
        for (const UniValue& v : doc["valid"].getValues()) {
            std::optional<Attestation> a = DecodeAttestation(ParseHex(v["attestation"].get_str()));
            BOOST_REQUIRE(a);
            (atts.size() < 6 ? atts : extra).push_back(*a);
            blockHashes[a->citedHeight] = uint256(ParseHex(v["blockHashInternal"].get_str()));
        }
        BOOST_REQUIRE_EQUAL(atts.size(), 6u);
        BOOST_REQUIRE_EQUAL(extra.size(), 2u);
        BOOST_REQUIRE_EQUAL(extra[0].seq, 0);
        BOOST_REQUIRE_EQUAL(extra[0].citedHeight, 1002u);
        R = 1003;
        limits.attestMaxAge = 8;
        limits.mSelect = 2;
        limits.bundleMax = 6;
        limits.startHeight = 1000;
        limits.priceMin = PRICE_MIN;
        limits.priceMax = PRICE_MAX;
        selected = { 0, 1, 2, 3, 4, 5 };
    }

    std::function<std::optional<CPubKey>(uint16_t)> PubkeyOf() const
    {
        return [this](uint16_t seq) -> std::optional<CPubKey> {
            auto it = keys.find(seq);
            if (it == keys.end()) return std::nullopt;
            return it->second;
        };
    }
    std::function<std::optional<uint256>(int)> BlockHashAt() const
    {
        return [this](int h) -> std::optional<uint256> {
            auto it = blockHashes.find(h);
            if (it == blockHashes.end()) return std::nullopt;
            return it->second;
        };
    }
    BundleVerdict Verify(const CTransaction& tx, BundleCarrier mode = BundleCarrier::SCRIPTSIG, bool skipVin0 = false,
                         const std::vector<unsigned char>& tail = {}, SigCache* cache = nullptr) const
    {
        return VerifyBundle(tx, mode, skipVin0, tail, R, selected, limits, PubkeyOf(), BlockHashAt(), cache);
    }
};

uint256 Sha256(const std::vector<unsigned char>& d)
{
    uint256 out;
    CSHA256().Write(d.data(), d.size()).Finalize(out.begin());
    return out;
}

CPubKey SomeKey()
{
    CKey k;
    k = CKey::TestOnlyRandomKey(true);
    return k.GetPubKey();
}

/** A carrier input spending with `bundle`, its redeem script committing to `commit` (default: SHA256(bundle)). */
CTxIn CarrierIn(const std::vector<unsigned char>& bundle, std::optional<uint256> commit = std::nullopt, uint32_t n = 0)
{
    const CScript redeem = CarrierScript(SomeKey(), commit ? *commit : Sha256(bundle));
    return CTxIn(COutPoint(uint256S("aa"), n), CarrierScriptSig(bundle, std::vector<unsigned char>(71, 0x30), redeem));
}

CTxIn PlainIn(uint32_t n = 0)
{
    return CTxIn(COutPoint(uint256S("bb"), n), CScript() << std::vector<unsigned char>(71, 0x30) << std::vector<unsigned char>(33, 0x02));
}

CTransaction TxWith(std::vector<CTxIn> vin)
{
    CMutableTransaction mtx;
    mtx.vin = vin;
    mtx.vout.push_back(CTxOut(0, CScript() << OP_RETURN));
    return CTransaction(mtx);
}

std::vector<unsigned char> Enc(const std::vector<Attestation>& atts)
{
    Bundle b;
    b.atts = atts;
    return EncodeBundle(b);
}

class RecordingCache : public SigCache
{
public:
    std::map<uint256, bool> entries;
    mutable int lookups = 0;
    int inserts = 0;
    std::optional<bool> Lookup(const uint256& key) const override
    {
        lookups++;
        auto it = entries.find(key);
        if (it == entries.end()) return std::nullopt;
        return it->second;
    }
    void Insert(const uint256& key, bool valid) override
    {
        inserts++;
        entries[key] = valid;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(yellowback_bundle_tests, BasicTestingSetup)

// Rule: BUNDLE-1
BOOST_AUTO_TEST_CASE(codec_round_trip_and_sizes)
{
    Fixture f;
    // Six attestations are 448 bytes: "YA" 01 06 then 6 x 74.
    std::vector<unsigned char> six = Enc(f.atts);
    BOOST_CHECK_EQUAL(six.size(), 448u);
    BOOST_CHECK_EQUAL(six[0], 'Y');
    BOOST_CHECK_EQUAL(six[1], 'A');
    BOOST_CHECK_EQUAL(six[2], 1);
    BOOST_CHECK_EQUAL(six[3], 6);
    BOOST_CHECK(six.size() <= MAX_SCRIPT_ELEMENT_SIZE);
    std::optional<Bundle> d = DecodeBundle(six);
    BOOST_REQUIRE(d);
    BOOST_CHECK_EQUAL(d->version, 1);
    BOOST_REQUIRE_EQUAL(d->atts.size(), 6u);
    for (size_t i = 0; i < 6; i++) BOOST_CHECK(d->atts[i] == f.atts[i]);
    BOOST_CHECK(EncodeBundle(*d) == six);
    // The vectors file carries the same bytes.
    UniValue doc;
    BOOST_REQUIRE(doc.read(std::string(json_tests::yellowback_attest_vectors, json_tests::yellowback_attest_vectors + sizeof(json_tests::yellowback_attest_vectors))));
    BOOST_CHECK_EQUAL(HexStr(six), doc["bundle6"].get_str());
    // Six distinct seqs: a bundle of them is the happy path of VerifyBundle below.
    for (size_t i = 0; i < 6; i++) BOOST_CHECK_EQUAL(f.atts[i].seq, i);
    // Empty bundle: 4 bytes, decodes.
    std::vector<unsigned char> zero = Enc({});
    BOOST_CHECK_EQUAL(zero.size(), 4u);
    BOOST_REQUIRE(DecodeBundle(zero));
    BOOST_CHECK(DecodeBundle(zero)->atts.empty());
    // A seventh is refused by the default ceiling (BUNDLE_MAX = 6) and admitted by an explicit larger one.
    std::vector<Attestation> seven = f.atts;
    seven.push_back(f.atts[0]);
    std::vector<unsigned char> sevenEnc = Enc(seven);
    BOOST_CHECK_EQUAL(sevenEnc.size(), 4u + 7 * 74);
    BOOST_CHECK(!DecodeBundle(sevenEnc));
    BOOST_CHECK(!DecodeBundle(sevenEnc, 6));
    BOOST_CHECK(DecodeBundle(sevenEnc, 7));
    // Malformed: short header, bad magic, version 0 / 2, count-length mismatch either way, trailing byte.
    BOOST_CHECK(!DecodeBundle({}));
    BOOST_CHECK(!DecodeBundle({ 'Y', 'A', 1 }));
    { std::vector<unsigned char> b = six; b[1] = 'B'; BOOST_CHECK(!DecodeBundle(b)); }
    { std::vector<unsigned char> b = six; b[2] = 0; BOOST_CHECK(!DecodeBundle(b)); }
    { std::vector<unsigned char> b = six; b[2] = 2; BOOST_CHECK(!DecodeBundle(b)); }
    { std::vector<unsigned char> b = six; b[3] = 5; BOOST_CHECK(!DecodeBundle(b)); }
    { std::vector<unsigned char> b = six; b.pop_back(); BOOST_CHECK(!DecodeBundle(b)); }
    { std::vector<unsigned char> b = six; b.push_back(0); BOOST_CHECK(!DecodeBundle(b)); }
    { std::vector<unsigned char> b = { 'Y', 'A', 1, 1 }; BOOST_CHECK(!DecodeBundle(b)); }
}

// Rule: BUNDLE-1
BOOST_AUTO_TEST_CASE(extract_positions_and_modes)
{
    Fixture f;
    const std::vector<unsigned char> bundle = Enc({ f.atts[0], f.atts[1] });
    std::string reason;

    // Carrier at vin[0].
    {
        auto r = ExtractBundle(TxWith({ CarrierIn(bundle), PlainIn() }), BundleCarrier::SCRIPTSIG, false, {}, &reason);
        BOOST_REQUIRE(r);
        BOOST_CHECK(r->first == bundle);
        BOOST_CHECK(r->second == BundleSource::SCRIPTSIG);
        BOOST_CHECK(FindCarrierInput(TxWith({ CarrierIn(bundle), PlainIn() }), false) == std::optional<size_t>(0));
    }
    // Carrier at vin[2].
    {
        CTransaction tx = TxWith({ PlainIn(0), PlainIn(1), CarrierIn(bundle), PlainIn(2) });
        auto r = ExtractBundle(tx, BundleCarrier::SCRIPTSIG, false, {}, &reason);
        BOOST_REQUIRE(r);
        BOOST_CHECK(r->first == bundle);
        BOOST_CHECK(FindCarrierInput(tx, false) == std::optional<size_t>(2));
        BOOST_CHECK(FindCarrierInput(tx, true) == std::optional<size_t>(2));
    }
    // Two carriers.
    {
        CTransaction tx = TxWith({ CarrierIn(bundle), PlainIn(), CarrierIn(bundle, std::nullopt, 1) });
        BOOST_CHECK(!ExtractBundle(tx, BundleCarrier::SCRIPTSIG, false, {}, &reason));
        BOOST_CHECK_EQUAL(reason, "two-carriers");
        BOOST_CHECK(!FindCarrierInput(tx, false, &reason));
        BOOST_CHECK_EQUAL(reason, "two-carriers");
        // ... but with vin[0] skipped there is exactly one.
        BOOST_CHECK(FindCarrierInput(tx, true) == std::optional<size_t>(2));
        BOOST_CHECK(ExtractBundle(tx, BundleCarrier::SCRIPTSIG, true, {}, &reason));
        BOOST_CHECK_EQUAL(f.Verify(tx).reason, "two-carriers");
        BOOST_CHECK(f.Verify(tx, BundleCarrier::EITHER).reason == "two-carriers");
    }
    // A REDEEM whose vin[0] looks like a carrier: with skipVin0 the vault input is never considered.
    {
        CTransaction tx = TxWith({ CarrierIn(bundle), PlainIn() });
        BOOST_CHECK(!ExtractBundle(tx, BundleCarrier::SCRIPTSIG, true, {}, &reason));
        BOOST_CHECK_EQUAL(reason, "shape");
        BOOST_CHECK(!FindCarrierInput(tx, true, &reason));
        BOOST_CHECK_EQUAL(reason, "shape");
        CTransaction tx2 = TxWith({ CarrierIn(bundle), CarrierIn(bundle, std::nullopt, 1) });
        auto r = ExtractBundle(tx2, BundleCarrier::SCRIPTSIG, true, {}, &reason);
        BOOST_REQUIRE(r);
        BOOST_CHECK(FindCarrierInput(tx2, true) == std::optional<size_t>(1));
    }
    // No carrier at all, or no inputs.
    {
        BOOST_CHECK(!ExtractBundle(TxWith({ PlainIn() }), BundleCarrier::SCRIPTSIG, false, {}, &reason));
        BOOST_CHECK_EQUAL(reason, "shape");
        BOOST_CHECK(!ExtractBundle(TxWith({}), BundleCarrier::SCRIPTSIG, false, {}, &reason));
        BOOST_CHECK_EQUAL(reason, "shape");
        BOOST_CHECK(!ExtractBundle(TxWith({}), BundleCarrier::SCRIPTSIG, true, {}, &reason));
    }
    // Hash mismatch: the redeem script commits to something else (the malleation case, R2).
    {
        uint256 other = Sha256(bundle);
        *other.begin() ^= 1;
        CTransaction tx = TxWith({ PlainIn(), CarrierIn(bundle, other) });
        BOOST_CHECK(FindCarrierInput(tx, false) == std::optional<size_t>(1));   // shape is fine
        BOOST_CHECK(!ExtractBundle(tx, BundleCarrier::SCRIPTSIG, false, {}, &reason));
        BOOST_CHECK_EQUAL(reason, "hash");
        BOOST_CHECK_EQUAL(f.Verify(tx).reason, "hash");
    }
    // OP_RETURN mode reads the tail and ignores carriers; SCRIPTSIG ignores the tail.
    {
        CTransaction carrierTx = TxWith({ CarrierIn(bundle) });
        CTransaction plainTx = TxWith({ PlainIn() });
        auto r = ExtractBundle(plainTx, BundleCarrier::OP_RETURN, false, bundle, &reason);
        BOOST_REQUIRE(r);
        BOOST_CHECK(r->first == bundle);
        BOOST_CHECK(r->second == BundleSource::OP_RETURN);
        BOOST_CHECK(!ExtractBundle(plainTx, BundleCarrier::OP_RETURN, false, {}, &reason));
        BOOST_CHECK_EQUAL(reason, "shape");
        r = ExtractBundle(carrierTx, BundleCarrier::OP_RETURN, false, bundle, &reason);
        BOOST_REQUIRE(r);
        BOOST_CHECK(r->second == BundleSource::OP_RETURN);
        BOOST_CHECK(!ExtractBundle(plainTx, BundleCarrier::SCRIPTSIG, false, bundle, &reason));
        BOOST_CHECK_EQUAL(reason, "shape");
        // EITHER: exactly one of the two.
        r = ExtractBundle(carrierTx, BundleCarrier::EITHER, false, {}, &reason);
        BOOST_REQUIRE(r);
        BOOST_CHECK(r->second == BundleSource::SCRIPTSIG);
        r = ExtractBundle(plainTx, BundleCarrier::EITHER, false, bundle, &reason);
        BOOST_REQUIRE(r);
        BOOST_CHECK(r->second == BundleSource::OP_RETURN);
        BOOST_CHECK(!ExtractBundle(carrierTx, BundleCarrier::EITHER, false, bundle, &reason));
        BOOST_CHECK_EQUAL(reason, "shape");
        BOOST_CHECK(!ExtractBundle(plainTx, BundleCarrier::EITHER, false, {}, &reason));
        BOOST_CHECK_EQUAL(reason, "shape");
        // The extractor does not decode: garbage rides through, VerifyBundle calls it "shape".
        std::vector<unsigned char> junk = { 1, 2, 3 };
        BOOST_CHECK(ExtractBundle(TxWith({ CarrierIn(junk) }), BundleCarrier::SCRIPTSIG, false, {}, &reason));
        BOOST_CHECK_EQUAL(f.Verify(TxWith({ CarrierIn(junk) })).reason, "shape");
        BOOST_CHECK_EQUAL(f.Verify(plainTx, BundleCarrier::OP_RETURN, false, junk).reason, "shape");
    }
}

// Rule: BUNDLE-1
BOOST_AUTO_TEST_CASE(verify_order_every_reason)
{
    Fixture f;
    // The happy path: all six, every seq selected, R = 1003.
    {
        BundleVerdict v = f.Verify(TxWith({ PlainIn(), CarrierIn(Enc(f.atts)) }));
        BOOST_CHECK_MESSAGE(v.ok, v.reason);
        BOOST_CHECK(v.reason.empty());
        BOOST_REQUIRE_EQUAL(v.C.size(), 6u);
        for (size_t i = 0; i < 6; i++) BOOST_CHECK(v.C[i] == f.atts[i]);
        BOOST_CHECK(!v.aMint && !v.aClaim);   // BundleStat fills these
        // The same through the OP_RETURN and EITHER modes.
        BOOST_CHECK(f.Verify(TxWith({ PlainIn() }), BundleCarrier::OP_RETURN, false, Enc(f.atts)).ok);
        BOOST_CHECK(f.Verify(TxWith({ PlainIn(), CarrierIn(Enc(f.atts)) }), BundleCarrier::EITHER).ok);
        // Exactly mSelect is enough.
        BOOST_CHECK(f.Verify(TxWith({ CarrierIn(Enc({ f.atts[0], f.atts[1] })) })).ok);
    }
    // shape: no carrier.
    BOOST_CHECK_EQUAL(f.Verify(TxWith({ PlainIn() })).reason, "shape");
    // shape: a carrier whose bundle is malformed even though it hashes right.
    {
        std::vector<unsigned char> b = Enc(f.atts);
        b[2] = 2;
        BOOST_CHECK_EQUAL(f.Verify(TxWith({ CarrierIn(b) })).reason, "shape");
        b = Enc(f.atts);
        b.push_back(0);
        BOOST_CHECK_EQUAL(f.Verify(TxWith({ CarrierIn(b) })).reason, "shape");
    }
    // hash, before anything about the content: a valid bundle committed wrongly.
    {
        uint256 other = Sha256(Enc(f.atts));
        *other.begin() ^= 1;
        BOOST_CHECK_EQUAL(f.Verify(TxWith({ CarrierIn(Enc(f.atts), other) })).reason, "hash");
        // Even a malformed bundle with a wrong hash is "hash", not "shape": hash precedes decoding.
        std::vector<unsigned char> junk = { 9 };
        BOOST_CHECK_EQUAL(f.Verify(TxWith({ CarrierIn(junk, other) })).reason, "hash");
    }
    // count: below mSelect, above bundleMax, and zero.
    BOOST_CHECK_EQUAL(f.Verify(TxWith({ CarrierIn(Enc({ f.atts[0] })) })).reason, "count");
    BOOST_CHECK_EQUAL(f.Verify(TxWith({ CarrierIn(Enc({})) })).reason, "count");
    {
        std::vector<Attestation> seven = f.atts;
        seven.push_back(f.atts[0]);   // also a dup and would be "dup" later; count comes first
        BOOST_CHECK_EQUAL(f.Verify(TxWith({ CarrierIn(Enc(seven)) })).reason, "count");
    }
    // member: seq 5 not selected (its attestation is otherwise valid); precedes dup, stale, sig.
    {
        Fixture g;
        g.selected = { 0, 1, 2, 3, 4 };
        BOOST_CHECK_EQUAL(g.Verify(TxWith({ CarrierIn(Enc({ g.atts[0], g.atts[1], g.atts[5] })) })).reason, "member");
        std::vector<Attestation> bad = { g.atts[0], g.atts[0], g.atts[5] };   // dup of 0 comes before 5 in order...
        BOOST_CHECK_EQUAL(g.Verify(TxWith({ CarrierIn(Enc(bad)) })).reason, "dup");   // ... so dup wins: checks run per attestation in order
        bad = { g.atts[5], g.atts[0], g.atts[0] };
        BOOST_CHECK_EQUAL(g.Verify(TxWith({ CarrierIn(Enc(bad)) })).reason, "member");
        Attestation s = g.atts[5];
        s.sig[5] ^= 1;
        BOOST_CHECK_EQUAL(g.Verify(TxWith({ CarrierIn(Enc({ g.atts[0], g.atts[1], s })) })).reason, "member");
        g.selected = {};
        BOOST_CHECK_EQUAL(g.Verify(TxWith({ CarrierIn(Enc({ g.atts[0], g.atts[1] })) })).reason, "member");
    }
    // dup: the same seq twice (two different attestations of one attestor, both fresh, both valid).
    BOOST_CHECK_EQUAL(f.Verify(TxWith({ CarrierIn(Enc({ f.atts[0], f.extra[0] })) })).reason, "dup");     // seq 0 at 1000 and 1002, both valid
    BOOST_CHECK(f.Verify(TxWith({ CarrierIn(Enc({ f.atts[1], f.extra[0] })) })).ok);                      // either one alone is fine
    BOOST_CHECK_EQUAL(f.Verify(TxWith({ CarrierIn(Enc({ f.atts[0], f.atts[1], f.atts[0] })) })).reason, "dup");
    // stale: citedHeight > R, <= R - attestMaxAge, < startHeight. Precedes range and sig.
    {
        Fixture g;
        g.R = 1002;   // atts[4], [5] cite 1003
        BOOST_CHECK_EQUAL(g.Verify(TxWith({ CarrierIn(Enc({ g.atts[0], g.atts[4] })) })).reason, "stale");
        g.R = 1003;
        g.limits.attestMaxAge = 3;   // (1000, 1003]: atts[0] at 1000 is out, atts[2] at 1001 is in
        BOOST_CHECK_EQUAL(g.Verify(TxWith({ CarrierIn(Enc({ g.atts[2], g.atts[0] })) })).reason, "stale");
        BOOST_CHECK(g.Verify(TxWith({ CarrierIn(Enc({ g.atts[2], g.atts[4] })) })).ok);
        g.limits.attestMaxAge = 8;
        g.limits.startHeight = 1001;
        BOOST_CHECK_EQUAL(g.Verify(TxWith({ CarrierIn(Enc({ g.atts[2], g.atts[0] })) })).reason, "stale");
        // stale before range: a stale attestation with an out-of-range price.
        g.limits.startHeight = 1000;
        Attestation a = g.atts[0];
        a.citedHeight = 990;
        a.priceMicroUsd = 1;
        BOOST_CHECK_EQUAL(g.Verify(TxWith({ CarrierIn(Enc({ g.atts[1], a })) })).reason, "stale");
        // stale before sig: a valid signature is not consulted for a stale attestation (blockHashAt would fail at 990).
        Attestation b = g.atts[0];
        b.citedHeight = 990;
        BOOST_CHECK_EQUAL(g.Verify(TxWith({ CarrierIn(Enc({ g.atts[1], b })) })).reason, "stale");
    }
    // range: price below priceMin / above priceMax (the signature is then wrong too, but range comes first).
    {
        Attestation a = f.atts[0];
        a.priceMicroUsd = PRICE_MIN - 1;
        BOOST_CHECK_EQUAL(f.Verify(TxWith({ CarrierIn(Enc({ f.atts[1], a })) })).reason, "range");
        a.priceMicroUsd = (uint32_t)PRICE_MAX + 1;
        BOOST_CHECK_EQUAL(f.Verify(TxWith({ CarrierIn(Enc({ f.atts[1], a })) })).reason, "range");
        a.priceMicroUsd = 0xFFFFFFFF;
        BOOST_CHECK_EQUAL(f.Verify(TxWith({ CarrierIn(Enc({ f.atts[1], a })) })).reason, "range");
        Fixture g;
        g.limits.priceMin = 100001;   // atts[0] is at 100000
        BOOST_CHECK_EQUAL(g.Verify(TxWith({ CarrierIn(Enc({ g.atts[1], g.atts[0] })) })).reason, "range");
        g.limits.priceMin = PRICE_MIN;
        g.limits.priceMax = 100999;   // atts[1] is at 101000
        BOOST_CHECK_EQUAL(g.Verify(TxWith({ CarrierIn(Enc({ g.atts[0], g.atts[1] })) })).reason, "range");
    }
    // sig: a flipped signature bit, a tampered price inside the range, a high-S re-encoding, an unknown key, an unknown block hash.
    {
        Attestation a = f.atts[0];
        a.sig[10] ^= 1;
        BOOST_CHECK_EQUAL(f.Verify(TxWith({ CarrierIn(Enc({ f.atts[1], a })) })).reason, "sig");
        a = f.atts[0];
        a.priceMicroUsd += 1;
        BOOST_CHECK_EQUAL(f.Verify(TxWith({ CarrierIn(Enc({ f.atts[1], a })) })).reason, "sig");
        // Good attestations before the bad one pass: the first failure is the bad one, still "sig".
        BOOST_CHECK_EQUAL(f.Verify(TxWith({ CarrierIn(Enc({ f.atts[1], f.atts[2], a })) })).reason, "sig");
        Fixture g;
        g.keys.erase(2);
        BOOST_CHECK_EQUAL(g.Verify(TxWith({ CarrierIn(Enc({ g.atts[0], g.atts[2] })) })).reason, "sig");
        Fixture h;
        h.blockHashes.erase(1001);
        BOOST_CHECK_EQUAL(h.Verify(TxWith({ CarrierIn(Enc({ h.atts[0], h.atts[2] })) })).reason, "sig");
        // A different block hash at the cited height (a reorg): the signature no longer binds.
        Fixture k;
        *k.blockHashes[1001].begin() ^= 1;
        BOOST_CHECK_EQUAL(k.Verify(TxWith({ CarrierIn(Enc({ k.atts[0], k.atts[2] })) })).reason, "sig");
        // Nullary callbacks are "sig", never a crash.
        BundleVerdict v = VerifyBundle(TxWith({ CarrierIn(Enc({ f.atts[0], f.atts[1] })) }), BundleCarrier::SCRIPTSIG, false, {},
                                       f.R, f.selected, f.limits, nullptr, nullptr, nullptr);
        BOOST_CHECK_EQUAL(v.reason, "sig");
    }
    // A failed verdict carries no attestations.
    BOOST_CHECK(f.Verify(TxWith({ CarrierIn(Enc({ f.atts[0] })) })).C.empty());
}

// Rule: BUNDLE-1
BOOST_AUTO_TEST_CASE(sig_cache_contract)
{
    Fixture f;
    RecordingCache cache;
    const CTransaction tx = TxWith({ CarrierIn(Enc(f.atts)) });
    // Cold: six lookups miss, six inserts, all valid.
    BundleVerdict v = f.Verify(tx, BundleCarrier::SCRIPTSIG, false, {}, &cache);
    BOOST_CHECK(v.ok);
    BOOST_CHECK_EQUAL(cache.lookups, 6);
    BOOST_CHECK_EQUAL(cache.inserts, 6);
    BOOST_CHECK_EQUAL(cache.entries.size(), 6u);
    for (const auto& e : cache.entries) BOOST_CHECK(e.second);
    // Keys are SHA256(attestation74 || blockHash(citedHeight)).
    for (const Attestation& a : f.atts) {
        std::vector<unsigned char> pre = EncodeAttestation(a);
        const uint256& bh = f.blockHashes[a.citedHeight];
        pre.insert(pre.end(), bh.begin(), bh.end());
        BOOST_CHECK(SigCacheKey(a, bh) == Sha256(pre));
        BOOST_CHECK(cache.entries.count(SigCacheKey(a, bh)));
    }
    // Warm: no verification, no insert, same verdict (cache_hit_equals_cold). pubkeyOf is not even consulted.
    Fixture noKeys;
    noKeys.keys.clear();
    v = noKeys.Verify(tx, BundleCarrier::SCRIPTSIG, false, {}, &cache);
    BOOST_CHECK(v.ok);
    BOOST_CHECK_EQUAL(cache.inserts, 6);
    // A negative entry is honoured too, and a cold negative is inserted as false.
    Attestation bad = f.atts[0];
    bad.sig[0] ^= 1;
    const CTransaction badTx = TxWith({ CarrierIn(Enc({ bad, f.atts[1] })) });
    BOOST_CHECK_EQUAL(f.Verify(badTx, BundleCarrier::SCRIPTSIG, false, {}, &cache).reason, "sig");
    BOOST_CHECK_EQUAL(cache.inserts, 7);
    BOOST_CHECK(cache.entries.at(SigCacheKey(bad, f.blockHashes[1000])) == false);
    // The key binds the block hash: a reorged hash is a fresh cache line, not a stale hit.
    Fixture k;
    *k.blockHashes[1000].begin() ^= 1;
    BOOST_CHECK_EQUAL(k.Verify(tx, BundleCarrier::SCRIPTSIG, false, {}, &cache).reason, "sig");
    BOOST_CHECK_EQUAL(cache.inserts, 8);
    // The cache is behind the cheap checks: a "count" failure touches it not at all.
    const int before = cache.lookups;
    BOOST_CHECK_EQUAL(f.Verify(TxWith({ CarrierIn(Enc({ f.atts[0] })) }), BundleCarrier::SCRIPTSIG, false, {}, &cache).reason, "count");
    BOOST_CHECK_EQUAL(cache.lookups, before);
}

// Rule: BUNDLE-1
BOOST_AUTO_TEST_CASE(bundle_stat)
{
    Fixture f;
    auto W = [](std::initializer_list<uint64_t> ws) {
        std::vector<arith_uint256> out;
        for (uint64_t w : ws) out.push_back(arith_uint256(w));
        return out;
    };
    // Prices by seq: 0 100000, 1 101000, 2 99500, 3 100500, 4 100000, 5 102000.
    // Equal weights, Q = 3333 / 6667 bps: thresholds ceil(6*3333/1e4) = 2, ceil(6*6667/1e4) = 5 of 6.
    // Sorted: 99500, 100000(seq0), 100000(seq4), 100500, 101000, 102000 -> aMint = 100000, aClaim = 101000.
    auto r = BundleStat(f.atts, W({ 1, 1, 1, 1, 1, 1 }), 2, 3333, 6667);
    BOOST_REQUIRE(r.first && r.second);
    BOOST_CHECK_EQUAL(*r.first, 100000);
    BOOST_CHECK_EQUAL(*r.second, 101000);
    // Undefined below mSelect, on a weights-length mismatch, on empty input, on a bad quantile.
    BOOST_CHECK(!BundleStat(f.atts, W({ 1, 1, 1, 1, 1, 1 }), 7, 3333, 6667).first);
    BOOST_CHECK(!BundleStat(f.atts, W({ 1, 1 }), 2, 3333, 6667).first);
    BOOST_CHECK(!BundleStat({}, W({}), 0, 3333, 6667).first);
    BOOST_CHECK(!BundleStat(f.atts, W({ 1, 1, 1, 1, 1, 1 }), 2, -1, 6667).first);
    BOOST_CHECK(!BundleStat(f.atts, W({ 1, 1, 1, 1, 1, 1 }), 2, 3333, 10001).second);
    // Weighted: one heavy attestor drags the quantile. Weights on the file order: seq2 (99500) weight 100, others 1: total 105,
    // low threshold ceil(105*3333/1e4) = 35 -> reached at 99500 (cum 100); high ceil(105*6667/1e4) = 71 -> also 99500.
    r = BundleStat(f.atts, W({ 1, 1, 100, 1, 1, 1 }), 2, 3333, 6667);
    BOOST_CHECK_EQUAL(*r.first, 99500);
    BOOST_CHECK_EQUAL(*r.second, 99500);
    // Boundary: cumulative weight exactly at the threshold counts (">=" ). Two attestations, weights 1 and 2, Q_LOW = 3334 bps:
    // ceil(3*3334/1e4) = ceil(1.0002) = 2 -> the second; at 3333 bps: ceil(0.9999) = 1 -> the first.
    std::vector<Attestation> two = { f.atts[2], f.atts[1] };   // 99500, 101000
    BOOST_CHECK_EQUAL(*BundleStat(two, W({ 1, 2 }), 2, 3333, 3334).first, 99500);
    BOOST_CHECK_EQUAL(*BundleStat(two, W({ 1, 2 }), 2, 3333, 3334).second, 101000);
    // Exactly at: weights 1 and 1, 5000 bps -> threshold 1 -> the first; 5001 -> 2 -> the second.
    BOOST_CHECK_EQUAL(*BundleStat(two, W({ 1, 1 }), 2, 5000, 5001).first, 99500);
    BOOST_CHECK_EQUAL(*BundleStat(two, W({ 1, 1 }), 2, 5000, 5001).second, 101000);
    // 0 and 10000 bps: the minimum and the maximum.
    BOOST_CHECK_EQUAL(*BundleStat(f.atts, W({ 3, 1, 4, 1, 5, 9 }), 2, 0, 10000).first, 99500);
    BOOST_CHECK_EQUAL(*BundleStat(f.atts, W({ 3, 1, 4, 1, 5, 9 }), 2, 0, 10000).second, 102000);
    // Ties in price sort by seq and share the bucket: seq0 and seq4 both at 100000.
    std::vector<Attestation> tie = { f.atts[4], f.atts[0] };
    BOOST_CHECK_EQUAL(*BundleStat(tie, W({ 1, 1 }), 2, 5000, 10000).first, 100000);
    // All-zero weights: threshold 0, the lowest price for both (stated for totality).
    r = BundleStat(two, W({ 0, 0 }), 2, 3333, 6667);
    BOOST_CHECK_EQUAL(*r.first, 99500);
    BOOST_CHECK_EQUAL(*r.second, 99500);
    // Large weights (bondZat * AGE_CAP ~ 4e17 each) do not overflow.
    arith_uint256 big = arith_uint256(2000000000000ULL) * arith_uint256(207360);
    std::vector<arith_uint256> bigs(6, big);
    r = BundleStat(f.atts, bigs, 2, 3333, 6667);
    BOOST_CHECK_EQUAL(*r.first, 100000);
    BOOST_CHECK_EQUAL(*r.second, 101000);
}

BOOST_AUTO_TEST_SUITE_END()
