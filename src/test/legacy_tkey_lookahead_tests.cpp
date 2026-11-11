// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Beta2 (seed-only restore of ECC coins): the legacy transparent HD lookahead (CWallet::TopUpLegacyTKeys,
// MarkLegacyTKeyUsed, NoteLegacyTKeysUsed), its window arithmetic, the key path parser and the keypool marking
// (Bitcoin Core's MarkReserveKeysAsUsed). The end-to-end restore is qa/rpc-tests/wallet_seed_restore_ecc.py.

#include "chainparams.h"
#include "key_io.h"
#include "script/ismine.h"
#include "script/standard.h"
#include "test/test_bitcoin.h"
#include "wallet/db.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "zcash/address/mnemonic.h"
#include "zcash/address/transparent.h"

#include <boost/test/unit_test.hpp>

namespace {

MnemonicSeed LookaheadTestSeed()
{
    RawHDSeed entropy(32, 0x2a);
    std::optional<MnemonicSeed> m = MnemonicSeed::FromEntropy(entropy, Params().BIP44CoinType());
    BOOST_REQUIRE(m.has_value());
    return m.value();
}

CKeyID SeedKey(bool external, uint32_t index)
{
    auto account = libzcash::transparent::AccountKey::ForAccount(LookaheadTestSeed(), Params().BIP44CoinType(), libzcash::ZCASH_LEGACY_ACCOUNT);
    BOOST_REQUIRE(account.has_value());
    std::optional<CKey> key = external ? account.value().DeriveExternalSpendingKey(index) : account.value().DeriveInternalSpendingKey(index);
    BOOST_REQUIRE(key.has_value());
    return key.value().GetPubKey().GetID();
}

CTransaction Paying(const CScript& to)
{
    CMutableTransaction mtx;
    mtx.fOverwintered = true;
    mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    mtx.nVersion = SAPLING_TX_VERSION;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0x77"), 0), CScript(), CTxIn::SEQUENCE_FINAL));
    mtx.vout.push_back(CTxOut(1000, to));
    return CTransaction(mtx);
}

uint32_t Counter(const CWallet& w, bool external)
{
    CHDChain chain = w.GetMnemonicHDChain().value();
    return chain.GetLegacyTKeyCounter(external);
}

//! The lowest and highest internal index among the keypool's entries.
std::pair<uint32_t, uint32_t> PoolRange(const CWallet& w)
{
    uint32_t lo = UINT32_MAX, hi = 0;
    for (int64_t nIndex : w.setKeyPool) {
        auto id = w.mapKeyPoolKeyId.find(nIndex);
        BOOST_REQUIRE(id != w.mapKeyPoolKeyId.end());
        auto pos = ParseLegacyTKeyPath(w.mapKeyMetadata.at(id->second).hdKeypath, Params().BIP44CoinType());
        BOOST_REQUIRE(pos.has_value() && !pos.value().first);
        lo = std::min(lo, pos.value().second);
        hi = std::max(hi, pos.value().second);
    }
    return {lo, hi};
}

void NewSeededWallet(CWallet& w)
{
    bool fFirstRun;
    BOOST_REQUIRE_EQUAL(w.LoadWallet(fFirstRun), DB_LOAD_OK);
    LOCK(w.cs_wallet);
    BOOST_REQUIRE(w.SetMnemonicSeed(LookaheadTestSeed()));
    w.SetMnemonicHDChain(CHDChain(LookaheadTestSeed().Fingerprint(), 1), false);
    w.TopUpKeyPool();        // -keypool + 1 internal keys, as the restore's NewKeyPool and the first top-up leave it
    w.TopUpLegacyTKeys();
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(legacy_tkey_lookahead_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(window_arithmetic)
{
    // the lookahead holds the keypool size plus one keys (as many as the keypool), from the counter on
    BOOST_CHECK_EQUAL(LegacyTKeyLookahead(100), 101U);
    BOOST_CHECK_EQUAL(LegacyTKeyLookahead(1), 2U);
    BOOST_CHECK_EQUAL(LegacyTKeyLookahead(0), 1U);
    BOOST_CHECK_EQUAL(LegacyTKeyLookahead(-7), 1U);
    BOOST_CHECK_EQUAL(LegacyTKeyLookahead(INT64_MAX), 0x7FFFFFFFU);
    BOOST_CHECK_EQUAL(LegacyTKeyLookaheadEnd(0, 101), 101U);
    BOOST_CHECK_EQUAL(LegacyTKeyLookaheadEnd(272, 101), 373U);   // last used 271: 272..372 held, a gap of 100 is found
    BOOST_CHECK_EQUAL(LegacyTKeyLookaheadEnd(0x7FFFFFF0U, 101), 0x80000000U);   // never a hardened index
    BOOST_CHECK_EQUAL(LegacyTKeyLookaheadEnd(0xFFFFFFFFU, 0x7FFFFFFFU), 0x80000000U);
}

BOOST_AUTO_TEST_CASE(key_path_parser)
{
    const uint32_t coin = Params().BIP44CoinType();
    const std::string account = libzcash::transparent::AccountKey::KeyPath(coin, libzcash::ZCASH_LEGACY_ACCOUNT);
    BOOST_CHECK(ParseLegacyTKeyPath(account + "/0/0", coin) == std::make_optional(std::make_pair(true, 0U)));
    BOOST_CHECK(ParseLegacyTKeyPath(account + "/1/150", coin) == std::make_optional(std::make_pair(false, 150U)));
    BOOST_CHECK(ParseLegacyTKeyPath(account + "/0/2147483647", coin) == std::make_optional(std::make_pair(true, 0x7FFFFFFFU)));
    BOOST_CHECK(libzcash::transparent::AccountKey::KeyPath(coin, libzcash::ZCASH_LEGACY_ACCOUNT, true, 42) == account + "/0/42");
    for (const std::string bad : {account + "/0/2147483648", account + "/0/4294967296", account + "/2/1", account + "/0/",
                                  account + "/0/01", account + "/0/1'", account + "/0/1/2", account + "/0/-1", account + "/01",
                                  libzcash::transparent::AccountKey::KeyPath(coin, 0) + "/0/1",
                                  libzcash::transparent::AccountKey::KeyPath(coin + 1, libzcash::ZCASH_LEGACY_ACCOUNT) + "/0/1",
                                  std::string("m/32'/") + std::to_string(coin) + "'/2147483647'/0'", std::string("")}) {
        BOOST_CHECK_MESSAGE(!ParseLegacyTKeyPath(bad, coin).has_value(), bad);
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(legacy_tkey_lookahead_db_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(restore_marks_and_keypool)
{
    bitdb.MakeMock();
    const std::string file = "legacy_tkey_lookahead_test.dat";
    const uint32_t N = LegacyTKeyLookahead(DEFAULT_KEYPOOL_SIZE);   // 101
    {
        CWallet w(Params(), file);
        NewSeededWallet(w);
        LOCK(w.cs_wallet);
        // a restored wallet: the keypool holds internal 0..100 (issued), the lookahead external 0..100 and internal
        // 101..201 (held, counters unmoved)
        BOOST_CHECK_EQUAL(Counter(w, true), 0U);
        BOOST_CHECK_EQUAL(Counter(w, false), N);
        BOOST_CHECK_EQUAL(w.setKeyPool.size(), (size_t)N);
        BOOST_CHECK(PoolRange(w) == std::make_pair(0U, N - 1));
        BOOST_CHECK_EQUAL(w.mapLegacyTKeyHeld.size(), 2U * N);
        BOOST_CHECK_EQUAL(w.nLegacyTKeyHeldEnd[1], N);
        BOOST_CHECK_EQUAL(w.nLegacyTKeyHeldEnd[0], 2U * N);
        BOOST_CHECK(w.IsHeldLegacyTKey(SeedKey(true, 0)) && w.IsHeldLegacyTKey(SeedKey(true, N - 1)));
        BOOST_CHECK(!w.HaveKey(SeedKey(true, N)));
        BOOST_CHECK(!w.IsHeldLegacyTKey(SeedKey(false, 0)) && w.HaveKey(SeedKey(false, 0)));   // pool keys are issued
        BOOST_CHECK(w.IsHeldLegacyTKey(SeedKey(false, 2 * N - 1)) && !w.HaveKey(SeedKey(false, 2 * N)));
        BOOST_CHECK(IsMine(w, GetScriptForDestination(SeedKey(true, 60))) == ISMINE_SPENDABLE);

        // an output paying external key 60: the counter moves to 61, keys 0..60 become issued, the window 61..161
        w.NoteLegacyTKeysUsed(Paying(GetScriptForDestination(SeedKey(true, 60))));
        BOOST_CHECK_EQUAL(Counter(w, true), 61U);
        BOOST_CHECK(!w.IsHeldLegacyTKey(SeedKey(true, 0)) && !w.IsHeldLegacyTKey(SeedKey(true, 60)));
        BOOST_CHECK(w.IsHeldLegacyTKey(SeedKey(true, 61)) && w.IsHeldLegacyTKey(SeedKey(true, 61 + N - 1)));
        BOOST_CHECK(!w.HaveKey(SeedKey(true, 61 + N)));
        BOOST_CHECK(w.mapAddressBook.count(SeedKey(true, 60)) && w.mapAddressBook[SeedKey(true, 60)].purpose == "receive");
        BOOST_CHECK(!w.mapAddressBook.count(SeedKey(true, 59)));   // issued, never seen paid: not listed
        // a key below the counter, or not of this seed, moves nothing
        w.NoteLegacyTKeysUsed(Paying(GetScriptForDestination(SeedKey(true, 10))));
        const CKey other = CKey::TestOnlyRandomKey(true);
        BOOST_REQUIRE(w.AddKeyPubKey(other, other.GetPubKey()));
        w.NoteLegacyTKeysUsed(Paying(GetScriptForDestination(other.GetPubKey().GetID())));
        BOOST_CHECK_EQUAL(Counter(w, true), 61U);

        // getnewaddress hands out the same key the seed derives at the counter, and the window follows it
        BOOST_CHECK(w.GenerateNewKey(true).GetID() == SeedKey(true, 61));
        BOOST_CHECK_EQUAL(Counter(w, true), 62U);
        BOOST_CHECK(!w.IsHeldLegacyTKey(SeedKey(true, 61)) && w.IsHeldLegacyTKey(SeedKey(true, 62 + N - 1)));

        // keypool marking: a P2PK output to the pool's internal key 50 takes internal 0..50 out of the pool, which
        // refills from the counter (101 + 51 = 152)
        CPubKey pk50;
        BOOST_REQUIRE(w.GetPubKey(SeedKey(false, 50), pk50));
        w.NoteLegacyTKeysUsed(Paying(CScript() << ToByteVector(pk50) << OP_CHECKSIG));
        BOOST_CHECK_EQUAL(w.setKeyPool.size(), (size_t)N);
        BOOST_CHECK(PoolRange(w) == std::make_pair(51U, 51U + N - 1));
        BOOST_CHECK_EQUAL(Counter(w, false), 152U);
        BOOST_CHECK_EQUAL(w.mapKeyPoolIndex.count(SeedKey(false, 50)), 0U);
        BOOST_CHECK(w.IsHeldLegacyTKey(SeedKey(false, 152 + N - 1)) && !w.HaveKey(SeedKey(false, 152 + N)));
        // an internal key beyond the pool (held, 180): every pool entry is below it and leaves; the pool refills
        // from 181
        BOOST_REQUIRE(w.IsHeldLegacyTKey(SeedKey(false, 180)));
        w.NoteLegacyTKeysUsed(Paying(GetScriptForDestination(SeedKey(false, 180))));
        BOOST_CHECK(PoolRange(w) == std::make_pair(181U, 181U + N - 1));
        BOOST_CHECK_EQUAL(Counter(w, false), 181U + N);
        BOOST_CHECK(!w.mapAddressBook.count(SeedKey(false, 180)));   // change is not filed
        BOOST_CHECK(w.HaveKey(SeedKey(false, 160)) && !w.IsHeldLegacyTKey(SeedKey(false, 160)));   // skipped: issued
    }
    {
        // the file holds the issued keys and the counters, never a held key; a reload derives the window again
        CWallet w(Params(), file);
        bool fFirstRun;
        BOOST_REQUIRE_EQUAL(w.LoadWallet(fFirstRun), DB_LOAD_OK);
        LOCK(w.cs_wallet);
        BOOST_CHECK_EQUAL(Counter(w, true), 62U);
        BOOST_CHECK(w.HaveKey(SeedKey(true, 61)) && w.HaveKey(SeedKey(true, 10)));
        BOOST_CHECK(!w.HaveKey(SeedKey(true, 62)));
        BOOST_CHECK(w.HaveKey(SeedKey(false, 160)));
        BOOST_CHECK(PoolRange(w) == std::make_pair(181U, 181U + N - 1));
        BOOST_CHECK_EQUAL(w.mapKeyPoolIndex.size(), (size_t)N);
        w.TopUpLegacyTKeys();
        BOOST_CHECK(w.IsHeldLegacyTKey(SeedKey(true, 62)) && w.IsHeldLegacyTKey(SeedKey(true, 62 + N - 1)));
        BOOST_CHECK(!w.HaveKey(SeedKey(true, 62 + N)));
        // the reserve/keep path: a kept key leaves both pool maps
        int64_t nIndex;
        CKeyPool keypool;
        w.ReserveKeyFromKeyPool(nIndex, keypool);
        BOOST_REQUIRE(nIndex > 0);
        w.KeepKey(nIndex);
        BOOST_CHECK_EQUAL(w.mapKeyPoolKeyId.count(nIndex), 0U);
        BOOST_CHECK_EQUAL(w.mapKeyPoolIndex.count(keypool.vchPubKey.GetID()), 0U);
    }
    bitdb.Flush(true);
    bitdb.Reset();
}

BOOST_AUTO_TEST_SUITE_END()
