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

//! The wallet database's raw record access, for writing what an intermediate build wrote and reading records back.
class RawWalletDB : public CWalletDB
{
public:
    explicit RawWalletDB(const std::string& file) : CWalletDB(file) {}
    using CDB::Exists;
    using CDB::Read;
    using CDB::Write;
};

//! The record holds, per chain, the key IDs the seed derives at the counter and the -keypool + 1 indices from it.
void CheckLookaheadRecord(const CLegacyTLookahead& r, const CWallet& w, uint32_t n)
{
    BOOST_CHECK(r.seedFp == LookaheadTestSeed().Fingerprint());
    for (bool external : {false, true}) {
        BOOST_CHECK_EQUAL(r.nStart[external], Counter(w, external));
        BOOST_REQUIRE_EQUAL(r.vIds[external].size(), (size_t)n);
        for (uint32_t k = 0; k < n; k += 25)
            BOOST_CHECK(CKeyID(r.vIds[external][k]) == SeedKey(external, r.nStart[external] + k));
        BOOST_CHECK(CKeyID(r.vIds[external][n - 1]) == SeedKey(external, r.nStart[external] + n - 1));
    }
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

BOOST_AUTO_TEST_CASE(held_key_write_failure)
{
    // Review L-a: a mark writes the held keys up to the paid one, then the counter. If a key write fails, the counter
    // must not move past that key (after a restart it would be below the counter and not in the file: its coins
    // unseen); the key stays held and the failure is flagged (getwalletinfo lookahead_incomplete).
    bitdb.MakeMock();
    const std::string file = "legacy_tkey_write_failure_test.dat";
    {
        CWallet w(Params(), file);
        NewSeededWallet(w);
        LOCK(w.cs_wallet);
        // the file holds a record for external key 50 already: writing the key fails (no overwrite), as a full disk would
        auto account = libzcash::transparent::AccountKey::ForAccount(LookaheadTestSeed(), Params().BIP44CoinType(), libzcash::ZCASH_LEGACY_ACCOUNT);
        const CKey k50 = account.value().DeriveExternalSpendingKey(50).value();
        BOOST_REQUIRE(CWalletDB(file).WriteKey(k50.GetPubKey(), k50.GetPrivKey(), CKeyMetadata(GetTime())));
        BOOST_REQUIRE(w.IsHeldLegacyTKey(SeedKey(true, 50)));

        BOOST_CHECK(!w.NoteLegacyTKeysUsed(Paying(GetScriptForDestination(SeedKey(true, 60))), 7));
        BOOST_CHECK_EQUAL(Counter(w, true), 0U);                            // not moved past key 50
        BOOST_CHECK(w.IsHeldLegacyTKey(SeedKey(true, 50)));                 // still held: a later mark writes it
        BOOST_CHECK(!w.IsHeldLegacyTKey(SeedKey(true, 49)) && !w.IsHeldLegacyTKey(SeedKey(true, 60)));   // written
        BOOST_CHECK(w.fLegacyTKeyLookaheadIncomplete);
        BOOST_CHECK_EQUAL(w.nLegacyTKeyIncompleteFrom, 7);
    }
    {
        // the counter in the file is the one before the mark, the flag is kept
        CWallet w(Params(), file);
        bool fFirstRun;
        BOOST_REQUIRE_EQUAL(w.LoadWallet(fFirstRun), DB_LOAD_OK);
        LOCK(w.cs_wallet);
        BOOST_CHECK(w.fLegacyTKeyLookaheadIncomplete);
        BOOST_CHECK_EQUAL(w.nLegacyTKeyIncompleteFrom, 7);
        BOOST_CHECK(w.HaveKey(SeedKey(true, 60)) && w.HaveKey(SeedKey(true, 50)));
    }
    bitdb.Flush(true);
    bitdb.Reset();
}

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
        // review 3 H-1: the stored key IDs are the window's, from the seed; unlocked, nothing is only watched
        BOOST_REQUIRE(w.legacyTLookahead.has_value());
        CheckLookaheadRecord(w.legacyTLookahead.value(), w, N);
        BOOST_CHECK(w.mapLegacyTKeyWatched.empty());

        // an output paying external key 60: the counter moves to 61, keys 0..60 become issued, the window 61..161
        w.NoteLegacyTKeysUsed(Paying(GetScriptForDestination(SeedKey(true, 60))));
        BOOST_CHECK_EQUAL(Counter(w, true), 61U);
        BOOST_CHECK(!w.IsHeldLegacyTKey(SeedKey(true, 0)) && !w.IsHeldLegacyTKey(SeedKey(true, 60)));
        BOOST_CHECK(w.IsHeldLegacyTKey(SeedKey(true, 61)) && w.IsHeldLegacyTKey(SeedKey(true, 61 + N - 1)));
        BOOST_CHECK(!w.HaveKey(SeedKey(true, 61 + N)));
        BOOST_CHECK(w.mapAddressBook.count(SeedKey(true, 60)) && w.mapAddressBook[SeedKey(true, 60)].purpose == "receive");
        BOOST_CHECK(!w.mapAddressBook.count(SeedKey(true, 59)));   // issued, never seen paid: not listed
        // a key below the counter, or not of this seed, moves nothing; key 10 was re-found with 60 (written by the
        // mark, not issued by this wallet), so its payment files it (review M-1)
        w.NoteLegacyTKeysUsed(Paying(GetScriptForDestination(SeedKey(true, 10))));
        BOOST_CHECK(w.mapAddressBook.count(SeedKey(true, 10)) && w.mapAddressBook[SeedKey(true, 10)].purpose == "receive");
        const CKey other = CKey::TestOnlyRandomKey(true);
        BOOST_REQUIRE(w.AddKeyPubKey(other, other.GetPubKey()));
        w.NoteLegacyTKeysUsed(Paying(GetScriptForDestination(other.GetPubKey().GetID())));
        BOOST_CHECK_EQUAL(Counter(w, true), 61U);

        // getnewaddress hands out the same key the seed derives at the counter, and the window follows it
        BOOST_CHECK(w.GenerateNewKey(true).GetID() == SeedKey(true, 61));
        BOOST_CHECK_EQUAL(Counter(w, true), 62U);
        BOOST_CHECK(!w.IsHeldLegacyTKey(SeedKey(true, 61)) && w.IsHeldLegacyTKey(SeedKey(true, 62 + N - 1)));
        // review M-1: a key this wallet issued itself (getnewaddress files it; the vault RPCs' change keys,
        // NewWalletKey, are deliberately not filed) keeps its address-book state when it is paid
        w.NoteLegacyTKeysUsed(Paying(GetScriptForDestination(SeedKey(true, 61))));
        BOOST_CHECK(!w.mapAddressBook.count(SeedKey(true, 61)));
        BOOST_CHECK_EQUAL(Counter(w, true), 62U);

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
        BOOST_REQUIRE(w.legacyTLookahead.has_value());       // review 3 H-1: the window's key IDs are in the file
        BOOST_CHECK_EQUAL(w.legacyTLookahead.value().nStart[1], 62U);
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

BOOST_AUTO_TEST_CASE(stale_counter_after_crash)
{
    // Review L-1: a mark writes the keys up to a paid one, then the counter. A crash (or a failed write) between
    // the two leaves keys at and past the counter on disk; getnewaddress and the keypool must skip them as issued
    // (one of them was paid), not hand them out again nor try to write them again (the database refuses it).
    bitdb.MakeMock();
    const std::string file = "legacy_tkey_stale_counter_test.dat";
    const uint32_t N = LegacyTKeyLookahead(DEFAULT_KEYPOOL_SIZE);   // 101
    uint32_t internalCounter;
    {
        CWallet w(Params(), file);
        NewSeededWallet(w);
        LOCK(w.cs_wallet);
        BOOST_CHECK(w.MarkLegacyTKeyUsed(SeedKey(true, 70)));        // writes external 0..70, the counter 71
        BOOST_CHECK_EQUAL(Counter(w, true), 71U);
        internalCounter = Counter(w, false);
        // the crash: the counter on disk is the one before the mark
        CHDChain stale(LookaheadTestSeed().Fingerprint(), 1);
        for (uint32_t i = 0; i < internalCounter; i++)
            stale.IncrementLegacyTKeyCounter(false);
        BOOST_REQUIRE(CWalletDB(file).WriteMnemonicHDChain(stale));
    }
    {
        CWallet w(Params(), file);
        bool fFirstRun;
        BOOST_REQUIRE_EQUAL(w.LoadWallet(fFirstRun), DB_LOAD_OK);
        LOCK(w.cs_wallet);
        w.TopUpLegacyTKeys();
        BOOST_CHECK_EQUAL(Counter(w, true), 0U);
        BOOST_CHECK(w.HaveKey(SeedKey(true, 70)) && !w.IsHeldLegacyTKey(SeedKey(true, 70)));
        // the first getnewaddress skips the 71 stored keys and issues index 71, without throwing
        CPubKey k;
        BOOST_CHECK_NO_THROW(k = w.GenerateNewKey(true));
        BOOST_CHECK(k.GetID() == SeedKey(true, 71));
        BOOST_CHECK_EQUAL(Counter(w, true), 72U);
        BOOST_CHECK(w.GenerateNewKey(true).GetID() == SeedKey(true, 72));
        BOOST_CHECK(w.IsHeldLegacyTKey(SeedKey(true, 73 + N - 1)));
        // the keypool still tops up (the internal chain was not affected)
        BOOST_CHECK_EQUAL(Counter(w, false), internalCounter);
        BOOST_CHECK_NO_THROW(w.TopUpKeyPool(N + 3));
        BOOST_CHECK(w.setKeyPool.size() >= (size_t)N + 3);
    }
    {
        // and the counter it wrote holds after a reload
        CWallet w(Params(), file);
        bool fFirstRun;
        BOOST_REQUIRE_EQUAL(w.LoadWallet(fFirstRun), DB_LOAD_OK);
        LOCK(w.cs_wallet);
        BOOST_CHECK_EQUAL(Counter(w, true), 73U);
    }
    bitdb.Flush(true);
    bitdb.Reset();
}

BOOST_AUTO_TEST_CASE(lookahead_key_ids)
{
    // Review 3 H-1: the wallet stores the KEY IDs of its transparent lookahead in clear (legacytlookahead), never the
    // legacy account's extended public key: no chain code or public key of the account or of a chain is in the record,
    // so a copy of the file plus one leaked key gives no other key, and the file alone no shielding OVK.
    bitdb.MakeMock();
    const std::string file = "legacy_tkey_key_ids_test.dat";
    const uint32_t N = LegacyTKeyLookahead(DEFAULT_KEYPOOL_SIZE);   // 101
    CLegacyTLookahead stored;
    {
        CWallet w(Params(), file);
        NewSeededWallet(w);
        LOCK(w.cs_wallet);
        BOOST_REQUIRE(w.legacyTLookahead.has_value());
        stored = w.legacyTLookahead.value();
        CheckLookaheadRecord(stored, w, N);
        // the record's bytes hold no chain code (the account's or either chain's) and no account or chain public key
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        ss << stored;
        const std::string bytes(ss.begin(), ss.end());
        auto account = libzcash::transparent::AccountKey::ForAccount(LookaheadTestSeed(), Params().BIP44CoinType(), libzcash::ZCASH_LEGACY_ACCOUNT).value();
        const CChainablePubKey acct = account.ToAccountPubKey().GetChainablePubKey();
        std::vector<CChainablePubKey> secrets{acct, acct.Derive(0).value(), acct.Derive(1).value()};
        for (const CChainablePubKey& x : secrets) {
            const std::string cc(x.GetChainCode().begin(), x.GetChainCode().end());
            const std::string pk(x.GetPubKey().begin(), x.GetPubKey().end());
            BOOST_CHECK(bytes.find(cc) == std::string::npos);
            BOOST_CHECK(bytes.find(pk) == std::string::npos);
        }
        // getnewaddress moves the window and the record with it
        BOOST_CHECK(w.GenerateNewKey(true).GetID() == SeedKey(true, 0));
        BOOST_CHECK_EQUAL(w.legacyTLookahead.value().nStart[1], 1U);
        CheckLookaheadRecord(w.legacyTLookahead.value(), w, N);
        stored = w.legacyTLookahead.value();
        // the file carries a tampered record and the extended public key an intermediate build stored
        CLegacyTLookahead tampered = stored;
        tampered.vIds[1][3] = uint160(SeedKey(true, 900));
        BOOST_REQUIRE(CWalletDB(file).WriteLegacyTLookahead(tampered));
        BOOST_REQUIRE(RawWalletDB(file).Write(std::string("legacytaccountpub"),
                                              std::make_pair(LookaheadTestSeed().Fingerprint(), acct)));
        BOOST_REQUIRE(RawWalletDB(file).Exists(std::string("legacytaccountpub")));
    }
    {
        CWallet w(Params(), file);
        bool fFirstRun;
        BOOST_REQUIRE_EQUAL(w.LoadWallet(fFirstRun), DB_LOAD_OK);
        LOCK(w.cs_wallet);
        // the old record is erased from the logical database at load, never read (the file is not rewritten, so its
        // bytes may stay in a free page: nothing here checks raw bytes)
        BOOST_CHECK(!w.fObsoleteLegacyTAccountPub);
        BOOST_CHECK(!RawWalletDB(file).Exists(std::string("legacytaccountpub")));
        // the tampered record is loaded, then checked against the seed and rewritten at the first unlocked top-up
        BOOST_REQUIRE(w.legacyTLookahead.has_value());
        BOOST_CHECK(CKeyID(w.legacyTLookahead.value().vIds[1][3]) == SeedKey(true, 900));
        w.TopUpLegacyTKeys();
        BOOST_CHECK(w.legacyTLookahead.value() == stored);
        CLegacyTLookahead reread;
        BOOST_REQUIRE(RawWalletDB(file).Read(std::string("legacytlookahead"), reread));
        BOOST_CHECK(reread == stored);
        BOOST_CHECK(w.GenerateNewKey(true).GetID() == SeedKey(true, 1));   // the seed's key, whatever the record said
    }
    {
        // a wallet that cannot derive (no seed: as a locked one) watches the stored IDs: a payment to one is a
        // watch-only coin, never a key; one that leaves fewer than -keypool + 1 watched IDs beyond it sets the flag
        CWallet w(Params(), "legacy_tkey_key_ids_watch_test.dat");
        bool fFirstRun;
        BOOST_REQUIRE_EQUAL(w.LoadWallet(fFirstRun), DB_LOAD_OK);
        LOCK(w.cs_wallet);
        CHDChain chain(LookaheadTestSeed().Fingerprint(), 1);
        for (uint32_t i = 0; i < stored.nStart[0]; i++)
            chain.IncrementLegacyTKeyCounter(false);
        for (uint32_t i = 0; i < stored.nStart[1]; i++)
            chain.IncrementLegacyTKeyCounter(true);
        w.SetMnemonicHDChain(chain, true);
        w.LoadLegacyTLookahead(stored);
        w.TopUpLegacyTKeys();
        BOOST_CHECK_EQUAL(w.mapLegacyTKeyWatched.size(), 2U * N);
        BOOST_CHECK_EQUAL(w.nLegacyTKeyWatchedEnd[1], 1U + N);
        const CTxOut paid(1000, GetScriptForDestination(SeedKey(true, 5)));
        BOOST_CHECK(w.IsMine(paid) == ISMINE_WATCH_UNSOLVABLE);
        BOOST_CHECK(!w.HaveKey(SeedKey(true, 5)));
        BOOST_CHECK(w.IsMine(CTxOut(1000, GetScriptForDestination(SeedKey(true, 1 + N)))) == ISMINE_NO);   // past the window
        BOOST_CHECK(::IsMine(w, paid.scriptPubKey) == ISMINE_NO);   // validateaddress and the key store: not a key
        BOOST_CHECK(!w.fLegacyTKeyLookaheadIncomplete);
        w.NoteLegacyTKeysUsed(Paying(GetScriptForDestination(SeedKey(true, 5))));      // in the mempool: nothing
        BOOST_CHECK(!w.fLegacyTKeyLookaheadIncomplete);
        w.NoteLegacyTKeysUsed(Paying(GetScriptForDestination(SeedKey(true, 5))), 9);   // mined at 9: 5 + 1 + N > 1 + N
        BOOST_CHECK(w.fLegacyTKeyLookaheadIncomplete);
        BOOST_CHECK_EQUAL(w.nLegacyTKeyIncompleteFrom, 9);
        BOOST_CHECK_EQUAL(Counter(w, true), 1U);   // locked, the counter stays (the key is not held)
    }
    bitdb.Flush(true);
    bitdb.Reset();
}

BOOST_AUTO_TEST_SUITE_END()
