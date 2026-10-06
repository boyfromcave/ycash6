// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The wallet layer's own files and its completion thread (v3 plan W7, S16, audit C-5), driven
// without a node: <datadir>/yellowback/carriers.dat (record, update, spend, reload, a damaged or
// unwritable file), <datadir>/yellowback/attest-signed.dat (append and reload, the v1 layout and
// its rewrite to v2, a torn tail, a foreign file the guard refuses to append to, a failed v1
// rewrite), the completion thread (a completion that asks to be retried, completions that
// throw) and the H5 lock layer (release, `lockunspent true` then re-apply). The functional
// scripts cover the happy paths through a running node; these are the failure paths and the
// calls a running node seldom reaches.

#include "yellowback/index.h"
#include "yellowback/params.h"
#include "yellowback/wallet.h"

#include "key.h"
#include "test/test_bitcoin.h"
#include "wallet/db.h"
#include "wallet/wallet.h"

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <fstream>
#include <memory>
#include <thread>

/** The YED attestor set the regtest parameters of these cases name (U-22). */
static inline uint256 TestSet() { return uint256S("5e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e7"); }

using namespace yellowback;

namespace {

/** WalletTestingSetup's wallet on regtest, plus a fresh (empty, healthy) Yellowback index. */
struct YbWalletSetup : public TestingSetup
{
    CWallet* wallet;
    std::unique_ptr<YellowbackIndex> index;

    YbWalletSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        bitdb.MakeMock();
        bool fFirstRun;
        wallet = new CWallet(::Params(), "yb_wallet_test.dat");
        wallet->LoadWallet(fFirstRun);
        index.reset(new YellowbackIndex(RegtestParams(1, 0, 0, TestSet()), pathTemp / "yb-wallet-index", 1 << 20, true));
    }
    ~YbWalletSetup()
    {
        index.reset();
        delete wallet;
        bitdb.Flush(true);
        bitdb.Reset();
    }
};

std::vector<unsigned char> ReadBytes(const fs::path& p)
{
    std::ifstream f(p.string(), std::ios::binary);
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

void WriteBytes(const fs::path& p, const std::vector<unsigned char>& data, bool append = false)
{
    fs::create_directories(p.parent_path());
    std::ofstream f(p.string(), std::ios::binary | (append ? std::ios::app : std::ios::trunc));
    f.write((const char*)data.data(), data.size());
}

COutPoint Out(unsigned char tag, uint32_t n)
{
    return COutPoint(uint256(std::vector<unsigned char>(32, tag)), n);
}

/** A carrier whose window lapses after refHeight + REF_WINDOW (refHeight well above the regtest tip, so the startup sweep never acts on it). */
CarrierRecord Carrier(unsigned char tag, int32_t refHeight, int32_t createdHeight)
{
    CarrierRecord c;
    c.outpoint = Out(tag, 2);
    c.refHeight = refHeight;
    c.selector.assign(36, tag);
    c.bundle.assign(70, (unsigned char)(tag + 1));
    c.pk = CKey::TestOnlyRandomKey(true).GetPubKey();
    c.createdHeight = createdHeight;
    return c;
}

SignedAttestation Signed(uint16_t seq, uint32_t citedHeight, uint32_t price, unsigned char hashTag)
{
    SignedAttestation r;
    r.seq = seq;
    r.citedHeight = citedHeight;
    r.priceMicroUsd = price;
    r.sig.fill((unsigned char)(seq + price));
    r.blockHash = hashTag ? uint256(std::vector<unsigned char>(32, hashTag)) : uint256();
    return r;
}

/** One line of the v1 file: seq, citedHeight, price, sig (no block hash). */
std::vector<unsigned char> V1Line(const SignedAttestation& r)
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << r.seq << r.citedHeight << r.priceMicroUsd << FLATDATA(r.sig);
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

const std::vector<unsigned char> MAGIC_V1 = { 'Y', 'B', 'S', 1 };
const std::vector<unsigned char> MAGIC_V2 = { 'Y', 'B', 'S', 2 };

bool StartsWith(const std::vector<unsigned char>& data, const std::vector<unsigned char>& prefix)
{
    return data.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), data.begin());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(yellowback_wallet_tests, YbWalletSetup)

// W7: carriers.dat is rewritten on every change and read back at Attach.
BOOST_AUTO_TEST_CASE(carriers_file_record_update_spend_reload)
{
    const fs::path file = YellowbackWallet::CarriersFile();
    BOOST_CHECK(!fs::exists(file));
    const CarrierRecord c1 = Carrier(0x11, 1000, 5);
    const CarrierRecord c2 = Carrier(0x22, 2000, 6);
    {
        YellowbackWallet yw(wallet, index.get());
        yw.Attach();   // no file yet: nothing outstanding
        BOOST_CHECK(yw.OutstandingCarriers().empty());

        yw.RecordCarrier(c1);
        yw.RecordCarrier(c2);
        BOOST_CHECK(fs::exists(file));
        BOOST_CHECK_EQUAL(yw.OutstandingCarriers().size(), 2U);

        // Recording the same outpoint again replaces the record in place (no duplicate).
        CarrierRecord c1b = c1;
        c1b.createdHeight = 9;
        c1b.bundle.assign(70, 0x99);
        yw.RecordCarrier(c1b);
        std::vector<CarrierRecord> out = yw.OutstandingCarriers();
        BOOST_REQUIRE_EQUAL(out.size(), 2U);
        BOOST_CHECK(out[0].outpoint == c1.outpoint);     // oldest first: the update kept its slot
        BOOST_CHECK_EQUAL(out[0].createdHeight, 9);
        BOOST_CHECK(yw.GetCarrier(c1.outpoint)->bundle == c1b.bundle);
        BOOST_CHECK(!yw.GetCarrier(Out(0x33, 2)).has_value());

        // The window: lapsed only once tip > refHeight + REF_WINDOW.
        BOOST_CHECK(yw.LapsedCarriers(1000 + REF_WINDOW).empty());
        std::vector<CarrierRecord> lapsed = yw.LapsedCarriers(1000 + REF_WINDOW + 1);
        BOOST_REQUIRE_EQUAL(lapsed.size(), 1U);
        BOOST_CHECK(lapsed[0].outpoint == c1.outpoint);
        BOOST_CHECK_EQUAL(yw.LapsedCarriers(2000 + REF_WINDOW + 1).size(), 2U);

        // Spending an unknown outpoint leaves the file alone; spending a known one rewrites it.
        const std::vector<unsigned char> before = ReadBytes(file);
        yw.SpendCarrier(Out(0x33, 2));
        BOOST_CHECK(ReadBytes(file) == before);
        BOOST_CHECK_EQUAL(yw.OutstandingCarriers().size(), 2U);
        yw.SpendCarrier(c2.outpoint);
        BOOST_CHECK_EQUAL(yw.OutstandingCarriers().size(), 1U);
        BOOST_CHECK(ReadBytes(file) != before);
    }
    // A restart reads back exactly what was outstanding, every field intact.
    YellowbackWallet yw2(wallet, index.get());
    yw2.Attach();
    std::vector<CarrierRecord> back = yw2.OutstandingCarriers();
    BOOST_REQUIRE_EQUAL(back.size(), 1U);
    BOOST_CHECK(back[0].outpoint == c1.outpoint);
    BOOST_CHECK_EQUAL(back[0].refHeight, 1000);
    BOOST_CHECK_EQUAL(back[0].createdHeight, 9);
    BOOST_CHECK(back[0].selector == c1.selector);
    BOOST_CHECK(back[0].bundle == std::vector<unsigned char>(70, 0x99));
    BOOST_CHECK(back[0].pk == c1.pk);
}

// W7: a carriers.dat that cannot be read is forgotten (logged), never fatal.
BOOST_AUTO_TEST_CASE(carriers_file_damaged)
{
    const fs::path file = YellowbackWallet::CarriersFile();
    {
        YellowbackWallet yw(wallet, index.get());
        yw.Attach();
        yw.RecordCarrier(Carrier(0x11, 1000, 5));
        yw.RecordCarrier(Carrier(0x22, 1000, 5));
    }
    const std::vector<unsigned char> good = ReadBytes(file);
    BOOST_REQUIRE(good.size() > 8);

    // A foreign magic: nothing is loaded.
    std::vector<unsigned char> foreign = good;
    foreign[2] = 'X';
    WriteBytes(file, foreign);
    {
        YellowbackWallet yw(wallet, index.get());
        BOOST_CHECK_NO_THROW(yw.Attach());
        BOOST_CHECK(yw.OutstandingCarriers().empty());
    }

    // A truncated record vector: nothing is loaded (no half record).
    WriteBytes(file, std::vector<unsigned char>(good.begin(), good.end() - 10));
    {
        YellowbackWallet yw(wallet, index.get());
        BOOST_CHECK_NO_THROW(yw.Attach());
        BOOST_CHECK(yw.OutstandingCarriers().empty());
    }

    // Shorter than the magic itself.
    WriteBytes(file, std::vector<unsigned char>(good.begin(), good.begin() + 2));
    {
        YellowbackWallet yw(wallet, index.get());
        BOOST_CHECK_NO_THROW(yw.Attach());
        BOOST_CHECK(yw.OutstandingCarriers().empty());
    }

    // The good file still loads.
    WriteBytes(file, good);
    YellowbackWallet yw(wallet, index.get());
    yw.Attach();
    BOOST_CHECK_EQUAL(yw.OutstandingCarriers().size(), 2U);
}

// W7: when carriers.dat cannot be written the carrier stays in memory (the sweep can still find it
// in this run) and the previous file is left whole -- the temporary is never renamed over it.
BOOST_AUTO_TEST_CASE(carriers_file_unwritable)
{
    const fs::path file = YellowbackWallet::CarriersFile();
    YellowbackWallet yw(wallet, index.get());
    yw.Attach();
    const CarrierRecord c1 = Carrier(0x11, 1000, 5);
    yw.RecordCarrier(c1);
    const std::vector<unsigned char> saved = ReadBytes(file);

    // The temporary's name is taken by a directory: fopen fails.
    fs::create_directories(file.string() + ".tmp");
    const CarrierRecord c2 = Carrier(0x22, 1000, 5);
    yw.RecordCarrier(c2);
    BOOST_CHECK_EQUAL(yw.OutstandingCarriers().size(), 2U);
    BOOST_CHECK(yw.GetCarrier(c2.outpoint).has_value());
    BOOST_CHECK(ReadBytes(file) == saved);

    // The same for an update and a spend: memory moves, the file does not.
    CarrierRecord c1b = c1;
    c1b.createdHeight = 77;
    yw.RecordCarrier(c1b);
    BOOST_CHECK_EQUAL(yw.GetCarrier(c1.outpoint)->createdHeight, 77);
    yw.SpendCarrier(c1.outpoint);
    BOOST_CHECK(!yw.GetCarrier(c1.outpoint).has_value());
    BOOST_CHECK(ReadBytes(file) == saved);

    // Once the path is free again the next change writes everything outstanding.
    fs::remove_all(file.string() + ".tmp");
    yw.RecordCarrier(Carrier(0x33, 1000, 5));
    YellowbackWallet yw2(wallet, index.get());
    yw2.Attach();
    BOOST_CHECK_EQUAL(yw2.OutstandingCarriers().size(), 2U);
    BOOST_CHECK(yw2.GetCarrier(c2.outpoint).has_value());
    BOOST_CHECK(!yw2.GetCarrier(c1.outpoint).has_value());
}

// S16, audit C-5: the signing guard is keyed by (seq, citedHeight, blockHash), appended and reloaded.
BOOST_AUTO_TEST_CASE(signed_guard_append_reload_torn_tail)
{
    const fs::path file = YellowbackWallet::SignedFile();
    const SignedAttestation r1 = Signed(3, 100, 50000, 0xa1);
    const SignedAttestation r2 = Signed(3, 101, 50001, 0xa2);
    {
        YellowbackWallet yw(wallet, index.get());
        yw.Attach();
        BOOST_CHECK(!yw.LookupSigned(3, 100, r1.blockHash).has_value());
        BOOST_CHECK(yw.RecordSigned(r1));
        BOOST_CHECK(StartsWith(ReadBytes(file), MAGIC_V2));
        BOOST_CHECK(yw.RecordSigned(r2));
        BOOST_CHECK_EQUAL(yw.LookupSigned(3, 100, r1.blockHash)->priceMicroUsd, 50000U);
        // Another block at the same height (after a reorg) is not covered by the line (C-5).
        BOOST_CHECK(!yw.LookupSigned(3, 100, r2.blockHash).has_value());
        BOOST_CHECK(!yw.LookupSigned(4, 100, r1.blockHash).has_value());
    }
    {
        YellowbackWallet yw(wallet, index.get());
        yw.Attach();
        std::optional<SignedAttestation> got = yw.LookupSigned(3, 101, r2.blockHash);
        BOOST_REQUIRE(got.has_value());
        BOOST_CHECK_EQUAL(got->priceMicroUsd, 50001U);
        BOOST_CHECK(got->sig == r2.sig);
    }
    // A torn tail (a crash mid-append) keeps every line read before it.
    WriteBytes(file, std::vector<unsigned char>(7, 0xee), true);
    YellowbackWallet yw(wallet, index.get());
    BOOST_CHECK_NO_THROW(yw.Attach());
    BOOST_CHECK(yw.LookupSigned(3, 100, r1.blockHash).has_value());
    BOOST_CHECK(yw.LookupSigned(3, 101, r2.blockHash).has_value());
}

// S16, audit C-5: a v1 file (no block hash) is honoured for every hash and rewritten as v2, after
// which appends work and both layouts' lines survive a restart.
BOOST_AUTO_TEST_CASE(signed_guard_v1_file_rewritten)
{
    const fs::path file = YellowbackWallet::SignedFile();
    const SignedAttestation a = Signed(1, 200, 42000, 0);
    const SignedAttestation b = Signed(2, 200, 43000, 0);
    std::vector<unsigned char> v1 = MAGIC_V1;
    for (const SignedAttestation& r : {a, b}) {
        std::vector<unsigned char> line = V1Line(r);
        v1.insert(v1.end(), line.begin(), line.end());
    }
    WriteBytes(file, v1);

    const uint256 anyHash(std::vector<unsigned char>(32, 0x5c));
    {
        YellowbackWallet yw(wallet, index.get());
        yw.Attach();
        std::optional<SignedAttestation> got = yw.LookupSigned(1, 200, anyHash);   // the v1 line covers every hash
        BOOST_REQUIRE(got.has_value());
        BOOST_CHECK_EQUAL(got->priceMicroUsd, 42000U);
        BOOST_CHECK(got->blockHash.IsNull());
        BOOST_CHECK(got->sig == a.sig);
        BOOST_CHECK_EQUAL(yw.LookupSigned(2, 200, uint256())->priceMicroUsd, 43000U);
        BOOST_CHECK(!yw.LookupSigned(1, 201, anyHash).has_value());
        BOOST_CHECK(StartsWith(ReadBytes(file), MAGIC_V2));       // rewritten in the v2 layout
        BOOST_CHECK(!fs::exists(file.string() + ".v2"));
        BOOST_CHECK(yw.RecordSigned(Signed(1, 201, 44000, 0xb1)));  // and appendable
    }
    YellowbackWallet yw(wallet, index.get());
    yw.Attach();
    BOOST_CHECK_EQUAL(yw.LookupSigned(1, 200, anyHash)->priceMicroUsd, 42000U);
    BOOST_CHECK_EQUAL(yw.LookupSigned(2, 200, anyHash)->priceMicroUsd, 43000U);
    BOOST_CHECK_EQUAL(yw.LookupSigned(1, 201, uint256(std::vector<unsigned char>(32, 0xb1)))->priceMicroUsd, 44000U);
}

// S16: when the v1 rewrite fails the v1 file stays, its lines still guard, and RecordSigned refuses
// to append a v2 line to it (the caller then returns no signature).
BOOST_AUTO_TEST_CASE(signed_guard_v1_rewrite_fails)
{
    const fs::path file = YellowbackWallet::SignedFile();
    const SignedAttestation a = Signed(1, 300, 42000, 0);
    std::vector<unsigned char> v1 = MAGIC_V1;
    std::vector<unsigned char> line = V1Line(a);
    v1.insert(v1.end(), line.begin(), line.end());
    WriteBytes(file, v1);
    fs::create_directories(file.string() + ".v2");   // the rewrite's temporary cannot be opened

    YellowbackWallet yw(wallet, index.get());
    yw.Attach();
    BOOST_CHECK(ReadBytes(file) == v1);
    BOOST_CHECK(yw.LookupSigned(1, 300, uint256(std::vector<unsigned char>(32, 0x01))).has_value());
    const SignedAttestation fresh = Signed(1, 301, 45000, 0xc1);
    BOOST_CHECK(!yw.RecordSigned(fresh));
    BOOST_CHECK(ReadBytes(file) == v1);
    BOOST_CHECK(!yw.LookupSigned(1, 301, fresh.blockHash).has_value());   // a refused line is not remembered
}

// S16: a file that is not a signing guard is never appended to.
BOOST_AUTO_TEST_CASE(signed_guard_foreign_file)
{
    const fs::path file = YellowbackWallet::SignedFile();
    const SignedAttestation r = Signed(5, 400, 46000, 0xd1);

    const std::vector<unsigned char> foreign = { 'N', 'O', 'P', 'E', 1, 2, 3, 4, 5, 6 };
    WriteBytes(file, foreign);
    {
        YellowbackWallet yw(wallet, index.get());
        BOOST_CHECK_NO_THROW(yw.Attach());
        BOOST_CHECK(!yw.LookupSigned(5, 400, r.blockHash).has_value());
        BOOST_CHECK(!yw.RecordSigned(r));
        BOOST_CHECK(ReadBytes(file) == foreign);
        BOOST_CHECK(!yw.LookupSigned(5, 400, r.blockHash).has_value());
    }

    const std::vector<unsigned char> stub = { 'Y', 'B' };   // shorter than the magic
    WriteBytes(file, stub);
    YellowbackWallet yw(wallet, index.get());
    BOOST_CHECK_NO_THROW(yw.Attach());
    BOOST_CHECK(!yw.RecordSigned(r));
    BOOST_CHECK(ReadBytes(file) == stub);
}

// W7 wait=false: the completion thread retries a completion until it reports done, and gives up on
// one that throws (std::exception or anything else) instead of retrying it forever or dying.
BOOST_AUTO_TEST_CASE(completion_thread_retries_and_survives_throws)
{
    std::atomic<int> retryCalls(0), stdThrowCalls(0), otherThrowCalls(0), doneCalls(0);
    YellowbackWallet yw(wallet, index.get());
    yw.AddPendingCompletion(Out(0x01, 0), [&]() { return ++retryCalls >= 2; });
    yw.AddPendingCompletion(Out(0x02, 0), [&]() -> bool { ++stdThrowCalls; throw std::runtime_error("injected"); });
    yw.AddPendingCompletion(Out(0x03, 0), [&]() -> bool { ++otherThrowCalls; throw 7; });
    yw.AddPendingCompletion(Out(0x04, 0), [&]() { ++doneCalls; return true; });
    // A second completion for the same carrier replaces the first.
    yw.AddPendingCompletion(Out(0x04, 0), [&]() { doneCalls += 10; return true; });
    BOOST_CHECK_EQUAL(yw.PendingCompletions(), 4U);

    yw.Attach();
    // Wake the thread as an applied block does (it would also wake on its own each second).
    BOOST_REQUIRE(index->onReconcile);
    index->onReconcile();
    for (int i = 0; i < 200 && yw.PendingCompletions() != 0; i++) std::this_thread::sleep_for(std::chrono::milliseconds(50));
    BOOST_CHECK_EQUAL(yw.PendingCompletions(), 0U);
    BOOST_CHECK_EQUAL(retryCalls.load(), 2);
    BOOST_CHECK_EQUAL(stdThrowCalls.load(), 1);
    BOOST_CHECK_EQUAL(otherThrowCalls.load(), 1);
    BOOST_CHECK_EQUAL(doneCalls.load(), 10);
    yw.StopThread();
    yw.StopThread();   // idempotent
}

// H5: the overlay's locks survive `lockunspent true` (UnlockAllCoins, then ReapplyLocks), and
// ReleaseLock (yed_unlockcoin) gives one outpoint back for good.
BOOST_AUTO_TEST_CASE(locks_release_and_reapply)
{
    YellowbackWallet yw(wallet, index.get());
    const COutPoint o1 = Out(0x41, 1), o2 = Out(0x42, 3);
    auto walletLocked = [&](const COutPoint& o) { LOCK(wallet->cs_wallet); return wallet->IsLockedCoin(o.hash, o.n); };

    yw.LockOwn({o1, o2});
    BOOST_CHECK_EQUAL(yw.LockedCount(), 2U);
    BOOST_CHECK(yw.IsYellowbackLocked(o1) && yw.IsYellowbackLocked(o2));
    BOOST_CHECK(walletLocked(o1) && walletLocked(o2));
    BOOST_CHECK(!yw.IsYellowbackLocked(Out(0x43, 0)));

    BOOST_CHECK(yw.ReleaseLock(o1));
    BOOST_CHECK(!yw.IsYellowbackLocked(o1));
    BOOST_CHECK(!walletLocked(o1));
    BOOST_CHECK(!yw.ReleaseLock(o1));    // not held any more

    {
        LOCK(wallet->cs_wallet);
        wallet->UnlockAllCoins();         // what `lockunspent true` does first
    }
    BOOST_CHECK(!walletLocked(o2));
    BOOST_CHECK(yw.IsYellowbackLocked(o2));   // the overlay still knows it
    yw.ReapplyLocks();
    BOOST_CHECK(walletLocked(o2));
    BOOST_CHECK(!walletLocked(o1));           // a released outpoint is not re-locked
    yw.ReapplyLocks();                        // idempotent
    BOOST_CHECK(walletLocked(o2));
    BOOST_CHECK(yw.Locked() == std::set<COutPoint>({o2}));
}

BOOST_AUTO_TEST_SUITE_END()
