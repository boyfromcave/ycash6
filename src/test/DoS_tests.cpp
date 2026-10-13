// Copyright (c) 2011-2014 The Bitcoin Core developers
// Copyright (c) 2018-2023 The Zcash developers
// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//
// Unit tests for denial-of-service detection/prevention code
//



#include "consensus/upgrades.h"
#include "keystore.h"
#include "main.h"
#include "net.h"
#include "pow.h"
#include "script/sign.h"
#include "serialize.h"
#include "util/system.h"

#include "test/test_bitcoin.h"

#include <stdint.h>

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

// Tests this internal-to-main.cpp method:
extern bool AddOrphanTx(const CTransaction& tx, NodeId peer);
extern void EraseOrphansFor(NodeId peer);
extern unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans);
struct COrphanTx {
    CTransaction tx;
    NodeId fromPeer;
};
extern std::map<uint256, COrphanTx> mapOrphanTransactions;
extern std::map<uint256, std::set<uint256> > mapOrphanTransactionsByPrev;

CService ip(uint32_t i)
{
    struct in_addr s;
    s.s_addr = i;
    return CService(CNetAddr(s), Params().GetDefaultPort());
}

BOOST_FIXTURE_TEST_SUITE(DoS_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(DoS_banning)
{
    const Consensus::Params& params = Params().GetConsensus();
    CNode::ClearBanned();
    CAddress addr1(ip(0xa0b0c001));
    CNode dummyNode1(INVALID_SOCKET, addr1, "", true);
    dummyNode1.nVersion = 1;
    Misbehaving(dummyNode1.GetId(), 100); // Should get banned
    SendMessages(params, &dummyNode1);
    BOOST_CHECK(CNode::IsBanned(addr1));
    BOOST_CHECK(!CNode::IsBanned(ip(0xa0b0c001|0x0000ff00))); // Different IP, not banned

    CAddress addr2(ip(0xa0b0c002));
    CNode dummyNode2(INVALID_SOCKET, addr2, "", true);
    dummyNode2.nVersion = 1;
    Misbehaving(dummyNode2.GetId(), 50);
    SendMessages(params, &dummyNode2);
    BOOST_CHECK(!CNode::IsBanned(addr2)); // 2 not banned yet...
    BOOST_CHECK(CNode::IsBanned(addr1));  // ... but 1 still should be
    Misbehaving(dummyNode2.GetId(), 50);
    SendMessages(params, &dummyNode2);
    BOOST_CHECK(CNode::IsBanned(addr2));
}

BOOST_AUTO_TEST_CASE(DoS_banscore)
{
    const Consensus::Params& params = Params().GetConsensus();
    CNode::ClearBanned();
    mapArgs["-banscore"] = "111"; // because 11 is my favorite number
    CAddress addr1(ip(0xa0b0c001));
    CNode dummyNode1(INVALID_SOCKET, addr1, "", true);
    dummyNode1.nVersion = 1;
    Misbehaving(dummyNode1.GetId(), 100);
    SendMessages(params, &dummyNode1);
    BOOST_CHECK(!CNode::IsBanned(addr1));
    Misbehaving(dummyNode1.GetId(), 10);
    SendMessages(params, &dummyNode1);
    BOOST_CHECK(!CNode::IsBanned(addr1));
    Misbehaving(dummyNode1.GetId(), 1);
    SendMessages(params, &dummyNode1);
    BOOST_CHECK(CNode::IsBanned(addr1));
    mapArgs.erase("-banscore");
}

BOOST_AUTO_TEST_CASE(DoS_bantime)
{
    FixedClock::SetGlobal();

    const Consensus::Params& params = Params().GetConsensus();
    CNode::ClearBanned();
    std::chrono::seconds nStartTime(GetTime());
    FixedClock::Instance()->Set(nStartTime); // Overrides future calls to GetTime()

    CAddress addr(ip(0xa0b0c001));
    CNode dummyNode(INVALID_SOCKET, addr, "", true);
    dummyNode.nVersion = 1;

    Misbehaving(dummyNode.GetId(), 100);
    SendMessages(params, &dummyNode);
    BOOST_CHECK(CNode::IsBanned(addr));

    FixedClock::Instance()->Set(nStartTime + std::chrono::seconds(60*60));
    BOOST_CHECK(CNode::IsBanned(addr));

    FixedClock::Instance()->Set(nStartTime + std::chrono::seconds(60*60*24+1));
    BOOST_CHECK(!CNode::IsBanned(addr));

    SystemClock::SetGlobal();
}

CTransaction RandomOrphan()
{
    std::map<uint256, COrphanTx>::iterator it;
    it = mapOrphanTransactions.lower_bound(InsecureRand256());
    if (it == mapOrphanTransactions.end())
        it = mapOrphanTransactions.begin();
    return it->second.tx;
}

// An orphan of exactly `size` serialized bytes: one input whose scriptSig is a single push (the shape of a
// post-quantum spend; signature validity is irrelevant to orphan parking) spending a missing parent.
static CTransaction SizedOrphan(unsigned int size)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(GetRandHash(), 0);
    tx.vout.resize(1);
    tx.vout[0].nValue = 1*CENT;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    // the push and the script length grow their own length prefixes past 255 / 65,535 bytes: converge
    size_t push = 1000;
    for (int i = 0; i < 4; i++) {
        tx.vin[0].scriptSig = CScript() << std::vector<unsigned char>(push, 0x42);
        push += (int64_t)size - (int64_t)GetSerializeSize(CTransaction(tx), SER_NETWORK, tx.nVersion);
    }
    tx.vin[0].scriptSig = CScript() << std::vector<unsigned char>(push, 0x42);
    CTransaction out(tx);
    assert(GetSerializeSize(out, SER_NETWORK, out.nVersion) == size);
    return out;
}

// Parameterized testing over consensus branch ids
BOOST_DATA_TEST_CASE(DoS_mapOrphans, boost::unit_test::data::xrange(static_cast<int>(Consensus::MAX_NETWORK_UPGRADES)))
{
    uint32_t consensusBranchId = NetworkUpgradeInfo[sample].nBranchId;

    CKey key = CKey::TestOnlyRandomKey(true);
    CBasicKeyStore keystore;
    keystore.AddKey(key);

    // 50 orphan transactions:
    for (int i = 0; i < 50; i++)
    {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].prevout.hash = InsecureRand256();
        tx.vin[0].scriptSig << OP_1;
        tx.vout.resize(1);
        tx.vout[0].nValue = 1*CENT;
        tx.vout[0].scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());

        AddOrphanTx(tx, i);
    }

    // ... and 50 that depend on other orphans:
    for (int i = 0; i < 50; i++)
    {
        CTransaction txPrev = RandomOrphan();

        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].prevout.hash = txPrev.GetHash();
        tx.vout.resize(1);
        tx.vout[0].nValue = 1*CENT;
        tx.vout[0].scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());
        const PrecomputedTransactionData txdata(tx, {txPrev.vout[0]});
        SignSignature(keystore, txPrev, tx, txdata, 0, SIGHASH_ALL, consensusBranchId);

        AddOrphanTx(tx, i);
    }

    // This really-big orphan should be ignored:
    for (int i = 0; i < 10; i++)
    {
        CTransaction txPrev = RandomOrphan();

        CMutableTransaction tx;
        tx.vout.resize(1);
        tx.vout[0].nValue = 1*CENT;
        tx.vout[0].scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());
        tx.vin.resize(2777);
        for (unsigned int j = 0; j < tx.vin.size(); j++)
        {
            tx.vin[j].prevout.n = j;
            tx.vin[j].prevout.hash = txPrev.GetHash();
        }
        // Fake the coins being spent (the random orphan doesn't actually have them all).
        std::vector<CTxOut> allPrevOutputs;
        allPrevOutputs.resize(tx.vin.size(), txPrev.vout[0]);
        const PrecomputedTransactionData txdata(tx, allPrevOutputs);
        SignSignature(keystore, txPrev, tx, txdata, 0, SIGHASH_ALL, consensusBranchId);
        // Re-use same signature for other inputs
        // (they don't have to be valid for this test)
        for (unsigned int j = 1; j < tx.vin.size(); j++)
            tx.vin[j].scriptSig = tx.vin[0].scriptSig;

        BOOST_CHECK(!AddOrphanTx(tx, i));
    }

    // Test EraseOrphansFor:
    for (NodeId i = 0; i < 3; i++)
    {
        size_t sizeBefore = mapOrphanTransactions.size();
        EraseOrphansFor(i);
        BOOST_CHECK(mapOrphanTransactions.size() < sizeBefore);
    }

    // Test LimitOrphanTxSize() function:
    LimitOrphanTxSize(40);
    BOOST_CHECK(mapOrphanTransactions.size() <= 40);
    LimitOrphanTxSize(10);
    BOOST_CHECK(mapOrphanTransactions.size() <= 10);
    LimitOrphanTxSize(0);
    BOOST_CHECK(mapOrphanTransactions.empty());
    BOOST_CHECK(mapOrphanTransactionsByPrev.empty());
}

// Audit 07/F-6 (ycash-dd's 5,000-byte bound): 6.20.0 already keeps orphans below 100,000 bytes, so an
// SLH-DSA-sized orphan (a 7,938-byte scriptSig, ~8 KB) is parked before and after UPGRADE_VAULT alike.
BOOST_AUTO_TEST_CASE(DoS_pq_sized_orphans)
{
    SelectParams(CBaseChainParams::REGTEST);
    LOCK(cs_main);
    LimitOrphanTxSize(0);
    CMutableTransaction slh;
    slh.vin.resize(1);
    slh.vin[0].prevout = COutPoint(GetRandHash(), 0);
    slh.vin[0].scriptSig = CScript() << std::vector<unsigned char>(7935, 0x42);   // PUSHDATA2 + 7,935 = 7,938 bytes
    BOOST_CHECK_EQUAL(slh.vin[0].scriptSig.size(), 7938U);
    slh.vout.resize(1);
    slh.vout[0].nValue = 1*CENT;
    slh.vout[0].scriptPubKey = CScript() << OP_TRUE;
    const CTransaction slhTx(slh);

    for (int activation : {(int)Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT, chainActive.Height() + 1}) {
        UpdateNetworkUpgradeParameters(Consensus::UPGRADE_VAULT, activation);
        BOOST_CHECK(AddOrphanTx(slhTx, 1));
        BOOST_CHECK(AddOrphanTx(SizedOrphan(99999), 1));
        BOOST_CHECK(!AddOrphanTx(SizedOrphan(100000), 1));
        BOOST_CHECK_EQUAL(mapOrphanTransactions.size(), 2U);
        LimitOrphanTxSize(DEFAULT_MAX_ORPHAN_TRANSACTIONS);
        BOOST_CHECK(mapOrphanTransactions.count(slhTx.GetHash()));
        LimitOrphanTxSize(0);
    }
    BOOST_CHECK(mapOrphanTransactionsByPrev.empty());
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_VAULT, Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);
    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_SUITE_END()
