// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The re-forked testnet's chain parameters (docs/plans/yellowback-testnet-plan.md §2.1, N1): Zcash
// testnet through block 510,247, then a new Ycash fork at 510,248. Byte-identical on both node lines
// (qa/yellowback-cross-line.manifest): CTestNetParams is changed identically on ycash6 and ycash-dd.

#include "arith_uint256.h"
#include "chainparams.h"
#include "chainparamsbase.h"
#include "consensus/upgrades.h"
#include "script/script.h"
#include "test/test_bitcoin.h"
#include "uint256.h"
#include "vault/state.h"
#include "yellowback/index.h"
#include "yellowback/params.h"

#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_FIXTURE_TEST_SUITE(testnet_params_tests, BasicTestingSetup)

static const int FORK = 510248;     // UPGRADE_YCASH, unchanged
static const int BLOSSOM = 510250;
static const int HEARTWOOD = 510252;
static const int CANOPY = 510254;
static const int VAULT = 510400;    // H_V, the ceremony's placeholder

BOOST_AUTO_TEST_CASE(testnet_network_identity)
{
    const CChainParams& test = Params(CBaseChainParams::TESTNET);
    // T-2: a magic of its own, distinct from Ycash/Zcash mainnet, the old testnet and regtest.
    const std::vector<unsigned char> magic(test.MessageStart(), test.MessageStart() + 4);
    BOOST_CHECK(magic == std::vector<unsigned char>({0xf7, 0x79, 0x62, 0xd3}));
    for (const std::string& other : {CBaseChainParams::MAIN, CBaseChainParams::REGTEST}) {
        const CChainParams& o = Params(other);
        BOOST_CHECK(std::vector<unsigned char>(o.MessageStart(), o.MessageStart() + 4) != magic);
    }
    BOOST_CHECK(magic != std::vector<unsigned char>({0xfa, 0x1a, 0xf9, 0xbf}));   // the old Ycash testnet
    BOOST_CHECK_EQUAL(test.GetDefaultPort(), 18833);

    // T-2: the datadir is testnet-yb (a leftover testnet3 holds the old branch); the RPC port is unchanged.
    SelectBaseParams(CBaseChainParams::TESTNET);
    BOOST_CHECK_EQUAL(BaseParams().DataDir(), "testnet-yb");
    BOOST_CHECK_EQUAL(BaseParams().RPCPort(), 18832);
    SelectBaseParams(CBaseChainParams::MAIN);

    // D1: fixed seeds only (pnSeed6_test, supplied with rc1), no DNS seed.
    BOOST_CHECK(test.DNSSeeds().empty());
}

BOOST_AUTO_TEST_CASE(testnet_checkpoints)
{
    const CCheckpointData& cp = Params(CBaseChainParams::TESTNET).Checkpoints();
    BOOST_CHECK_EQUAL(cp.mapCheckpoints.size(), 3U);
    BOOST_CHECK(cp.mapCheckpoints.count(0) == 1);
    BOOST_CHECK(cp.mapCheckpoints.at(38000) == uint256S("001e9a2d2e2892b88e9998cf7b079b41d59dd085423a921fe8386cecc42287b8"));
    // Zcash testnet's block 510,247 (testnet-prefix-v1 manifest), the last block before the re-fork.
    BOOST_CHECK(cp.mapCheckpoints.at(510247) == uint256S("0000ec904003d5591290064b0b4d3ccddffe87ef2a3a131284438959bf68fb31"));
    // The old Ycash branch's 650,000 is gone, and nothing above the fork is pinned until rc1.
    BOOST_CHECK(cp.mapCheckpoints.count(650000) == 0);
    BOOST_CHECK_EQUAL(cp.mapCheckpoints.rbegin()->first, 510247);
    BOOST_CHECK_EQUAL(cp.nTimeLastCheckpoint, 1559796960);
    BOOST_CHECK_EQUAL(cp.nTransactionsLastCheckpoint, 717489);
}

BOOST_AUTO_TEST_CASE(testnet_upgrade_schedule)
{
    const Consensus::Params& c = Params(CBaseChainParams::TESTNET).GetConsensus();
    const auto& u = c.vUpgrades;
    BOOST_CHECK_EQUAL(u[Consensus::UPGRADE_OVERWINTER].nActivationHeight, 207500);
    BOOST_CHECK_EQUAL(u[Consensus::UPGRADE_SAPLING].nActivationHeight, 280000);
    BOOST_CHECK_EQUAL(u[Consensus::UPGRADE_YCASH].nActivationHeight, FORK);
    BOOST_CHECK_EQUAL(u[Consensus::UPGRADE_BLOSSOM].nActivationHeight, BLOSSOM);
    BOOST_CHECK_EQUAL(u[Consensus::UPGRADE_HEARTWOOD].nActivationHeight, HEARTWOOD);
    BOOST_CHECK_EQUAL(u[Consensus::UPGRADE_CANOPY].nActivationHeight, CANOPY);
    BOOST_CHECK_EQUAL(u[Consensus::UPGRADE_VAULT].nActivationHeight, VAULT);
    BOOST_CHECK_EQUAL(u[Consensus::UPGRADE_NU5].nActivationHeight, Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);

    // The pre-fork activation hashes are Zcash testnet's; the fork block's is pinned by rc1, unset until then.
    BOOST_CHECK(u[Consensus::UPGRADE_OVERWINTER].hashActivationBlock.has_value());
    BOOST_CHECK(u[Consensus::UPGRADE_SAPLING].hashActivationBlock.has_value());
    BOOST_CHECK(!u[Consensus::UPGRADE_YCASH].hashActivationBlock.has_value());

    // Each epoch from the fork on has two blocks before the next; the branch id follows.
    BOOST_CHECK(FORK < BLOSSOM && BLOSSOM < HEARTWOOD && HEARTWOOD < CANOPY && CANOPY < VAULT);
    BOOST_CHECK_EQUAL(CurrentEpochBranchId(FORK - 1, c), NetworkUpgradeInfo[Consensus::UPGRADE_SAPLING].nBranchId);
    BOOST_CHECK_EQUAL(CurrentEpochBranchId(FORK + 1, c), NetworkUpgradeInfo[Consensus::UPGRADE_YCASH].nBranchId);
    BOOST_CHECK_EQUAL(CurrentEpochBranchId(BLOSSOM + 1, c), NetworkUpgradeInfo[Consensus::UPGRADE_BLOSSOM].nBranchId);
    BOOST_CHECK_EQUAL(CurrentEpochBranchId(HEARTWOOD + 1, c), NetworkUpgradeInfo[Consensus::UPGRADE_HEARTWOOD].nBranchId);
    BOOST_CHECK_EQUAL(CurrentEpochBranchId(VAULT - 1, c), NetworkUpgradeInfo[Consensus::UPGRADE_CANOPY].nBranchId);
    BOOST_CHECK_EQUAL(CurrentEpochBranchId(VAULT, c), NetworkUpgradeInfo[Consensus::UPGRADE_VAULT].nBranchId);

    // The future-timestamp rule follows Blossom by six blocks (MTP of post-Blossom blocks only).
    BOOST_CHECK_EQUAL(c.nFutureTimestampSoftForkHeight, BLOSSOM + 6);
}

BOOST_AUTO_TEST_CASE(testnet_subsidy_and_ydf)
{
    const CChainParams& test = Params(CBaseChainParams::TESTNET);
    const Consensus::Params& c = test.GetConsensus();
    // The subsidy, as the closed-form supply's step: 12.5 at the fork, halved by Blossom's spacing
    // from 510,250, and no halving before 1,189,750 = 1,680,000 - 2 * (510,250 - 10,000) + 510,250.
    BOOST_CHECK_EQUAL(yellowback::CirculatingSupplyAt(FORK, c) - yellowback::CirculatingSupplyAt(FORK - 1, c), 1250000000);
    BOOST_CHECK_EQUAL(yellowback::CirculatingSupplyAt(BLOSSOM - 1, c) - yellowback::CirculatingSupplyAt(BLOSSOM - 2, c), 1250000000);
    BOOST_CHECK_EQUAL(yellowback::CirculatingSupplyAt(BLOSSOM, c) - yellowback::CirculatingSupplyAt(BLOSSOM - 1, c), 625000000);
    BOOST_CHECK_EQUAL(yellowback::CirculatingSupplyAt(CANOPY, c) - yellowback::CirculatingSupplyAt(CANOPY - 1, c), 625000000);
    BOOST_CHECK_EQUAL(c.Halving(1189749), 0);
    BOOST_CHECK_EQUAL(c.Halving(1189750), 1);

    // The YDF (5 %, mandatory to 900,000) pays the first sm… address, P2PKH, from the fork through the
    // first Canopy block: its schedule counts from the fork, which did not move.
    BOOST_CHECK_EQUAL(test.GetYdfMandateEndHeight(), 900000);
    const CScript ydf = test.GetFoundersRewardScriptAtHeight(FORK);
    BOOST_CHECK(ydf.size() == 25 && ydf[0] == OP_DUP);
    BOOST_CHECK(test.GetFoundersRewardScriptAtHeight(CANOPY) == ydf);
}

BOOST_AUTO_TEST_CASE(testnet_work_and_maturity)
{
    const Consensus::Params& c = Params(CBaseChainParams::TESTNET).GetConsensus();
    // F-T2: the work of Zcash testnet block 280,000 (Sapling, the last pinned activation): above
    // block 279,999's (0x23bc0cbb1), below the prefix's at 510,247 (0x19496c5dab).
    const arith_uint256 work = UintToArith256(c.nMinimumChainWork);
    BOOST_CHECK(work == arith_uint256(0x23bc0da20ULL));
    BOOST_CHECK(work > arith_uint256(0x23bc0cbb1ULL));
    BOOST_CHECK(work < arith_uint256(0x19496c5dabULL));

    // T-4 / D4 (owner 2026-10-29): 48 blocks of maturity on testnet, the same in the YED module, so the module
    // adopts a testnet set; mainnet and regtest unchanged.
    BOOST_CHECK_EQUAL(c.nVaultMinSetMaturity, 48U);
    BOOST_CHECK_EQUAL(yellowback::TestParams().bondMaturity, 48);
    BOOST_CHECK(yellowback::TestParams().bondMaturity >= yellowback::TestParams().attestMaxAge);
    BOOST_CHECK_EQUAL(Params(CBaseChainParams::MAIN).GetConsensus().nVaultMinSetMaturity, vault::MIN_SET_MATURITY);
    BOOST_CHECK_EQUAL(Params(CBaseChainParams::REGTEST).GetConsensus().nVaultMinSetMaturity, 2U);
}

BOOST_AUTO_TEST_SUITE_END()
