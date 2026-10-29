// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The re-forked testnet's chain parameters (docs/plans/yellowback-testnet-plan.md §2.1, N1): Zcash
// testnet through block 510,247, then a new Ycash fork at 510,248. Revision 3: three compiled-in
// profiles of it, -testnet -testnetprofile=fast|slow|legacy, which share the history and differ in
// datadir, ports, magic and the Vault timing. Byte-identical on both node lines
// (qa/yellowback-cross-line.manifest): CTestNetParams is changed identically on both node lines.

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

#include <algorithm>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(testnet_params_tests, BasicTestingSetup)

static const int FORK = 510248;     // UPGRADE_YCASH, unchanged
static const int BLOSSOM = 510250;
static const int HEARTWOOD = 510252;
static const int CANOPY = 510254;
static const int VAULT = 510400;    // H_V on testnet-yb-fast, the ceremony's placeholder
static const int NONE = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

namespace {
/** One row of the plan's Revision 3 table. */
struct Profile {
    std::string name;
    unsigned char magic3;   // pchMessageStart[3]; bytes 0..2 are f7 79 62 on every profile
    int port;
    int rpcPort;
    std::string dataDir;
    int vaultHeight;
    uint32_t minSetMaturity;
};
const std::vector<Profile> PROFILES = {
    {"fast", 0xd3, 18833, 18832, "testnet-yb-fast", VAULT, 48},
    {"slow", 0xd4, 18933, 18932, "testnet-yb-slow", NONE, 16128},
    {"legacy", 0xd5, 19033, 19032, "testnet-legacy", NONE, 16128},
};

/** Params(TESTNET) of one profile; the selection goes back to the default (fast) afterwards. */
const CChainParams& TestNet(const std::string& profile)
{
    SelectTestnetProfile(profile);
    const CChainParams& p = Params(CBaseChainParams::TESTNET);
    SelectTestnetProfile(CBaseChainParams::TESTNET_FAST);
    return p;
}

std::vector<unsigned char> Magic(const CChainParams& p)
{
    return std::vector<unsigned char>(p.MessageStart(), p.MessageStart() + 4);
}

/** The invariants every YED column keeps (yellowback/params.cpp TestFastParams, the floors of its rule). */
void CheckColumnInvariants(const yellowback::Params& p)
{
    BOOST_CHECK(p.bondMaturity >= p.attestMaxAge);
    BOOST_CHECK(p.claimDelay >= p.attestMaxAge);
    BOOST_CHECK(p.attestArmDelay >= p.attestMaxAge);
    BOOST_CHECK(p.emergencyNoticeTtl >= p.emergencyPersist + p.refWindow);
    BOOST_CHECK(p.attestorLivenessMin >= 2 * p.attestMaxAge);
    BOOST_CHECK(p.cancelQuiet >= p.cancelSignersMax * p.claimDelay);
    BOOST_CHECK(p.dormancyBlocks >= p.dormancyMinBundles);
    BOOST_CHECK(p.dormancyCheck >= 1 && p.dormancyCheck <= p.dormancyBlocks);
    BOOST_CHECK(p.seatAgeUnit >= 1 && p.seatAgeCap >= p.seatAgeUnit);
    BOOST_CHECK(p.classMin[0] > 0);
    for (int i = 0; i < yellowback::NUM_CLASSES; i++) BOOST_CHECK(p.classMin[i] <= p.classMax[i]);
    for (int i = 1; i < yellowback::NUM_CLASSES; i++) BOOST_CHECK_EQUAL(p.classMin[i], p.classMax[i - 1] + 1);
    BOOST_CHECK((int64_t)p.classMax[yellowback::NUM_CLASSES - 1] + p.grace + 10000000 < (int64_t)LOCKTIME_THRESHOLD);
}

/** ceil(mainnet x 48 / 16,128), the fast column's scaling before its floor. */
int Scaled(int mainnet)
{
    return (int)(((int64_t)mainnet * 48 + 16128 - 1) / 16128);
}
} // namespace

BOOST_AUTO_TEST_CASE(testnet_profiles_identity)
{
    std::vector<std::vector<unsigned char>> seen;
    for (const Profile& pr : PROFILES) {
        const CChainParams& test = TestNet(pr.name);
        BOOST_CHECK_EQUAL(test.NetworkIDString(), "test");   // address encoding, YED's network, clients' chain checks
        BOOST_CHECK_EQUAL(test.TestnetProfile(), pr.name);
        // T-2, T-14: a magic of its own per profile, distinct from Ycash/Zcash mainnet, the old testnet and regtest.
        const std::vector<unsigned char> magic = Magic(test);
        BOOST_CHECK(magic == std::vector<unsigned char>({0xf7, 0x79, 0x62, pr.magic3}));
        BOOST_CHECK(magic != Magic(Params(CBaseChainParams::MAIN)));
        BOOST_CHECK(magic != Magic(Params(CBaseChainParams::REGTEST)));
        BOOST_CHECK(magic != std::vector<unsigned char>({0xfa, 0x1a, 0xf9, 0xbf}));   // the old Ycash testnet
        for (const std::vector<unsigned char>& other : seen) BOOST_CHECK(magic != other);
        seen.push_back(magic);
        BOOST_CHECK_EQUAL(test.GetDefaultPort(), pr.port);

        // A datadir per profile (a leftover testnet3 holds the old branch); the RPC port one below the P2P port.
        SelectTestnetProfile(pr.name);
        SelectBaseParams(CBaseChainParams::TESTNET);
        BOOST_CHECK_EQUAL(BaseParams().DataDir(), pr.dataDir);
        BOOST_CHECK_EQUAL(BaseParams().RPCPort(), pr.rpcPort);
        BOOST_CHECK_EQUAL(BaseParams().RPCPort(), pr.port - 1);
        SelectTestnetProfile(CBaseChainParams::TESTNET_FAST);
        SelectBaseParams(CBaseChainParams::MAIN);

        // D1: fixed seeds only, one list per profile (empty until rc1), no DNS seed.
        BOOST_CHECK(test.DNSSeeds().empty());
        BOOST_CHECK(test.FixedSeeds().empty());
    }
    BOOST_CHECK(Params(CBaseChainParams::MAIN).TestnetProfile().empty());
    BOOST_CHECK(Params(CBaseChainParams::REGTEST).TestnetProfile().empty());
    // The default selection (unit tests; the command line always names one) is fast.
    BOOST_CHECK_EQUAL(SelectedTestnetProfile(), CBaseChainParams::TESTNET_FAST);
    BOOST_CHECK(&Params(CBaseChainParams::TESTNET) == &TestNet("fast"));
    BOOST_CHECK_THROW(SelectTestnetProfile("medium"), std::runtime_error);
    BOOST_CHECK_THROW(SelectTestnetProfile(""), std::runtime_error);
    BOOST_CHECK_EQUAL(SelectedTestnetProfile(), CBaseChainParams::TESTNET_FAST);
}

BOOST_AUTO_TEST_CASE(testnet_profile_is_required)
{
    // T-14: -testnet without a profile, an unknown profile, or a profile without -testnet stops at startup.
    const std::map<std::string, std::string> saved = mapArgs;
    mapArgs.clear();
    mapArgs["-testnet"] = "1";
    BOOST_CHECK_THROW(ChainNameFromCommandLine(), std::runtime_error);
    mapArgs["-testnetprofile"] = "fastest";
    BOOST_CHECK_THROW(ChainNameFromCommandLine(), std::runtime_error);
    mapArgs["-testnetprofile"] = "";
    BOOST_CHECK_THROW(ChainNameFromCommandLine(), std::runtime_error);
    for (const Profile& pr : PROFILES) {
        mapArgs["-testnetprofile"] = pr.name;
        BOOST_CHECK_EQUAL(ChainNameFromCommandLine(), CBaseChainParams::TESTNET);
        BOOST_CHECK_EQUAL(SelectedTestnetProfile(), pr.name);
    }
    mapArgs.erase("-testnet");
    BOOST_CHECK_THROW(ChainNameFromCommandLine(), std::runtime_error);   // a profile without -testnet
    mapArgs["-regtest"] = "1";
    BOOST_CHECK_THROW(ChainNameFromCommandLine(), std::runtime_error);
    mapArgs.erase("-testnetprofile");
    BOOST_CHECK_EQUAL(ChainNameFromCommandLine(), CBaseChainParams::REGTEST);
    mapArgs.erase("-regtest");
    BOOST_CHECK_EQUAL(ChainNameFromCommandLine(), CBaseChainParams::MAIN);
    mapArgs = saved;
    SelectTestnetProfile(CBaseChainParams::TESTNET_FAST);
}

BOOST_AUTO_TEST_CASE(testnet_checkpoints)
{
    for (const Profile& pr : PROFILES) {
        const CCheckpointData& cp = TestNet(pr.name).Checkpoints();
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
}

BOOST_AUTO_TEST_CASE(testnet_upgrade_schedule)
{
    for (const Profile& pr : PROFILES) {
        const Consensus::Params& c = TestNet(pr.name).GetConsensus();
        const auto& u = c.vUpgrades;
        BOOST_CHECK_EQUAL(u[Consensus::UPGRADE_OVERWINTER].nActivationHeight, 207500);
        BOOST_CHECK_EQUAL(u[Consensus::UPGRADE_SAPLING].nActivationHeight, 280000);
        BOOST_CHECK_EQUAL(u[Consensus::UPGRADE_YCASH].nActivationHeight, FORK);
        BOOST_CHECK_EQUAL(u[Consensus::UPGRADE_BLOSSOM].nActivationHeight, BLOSSOM);
        BOOST_CHECK_EQUAL(u[Consensus::UPGRADE_HEARTWOOD].nActivationHeight, HEARTWOOD);
        BOOST_CHECK_EQUAL(u[Consensus::UPGRADE_CANOPY].nActivationHeight, CANOPY);
        // fast 510,400; slow unset until its first rc (T-15); legacy never.
        BOOST_CHECK_EQUAL(u[Consensus::UPGRADE_VAULT].nActivationHeight, pr.vaultHeight);
        // init.cpp's R-A3 check: NU5 (and on the 6.20.0 line NU6..NU6.2) unset, Sapling at or below the Vault height.
        BOOST_CHECK_EQUAL(u[Consensus::UPGRADE_NU5].nActivationHeight, NONE);
        if (pr.vaultHeight != NONE) BOOST_CHECK(u[Consensus::UPGRADE_SAPLING].nActivationHeight <= pr.vaultHeight);
        // Falcon follows the Vault height (pqFalconHeight 0, D-Q-2) on every profile.
        BOOST_CHECK_EQUAL(c.pqFalconHeight, 0);

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
        if (pr.vaultHeight == VAULT) {
            BOOST_CHECK_EQUAL(CurrentEpochBranchId(VAULT, c), NetworkUpgradeInfo[Consensus::UPGRADE_VAULT].nBranchId);
        } else {
            BOOST_CHECK_EQUAL(CurrentEpochBranchId(VAULT, c), NetworkUpgradeInfo[Consensus::UPGRADE_CANOPY].nBranchId);
            BOOST_CHECK_EQUAL(CurrentEpochBranchId(4000000, c), NetworkUpgradeInfo[Consensus::UPGRADE_CANOPY].nBranchId);
        }

        // The future-timestamp rule follows Blossom by six blocks (MTP of post-Blossom blocks only).
        BOOST_CHECK_EQUAL(c.nFutureTimestampSoftForkHeight, BLOSSOM + 6);
    }
}

BOOST_AUTO_TEST_CASE(testnet_subsidy_and_ydf)
{
    for (const Profile& pr : PROFILES) {
        const CChainParams& test = TestNet(pr.name);
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
}

BOOST_AUTO_TEST_CASE(testnet_work_and_maturity)
{
    for (const Profile& pr : PROFILES) {
        const Consensus::Params& c = TestNet(pr.name).GetConsensus();
        // F-T2: the work of Zcash testnet block 280,000 (Sapling, the last pinned activation): above
        // block 279,999's (0x23bc0cbb1), below the prefix's at 510,247 (0x19496c5dab).
        const arith_uint256 work = UintToArith256(c.nMinimumChainWork);
        BOOST_CHECK(work == arith_uint256(0x23bc0da20ULL));
        BOOST_CHECK(work > arith_uint256(0x23bc0cbb1ULL));
        BOOST_CHECK(work < arith_uint256(0x19496c5dabULL));
        // D4: 48 blocks on fast; slow is mainnet's 16,128; legacy keeps the default (unused: no Vault).
        BOOST_CHECK_EQUAL(c.nVaultMinSetMaturity, pr.minSetMaturity);
    }
    BOOST_CHECK_EQUAL(TestNet("slow").GetConsensus().nVaultMinSetMaturity, vault::MIN_SET_MATURITY);
    BOOST_CHECK_EQUAL(Params(CBaseChainParams::MAIN).GetConsensus().nVaultMinSetMaturity, vault::MIN_SET_MATURITY);
    BOOST_CHECK_EQUAL(Params(CBaseChainParams::REGTEST).GetConsensus().nVaultMinSetMaturity, 2U);
    // The module adopts a set only when its maturity equals BOND_MATURITY, and the primitive refuses one below
    // nVaultMinSetMaturity: the YED column of each Vault profile names exactly that network's minimum.
    BOOST_CHECK_EQUAL((uint32_t)yellowback::TestFastParams().bondMaturity, TestNet("fast").GetConsensus().nVaultMinSetMaturity);
    BOOST_CHECK_EQUAL((uint32_t)yellowback::TestParams().bondMaturity, TestNet("slow").GetConsensus().nVaultMinSetMaturity);
}

BOOST_AUTO_TEST_CASE(testnet_yed_columns)
{
    using yellowback::Params;
    const Params& main = yellowback::MainParams();
    const Params& slow = yellowback::TestParams();
    const Params& fast = yellowback::TestFastParams();
    const Params regtest = yellowback::RegtestParams(1, 0, 0, uint256S("01"));
    for (const Params* p : {&main, &slow, &fast, &regtest}) CheckColumnInvariants(*p);

    // slow is exactly mainnet's column but for the network and the address versions (yt…).
    for (const Params* p : {&slow, &fast}) {
        BOOST_CHECK_EQUAL(p->network, "test");
        BOOST_CHECK(p->addressVersion == std::vector<unsigned char>({0x20, 0x07}));
        BOOST_CHECK(p->pqAddressVersion == std::vector<unsigned char>({0x57, 0x1E}));
        BOOST_CHECK_EQUAL(p->startHeight, 0);
        BOOST_CHECK(p->attestorSetId.IsNull());   // each Vault profile's own set, named by its rc1
    }
    BOOST_CHECK_EQUAL(slow.bondMaturity, main.bondMaturity);
    BOOST_CHECK_EQUAL(slow.dormancyBlocks, main.dormancyBlocks);
    BOOST_CHECK_EQUAL(slow.claimDelay, main.claimDelay);
    BOOST_CHECK_EQUAL(slow.grace, main.grace);
    BOOST_CHECK_EQUAL(slow.attestorLivenessMin, main.attestorLivenessMin);
    BOOST_CHECK_EQUAL(slow.cancelQuiet, main.cancelQuiet);
    BOOST_CHECK_EQUAL(slow.seatAgeCap, main.seatAgeCap);
    for (int i = 0; i < yellowback::NUM_CLASSES; i++) {
        BOOST_CHECK_EQUAL(slow.classMin[i], main.classMin[i]);
        BOOST_CHECK_EQUAL(slow.classMax[i], main.classMax[i]);
    }

    // fast: every lifecycle window is max(floor, ceil(mainnet x 48 / 16,128)) (params.cpp TestFastParams).
    BOOST_CHECK_EQUAL(fast.bondMaturity, std::max(fast.attestMaxAge, Scaled(main.bondMaturity)));
    BOOST_CHECK_EQUAL(fast.bondMaturity, 48);
    BOOST_CHECK_EQUAL(fast.claimDelay, std::max(fast.attestMaxAge, Scaled(main.claimDelay)));
    BOOST_CHECK_EQUAL(fast.grace, Scaled(main.grace));
    BOOST_CHECK_EQUAL(fast.classMin[0], Scaled(main.classMin[0]));
    for (int i = 1; i < yellowback::NUM_CLASSES; i++) {
        BOOST_CHECK_EQUAL(fast.classMin[i], std::max(fast.classMax[i - 1] + 1, Scaled(main.classMin[i])));
    }
    for (int i = 0; i < yellowback::NUM_CLASSES; i++) BOOST_CHECK_EQUAL(fast.classMax[i], Scaled(main.classMax[i]));
    BOOST_CHECK_EQUAL(fast.attestArmDelay, std::max(fast.attestMaxAge, Scaled(main.attestArmDelay)));
    BOOST_CHECK_EQUAL(fast.emergencyNoticeTtl, std::max(fast.emergencyPersist + fast.refWindow, Scaled(main.emergencyNoticeTtl)));
    BOOST_CHECK_EQUAL(fast.ageCap, Scaled(main.ageCap));
    BOOST_CHECK_EQUAL(fast.foundingWindow, Scaled(main.foundingWindow));
    BOOST_CHECK_EQUAL(fast.seatAgeUnit, std::max(1, Scaled(main.seatAgeUnit)));
    BOOST_CHECK_EQUAL(fast.seatAgeCap, std::max(fast.seatAgeUnit, Scaled(main.seatAgeCap)));
    BOOST_CHECK_EQUAL(fast.attestorLivenessMin, std::max(2 * fast.attestMaxAge, Scaled(main.attestorLivenessMin)));
    BOOST_CHECK_EQUAL(fast.cancelQuiet, std::max(fast.cancelSignersMax * fast.claimDelay, Scaled(main.cancelQuiet)));
    BOOST_CHECK_EQUAL(fast.dormancyBlocks, std::max(fast.dormancyMinBundles, Scaled(main.dormancyBlocks)));
    BOOST_CHECK_EQUAL(fast.dormancyCheck, std::max(1, Scaled(main.dormancyCheck)));

    // ... and nothing else moves: prices, volatility, attestation freshness, counts, amounts, fees, policy.
    BOOST_CHECK_EQUAL(fast.pFastWindow, main.pFastWindow);
    BOOST_CHECK_EQUAL(fast.pMidWindow, main.pMidWindow);
    BOOST_CHECK_EQUAL(fast.pSlowWindow, main.pSlowWindow);
    BOOST_CHECK_EQUAL(fast.pSlowMinFill, main.pSlowMinFill);
    BOOST_CHECK_EQUAL(fast.volWindow, main.volWindow);
    BOOST_CHECK_EQUAL(fast.volStep, main.volStep);
    BOOST_CHECK_EQUAL(fast.pinWindow, main.pinWindow);
    BOOST_CHECK_EQUAL(fast.attestMaxAge, main.attestMaxAge);
    BOOST_CHECK_EQUAL(fast.attestInterval, main.attestInterval);
    BOOST_CHECK_EQUAL(fast.emergencyPersist, main.emergencyPersist);
    BOOST_CHECK_EQUAL(fast.dormancyMinBundles, main.dormancyMinBundles);
    BOOST_CHECK_EQUAL(fast.attestArmMin, main.attestArmMin);
    BOOST_CHECK_EQUAL(fast.cancelSignersMax, main.cancelSignersMax);
    BOOST_CHECK_EQUAL(fast.attestorSeats, main.attestorSeats);
    BOOST_CHECK_EQUAL(fast.nReg, main.nReg);
    BOOST_CHECK_EQUAL(fast.payeeWindow, main.payeeWindow);
    BOOST_CHECK_EQUAL(fast.bondMinFloorZat, main.bondMinFloorZat);
    BOOST_CHECK_EQUAL(fast.feeFloorCents, main.feeFloorCents);
    BOOST_CHECK_EQUAL(fast.maxMint, main.maxMint);
    BOOST_CHECK_EQUAL(fast.mintRequiresArmed, main.mintRequiresArmed);
    for (int i = 0; i < yellowback::NUM_CLASSES; i++) BOOST_CHECK_EQUAL(fast.baseRatioBps[i], main.baseRatioBps[i]);
}

BOOST_AUTO_TEST_CASE(testnet_yed_params_from_args)
{
    // init.cpp picks the column by the profile: fast reads TestFastParams, slow and legacy TestParams;
    // YED stays off on all three until a release names a set (and on legacy for good: no Vault height).
    for (const Profile& pr : PROFILES) {
        yellowback::Params p;
        BOOST_REQUIRE(!yellowback::ParamsFromArgs("test", pr.name, TestNet(pr.name).GetConsensus(), p).has_value());
        BOOST_CHECK_EQUAL(p.network, "test");
        BOOST_CHECK_EQUAL(p.bondMaturity, pr.name == "fast" ? 48 : 16128);
        BOOST_CHECK_EQUAL(p.dormancyBlocks, pr.name == "fast" ? 48 : 16128);
        BOOST_CHECK_EQUAL(p.startHeight, 0);
        BOOST_CHECK(!p.IsConfigured());
        BOOST_CHECK_EQUAL(p.pqFalconHeight, pr.vaultHeight == NONE ? -1 : pr.vaultHeight);
    }
    yellowback::Params q;
    BOOST_CHECK(yellowback::ParamsFromArgs("test", "", TestNet("fast").GetConsensus(), q).has_value());
    BOOST_CHECK(yellowback::ParamsFromArgs("test", "medium", TestNet("fast").GetConsensus(), q).has_value());
}

BOOST_AUTO_TEST_SUITE_END()
