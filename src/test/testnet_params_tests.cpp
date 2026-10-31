// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The testnets' chain parameters (docs/plans/yellowback-testnet-plan.md, Revision 3: three compiled-in
// profiles, -testnet -testnetprofile=fast|slow|legacy, with their own datadir, ports, magic and Vault
// timing). testnet-yb-fast is the re-forked testnet (§2.1, N1): Zcash testnet through block 510,247,
// then a new Ycash fork at 510,248. testnet-yb-slow and testnet-legacy are shadow forks of Ycash
// mainnet (docs/plans/yellowback-testnet-shadow-fork-plan.md): mainnet through H_S, then their own
// branch IDs (replay protection both ways) and a one-time difficulty reset. Byte-identical on both node
// lines (qa/yellowback-cross-line.manifest): the chain parameters change identically on both lines.

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "chainparamsbase.h"
#include "consensus/upgrades.h"
#include "pow.h"
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
/** One row of the plan's Revision 3 table (shadow: the shadow-fork plan's slow and legacy). */
struct Profile {
    std::string name;
    unsigned char magic3;   // pchMessageStart[3]; bytes 0..2 are f7 79 62 on every profile
    int port;
    int rpcPort;
    std::string dataDir;
    int vaultHeight;
    uint32_t minSetMaturity;
    bool shadow;            // a shadow fork of mainnet (else the re-forked Zcash testnet history)
};
const std::vector<Profile> PROFILES = {
    {"fast", 0xd3, 18833, 18832, "testnet-yb-fast", VAULT, 48, false},
    {"slow", 0xd4, 18933, 18932, "testnet-yb-slow", NONE, 16128, true},
    {"legacy", 0xd5, 19033, 19032, "testnet-legacy", NONE, 16128, true},
};
const std::vector<Profile> SHADOW = {PROFILES[1], PROFILES[2]};

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
        if (pr.shadow) continue;   // mainnet's (shadow_profiles_are_mainnet_through_the_split)
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
        if (pr.shadow) continue;   // mainnet's (shadow_profiles_are_mainnet_through_the_split)
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
        if (pr.shadow) continue;   // mainnet's (shadow_profiles_are_mainnet_through_the_split)
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
        // block 279,999's (0x23bc0cbb1), below the prefix's at 510,247 (0x19496c5dab). The shadow
        // forks keep mainnet's.
        const arith_uint256 work = UintToArith256(c.nMinimumChainWork);
        if (pr.shadow) {
            BOOST_CHECK(c.nMinimumChainWork == Params(CBaseChainParams::MAIN).GetConsensus().nMinimumChainWork);
        } else {
            BOOST_CHECK(work == arith_uint256(0x23bc0da20ULL));
            BOOST_CHECK(work > arith_uint256(0x23bc0cbb1ULL));
            BOOST_CHECK(work < arith_uint256(0x19496c5dabULL));
        }
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
    // The bond amounts are the one non-window difference (owner 2026-10-29): fast bonds at a thousandth of
    // mainnet's so its house seats can bond soon after the fork; slow keeps mainnet's.
    BOOST_CHECK_EQUAL(fast.bondMinFloorZat, main.bondMinFloorZat / 1000);
    BOOST_CHECK_EQUAL(fast.bondMinCapZat, main.bondMinCapZat / 1000);
    BOOST_CHECK_EQUAL(fast.bondShareBps, main.bondShareBps);
    BOOST_CHECK_EQUAL(yellowback::TestParams().bondMinFloorZat, main.bondMinFloorZat);
    BOOST_CHECK_EQUAL(yellowback::TestParams().bondMinCapZat, main.bondMinCapZat);
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

namespace {
/** The block index entries of a chain from height first to last, with the given bits and 75 s spacing. */
std::vector<CBlockIndex> Chain(int first, int last, uint32_t nBits)
{
    std::vector<CBlockIndex> blocks(last - first + 1);
    for (size_t i = 0; i < blocks.size(); i++) {
        blocks[i].nHeight = first + (int)i;
        blocks[i].nTime = 1700000000 + 75 * (uint32_t)i;
        blocks[i].nBits = nBits;
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
    }
    return blocks;
}
} // namespace

BOOST_AUTO_TEST_CASE(shadow_profiles_are_mainnet_through_the_split)
{
    // The shadow forks are mainnet's chain parameters with exactly these exceptions: the network ID,
    // the unit, the BIP44 coin type, the address prefixes (testnet's, as fast's), the magic, ports and
    // seeds (testnet_profiles_identity), the deprecated "testnet" RPC field, and from H_S + 1 the shadow
    // upgrade (its branch ID, the difficulty reset and minimum-difficulty blocks) and slow's Vault.
    const CChainParams& main = Params(CBaseChainParams::MAIN);
    const CChainParams& fast = TestNet("fast");
    const Consensus::Params& m = main.GetConsensus();
    for (const Profile& pr : SHADOW) {
        const CChainParams& test = TestNet(pr.name);
        const Consensus::Params& c = test.GetConsensus();

        // The exceptions.
        BOOST_CHECK_EQUAL(test.NetworkIDString(), "test");
        BOOST_CHECK_EQUAL(test.CurrencyUnits(), "TAY");
        BOOST_CHECK_EQUAL(test.BIP44CoinType(), 1U);
        BOOST_CHECK(test.TestnetToBeDeprecatedFieldRPC());
        for (int t = 0; t < KeyConstants::MAX_BASE58_TYPES; t++) {
            BOOST_CHECK(test.Base58Prefix((KeyConstants::Base58Type)t) == fast.Base58Prefix((KeyConstants::Base58Type)t));
        }
        for (int t = 0; t < KeyConstants::MAX_BECH32_TYPES; t++) {
            BOOST_CHECK_EQUAL(test.Bech32HRP((KeyConstants::Bech32Type)t), fast.Bech32HRP((KeyConstants::Bech32Type)t));
        }

        // Everything else is mainnet's: the genesis block, proof of work and its Ycash-fork rule.
        BOOST_CHECK(test.GenesisBlock().GetHash() == main.GenesisBlock().GetHash());
        BOOST_CHECK(c.hashGenesisBlock == uint256S("00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08"));
        BOOST_CHECK(c.powLimit == m.powLimit);
        BOOST_CHECK_EQUAL(c.nPowAveragingWindow, m.nPowAveragingWindow);
        BOOST_CHECK_EQUAL(c.nPowMaxAdjustDown, m.nPowMaxAdjustDown);
        BOOST_CHECK_EQUAL(c.nPowMaxAdjustUp, m.nPowMaxAdjustUp);
        BOOST_CHECK_EQUAL(c.nPreBlossomPowTargetSpacing, m.nPreBlossomPowTargetSpacing);
        BOOST_CHECK_EQUAL(c.nPostBlossomPowTargetSpacing, m.nPostBlossomPowTargetSpacing);
        BOOST_CHECK_EQUAL(c.fPowNoRetargeting, m.fPowNoRetargeting);
        BOOST_CHECK_EQUAL(c.minDifficultyAtYcashFork, m.minDifficultyAtYcashFork);
        BOOST_CHECK_EQUAL(c.scaledDifficultyAtYcashFork, m.scaledDifficultyAtYcashFork);
        BOOST_CHECK_EQUAL(c.nFutureTimestampSoftForkHeight, m.nFutureTimestampSoftForkHeight);
        BOOST_CHECK(c.nMinimumChainWork == m.nMinimumChainWork);
        BOOST_CHECK_EQUAL(c.nEquihashN, m.nEquihashN);
        BOOST_CHECK_EQUAL(c.nEquihashK, m.nEquihashK);
        for (int h : {0, 569999, 570000, 1100006, 3000000}) {
            BOOST_CHECK_EQUAL(test.EquihashN(h), main.EquihashN(h));
            BOOST_CHECK_EQUAL(test.EquihashK(h), main.EquihashK(h));
        }
        // Subsidy and coinbase rules.
        BOOST_CHECK_EQUAL(c.fCoinbaseMustBeShielded, m.fCoinbaseMustBeShielded);
        BOOST_CHECK_EQUAL(c.nSubsidySlowStartInterval, m.nSubsidySlowStartInterval);
        BOOST_CHECK_EQUAL(c.nPreBlossomSubsidyHalvingInterval, m.nPreBlossomSubsidyHalvingInterval);
        BOOST_CHECK_EQUAL(c.nPostBlossomSubsidyHalvingInterval, m.nPostBlossomSubsidyHalvingInterval);
        for (int h : {1, 20000, 569999, 570000, 1100006, 2275000, 3000000, 5000000}) {
            BOOST_CHECK_EQUAL(yellowback::CirculatingSupplyAt(h, c), yellowback::CirculatingSupplyAt(h, m));
            BOOST_CHECK_EQUAL(c.Halving(h), m.Halving(h));
        }
        BOOST_CHECK_EQUAL(c.nMajorityEnforceBlockUpgrade, m.nMajorityEnforceBlockUpgrade);
        BOOST_CHECK_EQUAL(c.nMajorityRejectBlockOutdated, m.nMajorityRejectBlockOutdated);
        BOOST_CHECK_EQUAL(c.nMajorityWindow, m.nMajorityWindow);
        // Every upgrade before the shadow upgrade: heights, protocol versions, activation hashes, branch IDs.
        for (int idx = Consensus::BASE_SPROUT; idx < Consensus::UPGRADE_SHADOW; idx++) {
            const auto i = Consensus::UpgradeIndex(idx);
            BOOST_CHECK_EQUAL(c.vUpgrades[i].nActivationHeight, m.vUpgrades[i].nActivationHeight);
            BOOST_CHECK_EQUAL(c.vUpgrades[i].nProtocolVersion, m.vUpgrades[i].nProtocolVersion);
            BOOST_CHECK(c.vUpgrades[i].hashActivationBlock == m.vUpgrades[i].hashActivationBlock);
            BOOST_CHECK(!c.vUpgrades[i].nBranchId.has_value());
            BOOST_CHECK_EQUAL(NetworkBranchId(i, c), NetworkBranchId(i, m));
        }
        BOOST_CHECK(c.vUpgrades[Consensus::UPGRADE_YCASH].hashActivationBlock ==
                    uint256S("0000014fbc5917ba8bcacf3336faf588d86b32443aa3a490a587af5750c77ec5"));
        // Checkpoints: mainnet's, up to H_S (all of them while H_S is unset).
        const int shadow = c.vUpgrades[Consensus::UPGRADE_SHADOW].nActivationHeight;
        for (const auto& kv : main.Checkpoints().mapCheckpoints) {
            if (shadow != NONE && kv.first >= shadow) {
                BOOST_CHECK(test.Checkpoints().mapCheckpoints.count(kv.first) == 0);
            } else {
                BOOST_CHECK(test.Checkpoints().mapCheckpoints.count(kv.first) == 1);
                BOOST_CHECK(test.Checkpoints().mapCheckpoints.at(kv.first) == kv.second);
            }
        }
        for (const auto& kv : test.Checkpoints().mapCheckpoints) BOOST_CHECK(main.Checkpoints().mapCheckpoints.count(kv.first) == 1);
        // The Sprout-pool checkpoint and ZIP 209.
        BOOST_CHECK_EQUAL(test.SproutValuePoolCheckpointHeight(), main.SproutValuePoolCheckpointHeight());
        BOOST_CHECK_EQUAL(test.SproutValuePoolCheckpointBalance(), main.SproutValuePoolCheckpointBalance());
        BOOST_CHECK(test.SproutValuePoolCheckpointBlockHash() == main.SproutValuePoolCheckpointBlockHash());
        BOOST_CHECK_EQUAL(test.ZIP209Enabled(), main.ZIP209Enabled());
        // The founders' reward (pre-fork) and the YDF (to the mandate's end) pay mainnet's scripts at
        // every address of both schedules, though this network displays testnet prefixes.
        BOOST_CHECK_EQUAL(test.GetYdfMandateEndHeight(), main.GetYdfMandateEndHeight());
        BOOST_CHECK_EQUAL(test.GetYdfMandateEndHeight(), 2275000);
        const int ycash = m.vUpgrades[Consensus::UPGRADE_YCASH].nActivationHeight;
        const int lastFr = std::min(ycash - 1, m.GetLastFoundersRewardBlockHeight(1));
        for (int h = 1; h <= lastFr; h += 9001) {
            BOOST_CHECK(test.GetFoundersRewardScriptAtHeight(h) == main.GetFoundersRewardScriptAtHeight(h));
        }
        BOOST_CHECK(test.GetFoundersRewardScriptAtHeight(lastFr) == main.GetFoundersRewardScriptAtHeight(lastFr));
        for (int h = ycash; h < main.GetYdfMandateEndHeight(); h += 17917) {
            BOOST_CHECK(test.GetFoundersRewardScriptAtHeight(h) == main.GetFoundersRewardScriptAtHeight(h));
        }
        BOOST_CHECK(test.GetFoundersRewardScriptAtHeight(2274999) == main.GetFoundersRewardScriptAtHeight(2274999));
    }
}

BOOST_AUTO_TEST_CASE(shadow_split_height)
{
    // H_S is one value for slow and legacy, unset (NO_ACTIVATION_HEIGHT) until the mainnet harvest
    // fixes it; the release guard refuses a tag until then (qa/yellowback-vault-params.py, R8).
    const Consensus::Params& m = Params(CBaseChainParams::MAIN).GetConsensus();
    const int slow = TestNet("slow").GetConsensus().vUpgrades[Consensus::UPGRADE_SHADOW].nActivationHeight;
    BOOST_CHECK_EQUAL(TestNet("legacy").GetConsensus().vUpgrades[Consensus::UPGRADE_SHADOW].nActivationHeight, slow);
    for (const Profile& pr : SHADOW) {
        const Consensus::Params& c = TestNet(pr.name).GetConsensus();
        BOOST_CHECK_EQUAL(c.vUpgrades[Consensus::UPGRADE_SHADOW].nProtocolVersion, 270013);
        if (slow == NONE) {
            BOOST_CHECK(!c.nPowAllowMinDifficultyBlocksAfterHeight.has_value());
        } else {
            const int hs = slow - 1;
            BOOST_CHECK(c.nPowAllowMinDifficultyBlocksAfterHeight == std::optional<uint32_t>(hs));
            BOOST_CHECK(hs >= m.vUpgrades[Consensus::UPGRADE_CANOPY].nActivationHeight);
            BOOST_CHECK(hs >= TestNet(pr.name).GetYdfMandateEndHeight());   // nothing is owed after the split
            BOOST_CHECK(TestNet(pr.name).Checkpoints().mapCheckpoints.rbegin()->first <= hs);
        }
    }
    // Mainnet, fast and regtest never activate it and have no network-own branch IDs.
    const std::vector<const CChainParams*> unshadowed = {&Params(CBaseChainParams::MAIN), &TestNet("fast"), &Params(CBaseChainParams::REGTEST)};
    for (const CChainParams* p : unshadowed) {
        const Consensus::Params& c = p->GetConsensus();
        BOOST_CHECK_EQUAL(c.vUpgrades[Consensus::UPGRADE_SHADOW].nActivationHeight, NONE);
        for (int idx = Consensus::BASE_SPROUT; idx < Consensus::MAX_NETWORK_UPGRADES; idx++) {
            BOOST_CHECK(!c.vUpgrades[idx].nBranchId.has_value());
            BOOST_CHECK_EQUAL(NetworkBranchId(Consensus::UpgradeIndex(idx), c), NetworkUpgradeInfo[idx].nBranchId);
        }
    }
}

BOOST_AUTO_TEST_CASE(shadow_branch_ids)
{
    // Three new IDs, distinct from each other, from every branch ID in NetworkUpgradeInfo but the
    // shadow upgrade's own entry (which is slow's), from Zcash's own Blossom..NU7 IDs and from the magics.
    const std::vector<uint32_t> ids = {SLOW_SHADOW_BRANCH_ID, SLOW_VAULT_BRANCH_ID, LEGACY_SHADOW_BRANCH_ID};
    BOOST_CHECK_EQUAL(SLOW_SHADOW_BRANCH_ID, 0x57a24d5dU);
    BOOST_CHECK_EQUAL(SLOW_VAULT_BRANCH_ID, 0xe1f1cc08U);
    BOOST_CHECK_EQUAL(LEGACY_SHADOW_BRANCH_ID, 0x35706728U);
    BOOST_CHECK_EQUAL(NetworkUpgradeInfo[Consensus::UPGRADE_SHADOW].nBranchId, SLOW_SHADOW_BRANCH_ID);
    for (size_t i = 0; i < ids.size(); i++) {
        for (size_t j = i + 1; j < ids.size(); j++) BOOST_CHECK(ids[i] != ids[j]);
        for (int idx = Consensus::BASE_SPROUT; idx < Consensus::MAX_NETWORK_UPGRADES; idx++) {
            if (idx == Consensus::UPGRADE_SHADOW) continue;
            BOOST_CHECK(ids[i] != NetworkUpgradeInfo[idx].nBranchId);
        }
        for (uint32_t z : {0x2bb40e60U, 0xf5b9230bU, 0xe9ff75a6U, 0xc2d6d0b4U, 0xc8e71055U, 0x4dec4df0U, 0x77190ad8U,
                           0x24e92764U, 0xfa1af9bfU, 0xaae83f5fU, 0xf77962d3U, 0xf77962d4U, 0xf77962d5U}) {
            BOOST_CHECK(ids[i] != z);
        }
    }

    // Each network's own IDs, and only on it.
    const Consensus::Params& m = Params(CBaseChainParams::MAIN).GetConsensus();
    const Consensus::Params& slow = TestNet("slow").GetConsensus();
    const Consensus::Params& legacy = TestNet("legacy").GetConsensus();
    BOOST_CHECK_EQUAL(NetworkBranchId(Consensus::UPGRADE_SHADOW, slow), SLOW_SHADOW_BRANCH_ID);
    BOOST_CHECK_EQUAL(NetworkBranchId(Consensus::UPGRADE_VAULT, slow), SLOW_VAULT_BRANCH_ID);
    BOOST_CHECK_EQUAL(NetworkBranchId(Consensus::UPGRADE_SHADOW, legacy), LEGACY_SHADOW_BRANCH_ID);
    BOOST_CHECK_EQUAL(NetworkBranchId(Consensus::UPGRADE_VAULT, legacy), NetworkUpgradeInfo[Consensus::UPGRADE_VAULT].nBranchId);
    BOOST_CHECK(NetworkBranchId(Consensus::UPGRADE_VAULT, slow) != NetworkBranchId(Consensus::UPGRADE_VAULT, m));
    BOOST_CHECK_EQUAL(NetworkBranchId(Consensus::UPGRADE_VAULT, m), 0x6d5b7a31U);
    BOOST_CHECK(IsConsensusBranchId(SLOW_VAULT_BRANCH_ID, slow));
    BOOST_CHECK(!IsConsensusBranchId(SLOW_VAULT_BRANCH_ID, m));
    BOOST_CHECK(!IsConsensusBranchId(SLOW_VAULT_BRANCH_ID, legacy));
    BOOST_CHECK(!IsConsensusBranchId(0x6d5b7a31, slow));          // slow's Vault is its own
    BOOST_CHECK(IsConsensusBranchId(0x6d5b7a31, m));
    BOOST_CHECK(IsConsensusBranchId(LEGACY_SHADOW_BRANCH_ID, legacy));
    BOOST_CHECK(!IsConsensusBranchId(LEGACY_SHADOW_BRANCH_ID, slow));
    BOOST_CHECK(!IsConsensusBranchId(SLOW_SHADOW_BRANCH_ID, legacy));

    // The epoch before each (the "old-consensus-branch-id" diagnosis), with a split height for the test.
    const int HS = 3000000;
    Consensus::Params s = slow, l = legacy;
    s.vUpgrades[Consensus::UPGRADE_SHADOW].nActivationHeight = HS + 1;
    l.vUpgrades[Consensus::UPGRADE_SHADOW].nActivationHeight = HS + 1;
    s.vUpgrades[Consensus::UPGRADE_VAULT].nActivationHeight = HS + 10080;
    const uint32_t canopy = NetworkUpgradeInfo[Consensus::UPGRADE_CANOPY].nBranchId;
    BOOST_CHECK_EQUAL(PrevEpochBranchId(SLOW_SHADOW_BRANCH_ID, s), canopy);
    BOOST_CHECK_EQUAL(PrevEpochBranchId(SLOW_VAULT_BRANCH_ID, s), SLOW_SHADOW_BRANCH_ID);
    BOOST_CHECK_EQUAL(PrevEpochBranchId(LEGACY_SHADOW_BRANCH_ID, l), canopy);
    BOOST_CHECK_EQUAL(PrevEpochBranchId(0x6d5b7a31, m), canopy);   // mainnet unchanged
    BOOST_CHECK_EQUAL(CurrentEpochBranchId(HS, s), canopy);
    BOOST_CHECK_EQUAL(CurrentEpochBranchId(HS + 1, s), SLOW_SHADOW_BRANCH_ID);
    BOOST_CHECK_EQUAL(CurrentEpochBranchId(HS + 10080, s), SLOW_VAULT_BRANCH_ID);
    BOOST_CHECK_EQUAL(CurrentEpochBranchId(HS + 1, l), LEGACY_SHADOW_BRANCH_ID);
    BOOST_CHECK_EQUAL(CurrentEpochBranchId(9000000, l), LEGACY_SHADOW_BRANCH_ID);
    BOOST_CHECK_EQUAL(CurrentEpoch(HS + 1, s), (int)Consensus::UPGRADE_SHADOW);
    BOOST_CHECK(IsActivationHeight(HS + 1, s, Consensus::UPGRADE_SHADOW));   // a new epoch: the history tree restarts
    // The epoch keeps the Equihash parameters (192, 7) of the epoch before it.
    BOOST_CHECK_EQUAL(CurrentEpoch(HS, s), (int)Consensus::UPGRADE_CANOPY);
}

BOOST_AUTO_TEST_CASE(shadow_difficulty_reset)
{
    // At H_S + 1 the hash rate is the testnet's, not mainnet's: the shadow upgrade's activation block and
    // the next nPowAveragingWindow blocks are at the PoW limit, so the window that follows holds only
    // post-split blocks; minimum-difficulty blocks are allowed from H_S + 1. Mainnet's parameters on the
    // same chain keep mainnet's difficulty.
    const int HS = 3000000;
    const Consensus::Params& m = Params(CBaseChainParams::MAIN).GetConsensus();
    const unsigned int limit = UintToArith256(m.powLimit).GetCompact();
    const uint32_t hard = 0x1d01d7f0;   // a mainnet-like target, far below the limit
    for (const Profile& pr : SHADOW) {
        Consensus::Params c = TestNet(pr.name).GetConsensus();
        BOOST_CHECK(c.powLimit == m.powLimit);
        c.vUpgrades[Consensus::UPGRADE_SHADOW].nActivationHeight = HS + 1;
        c.nPowAllowMinDifficultyBlocksAfterHeight = HS;   // as the profile sets it once H_S is set
        const int window = c.nPowAveragingWindow;

        // Mainnet's history up to H_S, then blocks at whatever the rule asks.
        std::vector<CBlockIndex> blocks = Chain(HS - 3 * window, HS + 3 * window, hard);
        const auto at = [&](int h) -> CBlockIndex* { return &blocks[h - (HS - 3 * window)]; };
        for (int h = HS + 1; h <= HS + 3 * window; h++) {
            CBlockHeader next;
            next.nTime = at(h - 1)->nTime + 75;    // on time: the minimum-difficulty rule does not apply
            at(h)->nBits = GetNextWorkRequired(at(h - 1), &next, c);
        }
        // Through H_S: mainnet's difficulty (the reset does not touch copied blocks).
        CBlockHeader onTime;
        onTime.nTime = at(HS - 1)->nTime + 75;
        BOOST_CHECK(GetNextWorkRequired(at(HS - 1), &onTime, c) == GetNextWorkRequired(at(HS - 1), &onTime, m));
        BOOST_CHECK(GetNextWorkRequired(at(HS - 1), &onTime, c) != limit);
        // H_S + 1 .. H_S + 1 + window: the limit.
        for (int h = HS + 1; h <= HS + 1 + window; h++) BOOST_CHECK_EQUAL(at(h)->nBits, limit);
        // After it the averaging window holds only limit blocks: on-time blocks move it by at most the
        // adjustment step, never back towards mainnet's difficulty.
        for (int h = HS + 2 + window; h <= HS + 3 * window; h++) {
            arith_uint256 t;
            t.SetCompact(at(h)->nBits);
            BOOST_CHECK(t <= UintToArith256(c.powLimit));
            BOOST_CHECK(t > UintToArith256(c.powLimit) / 2);
        }
        // The minimum-difficulty rule from H_S + 1: a late block (more than 6 x 75 s) may be at the limit.
        CBlockHeader late;
        late.nTime = at(HS + 3 * window - 1)->nTime + 6 * 75 + 1;
        BOOST_CHECK_EQUAL(GetNextWorkRequired(at(HS + 3 * window - 1), &late, c), limit);
        // Mainnet's parameters on the same chain: no reset at H_S + 1, no minimum-difficulty blocks.
        CBlockHeader lateMain;
        lateMain.nTime = at(HS)->nTime + 6 * 75 + 1;
        BOOST_CHECK(GetNextWorkRequired(at(HS), &lateMain, m) != limit);
    }
}

BOOST_AUTO_TEST_SUITE_END()
