// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yellowback/params.h"

#include <stdexcept>

namespace yellowback {

namespace {

/** The §3.1 mainnet/testnet column. Every rule-read value is compiled in (K10). */
void SetCommon(Params& p)
{
    p.minMint   = 10000;      // $100
    p.maxMint   = 250000;     // $2,500 (H-12: guarded issuance for the first parameter lifetime; DigiByte $100,000)
    p.minOutput = 100;        // $1.00 (DigiByte minOutputAmount)
    p.maxOutput = 10000000;   // $100,000 (param; DigiByte's maxMintAmount)
    p.tokenValue = TOKEN_VALUE;
    p.refWindow  = REF_WINDOW;

    p.pFastWindow = 96;   p.pFastMinFill = 48;     // ceil(W/2)
    p.pMidWindow  = 576;  p.pMidMinFill  = 384;    // ceil(2W/3) (L9)
    p.pSlowWindow = 2016; p.pSlowMinFill = 1344;

    p.nReg            = 576;
    p.peerLag         = 10;
    p.peerMin         = 5;
    p.deviationBps    = 1000;
    p.accuracyBandBps = 300;
    p.payeeWindow     = 100;

    p.feeMin = 50000000;            // 0.5 YEC (V10)
    p.feeBps = 15;                  // H-4 (was 25)

    p.grace              = 34560;   // 30 d
    p.claimDelay         = 1152;    // CLAIM_DELAY 1 d (U-23): the window in which one attestor can cancel a claim
    p.claimThresholdBps  = 11000;
    p.supplyCapBps       = 1500;    // 15 % of market cap (V21)
    p.globalRatioHaltBps = 30000;       // H-11 (was 25,000)
    p.recapRatioBps      = 60000;       // W16: twice the halt floor (H-11, was 50,000)
    p.divergenceBps      = 2000;
    p.classMin[0] = 34560;  p.classMax[0] = 103680;  p.baseRatioBps[0] = 50000;   // A: 30-90 d
    // H-5: classes B and C are disabled by an empty term range [classMax[0] + 1, classMax[0]]
    // (classMin > classMax): MINT-2 refuses every term in them, no code path changes and the ranges
    // stay contiguous. The enabled bounds were B 103,681-420,480 (90-365 d) and C 420,481-2,102,400
    // (1-5 y, MAX_LOCK, V19).
    p.classMin[1] = 103681; p.classMax[1] = 103680;  p.baseRatioBps[1] = 40000;   // B: disabled (H-5)
    p.classMin[2] = 103681; p.classMax[2] = 103680;  p.baseRatioBps[2] = 30000;   // C: disabled (H-5)

    p.volWindow         = 2016;
    p.volStep           = 48;
    p.volPeriodsPerYear = 8760;     // K13: equal on every network
    p.sigmaRefBps       = 10000;
    p.sigmaMultMaxBps   = 30000;

    p.nPenalty       = 288;         // L6 wallet defaults
    p.accuracyWindow = 576;
    p.payeeTiltBps   = 10000;

    // v3 §3.1: price attestation
    p.attestArmMin        = 7;      // ARM-1 (H-2; D-4 had 5)
    p.attestArmDelay      = 1152;   // ARM-2: one day
    p.attestRequired      = true;   // W15
    p.bundleCarrier       = BundleCarrier::SCRIPTSIG;   // W2
    p.nSlots              = 9;
    p.mSelect             = 4;
    p.kSlack              = 2;
    p.bundleMax           = 6;      // the 520-byte push
    p.qLowBps             = 3333;
    p.qHighBps            = 6667;
    p.attestMaxAge        = 20;     // 2 k (R4)
    p.pinWindow           = 288;    // PIN-1/2
    p.pinDeltaBps         = 500;
    p.pinMinTags          = 3;
    p.pinMinBundles       = 2;
    p.divergeBpsAttest    = 1500;   // MINT-10
    p.emergencyRatioBps   = 10500;  // NOT-1, RED-4(b)
    p.emergencyPersist    = 48;
    p.emergencyNoticeTtl  = 1152;
    p.residualMinZat      = 100000; // RED-5
    p.attestFeeBps        = 5000;   // AFEE-1 (H-4; D-3 had 2,500)
    p.bondMin             = 20000 * COIN;
    p.bondMinLock         = 420480; // one year
    p.bondMaturity        = 16128;  // two weeks
    p.ageCap              = 207360; // 180 d
    p.foundingWindow      = 8064;   // 7 d
    p.dormancyBlocks      = 16128;
    p.dormancyMinBundles  = 20;
    p.dormancyCheck       = 48;     // S15
    p.carrierValue        = 10000;  // wallet policy
    p.attestInterval      = 10;     // k, agent policy
    p.walletConfirmations = 6;      // wallet policy
    p.mintRequiresArmed   = true;   // H-1: MINT-4 refuses an unarmed mint (mint-halted-unarmed)
}

} // namespace

Params::Params()
    : startHeight(0), claimDelay(0),
      pFastWindow(0), pMidWindow(0), pSlowWindow(0), pFastMinFill(0), pMidMinFill(0), pSlowMinFill(0),
      nReg(0), peerLag(0), peerMin(0), deviationBps(0), accuracyBandBps(0), payeeWindow(0),
      feeMin(0), feeBps(0),
      grace(0), claimThresholdBps(0), supplyCapBps(0), globalRatioHaltBps(0), recapRatioBps(0), divergenceBps(0),
      volWindow(0), volStep(0), volPeriodsPerYear(0), sigmaRefBps(0), sigmaMultMaxBps(0),
      minMint(0), maxMint(0), minOutput(0), maxOutput(0), tokenValue(0), refWindow(0),
      nPenalty(0), accuracyWindow(0), payeeTiltBps(0),
      attestArmMin(0), attestArmDelay(0), attestRequired(true), bundleCarrier(BundleCarrier::SCRIPTSIG),
      nSlots(0), mSelect(0), kSlack(0), bundleMax(0), qLowBps(0), qHighBps(0), attestMaxAge(0),
      pinWindow(0), pinDeltaBps(0), pinMinTags(0), pinMinBundles(0), divergeBpsAttest(0),
      emergencyRatioBps(0), emergencyPersist(0), emergencyNoticeTtl(0), residualMinZat(0), attestFeeBps(0),
      bondMin(0), bondMinLock(0), bondMaturity(0), ageCap(0), foundingWindow(0),
      dormancyBlocks(0), dormancyMinBundles(0), dormancyCheck(0), carrierValue(0), attestInterval(0), walletConfirmations(0),
      mintRequiresArmed(false)
{
    for (int i = 0; i < NUM_CLASSES; i++) {
        classMin[i] = classMax[i] = baseRatioBps[i] = 0;
    }
}

int Params::ClassForLockBlocks(int64_t lockBlocks) const
{
    for (int i = 0; i < NUM_CLASSES; i++) {
        if (lockBlocks >= classMin[i] && lockBlocks <= classMax[i]) return i;
    }
    return -1;
}

const Params& MainParams()
{
    static Params p = [] {
        Params m;
        m.network = "main";
        SetCommon(m);
        m.addressVersion = { 0x1F, 0xE4 };   // renders "ye…" (D10)
        // U-22: startHeight is the UPGRADE_VAULT activation height and attestorSetId the network's
        // YED set; both are unset on mainnet until the gate-passing release (P8) sets them, so YED
        // is off. (The v3 miner-enforced START_HEIGHT 3,075,000 and its sunset are retired, §6.)
        m.startHeight = 0;
        return m;
    }();
    return p;
}

const Params& TestParams()
{
    static Params p = [] {
        Params t;
        t.network = "test";
        SetCommon(t);
        t.addressVersion = { 0x20, 0x07 };   // renders "yt…" (D10)
        // U-22: unset until a release sets the UPGRADE_VAULT height and the attestor set (YED off).
        t.startHeight = 0;
        return t;
    }();
    return p;
}

std::optional<BundleCarrier> ParseBundleCarrier(const std::string& name)
{
    if (name == "scriptsig") return BundleCarrier::SCRIPTSIG;
    if (name == "opreturn") return BundleCarrier::OP_RETURN;
    if (name == "either") return BundleCarrier::EITHER;
    return std::nullopt;
}

const char* BundleCarrierName(BundleCarrier carrier)
{
    switch (carrier) {
    case BundleCarrier::SCRIPTSIG: return "scriptsig";
    case BundleCarrier::OP_RETURN: return "opreturn";
    case BundleCarrier::EITHER: return "either";
    }
    return "unknown";
}

/** The §3.1 regtest column; only the seven arguments come from the chain and flags (M13). */
Params RegtestParams(int startHeight, int sigmaRefBps, int supplyCapBps, const uint256& attestorSetId,
                     int attestArmMin, BundleCarrier bundleCarrier, bool mintRequiresArmed)
{
    Params r;
    r.network = "regtest";
    SetCommon(r);
    r.addressVersion = { 0x20, 0x02 };       // renders "yr…" (D10)
    r.pFastWindow = 8;  r.pFastMinFill = 4;
    r.pMidWindow  = 24; r.pMidMinFill  = 16;
    r.pSlowWindow = 64; r.pSlowMinFill = 43;
    r.nReg    = 24;
    r.peerLag = 4;
    r.peerMin = 3;
    r.payeeWindow = 10;
    r.grace = 24;
    r.claimDelay = 10;
    // The hardening plan's mainnet values (H-4, H-11, H-12) stay out of the regtest column: its
    // scripts' fee, cap and recapitalisation arithmetic is written against the v3 values.
    r.feeBps             = 25;
    r.attestFeeBps       = 2500;
    r.maxMint            = 1000000;
    r.globalRatioHaltBps = 25000;
    r.recapRatioBps      = 50000;
    r.classMin[0] = 48;  r.classMax[0] = 96;
    r.classMin[1] = 97;  r.classMax[1] = 144;
    r.classMin[2] = 145; r.classMax[2] = 240;
    r.volWindow = 64;
    r.volStep   = 8;
    r.nPenalty       = 12;
    r.accuracyWindow = 24;
    // v3 §3.1 regtest column
    r.attestArmDelay      = 8;
    r.nSlots              = 5;
    r.mSelect             = 2;
    r.kSlack              = 1;
    r.attestMaxAge        = 8;      // k = 4
    r.pinWindow           = 16;
    r.pinMinTags          = 2;
    r.emergencyPersist    = 4;
    r.emergencyNoticeTtl  = 64;
    r.bondMin             = 10 * COIN;
    r.bondMinLock         = 200;
    r.bondMaturity        = 8;
    r.ageCap              = 64;
    r.foundingWindow      = 16;
    r.dormancyBlocks      = 16;
    r.dormancyMinBundles  = 2;
    r.dormancyCheck       = 4;
    r.attestInterval      = 4;
    r.walletConfirmations = 1;
    // the seven flags
    r.startHeight        = startHeight;
    r.sigmaRefBps        = sigmaRefBps;
    r.supplyCapBps       = supplyCapBps;
    r.attestorSetId      = attestorSetId;
    r.attestArmMin       = attestArmMin;
    r.bundleCarrier      = bundleCarrier;
    r.mintRequiresArmed  = mintRequiresArmed;
    return r;
}

const Params& SelectParams(const std::vector<Params>& sets, int height)
{
    const Params* best = nullptr;
    for (const Params& p : sets) {
        if (p.startHeight <= height && (!best || p.startHeight >= best->startHeight)) best = &p;
    }
    return best ? *best : sets.front();
}

const Params& ParamsForNetwork(const std::string& networkId)
{
    if (networkId == "main") return MainParams();
    if (networkId == "test") return TestParams();
    if (networkId == "regtest") {
        static Params r = RegtestParams(0, 0, 0, uint256());
        return r;
    }
    throw std::runtime_error("yellowback: unknown network " + networkId);
}

} // namespace yellowback
