// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yellowback/state.h"

#include "arith_uint256.h"
#include "crypto/pq/scheme.h"
#include "crypto/sha256.h"
#include "script/script.h"
#include "vault/act.h"
#include "vault/template.h"
#include "yellowback/attest.h"
#include "yellowback/bundle.h"
#include "yellowback/math.h"
#include "yellowback/script.h"

#include <algorithm>
#include <tuple>
#include <map>
#include <set>

namespace yellowback {

namespace verdict {
const char* const OK = "ok";
const char* const BURNED = "burned";
const char* const NON_YELLOWBACK = "non-yellowback";
const char* const BAD_MINT_AMOUNT = "bad-mint-amount";
const char* const BAD_MINT_CLASS = "bad-mint-class";
const char* const BAD_MINT_LOCK_HEIGHT = "bad-mint-lock-height";
const char* const BAD_MINT_REF_HEIGHT = "bad-mint-ref-height";
const char* const BAD_MINT_OUTPUTS = "bad-mint-outputs";
const char* const BAD_MINT_OWNER_KEY = "bad-mint-owner-key";
const char* const BAD_MINT_VAULT_SCRIPT = "bad-mint-vault-script";
const char* const MINT_NOT_ACTIVE = "mint-not-active";
const char* const MINT_HALTED_NO_PRICE = "mint-halted-no-price";
const char* const MINT_HALTED_GLOBAL_RATIO = "mint-halted-global-ratio";
const char* const MINT_HALTED_DIVERGENCE = "mint-halted-divergence";
const char* const MINT_HALTED_UNARMED = "mint-halted-unarmed";
const char* const BAD_MINT_COLLATERAL = "bad-mint-collateral";
const char* const MINT_UNSATISFIABLE = "mint-unsatisfiable";
const char* const MINT_SUPPLY_CAP = "mint-supply-cap";
const char* const BAD_MINT_TOKEN_OUTPUT = "bad-mint-token-output";
const char* const BAD_MINT_FEE = "bad-mint-fee";
const char* const BAD_TRANSFER_ASSIGNMENT = "bad-transfer-assignment";
const char* const TRANSFER_OVER_ASSIGNED = "transfer-over-assigned";
const char* const TRANSFER_NO_YED_INPUT = "transfer-no-yed-input";
const char* const VAULT_SPEND_MALFORMED = "vault-spend-malformed";
const char* const VAULT_SPEND_MISSING_BURN = "vault-spend-missing-burn";
const char* const VAULT_SPEND_SHORT_BURN = "vault-spend-short-burn";
const char* const VAULT_SPEND_BAD_FEE = "vault-spend-bad-fee";
const char* const VAULT_SPEND_BAD_PAYEE = "vault-spend-bad-payee";
const char* const BAD_REDEEM_EARLY_FEE = "bad-redeem-early-fee";
const char* const VAULT_CLAIM_NOT_UNDERWATER = "vault-claim-not-underwater";
const char* const MINT9_NO_BUNDLE = "mint9-no-bundle";
const char* const MINT9_BUNDLE_PREFIX = "mint9-bundle-";
const char* const MINT10_DIVERGED = "mint10-diverged";
const char* const RED1_BUNDLE_PREFIX = "red1-bundle-";
const char* const RED5_RESIDUAL = "red5-residual";
const char* const AFEE1_FEE = "afee1-fee";
const char* const VAULT_CLAIM_INTENTS = "vault-claim-intents";
const char* const INTENT_SPEND_MALFORMED = "intent-spend-malformed";
const char* const INTENT_CANCEL_RESIDUAL = "intent-cancel-residual";
const char* const INTENT_CANCEL_NO_VAULT = "intent-cancel-no-vault";
const char* const YED_TEMPLATE_OUTPUT = "yed-template-output";
const char* const BAD_YED_HOLDER = "bad-yed-holder";
const char* const BUNDLE_STAT = "stat";
const char* const ATTESTOR_REGISTER_RETIRED = "attestor-register-retired";
const char* const ATTESTOR_REVIVE_RETIRED = "attestor-revive-retired";
} // namespace verdict

// ---------------------------------------------------------------------------
// Shared helpers (§3.7 lookups)

namespace {

/** The key hash of a P2PKH scriptPubKey (OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG). */
std::optional<CKeyID> P2PKHKey(const CScript& s)
{
    if (s.size() != 25 || s[0] != OP_DUP || s[1] != OP_HASH160 || s[2] != 20 || s[23] != OP_EQUALVERIFY || s[24] != OP_CHECKSIG) {
        return std::nullopt;
    }
    return CKeyID(uint160(std::vector<unsigned char>(s.begin() + 3, s.begin() + 23)));
}

CScript P2PKHOf(const CKeyID& key)
{
    return CScript() << OP_DUP << OP_HASH160 << ToByteVector(key) << OP_EQUALVERIFY << OP_CHECKSIG;
}

/** A YED-tagged V (or I) among the outputs (U-23): the only template outputs the module itself creates. */
bool IsYedVaultOutput(const CScript& spk)
{
    vault::VaultParams v;
    return vault::ParseVault(spk, v) && v.tag == YED_TAG;
}

bool IsYedIntentOutput(const CScript& spk, vault::IntentParams* out = nullptr)
{
    vault::IntentParams i;
    if (!vault::ParseIntent(spk, i) || i.tag != YED_TAG) return false;
    if (out) *out = i;
    return true;
}

/** Tags[h] for h >= START_HEIGHT (nothing below it is read). */
std::optional<TagRecord> TagAt(const StateView& view, const Params& p, int64_t h)
{
    if (h < p.startHeight || h < 0 || h > 0xFFFFFFFFLL) return std::nullopt;
    return State(const_cast<StateView&>(view)).GetTag((uint32_t)h);
}

std::optional<Judgement> JudgementAt(const StateView& view, const Params& p, int64_t h)
{
    if (h < p.startHeight || h < 0 || h > 0xFFFFFFFFLL) return std::nullopt;
    return State(const_cast<StateView&>(view)).GetJudgement((uint32_t)h);
}

/** Quote-tag prices with lo < h <= hi (heights >= START_HEIGHT), ascending height, skipping the keys in `excluded` (PIN-1). */
std::vector<std::pair<int64_t, MicroUsd>> QuotePrices(const StateView& view, const Params& p, int64_t lo, int64_t hi,
                                                      const std::vector<uint160>& excluded = std::vector<uint160>())
{
    std::vector<std::pair<int64_t, MicroUsd>> out;
    for (int64_t h = std::max<int64_t>(lo + 1, p.startHeight); h <= hi; h++) {
        std::optional<TagRecord> t = TagAt(view, p, h);
        if (!t.has_value() || !t->IsQuote()) continue;
        if (std::find(excluded.begin(), excluded.end(), t->payoutKey) != excluded.end()) continue;
        out.push_back(std::make_pair(h, (MicroUsd)t->priceMicroUsd));
    }
    return out;
}

/** median(W, H) (PRICE-1): lowerMedian of the quote prices in (H - W, H], undefined below the window's fill. */
std::optional<MicroUsd> WindowMedian(const std::vector<std::pair<int64_t, MicroUsd>>& prices, int64_t height, int window, int minFill)
{
    std::vector<MicroUsd> v;
    for (const auto& hp : prices) {
        if (hp.first > height - window && hp.first <= height) v.push_back(hp.second);
    }
    if ((int64_t)v.size() < (int64_t)minFill) return std::nullopt;
    return LowerMedian(v);
}

/** blockHash(h) as the overlay knows it: Snapshots[h].blockHash for a stored, non-virtual snapshot (§3.8 BUNDLE-1, EQV-1, REV-1). */
std::optional<uint256> BlockHashAt(const StateView& view, const Params& p, int64_t h)
{
    if (h < p.startHeight || h < 0 || h > 0xFFFFFFFFLL) return std::nullopt;
    std::optional<Snapshot> s = State(const_cast<StateView&>(view)).GetSnapshot((uint32_t)h);
    if (!s.has_value() || s->blockHash.IsNull()) return std::nullopt;
    return s->blockHash;
}

/** What a transaction's verified bundle contributes to BundleLog[H] (R12) and to its TxLog entry. */
struct BundleFacts
{
    bool verified;                       //!< BUNDLE-1 held
    bool carrierPresent;                 //!< some carrier-shaped input exists (MINT-9's "no bundle" vs "bundle-<reason>")
    std::optional<MicroUsd> aMint, aClaim;
    std::vector<uint16_t> seqs;          //!< A, bundle order
    std::vector<uint16_t> selected;
    std::vector<std::tuple<uint16_t, int64_t, uint32_t>> pairs;   //!< (seq, price, citedHeight) of every attestation
    std::string reason;                  //!< BUNDLE-1's first failure when !verified

    BundleFacts() : verified(false), carrierPresent(false) {}
};

/** Per-evaluation memo: E(R) and Snapshots[h] are read repeatedly by a block's transactions. */
struct EvalContext
{
    State& st;
    const Params& params;
    const int height;
    SigCache* cache;
    std::map<int, std::vector<CKeyID>> eligible;
    std::map<int64_t, std::optional<Snapshot>> snapshots;
    // The BundleLog[H] accumulator (R12): flushed by EvaluateBlock before SNAP; a standalone ProcessTx never writes it.
    bool anyBundle;
    std::vector<MicroUsd> aMints, aClaims;
    std::set<uint16_t> selectedUnion;
    std::set<std::tuple<uint16_t, int64_t, uint32_t>> pairUnion;

    EvalContext(State& st, const Params& p, int h, SigCache* cache = nullptr) : st(st), params(p), height(h), cache(cache), anyBundle(false) {}

    /** ARMED at R (W15 folded in). */
    bool Armed(int64_t refHeight)
    {
        const std::optional<Snapshot>& S = Snap(refHeight);
        return S.has_value() && params.IsArmed(S->attest.IsArmed());
    }

    /** BUNDLE-1 for the transaction under evaluation, recorded into the BundleLog accumulator when it holds (R12). */
    BundleFacts Bundle(const CTransaction& tx, int64_t refHeight, const std::vector<unsigned char>& selector, bool skipVin0)
    {
        BundleFacts f;
        std::string why;
        f.carrierPresent = FindCarrierInput(tx, skipVin0, &why).has_value() || why == "two-carriers";
        BundleVerdict v = VerifyTxBundle(st.View(), params, tx, (int)refHeight, selector, skipVin0, cache, &f.selected);
        f.verified = v.ok;
        f.reason = v.reason;
        if (!v.ok) return f;
        f.aMint = v.aMint;
        f.aClaim = v.aClaim;
        for (const Attestation& a : v.C) {
            f.seqs.push_back(a.seq);
            f.pairs.push_back(std::make_tuple(a.seq, (int64_t)a.priceMicroUsd, a.citedHeight));
        }
        anyBundle = true;
        if (f.aMint.has_value()) aMints.push_back(f.aMint.value());
        if (f.aClaim.has_value()) aClaims.push_back(f.aClaim.value());
        selectedUnion.insert(f.selected.begin(), f.selected.end());
        pairUnion.insert(f.pairs.begin(), f.pairs.end());
        return f;
    }

    /** BundleLog[H] from the accumulator; nullopt when no bundle was verified in this block. */
    std::optional<BundleLogRecord> BundleRow() const
    {
        if (!anyBundle) return std::nullopt;
        BundleLogRecord row;
        row.aMint = LowerMedian(aMints).value_or(0);
        row.aClaim = LowerMedian(aClaims).value_or(0);
        row.selectedSeqs.assign(selectedUnion.begin(), selectedUnion.end());
        for (const auto& sp : pairUnion) {
            row.seqs.push_back(std::get<0>(sp));
            row.prices.push_back(std::get<1>(sp));
            row.citedHeights.push_back(std::get<2>(sp));
        }
        return row;
    }

    const std::vector<CKeyID>& Eligible(int refHeight)
    {
        auto it = eligible.find(refHeight);
        if (it != eligible.end()) return it->second;
        return eligible[refHeight] = EligiblePayees(st.View(), params, refHeight);
    }

    const std::optional<Snapshot>& Snap(int64_t h)
    {
        auto it = snapshots.find(h);
        if (it != snapshots.end()) return it->second;
        return snapshots[h] = SnapshotAt(st, params, h);
    }
};

/** A vault being spent by the transaction under evaluation. */
struct SpentVault
{
    COutPoint outpoint;
    VaultRecord record;
};

bool Contains(const std::vector<SpentVault>& v, const COutPoint& o)
{
    for (const SpentVault& s : v) {
        if (s.outpoint == o) return true;
    }
    return false;
}

bool ContainsKey(const std::vector<CKeyID>& keys, const CKeyID& k)
{
    return std::find(keys.begin(), keys.end(), k) != keys.end();
}

/** The TxLog fields a verified bundle fills (§3.6 TxLog). */
void LogBundle(TxLogRecord& log, const BundleFacts& f)
{
    if (!f.verified) return;
    log.aMint = f.aMint.value_or(0);
    log.aClaim = f.aClaim.value_or(0);
    log.bundleSeqs = f.seqs;
}

/**
 * AFEE-1 (the attestor-fee clause of MINT-8 / RED-3): vout[attestFeeVout] is P2PKH(bondPubKey(s)) for
 * some s in A, pays >= attestFeeZat and is none of the excluded vouts. Returns the payee's seq.
 * AFEE-0 (not ARMED or A empty) is the caller's: it does not call this.
 */
std::optional<uint16_t> AttestFeeOk(EvalContext& ctx, const CTransaction& tx, uint8_t attestFeeVout, const std::vector<uint16_t>& A,
                                    const std::set<unsigned int>& excluded, CAmount attestFeeZat)
{
    if (attestFeeVout == FEE_VOUT_NONE || attestFeeVout >= tx.vout.size() || excluded.count(attestFeeVout)) return std::nullopt;
    std::optional<CKeyID> key = P2PKHKey(tx.vout[attestFeeVout].scriptPubKey);
    if (!key.has_value()) return std::nullopt;
    if (tx.vout[attestFeeVout].nValue < attestFeeZat) return std::nullopt;
    for (uint16_t seq : A) {
        std::optional<AttestorRecord> rec = ctx.st.GetAttestor(seq);
        if (!rec.has_value()) continue;
        CPubKey pk = rec->BondKey();
        if (pk.IsValid() && pk.GetID() == key.value()) return seq;
    }
    return std::nullopt;
}

void SetVault(VaultRecord& v, const Payload& p, const Params& params, const CTransaction& tx, int height)
{
    v.ownerPubKey = p.ownerKeyBytes;
    v.termClass = p.termClass;
    v.lockHeight = (int32_t)p.lockHeight;
    v.claimHeight = (int32_t)((int64_t)p.lockHeight + params.grace);
    v.collateralZat = tx.vout.empty() ? 0 : tx.vout[0].nValue;
    v.mintedCents = p.cents;
    v.mintHeight = height;
    v.refHeight = (int32_t)p.refHeight;
    v.appHeight = (int32_t)((int64_t)p.refHeight + 1);     // IT-1: MINT-3 passed exactly this V
    v.ownerHeight = v.appHeight;                           // IT-1 (extended): the owner redeems in term too
}

// ---------------------------------------------------------------------------
// MINT-2..10 (§3.8). Not ARMED at R: the v2 clause order MINT-2..8 exactly (SERIALISATION.md §3 D),
// so v2 verdicts are unchanged. ARMED: the v3 plan's evaluation order (R15) — MINT-2, 3, 4, 6, 7, 8,
// then MINT-9, AFEE-1 (the attestor-fee clause of MINT-8, which needs A), MINT-5 (which needs pMint)
// and MINT-10 — so bundle signatures are verified only for a mint that has paid its pool fee.

/** What MINT evaluation learns beyond the verdict (TxLog fields). */
struct MintFacts
{
    BundleFacts bundle;
    CAmount attestFeeZat;
    std::optional<uint16_t> attestPayee;

    MintFacts() : attestFeeZat(0) {}
};

std::string MintVerdict(EvalContext& ctx, const CTransaction& tx, const Payload& p, unsigned int opReturnIndex, const Totals& totals, MintFacts& facts)
{
    const Params& P = ctx.params;
    const int64_t H = ctx.height;
    // MINT-2 (signed 64-bit arithmetic, M1)
    if (!P.IsValidClass(p.termClass)) return verdict::BAD_MINT_CLASS;
    if ((Cents)p.cents < P.minMint || (Cents)p.cents > P.maxMint) return verdict::BAD_MINT_AMOUNT;
    const int64_t lock = p.lockHeight, ref = p.refHeight;
    if (!(lock + (int64_t)P.grace < (int64_t)LOCKTIME_THRESHOLD)) return verdict::BAD_MINT_LOCK_HEIGHT;
    if (!(H - P.refWindow <= ref && ref <= H - 1) || ref < P.startHeight) return verdict::BAD_MINT_REF_HEIGHT;
    if (!(lock > ref) || lock - ref < P.classMin[p.termClass] || lock - ref > P.classMax[p.termClass]) return verdict::BAD_MINT_LOCK_HEIGHT;
    // MINT-3
    if (tx.vout.size() < 3) return verdict::BAD_MINT_OUTPUTS;
    // The owner is a post-quantum key id, scheme || keyHash in the 33 owner bytes (quantum spec §3.1, §3.2).
    const CPQKeyID owner = OwnerFromBytes(p.ownerKeyBytes);
    if (!vault::IsOwnerValid(owner)) return verdict::BAD_MINT_OWNER_KEY;
    // A Falcon (scheme 0x02) owner only from the Falcon height (quantum plan §4.4, spec A-4, R-A2; the mirror, A-5).
    if (owner.scheme == pq::SCHEME_FN_DSA_512 && !P.IsPQFalconActive(H)) return verdict::BAD_MINT_OWNER_KEY;
    // U-23: the collateral is the primitive's V (tag YED, the attestor set, CLAIM_DELAY, ownerHeight = lockHeight,
    // ownerHeight = appHeight = refHeight + 1, IT-1); v2's P2SH VaultScript and the pre-IT-1 shape (ownerHeight =
    // lockHeight, appHeight = lockHeight + GRACE) are refused for new mints.
    const CScript expected = YedVaultScript(P, owner, ref);
    if (expected.empty() || tx.vout[0].scriptPubKey != expected) return verdict::BAD_MINT_VAULT_SCRIPT;
    // MINT-4 (ACT-5's activation and the PARTICIPATION/ENFORCEMENT halts left with the upgrade, §6: the
    // module is active from START_HEIGHT; NOT_ACTIVE is the virtual snapshot below it)
    const std::optional<Snapshot>& S = ctx.Snap(ref);
    if (!S.has_value()) return verdict::MINT_NOT_ACTIVE;
    if (S->haltMask & HALT_NOT_ACTIVE) return verdict::MINT_NOT_ACTIVE;
    if (S->haltMask & HALT_NO_PRICE) return verdict::MINT_HALTED_NO_PRICE;
    // HALT-2 (amended, W16; IT-5): the global-ratio halt stops a mint only when the mint's class base
    // ratio is below the recapitalisation floor (with the in-term parameter set that is class C only).
    // Every class base exceeds the halt floor, so a mint can only raise the global ratio; the floor
    // keeps the best-backed class open to do so.
    if ((S->haltMask & HALT_GLOBAL_RATIO) && P.baseRatioBps[p.termClass] < P.recapRatioBps) return verdict::MINT_HALTED_GLOBAL_RATIO;
    if (S->haltMask & HALT_DIVERGENCE) return verdict::MINT_HALTED_DIVERGENCE;
    if ((S->haltMask & ~HALT_GLOBAL_RATIO) != 0) return verdict::MINT_NOT_ACTIVE; // an unknown bit: MINT-4 needs every other bit clear
    const bool armed = ctx.Armed(ref);
    // MINT-4 (H-1): with MINT_REQUIRES_ARMED a mint whose R is not ARMED is halted like any other; a claim is unaffected
    if (P.mintRequiresArmed && !armed) return verdict::MINT_HALTED_UNARMED;
    std::optional<MicroUsd> xMint = S->PMint();
    std::optional<MicroUsd> pMint = xMint;
    auto mint5 = [&]() -> const char* {
        if (!pMint.has_value()) return verdict::MINT_HALTED_NO_PRICE;
        std::optional<CAmount> required = RequiredCollateral((Cents)p.cents, MinRatioBps(P.baseRatioBps[p.termClass], S->sigmaMultBps), pMint.value());
        if (!required.has_value()) return verdict::MINT_UNSATISFIABLE;
        if (tx.vout[0].nValue < required.value() || tx.vout[0].nValue < 4 * P.feeMin) return verdict::BAD_MINT_COLLATERAL;
        return nullptr;
    };
    // MINT-5 at its v2 position when not ARMED (pMint = xMint)
    if (!armed) {
        if (const char* v = mint5()) return v;
    }
    // MINT-6 (amended, W20: the cap is soft above the recapitalisation floor; IT-5). A mint that would
    // take supply over the cap is refused only when its class base ratio is below RECAP_RATIO_BPS (class
    // C only with the in-term parameter set; H-10's termClass != 0 proxy is replaced by the ratio test).
    // The cap reads the cross-section xMint: it precedes MINT-9 (R15).
    std::optional<Cents> cap = SupplyCapCents(S->issuedZat, xMint, P.supplyCapBps);
    if (cap.has_value() && totals.supplyCents + (Cents)p.cents > cap.value()
        && P.baseRatioBps[p.termClass] < P.recapRatioBps) return verdict::MINT_SUPPLY_CAP;
    // MINT-7
    if (opReturnIndex == 1) return verdict::BAD_MINT_TOKEN_OUTPUT;
    // TOK-PQ (quantum spec F-7): from the Falcon height the token output is a Falcon TX_PQPKH.
    if (!HolderAllowed(P, H, tx.vout[1].scriptPubKey)) return verdict::BAD_YED_HOLDER;
    // MINT-8 (FEE-0 when E(R) is empty, K11)
    const std::vector<CKeyID>& eligible = ctx.Eligible((int)ref);
    if (!eligible.empty()) {
        const uint8_t fv = p.feeVout;
        if (fv == FEE_VOUT_NONE || fv >= tx.vout.size() || fv == 0 || fv == 1 || fv == opReturnIndex) return verdict::BAD_MINT_FEE;
        std::optional<CKeyID> key = P2PKHKey(tx.vout[fv].scriptPubKey);
        if (!key.has_value() || !ContainsKey(eligible, key.value())) return verdict::BAD_MINT_FEE;
        if (tx.vout[fv].nValue < FeeZat(tx.vout[0].nValue, P.feeMin, P.feeBps)) return verdict::BAD_MINT_FEE;
    }
    if (!armed) return verdict::OK;
    // MINT-9 (ARMED at R: BUNDLE-1 with the empty selector, W9; aMint defined)
    {
        facts.bundle = ctx.Bundle(tx, ref, std::vector<unsigned char>(), false);
        if (!facts.bundle.verified) {
            if (!facts.bundle.carrierPresent) return verdict::MINT9_NO_BUNDLE;
            return std::string(verdict::MINT9_BUNDLE_PREFIX) + facts.bundle.reason;
        }
        if (!facts.bundle.aMint.has_value()) return std::string(verdict::MINT9_BUNDLE_PREFIX) + verdict::BUNDLE_STAT;
        // AFEE-1 (MINT-8's attestor-fee clause; AFEE-0 when not ARMED)
        facts.attestFeeZat = AttestFeeZat(FeeZat(tx.vout[0].nValue, P.feeMin, P.feeBps), P.attestFeeBps);
        std::set<unsigned int> excluded = { 0u, 1u, opReturnIndex, (unsigned int)p.feeVout };
        facts.attestPayee = AttestFeeOk(ctx, tx, p.attestFeeVout, facts.bundle.seqs, excluded, facts.attestFeeZat);
        if (!facts.attestPayee.has_value()) return verdict::AFEE1_FEE;
        // PRICE-2 (revised): pMint = min(xMint, aMint)
        pMint = PriceCombine(xMint, S->PClaim(), facts.bundle.aMint, facts.bundle.aClaim).pMint;
    }
    // MINT-5 (ARMED: after MINT-9, with the combined pMint)
    if (const char* v = mint5()) return v;
    // MINT-10 (ARMED, amended W17: |pFast(R) - aMint| * 10^4 <= DIVERGE_BPS_ATTEST * min(pFast(R), aMint)).
    // The agreement test reads the pools' fast median -- the current market -- not the min-of-windows
    // xMint that MINT-5 prices collateral at: an honest rally lags xMint by a whole slow window and
    // looked like a pool/attestor disagreement. pFast is defined whenever xMint is (PRICE-1).
    {
        const MicroUsd x = S->PFast().value_or(xMint.value()), a = facts.bundle.aMint.value();
        const arith_uint256 diff = x >= a ? arith_uint256(x - a) : arith_uint256(a - x);
        if (diff * arith_uint256(BPS) > arith_uint256(std::max(0, P.divergeBpsAttest)) * arith_uint256(std::min(x, a))) return verdict::MINT10_DIVERGED;
    }
    return verdict::OK;
}

/** MINT-1..10. Returns true when the mint holds (an ACTIVE Vaults entry was created); false makes the transaction invalid (§15.10: no VOID vault). */
bool ApplyMint(EvalContext& ctx, const CTransaction& tx, const uint256& txid, const Payload& p, unsigned int opReturnIndex,
               TxLogRecord& log, Totals& totals)
{
    const Params& P = ctx.params;
    MintFacts facts;
    const std::string v = MintVerdict(ctx, tx, p, opReturnIndex, totals, facts);
    LogBundle(log, facts.bundle);
    VaultRecord vault;
    SetVault(vault, p, P, tx, ctx.height);
    const COutPoint vaultOut(txid, 0);
    if (v == verdict::OK) {
        vault.status = (uint8_t)VaultStatus::ACTIVE;
        if (!ctx.Eligible((int)p.refHeight).empty()) {
            vault.feePaidZat = tx.vout[p.feeVout].nValue;
            log.feeZat = vault.feePaidZat;
            std::optional<CKeyID> key = P2PKHKey(tx.vout[p.feeVout].scriptPubKey);
            log.hasPayee = key.has_value();
            if (key.has_value()) log.payee = key.value();
        }
        if (facts.attestPayee.has_value()) {
            log.attestFeeZat = tx.vout[p.attestFeeVout].nValue;
            log.hasAttestPayee = true;
            log.attestPayee = facts.attestPayee.value();
        }
        ctx.st.Put(keys::Vault(vaultOut), vault);
        TokenRecord tok;
        tok.cents = p.cents;
        tok.nValue = tx.vout[1].nValue;
        tok.scriptPubKey = tx.vout[1].scriptPubKey;
        tok.height = ctx.height;
        const COutPoint tokOut(txid, 1);
        ctx.st.Put(keys::Token(tokOut), tok);
        AssignedOutput a;
        a.outpoint = tokOut;
        a.cents = p.cents;
        a.scriptPubKey = tok.scriptPubKey;
        log.assigned.push_back(a);
        totals.supplyCents += (Cents)p.cents;
        totals.collateralZat += vault.collateralZat;
        totals.activeVaults++;
        log.yedOut = p.cents;
        log.verdict = verdict::OK;
        return true;
    }
    log.verdict = v;
    log.yedOut = 0;
    return false;
}

// ---------------------------------------------------------------------------
// XFER-1..3 for a TRANSFER, or a REDEEM payload that spends no ACTIVE vault

void ApplyTransfer(EvalContext& ctx, const CTransaction& tx, const uint256& txid, const Payload& p, Cents yedIn, TxLogRecord& log)
{
    const Params& P = ctx.params;
    const char* v = verdict::OK;
    for (const Assignment& a : p.assignments) {                                   // XFER-1
        if ((Cents)a.cents < P.minOutput || (Cents)a.cents > P.maxOutput) { v = verdict::BAD_TRANSFER_ASSIGNMENT; break; }
    }
    const int64_t total = p.AssignedCents();
    if (v == verdict::OK && total > yedIn) v = verdict::TRANSFER_OVER_ASSIGNED;    // XFER-2
    if (v == verdict::OK && yedIn <= 0) v = verdict::TRANSFER_NO_YED_INPUT;        // XFER-3
    if (v != verdict::OK) {
        log.verdict = v;                                                            // everything burns (cenotaph)
        log.yedOut = 0;
        return;
    }
    for (const Assignment& a : p.assignments) {
        const COutPoint out(txid, a.vout);
        TokenRecord tok;
        tok.cents = a.cents;
        tok.nValue = tx.vout[a.vout].nValue;
        tok.scriptPubKey = tx.vout[a.vout].scriptPubKey;
        tok.height = ctx.height;
        ctx.st.Put(keys::Token(out), tok);
        AssignedOutput ao;
        ao.outpoint = out;
        ao.cents = a.cents;
        ao.scriptPubKey = tok.scriptPubKey;
        log.assigned.push_back(ao);
    }
    log.yedOut = total;
    log.verdict = total < yedIn ? verdict::BURNED : verdict::OK;
}

// ---------------------------------------------------------------------------
// RED-1..5 over a transaction that spends at least one ACTIVE vault (M3)

/** What RED evaluation learns beyond the verdict (TxLog fields). */
struct RedFacts
{
    BundleFacts bundle;
    CAmount attestFeeZat;
    std::optional<uint16_t> attestPayee;
    CAmount residualZat;
    std::string claimPath;     //!< "a" | "b" | ""
    int claimantVout;          //!< U-23: the claim's claimant intent (-1 on the owner path)
    int residualVout;          //!< U-23: the owner's residual intent (-1 when none is due)

    RedFacts() : attestFeeZat(0), residualZat(0), claimantVout(-1), residualVout(-1) {}
};

/** The path a V spend takes (§15.3 selectors, U-23): 2 and 3 are the owner's, 4 the claim; 1 (a set unlock) is never a YED path. */
bool IsOwnerSelector(uint8_t sel) { return sel == vault::SEL_OWNER || sel == vault::SEL_RELEASED; }

std::string RedVerdict(EvalContext& ctx, const CTransaction& tx, const std::optional<FoundPayload>& fp,
                       const std::vector<SpentVault>& active, const std::optional<uint8_t>& selector, Cents yedIn, RedFacts& facts)
{
    const Params& P = ctx.params;
    const int64_t H = ctx.height;
    // RED-1
    if (active.size() != 1 || tx.vin.empty() || !(active[0].outpoint == tx.vin[0].prevout)) return verdict::VAULT_SPEND_MALFORMED;
    if (!selector.has_value() || !(IsOwnerSelector(selector.value()) || selector.value() == vault::SEL_APP)) return verdict::VAULT_SPEND_MALFORMED;
    if (!fp.has_value() || fp->payload.type != PayloadType::REDEEM) return verdict::VAULT_SPEND_MALFORMED;
    const Payload& p = fp->payload;
    const int64_t ref = p.refHeight;
    if (!(H - P.refWindow <= ref && ref <= H - 1) || ref < P.startHeight) return verdict::VAULT_SPEND_MALFORMED;
    for (const Assignment& a : p.assignments) {
        if ((Cents)a.cents < P.minOutput || (Cents)a.cents > P.maxOutput) return verdict::VAULT_SPEND_MALFORMED;
    }
    // TOK-PQ (quantum spec F-7): from the Falcon height every assigned output is a Falcon TX_PQPKH.
    for (const Assignment& a : p.assignments) {
        if (!HolderAllowed(P, H, tx.vout[a.vout].scriptPubKey)) return verdict::BAD_YED_HOLDER;
    }
    const VaultRecord& vault = active[0].record;
    const bool claim = selector.value() == vault::SEL_APP;
    // U-23: a claim moves the whole vault into intents (the primitive's S-2 holds: every I output carries
    // this V's parameters and Σ I >= V.value); the module wants one claimant intent, at most one owner
    // residual intent (RED-5 decides which is due) and no re-lock.
    std::vector<unsigned int> intents;
    if (claim) {
        const CScript vaultSpk = YedVaultScriptAt(P, vault.Owner(), vault.ownerHeight, vault.appHeight);
        const uint256 vaultHash = vault::ScriptHash256(vaultSpk);
        for (unsigned int j = 0; j < tx.vout.size(); j++) {
            if (tx.vout[j].scriptPubKey == vaultSpk) return verdict::VAULT_CLAIM_INTENTS;
            vault::IntentParams ip;
            if (IsYedIntentOutput(tx.vout[j].scriptPubKey, &ip) && ip.vaultHash == vaultHash) intents.push_back(j);
        }
        if (intents.empty() || intents.size() > 2) return verdict::VAULT_CLAIM_INTENTS;
    }
    const bool armed = claim && ctx.Armed(ref);      // the owner path reads no bundle (RED-1 amended)
    // RED-1 (amended): the claim path needs BUNDLE-1 with selector = vaultOutpoint and aClaim defined when ARMED
    if (armed) {
        facts.bundle = ctx.Bundle(tx, ref, OutPointSelector(active[0].outpoint), true);
        if (!facts.bundle.verified) return std::string(verdict::RED1_BUNDLE_PREFIX) + facts.bundle.reason;
        if (!facts.bundle.aClaim.has_value()) return std::string(verdict::RED1_BUNDLE_PREFIX) + verdict::BUNDLE_STAT;
    }
    // RED-2
    const int64_t burn = yedIn - p.AssignedCents();
    if (burn < vault.mintedCents) return burn <= 0 ? verdict::VAULT_SPEND_MISSING_BURN : verdict::VAULT_SPEND_SHORT_BURN;
    // RED-3 (FEE-0 when E(R) is empty, K11). IT-9 (the D-IT-16 hook, decided 2026-10-07): an owner redeem at a
    // height below lockHeight pays earlyRedeemFeeBps[class] of the collateral on top of FEE-1, through the same
    // payee output (AFEE-1's rule gives the owner path no attestor share); at or after lockHeight FEE-1 only.
    const std::vector<CKeyID>& eligible = ctx.Eligible((int)ref);
    std::set<unsigned int> assignedVouts;
    for (const Assignment& a : p.assignments) assignedVouts.insert(a.vout);
    if (!eligible.empty()) {
        const uint8_t fv = p.feeVout;
        if (fv == FEE_VOUT_NONE || fv >= tx.vout.size() || fv == fp->opReturnIndex || assignedVouts.count(fv)) return verdict::VAULT_SPEND_BAD_FEE;
        std::optional<CKeyID> key = P2PKHKey(tx.vout[fv].scriptPubKey);
        if (!key.has_value() || !ContainsKey(eligible, key.value())) return verdict::VAULT_SPEND_BAD_PAYEE;
        if (tx.vout[fv].nValue < FeeZat(vault.collateralZat, P.feeMin, P.feeBps)) return verdict::VAULT_SPEND_BAD_FEE;
        if (!claim && H < (int64_t)vault.lockHeight && P.IsValidClass(vault.termClass)
            && tx.vout[fv].nValue < FeeZat(vault.collateralZat, P.feeMin, P.feeBps) + EarlyRedeemFeeZat(vault.collateralZat, P.earlyRedeemFeeBps[vault.termClass])) {
            return verdict::BAD_REDEEM_EARLY_FEE;     // IT-9
        }
    }
    // AFEE-1 (RED-3's attestor-fee clause; AFEE-0 when not ARMED or on the owner path)
    if (armed) {
        facts.attestFeeZat = AttestFeeZat(FeeZat(vault.collateralZat, P.feeMin, P.feeBps), P.attestFeeBps);
        std::set<unsigned int> excluded = assignedVouts;
        excluded.insert(0u);
        excluded.insert(1u);
        excluded.insert(fp->opReturnIndex);
        excluded.insert((unsigned int)p.feeVout);
        facts.attestPayee = AttestFeeOk(ctx, tx, p.attestFeeVout, facts.bundle.seqs, excluded, facts.attestFeeZat);
        if (!facts.attestPayee.has_value()) return verdict::AFEE1_FEE;
    }
    // RED-4 (amended; IT-2): at every height the V's APP branch admits -- from the block after the mint
    // since IT-1 -- a claim is valid iff (a) the vault is underwater under pClaim of PRICE-2 (revised) at
    // CLAIM_THRESHOLD_BPS, or (b) a standing notice persists and it is underwater under pEmerg. There is
    // no "after the term" clause: in term, in grace and past it the same test decides.
    if (claim) {
        const std::optional<Snapshot>& S = ctx.Snap(ref);
        std::optional<MicroUsd> xClaim = S.has_value() ? S->PClaim() : std::nullopt;
        std::optional<MicroUsd> pClaim = xClaim, pEmerg;
        if (armed) {
            CombinedPrices c = PriceCombine(S->PMint(), xClaim, facts.bundle.aMint, facts.bundle.aClaim);
            pClaim = c.pClaim;
            pEmerg = c.pEmerg;
        }
        if (IsUnderwater(vault.collateralZat, pClaim, vault.mintedCents, P.claimThresholdBps)) {
            facts.claimPath = "a";
        } else {
            std::optional<NoticeRecord> notice = armed ? ctx.st.GetNotice(active[0].outpoint) : std::nullopt;   // (b) is false before arming
            const bool persisted = notice.has_value() && ref - (int64_t)notice->refHeight >= P.emergencyPersist &&
                                   ref - (int64_t)notice->refHeight <= P.emergencyNoticeTtl;
            if (!persisted || !IsUnderwater(vault.collateralZat, pEmerg, vault.mintedCents, P.emergencyRatioBps)) return verdict::VAULT_CLAIM_NOT_UNDERWATER;
            facts.claimPath = "b";
        }
        // RED-5: the residual above the claimant's cap goes back to the owner (R1: no margin under (b) alone).
        // U-23: it is the owner's residual intent, paying the owner's PQPKH at least the residual; the other
        // intent is the claimant's. With no residual due the claim has exactly one intent.
        if (!pClaim.has_value()) return verdict::RED5_RESIDUAL;
        const int marginBps = facts.claimPath == "a" ? P.claimThresholdBps : (int)BPS;
        facts.residualZat = ResidualZat(vault.collateralZat, ClaimantMaxZat(vault.mintedCents, marginBps, pClaim.value()));
        if (facts.residualZat >= P.residualMinZat) {
            const CPQKeyID owner = vault.Owner();
            if (!vault::IsOwnerValid(owner) || intents.size() != 2) return verdict::RED5_RESIDUAL;
            const uint256 ownerHash = vault::ScriptHash256(GetScriptForDestination(owner));   // the owner's PQPKH (quantum spec F-3)
            for (unsigned int j : intents) {
                vault::IntentParams ip;
                IsYedIntentOutput(tx.vout[j].scriptPubKey, &ip);
                if (ip.recipientHash == ownerHash && tx.vout[j].nValue >= facts.residualZat) { facts.residualVout = (int)j; break; }
            }
            if (facts.residualVout < 0) return verdict::RED5_RESIDUAL;
            facts.claimantVout = (int)(intents[0] == (unsigned int)facts.residualVout ? intents[1] : intents[0]);
        } else {
            if (intents.size() != 1) return verdict::VAULT_CLAIM_INTENTS;
            facts.claimantVout = (int)intents[0];
        }
    }
    return verdict::OK;
}

/** RED-1..5 over a spend of an ACTIVE vault. Returns true iff they failed (the transaction is then invalid). */
bool ApplyVaultSpend(EvalContext& ctx, const CTransaction& tx, const uint256& txid, const std::optional<FoundPayload>& fp,
                     std::vector<SpentVault>& active, Cents yedIn, TxLogRecord& log, Totals& totals, std::set<unsigned int>& yedOutputs)
{
    std::optional<uint8_t> selector = tx.vin.empty() ? std::nullopt : vault::ParseSelector(tx.vin[0].scriptSig);
    if (selector.has_value() && (IsOwnerSelector(selector.value()) || selector.value() == vault::SEL_APP)) {
        log.path = IsOwnerSelector(selector.value()) ? "owner" : "claim";
    }
    RedFacts facts;
    const std::string v = RedVerdict(ctx, tx, fp, active, selector, yedIn, facts);
    LogBundle(log, facts.bundle);
    log.residualZat = facts.residualZat;
    log.claimPath = facts.claimPath;
    if (v != verdict::OK) {
        log.verdict = v;
        log.yedOut = 0;
        return true;
    }
    const bool ownerPath = IsOwnerSelector(selector.value());
    const Payload& p = fp->payload;
    VaultRecord& vault = active[0].record;
    for (const Assignment& a : p.assignments) {
        const COutPoint out(txid, a.vout);
        TokenRecord tok;
        tok.cents = a.cents;
        tok.nValue = tx.vout[a.vout].nValue;
        tok.scriptPubKey = tx.vout[a.vout].scriptPubKey;
        tok.height = ctx.height;
        ctx.st.Put(keys::Token(out), tok);
        AssignedOutput ao;
        ao.outpoint = out;
        ao.cents = a.cents;
        ao.scriptPubKey = tok.scriptPubKey;
        log.assigned.push_back(ao);
    }
    log.yedOut = p.AssignedCents();
    log.verdict = verdict::OK;
    // U-23: the owner's spend closes the vault; a claim leaves it CLAIMING until its claimant intent is
    // released (CLAIMED) or cancelled by the attestor set (ACTIVE again at the re-created vault).
    vault.status = (uint8_t)(ownerPath ? VaultStatus::CLOSED : VaultStatus::CLAIMING);
    vault.closeHeight = ctx.height;
    vault.closingTxid = txid;
    vault.unbacked = false;
    vault.feePaidZat = 0; // rewritten by the close: the fee this spend paid (0 under FEE-0), SERIALISATION.md §3 J
    if (!ctx.Eligible((int)p.refHeight).empty()) {
        vault.feePaidZat = tx.vout[p.feeVout].nValue;
        log.feeZat = vault.feePaidZat;
        std::optional<CKeyID> key = P2PKHKey(tx.vout[p.feeVout].scriptPubKey);
        log.hasPayee = key.has_value();
        if (key.has_value()) log.payee = key.value();
    }
    if (facts.attestPayee.has_value()) {
        log.attestFeeZat = tx.vout[p.attestFeeVout].nValue;
        log.hasAttestPayee = true;
        log.attestPayee = facts.attestPayee.value();
    }
    // IT-6 (D-IT-14): a claimed vault's collateral stays in the system ratio until its claimant intent is
    // released (the debt left supply with this spend's burn); the owner's redeem removes it at once.
    if (ownerPath) totals.collateralZat -= vault.collateralZat;
    if (totals.activeVaults > 0) totals.activeVaults--;
    if (ownerPath) {
        totals.closedVaults++;
    } else {
        for (int j : { facts.claimantVout, facts.residualVout }) {
            if (j < 0) continue;
            IntentRecord ir;
            ir.vault = active[0].outpoint;
            ir.role = (uint8_t)(j == facts.claimantVout ? IntentRole::CLAIMANT : IntentRole::RESIDUAL);
            ir.height = ctx.height;
            ctx.st.Put(keys::Intent(COutPoint(txid, (uint32_t)j)), ir);
            yedOutputs.insert((unsigned int)j);
        }
    }
    log.closedVaults.push_back(active[0].outpoint);
    return false;
}

/** A spent claim intent (U-23). */
struct SpentIntent
{
    COutPoint outpoint;
    IntentRecord record;
    size_t vin;
};

/**
 * U-23, U-24: the release (selector 1) or attestor cancel (selector 2) of a claim intent. The primitive has
 * already checked the delay (BIP68 / I-2) and the payment (I-1 / I-2); the module moves its records:
 * the claimant intent's release closes the vault (CLAIMED); its cancel re-creates the byte-identical
 * vault, which becomes the same position again (ACTIVE at the new outpoint, its collateral the re-lock's
 * value), and the claim's burn is not refunded (U-24). The owner's residual intent may only be released.
 * The re-created vault must be vout[0]. Returns the verdict; OK on success.
 */
std::string ApplyIntentSpend(EvalContext& ctx, const CTransaction& tx, const uint256& txid, const SpentIntent& in,
                             const std::optional<FoundPayload>& fp, TxLogRecord& log, Totals& totals, std::set<unsigned int>& yedOutputs)
{
    const Params& P = ctx.params;
    std::optional<uint8_t> selector = vault::ParseSelector(tx.vin[in.vin].scriptSig);
    if (!selector.has_value() || !(selector.value() == vault::SEL_UNLOCK || selector.value() == vault::SEL_OWNER)) return verdict::INTENT_SPEND_MALFORMED;
    if (fp.has_value()) return verdict::INTENT_SPEND_MALFORMED;           // a release or cancel carries no Yellowback payload
    const bool cancel = selector.value() == vault::SEL_OWNER;
    if (cancel && in.record.Role() == IntentRole::RESIDUAL) return verdict::INTENT_CANCEL_RESIDUAL;
    std::optional<VaultRecord> vault = ctx.st.GetVault(in.record.vault);
    ctx.st.EraseKey(keys::Intent(in.outpoint));
    log.type = (uint8_t)(cancel ? TxLogType::CLAIM_CANCEL : TxLogType::CLAIM_RELEASE);
    if (in.record.Role() == IntentRole::RESIDUAL) return verdict::OK;    // the owner's residual: nothing else moves
    if (!vault.has_value() || vault->Status() != VaultStatus::CLAIMING) return verdict::OK;   // cannot happen; stated for totality
    if (!cancel) {
        vault->status = (uint8_t)VaultStatus::CLAIMED;
        ctx.st.Put(keys::Vault(in.record.vault), vault.value());
        totals.collateralZat -= vault->collateralZat;      // IT-6: the collateral leaves the system ratio at release
        totals.claimedVaults++;
        log.closedVaults.push_back(in.record.vault);
        return verdict::OK;
    }
    const CScript vaultSpk = YedVaultScriptAt(P, vault->Owner(), vault->ownerHeight, vault->appHeight);
    int relock = -1;
    for (unsigned int j = 0; j < tx.vout.size(); j++) {
        if (tx.vout[j].scriptPubKey != vaultSpk) continue;
        if (relock >= 0) return verdict::INTENT_CANCEL_NO_VAULT;
        relock = (int)j;
    }
    // The re-created vault is vout[0] (vault_buildcancel's shape), so the position stays "txid:0" as every
    // Yellowback position is (the wallet addresses vaults by txid).
    if (relock != 0) return verdict::INTENT_CANCEL_NO_VAULT;
    const COutPoint reopened(txid, (uint32_t)relock);
    VaultRecord v = vault.value();
    v.status = (uint8_t)VaultStatus::ACTIVE;
    v.collateralZat = tx.vout[relock].nValue;
    v.closeHeight = 0;
    v.closingTxid = uint256();
    v.burnedCents = 0;
    ctx.st.EraseKey(keys::Vault(in.record.vault));
    ctx.st.Put(keys::Vault(reopened), v);
    if (ctx.st.Has(keys::Notice(in.record.vault))) ctx.st.EraseKey(keys::Notice(in.record.vault));
    totals.collateralZat += v.collateralZat - vault->collateralZat;    // IT-6: the CLAIMING collateral was still counted
    totals.activeVaults++;
    log.closedVaults.push_back(in.record.vault);
    log.reopenedVaults.push_back(reopened);
    yedOutputs.insert((unsigned int)relock);
    return verdict::OK;
}

// ---------------------------------------------------------------------------
// v3 payload types (v3 plan §3.8): REG-A1, NOT-1, EQV-1, REV-1. Each returns true iff the rule held
// and state was written; a failing one leaves the transaction non-Yellowback (N7).

bool FullyValidKey(const CPubKey& k)
{
    return k.IsValid() && k.IsCompressed() && k.IsFullyValid();
}

/** One attestation signature, through the W8 cache when the caller has one. */
bool AttestationValid(EvalContext& ctx, const Attestation& a, const CPubKey& pk, const uint256& blockHash)
{
    const uint256 key = SigCacheKey(a, blockHash);
    std::optional<bool> cached = ctx.cache ? ctx.cache->Lookup(key) : std::nullopt;
    if (cached.has_value()) return cached.value();
    const bool valid = VerifyCompactSig(pk, AttestMessage(a.seq, a.priceMicroUsd, a.citedHeight, blockHash), a.sig);
    if (ctx.cache) ctx.cache->Insert(key, valid);
    return valid;
}

/** NOT-1: step one of an emergency claim. */
bool ApplyNotice(EvalContext& ctx, const CTransaction& tx, const Payload& p, TxLogRecord& log)
{
    const Params& P = ctx.params;
    const int64_t H = ctx.height;
    const COutPoint vaultOut = p.VaultOutPoint();
    std::optional<VaultRecord> vault = ctx.st.GetVault(vaultOut);
    if (!vault.has_value() || vault->Status() != VaultStatus::ACTIVE) return false;
    const int64_t ref = p.refHeight;
    if (!(H - P.refWindow <= ref && ref <= H - 1) || ref < P.startHeight) return false;
    if (!ctx.Armed(ref)) return false;
    BundleFacts f = ctx.Bundle(tx, ref, OutPointSelector(vaultOut), false);
    if (!f.verified) return false;
    const std::optional<Snapshot>& S = ctx.Snap(ref);
    CombinedPrices c = PriceCombine(S->PMint(), S->PClaim(), f.aMint, f.aClaim);
    if (!c.pEmerg.has_value()) return false;
    if (!IsUnderwater(vault->collateralZat, c.pEmerg, vault->mintedCents, P.emergencyRatioBps)) return false;
    std::optional<NoticeRecord> standing = ctx.st.GetNotice(vaultOut);
    if (standing.has_value() && H - (int64_t)standing->height <= P.emergencyNoticeTtl) return false;   // the reset attack
    NoticeRecord n;
    n.height = ctx.height;
    n.refHeight = (int32_t)ref;
    n.pEmerg = c.pEmerg.value();
    ctx.st.Put(keys::Notice(vaultOut), n);
    LogBundle(log, f);
    log.notice = true;
    return true;
}

/** The newest Attestors record of a member key (the mirror of the set's current member record, P4-b). */
std::optional<std::pair<uint16_t, AttestorRecord>> LatestRecord(const State& st, const std::vector<unsigned char>& key)
{
    std::optional<std::pair<uint16_t, AttestorRecord>> out;
    for (const auto& r : st.Attestors()) {
        if (r.second.attestorPubKey == key) out = r;
    }
    return out;
}

/** EJECTED (statusHeight moves only on a change), FROZEN when `freeze`: SET_REMOVE, SET_EQUIVOCATION, EQV-1. */
void EjectRecord(EvalContext& ctx, uint16_t seq, AttestorRecord rec, bool freeze)
{
    if (rec.Status() != AttestorStatus::EJECTED) {
        rec.status = (uint8_t)AttestorStatus::EJECTED;
        rec.statusHeight = ctx.height;
    }
    if (freeze) rec.bondFrozen = true;
    ctx.st.Put(keys::Attestor(seq), rec);
}

/**
 * EQV-1 (P4-b): two signed prices for one (seq, citedHeight, blockHash) by a member key eject the member and freeze
 * its bond. The key is the first record in seq order that is its key's newest, with an unspent, unfrozen bond, under
 * which both attestations verify (the primitive's ejection hook, yellowback/module.cpp, picks the same member of the
 * set: one key cannot be two). citedHeight in [START_HEIGHT, H).
 */
bool ApplyEquivocation(EvalContext& ctx, const CTransaction& tx, TxLogRecord& log)
{
    const Params& P = ctx.params;
    std::optional<std::pair<Attestation, Attestation>> e = EquivocationEvidence(tx, P);
    if (!e) return false;
    const Attestation& a = e->first;
    const Attestation& b = e->second;
    if ((int64_t)a.citedHeight >= ctx.height) return false;
    std::optional<uint256> blockHash = BlockHashAt(ctx.st.View(), P, a.citedHeight);
    if (!blockHash.has_value()) return false;
    const std::vector<std::pair<uint16_t, AttestorRecord>> all = ctx.st.Attestors();
    for (size_t i = 0; i < all.size(); i++) {
        const AttestorRecord& rec = all[i].second;
        if (rec.bondSpentHeight != 0 || rec.Frozen()) continue;
        bool newest = true;
        for (size_t j = i + 1; j < all.size(); j++) newest = newest && all[j].second.attestorPubKey != rec.attestorPubKey;
        if (!newest) continue;
        const CPubKey pk = rec.AttestorKey();
        if (!EquivocatedBy(e.value(), pk, blockHash.value())) continue;   // never the W8 cache: it is keyed by seq, not by key
        EjectRecord(ctx, all[i].first, rec, true);
        log.attestorSeq = all[i].first;
        log.bundleSeqs.push_back(a.seq);
        return true;
    }
    return false;
}

/**
 * The attestor set's acts on the mirror (P4-b; see state.h). Returns true when the transaction carried an act that
 * changed it (the TxLog entry is then ATTESTOR_REGISTER for a join, ATTESTOR_SET_ACT otherwise).
 */
bool ApplySetAct(EvalContext& ctx, const CTransaction& tx, const uint256& txid, TxLogRecord& log)
{
    const Params& P = ctx.params;
    if (P.attestorSetId.IsNull()) return false;
    const CScript* actSpk = nullptr;
    for (const CTxOut& o : tx.vout) {
        if (vault::IsActOutput(o.scriptPubKey)) { actSpk = &o.scriptPubKey; break; }
    }
    if (!actSpk) return false;
    vault::Act act;
    if (vault::DecodeAct(*actSpk, act) || !vault::ActFieldsValid(act)) return false;   // the primitive refuses either
    if (act.type == vault::ACT_SET_CREATE) {
        if (txid != P.attestorSetId || ctx.st.GetAttestorSet().has_value()) return false;
        AttestorSetRecord z;
        z.createHeight = ctx.height;
        z.seats = act.create.seats;
        z.maturity = act.create.maturity;
        z.livenessWindow = act.create.livenessWindow;
        ctx.st.Put(keys::AttestorSet(), z);
        log.type = (uint8_t)TxLogType::ATTESTOR_SET_ACT;
        return true;
    }
    if (act.TargetSet() != P.attestorSetId) return false;
    std::optional<AttestorSetRecord> z = ctx.st.GetAttestorSet();
    if (!z.has_value()) return false;
    switch (act.type) {
    case vault::ACT_SET_JOIN: {
        const vault::SetJoinBody& j = act.join;
        if (j.bondVout >= tx.vout.size()) return false;
        AttestorSeqRecord next = ctx.st.GetAttestorSeq();
        if (ctx.st.GetAttestor(next.next).has_value()) return false;    // the u16 counter wrapped (totality)
        AttestorRecord rec;
        rec.attestorPubKey = std::vector<unsigned char>(j.memberKey.begin(), j.memberKey.end());
        rec.bondPubKey = rec.attestorPubKey;
        rec.bondOutpoint = COutPoint(txid, j.bondVout);
        rec.bondZat = tx.vout[j.bondVout].nValue;
        rec.bondLocktime = j.bondLocktime;
        rec.flags = 0;
        rec.registerHeight = ctx.height;
        rec.status = (uint8_t)AttestorStatus::PENDING;
        rec.statusHeight = ctx.height;
        rec.lastAct = (int32_t)std::min<int64_t>((int64_t)ctx.height + z->maturity, 0x7FFFFFFF);
        ctx.st.Put(keys::Attestor(next.next), rec);
        BondIndexRecord bi;
        bi.seq = next.next;
        ctx.st.Put(keys::BondIndex(rec.bondOutpoint), bi);
        log.type = (uint8_t)TxLogType::ATTESTOR_REGISTER;
        log.attestorSeq = next.next;
        next.next = (uint16_t)(next.next + 1);
        ctx.st.Put(keys::AttestorSeq(), next);
        return true;
    }
    case vault::ACT_SET_HEARTBEAT:
    case vault::ACT_SET_REMOVE:
    case vault::ACT_SET_EQUIVOCATION: {
        CPubKey key;
        if (act.type == vault::ACT_SET_HEARTBEAT) key = act.heartbeat.memberKey;
        else if (act.type == vault::ACT_SET_REMOVE) key = act.remove.memberKey;
        else if (!vault::RecoverSig(vault::SetSigMsg(act.equivocation.setId, act.equivocation.roleA, act.equivocation.prevout,
                                                     act.equivocation.sighashA), act.equivocation.sigA, key)) return false;
        std::optional<std::pair<uint16_t, AttestorRecord>> r = LatestRecord(ctx.st, std::vector<unsigned char>(key.begin(), key.end()));
        if (!r.has_value()) return false;
        if (act.type == vault::ACT_SET_HEARTBEAT) {
            r->second.lastAct = ctx.height;
            ctx.st.Put(keys::Attestor(r->first), r->second);
        } else {
            EjectRecord(ctx, r->first, r->second, act.type == vault::ACT_SET_EQUIVOCATION || act.remove.burn == 1);
        }
        log.type = (uint8_t)TxLogType::ATTESTOR_SET_ACT;
        log.attestorSeq = r->first;
        return true;
    }
    default:
        return false;
    }
}

// ---------------------------------------------------------------------------
// One transaction (IN-1..3, TX-0, MINT / XFER / RED, and the v3 types)

TxOutcome ProcessTxImpl(EvalContext& ctx, const CTransaction& tx)
{
    TxOutcome out;
    TxLogRecord& log = out.log;
    log.height = ctx.height;
    log.verdict = verdict::NON_YELLOWBACK;
    if (tx.IsCoinBase()) return out; // TX-0: the coinbase registers nothing; only its scriptSig (the tag) is read

    const uint256 txid = tx.GetHash();
    Totals totals = ctx.st.GetTotals();
    const Totals before = totals;

    // ---- inputs (IN-1, and the vaults IN-2 will close). Shielded components are ignored (TX-0).
    Cents yedIn = 0;
    bool bondSpent = false;
    std::vector<SpentVault> active, voids;
    std::vector<SpentIntent> intents;
    for (size_t vin = 0; vin < tx.vin.size(); vin++) {
        const CTxIn& in = tx.vin[vin];
        const COutPoint& prev = in.prevout;
        if (std::optional<TokenRecord> tok = ctx.st.GetToken(prev)) {
            yedIn += tok->cents;
            AssignedOutput spent;
            spent.outpoint = prev;
            spent.cents = tok->cents;
            spent.scriptPubKey = tok->scriptPubKey;
            log.spentTokens.push_back(spent);
            ctx.st.EraseKey(keys::Token(prev));
        }
        if (std::optional<VaultRecord> v = ctx.st.GetVault(prev)) {
            if (v->Status() == VaultStatus::ACTIVE && !Contains(active, prev)) active.push_back({ prev, v.value() });
            else if (v->Status() == VaultStatus::VOIDED && !Contains(voids, prev)) voids.push_back({ prev, v.value() });
        }
        if (std::optional<IntentRecord> ir = ctx.st.GetIntent(prev)) {   // U-23: a claim intent
            bool dup = false;
            for (const SpentIntent& si : intents) dup = dup || si.outpoint == prev;
            if (!dup) intents.push_back({ prev, ir.value(), vin });
        }
        // IN-2 (amended): a bond spend withdraws the attestor unless it is EJECTED; the record stays
        if (std::optional<uint16_t> seq = ctx.st.GetBondIndex(prev)) {
            std::optional<AttestorRecord> rec = ctx.st.GetAttestor(seq.value());
            if (rec.has_value() && rec->bondSpentHeight == 0) {
                if (rec->Status() != AttestorStatus::EJECTED) {
                    rec->status = (uint8_t)AttestorStatus::WITHDRAWN;
                    rec->statusHeight = ctx.height;
                }
                rec->bondSpentHeight = ctx.height;
                ctx.st.Put(keys::Attestor(seq.value()), rec.value());
                bondSpent = true;
            }
        }
    }
    log.yedIn = yedIn;
    log.verdict = verdict::OK;
    // P4-b: the attestor set's acts on the Attestors mirror (after the bond spends above, as the primitive orders them)
    const bool setAct = ApplySetAct(ctx, tx, txid, log);
    const uint8_t setActType = log.type;

    // ---- outputs
    std::optional<FoundPayload> fp = FindPayload(tx);
    // The output indices a rule below created as YED-tagged templates (U-23); any other is invalid.
    std::set<unsigned int> yedOutputs;
    bool touched = !log.spentTokens.empty() || !active.empty() || !voids.empty() || bondSpent || !intents.empty() || setAct;
    auto fail = [&](const std::string& v) -> TxOutcome& {
        log.verdict = v;
        log.yedOut = 0;
        out.invalid = true;
        return out;
    };
    if (!intents.empty()) {
        // U-23: a claim intent's release or cancel (the primitive admits one template input per transaction, S-1)
        if (intents.size() != 1 || !active.empty()) return fail(verdict::INTENT_SPEND_MALFORMED);
        const std::string v = ApplyIntentSpend(ctx, tx, txid, intents[0], fp, log, totals, yedOutputs);
        if (v != verdict::OK) return fail(v);
        touched = true;
    } else if (!active.empty()) {
        // M3: a transaction spending an ACTIVE vault sees RED-1..5 only, whatever its payload.
        log.type = (uint8_t)TxLogType::REDEEM;
        out.vaultSpend = true;
        if (ApplyVaultSpend(ctx, tx, txid, fp, active, yedIn, log, totals, yedOutputs)) return fail(log.verdict);
        touched = true;
    } else if (fp.has_value() && fp->payload.type == PayloadType::MINT) {
        log.type = (uint8_t)TxLogType::MINT;
        if (!ApplyMint(ctx, tx, txid, fp->payload, fp->opReturnIndex, log, totals)) return fail(log.verdict);   // §15.10: no VOID vault
        yedOutputs.insert(0u);
        touched = true;
    } else if (fp.has_value() && (fp->payload.type == PayloadType::TRANSFER || fp->payload.type == PayloadType::REDEEM)) {
        log.type = (uint8_t)(fp->payload.type == PayloadType::TRANSFER ? TxLogType::TRANSFER : TxLogType::REDEEM);
        // TOK-PQ (quantum spec F-7): from the Falcon height an assignment to any other script makes the
        // transaction invalid (refused, not burned: a wallet that missed the activation keeps its YED).
        for (const Assignment& a : fp->payload.assignments) {
            if (!HolderAllowed(ctx.params, ctx.height, tx.vout[a.vout].scriptPubKey)) return fail(verdict::BAD_YED_HOLDER);
        }
        ApplyTransfer(ctx, tx, txid, fp->payload, yedIn, log);
    } else {
        // The v3 types (REG-A1, NOT-1, EQV-1, REV-1): a holding rule writes its table and a TxLog entry; a
        // failing one is non-Yellowback for outputs, exactly like a transaction with no payload.
        bool held = false;
        if (fp.has_value()) {
            switch (fp->payload.type) {
            case PayloadType::ATTESTOR_REGISTER: log.type = (uint8_t)TxLogType::ATTESTOR_REGISTER; return fail(verdict::ATTESTOR_REGISTER_RETIRED);   // P4-b
            case PayloadType::CLAIM_NOTICE: log.type = (uint8_t)TxLogType::CLAIM_NOTICE; held = ApplyNotice(ctx, tx, fp->payload, log); break;
            case PayloadType::EQUIVOCATION: log.type = (uint8_t)TxLogType::EQUIVOCATION; held = ApplyEquivocation(ctx, tx, log); break;
            case PayloadType::ATTESTOR_REVIVE: log.type = (uint8_t)TxLogType::ATTESTOR_REVIVE; return fail(verdict::ATTESTOR_REVIVE_RETIRED);      // P4-b
            default: break;
            }
        }
        if (held) {
            touched = true;
        } else {
            log.type = setAct ? setActType : (uint8_t)TxLogType::NONE;
            if (yedIn > 0) log.verdict = verdict::BURNED;
        }
    }

    // ---- U-23: a YED-tagged vault or intent output exists only as a mint's vault, a claim's intents or a
    // cancel's re-created vault
    for (unsigned int j = 0; j < tx.vout.size(); j++) {
        const CScript& spk = tx.vout[j].scriptPubKey;
        if (!yedOutputs.count(j) && (IsYedVaultOutput(spk) || IsYedIntentOutput(spk))) return fail(verdict::YED_TEMPLATE_OUTPUT);
    }

    // ---- IN-2 for VOID vaults (none is created since the vault upgrade; kept for a pre-upgrade record): an ordinary spend that closes them (K3)
    for (SpentVault& s : voids) {
        s.record.status = (uint8_t)VaultStatus::CLOSED;
        s.record.closeHeight = ctx.height;
        s.record.closingTxid = txid;
        s.record.unbacked = false;
        if (totals.voidVaults > 0) totals.voidVaults--;
        totals.closedVaults++;
        log.closedVaults.push_back(s.outpoint);
    }

    // ---- IN-3 (for a MINT the burn formula's yedOut is 0, N19: every YED input of a mint is burned)
    const Cents burnOut = log.Type() == TxLogType::MINT ? 0 : log.yedOut;
    const Cents burned = yedIn - burnOut;
    log.burned = burned;
    totals.supplyCents -= burned;
    for (SpentVault& s : active) {
        s.record.burnedCents = burned;
        ctx.st.Put(keys::Vault(s.outpoint), s.record);
        if (ctx.st.Has(keys::Notice(s.outpoint))) ctx.st.EraseKey(keys::Notice(s.outpoint));   // IN-2: the vault left ACTIVE
    }
    for (SpentVault& s : voids) {
        s.record.burnedCents = burned;
        ctx.st.Put(keys::Vault(s.outpoint), s.record);
    }
    if (touched) {
        if (!(SerializeRecord(totals) == SerializeRecord(before)) || !ctx.st.Has(keys::Totals())) ctx.st.Put(keys::Totals(), totals);
        ctx.st.Put(keys::TxLog(txid), log);
        out.relevant = true;
    } else {
        log.verdict = verdict::NON_YELLOWBACK;
    }
    return out;
}

// ---------------------------------------------------------------------------
// REG-4 judgement, performed at H for the quote tag at H - PEER_LAG

void Judge(State& st, const Params& P, int64_t H)
{
    const int64_t lag = P.peerLag;
    const int64_t t = H - lag;
    if (t < P.startHeight) return;
    std::optional<TagRecord> tag = TagAt(st.View(), P, t);
    if (!tag.has_value() || !tag->IsQuote()) return;
    std::vector<MicroUsd> peers;
    for (int64_t h = t - lag; h <= t + lag - 1; h++) {
        if (h == t) continue;
        std::optional<TagRecord> q = TagAt(st.View(), P, h);
        if (q.has_value() && q->IsQuote()) peers.push_back((MicroUsd)q->priceMicroUsd);
    }
    Judgement j;
    if ((int64_t)peers.size() >= (int64_t)P.peerMin) {
        std::optional<MicroUsd> m = LowerMedian(peers);
        if (m.has_value() && m.value() > 0) {
            const uint64_t price = tag->priceMicroUsd, med = (uint64_t)m.value();
            const uint64_t diff = price >= med ? price - med : med - price;
            const uint64_t dev = diff * (uint64_t)BPS / med;          // price, med <= PRICE_MAX: no overflow
            j.evaluated = true;
            j.inBand = dev <= (uint64_t)std::max(0, P.accuracyBandBps);
            j.penalized = dev > (uint64_t)std::max(0, P.deviationBps);
        }
    }
    st.Put(keys::Judgement((uint32_t)t), j);
}

} // namespace

// ---------------------------------------------------------------------------
// Public lookups

std::optional<Snapshot> SnapshotAt(const State& st, const Params& P, int64_t height)
{
    if (height < P.startHeight) return Snapshot::Virtual();
    if (height < 0 || height > 0xFFFFFFFFLL) return std::nullopt;
    return st.GetSnapshot((uint32_t)height);
}

std::vector<CKeyID> EligiblePayees(const StateView& view, const Params& P, int refHeight)
{
    // PIN-1: keys pinned at R are not eligible payees at R
    std::vector<CKeyID> pinned;
    if (refHeight >= P.startHeight && refHeight >= 0) {
        std::optional<Snapshot> s = State(const_cast<StateView&>(view)).GetSnapshot((uint32_t)refHeight);
        if (s.has_value()) {
            for (const uint160& k : s->pinnedKeys) pinned.push_back(CKeyID(k));
        }
    }
    std::vector<CKeyID> keys;
    for (int64_t h = std::max<int64_t>((int64_t)refHeight - P.payeeWindow + 1, P.startHeight); h <= refHeight; h++) {
        std::optional<TagRecord> t = TagAt(view, P, h);
        if (!t.has_value() || !t->IsQuote()) continue;
        CKeyID k(t->payoutKey);
        if (ContainsKey(pinned, k)) continue;
        if (!ContainsKey(keys, k)) keys.push_back(k);
    }
    return keys;
}

bool Registered(const StateView& view, const Params& P, const CKeyID& key, int refHeight)
{
    for (int64_t h = std::max<int64_t>((int64_t)refHeight - P.nReg + 1, P.startHeight); h <= refHeight; h++) {
        std::optional<TagRecord> t = TagAt(view, P, h);
        if (t.has_value() && t->IsQuote() && t->payoutKey == key) return true;
    }
    return false;
}

bool Penalized(const StateView& view, const Params& P, const CKeyID& key, int refHeight, int penaltyBlocks)
{
    // t + PEER_LAG < R <= t + PEER_LAG + N_PENALTY  <=>  R - PEER_LAG - N_PENALTY <= t < R - PEER_LAG
    const int64_t lo = (int64_t)refHeight - P.peerLag - std::max(0, penaltyBlocks);
    const int64_t hi = (int64_t)refHeight - P.peerLag - 1;
    for (int64_t t = std::max<int64_t>(lo, P.startHeight); t <= hi; t++) {
        std::optional<TagRecord> tag = TagAt(view, P, t);
        if (!tag.has_value() || !tag->IsQuote() || !(tag->payoutKey == key)) continue;
        std::optional<Judgement> j = JudgementAt(view, P, t);
        if (j.has_value() && j->penalized) return true;
    }
    return false;
}

int AccuracyBps(const StateView& view, const Params& P, const CKeyID& key, int refHeight, int accuracyWindow)
{
    const int64_t hi = (int64_t)refHeight - P.peerLag;
    const int64_t lo = hi - std::max(0, accuracyWindow) + 1;
    int64_t quoted = 0, inBand = 0;
    for (int64_t t = std::max<int64_t>(lo, P.startHeight); t <= hi; t++) {
        std::optional<TagRecord> tag = TagAt(view, P, t);
        if (!tag.has_value() || !tag->IsQuote() || !(tag->payoutKey == key)) continue;
        std::optional<Judgement> j = JudgementAt(view, P, t);
        if (!j.has_value() || !j->evaluated) continue;
        quoted++;
        if (j->inBand) inBand++;
    }
    return quoted > 0 ? (int)(BPS * inBand / quoted) : 0;
}

std::optional<CKeyID> DefaultPayee(const StateView& view, const Params& P, int refHeight,
                                   const std::vector<unsigned char>& selector, const PayeePolicy& policy)
{
    const std::vector<CKeyID> eligible = EligiblePayees(view, P, refHeight);
    if (eligible.empty()) return std::nullopt;
    if (policy.preferred.has_value() && ContainsKey(eligible, policy.preferred.value())) return policy.preferred;

    std::vector<std::pair<CKeyID, int64_t>> candidates;
    for (int64_t h = std::max<int64_t>((int64_t)refHeight - P.payeeWindow + 1, P.startHeight); h <= refHeight; h++) {
        std::optional<TagRecord> t = TagAt(view, P, h);
        if (!t.has_value() || !t->IsQuote()) continue;
        CKeyID k(t->payoutKey);
        if (!ContainsKey(eligible, k)) continue;                       // pinned at R (PIN-1)
        if (Penalized(view, P, k, refHeight, policy.penaltyBlocks)) continue;
        const int64_t w = BPS + (int64_t)std::max(0, policy.tiltBps) * (int64_t)AccuracyBps(view, P, k, refHeight, policy.accuracyWindow) / BPS;
        candidates.push_back(std::make_pair(k, w));
    }
    if (candidates.empty()) {
        for (const CKeyID& k : eligible) candidates.push_back(std::make_pair(k, (int64_t)BPS));
    }
    int64_t total = 0;
    for (const auto& c : candidates) total += c.second;
    if (total <= 0) return eligible.front();

    uint256 blockHash;
    if (refHeight >= P.startHeight && refHeight >= 0) {
        std::optional<Snapshot> s = State(const_cast<StateView&>(view)).GetSnapshot((uint32_t)refHeight);
        if (s.has_value()) blockHash = s->blockHash;
    }
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(blockHash.begin(), 32).Write(selector.data(), selector.size()).Finalize(digest);
    uint64_t seed = 0;
    for (int i = 7; i >= 0; i--) seed = (seed << 8) | digest[i];
    const int64_t pick = (int64_t)(seed % (uint64_t)total);
    int64_t cumulative = 0;
    for (const auto& c : candidates) {
        cumulative += c.second;
        if (cumulative > pick) return c.first;
    }
    return candidates.back().first;
}

// ---------------------------------------------------------------------------
// SNAP

Snapshot ComputeSnapshot(State& st, const Params& P, int height, const uint256& blockHash, CAmount subsidyZat,
                         const std::optional<CoinbaseTag>& tag)
{
    const int64_t H = height;
    Judge(st, P, H);                                                                    // REG-4

    // (ACT-1..3 left with the vault upgrade, §6: the module is active from START_HEIGHT)
    Snapshot s;
    s.blockHash = blockHash;
    s.tagged = tag.has_value();
    s.quote = tag.has_value() && tag->IsQuote();

    // ---- v3 (v3 plan §3.8 SNAP): maturity, ARM-1/2, PIN-1/2, seating; dormancy after the halts
    std::vector<std::pair<uint16_t, AttestorRecord>> attestors = st.Attestors();
    std::vector<std::string> attestorBefore;
    for (const auto& r : attestors) attestorBefore.push_back(SerializeRecord(r.second));
    // maturity and the set's member dormancy (P4-b, state.h): PENDING -> ELIGIBLE at registerHeight + max(set
    // maturity, BOND_MATURITY) over the module's bond floor; ELIGIBLE -> DORMANT when lastAct < H - livenessWindow;
    // DORMANT -> ELIGIBLE after a heartbeat that follows the dormancy
    const std::optional<AttestorSetRecord> aset = st.GetAttestorSet();
    std::set<std::vector<unsigned char>> slashed;      // keys with a frozen bond: barred for good, as v3 barred an ejected key
    for (const auto& r : attestors) {
        if (r.second.bondFrozen) slashed.insert(r.second.attestorPubKey);
    }
    int eligibleCount = 0;
    for (auto& r : attestors) {
        AttestorRecord& a = r.second;
        if (aset.has_value()) {
            const int64_t matureAt = (int64_t)a.registerHeight + std::max<int64_t>((int64_t)aset->maturity, P.bondMaturity);
            const bool floorOk = a.bondZat >= P.bondMin && (int64_t)a.bondLocktime >= (int64_t)a.registerHeight + P.bondMinLock &&
                                 !slashed.count(a.attestorPubKey);
            const bool live = (int64_t)a.lastAct >= H - (int64_t)aset->livenessWindow;
            if (a.Status() == AttestorStatus::PENDING && floorOk && H >= matureAt) {
                a.status = (uint8_t)AttestorStatus::ELIGIBLE;
                a.statusHeight = height;
            }
            if (a.Status() == AttestorStatus::ELIGIBLE && !live) {
                a.status = (uint8_t)AttestorStatus::DORMANT;
                a.statusHeight = height;
            } else if (a.Status() == AttestorStatus::DORMANT && live && a.lastAct > a.statusHeight) {
                a.status = (uint8_t)AttestorStatus::ELIGIBLE;
                a.statusHeight = height;
            }
        }
        if (a.Status() == AttestorStatus::ELIGIBLE) eligibleCount++;
    }
    // ARM-1/2 (status never moves backward; attestArmMin 0 never arms)
    AttestState m = st.GetAttest();
    const AttestState mBefore = m;
    if (m.Status() == AttestStatus::UNARMED && P.attestArmMin > 0 && eligibleCount >= P.attestArmMin) {
        m.status = (uint8_t)AttestStatus::TRIGGERED;
        m.triggerHeight = height;
        m.armHeight = (int32_t)(H + P.attestArmDelay);
    }
    if (m.Status() == AttestStatus::TRIGGERED && H >= m.armHeight) m.status = (uint8_t)AttestStatus::ARMED;
    if (!(m == mBefore) || !st.Has(keys::Attest())) st.Put(keys::Attest(), m);
    s.attest = m;
    // PIN-1/2 over W = (H - 1 - PIN_WINDOW, H - 1]: prior snapshots and BundleLog only
    std::vector<BundleLogRecord> window;
    for (int64_t h = std::max<int64_t>(H - P.pinWindow, P.startHeight); h <= H - 1; h++) {
        if (h < 0 || h > 0xFFFFFFFFLL) continue;
        std::optional<BundleLogRecord> row = st.GetBundleLog((uint32_t)h);
        if (row.has_value()) window.push_back(row.value());
    }
    if ((int64_t)window.size() >= (int64_t)std::max(1, P.pinMinBundles)) {                              // PIN-1
        int64_t aLo = -1, aHi = -1;
        for (const BundleLogRecord& row : window) {
            if (row.aMint <= 0) continue;                          // an undefined statistic is never a value (audit A-4)
            if (aLo < 0 || row.aMint < aLo) aLo = row.aMint;
            if (row.aMint > aHi) aHi = row.aMint;
        }
        if (aLo >= 0 && (aHi - aLo) * BPS > (int64_t)std::max(0, P.pinDeltaBps) * aLo) {
            std::map<uint160, std::pair<int, std::set<uint64_t>>> perKey;   // key -> (quote count, prices)
            for (int64_t h = std::max<int64_t>(H - P.pinWindow, P.startHeight); h <= H - 1; h++) {
                std::optional<TagRecord> t = TagAt(st.View(), P, h);
                if (!t.has_value() || !t->IsQuote()) continue;
                perKey[t->payoutKey].first++;
                perKey[t->payoutKey].second.insert(t->priceMicroUsd);
            }
            for (const auto& kv : perKey) {
                if (kv.second.first >= std::max(1, P.pinMinTags) && kv.second.second.size() == 1) s.pinnedKeys.push_back(kv.first);
            }
            std::sort(s.pinnedKeys.begin(), s.pinnedKeys.end());
        }
    }
    {                                                                                                  // PIN-2
        std::optional<Snapshot> s1 = SnapshotAt(st, P, H - 1);
        std::optional<Snapshot> s0 = SnapshotAt(st, P, H - 1 - P.pinWindow);
        std::optional<MicroUsd> x1 = s1.has_value() ? s1->PMint() : std::nullopt;
        std::optional<MicroUsd> x0 = s0.has_value() ? s0->PMint() : std::nullopt;
        if (x1.has_value() && x0.has_value()) {
            const int64_t lo = std::min(x1.value(), x0.value()), diff = std::max(x1.value(), x0.value()) - lo;
            if (diff * BPS > (int64_t)std::max(0, P.pinDeltaBps) * lo) {
                // seq -> (rows, prices, cited heights): a seq is pinned only when it signed one price at
                // PIN_MIN_TAGS distinct cited heights across PIN_MIN_TAGS rows. One attestation reused by
                // several bundles is one cited height and cannot pin (audit A-2).
                std::map<uint16_t, std::tuple<int, std::set<int64_t>, std::set<uint32_t>>> perSeq;
                for (const BundleLogRecord& row : window) {
                    std::set<uint16_t> seen;
                    for (size_t i = 0; i < row.seqs.size() && i < row.prices.size(); i++) {
                        if (seen.insert(row.seqs[i]).second) std::get<0>(perSeq[row.seqs[i]])++;
                        std::get<1>(perSeq[row.seqs[i]]).insert(row.prices[i]);
                        if (i < row.citedHeights.size()) std::get<2>(perSeq[row.seqs[i]]).insert(row.citedHeights[i]);
                    }
                }
                for (const auto& kv : perSeq) {
                    if (std::get<0>(kv.second) >= std::max(1, P.pinMinTags) && std::get<1>(kv.second).size() == 1
                        && (int64_t)std::get<2>(kv.second).size() >= (int64_t)std::max(1, P.pinMinTags)) s.pinnedSeqs.push_back(kv.first);
                }
            }
        }
    }
    // seating: the N_SLOTS ELIGIBLE seq of greatest weight(seq, H), ties by seq; seatedSince follows membership
    {
        std::vector<std::pair<arith_uint256, uint16_t>> ranked;
        for (const auto& r : attestors) {
            if (r.second.Status() == AttestorStatus::ELIGIBLE) ranked.push_back(std::make_pair(AttestorWeight(r.second, m, P, H), r.first));
        }
        std::sort(ranked.begin(), ranked.end(), [](const std::pair<arith_uint256, uint16_t>& x, const std::pair<arith_uint256, uint16_t>& y) {
            if (x.first != y.first) return x.first > y.first;
            return x.second < y.second;
        });
        // the set's seats bound N_SLOTS (P4-b; ELIGIBLE records are ACTIVE members, at most seats of them, so this binds only on paper)
        const int64_t slots = std::min<int64_t>(std::max(0, P.nSlots), aset.has_value() ? (int64_t)aset->seats : 0);
        for (size_t i = 0; i < ranked.size() && (int64_t)i < slots; i++) s.seated.push_back(ranked[i].second);
        std::sort(s.seated.begin(), s.seated.end());
        for (auto& r : attestors) {
            const bool in = std::find(s.seated.begin(), s.seated.end(), r.first) != s.seated.end();
            if (in && r.second.seatedSince == 0) r.second.seatedSince = height;
            if (!in && r.second.seatedSince != 0) r.second.seatedSince = 0;
        }
    }

    // PRICE-1..2 (the medians skip the quote tags of keys pinned at H)
    const int maxWindow = std::max(P.pFastWindow, std::max(P.pMidWindow, P.pSlowWindow));
    const std::vector<std::pair<int64_t, MicroUsd>> prices = QuotePrices(st.View(), P, H - maxWindow, H, s.pinnedKeys);
    std::optional<MicroUsd> pFast = WindowMedian(prices, H, P.pFastWindow, P.pFastMinFill);
    std::optional<MicroUsd> pMid = WindowMedian(prices, H, P.pMidWindow, P.pMidMinFill);
    std::optional<MicroUsd> pSlow = WindowMedian(prices, H, P.pSlowWindow, P.pSlowMinFill);
    std::optional<MicroUsd> pMint, pClaim;
    if (pFast.has_value() && pMid.has_value() && pSlow.has_value()) pMint = std::min(pFast.value(), std::min(pMid.value(), pSlow.value()));
    if (pMid.has_value() && pSlow.has_value()) pClaim = std::max(pMid.value(), pSlow.value());
    s.pFast = pFast.value_or(0);
    s.pMid = pMid.value_or(0);
    s.pSlow = pSlow.value_or(0);
    s.pMint = pMint.value_or(0);
    s.pClaim = pClaim.value_or(0);

    // SIGMA-1: s_0 is this SNAP's pFast, s_k = Snapshots[H - k * VOL_STEP].pFast; a virtual or missing sample is undefined (K12)
    std::vector<std::optional<MicroUsd>> samples;
    samples.push_back(pFast);
    if (P.volStep > 0) {
        for (int k = 1; k <= P.volWindow / P.volStep; k++) {
            std::optional<Snapshot> sk = SnapshotAt(st, P, H - (int64_t)k * P.volStep);
            samples.push_back(sk.has_value() ? sk->PFast() : std::nullopt);
        }
    }
    s.sigmaMultBps = SigmaMultBps(samples, P.sigmaRefBps, P.volPeriodsPerYear, P.sigmaMultMaxBps);

    // Issuance, totals, global ratio
    std::optional<Snapshot> prevOpt = SnapshotAt(st, P, H - 1);
    const Snapshot prev = prevOpt.has_value() ? prevOpt.value() : Snapshot();
    s.issuedZat = (CAmount)((uint64_t)prev.issuedZat + (uint64_t)subsidyZat);       // wraps rather than overflows (total)
    const Totals totals = st.GetTotals();
    s.supplyCents = totals.supplyCents;
    s.collateralZat = totals.collateralZat;
    std::optional<int64_t> ratio = GlobalRatioBps(s.collateralZat, pMint, s.supplyCents);
    s.globalRatioBps = ratio.value_or(0);

    // HALT-1..3 (HALT-4's NOT_ACTIVE, ACT-4's PARTICIPATION and ACT-6's ENFORCEMENT left with the upgrade, §6)
    uint32_t mask = 0;
    if (!pMint.has_value()) mask |= HALT_NO_PRICE;                                                          // HALT-1
    if (pMint.has_value() && s.supplyCents > 0 && ratio.has_value() && ratio.value() < P.globalRatioHaltBps) mask |= HALT_GLOBAL_RATIO; // HALT-2
    if (pFast.has_value() && pMid.has_value() && pSlow.has_value()) {                                       // HALT-3
        const int64_t k = BPS - P.divergenceBps;
        if (pFast.value() * BPS < k * pMid.value() || pMid.value() * BPS < k * pSlow.value()) mask |= HALT_DIVERGENCE;
    }
    s.haltMask = mask;

    // dormancy (v3, S15): only at H mod DORMANCY_CHECK == 0, with seatedSince and the BundleLog window (H - DORMANCY_BLOCKS, H]
    if (P.dormancyCheck > 0 && H % P.dormancyCheck == 0) {
        std::vector<BundleLogRecord> rows;
        for (int64_t h = std::max<int64_t>(H - P.dormancyBlocks + 1, P.startHeight); h <= H; h++) {
            if (h < 0 || h > 0xFFFFFFFFLL) continue;
            std::optional<BundleLogRecord> row = st.GetBundleLog((uint32_t)h);
            if (row.has_value()) rows.push_back(row.value());
        }
        for (auto& r : attestors) {
            if (r.second.Status() != AttestorStatus::ELIGIBLE || r.second.seatedSince == 0) continue;
            if ((int64_t)r.second.seatedSince > H - P.dormancyBlocks) continue;
            int selectedRows = 0;
            bool signedAny = false;
            for (const BundleLogRecord& row : rows) {
                if (std::find(row.selectedSeqs.begin(), row.selectedSeqs.end(), r.first) == row.selectedSeqs.end()) continue;
                selectedRows++;
                if (std::find(row.seqs.begin(), row.seqs.end(), r.first) != row.seqs.end()) signedAny = true;
            }
            if (selectedRows >= std::max(1, P.dormancyMinBundles) && !signedAny) {
                r.second.status = (uint8_t)AttestorStatus::DORMANT;
                r.second.statusHeight = height;
            }
        }
    }
    // write every attestor record the passes changed
    for (size_t i = 0; i < attestors.size(); i++) {
        if (SerializeRecord(attestors[i].second) != attestorBefore[i]) st.Put(keys::Attestor(attestors[i].first), attestors[i].second);
    }
    return s;
}

// ---------------------------------------------------------------------------
// Blocks

TxOutcome ProcessTx(State& st, const Params& params, const CTransaction& tx, int height, SigCache* cache)
{
    EvalContext ctx(st, params, height, cache);
    return ProcessTxImpl(ctx, tx);
}

BlockEvaluation EvaluateBlock(OverlayStateView& overlay, const Params& params, const CBlock& block, int height,
                              const uint256& blockHash, CAmount subsidyZat, SigCache* cache)
{
    BlockEvaluation ev;
    if (height < params.startHeight) return ev;          // ignored completely (§3.8)
    ev.undo.height = height;
    State st(overlay, &ev.undo);
    EvalContext ctx(st, params, height, cache);

    // The records the state hash always carries (Params, Totals; v3 AttestorSeq, Attest) exist from the first applied block.
    if (!st.Has(keys::Params())) st.Put(keys::Params(), ParamsRecord(params));
    if (!st.Has(keys::Totals())) st.Put(keys::Totals(), Totals());
    if (!st.Has(keys::AttestorSeq())) st.Put(keys::AttestorSeq(), AttestorSeqRecord());

    // TAG-1..5: the coinbase scriptSig, read first
    std::optional<CoinbaseTag> tag;
    if (!block.vtx.empty() && block.vtx[0].IsCoinBase() && !block.vtx[0].vin.empty()) {
        tag = FindTag(block.vtx[0].vin[0].scriptSig, height);
    }
    if (tag.has_value()) {
        TagRecord t;
        t.payoutKey = tag->payoutKey;
        t.priceMicroUsd = tag->priceMicroUsd;
        t.signal = tag->Signal();
        t.sourceMask = tag->sourceMask;
        st.Put(keys::Tag((uint32_t)height), t);
    }

    // Transactions in block order (TX-0 skips every coinbase, whose outputs may not be YED templates either,
    // U-23). BLK-1: the first invalid transaction makes the block invalid; the rest is not evaluated (the
    // caller discards the overlay).
    for (const CTransaction& tx : block.vtx) {
        if (tx.IsCoinBase()) {
            for (const CTxOut& o : tx.vout) {
                if (IsYedVaultOutput(o.scriptPubKey) || IsYedIntentOutput(o.scriptPubKey)) {
                    ev.blockInvalid = true;
                    ev.verdict = verdict::YED_TEMPLATE_OUTPUT;
                    ev.reason = ev.verdict + ":" + tx.GetHash().GetHex();
                    return ev;
                }
            }
            continue;
        }
        TxOutcome o = ProcessTxImpl(ctx, tx);
        if (o.invalid) {
            ev.txlogs.push_back(std::make_pair(tx.GetHash(), o.log));   // the dry runs (DryRun, yed_getblockverdict) read its verdict
            ev.blockInvalid = true;
            ev.verdict = o.log.verdict;
            ev.reason = o.log.verdict + ":" + tx.GetHash().GetHex();
            return ev;
        }
        if (o.relevant) ev.txlogs.push_back(std::make_pair(tx.GetHash(), o.log));
    }

    // BundleLog[H] (R12), before SNAP: dormancy reads the row of H
    if (std::optional<BundleLogRecord> row = ctx.BundleRow()) st.Put(keys::BundleLog((uint32_t)height), row.value());

    // SNAP
    ev.snapshot = ComputeSnapshot(st, params, height, blockHash, subsidyZat, tag);
    st.Put(keys::Snapshot((uint32_t)height), ev.snapshot);
    TipRecord tip;
    tip.height = height;
    tip.blockHash = blockHash;
    tip.schemaVersion = SCHEMA_VERSION;
    tip.network = params.network;
    st.Put(keys::Tip(), tip);
    return ev;
}

std::optional<std::string> ApplyBlock(StateView& view, const Params& params, const CBlock& block, int height,
                                      const uint256& blockHash, CAmount subsidyZat, UndoRecord& undo, SigCache* cache)
{
    OverlayStateView overlay(view);
    BlockEvaluation ev = EvaluateBlock(overlay, params, block, height, blockHash, subsidyZat, cache);
    overlay.Commit();
    undo = ev.undo;
    return std::nullopt;
}

void UndoBlock(StateView& view, const UndoRecord& undo)
{
    for (const UndoEntry& e : undo.entries) {
        if (e.hadValue) view.Write(e.key, e.value);
        else view.Erase(e.key);
    }
}

// ---------------------------------------------------------------------------
// v3: attestors, arming, selection (v3 plan §3.7, W9)

std::optional<std::pair<Attestation, Attestation>> EquivocationEvidence(const CTransaction& tx, const Params& P)
{
    std::optional<FoundPayload> fp = FindPayload(tx);
    if (!fp.has_value() || fp->payload.type != PayloadType::EQUIVOCATION) return std::nullopt;
    std::string reason;
    auto extracted = ExtractBundle(tx, P.bundleCarrier, false, std::vector<unsigned char>(), &reason);
    if (!extracted) return std::nullopt;
    std::optional<Bundle> bundle = DecodeBundle(extracted->first, 255);
    if (!bundle || bundle->atts.size() != 2) return std::nullopt;
    const Attestation& a = bundle->atts[0];
    const Attestation& b = bundle->atts[1];
    if (a.seq != b.seq || a.citedHeight != b.citedHeight || a.priceMicroUsd == b.priceMicroUsd) return std::nullopt;
    if ((int64_t)a.citedHeight < (int64_t)P.startHeight) return std::nullopt;
    return std::make_pair(a, b);
}

bool EquivocatedBy(const std::pair<Attestation, Attestation>& e, const CPubKey& key, const uint256& blockHash)
{
    const Attestation& a = e.first;
    const Attestation& b = e.second;
    return VerifyCompactSig(key, AttestMessage(a.seq, a.priceMicroUsd, a.citedHeight, blockHash), a.sig) &&
           VerifyCompactSig(key, AttestMessage(b.seq, b.priceMicroUsd, b.citedHeight, blockHash), b.sig);
}

bool ArmedAt(const StateView& view, const Params& P, int refHeight)
{
    std::optional<Snapshot> s = SnapshotAt(State(const_cast<StateView&>(view)), P, refHeight);
    return s.has_value() && P.IsArmed(s->attest.IsArmed());
}

std::vector<unsigned char> OutPointSelector(const COutPoint& out)
{
    std::vector<unsigned char> v(out.hash.begin(), out.hash.end());
    for (int i = 0; i < 4; i++) v.push_back((unsigned char)((out.n >> (8 * i)) & 0xff));
    return v;
}

int64_t AgeOrigin(const AttestorRecord& rec, const AttestState& attest, const Params& P)
{
    if (attest.Status() != AttestStatus::UNARMED && (int64_t)rec.registerHeight <= (int64_t)attest.triggerHeight + P.foundingWindow) {
        return attest.triggerHeight;
    }
    return rec.registerHeight;
}

arith_uint256 AttestorWeight(const AttestorRecord& rec, const AttestState& attest, const Params& P, int64_t height)
{
    return BondWeight(rec.bondZat, height - AgeOrigin(rec, attest, P), P.ageCap);
}

std::vector<uint16_t> Seated(const StateView& view, const Params& P, int height)
{
    State st(const_cast<StateView&>(view));
    const AttestState m = st.GetAttest();
    std::vector<std::pair<arith_uint256, uint16_t>> ranked;
    for (const auto& r : st.Attestors()) {
        if (r.second.Status() == AttestorStatus::ELIGIBLE) ranked.push_back(std::make_pair(AttestorWeight(r.second, m, P, height), r.first));
    }
    std::sort(ranked.begin(), ranked.end(), [](const std::pair<arith_uint256, uint16_t>& x, const std::pair<arith_uint256, uint16_t>& y) {
        if (x.first != y.first) return x.first > y.first;
        return x.second < y.second;
    });
    std::vector<uint16_t> seated;
    const std::optional<AttestorSetRecord> aset = st.GetAttestorSet();
    const int64_t slots = std::min<int64_t>(std::max(0, P.nSlots), aset.has_value() ? (int64_t)aset->seats : 0);
    for (size_t i = 0; i < ranked.size() && (int64_t)i < slots; i++) seated.push_back(ranked[i].second);
    std::sort(seated.begin(), seated.end());
    return seated;
}

std::vector<uint16_t> SelectAttestors(const uint256& blockHash, const std::vector<unsigned char>& selector,
                                      const std::vector<std::pair<uint16_t, arith_uint256>>& poolIn, int rounds)
{
    std::vector<std::pair<uint16_t, arith_uint256>> pool = poolIn;
    std::sort(pool.begin(), pool.end(), [](const std::pair<uint16_t, arith_uint256>& x, const std::pair<uint16_t, arith_uint256>& y) {
        return x.first < y.first;
    });
    std::vector<uint16_t> chosen;
    for (int i = 0; i < rounds && !pool.empty(); i++) {
        arith_uint256 total = 0;
        for (const auto& c : pool) total += c.second;
        if (total == 0) {                                      // every remaining weight is zero: lowest seq first
            chosen.push_back(pool.front().first);
            pool.erase(pool.begin());
            continue;
        }
        unsigned char digest[CSHA256::OUTPUT_SIZE];
        const unsigned char round = (unsigned char)(i & 0xff);
        CSHA256().Write(blockHash.begin(), 32).Write(selector.empty() ? nullptr : selector.data(), selector.size())
                 .Write((const unsigned char*)"S", 1).Write(&round, 1).Finalize(digest);
        const arith_uint256 seed = UintToArith256(uint256(std::vector<unsigned char>(digest, digest + 32)));
        const arith_uint256 pick = seed - (seed / total) * total;      // seed mod total (base_uint has no operator%)
        arith_uint256 cumulative = 0;
        for (size_t j = 0; j < pool.size(); j++) {
            cumulative += pool[j].second;
            if (cumulative > pick) {
                chosen.push_back(pool[j].first);
                pool.erase(pool.begin() + j);
                break;
            }
        }
    }
    return chosen;
}

std::vector<uint16_t> Selected(const StateView& view, const Params& P, int refHeight, const std::vector<unsigned char>& selector)
{
    State st(const_cast<StateView&>(view));
    if (refHeight < P.startHeight || refHeight < 0) return {};
    std::optional<Snapshot> s = st.GetSnapshot((uint32_t)refHeight);
    if (!s.has_value()) return {};
    std::vector<std::pair<uint16_t, arith_uint256>> pool;
    for (uint16_t seq : s->seated) {
        if (std::find(s->pinnedSeqs.begin(), s->pinnedSeqs.end(), seq) != s->pinnedSeqs.end()) continue;
        std::optional<AttestorRecord> rec = st.GetAttestor(seq);
        if (!rec.has_value()) continue;                        // cannot happen (records are never deleted); stated for totality
        pool.push_back(std::make_pair(seq, AttestorWeight(rec.value(), s->attest, P, refHeight)));
    }
    return SelectAttestors(s->blockHash, selector, pool, std::max(0, P.mSelect) + std::max(0, P.kSlack));
}

BundleVerdict VerifyTxBundle(const StateView& view, const Params& P, const CTransaction& tx, int refHeight,
                             const std::vector<unsigned char>& selector, bool skipVin0, SigCache* cache,
                             std::vector<uint16_t>* selectedOut)
{
    State st(const_cast<StateView&>(view));
    const std::vector<uint16_t> selected = Selected(view, P, refHeight, selector);
    if (selectedOut) *selectedOut = selected;
    BundleLimits limits;
    limits.attestMaxAge = P.attestMaxAge;
    limits.mSelect = (size_t)std::max(0, P.mSelect);
    limits.bundleMax = (size_t)std::max(0, P.bundleMax);
    limits.startHeight = P.startHeight;
    limits.priceMin = PRICE_MIN;
    limits.priceMax = PRICE_MAX;
    auto pubkeyOf = [&](uint16_t seq) -> std::optional<CPubKey> {
        std::optional<AttestorRecord> rec = st.GetAttestor(seq);
        if (!rec.has_value()) return std::nullopt;
        return rec->AttestorKey();
    };
    auto blockHashAt = [&](int h) -> std::optional<uint256> { return BlockHashAt(view, P, h); };
    BundleVerdict v = VerifyBundle(tx, P.bundleCarrier, skipVin0, std::vector<unsigned char>(), refHeight, selected, limits, pubkeyOf, blockHashAt, cache);
    if (!v.ok) return v;
    std::optional<Snapshot> s = refHeight >= P.startHeight && refHeight >= 0 ? st.GetSnapshot((uint32_t)refHeight) : std::nullopt;
    const AttestState attest = s.has_value() ? s->attest : AttestState();
    std::vector<arith_uint256> weights;
    for (const Attestation& a : v.C) {
        std::optional<AttestorRecord> rec = st.GetAttestor(a.seq);
        weights.push_back(rec.has_value() ? AttestorWeight(rec.value(), attest, P, refHeight) : arith_uint256(0));
    }
    auto stat = BundleStat(v.C, weights, limits.mSelect, P.qLowBps, P.qHighBps);
    v.aMint = stat.first;
    v.aClaim = stat.second;
    return v;
}

std::optional<uint16_t> DefaultAttestPayee(const StateView& view, const Params& P, int refHeight,
                                           const std::vector<unsigned char>& selector, const std::vector<uint16_t>& Ain,
                                           const AttestPolicy& policy)
{
    if (Ain.empty()) return std::nullopt;
    std::vector<uint16_t> A = Ain;
    std::sort(A.begin(), A.end());
    A.erase(std::unique(A.begin(), A.end()), A.end());
    if (policy.preferred.has_value() && std::find(A.begin(), A.end(), policy.preferred.value()) != A.end()) return policy.preferred;
    uint256 blockHash;
    if (refHeight >= P.startHeight && refHeight >= 0) {
        std::optional<Snapshot> s = State(const_cast<StateView&>(view)).GetSnapshot((uint32_t)refHeight);
        if (s.has_value()) blockHash = s->blockHash;
    }
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(blockHash.begin(), 32).Write(selector.empty() ? nullptr : selector.data(), selector.size())
             .Write((const unsigned char*)"A", 1).Finalize(digest);
    const arith_uint256 seed = UintToArith256(uint256(std::vector<unsigned char>(digest, digest + 32)));
    const arith_uint256 n((uint64_t)A.size());
    const arith_uint256 idx = seed - (seed / n) * n;
    return A[(size_t)idx.GetLow64()];
}

} // namespace yellowback
