// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_YELLOWBACK_STATE_H
#define YCASH_YELLOWBACK_STATE_H

#include "arith_uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "yellowback/bundle.h"
#include "yellowback/params.h"
#include "yellowback/payload.h"
#include "yellowback/tag.h"
#include "yellowback/view.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

/**
 * The Yellowback v2 state machine (plan §3.7–3.9): IN-1..3, TX-0, MINT-1..8,
 * XFER-1..3, RED-1..4, REG-4, ACT-1..6, PRICE-1..2, SIGMA-1, HALT-1..4, SNAP
 * and UNDO as pure functions of (block, state view, height, params, block
 * subsidy), extended by the v3 price-attestation rules (v3 plan §3.7–3.8):
 * REG-A1, the IN-2 bond spend, BUNDLE-1 (through bundle.h), MINT-9/10,
 * AFEE-0/1, RED-5, NOT-1, EQV-1, REV-1, ARM-1/2, PIN-1/2, seating, dormancy
 * and the revised SNAP order. The one input a v3 rule takes beyond the view
 * is the optional signature cache (W8), passed by the caller and nullable. Nothing here reads the clock, the transaction pool, the wallet or
 * configuration (§3.10); the block subsidy is an argument so this file links
 * against nothing in main.cpp (N22).
 *
 * Totality (K1, M1): EvaluateBlock never throws, never asserts on input and
 * never divides by an unchecked zero. A rule whose input is undefined — a
 * missing or virtual snapshot, an undefined price, a lookup that misses — is
 * false: a MINT rule that is false gives a VOID verdict, a RED rule that is
 * false gives the block-invalid verdict. Only BLK-1 (a failing spend of an
 * ACTIVE vault) can make a block invalid, and only ACT-5 decides whether an
 * enforcing node acts on it.
 *
 * DigiByte enforces the equivalent rules in consensus
 * (ref/digibyte/src/digidollar/validation.cpp) and rejects a failing
 * transaction outright; an overlay cannot reject a mint or transfer, so a
 * failing MINT registers a VOID vault and a failing TRANSFER burns (the
 * Runes "cenotaph" rule), while a failing ACTIVE-vault spend is the one
 * class of transaction enforcing miners refuse (V3).
 *
 * qa/rpc-tests/test_framework/yellowback_model.py is the second
 * implementation of this file; SERIALISATION.md next to it records every
 * reading of §3 both sides make (VOID vault record, judgement rows, fee
 * bookkeeping, verdict precedence).
 */
namespace yellowback {

/** Verdict strings (§4.2a). TxLog.verdict, Vaults.voidReason, yed_getblockverdict.reason match them. */
namespace verdict {
extern const char* const OK;
extern const char* const BURNED;                 //!< XFER-1..3 hold and Σ assigned < yedIn (a burn by rule)
extern const char* const NON_YELLOWBACK;         //!< dry runs only: the transaction touched nothing (never logged)
// MINT-2
extern const char* const BAD_MINT_AMOUNT;
extern const char* const BAD_MINT_CLASS;
extern const char* const BAD_MINT_LOCK_HEIGHT;
extern const char* const BAD_MINT_REF_HEIGHT;
// MINT-3
extern const char* const BAD_MINT_OUTPUTS;
extern const char* const BAD_MINT_OWNER_KEY;
extern const char* const BAD_MINT_VAULT_SCRIPT;
// MINT-4
extern const char* const MINT_NOT_ACTIVE;
extern const char* const MINT_HALTED_NO_PRICE;
extern const char* const MINT_HALTED_PARTICIPATION;
extern const char* const MINT_HALTED_GLOBAL_RATIO;
extern const char* const MINT_HALTED_DIVERGENCE;
// MINT-5
extern const char* const BAD_MINT_COLLATERAL;
extern const char* const MINT_UNSATISFIABLE;
// MINT-6
extern const char* const MINT_SUPPLY_CAP;
// MINT-7
extern const char* const BAD_MINT_TOKEN_OUTPUT;
// MINT-8
extern const char* const BAD_MINT_FEE;
// XFER-1..3
extern const char* const BAD_TRANSFER_ASSIGNMENT;
extern const char* const TRANSFER_OVER_ASSIGNED;
extern const char* const TRANSFER_NO_YED_INPUT;
// RED-1
extern const char* const VAULT_SPEND_MALFORMED;
// RED-2
extern const char* const VAULT_SPEND_MISSING_BURN;
extern const char* const VAULT_SPEND_SHORT_BURN;
// RED-3
extern const char* const VAULT_SPEND_BAD_FEE;
extern const char* const VAULT_SPEND_BAD_PAYEE;
// RED-4
extern const char* const VAULT_CLAIM_NOT_UNDERWATER;
// v3 (v3 plan §4.2a). The bundle failures carry BUNDLE-1's reason: "mint9-bundle-<reason>", "red1-bundle-<reason>".
extern const char* const MINT9_NO_BUNDLE;        //!< ARMED and no carrier-shaped input at all
extern const char* const MINT9_BUNDLE_PREFIX;    //!< "mint9-bundle-"
extern const char* const MINT10_DIVERGED;
extern const char* const RED1_BUNDLE_PREFIX;     //!< "red1-bundle-"
extern const char* const RED5_RESIDUAL;
extern const char* const AFEE1_FEE;
extern const char* const BUNDLE_STAT;            //!< the reason suffix when BUNDLE-1 held but the statistic is undefined
} // namespace verdict

/** The result of EvaluateBlock (§4.2a). */
struct BlockEvaluation
{
    bool blockInvalid;                 //!< BLK-1 condition, independent of ACT-5
    bool enforcementOn;                //!< ACT-5 at H (from Snapshots[H-1], incl. the sunset); blockInvalid && enforcementOn => reject
    std::string reason;                //!< "<verdict>:<txid>" of the first failing vault spend, else ""
    std::vector<std::pair<uint256, TxLogRecord>> txlogs;
    Snapshot snapshot;
    UndoRecord undo;

    BlockEvaluation() : blockInvalid(false), enforcementOn(false) {}
};

/** The result of ProcessTx. */
struct TxOutcome
{
    TxLogRecord log;
    bool relevant;      //!< a TxLog entry was written (the tx created or spent a Tokens/Vaults entry, N7)
    bool vaultSpend;    //!< the tx spent an ACTIVE vault (RED-1..4 applied, M3)
    bool redFailed;     //!< vaultSpend and RED-1..4 failed (the BLK-1 condition for this tx)

    TxOutcome() : relevant(false), vaultSpend(false), redFailed(false) {}
};

/**
 * Apply one non-coinbase transaction's effect on the state (§3.8): inputs
 * (IN-1..2) before outputs (MINT / XFER / RED), then IN-3. A coinbase is
 * TX-0: nothing happens and `relevant` is false. Writes the TxLog entry
 * when relevant. Total.
 */
TxOutcome ProcessTx(State& st, const Params& params, const CTransaction& tx, int height, SigCache* cache = nullptr);

/**
 * Evaluate a whole block into `overlay` without committing it (§3.8, §3.9
 * BLK-1): the coinbase tag first (TAG-1..5), then every transaction in
 * block order, then SNAP (REG-4, ACT-1..6, PRICE-1..2, SIGMA-1, HALT-1..4)
 * and the tip. Every write goes through the overlay and is recorded in the
 * returned undo record; the caller commits or discards. Below START_HEIGHT
 * nothing is written and the evaluation is empty. Total: no input can make
 * it throw (K1). Used by ConnectBlock, CreateNewBlock, MempoolCheck and
 * yed_getblockverdict.
 */
BlockEvaluation EvaluateBlock(OverlayStateView& overlay, const Params& params, const CBlock& block, int height,
                              const uint256& blockHash, CAmount subsidyZat, SigCache* cache = nullptr);

/**
 * EvaluateBlock over an overlay of `view`, then Commit(): the block is
 * applied to `view` and `undo` receives the inverse. Returns nullopt (the
 * v2 machine has no failure mode; the optional is kept for the index's
 * storage layer, which reports its own errors).
 */
std::optional<std::string> ApplyBlock(StateView& view, const Params& params, const CBlock& block, int height,
                                      const uint256& blockHash, CAmount subsidyZat, UndoRecord& undo, SigCache* cache = nullptr);

/** Restore every key recorded in `undo` to its pre-block value (byte-identical, UNDO). */
void UndoBlock(StateView& view, const UndoRecord& undo);

/**
 * SNAP for height H after the block's transactions (§3.7, §3.8; v3 §3.8
 * order): the REG-4 judgement for the tag at H - PEER_LAG (writes
 * Judgements), Activation (ACT-2/3; writes it), then the v3 passes —
 * maturity, ARM-1/2 (writes Attest), PIN-1/2, seating (writes seatedSince) —
 * the medians over the quote tags of keys not pinned at H, σ, issuance
 * (prev.issuedZat + subsidyZat), totals, halts, dormancy (writes Attestors
 * status) — and returns Snapshots[H]. BundleLog[H] must already be written
 * (EvaluateBlock does so before calling); dormancy reads it. `tag` is the
 * block's own tag, if any (tagged/quote fields). Total.
 */
Snapshot ComputeSnapshot(State& st, const Params& params, int height, const uint256& blockHash, CAmount subsidyZat,
                         const std::optional<CoinbaseTag>& tag);

/**
 * Snapshots[h] as a rule sees it: the virtual snapshot below START_HEIGHT
 * (§3.6), the stored record at or above it, nullopt when it is missing
 * (a rule reading it is then false).
 */
std::optional<Snapshot> SnapshotAt(const State& st, const Params& params, int64_t height);

/** ACT-5: enforcement at H from Snapshots[H - 1] (ACTIVE, ENFORCEMENT clear, H <= ENFORCE_UNTIL_HEIGHT). */
bool EnforcementOn(const State& st, const Params& params, int height);

/** ACT-1: valid tags with the signal bit in (H - SIGNAL_WINDOW, H]. */
uint32_t SignalCount(const State& st, const Params& params, int height);

/** E(R) (FEE-2): the payoutKeys of the quote tags at h in (R - PAYEE_WINDOW, R], height order, deduplicated, minus Snapshots[R].pinnedKeys (PIN-1); empty => FEE-0. */
std::vector<CKeyID> EligiblePayees(const StateView& view, const Params& params, int refHeight);

/** REG-1 (informational): some quote tag with this payoutKey exists in (R - N_REG, R]. */
bool Registered(const StateView& view, const Params& params, const CKeyID& key, int refHeight);
/** REG-2 (wallet policy, L6): a penalised quote at t with t + PEER_LAG < R <= t + PEER_LAG + penaltyBlocks. */
bool Penalized(const StateView& view, const Params& params, const CKeyID& key, int refHeight, int penaltyBlocks);
/** REG-3 (wallet policy, L6): 10^4 * inBand / quoted over the judged quotes in (R - PEER_LAG - window, R - PEER_LAG]; 0 if none. */
int AccuracyBps(const StateView& view, const Params& params, const CKeyID& key, int refHeight, int accuracyWindow);

/** The L6 knobs of FEE-W (node overrides of the §3.1 wallet defaults). */
struct PayeePolicy
{
    int penaltyBlocks;               //!< N_PENALTY
    int accuracyWindow;              //!< ACCURACY_WINDOW
    int tiltBps;                     //!< PAYEE_TILT_BPS
    std::optional<CKeyID> preferred; //!< -yellowbackpreferredpayee: replaces the pick when in E(R)

    PayeePolicy() : penaltyBlocks(0), accuracyWindow(0), tiltBps(0) {}
    /** The §3.1 defaults of a parameter set. */
    static PayeePolicy Defaults(const Params& p)
    {
        PayeePolicy pp;
        pp.penaltyBlocks = p.nPenalty;
        pp.accuracyWindow = p.accuracyWindow;
        pp.tiltBps = p.payeeTiltBps;
        return pp;
    }
};

/**
 * FEE-W, the wallet's default payee (policy, never a validity rule, L1):
 * over the quote tags in (R - PAYEE_WINDOW, R] whose key is not penalised,
 * weight 10^4 + tiltBps * accuracyBps / 10^4 each, seed = SHA256(blockHash(R)
 * ‖ selector) read as a little-endian uint64 from its first eight bytes,
 * pick = seed mod Σw, the first tag whose cumulative weight exceeds pick.
 * All penalised => every key of E(R) with equal weights. blockHash(R) is
 * Snapshots[R].blockHash (zero if missing). nullopt iff E(R) is empty.
 */
std::optional<CKeyID> DefaultPayee(const StateView& view, const Params& params, int refHeight,
                                   const std::vector<unsigned char>& selector, const PayeePolicy& policy);

// ---------------------------------------------------------------------------
// v3: attestors, arming, selection (v3 plan §3.7, W9)

/** "ARMED" as every v3 rule reads it for refHeight R: Snapshots[R].attest.status == ARMED and the set's ATTEST_REQUIRED (W15). */
bool ArmedAt(const StateView& view, const Params& params, int refHeight);

/** The 36-byte serialised COutPoint (txid internal bytes ‖ vout LE32): the selector of REDEEM claims and CLAIM_NOTICE (R13). */
std::vector<unsigned char> OutPointSelector(const COutPoint& out);

/** ageOrigin (§3.7): Attest.triggerHeight for a founding member (registerHeight <= triggerHeight + FOUNDING_WINDOW, status != UNARMED), else registerHeight. */
int64_t AgeOrigin(const AttestorRecord& rec, const AttestState& attest, const Params& params);

/** weight(seq, H) = bondZat * clamp(H - ageOrigin, 0, AGE_CAP) (§3.7), with the Attest state given. */
arith_uint256 AttestorWeight(const AttestorRecord& rec, const AttestState& attest, const Params& params, int64_t height);

/**
 * seated(H) over the current Attestors and the carried Attest: the N_SLOTS ELIGIBLE seq with the
 * greatest weight(seq, H), ties by seq ascending; returned ascending. SNAP calls it after ARM-1/2,
 * so Snapshots[H].seated is Seated(view, params, H) at that point.
 */
std::vector<uint16_t> Seated(const StateView& view, const Params& params, int height);

/**
 * W9 over an explicit pool (seq, weight): for round i in 0 .. rounds - 1 while the pool is non-empty,
 * seed_i = UintToArith256(SHA256(blockHash ‖ selector ‖ "S" ‖ u8 i)), pick = seed_i mod Σ weight
 * (256-bit, R10), chosen = the first seq in ascending order whose cumulative weight exceeds pick;
 * removed. Σ weight = 0 over the remaining pool => the remaining draws are the lowest seq first.
 * The Python reference is test_framework/yellowback_attest.py:select_attestors.
 */
std::vector<uint16_t> SelectAttestors(const uint256& blockHash, const std::vector<unsigned char>& selector,
                                      const std::vector<std::pair<uint16_t, arith_uint256>>& pool, int rounds);

/**
 * selected(R, selector): SelectAttestors over pool = Snapshots[R].seated \ Snapshots[R].pinnedSeqs (the
 * stored arrays, R11) with weight(s, R) under Snapshots[R].attest, M_SELECT + K_SLACK rounds, seeded by
 * Snapshots[R].blockHash. Empty when Snapshots[R] is missing or virtual.
 */
std::vector<uint16_t> Selected(const StateView& view, const Params& params, int refHeight, const std::vector<unsigned char>& selector);

/**
 * BUNDLE-1 for a transaction with refHeight R (bundle.h VerifyBundle with selected(R, selector), the
 * set's limits, Attestors' keys and Snapshots' block hashes), plus the bundle statistic under weight(s, R)
 * (aMint/aClaim of the verdict). `selectedOut`, when given, receives selected(R, selector). Total.
 */
BundleVerdict VerifyTxBundle(const StateView& view, const Params& params, const CTransaction& tx, int refHeight,
                             const std::vector<unsigned char>& selector, bool skipVin0, SigCache* cache,
                             std::vector<uint16_t>* selectedOut = nullptr);

/** The L6-style knob of AFEE-W (policy, never a validity rule). */
struct AttestPolicy
{
    std::optional<uint16_t> preferred;   //!< -yellowbackpreferredattestor: replaces the pick when in A
};

/**
 * AFEE-W, the wallet's default attestor payee (policy): `preferred` when it is in A; else A sorted
 * ascending and A[UintToArith256(SHA256(blockHash(R) ‖ selector ‖ "A")) mod |A|]. nullopt iff A is empty.
 */
std::optional<uint16_t> DefaultAttestPayee(const StateView& view, const Params& params, int refHeight,
                                           const std::vector<unsigned char>& selector, const std::vector<uint16_t>& A,
                                           const AttestPolicy& policy);

} // namespace yellowback

#endif // YCASH_YELLOWBACK_STATE_H
