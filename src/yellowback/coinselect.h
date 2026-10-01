// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_YELLOWBACK_COINSELECT_H
#define YCASH_YELLOWBACK_COINSELECT_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

/**
 * The floor-aware YED coin selector (plan Phase 8 H1, H2, H4; §4.6 change
 * floor). Pure: amounts in, indexes out — no wallet, no index, no clock, no
 * randomness, so it is table-testable (src/test/yellowback_coinselect_tests.cpp)
 * and two wallets with the same coins and the same amount always pick the same
 * inputs.
 *
 * The problem it solves is Ycash-specific and has no DigiByte counterpart:
 * DigiDollar's transfers carry the amount in the output itself, so any change
 * is representable, while a Yellowback YED output must be assigned at least
 * MIN_OUTPUT ($1.00) cents by the payload (XFER-1) — change in (0, MIN_OUTPUT)
 * cannot be assigned and would burn. Smallest-first accumulation (the Phase 6
 * selector) hits that band whenever the overshoot is under a dollar, so a user
 * with a single $100.00 coin could not send $99.50. This selector tries, in
 * order:
 *
 *   1. EXACT   a subset summing exactly to the target (change 0);
 *   2. SINGLE  one input whose change is >= MIN_OUTPUT (the smallest such);
 *   3. GREEDY  smallest-first accumulation, extended by the next coin while
 *              the change lies in the forbidden band (H11: this is also what
 *              consolidates dust, so no consolidation RPC is needed);
 *   4. SEARCH  a bounded, deterministic depth-first search for the selection
 *              with the smallest valid change, then the fewest inputs.
 *
 * A TRANSFER that finds none of the four refuses (H2, `change-floor`) and
 * NearestWorkable() supplies the two amounts the message and
 * yed_estimatesend.alternatives carry. A REDEEM or a CLAIM may instead burn a
 * sub-dollar remainder (H4, stage BURN, `extraBurn` <= MIN_OUTPUT - 1 = $0.99)
 * because refusing would strand the vault; a selection with valid change is
 * always preferred to one that burns.
 */
namespace yellowback {

enum class SelectStage { NONE, EXACT, SINGLE, GREEDY, SEARCH, BURN };

/** "none" | "exact" | "single" | "greedy" | "search" | "burn" (the contract's yed_estimatesend.stage). */
const char* SelectStageName(SelectStage stage);

struct Selection
{
    bool ok;                      //!< a usable selection was found
    bool insufficient;            //!< !ok because the coins do not reach the target at all
    bool tooManyInputs;           //!< !ok because reaching the target would need more than maxInputs coins (H11)
    SelectStage stage;
    std::vector<size_t> inputs;   //!< indexes into the coins vector passed in, ascending
    int64_t selected;             //!< sum of the selected coins
    int64_t change;               //!< selected - target - extraBurn; 0 or >= minOutput
    int64_t extraBurn;            //!< H4 only: cents burned on top of the target, in [0, minOutput)

    Selection() : ok(false), insufficient(false), tooManyInputs(false), stage(SelectStage::NONE), selected(0), change(0), extraBurn(0) {}
};

/** The nearest amounts that *are* workable from the same coins (H2); nullopt when there is none. */
struct Alternatives
{
    std::optional<int64_t> below;
    std::optional<int64_t> above;
};

/**
 * Select for `target` cents out of `coins` (each > 0). `minOutput` is MIN_OUTPUT,
 * `maxInputs` the H11 cap (250). With `allowSubDollarBurn` (REDEEM/CLAIM, H4) a
 * selection whose remainder lies in (0, minOutput) is accepted as stage BURN when
 * and only when no stage 1-4 selection exists.
 *
 * Deterministic: the coins are ranked by (cents, index in `coins`), every stage
 * and every tie-break below is a total order, and nothing else is consulted.
 */
Selection SelectFloorAware(const std::vector<int64_t>& coins, int64_t target, int64_t minOutput,
                           size_t maxInputs, bool allowSubDollarBurn);

/** The largest workable amount strictly below `target` and the smallest strictly above it (H2). */
Alternatives NearestWorkable(const std::vector<int64_t>& coins, int64_t target, int64_t minOutput, size_t maxInputs);

/** The node budget of stage 4 and of NearestWorkable (a bound, never a source of non-determinism). */
static const int64_t SELECT_SEARCH_BUDGET = 200000;

} // namespace yellowback

#endif // YCASH_YELLOWBACK_COINSELECT_H
