// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yellowback/coinselect.h"

#include <algorithm>
#include <numeric>

namespace yellowback {

const char* SelectStageName(SelectStage stage)
{
    switch (stage) {
    case SelectStage::EXACT:  return "exact";
    case SelectStage::SINGLE: return "single";
    case SelectStage::GREEDY: return "greedy";
    case SelectStage::SEARCH: return "search";
    case SelectStage::BURN:   return "burn";
    case SelectStage::NONE:   break;
    }
    return "none";
}

namespace {

/**
 * The coins ranked for the search: descending by cents, ties by their position in the caller's
 * vector. Descending is what makes the pruning bite (a target is reached in few steps) and the
 * tie-break is what makes the whole selector independent of the order the caller listed its
 * coins in — two wallets with the same coins select the same amounts (H1, determinism).
 */
std::vector<size_t> RankDescending(const std::vector<int64_t>& coins)
{
    std::vector<size_t> order(coins.size());
    std::iota(order.begin(), order.end(), (size_t)0);
    std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) {
        if (coins[a] != coins[b]) return coins[a] > coins[b];
        return a < b;
    });
    return order;
}

/** The ranked coins ascending (the greedy stage: smallest first, so small outputs consolidate, H11). */
std::vector<size_t> RankAscending(const std::vector<int64_t>& coins)
{
    std::vector<size_t> order = RankDescending(coins);
    std::reverse(order.begin(), order.end());
    // Reversing a descending stable order puts equal coins in descending position order; restore
    // ascending position for equal coins so the ranking is the documented (cents, index) order.
    std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) {
        if (coins[a] != coins[b]) return coins[a] < coins[b];
        return a < b;
    });
    return order;
}

/** What a depth-first walk is looking for. */
enum class Goal {
    EXACT,          //!< sum == target, fewest inputs
    VALID_CHANGE,   //!< sum == target or sum >= target + minOutput, smallest change then fewest inputs
    OVERSHOOT,      //!< sum >= target, smallest sum (H4: the cheapest remainder to burn)
    ABOVE,          //!< sum > target, smallest sum (H2: the nearest workable amount above)
    BELOW,          //!< sum < target, largest sum (H2)
};

struct Walk
{
    const std::vector<int64_t>& coins;
    const std::vector<size_t>& order;     //!< descending
    std::vector<int64_t> suffix;          //!< suffix[i] = sum of order[i..] (the reachability bound)
    int64_t target;
    int64_t minOutput;
    size_t maxInputs;
    Goal goal;
    int64_t budget;

    bool found;
    int64_t bestSum;
    std::vector<size_t> bestPick;         //!< positions in `order`
    std::vector<size_t> pick;

    Walk(const std::vector<int64_t>& coins, const std::vector<size_t>& order, int64_t target,
         int64_t minOutput, size_t maxInputs, Goal goal, int64_t budget)
        : coins(coins), order(order), target(target), minOutput(minOutput), maxInputs(maxInputs),
          goal(goal), budget(budget), found(false), bestSum(0)
    {
        suffix.assign(order.size() + 1, 0);
        for (size_t i = order.size(); i > 0; i--) suffix[i - 1] = suffix[i] + coins[order[i - 1]];
    }

    bool Better(int64_t sum, size_t count) const
    {
        if (!found) return true;
        switch (goal) {
        case Goal::EXACT:        return count < bestPick.size();
        case Goal::VALID_CHANGE: return sum < bestSum || (sum == bestSum && count < bestPick.size());
        case Goal::OVERSHOOT:    return sum < bestSum || (sum == bestSum && count < bestPick.size());
        case Goal::ABOVE:        return sum < bestSum;
        case Goal::BELOW:        return sum > bestSum;
        }
        return false;
    }

    void Record(int64_t sum)
    {
        if (!Better(sum, pick.size())) return;
        found = true;
        bestSum = sum;
        bestPick = pick;
    }

    /** True when the goal can no longer be improved on this branch (and the whole walk may stop). */
    bool Done() const
    {
        return found && ((goal == Goal::EXACT && bestPick.size() == 1) ||
                         ((goal == Goal::VALID_CHANGE || goal == Goal::OVERSHOOT) && bestSum == target));
    }

    void Descend(size_t pos, int64_t sum)
    {
        if (budget <= 0 || Done()) return;
        budget--;
        for (size_t i = pos; i < order.size(); i++) {
            if (budget <= 0 || Done()) return;
            const int64_t value = coins[order[i]];
            const int64_t next = sum + value;
            // Reachability: even taking every remaining coin cannot reach the target.
            if (goal != Goal::BELOW && sum + suffix[i] < target) return;
            pick.push_back(i);
            bool descend = pick.size() < maxInputs;
            switch (goal) {
            case Goal::EXACT:
                if (next == target) { Record(next); descend = false; }
                else if (next > target) descend = false;     // positive coins: no way back down
                break;
            case Goal::VALID_CHANGE:
                if (next == target || next >= target + minOutput) { Record(next); descend = false; }
                // a crossing that lands in the forbidden band can only be fixed by adding more
                else if (next > target) { /* keep descending: any further coin lifts it out */ }
                break;
            case Goal::OVERSHOOT:
                if (next >= target) { Record(next); descend = false; }
                break;
            case Goal::ABOVE:
                if (next > target) { Record(next); descend = false; }
                break;
            case Goal::BELOW:
                if (next < target) Record(next);
                else descend = false;
                break;
            }
            if (descend) Descend(i + 1, next);
            pick.pop_back();
        }
    }

    /** The selected coin indexes (into the caller's vector), ascending. */
    std::vector<size_t> Result() const
    {
        std::vector<size_t> out;
        for (size_t p : bestPick) out.push_back(order[p]);
        std::sort(out.begin(), out.end());
        return out;
    }
};

Selection Make(SelectStage stage, const std::vector<int64_t>& coins, const std::vector<size_t>& idx,
               int64_t target, int64_t extraBurn)
{
    Selection s;
    s.ok = true;
    s.stage = stage;
    s.inputs = idx;
    s.selected = 0;
    for (size_t i : idx) s.selected += coins[i];
    s.extraBurn = extraBurn;
    s.change = s.selected - target - extraBurn;
    return s;
}

/** The most the H11 cap can reach: the sum of the `maxInputs` largest coins. */
int64_t Reachable(const std::vector<int64_t>& coins, const std::vector<size_t>& desc, size_t maxInputs)
{
    int64_t sum = 0;
    for (size_t i = 0; i < desc.size() && i < maxInputs; i++) sum += coins[desc[i]];
    return sum;
}

} // namespace

Selection SelectFloorAware(const std::vector<int64_t>& coins, int64_t target, int64_t minOutput,
                           size_t maxInputs, bool allowSubDollarBurn)
{
    Selection none;
    if (target < 0) return none;
    if (target == 0) { none.ok = true; none.stage = SelectStage::EXACT; return none; }

    int64_t total = 0;
    for (int64_t c : coins) {
        if (c <= 0) continue;
        total += c;
    }
    if (total < target) { none.insufficient = true; return none; }

    const std::vector<size_t> desc = RankDescending(coins);
    if (Reachable(coins, desc, maxInputs) < target) { none.tooManyInputs = true; return none; }

    // 1. Exact match: change 0 needs no floor at all.
    {
        Walk w(coins, desc, target, minOutput, maxInputs, Goal::EXACT, SELECT_SEARCH_BUDGET);
        w.Descend(0, 0);
        if (w.found) return Make(SelectStage::EXACT, coins, w.Result(), target, 0);
    }

    // 2. One input whose change clears the floor: the smallest such coin.
    {
        const std::vector<size_t> asc = RankAscending(coins);
        for (size_t i : asc) {
            if (coins[i] >= target + minOutput) {
                return Make(SelectStage::SINGLE, coins, { i }, target, 0);
            }
        }
    }

    // 3. Greedy smallest-first, extended while the change lies in the forbidden band. This is
    //    also what consolidates small outputs (H11: no consolidation RPC).
    {
        const std::vector<size_t> asc = RankAscending(coins);
        std::vector<size_t> pick;
        int64_t sum = 0;
        for (size_t i : asc) {
            if (coins[i] <= 0) continue;
            if (pick.size() == maxInputs) break;
            pick.push_back(i);
            sum += coins[i];
            if (sum < target) continue;
            const int64_t change = sum - target;
            if (change == 0 || change >= minOutput) {
                std::sort(pick.begin(), pick.end());
                return Make(SelectStage::GREEDY, coins, pick, target, 0);
            }
            // change is in (0, minOutput): keep extending (the next coin lifts it out).
        }
    }

    // 4. Bounded search for the smallest valid change, then the fewest inputs.
    {
        Walk w(coins, desc, target, minOutput, maxInputs, Goal::VALID_CHANGE, SELECT_SEARCH_BUDGET);
        w.Descend(0, 0);
        if (w.found) return Make(SelectStage::SEARCH, coins, w.Result(), target, 0);
    }

    // H4: a REDEEM or a CLAIM may burn a sub-dollar remainder rather than strand the vault.
    if (allowSubDollarBurn) {
        Walk w(coins, desc, target, minOutput, maxInputs, Goal::OVERSHOOT, SELECT_SEARCH_BUDGET);
        w.Descend(0, 0);
        if (w.found) {
            const int64_t extra = w.bestSum - target;
            if (extra > 0 && extra < minOutput) return Make(SelectStage::BURN, coins, w.Result(), target, extra);
        }
    }
    return none;
}

Alternatives NearestWorkable(const std::vector<int64_t>& coins, int64_t target, int64_t minOutput, size_t maxInputs)
{
    Alternatives alt;
    const std::vector<size_t> desc = RankDescending(coins);
    const int64_t reach = Reachable(coins, desc, maxInputs);
    if (reach <= 0) return alt;

    // Above: every workable amount above the target is an achievable sum (an amount below the
    // reachable total by at least minOutput is workable, and the target is not, so the target is
    // already within minOutput of it). The smallest achievable sum strictly above it is the answer.
    {
        Walk w(coins, desc, target, minOutput, maxInputs, Goal::ABOVE, SELECT_SEARCH_BUDGET);
        w.Descend(0, 0);
        int64_t above = w.found ? w.bestSum : 0;
        if (reach > target && (!w.found || reach < above)) above = reach;   // the total is always achievable
        if (above > target) alt.above = above;
    }
    // Below: anything at or under reach - minOutput is workable (spend everything, the change
    // clears the floor), and an achievable sum below the target is workable exactly.
    {
        int64_t below = reach - minOutput;
        Walk w(coins, desc, target, minOutput, maxInputs, Goal::BELOW, SELECT_SEARCH_BUDGET);
        w.Descend(0, 0);
        if (w.found && w.bestSum > below) below = w.bestSum;
        if (below >= minOutput && below < target) alt.below = below;
    }
    return alt;
}

} // namespace yellowback
