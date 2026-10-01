// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The floor-aware YED selector (Phase 8 H1, H2, H4, H11), table-driven against
// adversarial coin sets: the sets that make smallest-first accumulation land in
// the forbidden change band (0, MIN_OUTPUT), sets where only an exact subset
// works, sets where only the bounded search finds a way, sets that cannot work
// at any input count, and the H11 cap. Written before the selector (H12).

#include "yellowback/coinselect.h"
#include "yellowback/params.h"
#include "yellowback/script.h"

#include "key.h"
#include "keystore.h"
#include "script/ismine.h"
#include "script/standard.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <numeric>
#include <string>

using namespace yellowback;

namespace {

const int64_t FLOOR = MainParams().minOutput;   // MIN_OUTPUT: 100 cents = $1.00
const size_t CAP = 250;             // H11

struct Case
{
    const char* name;
    std::vector<int64_t> coins;
    int64_t target;
    bool ok;                        //!< a TRANSFER selection exists (no burn allowed)
    SelectStage stage;              //!< the stage that must produce it (NONE when !ok)
    int64_t change;                 //!< the YED change it must leave
};

/** Every invariant a selection must satisfy whatever the stage (checked for every row). */
void CheckInvariants(const Case& c, const Selection& s, bool allowBurn)
{
    const std::string label(c.name);
    BOOST_CHECK_MESSAGE(s.extraBurn >= 0 && s.extraBurn < FLOOR, label + ": extraBurn out of [0, MIN_OUTPUT)");
    if (!s.ok) {
        BOOST_CHECK_MESSAGE(s.inputs.empty(), label + ": a failed selection must name no inputs");
        BOOST_CHECK_MESSAGE(s.stage == SelectStage::NONE, label + ": a failed selection must be stage NONE");
        return;
    }
    BOOST_CHECK_MESSAGE(s.inputs.size() <= CAP, label + ": more than the H11 cap of inputs");
    // indexes are distinct, ascending and in range
    for (size_t i = 0; i < s.inputs.size(); i++) {
        BOOST_CHECK_MESSAGE(s.inputs[i] < c.coins.size(), label + ": index out of range");
        if (i) BOOST_CHECK_MESSAGE(s.inputs[i - 1] < s.inputs[i], label + ": indexes not strictly ascending");
    }
    int64_t sum = 0;
    for (size_t i : s.inputs) sum += c.coins[i];
    BOOST_CHECK_MESSAGE(sum == s.selected, label + ": selected does not match the coins named");
    BOOST_CHECK_MESSAGE(s.selected == c.target + s.change + s.extraBurn, label + ": the selection does not balance");
    BOOST_CHECK_MESSAGE(s.change == 0 || s.change >= FLOOR, label + ": change inside the forbidden band");
    if (!allowBurn) BOOST_CHECK_MESSAGE(s.extraBurn == 0, label + ": a TRANSFER selection burned");
    if (s.extraBurn > 0) BOOST_CHECK_MESSAGE(s.stage == SelectStage::BURN, label + ": a burn outside stage BURN");
}

/** Determinism: the same inputs give the same answer, call after call (H1). */
void CheckDeterministic(const std::vector<int64_t>& coins, int64_t target, bool allowBurn)
{
    Selection a = SelectFloorAware(coins, target, FLOOR, CAP, allowBurn);
    for (int i = 0; i < 3; i++) {
        Selection b = SelectFloorAware(coins, target, FLOOR, CAP, allowBurn);
        BOOST_CHECK(a.ok == b.ok && a.stage == b.stage && a.inputs == b.inputs && a.change == b.change && a.extraBurn == b.extraBurn);
    }
}

std::vector<int64_t> Repeat(int64_t value, size_t n)
{
    return std::vector<int64_t>(n, value);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(yellowback_coinselect_tests, BasicTestingSetup)

// Rule: H1
BOOST_AUTO_TEST_CASE(h1_selector_table)
{
    const std::vector<Case> table = {
        // --- stage 1: exact
        { "exact_single_coin",            { 1000, 5000 },            5000,  true,  SelectStage::EXACT,  0 },
        { "exact_two_coins",              { 2500, 2500, 9900 },      5000,  true,  SelectStage::EXACT,  0 },
        { "exact_beats_single_with_change", { 5000, 100000 },        5000,  true,  SelectStage::EXACT,  0 },
        { "exact_whole_wallet",           { 700, 300 },              1000,  true,  SelectStage::EXACT,  0 },
        // --- stage 2: one input, valid change
        { "single_input_valid_change",    { 100000 },                4000,  true,  SelectStage::SINGLE, 96000 },
        { "single_smallest_that_works",   { 9000, 100000 },          4000,  true,  SelectStage::SINGLE, 5000 },
        { "single_exactly_at_the_floor",  { 4100 },                  4000,  true,  SelectStage::SINGLE, 100 },
        // --- stage 3: greedy, and greedy with extension
        { "single_large_coin_when_no_exact", { 1000, 4000, 100000 },  4500,  true,  SelectStage::SINGLE, 95500 },
        { "greedy_two_small_coins",       { 1000, 4000 },            4500,  true,  SelectStage::GREEDY, 500 },
        // 99.50 of a 100.00 coin: the classic band (a 50-cent change); adding the dollar coin fixes it.
        { "greedy_extension_over_band",   { 100, 10000 },            9950,  true,  SelectStage::GREEDY, 150 },
        { "greedy_two_small_then_big",    { 100, 100, 10000 },       9970,  true,  SelectStage::GREEDY, 230 },
        // --- H2: nothing works, a TRANSFER must refuse
        { "band_single_coin_only",        { 10000 },                 9950,  false, SelectStage::NONE,   0 },
        { "band_all_coins_together",      { 5000, 5000 },            9950,  false, SelectStage::NONE,   0 },
        { "band_three_coins",             { 200, 300, 9500 },        9950,  false, SelectStage::NONE,   0 },
        // --- insufficient
        { "insufficient",                 { 100, 200 },              1000,  false, SelectStage::NONE,   0 },
        { "insufficient_by_one_cent",     { 999 },                   1000,  false, SelectStage::NONE,   0 },
        // --- exact at the very top of the wallet still works
        { "exact_total_of_many",          { 100, 100, 100, 100 },    400,   true,  SelectStage::EXACT,  0 },
    };

    for (const Case& c : table) {
        Selection s = SelectFloorAware(c.coins, c.target, FLOOR, CAP, false);
        const std::string label(c.name);
        BOOST_CHECK_MESSAGE(s.ok == c.ok, label + ": ok = " + std::to_string(s.ok));
        BOOST_CHECK_MESSAGE(s.stage == c.stage, label + ": stage = " + SelectStageName(s.stage));
        if (c.ok) BOOST_CHECK_MESSAGE(s.change == c.change, label + ": change = " + std::to_string(s.change));
        CheckInvariants(c, s, false);
        CheckDeterministic(c.coins, c.target, false);
    }
}

// Rule: H1
BOOST_AUTO_TEST_CASE(h1_insufficient_is_distinguished_from_the_floor)
{
    // insufficient-yed and change-floor are different refusals (the contract's error table).
    Selection poor = SelectFloorAware({ 100, 200 }, 1000, FLOOR, CAP, false);
    BOOST_CHECK(!poor.ok);
    BOOST_CHECK(poor.insufficient);
    Selection band = SelectFloorAware({ 10000 }, 9950, FLOOR, CAP, false);
    BOOST_CHECK(!band.ok);
    BOOST_CHECK(!band.insufficient);
}

// Rule: H1
BOOST_AUTO_TEST_CASE(h1_selection_order_is_stable_under_coin_order)
{
    // The same multiset in a different order selects the same *amounts* (the ranking is by
    // cents, ties by position), so two wallets that list the same coins differently agree.
    const std::vector<int64_t> a = { 100, 4000, 10000 };
    const std::vector<int64_t> b = { 10000, 100, 4000 };
    Selection sa = SelectFloorAware(a, 4050, FLOOR, CAP, false);
    Selection sb = SelectFloorAware(b, 4050, FLOOR, CAP, false);
    BOOST_CHECK(sa.ok && sb.ok);
    std::vector<int64_t> va, vb;
    for (size_t i : sa.inputs) va.push_back(a[i]);
    for (size_t i : sb.inputs) vb.push_back(b[i]);
    std::sort(va.begin(), va.end());
    std::sort(vb.begin(), vb.end());
    BOOST_CHECK(va == vb);
    BOOST_CHECK_EQUAL(sa.change, sb.change);
}

// Rule: H11
BOOST_AUTO_TEST_CASE(h11_input_cap_is_respected)
{
    // 400 one-dollar coins, a target that needs 300 of them: over the 250-input cap, so the
    // selector must refuse rather than build a transaction the builder would reject.
    const std::vector<int64_t> coins = Repeat(100, 400);
    Selection over = SelectFloorAware(coins, 30000, FLOOR, CAP, false);
    BOOST_CHECK(!over.ok);
    BOOST_CHECK(!over.insufficient);          // the coins are there; the cap is what refuses
    BOOST_CHECK(over.tooManyInputs);
    // 250 of them is exactly at the cap and works.
    Selection at = SelectFloorAware(coins, 25000, FLOOR, CAP, false);
    BOOST_CHECK(at.ok);
    BOOST_CHECK_EQUAL(at.inputs.size(), CAP);
    BOOST_CHECK_EQUAL(at.change, 0);
}

// Rule: H1
BOOST_AUTO_TEST_CASE(h1_bounded_search_when_greedy_is_capped_out)
{
    // 300 one-dollar coins and one $255.50 coin; the target is $255.00. There is no exact subset
    // within the cap (the dollar coins reach only $250.00), the single big coin leaves 50 cents
    // of change (the forbidden band), and greedy smallest-first runs into the 250-input cap
    // before it reaches the target. Only the bounded search finds $255.50 + $1.00 = change $1.50.
    std::vector<int64_t> coins = Repeat(100, 300);
    coins.push_back(25550);
    Selection s = SelectFloorAware(coins, 25500, FLOOR, CAP, false);
    BOOST_CHECK(s.ok);
    BOOST_CHECK(s.stage == SelectStage::SEARCH);
    BOOST_CHECK_EQUAL(s.change, 150);
    BOOST_CHECK_EQUAL(s.inputs.size(), 2u);
    Case c{ "bounded_search", coins, 25500, true, SelectStage::SEARCH, 150 };
    CheckInvariants(c, s, false);
    CheckDeterministic(coins, 25500, false);
}

// Rule: H4
BOOST_AUTO_TEST_CASE(h4_redeem_burns_a_sub_dollar_remainder)
{
    // The band case a TRANSFER refuses: a REDEEM burns the 50 cents instead of stranding the vault.
    Selection s = SelectFloorAware({ 10000 }, 9950, FLOOR, CAP, true);
    BOOST_CHECK(s.ok);
    BOOST_CHECK(s.stage == SelectStage::BURN);
    BOOST_CHECK_EQUAL(s.extraBurn, 50);
    BOOST_CHECK_EQUAL(s.change, 0);
    BOOST_CHECK_EQUAL(s.selected, 10000);
    BOOST_CHECK(s.extraBurn < FLOOR);          // bounded by $0.99

    // The burn is bounded by $0.99 in every case the selector accepts it.
    Selection worst = SelectFloorAware({ 10099 }, 10000, FLOOR, CAP, true);
    BOOST_CHECK(worst.ok);
    BOOST_CHECK(worst.stage == SelectStage::BURN);
    BOOST_CHECK_EQUAL(worst.extraBurn, 99);

    // A selection with valid change is still preferred to one that burns.
    Selection prefer = SelectFloorAware({ 10000, 10100 }, 9950, FLOOR, CAP, true);
    BOOST_CHECK(prefer.ok);
    BOOST_CHECK(prefer.stage != SelectStage::BURN);
    BOOST_CHECK_EQUAL(prefer.extraBurn, 0);
    BOOST_CHECK_EQUAL(prefer.change, 150);

    // An exact match is preferred to a burn too.
    Selection exact = SelectFloorAware({ 9950, 10000 }, 9950, FLOOR, CAP, true);
    BOOST_CHECK(exact.stage == SelectStage::EXACT);
    BOOST_CHECK_EQUAL(exact.extraBurn, 0);

    // Insufficient coins are still insufficient, burn or no burn.
    Selection poor = SelectFloorAware({ 100 }, 9950, FLOOR, CAP, true);
    BOOST_CHECK(!poor.ok);
    BOOST_CHECK(poor.insufficient);
}

// Rule: H2
BOOST_AUTO_TEST_CASE(h2_nearest_workable_amounts)
{
    // One $100.00 coin: $99.50 is unworkable; the nearest workable amounts are $99.00
    // (change exactly at the floor) and $100.00 (spend it all, change 0).
    Alternatives alt = NearestWorkable({ 10000 }, 9950, FLOOR, CAP);
    BOOST_CHECK(alt.below.has_value() && alt.below.value() == 9900);
    BOOST_CHECK(alt.above.has_value() && alt.above.value() == 10000);

    // Two coins: the achievable sums are 5000, 5000, 10000; below the band the floor rule gives
    // 9900, above it only the full 10000 is achievable.
    Alternatives two = NearestWorkable({ 5000, 5000 }, 9950, FLOOR, CAP);
    BOOST_CHECK(two.below.has_value() && two.below.value() == 9900);
    BOOST_CHECK(two.above.has_value() && two.above.value() == 10000);

    // A coin set with a small coin: 9500 + 200 + 300 = 10000; 9950 is unworkable, 9950 - 50 is
    // not achievable either, so below is still 9900 and above is 10000.
    Alternatives three = NearestWorkable({ 200, 300, 9500 }, 9950, FLOOR, CAP);
    BOOST_CHECK(three.below.has_value() && three.below.value() == 9900);
    BOOST_CHECK(three.above.has_value() && three.above.value() == 10000);

    // Nothing above the wallet total is workable.
    Alternatives top = NearestWorkable({ 10000 }, 10000, FLOOR, CAP);
    BOOST_CHECK(!top.above.has_value());

    // A wallet holding less than one workable amount has no alternative below.
    // A wallet with one dollar: $1.00 itself is workable below $1.50, nothing is above it.
    Alternatives tiny = NearestWorkable({ 100 }, 150, FLOOR, CAP);
    BOOST_CHECK(tiny.below.has_value() && tiny.below.value() == 100);
    BOOST_CHECK(!tiny.above.has_value());
}

// Rule: H2
BOOST_AUTO_TEST_CASE(h2_alternatives_are_workable_and_the_band_is_not)
{
    // The property the message promises: both alternatives really are selectable and every
    // amount strictly between `below` and the target really is not.
    const std::vector<int64_t> coins = { 10000 };
    const int64_t target = 9950;
    Alternatives alt = NearestWorkable(coins, target, FLOOR, CAP);
    BOOST_REQUIRE(alt.below.has_value() && alt.above.has_value());
    BOOST_CHECK(SelectFloorAware(coins, alt.below.value(), FLOOR, CAP, false).ok);
    BOOST_CHECK(SelectFloorAware(coins, alt.above.value(), FLOOR, CAP, false).ok);
    for (int64_t t = alt.below.value() + 1; t < alt.above.value(); t++) {
        BOOST_CHECK_MESSAGE(!SelectFloorAware(coins, t, FLOOR, CAP, false).ok, "amount " + std::to_string(t) + " should be unworkable");
    }
}

// Rule: H1
BOOST_AUTO_TEST_CASE(h1_large_wallet_terminates_and_is_deterministic)
{
    // 300 coins of assorted sizes: the search is bounded, the answer is stable, and the
    // invariants hold. (The bound is what keeps a pathological wallet from hanging the RPC.)
    std::vector<int64_t> coins;
    for (int i = 0; i < 300; i++) coins.push_back(100 + (int64_t)((i * 37) % 53) * 7);
    const int64_t total = std::accumulate(coins.begin(), coins.end(), (int64_t)0);
    for (int64_t target : { (int64_t)100, (int64_t)12345, total / 2, total - 50, total }) {
        Selection s = SelectFloorAware(coins, target, FLOOR, CAP, false);
        Case c{ "large_wallet", coins, target, s.ok, s.stage, s.change };
        CheckInvariants(c, s, false);
        CheckDeterministic(coins, target, false);
    }
}

// Rule: H1
BOOST_AUTO_TEST_CASE(h1_degenerate_arguments)
{
    BOOST_CHECK(!SelectFloorAware({}, 100, FLOOR, CAP, false).ok);
    BOOST_CHECK(SelectFloorAware({}, 100, FLOOR, CAP, false).insufficient);
    Selection zero = SelectFloorAware({ 500 }, 0, FLOOR, CAP, false);
    BOOST_CHECK(zero.ok && zero.inputs.empty() && zero.change == 0);
    BOOST_CHECK(!SelectFloorAware({ 500 }, -1, FLOOR, CAP, false).ok);
    BOOST_CHECK(!SelectFloorAware({ 500 }, 100, FLOOR, 0, false).ok);   // a zero cap selects nothing
    BOOST_CHECK(SelectFloorAware({ 500 }, 100, FLOOR, 0, false).tooManyInputs);
}

// Rule: H5
BOOST_AUTO_TEST_CASE(p2sh_yellowback_outputs_are_never_mine)
{
    // The YEC side of every builder draws from CWallet::AvailableCoins, which offers only IsMine
    // outputs. A vault, a carrier and a bond are P2SH of scripts Solver calls TX_NONSTANDARD, so
    // none is IsMine even when the wallet holds the key inside it (v3 plan R6): sendtoaddress and
    // the Yellowback builders can never spend one as plain YEC, and no coin lock is needed.
    CBasicKeyStore ks;
    CKey k;
    k.MakeNewKey(true);
    ks.AddKey(k);
    const CPubKey pk = k.GetPubKey();
    std::vector<unsigned char> h(32, 0x11);
    const CScript carrier = CarrierScript(pk, uint256(h));
    const CScript bond = BondScript(pk, 500);
    const CScript vault = VaultScript(300, pk, 324);
    BOOST_REQUIRE(!carrier.empty() && !bond.empty() && !vault.empty());
    BOOST_CHECK_EQUAL((int)::IsMine(ks, GetScriptForDestination(pk.GetID())), (int)ISMINE_SPENDABLE);
    for (const CScript& redeem : { carrier, bond, vault }) {
        BOOST_CHECK_EQUAL((int)::IsMine(ks, P2SHScript(redeem)), (int)ISMINE_NO);
        // Even with the redeem script known to the keystore the template is unsolvable.
        ks.AddCScript(redeem);
        BOOST_CHECK_EQUAL((int)::IsMine(ks, P2SHScript(redeem)), (int)ISMINE_NO);
        txnouttype type;
        std::vector<std::vector<unsigned char>> sols;
        BOOST_CHECK(!Solver(redeem, type, sols) || type == TX_NONSTANDARD);
    }
}

BOOST_AUTO_TEST_SUITE_END()
