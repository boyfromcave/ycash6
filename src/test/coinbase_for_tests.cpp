// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// CreateCoinbaseTransaction with the scriptSig flags as an argument (getcoinbasetemplatefor, beta3 item 3):
// the coinbase the node's own miner builds, except that the bytes after `<height> OP_0` come from the caller
// and the global COINBASE_FLAGS is neither read nor written. The outputs, the development-fund rule (-ydf
// included) and the amount are those of the four-argument function. Byte-identical on both node lines
// (qa/yellowback-cross-line.manifest).

#include "amount.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "main.h"
#include "miner.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "test/test_bitcoin.h"

#include <boost/shared_ptr.hpp>
#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(coinbase_for_tests, BasicTestingSetup)

namespace {

// Mainnet: the development fund's mandate ended at 2,275,000.
const int MANDATE_END = 2275000;
const CAmount FEES = 12345;

MinerAddress PayTo(const CScript& script)
{
    boost::shared_ptr<CReserveScript> payout(new CReserveScript());
    payout->reserveScript = script;
    return payout;
}

struct ArgGuard {
    std::string name;
    ArgGuard(const std::string& nameIn, const std::string& value) : name(nameIn) { mapArgs[name] = value; }
    ~ArgGuard() { mapArgs.erase(name); }
};

struct FlagsGuard {
    CScript saved;
    FlagsGuard(const CScript& flags) : saved(COINBASE_FLAGS) { COINBASE_FLAGS = flags; }
    ~FlagsGuard() { COINBASE_FLAGS = saved; }
};

} // namespace

BOOST_AUTO_TEST_CASE(flags_are_the_argument_not_the_global)
{
    const CChainParams& chainparams = Params();
    BOOST_REQUIRE_EQUAL(chainparams.GetYdfMandateEndHeight(), MANDATE_END);
    const CScript payout = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x11) << OP_EQUALVERIFY << OP_CHECKSIG;
    const CScript global = CScript() << std::vector<unsigned char>(36, 0xaa);
    const CScript mine = CScript() << std::vector<unsigned char>(36, 0xbb);
    FlagsGuard guard(global);

    for (int nHeight : {MANDATE_END - 1, MANDATE_END}) {
        const CMutableTransaction stock = CreateCoinbaseTransaction(chainparams, FEES, PayTo(payout), nHeight);
        const CMutableTransaction same = CreateCoinbaseTransaction(chainparams, FEES, PayTo(payout), nHeight, global);
        const CMutableTransaction other = CreateCoinbaseTransaction(chainparams, FEES, PayTo(payout), nHeight, mine);
        const CMutableTransaction bare = CreateCoinbaseTransaction(chainparams, FEES, PayTo(payout), nHeight, CScript());

        // the global is what the four-argument function appends, and the call left it alone
        BOOST_CHECK(COINBASE_FLAGS == global);
        BOOST_CHECK(CTransaction(stock) == CTransaction(same));
        BOOST_CHECK(stock.vin[0].scriptSig == (CScript() << nHeight << OP_0) + global);
        // the argument is what the five-argument function appends
        BOOST_CHECK(other.vin[0].scriptSig == (CScript() << nHeight << OP_0) + mine);
        BOOST_CHECK(bare.vin[0].scriptSig == (CScript() << nHeight << OP_0));
        // and nothing else differs
        BOOST_CHECK(other.vout == stock.vout);
        BOOST_CHECK(bare.vout == stock.vout);
        BOOST_CHECK_EQUAL(other.nExpiryHeight, 0u);
        BOOST_CHECK(other.vin.size() == 1 && other.vin[0].prevout.IsNull());
    }
}

BOOST_AUTO_TEST_CASE(amount_is_subsidy_less_fund_plus_fees)
{
    const CChainParams& chainparams = Params();
    const CScript payout = CScript() << OP_HASH160 << std::vector<unsigned char>(20, 0x22) << OP_EQUAL;
    const CScript flags = CScript() << std::vector<unsigned char>(36, 0xcc);

    // The block subsidy at a height, read off the stock coinbase without fees: the sum of its outputs.
    auto subsidyAt = [&](int nHeight) {
        CAmount n = 0;
        for (const CTxOut& out : CreateCoinbaseTransaction(chainparams, 0, PayTo(payout), nHeight).vout) n += out.nValue;
        return n;
    };

    // inside the mandate: subsidy / 20 to the fund, whatever -ydf says
    for (const char* ydf : {"0", "5"}) {
        ArgGuard arg("-ydf", ydf);
        const int nHeight = MANDATE_END - 1;
        const CAmount nSubsidy = subsidyAt(nHeight);
        BOOST_REQUIRE(nSubsidy > 0);
        const CMutableTransaction mtx = CreateCoinbaseTransaction(chainparams, FEES, PayTo(payout), nHeight, flags);
        BOOST_REQUIRE_EQUAL(mtx.vout.size(), 2u);
        BOOST_CHECK_EQUAL(mtx.vout[1].nValue, nSubsidy / 20);
        BOOST_CHECK(mtx.vout[1].scriptPubKey == chainparams.GetFoundersRewardScriptAtHeight(nHeight));
        BOOST_CHECK_EQUAL(mtx.vout[0].nValue, nSubsidy - nSubsidy / 20 + FEES);
        BOOST_CHECK(mtx.vout[0].scriptPubKey == payout);
    }

    const int nHeight = MANDATE_END;
    const CAmount nSubsidy = subsidyAt(nHeight);
    BOOST_REQUIRE(nSubsidy > 0);
    {
        // past the mandate, the default (-ydf unset, 0): one output, the subsidy and every fee
        BOOST_REQUIRE_EQUAL(DEFAULT_YDF_FEE_PERCENTAGE, 0u);
        const CMutableTransaction mtx = CreateCoinbaseTransaction(chainparams, FEES, PayTo(payout), nHeight, flags);
        BOOST_REQUIRE_EQUAL(mtx.vout.size(), 1u);
        BOOST_CHECK_EQUAL(mtx.vout[0].nValue, nSubsidy + FEES);
        BOOST_CHECK(mtx.vout[0].scriptPubKey == payout);
    }
    {
        // past the mandate with -ydf=5: 5 % of the subsidy (never of the fees) to the fund, as the stock coinbase
        ArgGuard arg("-ydf", "5");
        const CMutableTransaction mtx = CreateCoinbaseTransaction(chainparams, FEES, PayTo(payout), nHeight, flags);
        const CMutableTransaction stock = CreateCoinbaseTransaction(chainparams, FEES, PayTo(payout), nHeight);
        BOOST_REQUIRE_EQUAL(mtx.vout.size(), 2u);
        BOOST_CHECK_EQUAL(mtx.vout[1].nValue, nSubsidy * 5 / 100);
        BOOST_CHECK(mtx.vout[1].scriptPubKey == chainparams.GetFoundersRewardScriptAtHeight(nHeight));
        BOOST_CHECK_EQUAL(mtx.vout[0].nValue, nSubsidy - nSubsidy * 5 / 100 + FEES);
        BOOST_CHECK(mtx.vout == stock.vout);
    }
}

BOOST_AUTO_TEST_SUITE_END()
