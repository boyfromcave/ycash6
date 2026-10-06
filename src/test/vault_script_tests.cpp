// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The consensus plumbing of the vault primitive (docs/plans/yellowback-upgrade-plan.md
// §15.1-§15.2): OP_CHECKSEQUENCEVERIFY (BIP112, 0xb2) under SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
// BIP68 height-based sequence locks, and OP_CHECKSETSIG (0xc0) / OP_CHECKSETDORMANT (0xc1)
// under SCRIPT_VERIFY_VAULT, driven through a mock BaseSignatureChecker.

#include "chainparams.h"
#include "coins.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#include "main.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "test/test_bitcoin.h"
#include "txmempool.h"
#include "util/test.h"

#include <boost/test/unit_test.hpp>

#include <optional>
#include <vector>

namespace {

typedef std::vector<unsigned char> valtype;

const unsigned int VAULT_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                                 SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_VAULT;
const unsigned int PRE_VAULT_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
const uint32_t VAULT_BRANCH_ID = 0x6d5b7a31;

CMutableTransaction SpendingTx(uint32_t nSequence)
{
    CMutableTransaction mtx;
    mtx.fOverwintered = true;
    mtx.nVersion = SAPLING_TX_VERSION;
    mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(uint256S("01"), 0);
    mtx.vin[0].nSequence = nSequence;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return mtx;
}

// Evaluates `script` (no scriptSig) as the only input of a v4 transaction with `nSequence`.
ScriptError EvalCsv(const CScript& script, uint32_t nSequence, unsigned int flags)
{
    CTransaction tx(SpendingTx(nSequence));
    PrecomputedTransactionData txdata(tx, {CTxOut(2000, script)});
    TransactionSignatureChecker checker(&tx, txdata, 0, 2000);
    std::vector<valtype> stack;
    ScriptError err;
    bool ok = EvalScript(stack, script, flags, checker, VAULT_BRANCH_ID, &err);
    if (ok) {
        BOOST_CHECK(err == SCRIPT_ERR_OK);
    } else {
        BOOST_CHECK(err != SCRIPT_ERR_OK);
    }
    return err;
}

// A checker that answers the set questions from fixed values and records what it was asked.
class MockSetChecker : public BaseSignatureChecker
{
public:
    std::optional<int> threshold;
    bool sigsOk = true;
    bool released = false;
    mutable int setSigCalls = 0;
    mutable uint256 lastSetId;
    mutable uint8_t lastRole = 0;
    mutable std::vector<valtype> lastSigs;
    mutable uint32_t lastBranchId = 0;

    std::optional<int> SetThreshold(const uint256& setId, uint8_t role) const override
    {
        return threshold;
    }
    bool CheckSetSigs(const uint256& setId, uint8_t role, const std::vector<valtype>& sigs,
                      const CScript& scriptCode, uint32_t consensusBranchId) const override
    {
        setSigCalls++;
        lastSetId = setId;
        lastRole = role;
        lastSigs = sigs;
        lastBranchId = consensusBranchId;
        return sigsOk;
    }
    bool IsSetReleased(const uint256& setId) const override
    {
        lastSetId = setId;
        return released;
    }
};

valtype SetId(unsigned char b) { return valtype(32, b); }

// 65-byte compact recoverable signature: header || r || s, s low.
valtype CompactSig(unsigned char header = 31, unsigned char fill = 0x11)
{
    valtype sig(65, fill);
    sig[0] = header;
    sig[33] = 0x3f; // s well below n/2
    return sig;
}

ScriptError Eval(const CScript& script, const BaseSignatureChecker& checker, unsigned int flags,
                 std::vector<valtype>* outStack = nullptr)
{
    std::vector<valtype> stack;
    ScriptError err;
    EvalScript(stack, script, flags, checker, VAULT_BRANCH_ID, &err);
    if (outStack) *outStack = stack;
    return err;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(vault_script_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(vault_upgrade_constants)
{
    BOOST_CHECK_EQUAL(NetworkUpgradeInfo[Consensus::UPGRADE_VAULT].nBranchId, VAULT_BRANCH_ID);
    BOOST_CHECK_EQUAL(std::string(NetworkUpgradeInfo[Consensus::UPGRADE_VAULT].strName), "Vault");
    BOOST_CHECK(Consensus::UPGRADE_VAULT == Consensus::UPGRADE_NU6_2 + 1);
    BOOST_CHECK(Consensus::UPGRADE_ZFUTURE == Consensus::UPGRADE_VAULT + 1);
    BOOST_CHECK(OP_CHECKSEQUENCEVERIFY == 0xb2);
    BOOST_CHECK(OP_CHECKSETSIG == 0xc0);
    BOOST_CHECK(OP_CHECKSETDORMANT == 0xc1);
    BOOST_CHECK_EQUAL(GetOpName(OP_CHECKSETSIG), "OP_CHECKSETSIG");
    BOOST_CHECK_EQUAL(GetOpName(OP_CHECKSETDORMANT), "OP_CHECKSETDORMANT");

    // No activation on any network until the gate-passing release (P8).
    for (auto net : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET, CBaseChainParams::REGTEST}) {
        BOOST_CHECK_EQUAL(Params(net).GetConsensus().vUpgrades[Consensus::UPGRADE_VAULT].nActivationHeight,
                          Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);
        BOOST_CHECK_EQUAL(GetVaultScriptFlags(10000000, Params(net).GetConsensus()), 0U);
    }

    // Regtest: Vault activates on top of Overwinter + Sapling alone (no Blossom..NU6.2).
    SelectParams(CBaseChainParams::REGTEST);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_OVERWINTER, 1);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_SAPLING, 1);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_VAULT, 10);
    const auto& consensus = Params().GetConsensus();
    BOOST_CHECK_EQUAL(CurrentEpochBranchId(9, consensus), NetworkUpgradeInfo[Consensus::UPGRADE_SAPLING].nBranchId);
    BOOST_CHECK_EQUAL(CurrentEpochBranchId(10, consensus), VAULT_BRANCH_ID);
    BOOST_CHECK_EQUAL(GetVaultScriptFlags(9, consensus), 0U);
    BOOST_CHECK_EQUAL(GetVaultScriptFlags(10, consensus),
                      (unsigned int)(SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_VAULT));
    // The epoch before Vault is the highest one actually scheduled, not NU6.2.
    BOOST_CHECK_EQUAL(PrevEpochBranchId(VAULT_BRANCH_ID, consensus), NetworkUpgradeInfo[Consensus::UPGRADE_SAPLING].nBranchId);
    // Regtest keeps Equihash (48, 5) under the upgrade.
    BOOST_CHECK_EQUAL(Params().EquihashN(10), 48U);
    BOOST_CHECK_EQUAL(Params().EquihashK(10), 5U);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_VAULT, Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_SAPLING, Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_OVERWINTER, Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);
    SelectParams(CBaseChainParams::MAIN);

    // Mainnet: inherits Equihash (192, 7) from the Ycash upgrade at any height.
    BOOST_CHECK_EQUAL(Params().EquihashN(3000000), 192U);
    BOOST_CHECK_EQUAL(Params().EquihashK(3000000), 7U);
}

// BIP112 vectors: <n> OP_CHECKSEQUENCEVERIFY against the input's nSequence.
BOOST_AUTO_TEST_CASE(vault_csv)
{
    auto csv = [](int64_t n) { return CScript() << CScriptNum(n) << OP_CHECKSEQUENCEVERIFY; };

    // Without the flag: OP_NOP3, discouraged by policy only.
    BOOST_CHECK_EQUAL(EvalCsv(csv(10), 0, PRE_VAULT_FLAGS), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(EvalCsv(csv(10), 0, PRE_VAULT_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS),
                      SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
    BOOST_CHECK_EQUAL(EvalCsv(CScript() << OP_CHECKSEQUENCEVERIFY << OP_1, 0, PRE_VAULT_FLAGS), SCRIPT_ERR_OK);

    // With the flag: satisfied iff nSequence >= n (height type, disable bit clear).
    BOOST_CHECK_EQUAL(EvalCsv(csv(10), 10, VAULT_FLAGS), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(EvalCsv(csv(10), 11, VAULT_FLAGS), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(EvalCsv(csv(10), 9, VAULT_FLAGS), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK_EQUAL(EvalCsv(csv(0), 0, VAULT_FLAGS), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(EvalCsv(csv(0xffff), 0xffff, VAULT_FLAGS), SCRIPT_ERR_OK);
    // Bits outside the type flag and the low 16 bits are masked off on both sides.
    BOOST_CHECK_EQUAL(EvalCsv(csv(10 | (1 << 16)), 10, VAULT_FLAGS), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(EvalCsv(csv(10), 10 | (1 << 20), VAULT_FLAGS), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(EvalCsv(csv(10), 9 | (1 << 20), VAULT_FLAGS), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    // The input's disable bit set: CSV fails (cannot bypass the relative lock).
    BOOST_CHECK_EQUAL(EvalCsv(csv(10), 0xffffffff, VAULT_FLAGS), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK_EQUAL(EvalCsv(csv(10), 0xfffffffe, VAULT_FLAGS), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    // The operand's disable bit set: CSV is a NOP.
    BOOST_CHECK_EQUAL(EvalCsv(csv((int64_t)1 << 31), 0, VAULT_FLAGS), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(EvalCsv(csv(((int64_t)1 << 31) | 10), 0xffffffff, VAULT_FLAGS), SCRIPT_ERR_OK);
    // The operand's type flag set (time-based, bit 22): fails on Ycash (plan §15.2).
    BOOST_CHECK_EQUAL(EvalCsv(csv((1 << 22) | 1), (1 << 22) | 1, VAULT_FLAGS), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    // Height operand vs a time-typed input: type mismatch fails.
    BOOST_CHECK_EQUAL(EvalCsv(csv(1), (1 << 22) | 5, VAULT_FLAGS), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    // Negative operand, empty stack, oversized operand.
    BOOST_CHECK_EQUAL(EvalCsv(csv(-1), 0, VAULT_FLAGS), SCRIPT_ERR_NEGATIVE_LOCKTIME);
    BOOST_CHECK_EQUAL(EvalCsv(CScript() << OP_CHECKSEQUENCEVERIFY, 0, VAULT_FLAGS), SCRIPT_ERR_INVALID_STACK_OPERATION);
    BOOST_CHECK_EQUAL(EvalCsv(CScript() << valtype(6, 0x01) << OP_CHECKSEQUENCEVERIFY, 0, VAULT_FLAGS),
                      SCRIPT_ERR_UNKNOWN_ERROR);
    // CSV leaves its operand on the stack (it is a NOP-shaped VERIFY).
    {
        CTransaction tx(SpendingTx(10));
        PrecomputedTransactionData txdata(tx, {CTxOut(2000, CScript())});
        TransactionSignatureChecker checker(&tx, txdata, 0, 2000);
        std::vector<valtype> stack;
        BOOST_CHECK(EvalScript(stack, csv(10), VAULT_FLAGS, checker, VAULT_BRANCH_ID));
        BOOST_CHECK_EQUAL(stack.size(), 1U);
    }
    // The base checker refuses CheckSequence.
    {
        BaseSignatureChecker base;
        BOOST_CHECK_EQUAL(Eval(csv(1), base, VAULT_FLAGS), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    }
}

// BIP68, height part: Bitcoin's CalculateSequenceLocks/EvaluateSequenceLocks.
BOOST_AUTO_TEST_CASE(vault_bip68_calculate)
{
    auto tx2 = [](uint32_t s0, uint32_t s1) {
        CMutableTransaction mtx = SpendingTx(s0);
        mtx.vin.resize(2);
        mtx.vin[1].prevout = COutPoint(uint256S("02"), 0);
        mtx.vin[1].nSequence = s1;
        return CTransaction(mtx);
    };

    // Disable bit on every input: no relative lock.
    auto r = CalculateSequenceLocks(tx2(0xffffffff, 0xfffffffe), {100, 200});
    BOOST_REQUIRE(r.has_value());
    BOOST_CHECK_EQUAL(*r, -1);
    BOOST_CHECK(EvaluateSequenceLocks(0, *r));

    // Lock 0: a coin at H is spendable at H (same-block chains keep working).
    r = CalculateSequenceLocks(tx2(0, 0xffffffff), {100, 0});
    BOOST_REQUIRE(r.has_value());
    BOOST_CHECK_EQUAL(*r, 99);
    BOOST_CHECK(EvaluateSequenceLocks(100, *r));
    BOOST_CHECK(!EvaluateSequenceLocks(99, *r));

    // Lock n: a coin at H is spendable from H + n, not at H + n - 1.
    r = CalculateSequenceLocks(tx2(10, 0xffffffff), {100, 0});
    BOOST_REQUIRE(r.has_value());
    BOOST_CHECK_EQUAL(*r, 109);
    BOOST_CHECK(EvaluateSequenceLocks(110, *r));
    BOOST_CHECK(!EvaluateSequenceLocks(109, *r));

    // The tightest input wins.
    r = CalculateSequenceLocks(tx2(10, 5), {100, 108});
    BOOST_REQUIRE(r.has_value());
    BOOST_CHECK_EQUAL(*r, 112);

    // Only the low 16 bits count.
    r = CalculateSequenceLocks(tx2(0x00010003, 0xffffffff), {100, 0});
    BOOST_REQUIRE(r.has_value());
    BOOST_CHECK_EQUAL(*r, 102);

    // The type flag (time-based lock) with the disable bit clear: invalid.
    BOOST_CHECK(!CalculateSequenceLocks(tx2(1 << 22, 0xffffffff), {100, 0}).has_value());
    BOOST_CHECK(!CalculateSequenceLocks(tx2(0xffffffff, (1 << 22) | 3), {0, 100}).has_value());
    // ... but not when the disable bit is set too.
    BOOST_CHECK(CalculateSequenceLocks(tx2(0xffffffff, (1U << 31) | (1 << 22)), {0, 100}).has_value());
}

BOOST_AUTO_TEST_CASE(vault_bip68_contextual)
{
    CCoinsViewDummy dummy;
    CCoinsViewCache view(&dummy);
    CMutableTransaction parent;
    parent.vout.resize(1);
    parent.vout[0].nValue = 2000;
    CTransaction parentTx(parent);
    {
        CCoinsModifier c = view.ModifyNewCoins(parentTx.GetHash());
        *c = CCoins(parentTx, 100);
    }
    CMutableTransaction child = SpendingTx(10);
    child.vin[0].prevout = COutPoint(parentTx.GetHash(), 0);

    CValidationState ok1;
    BOOST_CHECK(ContextualCheckSequenceLocks(CTransaction(child), view, 110, ok1, false));

    CValidationState early;
    BOOST_CHECK(!ContextualCheckSequenceLocks(CTransaction(child), view, 109, early, false));
    BOOST_CHECK_EQUAL(early.GetRejectReason(), "bad-txns-nonfinal");
    int dos = 0;
    BOOST_CHECK(early.IsInvalid(dos));
    BOOST_CHECK_EQUAL(dos, 100);

    CValidationState earlyPool;
    BOOST_CHECK(!ContextualCheckSequenceLocks(CTransaction(child), view, 109, earlyPool, true));
    BOOST_CHECK_EQUAL(earlyPool.GetRejectReason(), "non-BIP68-final");

    child.vin[0].nSequence = (1 << 22) | 1;
    CValidationState timeLock;
    BOOST_CHECK(!ContextualCheckSequenceLocks(CTransaction(child), view, 1000, timeLock, false));
    BOOST_CHECK_EQUAL(timeLock.GetRejectReason(), "bad-txns-vault-timelock");

    // A mempool parent counts as confirming in the block being checked.
    {
        CCoinsModifier c = view.ModifyCoins(parentTx.GetHash());
        c->nHeight = MEMPOOL_HEIGHT;
    }
    child.vin[0].nSequence = 0;
    CValidationState pool0;
    BOOST_CHECK(ContextualCheckSequenceLocks(CTransaction(child), view, 500, pool0, true));
    child.vin[0].nSequence = 1;
    CValidationState pool1;
    BOOST_CHECK(!ContextualCheckSequenceLocks(CTransaction(child), view, 500, pool1, true));
}

BOOST_AUTO_TEST_CASE(vault_opcodes_gated)
{
    MockSetChecker checker;
    checker.threshold = 1;
    CScript setsig = CScript() << CompactSig() << SetId(7) << OP_1 << OP_CHECKSETSIG;
    CScript dormant = CScript() << SetId(7) << OP_CHECKSETDORMANT;

    // Before UPGRADE_VAULT the bytes are bad opcodes, exactly as today.
    BOOST_CHECK_EQUAL(Eval(setsig, checker, PRE_VAULT_FLAGS), SCRIPT_ERR_BAD_OPCODE);
    BOOST_CHECK_EQUAL(Eval(dormant, checker, PRE_VAULT_FLAGS), SCRIPT_ERR_BAD_OPCODE);
    BOOST_CHECK_EQUAL(Eval(setsig, checker, STANDARD_SCRIPT_VERIFY_FLAGS), SCRIPT_ERR_BAD_OPCODE);
    BOOST_CHECK_EQUAL(checker.setSigCalls, 0);
    // An unexecuted branch never reaches them.
    BOOST_CHECK_EQUAL(Eval(CScript() << OP_0 << OP_IF << OP_CHECKSETSIG << OP_CHECKSETDORMANT << OP_ENDIF << OP_1,
                           checker, PRE_VAULT_FLAGS), SCRIPT_ERR_OK);
    // 0xbb-0xbf stay bad opcodes under the upgrade.
    for (int op = 0xba; op <= 0xbf; op++) {
        CScript s;
        s.push_back((unsigned char)op);
        BOOST_CHECK_EQUAL(Eval(s, checker, VAULT_FLAGS), SCRIPT_ERR_BAD_OPCODE);
    }
    {
        CScript s;
        s.push_back((unsigned char)0xc2);
        BOOST_CHECK_EQUAL(Eval(s, checker, VAULT_FLAGS), SCRIPT_ERR_BAD_OPCODE);
    }
    // The base checker fails every set question.
    BaseSignatureChecker base;
    BOOST_CHECK_EQUAL(Eval(setsig, base, VAULT_FLAGS), SCRIPT_ERR_SETSIG);
    std::vector<valtype> stack;
    BOOST_CHECK_EQUAL(Eval(dormant, base, VAULT_FLAGS, &stack), SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    BOOST_CHECK(stack[0].empty());
}

BOOST_AUTO_TEST_CASE(vault_checksetsig)
{
    // Success: k = 2 signatures, pushed sig_1 then sig_2, handed over in push order.
    {
        MockSetChecker checker;
        checker.threshold = 2;
        valtype s1 = CompactSig(31, 0x21), s2 = CompactSig(34, 0x22);
        CScript script = CScript() << s1 << s2 << SetId(9) << OP_2 << OP_CHECKSETSIG;
        std::vector<valtype> stack;
        BOOST_CHECK_EQUAL(Eval(script, checker, VAULT_FLAGS, &stack), SCRIPT_ERR_OK);
        BOOST_REQUIRE_EQUAL(stack.size(), 1U);
        BOOST_CHECK(stack[0] == valtype(1, 1));
        BOOST_CHECK_EQUAL(checker.setSigCalls, 1);
        BOOST_CHECK(checker.lastSetId == uint256(SetId(9)));
        BOOST_CHECK_EQUAL(checker.lastRole, 2);
        BOOST_REQUIRE_EQUAL(checker.lastSigs.size(), 2U);
        BOOST_CHECK(checker.lastSigs[0] == s1);
        BOOST_CHECK(checker.lastSigs[1] == s2);
        BOOST_CHECK_EQUAL(checker.lastBranchId, VAULT_BRANCH_ID);
    }
    // Extra stack items below the k signatures are left alone.
    {
        MockSetChecker checker;
        checker.threshold = 1;
        CScript script = CScript() << OP_5 << CompactSig() << SetId(9) << OP_1 << OP_CHECKSETSIG;
        std::vector<valtype> stack;
        BOOST_CHECK_EQUAL(Eval(script, checker, VAULT_FLAGS, &stack), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 2U);
    }

    auto expect = [](const CScript& script, std::optional<int> k, bool sigsOk, ScriptError want) {
        MockSetChecker checker;
        checker.threshold = k;
        checker.sigsOk = sigsOk;
        BOOST_CHECK_EQUAL(Eval(script, checker, VAULT_FLAGS), want);
    };
    // Stack shape.
    expect(CScript() << OP_CHECKSETSIG, 1, true, SCRIPT_ERR_INVALID_STACK_OPERATION);
    expect(CScript() << OP_1 << OP_CHECKSETSIG, 1, true, SCRIPT_ERR_INVALID_STACK_OPERATION);
    // setId must be exactly 32 bytes; role exactly one byte, 1 or 2.
    expect(CScript() << CompactSig() << valtype(31, 7) << OP_1 << OP_CHECKSETSIG, 1, true, SCRIPT_ERR_SETSIG);
    expect(CScript() << CompactSig() << valtype(33, 7) << OP_1 << OP_CHECKSETSIG, 1, true, SCRIPT_ERR_SETSIG);
    expect(CScript() << CompactSig() << SetId(7) << OP_3 << OP_CHECKSETSIG, 1, true, SCRIPT_ERR_SETSIG);
    expect(CScript() << CompactSig() << SetId(7) << OP_0 << OP_CHECKSETSIG, 1, true, SCRIPT_ERR_SETSIG);
    expect(CScript() << CompactSig() << SetId(7) << valtype{1, 0} << OP_CHECKSETSIG, 1, true, SCRIPT_ERR_SETSIG);
    // Unknown set; a threshold the stack cannot meet; a zero threshold.
    expect(CScript() << CompactSig() << SetId(7) << OP_1 << OP_CHECKSETSIG, std::nullopt, true, SCRIPT_ERR_SETSIG);
    expect(CScript() << CompactSig() << SetId(7) << OP_1 << OP_CHECKSETSIG, 2, true, SCRIPT_ERR_SETSIG);
    expect(CScript() << CompactSig() << SetId(7) << OP_1 << OP_CHECKSETSIG, 0, true, SCRIPT_ERR_SETSIG);
    // Signature encoding: 65 bytes, header 31..34, low S.
    expect(CScript() << valtype(64, 0x11) << SetId(7) << OP_1 << OP_CHECKSETSIG, 1, true, SCRIPT_ERR_SETSIG);
    expect(CScript() << valtype(66, 0x11) << SetId(7) << OP_1 << OP_CHECKSETSIG, 1, true, SCRIPT_ERR_SETSIG);
    expect(CScript() << CompactSig(27) << SetId(7) << OP_1 << OP_CHECKSETSIG, 1, true, SCRIPT_ERR_SETSIG);
    expect(CScript() << CompactSig(35) << SetId(7) << OP_1 << OP_CHECKSETSIG, 1, true, SCRIPT_ERR_SETSIG);
    {
        valtype high = CompactSig();
        for (int i = 33; i < 65; i++) high[i] = 0xff; // s > n/2
        expect(CScript() << high << SetId(7) << OP_1 << OP_CHECKSETSIG, 1, true, SCRIPT_ERR_SETSIG);
        valtype half(65, 0);
        half[0] = 32;
        const unsigned char HALF_ORDER[32] = {
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
        };
        std::copy(HALF_ORDER, HALF_ORDER + 32, half.begin() + 33);
        expect(CScript() << half << SetId(7) << OP_1 << OP_CHECKSETSIG, 1, true, SCRIPT_ERR_OK); // s == n/2 is low
        half[64] = 0xA1;
        expect(CScript() << half << SetId(7) << OP_1 << OP_CHECKSETSIG, 1, true, SCRIPT_ERR_SETSIG);
    }
    // The checker rejects the signatures: a failure, never a "false" result.
    expect(CScript() << CompactSig() << SetId(7) << OP_1 << OP_CHECKSETSIG, 1, false, SCRIPT_ERR_SETSIG);
    // At most one OP_CHECKSETSIG per evaluation, even if the first succeeded.
    expect(CScript() << CompactSig() << SetId(7) << OP_1 << OP_CHECKSETSIG << OP_DROP
                     << CompactSig() << SetId(7) << OP_1 << OP_CHECKSETSIG,
           1, true, SCRIPT_ERR_SETSIG_COUNT);
    // ... but an unexecuted second one does not count.
    expect(CScript() << CompactSig() << SetId(7) << OP_1 << OP_CHECKSETSIG
                     << OP_0 << OP_IF << OP_CHECKSETSIG << OP_ENDIF,
           1, true, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(vault_checksetdormant)
{
    MockSetChecker checker;
    std::vector<valtype> stack;

    checker.released = true;
    BOOST_CHECK_EQUAL(Eval(CScript() << SetId(5) << OP_CHECKSETDORMANT, checker, VAULT_FLAGS, &stack), SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    BOOST_CHECK(stack[0] == valtype(1, 1));
    BOOST_CHECK(checker.lastSetId == uint256(SetId(5)));

    checker.released = false;
    BOOST_CHECK_EQUAL(Eval(CScript() << SetId(5) << OP_CHECKSETDORMANT, checker, VAULT_FLAGS, &stack), SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    BOOST_CHECK(stack[0].empty());
    // As a branch selector.
    BOOST_CHECK_EQUAL(Eval(CScript() << SetId(5) << OP_CHECKSETDORMANT << OP_IF << OP_1 << OP_ELSE << OP_0 << OP_ENDIF,
                           checker, VAULT_FLAGS, &stack), SCRIPT_ERR_OK);
    BOOST_CHECK(stack.back().empty());

    BOOST_CHECK_EQUAL(Eval(CScript() << OP_CHECKSETDORMANT, checker, VAULT_FLAGS), SCRIPT_ERR_INVALID_STACK_OPERATION);
    BOOST_CHECK_EQUAL(Eval(CScript() << valtype(20, 5) << OP_CHECKSETDORMANT, checker, VAULT_FLAGS), SCRIPT_ERR_SETSIG);
    // OP_CHECKSETDORMANT does not count against the one-OP_CHECKSETSIG rule.
    checker.threshold = 1;
    BOOST_CHECK_EQUAL(Eval(CScript() << CompactSig() << SetId(5) << OP_1 << OP_CHECKSETSIG << OP_DROP
                                     << SetId(5) << OP_CHECKSETDORMANT << OP_DROP << SetId(5) << OP_CHECKSETDORMANT,
                           checker, VAULT_FLAGS), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(vault_script_error_strings)
{
    BOOST_CHECK_EQUAL(ScriptErrorString(SCRIPT_ERR_SETSIG), "OP_CHECKSETSIG or OP_CHECKSETDORMANT failed");
    BOOST_CHECK_EQUAL(ScriptErrorString(SCRIPT_ERR_SETSIG_COUNT), "More than one OP_CHECKSETSIG in a script evaluation");
}

BOOST_AUTO_TEST_SUITE_END()
