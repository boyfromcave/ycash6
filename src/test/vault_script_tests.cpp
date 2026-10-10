// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The vault primitive's consensus plumbing (docs/plans/yellowback-upgrade-plan.md §15.1, §15.2):
// UPGRADE_VAULT and its branch ID, OP_CHECKSEQUENCEVERIFY (BIP112, height-based only), the BIP68
// sequence-lock calculation, and OP_CHECKSETSIG / OP_CHECKSETDORMANT against a mock checker
// (the real set checker is vault::SetSigChecker, src/vault/).

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
#include "uint256.h"
#include "util/strencodings.h"

#include <boost/test/unit_test.hpp>

#include <optional>
#include <vector>

typedef std::vector<unsigned char> valtype;

namespace {

const uint32_t VAULT_BRANCH_ID = 0x6d5b7a31;
const unsigned int VAULT_FLAGS = SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_VAULT;

/** A set checker whose answers the test sets, recording what the interpreter passes it. */
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
    mutable uint256 lastDormantSetId;

    std::optional<int> SetThreshold(const uint256& setId, uint8_t role) const override
    {
        lastSetId = setId;
        lastRole = role;
        return threshold;
    }

    bool CheckSetSigs(const uint256& setId, uint8_t role, const std::vector<valtype>& sigs,
                      const CScript& scriptCode, uint32_t consensusBranchId) const override
    {
        setSigCalls++;
        lastSigs = sigs;
        BOOST_CHECK(setId == lastSetId);
        BOOST_CHECK_EQUAL(role, lastRole);
        BOOST_CHECK_EQUAL(consensusBranchId, VAULT_BRANCH_ID);
        return sigsOk;
    }

    bool IsSetReleased(const uint256& setId) const override
    {
        lastDormantSetId = setId;
        return released;
    }
};

valtype SetIdBytes(unsigned char fill = 0x5a)
{
    valtype v(32, fill);
    v[0] = 0x01;   // not symmetric, so a byte-order slip shows
    return v;
}

/** A well-formed 65-byte set signature: header 31, r = s = small (low S). */
valtype GoodSig(unsigned char tag)
{
    valtype sig(65, 0x00);
    sig[0] = 31;
    sig[1] = tag;          // r
    sig[64] = tag;         // s, low
    return sig;
}

ScriptError Eval(const CScript& script, unsigned int flags, const BaseSignatureChecker& checker,
                 std::vector<valtype>* stackOut = nullptr)
{
    std::vector<valtype> stack;
    ScriptError err;
    EvalScript(stack, script, flags, checker, VAULT_BRANCH_ID, &err);
    if (stackOut) *stackOut = stack;
    return err;
}

/** A v4 (Sapling) transaction with one input whose nSequence is nSequence. */
CMutableTransaction SeqTx(uint32_t nSequence)
{
    CMutableTransaction mtx;
    mtx.fOverwintered = true;
    mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    mtx.nVersion = SAPLING_TX_VERSION;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(uint256S("01"), 0);
    mtx.vin[0].nSequence = nSequence;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1;
    return mtx;
}

ScriptError CsvEval(int64_t arg, uint32_t txSequence, unsigned int flags = SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)
{
    CMutableTransaction mtx = SeqTx(txSequence);
    PrecomputedTransactionData txdata(CTransaction(mtx), {CTxOut(1, CScript())});
    MutableTransactionSignatureChecker checker(&mtx, txdata, 0, 1);
    CScript script = CScript() << CScriptNum(arg) << OP_CHECKSEQUENCEVERIFY;
    std::vector<valtype> stack;
    ScriptError err;
    EvalScript(stack, script, flags, checker, VAULT_BRANCH_ID, &err);
    return err;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(vault_script_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(vault_upgrade_info)
{
    BOOST_CHECK_EQUAL(NetworkUpgradeInfo[Consensus::UPGRADE_VAULT].nBranchId, VAULT_BRANCH_ID);
    BOOST_CHECK_EQUAL(std::string(NetworkUpgradeInfo[Consensus::UPGRADE_VAULT].strName), "Vault");
    BOOST_CHECK(Consensus::UPGRADE_VAULT == Consensus::UPGRADE_NU6_2 + 1);   // 6.20.0: after NU6.2
    BOOST_CHECK(Consensus::UPGRADE_ZFUTURE == Consensus::UPGRADE_VAULT + 1);
    BOOST_CHECK(IsConsensusBranchId(VAULT_BRANCH_ID));
    // 6.20.0 keeps Equihash in NetworkUpgradeInfo and walks back to the last override: Vault
    // has none, so it inherits the Ycash upgrade's (192, 7), the epoch before it; regtest keeps
    // (48, 5) under every upgrade.
    BOOST_CHECK_EQUAL(NetworkUpgradeInfo[Consensus::UPGRADE_VAULT].nEquihashN, NUInfo::EQUIHASH_DEFAULT);
    BOOST_CHECK_EQUAL(NetworkUpgradeInfo[Consensus::UPGRADE_VAULT].nEquihashK, NUInfo::EQUIHASH_DEFAULT);
    BOOST_CHECK_EQUAL(Params(CBaseChainParams::MAIN).EquihashN(4000000), 192U);
    BOOST_CHECK_EQUAL(Params(CBaseChainParams::MAIN).EquihashK(4000000), 7U);
    BOOST_CHECK_EQUAL(Params(CBaseChainParams::REGTEST).EquihashN(4000000), 48U);
    BOOST_CHECK_EQUAL(Params(CBaseChainParams::REGTEST).EquihashK(4000000), 5U);

    for (auto network : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET, CBaseChainParams::REGTEST}) {
        const Consensus::Params& params = Params(network).GetConsensus();
        BOOST_CHECK_EQUAL(params.vUpgrades[Consensus::UPGRADE_VAULT].nActivationHeight,
                          Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);
        BOOST_CHECK_EQUAL(GetVaultScriptFlags(4000000, params), 0U);
    }
    // Mainnet's current epoch stays Canopy at any height.
    BOOST_CHECK_EQUAL(CurrentEpochBranchId(4000000, Params(CBaseChainParams::MAIN).GetConsensus()),
                      NetworkUpgradeInfo[Consensus::UPGRADE_CANOPY].nBranchId);
}

BOOST_AUTO_TEST_CASE(vault_upgrade_regtest_activation)
{
    SelectParams(CBaseChainParams::REGTEST);
    // The functional harness activates Overwinter and Sapling only; Vault activates on top of
    // them without Ycash, Blossom, Heartwood, Canopy or NU5.
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_OVERWINTER, 1);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_SAPLING, 1);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_VAULT, 10);
    const Consensus::Params& params = Params().GetConsensus();

    BOOST_CHECK_EQUAL(CurrentEpochBranchId(9, params), NetworkUpgradeInfo[Consensus::UPGRADE_SAPLING].nBranchId);
    BOOST_CHECK_EQUAL(CurrentEpochBranchId(10, params), VAULT_BRANCH_ID);
    BOOST_CHECK(IsActivationHeight(10, params, Consensus::UPGRADE_VAULT));
    BOOST_CHECK_EQUAL(NextActivationHeight(5, params).value(), 10);
    BOOST_CHECK_EQUAL(GetVaultScriptFlags(9, params), 0U);
    BOOST_CHECK_EQUAL(GetVaultScriptFlags(10, params), VAULT_FLAGS);
    // The previous epoch is the highest upgrade below Vault with a height, not NU5.
    BOOST_CHECK_EQUAL(PrevEpochBranchId(VAULT_BRANCH_ID, params), NetworkUpgradeInfo[Consensus::UPGRADE_SAPLING].nBranchId);

    // With the Ycash upgrades active too (the Yellowback harness), Canopy is the previous epoch.
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_YCASH, 1);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_BLOSSOM, 1);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_HEARTWOOD, 1);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_CANOPY, 1);
    BOOST_CHECK_EQUAL(CurrentEpochBranchId(9, params), NetworkUpgradeInfo[Consensus::UPGRADE_CANOPY].nBranchId);
    BOOST_CHECK_EQUAL(CurrentEpochBranchId(10, params), VAULT_BRANCH_ID);
    BOOST_CHECK_EQUAL(PrevEpochBranchId(VAULT_BRANCH_ID, params), NetworkUpgradeInfo[Consensus::UPGRADE_CANOPY].nBranchId);
    // Other upgrades keep the index-minus-one rule.
    BOOST_CHECK_EQUAL(PrevEpochBranchId(NetworkUpgradeInfo[Consensus::UPGRADE_CANOPY].nBranchId, params),
                      NetworkUpgradeInfo[Consensus::UPGRADE_HEARTWOOD].nBranchId);

    for (auto idx : {Consensus::UPGRADE_OVERWINTER, Consensus::UPGRADE_SAPLING, Consensus::UPGRADE_YCASH,
                     Consensus::UPGRADE_BLOSSOM, Consensus::UPGRADE_HEARTWOOD, Consensus::UPGRADE_CANOPY,
                     Consensus::UPGRADE_VAULT}) {
        UpdateNetworkUpgradeParameters(idx, Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);
    }
    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_CASE(vault_opnames)
{
    BOOST_CHECK_EQUAL(std::string(GetOpName(OP_CHECKSETSIG)), "OP_CHECKSETSIG");
    BOOST_CHECK_EQUAL(std::string(GetOpName(OP_CHECKSETDORMANT)), "OP_CHECKSETDORMANT");
    BOOST_CHECK_EQUAL((int)OP_CHECKSETSIG, 0xc0);
    BOOST_CHECK_EQUAL((int)OP_CHECKSETDORMANT, 0xc1);
    BOOST_CHECK_EQUAL((int)OP_CHECKSEQUENCEVERIFY, 0xb2);
    // OP_NOP3 keeps its name, as OP_NOP2 does for CLTV (script asm and the test data parse it).
    BOOST_CHECK_EQUAL(std::string(GetOpName(OP_NOP3)), "OP_NOP3");
}

BOOST_AUTO_TEST_CASE(vault_csv_vectors)
{
    // Without the flag: OP_NOP3, as today.
    BOOST_CHECK_EQUAL(CsvEval(10, 0, 0), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(CsvEval(10, 0, SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS), SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);

    // With it: BIP112.
    BOOST_CHECK_EQUAL(CsvEval(10, 10), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(CsvEval(10, 11), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(CsvEval(10, 9), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK_EQUAL(CsvEval(0, 0), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(CsvEval(65535, 65535), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(CsvEval(-1, 10), SCRIPT_ERR_NEGATIVE_LOCKTIME);
    // The input's disable flag defeats the check.
    BOOST_CHECK_EQUAL(CsvEval(10, CTxIn::SEQUENCE_FINAL), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK_EQUAL(CsvEval(10, CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG | 20), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    // An operand with the disable flag is a NOP (BIP112's extension point).
    BOOST_CHECK_EQUAL(CsvEval((int64_t)CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG, 0), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(CsvEval((int64_t)(CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG | CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG), 0), SCRIPT_ERR_OK);
    // Ycash: an operand with the type flag (time-based) fails, whatever the input says.
    BOOST_CHECK_EQUAL(CsvEval((int64_t)(CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | 1), CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | 5),
                      SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK_EQUAL(CsvEval((int64_t)CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG, 0), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    // A height operand against a time-typed input fails (apples to apples).
    BOOST_CHECK_EQUAL(CsvEval(1, CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | 5), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    // Bits outside the mask and the type flag are ignored on both sides.
    BOOST_CHECK_EQUAL(CsvEval(0x3fbf0000 | 10, 10), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(CsvEval(10, 0x3fbf0000 | 10), SCRIPT_ERR_OK);
    // A 5-byte operand is accepted (as CLTV); 2^32 masks to 0.
    BOOST_CHECK_EQUAL(CsvEval(0x100000000LL, 0), SCRIPT_ERR_OK);

    // Empty stack.
    {
        CMutableTransaction mtx = SeqTx(0);
        PrecomputedTransactionData txdata(CTransaction(mtx), {CTxOut(1, CScript())});
    MutableTransactionSignatureChecker checker(&mtx, txdata, 0, 1);
        BOOST_CHECK_EQUAL(Eval(CScript() << OP_CHECKSEQUENCEVERIFY, SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, checker),
                          SCRIPT_ERR_INVALID_STACK_OPERATION);
    }
    // CSV leaves its operand (like CLTV); the base checker refuses every sequence.
    {
        BaseSignatureChecker base;
        std::vector<valtype> stack;
        BOOST_CHECK_EQUAL(Eval(CScript() << 5 << OP_CHECKSEQUENCEVERIFY, SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, base, &stack),
                          SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        CMutableTransaction mtx = SeqTx(5);
        PrecomputedTransactionData txdata(CTransaction(mtx), {CTxOut(1, CScript())});
    MutableTransactionSignatureChecker checker(&mtx, txdata, 0, 1);
        BOOST_CHECK_EQUAL(Eval(CScript() << 5 << OP_CHECKSEQUENCEVERIFY, SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, checker, &stack),
                          SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1U);
    }
    // A pre-Overwinter (v1) transaction cannot satisfy CSV.
    {
        CMutableTransaction mtx;
        mtx.nVersion = 1;
        mtx.vin.resize(1);
        mtx.vin[0].nSequence = 5;
        PrecomputedTransactionData txdata(CTransaction(mtx), {CTxOut(1, CScript())});
    MutableTransactionSignatureChecker checker(&mtx, txdata, 0, 1);
        BOOST_CHECK_EQUAL(Eval(CScript() << 5 << OP_CHECKSEQUENCEVERIFY, SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, checker),
                          SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    }
}

BOOST_AUTO_TEST_CASE(vault_bip68_calculate)
{
    auto tx = [](std::vector<uint32_t> seqs) {
        CMutableTransaction mtx = SeqTx(0);
        mtx.vin.resize(seqs.size());
        for (size_t i = 0; i < seqs.size(); i++) {
            mtx.vin[i].prevout = COutPoint(uint256S("01"), i);
            mtx.vin[i].nSequence = seqs[i];
        }
        return CTransaction(mtx);
    };

    // Disabled inputs carry no lock.
    BOOST_CHECK_EQUAL(CalculateSequenceLocks(tx({CTxIn::SEQUENCE_FINAL}), {100}).value(), -1);
    BOOST_CHECK_EQUAL(CalculateSequenceLocks(tx({0xfffffffe}), {100}).value(), -1);
    // A coin at height 100 with a lock of 5 is spendable from height 105.
    int m = CalculateSequenceLocks(tx({5}), {100}).value();
    BOOST_CHECK_EQUAL(m, 104);
    BOOST_CHECK(!EvaluateSequenceLocks(104, m));
    BOOST_CHECK(EvaluateSequenceLocks(105, m));
    // Lock 0 and 1: the same block and the next block.
    BOOST_CHECK(EvaluateSequenceLocks(100, CalculateSequenceLocks(tx({0}), {100}).value()));
    BOOST_CHECK(!EvaluateSequenceLocks(100, CalculateSequenceLocks(tx({1}), {100}).value()));
    BOOST_CHECK(EvaluateSequenceLocks(101, CalculateSequenceLocks(tx({1}), {100}).value()));
    // Only the low 16 bits count.
    BOOST_CHECK_EQUAL(CalculateSequenceLocks(tx({0x3fbf0005}), {100}).value(), 104);
    BOOST_CHECK_EQUAL(CalculateSequenceLocks(tx({0xffff}), {0}).value(), 65534);
    // The maximum over inputs.
    BOOST_CHECK_EQUAL(CalculateSequenceLocks(tx({5, CTxIn::SEQUENCE_FINAL, 3}), {100, 1, 110}).value(), 112);
    // A time-based lock makes the transaction invalid; with the disable flag it is ignored.
    BOOST_CHECK(!CalculateSequenceLocks(tx({CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | 5}), {100}));
    BOOST_CHECK(!CalculateSequenceLocks(tx({5, CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG}), {100, 100}));
    BOOST_CHECK_EQUAL(CalculateSequenceLocks(
        tx({CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG | CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | 5}), {100}).value(), -1);
}

BOOST_AUTO_TEST_CASE(vault_bip68_contextual)
{
    CCoinsViewDummy dummy;
    CCoinsViewCache view(&dummy);

    CMutableTransaction parentA = SeqTx(CTxIn::SEQUENCE_FINAL);
    parentA.vin[0].prevout = COutPoint(uint256S("aa"), 0);
    CMutableTransaction parentB = SeqTx(CTxIn::SEQUENCE_FINAL);
    parentB.vin[0].prevout = COutPoint(uint256S("bb"), 0);
    CTransaction a(parentA), b(parentB);
    {
        CCoinsModifier ca = view.ModifyCoins(a.GetHash());
        ca->FromTx(a, 100);
    }
    {
        CCoinsModifier cb = view.ModifyCoins(b.GetHash());
        cb->FromTx(b, MEMPOOL_HEIGHT);
    }

    auto spend = [](const CTransaction& parent, uint32_t seq) {
        CMutableTransaction mtx = SeqTx(seq);
        mtx.vin[0].prevout = COutPoint(parent.GetHash(), 0);
        return CTransaction(mtx);
    };

    CValidationState state;
    BOOST_CHECK(ContextualCheckSequenceLocks(spend(a, 5), view, 105, state, false));
    BOOST_CHECK(!ContextualCheckSequenceLocks(spend(a, 5), view, 104, state, false));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-nonfinal");
    int dos = 0;
    BOOST_CHECK(state.IsInvalid(dos));
    BOOST_CHECK_EQUAL(dos, 100);

    CValidationState mstate;
    BOOST_CHECK(!ContextualCheckSequenceLocks(spend(a, 5), view, 104, mstate, true));
    BOOST_CHECK_EQUAL(mstate.GetRejectReason(), "non-BIP68-final");
    BOOST_CHECK(mstate.IsInvalid(dos));
    BOOST_CHECK_EQUAL(dos, 0);

    CValidationState tstate;
    BOOST_CHECK(!ContextualCheckSequenceLocks(spend(a, CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | 1), view, 1000, tstate, false));
    BOOST_CHECK_EQUAL(tstate.GetRejectReason(), "bad-txns-vault-timelock");

    // A mempool parent counts as confirming in the block checked: lock 0 passes, lock 1 waits.
    CValidationState pstate;
    BOOST_CHECK(ContextualCheckSequenceLocks(spend(b, 0), view, 200, pstate, true));
    BOOST_CHECK(!ContextualCheckSequenceLocks(spend(b, 1), view, 200, pstate, true));
    BOOST_CHECK(ContextualCheckSequenceLocks(spend(b, CTxIn::SEQUENCE_FINAL), view, 200, pstate, true));
}

BOOST_AUTO_TEST_CASE(vault_opcodes_without_flag)
{
    MockSetChecker checker;
    checker.threshold = 1;
    checker.released = true;
    const valtype setId = SetIdBytes();

    // Executed, they are SCRIPT_ERR_BAD_OPCODE exactly as before the upgrade, under any other flags.
    for (unsigned int flags : {0U, (unsigned int)SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
                               (unsigned int)SCRIPT_VERIFY_CHECKSEQUENCEVERIFY}) {
        BOOST_CHECK_EQUAL(Eval(CScript() << GoodSig(1) << setId << OP_1 << OP_CHECKSETSIG, flags, checker), SCRIPT_ERR_BAD_OPCODE);
        BOOST_CHECK_EQUAL(Eval(CScript() << setId << OP_CHECKSETDORMANT, flags, checker), SCRIPT_ERR_BAD_OPCODE);
        BOOST_CHECK_EQUAL(Eval(CScript() << OP_CHECKSETSIG, flags, checker), SCRIPT_ERR_BAD_OPCODE);
        // Unexecuted, they are skipped, as any unknown byte is today.
        std::vector<valtype> stack;
        BOOST_CHECK_EQUAL(Eval(CScript() << OP_0 << OP_IF << OP_CHECKSETSIG << OP_CHECKSETDORMANT << OP_ENDIF << OP_1,
                               flags, checker, &stack), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1U);
    }
    // 0xbb-0xbf stay BAD_OPCODE with the flag.
    for (int op = 0xba; op <= 0xbf; op++) {
        BOOST_CHECK_EQUAL(Eval(CScript() << (opcodetype)op, SCRIPT_VERIFY_VAULT, checker), SCRIPT_ERR_BAD_OPCODE);
    }
    // 0xc2 is OP_CHECKPQSIG (quantum plan §4.2, pq_script_tests); 0xc3 stays BAD_OPCODE.
    BOOST_CHECK_EQUAL(Eval(CScript() << (opcodetype)0xc3, SCRIPT_VERIFY_VAULT, checker), SCRIPT_ERR_BAD_OPCODE);
    BOOST_CHECK_EQUAL(checker.setSigCalls, 0);
}

BOOST_AUTO_TEST_CASE(vault_checksetsig)
{
    const valtype setId = SetIdBytes();
    const valtype sig1 = GoodSig(1), sig2 = GoodSig(2), sig3 = GoodSig(3);

    // Pop order: role on top (the templates push <setId> then OP_1/OP_2), then setId, then k sigs.
    {
        MockSetChecker checker;
        checker.threshold = 2;
        std::vector<valtype> stack;
        CScript s = CScript() << sig3 << sig1 << sig2 << setId << OP_1 << OP_CHECKSETSIG;
        BOOST_CHECK_EQUAL(Eval(s, SCRIPT_VERIFY_VAULT, checker, &stack), SCRIPT_ERR_OK);
        BOOST_CHECK(checker.lastSetId == uint256(setId));
        BOOST_CHECK_EQUAL(checker.lastRole, 1);
        BOOST_CHECK_EQUAL(checker.setSigCalls, 1);
        BOOST_REQUIRE_EQUAL(checker.lastSigs.size(), 2U);
        BOOST_CHECK(checker.lastSigs[0] == sig1);      // push order, sig_1 first
        BOOST_CHECK(checker.lastSigs[1] == sig2);
        // Exactly k popped; success pushes 1.
        BOOST_REQUIRE_EQUAL(stack.size(), 2U);
        BOOST_CHECK(stack[0] == sig3);
        BOOST_CHECK(stack[1] == valtype(1, 1));
    }
    // Role 2 (cancel).
    {
        MockSetChecker checker;
        checker.threshold = 1;
        BOOST_CHECK_EQUAL(Eval(CScript() << sig1 << setId << OP_2 << OP_CHECKSETSIG, SCRIPT_VERIFY_VAULT, checker), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(checker.lastRole, 2);
    }
    // Operands in the wrong order, wrong sizes, wrong roles.
    {
        MockSetChecker checker;
        checker.threshold = 1;
        const unsigned int f = SCRIPT_VERIFY_VAULT;
        BOOST_CHECK_EQUAL(Eval(CScript() << sig1 << OP_1 << setId << OP_CHECKSETSIG, f, checker), SCRIPT_ERR_SETSIG);
        BOOST_CHECK_EQUAL(Eval(CScript() << sig1 << valtype(31, 7) << OP_1 << OP_CHECKSETSIG, f, checker), SCRIPT_ERR_SETSIG);
        BOOST_CHECK_EQUAL(Eval(CScript() << sig1 << valtype(33, 7) << OP_1 << OP_CHECKSETSIG, f, checker), SCRIPT_ERR_SETSIG);
        BOOST_CHECK_EQUAL(Eval(CScript() << sig1 << setId << OP_0 << OP_CHECKSETSIG, f, checker), SCRIPT_ERR_SETSIG);
        BOOST_CHECK_EQUAL(Eval(CScript() << sig1 << setId << OP_3 << OP_CHECKSETSIG, f, checker), SCRIPT_ERR_SETSIG);
        BOOST_CHECK_EQUAL(Eval(CScript() << sig1 << setId << OP_1NEGATE << OP_CHECKSETSIG, f, checker), SCRIPT_ERR_SETSIG);
        BOOST_CHECK_EQUAL(Eval(CScript() << sig1 << setId << valtype{1, 0} << OP_CHECKSETSIG, f, checker), SCRIPT_ERR_SETSIG);
        BOOST_CHECK_EQUAL(Eval(CScript() << setId << OP_CHECKSETSIG, f, checker), SCRIPT_ERR_INVALID_STACK_OPERATION);
        BOOST_CHECK_EQUAL(Eval(CScript() << OP_CHECKSETSIG, f, checker), SCRIPT_ERR_INVALID_STACK_OPERATION);
        BOOST_CHECK_EQUAL(checker.setSigCalls, 0);
    }
    // k from the checker: unknown set, too few signatures on the stack.
    {
        MockSetChecker checker;   // threshold nullopt: unknown set
        BOOST_CHECK_EQUAL(Eval(CScript() << sig1 << setId << OP_1 << OP_CHECKSETSIG, SCRIPT_VERIFY_VAULT, checker), SCRIPT_ERR_SETSIG);
        checker.threshold = 3;
        BOOST_CHECK_EQUAL(Eval(CScript() << sig1 << sig2 << setId << OP_1 << OP_CHECKSETSIG, SCRIPT_VERIFY_VAULT, checker), SCRIPT_ERR_SETSIG);
        checker.threshold = 0;
        BOOST_CHECK_EQUAL(Eval(CScript() << sig1 << setId << OP_1 << OP_CHECKSETSIG, SCRIPT_VERIFY_VAULT, checker), SCRIPT_ERR_SETSIG);
        BOOST_CHECK_EQUAL(checker.setSigCalls, 0);
    }
    // Signature shape: 65 bytes, header 31..34, low S.
    {
        MockSetChecker checker;
        checker.threshold = 1;
        auto one = [&](const valtype& sig) {
            return Eval(CScript() << sig << setId << OP_1 << OP_CHECKSETSIG, SCRIPT_VERIFY_VAULT, checker);
        };
        BOOST_CHECK_EQUAL(one(valtype(64, 1)), SCRIPT_ERR_SETSIG);
        valtype longer = sig1; longer.push_back(0);
        BOOST_CHECK_EQUAL(one(longer), SCRIPT_ERR_SETSIG);
        for (int header : {27, 28, 29, 30, 35, 0}) {
            valtype s = sig1; s[0] = header;
            BOOST_CHECK_EQUAL(one(s), SCRIPT_ERR_SETSIG);
        }
        for (int header : {31, 32, 33, 34}) {
            valtype s = sig1; s[0] = header;
            BOOST_CHECK_EQUAL(one(s), SCRIPT_ERR_OK);
        }
        // s = n/2 is low, n/2 + 1 is high.
        valtype half = ParseHex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0");
        valtype s = sig1;
        std::copy(half.begin(), half.end(), s.begin() + 33);
        BOOST_CHECK_EQUAL(one(s), SCRIPT_ERR_OK);
        s[64] = 0xA1;
        BOOST_CHECK_EQUAL(one(s), SCRIPT_ERR_SETSIG);
        std::fill(s.begin() + 33, s.end(), 0xff);
        BOOST_CHECK_EQUAL(one(s), SCRIPT_ERR_SETSIG);
    }
    // The checker's verdict: a failure is an error, never a false result.
    {
        MockSetChecker checker;
        checker.threshold = 1;
        checker.sigsOk = false;
        BOOST_CHECK_EQUAL(Eval(CScript() << sig1 << setId << OP_1 << OP_CHECKSETSIG << OP_NOT, SCRIPT_VERIFY_VAULT, checker), SCRIPT_ERR_SETSIG);
        BOOST_CHECK_EQUAL(checker.setSigCalls, 1);
    }
    // At most one OP_CHECKSETSIG per evaluation, executed; a second in an unexecuted branch is fine.
    {
        MockSetChecker checker;
        checker.threshold = 1;
        CScript twice = CScript() << sig1 << setId << OP_1 << OP_CHECKSETSIG << OP_DROP
                                  << sig2 << setId << OP_2 << OP_CHECKSETSIG;
        BOOST_CHECK_EQUAL(Eval(twice, SCRIPT_VERIFY_VAULT, checker), SCRIPT_ERR_SETSIG_COUNT);
        BOOST_CHECK_EQUAL(checker.setSigCalls, 1);
        CScript branch = CScript() << sig1 << setId << OP_1 << OP_CHECKSETSIG
                                   << OP_0 << OP_IF << OP_CHECKSETSIG << OP_ENDIF;
        BOOST_CHECK_EQUAL(Eval(branch, SCRIPT_VERIFY_VAULT, checker), SCRIPT_ERR_OK);
        // The counter is per EvalScript call: a fresh evaluation may use it again.
        BOOST_CHECK_EQUAL(Eval(CScript() << sig1 << setId << OP_1 << OP_CHECKSETSIG, SCRIPT_VERIFY_VAULT, checker), SCRIPT_ERR_OK);
    }
    // The base checker's defaults fail: the existing checkers cannot satisfy it.
    {
        BaseSignatureChecker base;
        BOOST_CHECK_EQUAL(Eval(CScript() << sig1 << setId << OP_1 << OP_CHECKSETSIG, SCRIPT_VERIFY_VAULT, base), SCRIPT_ERR_SETSIG);
        CMutableTransaction mtx = SeqTx(0);
        PrecomputedTransactionData txdata(CTransaction(mtx), {CTxOut(1, CScript())});
        MutableTransactionSignatureChecker txChecker(&mtx, txdata, 0, 1);
        BOOST_CHECK_EQUAL(Eval(CScript() << sig1 << setId << OP_1 << OP_CHECKSETSIG, SCRIPT_VERIFY_VAULT, txChecker), SCRIPT_ERR_SETSIG);
    }
}

BOOST_AUTO_TEST_CASE(vault_checksetdormant)
{
    const valtype setId = SetIdBytes(0x33);
    MockSetChecker checker;
    std::vector<valtype> stack;

    checker.released = true;
    BOOST_CHECK_EQUAL(Eval(CScript() << setId << OP_CHECKSETDORMANT, SCRIPT_VERIFY_VAULT, checker, &stack), SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    BOOST_CHECK(stack[0] == valtype(1, 1));
    BOOST_CHECK(checker.lastDormantSetId == uint256(setId));

    checker.released = false;
    BOOST_CHECK_EQUAL(Eval(CScript() << setId << OP_CHECKSETDORMANT, SCRIPT_VERIFY_VAULT, checker, &stack), SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    BOOST_CHECK(stack[0].empty());
    // ... so OP_VERIFY fails on a live set (the OWNER-RELEASED branch).
    BOOST_CHECK_EQUAL(Eval(CScript() << setId << OP_CHECKSETDORMANT << OP_VERIFY, SCRIPT_VERIFY_VAULT, checker), SCRIPT_ERR_VERIFY);

    BOOST_CHECK_EQUAL(Eval(CScript() << valtype(31, 1) << OP_CHECKSETDORMANT, SCRIPT_VERIFY_VAULT, checker), SCRIPT_ERR_SETSIG);
    BOOST_CHECK_EQUAL(Eval(CScript() << valtype(33, 1) << OP_CHECKSETDORMANT, SCRIPT_VERIFY_VAULT, checker), SCRIPT_ERR_SETSIG);
    BOOST_CHECK_EQUAL(Eval(CScript() << OP_CHECKSETDORMANT, SCRIPT_VERIFY_VAULT, checker), SCRIPT_ERR_INVALID_STACK_OPERATION);
    // Not limited in count.
    BOOST_CHECK_EQUAL(Eval(CScript() << setId << OP_CHECKSETDORMANT << OP_DROP << setId << OP_CHECKSETDORMANT,
                           SCRIPT_VERIFY_VAULT, checker), SCRIPT_ERR_OK);

    // The base checker says not released.
    BaseSignatureChecker base;
    BOOST_CHECK_EQUAL(Eval(CScript() << setId << OP_CHECKSETDORMANT, SCRIPT_VERIFY_VAULT, base, &stack), SCRIPT_ERR_OK);
    BOOST_CHECK(stack.back().empty());
}

BOOST_AUTO_TEST_CASE(vault_flags_not_in_static_policy)
{
    // The upgrade's flags are added by height (GetVaultScriptFlags), never to the static sets,
    // so nothing changes before activation (plan §15.1).
    BOOST_CHECK_EQUAL(STANDARD_SCRIPT_VERIFY_FLAGS & VAULT_FLAGS, 0U);
    BOOST_CHECK_EQUAL(MANDATORY_SCRIPT_VERIFY_FLAGS & VAULT_FLAGS, 0U);
}

BOOST_AUTO_TEST_SUITE_END()
