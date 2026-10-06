// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Relay policy for the vault primitive (docs/plans/yellowback-upgrade-plan.md §15.3, §15.5):
// Solver recognises the V and I templates (no destination), they are standard outputs only
// where UPGRADE_VAULT is active at the next block, a `YV` act OP_RETURN may carry up to
// MAX_VAULT_ACT_BYTES there (other OP_RETURNs unchanged), and a template input's scriptSig
// passes AreInputsStandard.

#include "chainparams.h"
#include "coins.h"
#include "consensus/upgrades.h"
#include "key.h"
#include "main.h"
#include "policy/policy.h"
#include "script/standard.h"
#include "test/test_bitcoin.h"
#include "vault/act.h"
#include "vault/template.h"

#include <boost/test/unit_test.hpp>

using namespace vault;

namespace {

typedef std::vector<unsigned char> valtype;

CPubKey Key(unsigned char seed)
{
    CKey k;
    std::vector<unsigned char> secret(32, 0);
    secret[0] = 0x44;
    secret[31] = seed;
    k.Set(secret.begin(), secret.end(), true);
    return k.GetPubKey();
}

VaultParams Params1()
{
    VaultParams v;
    v.tag = {'T', 'E', 'S', 'T'};
    v.setId = uint256S("0x11");
    v.cancelSetId = uint256S("0x22");
    v.delay = 5;
    v.ownerHeight = 1000;
    v.ownerKey = Key(1);
    v.appHeight = 0;
    return v;
}

CMutableTransaction Tx(int height)
{
    CMutableTransaction m = CreateNewContextualCMutableTransaction(Params().GetConsensus(), height, /* requireV4 */ true);
    m.vin.push_back(CTxIn(COutPoint(uint256S("0x33"), 0), CScript() << valtype(72, 1) << valtype(33, 2), 0xffffffff));
    return m;
}

CScript ActScript(size_t sigs)
{
    Act a;
    a.type = ACT_SET_HEARTBEAT;
    a.heartbeat.setId = uint256S("0x11");
    a.heartbeat.memberKey = Key(2);
    for (size_t i = 0; i < sigs; i++) {
        valtype s(65, 0x20);
        s[0] = 31;
        a.sigs.push_back(s);
    }
    return EncodeAct(a);
}

struct RegtestVault {
    RegtestVault()
    {
        SelectParams(CBaseChainParams::REGTEST);
        UpdateNetworkUpgradeParameters(Consensus::UPGRADE_OVERWINTER, 1);
        UpdateNetworkUpgradeParameters(Consensus::UPGRADE_SAPLING, 1);
        UpdateNetworkUpgradeParameters(Consensus::UPGRADE_VAULT, 10);
    }
    ~RegtestVault()
    {
        for (auto idx : {Consensus::UPGRADE_OVERWINTER, Consensus::UPGRADE_SAPLING, Consensus::UPGRADE_VAULT})
            UpdateNetworkUpgradeParameters(idx, Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);
        SelectParams(CBaseChainParams::MAIN);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(vault_policy_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(solver_recognises_templates)
{
    VaultParams vp = Params1();
    CScript vspk = BuildVault(vp);
    CScript ispk = BuildIntent(IntentFor(vp, vspk, GetScriptForDestination(Key(3).GetID())));
    txnouttype t;
    std::vector<valtype> sol;
    BOOST_CHECK(Solver(vspk, t, sol));
    BOOST_CHECK_EQUAL(t, TX_VAULT);
    BOOST_CHECK(sol.empty());
    BOOST_CHECK(Solver(ispk, t, sol));
    BOOST_CHECK_EQUAL(t, TX_VAULT_INTENT);
    BOOST_CHECK_EQUAL(std::string(GetTxnOutputType(TX_VAULT)), "vault");
    BOOST_CHECK_EQUAL(std::string(GetTxnOutputType(TX_VAULT_INTENT)), "vaultintent");
    CTxDestination dest;
    BOOST_CHECK(!ExtractDestination(vspk, dest));
    BOOST_CHECK(!ExtractDestination(ispk, dest));
    std::vector<CTxDestination> dests;
    int n;
    BOOST_CHECK(!ExtractDestinations(vspk, t, dests, n));
    BOOST_CHECK_EQUAL(ScriptSigArgsExpected(TX_VAULT, sol), -1);
    // A malformed V (a non-minimal delay push) is not a template.
    // Rebuild with the delay pushed as a 2-byte number: <tag> <cancelSetId> 0x02 0x05 0x00 ...
    CScript nonMinimal;
    CScript::const_iterator it = vspk.begin();
    opcodetype op;
    valtype data;
    int i = 0;
    while (vspk.GetOp(it, op, data)) {
        if (i == 2) nonMinimal << valtype{0x05, 0x00};
        else if (data.empty()) nonMinimal << op;
        else nonMinimal << data;
        i++;
    }
    BOOST_CHECK(nonMinimal != vspk);
    BOOST_CHECK(!Solver(nonMinimal, t, sol));
    BOOST_CHECK_EQUAL(t, TX_NONSTANDARD);
}

BOOST_AUTO_TEST_CASE(templates_standard_from_activation)
{
    RegtestVault rv;
    std::string reason;
    VaultParams vp = Params1();
    CScript vspk = BuildVault(vp);
    CScript ispk = BuildIntent(IntentFor(vp, vspk, GetScriptForDestination(Key(3).GetID())));
    for (const CScript& spk : {vspk, ispk}) {
        CMutableTransaction before = Tx(9);
        before.vout.push_back(CTxOut(100000, spk));
        BOOST_CHECK(!IsStandardTx(CTransaction(before), reason, Params(), 9));
        BOOST_CHECK_EQUAL(reason, "scriptpubkey");
        CMutableTransaction after = Tx(10);
        after.vout.push_back(CTxOut(100000, spk));
        reason.clear();
        BOOST_CHECK_MESSAGE(IsStandardTx(CTransaction(after), reason, Params(), 10), reason);
    }
}

BOOST_AUTO_TEST_CASE(act_op_return_size)
{
    RegtestVault rv;
    std::string reason;
    // A heartbeat with 3 signatures: well above the 83-byte data carrier limit.
    CScript act = ActScript(3);
    BOOST_CHECK(act.size() > MAX_OP_RETURN_RELAY);
    BOOST_CHECK(act.size() <= MAX_VAULT_ACT_BYTES);
    CMutableTransaction before = Tx(9);
    before.vout.push_back(CTxOut(0, act));
    BOOST_CHECK(!IsStandardTx(CTransaction(before), reason, Params(), 9)); // ordinary data before activation
    BOOST_CHECK_EQUAL(reason, "scriptpubkey");
    CMutableTransaction after = Tx(10);
    after.vout.push_back(CTxOut(0, act));
    reason.clear();
    BOOST_CHECK_MESSAGE(IsStandardTx(CTransaction(after), reason, Params(), 10), reason);

    // At most MAX_VAULT_ACT_BYTES (18 signatures do not fit).
    CScript big = ActScript(18);
    BOOST_CHECK(big.size() > MAX_VAULT_ACT_BYTES);
    CMutableTransaction tooBig = Tx(10);
    tooBig.vout.push_back(CTxOut(0, big));
    BOOST_CHECK(!IsStandardTx(CTransaction(tooBig), reason, Params(), 10));

    // Other OP_RETURNs keep the data carrier limit.
    CMutableTransaction other = Tx(10);
    other.vout.push_back(CTxOut(0, CScript() << OP_RETURN << valtype(200, 0x41)));
    BOOST_CHECK(!IsStandardTx(CTransaction(other), reason, Params(), 10));
    BOOST_CHECK_EQUAL(reason, "scriptpubkey");

    // An act counts as the transaction's one OP_RETURN.
    CMutableTransaction two = Tx(10);
    two.vout.push_back(CTxOut(0, act));
    two.vout.push_back(CTxOut(0, CScript() << OP_RETURN << valtype(10, 0x41)));
    BOOST_CHECK(!IsStandardTx(CTransaction(two), reason, Params(), 10));
    BOOST_CHECK_EQUAL(reason, "multi-op-return");
}

BOOST_AUTO_TEST_CASE(template_inputs_standard)
{
    RegtestVault rv;
    VaultParams vp = Params1();
    CScript vspk = BuildVault(vp);
    CCoinsViewDummy base; // 6.20.0: CCoinsView is abstract
    CCoinsViewCache view(&base);
    const uint256 prev = uint256S("0x55");
    {
        CCoinsModifier c = view.ModifyCoins(prev);
        c->vout.resize(1);
        c->vout[0] = CTxOut(100000, vspk);
        c->nHeight = 11;
    }
    CMutableTransaction m = Tx(12);
    m.vin[0].prevout = COutPoint(prev, 0);
    // 15 signatures of 65 bytes and the selector: within the 1,650-byte scriptSig limit.
    CScript ss;
    for (int i = 0; i < 15; i++) ss << valtype(65, 0x20);
    ss << OP_1;
    BOOST_CHECK(ss.size() <= 1650);
    m.vin[0].scriptSig = ss;
    m.vout.push_back(CTxOut(1000, GetScriptForDestination(Key(4).GetID())));
    std::string reason;
    BOOST_CHECK_MESSAGE(IsStandardTx(CTransaction(m), reason, Params(), 12), reason);
    BOOST_CHECK(AreInputsStandard(CTransaction(m), view, CurrentEpochBranchId(12, Params().GetConsensus())));
}

BOOST_AUTO_TEST_SUITE_END()
