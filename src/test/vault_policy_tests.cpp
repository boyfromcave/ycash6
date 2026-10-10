// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Relay policy for the vault primitive (docs/plans/yellowback-upgrade-plan.md §15.3, §15.5):
// Solver recognises the V and I templates (no destination), they are standard outputs only
// where UPGRADE_VAULT is active at the next block, a `YV` act OP_RETURN may carry up to
// MAX_VAULT_ACT_BYTES there (other OP_RETURNs unchanged), and a template input's scriptSig
// passes AreInputsStandard. Post-quantum (docs/plans/yellowback-quantum-spec.md §2.3, F-6, A-1, A-14):
// TX_PQPKH is standard from activation, a scheme-2 PQPKH/V/I output only once Falcon is active, and a
// PQPKH/V/I input may carry a scriptSig up to MAX_STANDARD_PQ_SCRIPTSIG (every other input 1,650).

#include "chainparams.h"
#include "crypto/pq/scheme.h"
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
    v.owner = CPQKeyID(1, Hash(Key(1).begin(), Key(1).end()));   // a post-quantum owner id (quantum plan §4.3)
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

namespace {

/** <sig chunks> <s> <pk chunks> <p>, the PQ owner/holder stack shape, with dummy bytes of the scheme's sizes. */
CScript PQArgs(uint8_t scheme, int sigLen = -1, int extraPushes = 0)
{
    const size_t sl = sigLen >= 0 ? (size_t)sigLen : pq::SigSize(scheme) + 1, pl = pq::PubKeySize(scheme);
    CScript ss;
    int s = 0, p = 0;
    for (size_t i = 0; i < sl; i += pq::MAX_CHUNK, s++) ss << valtype(std::min(pq::MAX_CHUNK, sl - i), 0x5a);
    ss << CScript::EncodeOP_N(s);
    for (size_t i = 0; i < pl; i += pq::MAX_CHUNK, p++) ss << valtype(std::min(pq::MAX_CHUNK, pl - i), 0x6b);
    ss << CScript::EncodeOP_N(p);
    for (int i = 0; i < extraPushes; i++) ss << valtype(1, 0x07);
    return ss;
}

void AddCoin(CCoinsViewCache& view, const uint256& txid, const CScript& spk)
{
    CCoinsModifier c = view.ModifyCoins(txid);
    c->vout.resize(1);
    c->vout[0] = CTxOut(100000, spk);
    c->nHeight = 11;
}

} // namespace

BOOST_AUTO_TEST_CASE(pqpkh_standard_from_activation_and_falcon_gate)
{
    RegtestVault rv;
    std::string reason;
    const CScript slh = GetScriptForDestination(CPQKeyID(pq::SCHEME_SLH_DSA_SHA2_128S, uint256S("0xab")));
    const CScript fal = GetScriptForDestination(CPQKeyID(pq::SCHEME_FN_DSA_512, uint256S("0xab")));
    BOOST_REQUIRE_EQUAL(slh.size(), 35U);
    txnouttype t;
    BOOST_CHECK(IsStandard(slh, t) && t == TX_PQPKH);
    CMutableTransaction before = Tx(9);
    before.vout.push_back(CTxOut(100000, slh));
    BOOST_CHECK(!IsStandardTx(CTransaction(before), reason, Params(), 9));
    BOOST_CHECK_EQUAL(reason, "scriptpubkey");
    CMutableTransaction after = Tx(10);
    after.vout.push_back(CTxOut(100000, slh));
    reason.clear();
    BOOST_CHECK_MESSAGE(IsStandardTx(CTransaction(after), reason, Params(), 10), reason);

    // Scheme 2 (FN-DSA-512) outputs: PQPKH, V and I, refused while Falcon is inactive (A-1), standard once active.
    VaultParams vp = Params1();
    vp.owner.scheme = pq::SCHEME_FN_DSA_512;
    const CScript fv = BuildVault(vp);
    const CScript fi = BuildIntent(IntentFor(vp, fv, GetScriptForDestination(Key(3).GetID())));
    BOOST_REQUIRE(!fv.empty() && !fi.empty());
    BOOST_CHECK_EQUAL(PQScriptScheme(fv, TX_VAULT).value_or(0), pq::SCHEME_FN_DSA_512);
    BOOST_CHECK_EQUAL(PQScriptScheme(fi, TX_VAULT_INTENT).value_or(0), pq::SCHEME_FN_DSA_512);
    BOOST_CHECK_EQUAL(PQScriptScheme(slh, TX_PQPKH).value_or(0), pq::SCHEME_SLH_DSA_SHA2_128S);
    BOOST_CHECK(!PQScriptScheme(GetScriptForDestination(Key(3).GetID()), TX_PUBKEYHASH).has_value());
    BOOST_CHECK(!IsPQFalconActive(Params().GetConsensus(), 10));
    for (const CScript& spk : {fal, fv, fi}) {
        CMutableTransaction m = Tx(10);
        m.vout.push_back(CTxOut(100000, spk));
        reason.clear();
        BOOST_CHECK(!IsStandardTx(CTransaction(m), reason, Params(), 10));
        BOOST_CHECK_EQUAL(reason, "scriptpubkey");
    }
    mapArgs["-pqfalcon"] = "1";
    SelectParams(CBaseChainParams::REGTEST);
    BOOST_CHECK(IsPQFalconActive(Params().GetConsensus(), 10));
    for (const CScript& spk : {fal, fv, fi}) {
        CMutableTransaction m = Tx(10);
        m.vout.push_back(CTxOut(100000, spk));
        reason.clear();
        BOOST_CHECK_MESSAGE(IsStandardTx(CTransaction(m), reason, Params(), 10), reason);
    }
    mapArgs.erase("-pqfalcon");
    SelectParams(CBaseChainParams::REGTEST);
    BOOST_CHECK(!IsPQFalconActive(Params().GetConsensus(), 10));
}

BOOST_AUTO_TEST_CASE(pq_scriptsig_limits)
{
    RegtestVault rv;
    std::string reason;
    CCoinsViewDummy base;
    CCoinsViewCache view(&base);
    const uint256 pPkh = uint256S("0x61"), pSlh = uint256S("0x62"), pFal = uint256S("0x63"), pV = uint256S("0x64"),
                  pI = uint256S("0x65");
    AddCoin(view, pPkh, GetScriptForDestination(Key(5).GetID()));
    AddCoin(view, pSlh, GetScriptForDestination(CPQKeyID(pq::SCHEME_SLH_DSA_SHA2_128S, uint256S("0x01"))));
    AddCoin(view, pFal, GetScriptForDestination(CPQKeyID(pq::SCHEME_FN_DSA_512, uint256S("0x02"))));
    const CScript vspk = BuildVault(Params1());
    AddCoin(view, pV, vspk);
    AddCoin(view, pI, BuildIntent(IntentFor(Params1(), vspk, GetScriptForDestination(Key(3).GetID()))));
    const uint32_t branch = CurrentEpochBranchId(12, Params().GetConsensus());

    auto spend = [&](const uint256& prev, const CScript& ss, int height) {
        CMutableTransaction m = Tx(height);
        m.vin[0].prevout = COutPoint(prev, 0);
        m.vin[0].scriptSig = ss;
        m.vout.push_back(CTxOut(1000, GetScriptForDestination(Key(4).GetID())));
        return CTransaction(m);
    };

    // An SLH-DSA PQPKH spend: 7,938 bytes, 19 pushes (quantum spec §2.1).
    const CScript slh = PQArgs(pq::SCHEME_SLH_DSA_SHA2_128S);
    BOOST_CHECK_EQUAL(slh.size(), 7938U);
    BOOST_CHECK_MESSAGE(IsStandardTx(spend(pSlh, slh, 12), reason, Params(), 12), reason);
    BOOST_CHECK(AreInputsStandard(spend(pSlh, slh, 12), view, branch));
    // Before the upgrade the 1,650-byte limit stands (IsStandardTx).
    BOOST_CHECK(!IsStandardTx(spend(pSlh, slh, 9), reason, Params(), 9));
    BOOST_CHECK_EQUAL(reason, "scriptsig-size");
    // The exact count per scheme (A-14): one push more or fewer is non-standard.
    BOOST_CHECK(!AreInputsStandard(spend(pSlh, PQArgs(pq::SCHEME_SLH_DSA_SHA2_128S, -1, 1), 12), view, branch));
    // a Falcon-shaped stack against an SLH key is the wrong count
    BOOST_CHECK(!AreInputsStandard(spend(pSlh, PQArgs(pq::SCHEME_FN_DSA_512), 12), view, branch));
    // A Falcon PQPKH spend: 1,577 bytes, 6 pushes.
    const CScript fal = PQArgs(pq::SCHEME_FN_DSA_512);
    BOOST_CHECK_EQUAL(fal.size(), 1577U);
    BOOST_CHECK(AreInputsStandard(spend(pFal, fal, 12), view, branch));
    BOOST_CHECK(!AreInputsStandard(spend(pFal, slh, 12), view, branch));

    // Above MAX_STANDARD_PQ_SCRIPTSIG: refused by IsStandardTx (and by AreInputsStandard for a PQ prevout).
    CScript huge = slh;
    huge << valtype(MAX_STANDARD_PQ_SCRIPTSIG - slh.size() + 1 - 3, 0x01);
    BOOST_CHECK(huge.size() > MAX_STANDARD_PQ_SCRIPTSIG);
    BOOST_CHECK(!IsStandardTx(spend(pSlh, huge, 12), reason, Params(), 12));
    BOOST_CHECK_EQUAL(reason, "scriptsig-size");
    BOOST_CHECK(!AreInputsStandard(spend(pSlh, huge, 12), view, branch));

    // A P2PKH input whose scriptSig passes IsStandardTx's relaxed bound is caught by AreInputsStandard (F-6).
    CScript fat;
    fat << valtype(520, 0x01) << valtype(520, 0x02) << valtype(520, 0x03) << valtype(100, 0x04);
    BOOST_CHECK(fat.size() > MAX_STANDARD_SCRIPTSIG && fat.size() <= MAX_STANDARD_PQ_SCRIPTSIG);
    BOOST_CHECK_MESSAGE(IsStandardTx(spend(pPkh, fat, 12), reason, Params(), 12), reason);
    BOOST_CHECK(!AreInputsStandard(spend(pPkh, fat, 12), view, branch));

    // V and I owner spends (selector 2 / 3) of 7,939 bytes are standard inputs (F-6: every V/I selector).
    CScript vOwner = slh;
    vOwner << OP_2;
    BOOST_CHECK_EQUAL(vOwner.size(), 7939U);
    BOOST_CHECK(AreInputsStandard(spend(pV, vOwner, 12), view, branch));
    CScript iOwner = slh;
    iOwner << OP_3;
    BOOST_CHECK(AreInputsStandard(spend(pI, iOwner, 12), view, branch));
    CScript vHuge = huge;
    vHuge << OP_2;
    BOOST_CHECK(!AreInputsStandard(spend(pV, vHuge, 12), view, branch));

    // P2SH-wrapped PQPKH stays non-standard (quantum spec §2.3): its redeem solves to TX_PQPKH, args -1.
    const CScript redeem = GetScriptForDestination(CPQKeyID(pq::SCHEME_FN_DSA_512, uint256S("0x03")));
    const uint256 pSh = uint256S("0x66");
    AddCoin(view, pSh, GetScriptForDestination(CScriptID(redeem)));
    CScript shSig = fal;
    shSig << ToByteVector(redeem);
    BOOST_CHECK(!AreInputsStandard(spend(pSh, shSig, 12), view, branch));
}

BOOST_AUTO_TEST_SUITE_END()
