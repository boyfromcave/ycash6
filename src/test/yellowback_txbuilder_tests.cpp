// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The v2 transaction builder's pure layer (plan §3.5, §4.2a): every template's
// output layout (vout order, feeVout, payload round-trip, nLockTime /
// nSequence / nExpiryHeight), SignVaultSpend under STANDARD_SCRIPT_VERIFY_FLAGS
// with the right amount and branch id and with the wrong ones (ZIP-243 binds
// both, mapping §13.1), the VOID release and the SWEEP without OP_RETURN or
// fee output, and the pure shapes evaluated by the state machine itself
// (MINT-1..8 and RED-1..4 over a MemoryStateView), so the wallet and the
// validator cannot disagree on a template the wallet emits. The Build*
// functions that select coins from a CWallet are exercised by the functional
// tests (yellowback_lifecycle.py, yellowback_claim.py, yellowback_void_mint.py).

#include "yellowback/attest.h"
#include "yellowback/bundle.h"
#include "yellowback/index.h"
#include "yellowback/math.h"
#include "yellowback/params.h"
#include "yellowback/payload.h"
#include "yellowback/script.h"
#include "yellowback/state.h"
#include "yellowback/txbuilder.h"
#include "yellowback/view.h"

#include "chainparams.h"
#include "consensus/upgrades.h"
#include "key.h"
#include "keystore.h"
#include "main.h"
#include "policy/policy.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script_error.h"
#include "script/standard.h"
#include "crypto/sha256.h"
#include "script/ismine.h"
#include "script/sign.h"
#include "test/test_bitcoin.h"
#include "util/test.h"
#include "zip317.h"

#include <boost/test/unit_test.hpp>

using namespace yellowback;

namespace {

const unsigned int CONSENSUS_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;   // main.cpp:3412 (v4.5.0 :2931)

CKey NewKey()
{
    CKey k;
    k = CKey::TestOnlyRandomKey(true);
    return k;
}

/** A Sapling-format transaction shell as Context::NewTx makes it. */
CMutableTransaction Shell(uint32_t nExpiryHeight)
{
    CMutableTransaction mtx;
    mtx.fOverwintered = true;
    mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    mtx.nVersion = SAPLING_TX_VERSION;
    mtx.nExpiryHeight = nExpiryHeight;
    return mtx;
}

bool Verify(const CMutableTransaction& mtx, unsigned int nIn, const CScript& scriptPubKey, CAmount amount, uint32_t branchId,
            ScriptError* err = nullptr, unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS)
{
    const CTransaction tx(mtx);
    PrecomputedTransactionData txdata(tx, {});
    return VerifyScript(tx.vin[nIn].scriptSig, scriptPubKey, flags, TransactionSignatureChecker(&tx, txdata, nIn, amount), branchId, err);
}

YedCoin Coin(const uint256& txid, uint32_t n, Cents cents, const CKey& key)
{
    YedCoin c;
    c.outpoint = COutPoint(txid, n);
    c.token.cents = cents;
    c.token.nValue = TOKEN_VALUE;
    c.token.scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());
    c.token.height = 100;
    return c;
}

/** A vault shape for tests: the ACTIVE vault of `owner`, 5 YEC, class A on the regtest set. */
struct Fixture
{
    yellowback::Params params;
    CKey owner;
    CKey yedKey;
    CKey payeeKey;
    uint32_t lockHeight, claimHeight;
    CAmount vaultValue;
    COutPoint vaultOut;
    CScript vaultScript;
    uint32_t branchId;

    Fixture() : params(RegtestParams(1, 0, 0, 0)), owner(NewKey()), yedKey(NewKey()), payeeKey(NewKey()),
                lockHeight(300), claimHeight(300 + params.grace), vaultValue(5 * COIN), vaultOut(uint256S("aa"), 0),
                branchId(NetworkUpgradeInfo[Consensus::UPGRADE_SAPLING].nBranchId)
    {
        vaultScript = VaultScript(lockHeight, owner.GetPubKey(), claimHeight);
        BOOST_REQUIRE(!vaultScript.empty());
    }

    VaultSpendShape Shape(bool ownerPath, bool withPayload, bool transparentDest, bool withPayee, std::vector<YedCoin> yed, Cents change = 0) const
    {
        VaultSpendShape s;
        s.vaultOut = vaultOut;
        s.vaultScript = vaultScript;
        s.vaultValue = vaultValue;
        s.lockHeight = lockHeight;
        s.claimHeight = claimHeight;
        s.ownerPath = ownerPath;
        s.withPayload = withPayload;
        s.refHeight = 250;
        if (withPayee) s.payee = payeeKey.GetPubKey().GetID();
        s.feeZat = FeeZat(vaultValue, params.feeMin, params.feeBps);
        s.yedInputs = yed;
        s.changeCents = change;
        s.changeScript = GetScriptForDestination(NewKey().GetPubKey().GetID());
        if (transparentDest) s.collateralScript = GetScriptForDestination(NewKey().GetPubKey().GetID());
        s.networkFee = DEFAULT_YELLOWBACK_FEE;
        return s;
    }

    BuiltTx Built(const VaultSpendShape& s, const VaultSpendPlan& plan) const
    {
        BuiltTx out;
        out.tx = Shell((uint32_t)(s.refHeight + REF_WINDOW));
        out.tx.nLockTime = plan.nLockTime;
        out.tx.vin = plan.vin;
        out.tx.vout = plan.vout;
        out.vaultScript = s.vaultScript;
        out.vaultValue = s.vaultValue;
        out.ownerPubKey = owner.GetPubKey();
        out.changeVout = plan.changeVout;
        for (const YedCoin& c : s.yedInputs) out.yedPrevs.push_back(std::make_pair(c.token.scriptPubKey, c.token.nValue));
        return out;
    }

    void AddKeys(CBasicKeyStore& ks) const
    {
        ks.AddKey(owner);
        ks.AddKey(yedKey);
    }
};

std::optional<FoundPayload> PayloadOf(const CMutableTransaction& mtx) { return FindPayload(CTransaction(mtx)); }

/**
 * v3: an ARMED state written straight into a MemoryStateView (no chain): n ELIGIBLE attestors
 * (seq i signs with hot[i], is paid at bond[i]), Attest ARMED, Snapshots[R] ACTIVE at price x with
 * every attestor seated and a block hash to seed W9, one quote tag at R for E(R). Everything the
 * wallet's shapes are judged against by ProcessTx at H = R + 3.
 */
struct Armed
{
    yellowback::Params P;
    MemoryStateView view;
    std::vector<CKey> hot, bond;
    CKey payeeKey, claimantKey, carrierKey;
    int R;
    MicroUsd x;
    uint256 blockHash;

    Armed(int n = 3, MicroUsd price = 2000000, int refHeight = 250) : P(RegtestParams(1, 0, 0, 0)), payeeKey(NewKey()), claimantKey(NewKey()), carrierKey(NewKey()), R(refHeight), x(price)
    {
        State st(view);
        for (int i = 0; i < n; i++) {
            hot.push_back(NewKey());
            bond.push_back(NewKey());
            AttestorRecord rec;
            const CPubKey h = hot[i].GetPubKey(), b = bond[i].GetPubKey();
            rec.attestorPubKey.assign(h.begin(), h.end());
            rec.bondPubKey.assign(b.begin(), b.end());
            rec.bondOutpoint = COutPoint(uint256S(strprintf("b%d", i)), 0);
            rec.bondZat = 10 * COIN;
            rec.bondLocktime = 100000;
            rec.registerHeight = 10;
            rec.status = (uint8_t)AttestorStatus::ELIGIBLE;
            rec.statusHeight = 18;
            rec.seatedSince = 20;
            st.Put(keys::Attestor((uint16_t)i), rec);
        }
        AttestorSeqRecord next;
        next.next = (uint16_t)n;
        st.Put(keys::AttestorSeq(), next);
        AttestState a;
        a.status = (uint8_t)AttestStatus::ARMED;
        a.triggerHeight = 18;
        a.armHeight = 26;
        st.Put(keys::Attest(), a);
        std::vector<unsigned char> v(32, 0x5a);
        v[0] = (unsigned char)R;
        blockHash = uint256(v);
        Snapshot S;
        S.blockHash = blockHash;
        S.activation.status = (uint8_t)ActivationStatus::ACTIVE;
        S.pFast = S.pMid = S.pSlow = S.pMint = S.pClaim = x;
        S.sigmaMultBps = 10000;
        S.haltMask = 0;
        S.attest = a;
        for (int i = 0; i < n; i++) S.seated.push_back((uint16_t)i);
        st.Put(keys::Snapshot(R), S);
        TagRecord tag;
        tag.payoutKey = payeeKey.GetPubKey().GetID();
        tag.priceMicroUsd = x;
        tag.signal = true;
        st.Put(keys::Tag(R), tag);
        BOOST_REQUIRE(ArmedAt(view, P, R));
    }

    Attestation Att(int seq, MicroUsd price, int cited = -1) const
    {
        Attestation a;
        a.seq = (uint16_t)seq;
        a.priceMicroUsd = (uint32_t)price;
        a.citedHeight = (uint32_t)(cited < 0 ? R : cited);
        const uint256 msg = AttestMessage(a.seq, a.priceMicroUsd, a.citedHeight, blockHash);
        std::vector<unsigned char> der;
        BOOST_REQUIRE(hot[seq].Sign(msg, der));
        a.sig.fill(0);
        size_t pos = 3;
        for (int part = 0; part < 2; part++) {
            size_t len = der[pos++];
            size_t skip = len > 32 ? len - 32 : 0;
            std::copy(der.begin() + pos + skip, der.begin() + pos + len, a.sig.begin() + part * 32 + (32 - (len - skip)));
            pos += len + 1;
        }
        BOOST_REQUIRE(VerifyCompactSig(hot[seq].GetPubKey(), msg, a.sig));
        return a;
    }

    /** The bundle for (R, selector): every selected seq signs `price` (or prices[seq]); `extra` seqs are appended. */
    std::vector<unsigned char> BundleFor(const std::vector<unsigned char>& selector, MicroUsd price, std::map<int, MicroUsd> prices = {}, std::vector<int> extra = {}) const
    {
        Bundle b;
        for (uint16_t seq : Selected(view, P, R, selector)) {
            auto it = prices.find(seq);
            b.atts.push_back(Att(seq, it != prices.end() ? it->second : price));
        }
        for (int seq : extra) b.atts.push_back(Att(seq, price));
        return EncodeBundle(b);
    }

    CarrierRecord Carrier(const std::vector<unsigned char>& bundle, const std::vector<unsigned char>& selector, const uint256& fundingTxid) const
    {
        CarrierRecord c;
        c.outpoint = COutPoint(fundingTxid, 0);
        c.refHeight = R;
        c.selector = selector;
        c.bundle = bundle;
        c.pk = carrierKey.GetPubKey();
        c.createdHeight = R + 1;
        return c;
    }

    void AddKeys(CBasicKeyStore& ks) const
    {
        ks.AddKey(carrierKey);
        ks.AddKey(claimantKey);
        for (const CKey& k : hot) ks.AddKey(k);
        for (const CKey& k : bond) ks.AddKey(k);
    }

    /** ProcessTx over a copy of the state at H = R + 3 (the verdict of the wallet's shape). */
    TxOutcome Judge(const CMutableTransaction& mtx) const
    {
        MemoryStateView copy = view;
        State st(copy);
        return ProcessTx(st, P, CTransaction(mtx), R + 3);
    }
};

/** The wallet's transparent MINT at R with the carrier as vin[last]: collateral for `cents` at pMint = min(x, aMint). */
CMutableTransaction ArmedMint(const Armed& a, Cents cents, const std::vector<unsigned char>& bundle, const CBasicKeyStore& ks, uint32_t branchId,
                              std::optional<MicroUsd> aMint, bool withAttestFee = true, CAmount* collateralOut = nullptr, CarrierRecord* carrierOut = nullptr)
{
    const CKey owner = NewKey();
    MintShape s;
    s.cents = cents;
    s.termClass = 0;
    s.lockHeight = (uint32_t)(a.R + 48);
    s.claimHeight = s.lockHeight + a.P.grace;
    s.refHeight = a.R;
    s.owner = owner.GetPubKey();
    const MicroUsd pMint = aMint.has_value() ? std::min(a.x, aMint.value()) : a.x;
    CAmount collateral = std::max(RequiredCollateralRounded(cents, MinRatioBps(a.P.baseRatioBps[0], 10000), pMint).value(), 4 * a.P.feeMin);
    if (collateral % 1000 != 0) collateral += 1000 - collateral % 1000;
    s.collateralZat = collateral;
    s.payee = DefaultPayee(a.view, a.P, a.R, std::vector<unsigned char>(s.owner.begin(), s.owner.end()), PayeePolicy::Defaults(a.P));
    BOOST_REQUIRE(s.payee.has_value());
    s.feeZat = FeeZat(collateral, a.P.feeMin, a.P.feeBps);
    std::vector<uint16_t> sel;
    BundleVerdict v = VerifyBundleBytes(a.view, a.P, bundle, a.R, std::vector<unsigned char>(), &sel);
    if (withAttestFee && v.ok) {
        std::vector<uint16_t> A;
        for (const Attestation& att : v.C) A.push_back(att.seq);
        std::optional<uint16_t> payee = DefaultAttestPayee(a.view, a.P, a.R, std::vector<unsigned char>(), A, AttestPolicy());
        BOOST_REQUIRE(payee.has_value());
        s.attestPayee = a.bond[payee.value()].GetPubKey().GetID();
        s.attestFeeZat = AttestFeeZat(s.feeZat, a.P.attestFeeBps);
    }
    int feeVout = -1, attestFeeVout = -1;
    CMutableTransaction mtx = Shell((uint32_t)(a.R + REF_WINDOW));
    mtx.vout = MintOutputs(s, feeVout, &attestFeeVout);
    mtx.vout.push_back(CTxOut(1 * COIN, GetScriptForDestination(NewKey().GetPubKey().GetID())));   // YEC change
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("f1"), 0)));                                        // YEC funding
    const CarrierRecord c = a.Carrier(bundle, std::vector<unsigned char>(), uint256S("ca"));
    mtx.vin.push_back(CTxIn(c.outpoint));
    SignCarrierInput(mtx, 1, c, ks, branchId);
    if (collateralOut) *collateralOut = collateral;
    if (carrierOut) *carrierOut = c;
    return mtx;
}

int OpReturns(const CMutableTransaction& mtx)
{
    int n = 0;
    for (const CTxOut& o : mtx.vout) if (!o.scriptPubKey.empty() && o.scriptPubKey[0] == OP_RETURN) n++;
    return n;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(yellowback_txbuilder_tests, BasicTestingSetup)

// Rule: MINT-1 MINT-3 MINT-7 MINT-8
BOOST_AUTO_TEST_CASE(mint_layout_matches_3_5)
{
    Fixture f;
    MintShape s;
    s.cents = 100000;
    s.termClass = 0;
    s.lockHeight = f.lockHeight;
    s.claimHeight = f.claimHeight;
    s.refHeight = 250;
    s.owner = f.owner.GetPubKey();
    s.collateralZat = 251 * COIN;
    s.payee = f.payeeKey.GetPubKey().GetID();
    s.feeZat = FeeZat(s.collateralZat, f.params.feeMin, f.params.feeBps);
    int feeVout = -1;
    std::vector<CTxOut> vout = MintOutputs(s, feeVout);
    BOOST_REQUIRE_EQUAL(vout.size(), 4u);
    BOOST_CHECK_EQUAL(feeVout, 3);
    BOOST_CHECK(vout[0].scriptPubKey == P2SHScript(f.vaultScript));
    BOOST_CHECK_EQUAL(vout[0].nValue, 251 * COIN);
    BOOST_CHECK(vout[1].scriptPubKey == GetScriptForDestination(f.owner.GetPubKey().GetID()));
    BOOST_CHECK_EQUAL(vout[1].nValue, TOKEN_VALUE);
    BOOST_CHECK_EQUAL(vout[2].nValue, 0);
    BOOST_CHECK(vout[3].scriptPubKey == GetScriptForDestination(f.payeeKey.GetPubKey().GetID()));
    BOOST_CHECK_EQUAL(vout[3].nValue, s.feeZat);
    // Payload round-trip.
    CMutableTransaction mtx = Shell(290);
    mtx.vout = vout;
    std::optional<FoundPayload> fp = PayloadOf(mtx);
    BOOST_REQUIRE(fp.has_value());
    BOOST_CHECK_EQUAL(fp->opReturnIndex, 2u);
    BOOST_CHECK(fp->payload.type == PayloadType::MINT);
    BOOST_CHECK_EQUAL(fp->payload.cents, 100000u);
    BOOST_CHECK_EQUAL(fp->payload.termClass, 0);
    BOOST_CHECK_EQUAL(fp->payload.lockHeight, f.lockHeight);
    BOOST_CHECK_EQUAL(fp->payload.refHeight, 250u);
    BOOST_CHECK_EQUAL((int)fp->payload.feeVout, 3);
    BOOST_CHECK(fp->payload.ownerPubKey == f.owner.GetPubKey());
    // FEE-0: no payee => three outputs and feeVout = 0xFF.
    s.payee = std::nullopt;
    vout = MintOutputs(s, feeVout);
    BOOST_CHECK_EQUAL(vout.size(), 3u);
    BOOST_CHECK_EQUAL(feeVout, -1);
    mtx.vout = vout;
    fp = PayloadOf(mtx);
    BOOST_REQUIRE(fp.has_value());
    BOOST_CHECK_EQUAL((int)fp->payload.feeVout, (int)FEE_VOUT_NONE);
    // A lock that cannot be scripted is refused with the mint-bad-lock identifier.
    s.lockHeight = LOCKTIME_THRESHOLD;
    BOOST_CHECK_THROW(MintOutputs(s, feeVout), std::runtime_error);
}

// Rule: MINT-2 MINT-4 MINT-5 MINT-6 MINT-8
BOOST_AUTO_TEST_CASE(mint_shape_passes_the_state_machine)
{
    // The wallet's own template, evaluated by ProcessTx over a state whose reference snapshot is
    // ACTIVE with a price and one quote tag in the payee window: the verdict must be `ok`.
    Fixture f;
    MemoryStateView view;
    State st(view);
    const int R = 250;
    const MicroUsd pMint = 2000000;   // $2.00
    Snapshot S;
    S.activation.status = (uint8_t)ActivationStatus::ACTIVE;
    S.pFast = S.pMid = S.pSlow = S.pMint = S.pClaim = pMint;
    S.sigmaMultBps = 10000;
    S.haltMask = 0;
    st.Put(keys::Snapshot(R), S);
    TagRecord tag;
    tag.payoutKey = f.payeeKey.GetPubKey().GetID();
    tag.priceMicroUsd = pMint;
    tag.signal = true;
    st.Put(keys::Tag(R), tag);
    BOOST_REQUIRE_EQUAL(EligiblePayees(view, f.params, R).size(), 1u);

    MintShape s;
    s.cents = 100000;
    s.termClass = f.params.ClassForLockBlocks(48);
    BOOST_REQUIRE_EQUAL(s.termClass, 0);
    s.lockHeight = R + 48;
    s.claimHeight = s.lockHeight + f.params.grace;
    s.refHeight = R;
    s.owner = f.owner.GetPubKey();
    std::optional<CAmount> required = RequiredCollateralRounded(s.cents, MinRatioBps(f.params.baseRatioBps[0], S.sigmaMultBps), pMint);
    BOOST_REQUIRE(required.has_value());
    s.collateralZat = std::max(required.value(), 4 * f.params.feeMin);
    s.payee = DefaultPayee(view, f.params, R, std::vector<unsigned char>(s.owner.begin(), s.owner.end()), PayeePolicy::Defaults(f.params));
    BOOST_REQUIRE(s.payee.has_value());
    s.feeZat = FeeZat(s.collateralZat, f.params.feeMin, f.params.feeBps);
    int feeVout = -1;
    CMutableTransaction mtx = Shell(R + REF_WINDOW);
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("11"), 0)));
    mtx.vout = MintOutputs(s, feeVout);
    mtx.vout.push_back(CTxOut(1 * COIN, GetScriptForDestination(NewKey().GetPubKey().GetID())));   // YEC change at vout[4]
    TxOutcome o = ProcessTx(st, f.params, CTransaction(mtx), R + 3);
    BOOST_CHECK(o.relevant);
    BOOST_CHECK_EQUAL(o.log.verdict, verdict::OK);
    BOOST_CHECK_EQUAL(o.log.yedOut, 100000);
    BOOST_CHECK_EQUAL(o.log.feeZat, s.feeZat);
    BOOST_CHECK(o.log.hasPayee);
    // A collateral one zat short is VOID (bad-mint-collateral) — the wallet rounds up, never down.
    mtx.vout[0].nValue = required.value() - 1;
    MemoryStateView view2 = view;
    State st2(view2);
    o = ProcessTx(st2, f.params, CTransaction(mtx), R + 3);
    BOOST_CHECK_EQUAL(o.log.verdict, verdict::BAD_MINT_COLLATERAL);
}

// Rule: RED-1 RED-2 RED-3 TPL-2
BOOST_AUTO_TEST_CASE(redeem_layout_transparent_destination)
{
    Fixture f;
    // Debt 100000 cents paid from two YED coins of 60000 and 50000 => change 10000.
    std::vector<YedCoin> yed = { Coin(uint256S("b1"), 1, 60000, f.yedKey), Coin(uint256S("b2"), 1, 50000, f.yedKey) };
    VaultSpendShape s = f.Shape(true, true, true, true, yed, 10000);
    VaultSpendPlan plan = PlanVaultSpend(s);
    BOOST_REQUIRE_EQUAL(plan.vin.size(), 3u);
    BOOST_CHECK(plan.vin[0].prevout == f.vaultOut);
    BOOST_CHECK_EQUAL(plan.vin[0].nSequence, 0xFFFFFFFEu);
    BOOST_CHECK_EQUAL(plan.nLockTime, f.lockHeight);
    BOOST_REQUIRE_EQUAL(plan.vout.size(), 4u);           // collateral, fee, change, payload
    BOOST_CHECK_EQUAL(plan.feeVout, 1);
    BOOST_CHECK_EQUAL(plan.changeVout, 2);
    BOOST_CHECK_EQUAL(plan.burnCents, 100000);
    BOOST_CHECK_EQUAL(plan.collateralOut, f.vaultValue + 2 * TOKEN_VALUE - DEFAULT_YELLOWBACK_FEE - s.feeZat - TOKEN_VALUE);
    BOOST_CHECK_EQUAL(plan.vout[0].nValue, plan.collateralOut);
    BOOST_CHECK(plan.vout[0].scriptPubKey == s.collateralScript.value());
    BOOST_CHECK_EQUAL(plan.vout[1].nValue, s.feeZat);
    BOOST_CHECK(plan.vout[1].scriptPubKey == GetScriptForDestination(f.payeeKey.GetPubKey().GetID()));
    BOOST_CHECK_EQUAL(plan.vout[2].nValue, TOKEN_VALUE);
    BOOST_CHECK(plan.vout[2].scriptPubKey == s.changeScript);
    BuiltTx b = f.Built(s, plan);
    BOOST_CHECK_EQUAL(b.tx.nExpiryHeight, (uint32_t)(s.refHeight + REF_WINDOW));
    std::optional<FoundPayload> fp = PayloadOf(b.tx);
    BOOST_REQUIRE(fp.has_value());
    BOOST_CHECK_EQUAL(fp->opReturnIndex, 3u);
    BOOST_CHECK(fp->payload.type == PayloadType::REDEEM);
    BOOST_CHECK_EQUAL(fp->payload.refHeight, 250u);
    BOOST_CHECK_EQUAL((int)fp->payload.feeVout, 1);
    BOOST_REQUIRE_EQUAL(fp->payload.assignments.size(), 1u);
    BOOST_CHECK_EQUAL((int)fp->payload.assignments[0].vout, 2);
    BOOST_CHECK_EQUAL(fp->payload.assignments[0].cents, 10000u);
    // Without change and under FEE-0: collateral + payload only, feeVout = 0xFF, count = 0.
    VaultSpendShape s0 = f.Shape(true, true, true, false, { Coin(uint256S("b3"), 1, 100000, f.yedKey) });
    VaultSpendPlan p0 = PlanVaultSpend(s0);
    BOOST_REQUIRE_EQUAL(p0.vout.size(), 2u);
    BOOST_CHECK_EQUAL(p0.feeVout, -1);
    BOOST_CHECK_EQUAL(p0.changeVout, -1);
    BOOST_CHECK_EQUAL(p0.collateralOut, f.vaultValue + TOKEN_VALUE - DEFAULT_YELLOWBACK_FEE);
    BuiltTx b0 = f.Built(s0, p0);
    fp = PayloadOf(b0.tx);
    BOOST_REQUIRE(fp.has_value());
    BOOST_CHECK_EQUAL((int)fp->payload.feeVout, (int)FEE_VOUT_NONE);
    BOOST_CHECK(fp->payload.assignments.empty());
    // A vault that cannot cover the fees is refused.
    VaultSpendShape tiny = f.Shape(true, true, true, true, {});
    tiny.vaultValue = tiny.feeZat;
    BOOST_CHECK_THROW(PlanVaultSpend(tiny), std::runtime_error);
}

// Rule: RED-3
BOOST_AUTO_TEST_CASE(redeem_layout_sapling_destination)
{
    // M13: YED change (if any) at vout[0], then the payload, then the fee output; feeVout names it
    // wherever it lands (vout[2] with change, vout[1] without); the collateral is the caller's note.
    Fixture f;
    std::vector<YedCoin> yed = { Coin(uint256S("b1"), 1, 110000, f.yedKey) };
    VaultSpendShape s = f.Shape(true, true, false, true, yed, 10000);
    VaultSpendPlan plan = PlanVaultSpend(s);
    BOOST_REQUIRE_EQUAL(plan.vout.size(), 3u);
    BOOST_CHECK_EQUAL(plan.changeVout, 0);
    BOOST_CHECK_EQUAL(plan.feeVout, 2);
    BOOST_CHECK_EQUAL(plan.vout[2].nValue, s.feeZat);
    BOOST_CHECK_EQUAL(plan.collateralOut, f.vaultValue + TOKEN_VALUE - DEFAULT_YELLOWBACK_FEE - s.feeZat - TOKEN_VALUE);
    BuiltTx b = f.Built(s, plan);
    std::optional<FoundPayload> fp = PayloadOf(b.tx);
    BOOST_REQUIRE(fp.has_value());
    BOOST_CHECK_EQUAL(fp->opReturnIndex, 1u);
    BOOST_CHECK_EQUAL((int)fp->payload.feeVout, 2);
    BOOST_CHECK_EQUAL((int)fp->payload.assignments[0].vout, 0);
    // Without change: payload at vout[0], fee at vout[1].
    VaultSpendShape s1 = f.Shape(true, true, false, true, { Coin(uint256S("b2"), 1, 100000, f.yedKey) });
    VaultSpendPlan p1 = PlanVaultSpend(s1);
    BOOST_REQUIRE_EQUAL(p1.vout.size(), 2u);
    BOOST_CHECK_EQUAL(p1.feeVout, 1);
    BOOST_CHECK_EQUAL(p1.changeVout, -1);
    BuiltTx b1 = f.Built(s1, p1);
    fp = PayloadOf(b1.tx);
    BOOST_REQUIRE(fp.has_value());
    BOOST_CHECK_EQUAL(fp->opReturnIndex, 0u);
    BOOST_CHECK_EQUAL((int)fp->payload.feeVout, 1);
    // A release to a Sapling address has no transparent output at all.
    VaultSpendShape rel = f.Shape(true, false, false, false, {});
    VaultSpendPlan pr = PlanVaultSpend(rel);
    BOOST_CHECK(pr.vout.empty());
    BOOST_CHECK_EQUAL(pr.collateralOut, f.vaultValue - DEFAULT_YELLOWBACK_FEE);
}

// Rule: RED-4
BOOST_AUTO_TEST_CASE(claim_layout)
{
    Fixture f;
    std::vector<YedCoin> yed = { Coin(uint256S("c1"), 1, 100000, f.yedKey) };
    VaultSpendShape s = f.Shape(false, true, true, true, yed);
    VaultSpendPlan plan = PlanVaultSpend(s);
    BOOST_CHECK_EQUAL(plan.nLockTime, f.claimHeight);
    BOOST_REQUIRE_EQUAL(plan.vout.size(), 3u);           // collateral, fee, payload
    BOOST_CHECK_EQUAL(plan.feeVout, 1);
    BOOST_CHECK_EQUAL(plan.burnCents, 100000);
    BuiltTx b = f.Built(s, plan);
    CBasicKeyStore ks;
    f.AddKeys(ks);
    SignVaultSpend(b, ks, f.branchId, false);
    BOOST_CHECK_EQUAL(b.path, "claim");
    BOOST_CHECK(b.tx.vin[0].scriptSig == ClaimScriptSig(f.vaultScript));
    std::optional<VaultSpendPath> path = ParseVaultSpendPath(b.tx.vin[0].scriptSig);
    BOOST_REQUIRE(path.has_value());
    BOOST_CHECK(!path->ownerPath);
    BOOST_CHECK_EQUAL(path->pushes, 2u);
    // The claim path verifies at claimHeight with no signature; the YED input is signed.
    ScriptError err;
    BOOST_CHECK_MESSAGE(Verify(b.tx, 0, P2SHScript(f.vaultScript), f.vaultValue, f.branchId, &err), ScriptErrorString(err));
    BOOST_CHECK(Verify(b.tx, 1, yed[0].token.scriptPubKey, TOKEN_VALUE, f.branchId, &err));
}

// Rule: RED-1 TPL-2
BOOST_AUTO_TEST_CASE(sign_vault_spend_owner_path)
{
    Fixture f;
    std::vector<YedCoin> yed = { Coin(uint256S("d1"), 1, 100000, f.yedKey) };
    VaultSpendShape s = f.Shape(true, true, true, true, yed);
    BuiltTx b = f.Built(s, PlanVaultSpend(s));
    CBasicKeyStore ks;
    f.AddKeys(ks);
    SignVaultSpend(b, ks, f.branchId, true);
    BOOST_CHECK_EQUAL(b.path, "owner");
    // Exactly the wallet's `<sig> OP_1 <script>` shape (TPL-2).
    std::optional<VaultSpendPath> path = ParseVaultSpendPath(b.tx.vin[0].scriptSig);
    BOOST_REQUIRE(path.has_value());
    BOOST_CHECK(path->ownerPath);
    BOOST_CHECK_EQUAL(path->pushes, 3u);
    BOOST_CHECK(path->selector == CScriptNum(1).getvch());
    BOOST_CHECK(path->vaultScript == f.vaultScript);
    BOOST_CHECK(b.tx.vin[0].scriptSig.IsPushOnly());
    // Verifies under the standard and the consensus flags with the right amount and branch id.
    ScriptError err;
    const CScript spk = P2SHScript(f.vaultScript);
    BOOST_CHECK_MESSAGE(Verify(b.tx, 0, spk, f.vaultValue, f.branchId, &err), ScriptErrorString(err));
    BOOST_CHECK(Verify(b.tx, 0, spk, f.vaultValue, f.branchId, &err, CONSENSUS_FLAGS));
    BOOST_CHECK(Verify(b.tx, 1, yed[0].token.scriptPubKey, TOKEN_VALUE, f.branchId, &err));
    // ZIP-243 binds the amount and the branch id (mapping §13.1): either wrong => the signature fails.
    BOOST_CHECK(!Verify(b.tx, 0, spk, f.vaultValue + 1, f.branchId, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);
    const uint32_t overwinter = NetworkUpgradeInfo[Consensus::UPGRADE_OVERWINTER].nBranchId;
    BOOST_CHECK(!Verify(b.tx, 0, spk, f.vaultValue, overwinter, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);
    // Signed under Overwinter's id it verifies there and not under Sapling's.
    BuiltTx b2 = f.Built(s, PlanVaultSpend(s));
    SignVaultSpend(b2, ks, overwinter, true);
    BOOST_CHECK(Verify(b2.tx, 0, spk, f.vaultValue, overwinter));
    BOOST_CHECK(!Verify(b2.tx, 0, spk, f.vaultValue, f.branchId));
    // The owner key must be in the keystore; the YED keys too.
    CBasicKeyStore onlyYed;
    onlyYed.AddKey(f.yedKey);
    BuiltTx b3 = f.Built(s, PlanVaultSpend(s));
    BOOST_CHECK_THROW(SignVaultSpend(b3, onlyYed, f.branchId, true), std::runtime_error);
    CBasicKeyStore onlyOwner;
    onlyOwner.AddKey(f.owner);
    BuiltTx b4 = f.Built(s, PlanVaultSpend(s));
    BOOST_CHECK_THROW(SignVaultSpend(b4, onlyOwner, f.branchId, true), std::runtime_error);
}

// Rule: RED-1 RED-2 RED-3 RED-4 MP-1
BOOST_AUTO_TEST_CASE(vault_spend_shapes_pass_the_state_machine)
{
    // The wallet's REDEEM and CLAIM, evaluated by ProcessTx over an index holding the ACTIVE
    // vault, the YED input and a snapshot at R: `ok` for both; and the SWEEP / release shapes
    // seen by the same machine: the sweep fails RED-1 (by design, L10), the release of a VOID
    // vault is an ordinary spend (K3).
    Fixture f;
    const int R = 250, H = 253;
    auto seed = [&](MemoryStateView& view, VaultStatus status, MicroUsd pClaim) {
        State st(view);
        VaultRecord v;
        // One CPubKey: begin() and end() from two GetPubKey() calls are iterators into
        // different temporaries, and the copy walks off the first key (ASan, 65-byte stack object).
        const CPubKey ownerPub = f.owner.GetPubKey();
        v.ownerPubKey.assign(ownerPub.begin(), ownerPub.end());
        v.termClass = 0;
        v.lockHeight = f.lockHeight;
        v.claimHeight = f.claimHeight;
        v.collateralZat = f.vaultValue;
        v.mintedCents = 10000;   // $100 against 5 YEC
        v.mintHeight = 200;
        v.refHeight = 197;
        v.status = (uint8_t)status;
        st.Put(keys::Vault(f.vaultOut), v);
        TokenRecord t;
        t.cents = 10000;
        t.nValue = TOKEN_VALUE;
        t.scriptPubKey = GetScriptForDestination(f.yedKey.GetPubKey().GetID());
        t.height = 210;
        st.Put(keys::Token(COutPoint(uint256S("e1"), 1)), t);
        Snapshot S;
        S.activation.status = (uint8_t)ActivationStatus::ACTIVE;
        S.pFast = S.pMid = S.pSlow = S.pMint = S.pClaim = pClaim;
        st.Put(keys::Snapshot(R), S);
        TagRecord tag;
        tag.payoutKey = f.payeeKey.GetPubKey().GetID();
        tag.priceMicroUsd = pClaim;
        st.Put(keys::Tag(R), tag);
        Totals totals;
        totals.supplyCents = 10000;
        totals.collateralZat = f.vaultValue;
        totals.activeVaults = 1;
        st.Put(keys::Totals(), totals);
    };
    std::vector<YedCoin> yed = { Coin(uint256S("e1"), 1, 10000, f.yedKey) };
    CBasicKeyStore ks;
    f.AddKeys(ks);

    // REDEEM (owner path): ok, vault CLOSED, burn = the debt, fee recorded.
    {
        MemoryStateView view;
        seed(view, VaultStatus::ACTIVE, 100000000);   // $100/YEC: 5 YEC = $500 >= $110
        State st(view);
        VaultSpendShape s = f.Shape(true, true, true, true, yed);
        BuiltTx b = f.Built(s, PlanVaultSpend(s));
        SignVaultSpend(b, ks, f.branchId, true);
        TxOutcome o = ProcessTx(st, f.params, CTransaction(b.tx), H);
        BOOST_CHECK(o.vaultSpend);
        BOOST_CHECK(!o.redFailed);
        BOOST_CHECK_EQUAL(o.log.verdict, verdict::OK);
        BOOST_CHECK_EQUAL(o.log.path, "owner");
        BOOST_CHECK_EQUAL(o.log.burned, 10000);
        BOOST_CHECK_EQUAL(o.log.feeZat, s.feeZat);
        BOOST_CHECK(st.GetVault(f.vaultOut)->Status() == VaultStatus::CLOSED);
        BOOST_CHECK(!st.GetVault(f.vaultOut)->unbacked);
    }
    // CLAIM at an underwater price ($2: 5 YEC = $10 < $110): ok, CLAIMED.
    {
        MemoryStateView view;
        seed(view, VaultStatus::ACTIVE, 2000000);
        State st(view);
        VaultSpendShape s = f.Shape(false, true, true, true, yed);
        BuiltTx b = f.Built(s, PlanVaultSpend(s));
        SignVaultSpend(b, ks, f.branchId, false);
        TxOutcome o = ProcessTx(st, f.params, CTransaction(b.tx), H);
        BOOST_CHECK_EQUAL(o.log.verdict, verdict::OK);
        BOOST_CHECK_EQUAL(o.log.path, "claim");
        BOOST_CHECK(st.GetVault(f.vaultOut)->Status() == VaultStatus::CLAIMED);
    }
    // CLAIM at a healthy price: RED-4 fails (what yed_claim's claim-not-underwater gate prevents).
    {
        MemoryStateView view;
        seed(view, VaultStatus::ACTIVE, 100000000);   // $100/YEC: 5 YEC = $500 >= $110
        State st(view);
        VaultSpendShape s = f.Shape(false, true, true, true, yed);
        BuiltTx b = f.Built(s, PlanVaultSpend(s));
        SignVaultSpend(b, ks, f.branchId, false);
        TxOutcome o = ProcessTx(st, f.params, CTransaction(b.tx), H);
        BOOST_CHECK(o.redFailed);
        BOOST_CHECK_EQUAL(o.log.verdict, verdict::VAULT_CLAIM_NOT_UNDERWATER);
    }
    // SWEEP of an ACTIVE vault: no payload => fails RED-1 by design; the vault closes unbacked.
    {
        MemoryStateView view;
        seed(view, VaultStatus::ACTIVE, 100000000);   // $100/YEC: 5 YEC = $500 >= $110
        State st(view);
        VaultSpendShape s = f.Shape(true, false, true, false, {});
        BuiltTx b = f.Built(s, PlanVaultSpend(s));
        SignVaultSpend(b, ks, f.branchId, true);
        TxOutcome o = ProcessTx(st, f.params, CTransaction(b.tx), H);
        BOOST_CHECK(o.redFailed);
        BOOST_CHECK_EQUAL(o.log.verdict, verdict::VAULT_SPEND_MALFORMED);
        BOOST_CHECK(st.GetVault(f.vaultOut)->Status() == VaultStatus::CLOSED);
        BOOST_CHECK(st.GetVault(f.vaultOut)->unbacked);
        BOOST_CHECK_EQUAL(st.GetTotals().unbackedCents, 10000);
    }
    // VOID release: the same shape on a VOID vault is an ordinary spend (K3): closed, not unbacked, nothing burned.
    {
        MemoryStateView view;
        seed(view, VaultStatus::VOID, 100000000);
        State st(view);
        VaultSpendShape s = f.Shape(true, false, true, false, {});
        BuiltTx b = f.Built(s, PlanVaultSpend(s));
        SignVaultSpend(b, ks, f.branchId, true);
        TxOutcome o = ProcessTx(st, f.params, CTransaction(b.tx), H);
        BOOST_CHECK(!o.vaultSpend);
        BOOST_CHECK(!o.redFailed);
        BOOST_CHECK(st.GetVault(f.vaultOut)->Status() == VaultStatus::CLOSED);
        BOOST_CHECK(!st.GetVault(f.vaultOut)->unbacked);
        BOOST_CHECK_EQUAL(st.GetVault(f.vaultOut)->burnedCents, 0);
    }
}

// Rule: RED-1
BOOST_AUTO_TEST_CASE(void_release_has_no_payload_and_no_fee)
{
    // L14: the VOID release is the owner-path spend with one output, no OP_RETURN, no fee output,
    // nLockTime = lockHeight, nSequence non-final, burnedCents = 0.
    Fixture f;
    VaultSpendShape s = f.Shape(true, false, true, true, {});   // a payee is ignored without a payload
    VaultSpendPlan plan = PlanVaultSpend(s);
    BOOST_REQUIRE_EQUAL(plan.vin.size(), 1u);
    BOOST_CHECK_EQUAL(plan.vin[0].nSequence, 0xFFFFFFFEu);
    BOOST_CHECK_EQUAL(plan.nLockTime, f.lockHeight);
    BOOST_REQUIRE_EQUAL(plan.vout.size(), 1u);
    BOOST_CHECK_EQUAL(plan.feeVout, -1);
    BOOST_CHECK_EQUAL(plan.changeVout, -1);
    BOOST_CHECK_EQUAL(plan.burnCents, 0);
    BOOST_CHECK_EQUAL(plan.collateralOut, f.vaultValue - DEFAULT_YELLOWBACK_FEE);
    BuiltTx b = f.Built(s, plan);
    BOOST_CHECK_EQUAL(OpReturns(b.tx), 0);
    BOOST_CHECK(!PayloadOf(b.tx).has_value());
    CBasicKeyStore ks;
    f.AddKeys(ks);
    SignVaultSpend(b, ks, f.branchId, true);
    BOOST_CHECK(b.ownYedOutputs.empty());
    ScriptError err;
    BOOST_CHECK_MESSAGE(Verify(b.tx, 0, P2SHScript(f.vaultScript), f.vaultValue, f.branchId, &err), ScriptErrorString(err));
}

// Rule: RED-1 MP-1
BOOST_AUTO_TEST_CASE(sweep_has_no_burn_no_fee_no_payload)
{
    // L10: the SWEEP is the same shape as the release on an ACTIVE vault: no YED input, no fee,
    // no payload; it fails RED-1 on purpose and is admitted only under abandonment (L13).
    Fixture f;
    VaultSpendShape s = f.Shape(true, false, true, true, {});
    VaultSpendPlan plan = PlanVaultSpend(s);
    BOOST_CHECK_EQUAL(plan.vin.size(), 1u);
    BOOST_CHECK_EQUAL(plan.vout.size(), 1u);
    BOOST_CHECK_EQUAL(plan.feeVout, -1);
    BOOST_CHECK_EQUAL(plan.burnCents, 0);
    BuiltTx b = f.Built(s, plan);
    BOOST_CHECK_EQUAL(OpReturns(b.tx), 0);
    for (const CTxOut& o : b.tx.vout) BOOST_CHECK(o.scriptPubKey != GetScriptForDestination(f.payeeKey.GetPubKey().GetID()));
    CBasicKeyStore ks;
    f.AddKeys(ks);
    SignVaultSpend(b, ks, f.branchId, true);
    BOOST_CHECK(Verify(b.tx, 0, P2SHScript(f.vaultScript), f.vaultValue, f.branchId));
    BOOST_CHECK(Verify(b.tx, 0, P2SHScript(f.vaultScript), f.vaultValue, f.branchId, nullptr, CONSENSUS_FLAGS));
}

// ---------------------------------------------------------------- v3 (plan §3.4, §3.5, §4.6)

// Rule: MINT-8 AFEE-0 AFEE-1
BOOST_AUTO_TEST_CASE(v3_mint_layout_places_the_attestor_fee_after_the_pool_fee)
{
    Fixture f;
    MintShape s;
    s.cents = 100000;
    s.termClass = 0;
    s.lockHeight = f.lockHeight;
    s.claimHeight = f.claimHeight;
    s.refHeight = 250;
    s.owner = f.owner.GetPubKey();
    s.collateralZat = 251 * COIN;
    s.payee = f.payeeKey.GetPubKey().GetID();
    s.feeZat = FeeZat(s.collateralZat, f.params.feeMin, f.params.feeBps);
    const CKey bondKey = NewKey();
    s.attestPayee = bondKey.GetPubKey().GetID();
    s.attestFeeZat = AttestFeeZat(s.feeZat, f.params.attestFeeBps);
    int feeVout = -1, attestFeeVout = -1;
    std::vector<CTxOut> vout = MintOutputs(s, feeVout, &attestFeeVout);
    BOOST_REQUIRE_EQUAL(vout.size(), 5u);
    BOOST_CHECK_EQUAL(feeVout, 3);
    BOOST_CHECK_EQUAL(attestFeeVout, 4);   // vout[4] with both fees (§3.5)
    BOOST_CHECK(vout[4].scriptPubKey == GetScriptForDestination(bondKey.GetPubKey().GetID()));
    BOOST_CHECK_EQUAL(vout[4].nValue, s.attestFeeZat);
    CMutableTransaction mtx = Shell(290);
    mtx.vout = vout;
    std::optional<FoundPayload> fp = PayloadOf(mtx);
    BOOST_REQUIRE(fp.has_value());
    BOOST_CHECK_EQUAL((int)fp->payload.feeVout, 3);
    BOOST_CHECK_EQUAL((int)fp->payload.attestFeeVout, 4);
    // FEE-0 with an attestor fee: vout[3].
    s.payee = std::nullopt;
    vout = MintOutputs(s, feeVout, &attestFeeVout);
    BOOST_REQUIRE_EQUAL(vout.size(), 4u);
    BOOST_CHECK_EQUAL(feeVout, -1);
    BOOST_CHECK_EQUAL(attestFeeVout, 3);
    mtx.vout = vout;
    fp = PayloadOf(mtx);
    BOOST_REQUIRE(fp.has_value());
    BOOST_CHECK_EQUAL((int)fp->payload.feeVout, (int)FEE_VOUT_NONE);
    BOOST_CHECK_EQUAL((int)fp->payload.attestFeeVout, 3);
    // AFEE-0: no attestor payee => the v2 shape, attestFeeVout = 0xFF.
    s.attestPayee = std::nullopt;
    vout = MintOutputs(s, feeVout, &attestFeeVout);
    BOOST_CHECK_EQUAL(vout.size(), 3u);
    BOOST_CHECK_EQUAL(attestFeeVout, -1);
    mtx.vout = vout;
    BOOST_CHECK_EQUAL((int)PayloadOf(mtx)->payload.attestFeeVout, (int)FEE_VOUT_NONE);
}

// Rule: RED-3 RED-5 AFEE-1
BOOST_AUTO_TEST_CASE(v3_claim_layout_attestor_fee_and_residual)
{
    Fixture f;
    const CKey bondKey = NewKey();
    std::vector<YedCoin> yed = { Coin(uint256S("01"), 0, 100000, f.yedKey), Coin(uint256S("02"), 0, 100, f.yedKey) };
    // Transparent destination: collateral, fee, change, attestor fee, residual, payload.
    VaultSpendShape s = f.Shape(false, true, true, true, yed, 100);
    s.attestPayee = bondKey.GetPubKey().GetID();
    s.attestFeeZat = AttestFeeZat(s.feeZat, f.params.attestFeeBps);
    s.residualZat = 2 * COIN;
    s.ownerPubKey = f.owner.GetPubKey();
    s.carrierValue = CARRIER_VALUE;
    VaultSpendPlan plan = PlanVaultSpend(s);
    BOOST_REQUIRE_EQUAL(plan.vout.size(), 6u);
    BOOST_CHECK_EQUAL(plan.feeVout, 1);
    BOOST_CHECK_EQUAL(plan.changeVout, 2);
    BOOST_CHECK_EQUAL(plan.attestFeeVout, 3);
    BOOST_CHECK_EQUAL(plan.residualVout, 4);
    BOOST_CHECK(plan.vout[3].scriptPubKey == GetScriptForDestination(bondKey.GetPubKey().GetID()));
    BOOST_CHECK_EQUAL(plan.vout[3].nValue, s.attestFeeZat);
    BOOST_CHECK(plan.vout[4].scriptPubKey == GetScriptForDestination(f.owner.GetPubKey().GetID()));
    BOOST_CHECK_EQUAL(plan.vout[4].nValue, 2 * COIN);
    BOOST_CHECK_EQUAL(plan.collateralOut, f.vaultValue + CARRIER_VALUE + 2 * TOKEN_VALUE - DEFAULT_YELLOWBACK_FEE - s.feeZat - s.attestFeeZat - 2 * COIN - TOKEN_VALUE);
    CMutableTransaction mtx = Shell(290);
    mtx.vout = plan.vout;
    std::optional<FoundPayload> fp = PayloadOf(mtx);
    BOOST_REQUIRE(fp.has_value());
    BOOST_CHECK_EQUAL(fp->opReturnIndex, 5u);
    BOOST_CHECK_EQUAL((int)fp->payload.feeVout, 1);
    BOOST_CHECK_EQUAL((int)fp->payload.attestFeeVout, 3);
    BOOST_REQUIRE_EQUAL(fp->payload.assignments.size(), 1u);
    BOOST_CHECK_EQUAL((int)fp->payload.assignments[0].vout, 2);
    // FEE-0 and no change: the attestor fee may not sit at vout[1] (AFEE-1), so the payload takes it.
    VaultSpendShape s0 = f.Shape(false, true, true, false, { yed[0] }, 0);
    s0.attestPayee = s.attestPayee;
    s0.attestFeeZat = s.attestFeeZat;
    s0.residualZat = 2 * COIN;
    s0.ownerPubKey = f.owner.GetPubKey();
    s0.carrierValue = CARRIER_VALUE;
    plan = PlanVaultSpend(s0);
    BOOST_REQUIRE_EQUAL(plan.vout.size(), 4u);
    BOOST_CHECK_EQUAL(plan.attestFeeVout, 2);
    BOOST_CHECK_EQUAL(plan.residualVout, 3);
    mtx.vout = plan.vout;
    fp = PayloadOf(mtx);
    BOOST_REQUIRE(fp.has_value());
    BOOST_CHECK_EQUAL(fp->opReturnIndex, 1u);
    BOOST_CHECK_EQUAL((int)fp->payload.attestFeeVout, 2);
    // Sapling destination (S11): change, payload, fee, attestor fee, residual — all transparent.
    VaultSpendShape sz = f.Shape(false, true, false, true, yed, 100);
    sz.attestPayee = s.attestPayee;
    sz.attestFeeZat = s.attestFeeZat;
    sz.residualZat = 2 * COIN;
    sz.ownerPubKey = f.owner.GetPubKey();
    sz.carrierValue = CARRIER_VALUE;
    plan = PlanVaultSpend(sz);
    BOOST_REQUIRE_EQUAL(plan.vout.size(), 5u);
    BOOST_CHECK_EQUAL(plan.changeVout, 0);
    BOOST_CHECK_EQUAL(plan.feeVout, 2);
    BOOST_CHECK_EQUAL(plan.attestFeeVout, 3);
    BOOST_CHECK_EQUAL(plan.residualVout, 4);
    mtx.vout = plan.vout;
    fp = PayloadOf(mtx);
    BOOST_REQUIRE(fp.has_value());
    BOOST_CHECK_EQUAL(fp->opReturnIndex, 1u);
    BOOST_CHECK_EQUAL((int)fp->payload.feeVout, 2);
    BOOST_CHECK_EQUAL((int)fp->payload.attestFeeVout, 3);
    // The v2 shape is untouched when nothing v3 is set (AFEE-0, no residual).
    plan = PlanVaultSpend(f.Shape(false, true, true, true, yed, 100));
    BOOST_CHECK_EQUAL(plan.vout.size(), 4u);
    BOOST_CHECK_EQUAL(plan.attestFeeVout, -1);
    BOOST_CHECK_EQUAL(plan.residualVout, -1);
    mtx.vout = plan.vout;
    BOOST_CHECK_EQUAL((int)PayloadOf(mtx)->payload.attestFeeVout, (int)FEE_VOUT_NONE);
}

// Rule: BUNDLE-1
BOOST_AUTO_TEST_CASE(v3_carrier_scriptsig_verifies_under_standard_flags)
{
    Armed a;
    CBasicKeyStore ks;
    a.AddKeys(ks);
    const uint32_t branchId = NetworkUpgradeInfo[Consensus::UPGRADE_SAPLING].nBranchId;
    const std::vector<unsigned char> bundle = a.BundleFor(std::vector<unsigned char>(), a.x);
    const CarrierRecord c = a.Carrier(bundle, std::vector<unsigned char>(), uint256S("ca"));
    const CTxOut funding = CarrierOutput(c.pk, c.bundle, CARRIER_VALUE);
    BOOST_CHECK(funding.scriptPubKey.IsPayToScriptHash());
    CMutableTransaction mtx = Shell((uint32_t)(a.R + REF_WINDOW));
    mtx.vin.push_back(CTxIn(c.outpoint));
    mtx.vout.push_back(CTxOut(CARRIER_VALUE - 1000, GetScriptForDestination(NewKey().GetPubKey().GetID())));
    SignCarrierInput(mtx, 0, c, ks, branchId);
    std::optional<CarrierSpend> spend = ParseCarrierScriptSig(mtx.vin[0].scriptSig);
    BOOST_REQUIRE(spend.has_value());
    BOOST_CHECK(spend->bundle == bundle);
    BOOST_CHECK(spend->pk == c.pk);
    ScriptError err;
    BOOST_CHECK_MESSAGE(Verify(mtx, 0, funding.scriptPubKey, CARRIER_VALUE, branchId, &err), ScriptErrorString(err));
    BOOST_CHECK(Verify(mtx, 0, funding.scriptPubKey, CARRIER_VALUE, branchId, &err, CONSENSUS_FLAGS));
    // The wrong amount or branch id fails (ZIP-243 binds both).
    BOOST_CHECK(!Verify(mtx, 0, funding.scriptPubKey, CARRIER_VALUE + 1, branchId));
    BOOST_CHECK(!Verify(mtx, 0, funding.scriptPubKey, CARRIER_VALUE, branchId + 1));
    // A substituted bundle push fails the hash check (R2): the redeem script commits to SHA256(bundle).
    Bundle other;
    other.atts.push_back(a.Att(0, a.x + 1));
    mtx.vin[0].scriptSig = CarrierScriptSig(EncodeBundle(other), spend->sig, spend->carrierScript);
    BOOST_CHECK(!Verify(mtx, 0, funding.scriptPubKey, CARRIER_VALUE, branchId, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EQUALVERIFY);
    // ExtractBundle sees the same bytes the script commits to.
    SignCarrierInput(mtx, 0, c, ks, branchId);
    auto ex = ExtractBundle(CTransaction(mtx), BundleCarrier::SCRIPTSIG, false, std::vector<unsigned char>());
    BOOST_REQUIRE(ex.has_value());
    BOOST_CHECK(ex->first == bundle);
}

// Rule: REG-A1
BOOST_AUTO_TEST_CASE(v3_bond_input_signs_under_cltv)
{
    CBasicKeyStore ks;
    const CKey bondKey = NewKey();
    ks.AddKey(bondKey);
    const uint32_t branchId = NetworkUpgradeInfo[Consensus::UPGRADE_SAPLING].nBranchId;
    const uint32_t locktime = 500;
    const CScript bond = BondScript(bondKey.GetPubKey(), locktime);
    const CScript spk = P2SHScript(bond);
    CMutableTransaction mtx = Shell(600);
    mtx.nLockTime = locktime;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("b0"), 0), CScript(), 0xFFFFFFFE));
    mtx.vout.push_back(CTxOut(10 * COIN - 1000, GetScriptForDestination(NewKey().GetPubKey().GetID())));
    SignBondInput(mtx, 0, bondKey.GetPubKey(), locktime, 10 * COIN, ks, branchId);
    ScriptError err;
    BOOST_CHECK_MESSAGE(Verify(mtx, 0, spk, 10 * COIN, branchId, &err), ScriptErrorString(err));
    // Before the locktime CLTV fails; with the wrong value the signature fails.
    mtx.nLockTime = locktime - 1;
    BOOST_CHECK(!Verify(mtx, 0, spk, 10 * COIN, branchId, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    mtx.nLockTime = locktime;
    BOOST_CHECK(!Verify(mtx, 0, spk, 10 * COIN + 1, branchId));
    // The bond key is not a solvable script: the wallet never selects the bond as plain YEC (R6).
    BOOST_CHECK_EQUAL((int)::IsMine(ks, spk), (int)ISMINE_NO);
}

// Rule: MINT-5 MINT-9 MINT-10 AFEE-1 PRICE-2
BOOST_AUTO_TEST_CASE(v3_armed_mint_passes_and_the_dry_run_names_the_rule)
{
    Armed a;
    CBasicKeyStore ks;
    a.AddKeys(ks);
    const uint32_t branchId = NetworkUpgradeInfo[Consensus::UPGRADE_SAPLING].nBranchId;
    const std::vector<unsigned char> none;
    const std::vector<uint16_t> selected = Selected(a.view, a.P, a.R, none);
    BOOST_REQUIRE_EQUAL(selected.size(), 3u);   // M_SELECT + K_SLACK = 3 of 3 seated

    // The wallet's shape with the attestors at $1.90 against the pools' $2.00: pMint = aMint (source "a").
    const MicroUsd aPrice = 1900000;
    std::vector<unsigned char> bundle = a.BundleFor(none, aPrice);
    std::vector<uint16_t> sel;
    BundleVerdict v = VerifyBundleBytes(a.view, a.P, bundle, a.R, none, &sel);
    BOOST_REQUIRE_MESSAGE(v.ok, v.reason);
    BOOST_REQUIRE(v.aMint.has_value());
    BOOST_CHECK_EQUAL(v.aMint.value(), aPrice);
    CAmount collateral = 0;
    CMutableTransaction mtx = ArmedMint(a, 100000, bundle, ks, branchId, v.aMint, true, &collateral);
    TxOutcome o = a.Judge(mtx);
    BOOST_CHECK_EQUAL(o.log.verdict, verdict::OK);
    BOOST_CHECK_EQUAL(o.log.bundleSeqs.size(), 3u);
    BOOST_CHECK_EQUAL(o.log.aMint, aPrice);
    BOOST_CHECK_EQUAL(o.log.attestFeeZat, AttestFeeZat(FeeZat(collateral, a.P.feeMin, a.P.feeBps), a.P.attestFeeBps));
    BOOST_CHECK(o.log.hasAttestPayee);
    // The same collateral sized at xMint alone would be short under the combined pMint (MINT-5).
    {
        MemoryStateView copy = a.view;
        State st(copy);
        std::optional<TxLogRecord> dry = DryRun(copy, a.P, CTransaction(mtx), a.R + 3);
        BOOST_REQUIRE(dry.has_value());
        BOOST_CHECK_EQUAL(dry->verdict, verdict::OK);
    }
    CMutableTransaction shortMint = ArmedMint(a, 100000, bundle, ks, branchId, std::nullopt /* sized at x */);
    BOOST_CHECK_EQUAL(DryRun(a.view, a.P, CTransaction(shortMint), a.R + 3)->verdict, verdict::BAD_MINT_COLLATERAL);

    // mint9-*: a bundle carrying a seq outside selected(R, "") (the state has three; sign as none of them differently: drop one, add a stale one).
    Bundle bad;
    bad.atts.push_back(a.Att(selected[0], aPrice));
    bad.atts.push_back(a.Att(selected[1], aPrice, a.R - a.P.attestMaxAge));   // stale: citedHeight <= R - ATTEST_MAX_AGE
    CMutableTransaction stale = ArmedMint(a, 100000, EncodeBundle(bad), ks, branchId, aPrice);
    std::optional<TxLogRecord> dry = DryRun(a.view, a.P, CTransaction(stale), a.R + 3);
    BOOST_REQUIRE(dry.has_value());
    BOOST_CHECK_EQUAL(dry->verdict, std::string(verdict::MINT9_BUNDLE_PREFIX) + "stale");
    // mint9-no-bundle: no carrier input at all while armed.
    CMutableTransaction noCarrier = mtx;
    noCarrier.vin.pop_back();
    BOOST_CHECK_EQUAL(DryRun(a.view, a.P, CTransaction(noCarrier), a.R + 3)->verdict, verdict::MINT9_NO_BUNDLE);
    // mint10-diverged: attestors at 2x the pools.
    const MicroUsd far = 4000000;
    CMutableTransaction diverged = ArmedMint(a, 100000, a.BundleFor(none, far), ks, branchId, far);
    BOOST_CHECK_EQUAL(DryRun(a.view, a.P, CTransaction(diverged), a.R + 3)->verdict, verdict::MINT10_DIVERGED);
    // afee1-fee: the attestor fee output missing while A is non-empty.
    CMutableTransaction noAfee = ArmedMint(a, 100000, bundle, ks, branchId, v.aMint, false);
    BOOST_CHECK_EQUAL(DryRun(a.view, a.P, CTransaction(noAfee), a.R + 3)->verdict, verdict::AFEE1_FEE);
    // The wallet's preflight arithmetic: BundleVerdict::C is A, and AFEE-W picks from it.
    std::vector<uint16_t> A;
    for (const Attestation& att : v.C) A.push_back(att.seq);
    std::optional<uint16_t> payee = DefaultAttestPayee(a.view, a.P, a.R, none, A, AttestPolicy());
    BOOST_REQUIRE(payee.has_value());
    BOOST_CHECK(std::find(A.begin(), A.end(), payee.value()) != A.end());
    AttestPolicy pref;
    pref.preferred = A.back();
    BOOST_CHECK_EQUAL(DefaultAttestPayee(a.view, a.P, a.R, none, A, pref).value(), A.back());
}

// Rule: RED-1 RED-3 RED-4 RED-5 AFEE-1 MP-1
BOOST_AUTO_TEST_CASE(v3_armed_claim_pays_the_residual_under_the_emergency_clause)
{
    // Pools at $2.20 (not underwater at 110 %), attestors at $2.00: pClaim = 2.20 (clause (a) false),
    // pEmerg = 2.00 and a persisted notice open clause (b) (R1: margin 100 %, a residual is due).
    Armed a(3, 2200000);
    CBasicKeyStore ks;
    a.AddKeys(ks);
    const CKey owner = NewKey();
    const uint32_t branchId = NetworkUpgradeInfo[Consensus::UPGRADE_SAPLING].nBranchId;
    const uint256 mintTxid = uint256S("aa");
    const COutPoint vaultOut(mintTxid, 0);
    const std::vector<unsigned char> selector = OutPointSelector(vaultOut);
    State st(a.view);
    VaultRecord vault;
    const CPubKey ownerPk = owner.GetPubKey();
    vault.ownerPubKey.assign(ownerPk.begin(), ownerPk.end());
    vault.termClass = 0;
    vault.lockHeight = a.R - 30;
    vault.claimHeight = a.R - 6;
    vault.collateralZat = 50 * COIN;
    vault.mintedCents = 10000;
    vault.mintHeight = a.R - 80;
    vault.refHeight = a.R - 82;
    vault.status = (uint8_t)VaultStatus::ACTIVE;
    st.Put(keys::Vault(vaultOut), vault);
    YedCoin coin = Coin(uint256S("01"), 0, 10000, a.claimantKey);
    st.Put(keys::Token(coin.outpoint), coin.token);
    NoticeRecord notice;
    notice.height = a.R - 3;
    notice.refHeight = a.R - a.P.emergencyPersist;
    notice.pEmerg = 2000000;
    st.Put(keys::Notice(vaultOut), notice);

    const MicroUsd aPrice = 2000000;
    const std::vector<unsigned char> bundle = a.BundleFor(selector, aPrice);
    std::vector<uint16_t> sel;
    BundleVerdict v = VerifyBundleBytes(a.view, a.P, bundle, a.R, selector, &sel);
    BOOST_REQUIRE_MESSAGE(v.ok, v.reason);
    BOOST_CHECK(!IsUnderwater(vault.collateralZat, std::max(a.x, aPrice), vault.mintedCents, a.P.claimThresholdBps));   // (a) false
    BOOST_CHECK(IsUnderwater(vault.collateralZat, std::min(a.x, aPrice), vault.mintedCents, a.P.emergencyRatioBps));    // (b) true
    const MicroUsd pClaim = std::max(a.x, aPrice);
    const CAmount residual = ResidualZat(vault.collateralZat, ClaimantMaxZat(vault.mintedCents, 10000, pClaim));
    BOOST_REQUIRE(residual >= a.P.residualMinZat);

    std::vector<uint16_t> A;
    for (const Attestation& att : v.C) A.push_back(att.seq);
    const uint16_t attestPayee = DefaultAttestPayee(a.view, a.P, a.R, selector, A, AttestPolicy()).value();
    VaultSpendShape s;
    s.vaultOut = vaultOut;
    s.vaultScript = VaultScript((uint32_t)vault.lockHeight, ownerPk, (uint32_t)vault.claimHeight);
    s.vaultValue = vault.collateralZat;
    s.lockHeight = vault.lockHeight;
    s.claimHeight = vault.claimHeight;
    s.ownerPath = false;
    s.withPayload = true;
    s.refHeight = a.R;
    s.payee = DefaultPayee(a.view, a.P, a.R, selector, PayeePolicy::Defaults(a.P));
    BOOST_REQUIRE(s.payee.has_value());
    s.feeZat = FeeZat(vault.collateralZat, a.P.feeMin, a.P.feeBps);
    s.yedInputs = { coin };
    s.collateralScript = GetScriptForDestination(NewKey().GetPubKey().GetID());
    s.networkFee = DEFAULT_YELLOWBACK_FEE;
    s.attestPayee = a.bond[attestPayee].GetPubKey().GetID();
    s.attestFeeZat = AttestFeeZat(s.feeZat, a.P.attestFeeBps);
    s.residualZat = residual;
    s.ownerPubKey = ownerPk;
    s.carrierValue = CARRIER_VALUE;
    auto build = [&](const VaultSpendShape& shape) {
        VaultSpendPlan plan = PlanVaultSpend(shape);
        BuiltTx b;
        b.kind = BuiltKind::CLAIM;
        b.tx = Shell((uint32_t)(a.R + REF_WINDOW));
        b.tx.nLockTime = plan.nLockTime;
        b.tx.vin = plan.vin;
        b.tx.vout = plan.vout;
        b.vaultScript = shape.vaultScript;
        b.vaultValue = shape.vaultValue;
        b.ownerPubKey = ownerPk;
        b.changeVout = plan.changeVout;
        b.yedPrevs.push_back(std::make_pair(coin.token.scriptPubKey, coin.token.nValue));
        b.carrier = a.Carrier(bundle, selector, uint256S("cb"));
        b.tx.vin.push_back(CTxIn(b.carrier->outpoint));
        b.carrierVin = (int)b.tx.vin.size() - 1;
        SignVaultSpend(b, ks, branchId, false);
        return b;
    };
    BuiltTx b = build(s);
    BOOST_CHECK_EQUAL(b.carrierVin, 2);   // never vin[0] (§3.5)
    std::optional<TxLogRecord> dry = DryRun(a.view, a.P, CTransaction(b.tx), a.R + 3);
    BOOST_REQUIRE(dry.has_value());
    BOOST_CHECK_EQUAL(dry->verdict, verdict::OK);
    BOOST_CHECK_EQUAL(dry->claimPath, "b");
    BOOST_CHECK_EQUAL(dry->residualZat, residual);
    BOOST_CHECK_EQUAL(dry->attestFeeZat, s.attestFeeZat);
    BOOST_CHECK_EQUAL(dry->aClaim, aPrice);
    // The carrier input verifies under the standard flags with its funding output.
    ScriptError err;
    BOOST_CHECK_MESSAGE(Verify(b.tx, 2, CarrierOutput(a.carrierKey.GetPubKey(), bundle, CARRIER_VALUE).scriptPubKey, CARRIER_VALUE, branchId, &err), ScriptErrorString(err));
    // red5-residual: the same claim without the residual output.
    VaultSpendShape noResidual = s;
    noResidual.residualZat = 0;
    BOOST_CHECK_EQUAL(DryRun(a.view, a.P, CTransaction(build(noResidual).tx), a.R + 3)->verdict, verdict::RED5_RESIDUAL);
    // afee1-fee: no attestor fee output.
    VaultSpendShape noAfee = s;
    noAfee.attestPayee = std::nullopt;
    BOOST_CHECK_EQUAL(DryRun(a.view, a.P, CTransaction(build(noAfee).tx), a.R + 3)->verdict, verdict::AFEE1_FEE);
    // red1-bundle-*: a bundle built for the empty selector is not this vault's selection (or is short of it).
    VaultSpendShape wrongSel = s;
    BuiltTx w = build(wrongSel);
    w.carrier->bundle = a.BundleFor(std::vector<unsigned char>(), aPrice);
    w.tx.vin[2].scriptSig = CScript();
    // Re-sign with the mis-selected bundle: BUNDLE-1 reads the bytes the carrier commits to.
    w.carrier->selector = selector;
    SignCarrierInput(w.tx, 2, w.carrier.value(), ks, branchId);
    std::optional<TxLogRecord> wrong = DryRun(a.view, a.P, CTransaction(w.tx), a.R + 3);
    BOOST_REQUIRE(wrong.has_value());
    const std::string prefix = verdict::RED1_BUNDLE_PREFIX;
    BOOST_CHECK_MESSAGE(wrong->verdict == verdict::OK || wrong->verdict.compare(0, prefix.size(), prefix) == 0, wrong->verdict);
    // Without a persisted notice clause (b) is false: claim-not-underwater.
    {
        MemoryStateView copy = a.view;
        State st2(copy);
        st2.EraseKey(keys::Notice(vaultOut));
        BOOST_CHECK_EQUAL(DryRun(copy, a.P, CTransaction(b.tx), a.R + 3)->verdict, verdict::VAULT_CLAIM_NOT_UNDERWATER);
    }
}

// Rule: TPL-2 NOT-1
BOOST_AUTO_TEST_CASE(v3_carrier_templates_are_standard)
{
    // The built MINT (with carrier and attestor fee), CLAIM_NOTICE and EQUIVOCATION through
    // IsStandardTx and AreInputsStandard with every prevout in a coins view (yellowback_script_tests.cpp's setup).
    RegtestActivateSapling();
    Armed a;
    CBasicKeyStore ks;
    a.AddKeys(ks);
    LOCK(cs_main);
    const uint32_t branchId = NetworkUpgradeInfo[Consensus::UPGRADE_SAPLING].nBranchId;
    const std::vector<unsigned char> none;
    const std::vector<unsigned char> bundle = a.BundleFor(none, a.x);
    const CScript userP2PKH = GetScriptForDestination(a.claimantKey.GetPubKey().GetID());
    CMutableTransaction fund;
    fund.fOverwintered = true;
    fund.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    fund.nVersion = SAPLING_TX_VERSION;
    fund.vout.push_back(CTxOut(10000 * COIN, userP2PKH));                                 // 0: YEC
    fund.vout.push_back(CarrierOutput(a.carrierKey.GetPubKey(), bundle, CARRIER_VALUE));  // 1: a carrier
    fund.vout.push_back(CarrierOutput(a.carrierKey.GetPubKey(), bundle, CARRIER_VALUE));  // 2: another
    CCoinsViewDummy dummy;
    CCoinsViewCache view(&dummy);
    view.ModifyCoins(fund.GetHash())->FromTx(fund, 1);
    const uint256 fundHash = fund.GetHash();
    auto checkStandard = [&](const CMutableTransaction& mtx, const std::string& what) {
        std::string reason;
        BOOST_CHECK_MESSAGE(IsStandardTx(CTransaction(mtx), reason, ::Params(), 1), what + ": " + reason);
        BOOST_CHECK_MESSAGE(AreInputsStandard(CTransaction(mtx), view, branchId), what + ": inputs");
    };
    CarrierRecord c1 = a.Carrier(bundle, none, fundHash);
    c1.outpoint = COutPoint(fundHash, 1);
    // MINT: YEC input, carrier last, five outputs plus change.
    CMutableTransaction mint = ArmedMint(a, 100000, bundle, ks, branchId, a.x);
    mint.vin[0] = CTxIn(COutPoint(fundHash, 0));
    mint.vin[1] = CTxIn(c1.outpoint);
    BOOST_CHECK(SignSignature(ks, userP2PKH, mint, PrecomputedTransactionData(CTransaction(mint), {}), 0, 10000 * COIN, SIGHASH_ALL, branchId));
    SignCarrierInput(mint, 1, c1, ks, branchId);
    checkStandard(mint, "MINT");
    // CLAIM_NOTICE: the carrier alone funds it (CARRIER_VALUE covers the network fee).
    CMutableTransaction notice = Shell((uint32_t)(a.R + REF_WINDOW));
    notice.vin.push_back(CTxIn(c1.outpoint));
    notice.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(Payload::ClaimNotice(COutPoint(uint256S("aa"), 0), (uint32_t)a.R)))));
    notice.vout.push_back(CTxOut(CARRIER_VALUE - 1000, userP2PKH));
    SignCarrierInput(notice, 0, c1, ks, branchId);
    checkStandard(notice, "CLAIM_NOTICE");
    BOOST_CHECK(FindPayload(CTransaction(notice)).has_value());
    // EQUIVOCATION: a carrier whose bundle is two attestations of one seq at two prices.
    Bundle two;
    two.atts = { a.Att(0, a.x), a.Att(0, a.x + 1000) };
    CarrierRecord c2 = a.Carrier(EncodeBundle(two), none, fundHash);
    c2.outpoint = COutPoint(fundHash, 2);
    CMutableTransaction fund2 = fund;
    fund2.vout[2] = CarrierOutput(a.carrierKey.GetPubKey(), c2.bundle, CARRIER_VALUE);
    view.ModifyCoins(fund.GetHash())->FromTx(fund2, 1);
    CMutableTransaction eqv = Shell((uint32_t)(a.R + REF_WINDOW));
    eqv.vin.push_back(CTxIn(c2.outpoint));
    eqv.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(Payload::Equivocation()))));
    eqv.vout.push_back(CTxOut(CARRIER_VALUE - 1000, userP2PKH));
    SignCarrierInput(eqv, 0, c2, ks, branchId);
    checkStandard(eqv, "EQUIVOCATION");
    std::optional<TxLogRecord> dry = DryRun(a.view, a.P, CTransaction(eqv), a.R + 3);
    BOOST_REQUIRE(dry.has_value());
    BOOST_CHECK(dry->Type() == TxLogType::EQUIVOCATION);
    // The sweep: two carriers into one output, each signed with its own recorded bundle.
    CMutableTransaction sweep = Shell((uint32_t)(a.R + REF_WINDOW));
    sweep.vin.push_back(CTxIn(c1.outpoint));
    sweep.vin.push_back(CTxIn(c2.outpoint));
    sweep.vout.push_back(CTxOut(2 * CARRIER_VALUE - 1000, userP2PKH));
    SignCarrierInput(sweep, 0, c1, ks, branchId);
    SignCarrierInput(sweep, 1, c2, ks, branchId);
    checkStandard(sweep, "SWEEP_CARRIERS");
    RegtestDeactivateSapling();
}

// Rule: FEE-W
BOOST_AUTO_TEST_CASE(outpoint_selector_is_the_serialised_outpoint)
{
    // The REDEEM/CLAIM selector is the 36-byte serialised vault outpoint (§3.7): txid bytes then LE index.
    COutPoint o(uint256S("0102"), 7);
    std::vector<unsigned char> sel = OutPointSelector(o);
    BOOST_REQUIRE_EQUAL(sel.size(), 36u);
    BOOST_CHECK(std::vector<unsigned char>(sel.begin(), sel.begin() + 32) == std::vector<unsigned char>(o.hash.begin(), o.hash.end()));
    BOOST_CHECK_EQUAL((int)sel[32], 7);
    BOOST_CHECK_EQUAL((int)sel[33], 0);
}

// ---------------------------------------------------------------- P-2: the network fee under ZIP-317

// P-2: a transparent MINT with three P2PKH funding inputs, the carrier, both fees and YEC change
// pays exactly the conventional fee of the signed transaction (more than the 1000-zat floor), and
// the stand-in signatures never undercount, whatever lengths the real signatures come out at.
BOOST_AUTO_TEST_CASE(p2_mint_fee_is_the_conventional_fee)
{
    Armed a;
    const uint32_t branchId = NetworkUpgradeInfo[Consensus::UPGRADE_SAPLING].nBranchId;
    const std::vector<unsigned char> bundle = a.BundleFor(std::vector<unsigned char>(), a.x);
    const CarrierRecord c = a.Carrier(bundle, std::vector<unsigned char>(), uint256S("ca"));
    for (int round = 0; round < 16; round++) {
        CBasicKeyStore ks;
        a.AddKeys(ks);
        MintShape m;
        m.cents = 100000;
        m.termClass = 0;
        m.lockHeight = (uint32_t)(a.R + 48);
        m.claimHeight = m.lockHeight + a.P.grace;
        m.refHeight = a.R;
        m.owner = NewKey().GetPubKey();
        m.collateralZat = 251 * COIN;
        m.payee = NewKey().GetPubKey().GetID();
        m.feeZat = FeeZat(m.collateralZat, a.P.feeMin, a.P.feeBps);
        m.attestPayee = a.bond[0].GetPubKey().GetID();
        m.attestFeeZat = AttestFeeZat(m.feeZat, a.P.attestFeeBps);
        int feeVout = -1, attestFeeVout = -1;
        CMutableTransaction mtx = Shell((uint32_t)(a.R + REF_WINDOW));
        mtx.vout = MintOutputs(m, feeVout, &attestFeeVout);
        mtx.vout.push_back(CTxOut(1 * COIN, GetScriptForDestination(NewKey().GetPubKey().GetID())));   // YEC change
        std::vector<CScript> funding;
        for (int i = 0; i < 3; i++) {
            const CKey k = NewKey();
            ks.AddKey(k);
            funding.push_back(GetScriptForDestination(k.GetPubKey().GetID()));
            mtx.vin.push_back(CTxIn(COutPoint(uint256S(strprintf("f%d", i)), (uint32_t)round)));
        }
        mtx.vin.push_back(CTxIn(c.outpoint));
        // The wallet's probe (Context::FeeOf): stand-ins for every input, priced before signing.
        CMutableTransaction probe = mtx;
        for (int i = 0; i < 3; i++) probe.vin[i].scriptSig = PendingP2PKHSig(funding[i], ks);
        probe.vin[3].scriptSig = PendingCarrierSig(c);
        const CAmount fee = NetworkFee(probe);
        // Signed for real.
        const PrecomputedTransactionData txdata(CTransaction(mtx), {});
        for (int i = 0; i < 3; i++) BOOST_REQUIRE(SignSignature(ks, funding[i], mtx, txdata, i, 50 * COIN, SIGHASH_ALL, branchId));
        SignCarrierInput(mtx, 3, c, ks, branchId);
        const CTransaction tx(mtx);
        BOOST_CHECK_GT(fee, DEFAULT_YELLOWBACK_FEE);
        BOOST_CHECK_EQUAL(fee, tx.GetConventionalFee());   // the six outputs set the action count
        for (size_t i = 0; i < mtx.vin.size(); i++) BOOST_CHECK_GE(probe.vin[i].scriptSig.size(), mtx.vin[i].scriptSig.size());
    }
    // The stand-in for a key the keystore does not hold counts it uncompressed.
    CBasicKeyStore empty;
    const CScript unknown = GetScriptForDestination(NewKey().GetPubKey().GetID());
    BOOST_CHECK_EQUAL(PendingP2PKHSig(unknown, empty).size(), 1 + MAX_SIG_SIZE + 1 + CPubKey::PUBLIC_KEY_SIZE);
}

// P-2: a REDEEM burning three YED coins with change and a pool fee pays exactly the conventional
// fee of the signed transaction out of the collateral; the Sapling destination counts its note
// padded to two outputs; -yellowbackfee above the conventional fee still wins.
BOOST_AUTO_TEST_CASE(p2_redeem_fee_is_the_conventional_fee)
{
    Fixture f;
    CBasicKeyStore ks;
    f.AddKeys(ks);
    std::vector<YedCoin> yed = { Coin(uint256S("e1"), 1, 40000, f.yedKey), Coin(uint256S("e2"), 1, 40000, f.yedKey), Coin(uint256S("e3"), 1, 30000, f.yedKey) };
    VaultSpendShape s = f.Shape(true, true, true, true, yed, 10000);
    VaultSpendPlan plan = PlanPricedVaultSpend(s, ks, std::nullopt);
    BOOST_CHECK_GT(s.networkFee, DEFAULT_YELLOWBACK_FEE);
    BOOST_CHECK_EQUAL(plan.collateralOut, f.vaultValue + 3 * TOKEN_VALUE - s.networkFee - s.feeZat - TOKEN_VALUE);
    BuiltTx b = f.Built(s, plan);
    SignVaultSpend(b, ks, f.branchId, true);
    const CTransaction tx(b.tx);
    BOOST_CHECK_EQUAL(s.networkFee, tx.GetConventionalFee());
    // Repricing is idempotent: the shape's own fee prices it again at the same amount.
    VaultSpendShape again = s;
    BOOST_CHECK_EQUAL(PlanPricedVaultSpend(again, ks, std::nullopt).collateralOut, plan.collateralOut);
    BOOST_CHECK_EQUAL(again.networkFee, s.networkFee);

    // Sapling destination: the transparent part plus one note, padded to two Sapling outputs.
    VaultSpendShape z = f.Shape(true, true, false, true, yed, 10000);
    VaultSpendPlan zp = PlanPricedVaultSpend(z, ks, std::nullopt);
    BuiltTx zb = f.Built(z, zp);
    SignVaultSpend(zb, ks, f.branchId, true);
    const size_t zActions = CalculateLogicalActionCount(zb.tx.vin, zb.tx.vout, 0, 0, 2, 0);
    BOOST_CHECK_EQUAL(z.networkFee, CalculateConventionalFee(zActions));
    BOOST_CHECK_EQUAL(zp.collateralOut, f.vaultValue + 3 * TOKEN_VALUE - z.networkFee - z.feeZat - TOKEN_VALUE);

    // A release (one input, one output) is at the 1000-zat floor; a higher -yellowbackfee wins.
    VaultSpendShape r = f.Shape(true, false, true, false, {});
    PlanPricedVaultSpend(r, ks, std::nullopt);
    BOOST_CHECK_EQUAL(r.networkFee, DEFAULT_YELLOWBACK_FEE);
    const CAmount saved = g_yellowbackFee;
    g_yellowbackFee = 50000;
    VaultSpendShape h = f.Shape(true, true, true, true, yed, 10000);
    h.networkFee = g_yellowbackFee;
    VaultSpendPlan hp = PlanPricedVaultSpend(h, ks, std::nullopt);
    g_yellowbackFee = saved;
    BOOST_CHECK_EQUAL(h.networkFee, 50000);
    BOOST_CHECK_EQUAL(hp.collateralOut, f.vaultValue + 3 * TOKEN_VALUE - 50000 - h.feeZat - TOKEN_VALUE);
}

BOOST_AUTO_TEST_SUITE_END()
