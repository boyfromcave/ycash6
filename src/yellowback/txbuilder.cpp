// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yellowback/txbuilder.h"

#include "chainparams.h"
#include "consensus/upgrades.h"
#include "key_io.h"
#include "main.h"
#include "txmempool.h"
#include "policy/policy.h"
#include "script/interpreter.h"
#include "script/script_error.h"
#include "script/sign.h"
#include "script/standard.h"
#include "streams.h"
#include "util/system.h"
#include "util/moneystr.h"
#include "wallet/wallet.h"
#include "yellowback/coinselect.h"
#include "yellowback/math.h"
#include "yellowback/payload.h"
#include "yellowback/policy.h"
#include "yellowback/state.h"
#include "crypto/sha256.h"
#include "zcash/Address.hpp"
#include "zcash/address/zip32.h"
#include "zip317.h"

#include <algorithm>
#include <variant>

namespace yellowback {

// ---------------------------------------------------------------- pure shapes (§3.5)

std::vector<CTxOut> MintOutputs(const MintShape& s, int& feeVout, int* attestFeeVoutOut)
{
    const CScript vault = VaultScript(s.lockHeight, s.owner, s.claimHeight);
    if (vault.empty()) throw std::runtime_error("mint-bad-lock: cannot build the vault script");
    feeVout = s.payee.has_value() ? 3 : -1;
    // v3 AFEE-1: the attestor fee after the pool fee (vout[4] with both, vout[3] under FEE-0)
    const int attestFeeVout = s.attestPayee.has_value() ? (s.payee.has_value() ? 4 : 3) : -1;
    if (attestFeeVoutOut) *attestFeeVoutOut = attestFeeVout;
    std::vector<unsigned char> payload = EncodePayload(Payload::Mint((uint8_t)s.termClass, (uint32_t)s.cents, s.lockHeight, (uint32_t)s.refHeight,
                                                                     s.owner, feeVout < 0 ? FEE_VOUT_NONE : (uint8_t)feeVout,
                                                                     attestFeeVout < 0 ? FEE_VOUT_NONE : (uint8_t)attestFeeVout));
    if (payload.empty()) throw std::runtime_error("cannot encode the mint payload");
    std::vector<CTxOut> vout;
    vout.push_back(CTxOut(s.collateralZat, P2SHScript(vault)));                        // vout[0] vault
    vout.push_back(CTxOut(TOKEN_VALUE, GetScriptForDestination(s.owner.GetID())));      // vout[1] token
    vout.push_back(CTxOut(0, PayloadScript(payload)));                                  // vout[2] payload
    if (s.payee.has_value()) vout.push_back(CTxOut(s.feeZat, GetScriptForDestination(s.payee.value())));   // vout[3] fee
    if (s.attestPayee.has_value()) vout.push_back(CTxOut(s.attestFeeZat, GetScriptForDestination(s.attestPayee.value())));   // attestor fee
    return vout;
}

VaultSpendPlan PlanVaultSpend(const VaultSpendShape& s)
{
    VaultSpendPlan plan;
    plan.nLockTime = s.ownerPath ? s.lockHeight : s.claimHeight;
    plan.vin.push_back(CTxIn(s.vaultOut, CScript(), 0xFFFFFFFE));
    CAmount yedValue = 0;
    Cents yedIn = 0;
    for (const YedCoin& c : s.yedInputs) {
        plan.vin.push_back(CTxIn(c.outpoint));
        yedValue += c.token.nValue;
        yedIn += c.token.cents;
    }
    const bool change = s.withPayload && s.changeCents > 0;
    const bool fee = s.withPayload && s.payee.has_value();
    const bool attest = s.withPayload && s.attestPayee.has_value();
    const bool residual = s.withPayload && s.residualZat > 0;
    if (residual && !s.ownerPubKey.IsValid()) throw std::runtime_error("vault-not-found: the residual needs the owner key");
    plan.collateralOut = s.vaultValue + s.carrierValue + yedValue - s.networkFee - (fee ? s.feeZat : 0) - (attest ? s.attestFeeZat : 0)
                         - (residual ? s.residualZat : 0) - (change ? TOKEN_VALUE : 0);
    if (plan.collateralOut <= 0) throw std::runtime_error("vault-value-too-small: the vault does not cover the fees");
    plan.burnCents = s.withPayload ? yedIn - s.changeCents : yedIn;

    // Slots in order; indices are fixed before the payload is encoded (feeVout / attestFeeVout / assignments).
    enum Slot { COLLATERAL, FEE, CHANGE, ATTEST, RESIDUAL, PAYLOAD };
    std::vector<Slot> order;
    if (s.collateralScript.has_value()) {
        order.push_back(COLLATERAL);
        if (!s.withPayload) {
            plan.vout.push_back(CTxOut(plan.collateralOut, s.collateralScript.value()));
            return plan;
        }
        if (fee) order.push_back(FEE);
        if (change) order.push_back(CHANGE);
        if (attest && !fee && !change) order.push_back(PAYLOAD);   // AFEE-1 excludes vout[1]: the payload takes it
        if (attest) order.push_back(ATTEST);
        if (residual) order.push_back(RESIDUAL);
        if (std::find(order.begin(), order.end(), PAYLOAD) == order.end()) order.push_back(PAYLOAD);
    } else {
        // Sapling destination (M13, S11): change, payload, fee, attestor fee, residual; the collateral is the caller's note.
        if (!s.withPayload) return plan;
        if (change) order.push_back(CHANGE);
        order.push_back(PAYLOAD);
        if (fee) order.push_back(FEE);
        if (attest && !fee && !change) {
            // The attestor fee may not sit at vout[1] (AFEE-1): the residual takes it when there is one.
            if (!residual) throw std::runtime_error("attest-fee-shape: a Sapling-paid claim with no pool fee, no YED change and no residual cannot place the attestor fee; pass a transparent destination");
            order.push_back(RESIDUAL);
            order.push_back(ATTEST);
        } else {
            if (attest) order.push_back(ATTEST);
            if (residual) order.push_back(RESIDUAL);
        }
    }
    std::vector<Assignment> assignments;
    for (size_t i = 0; i < order.size(); i++) {
        switch (order[i]) {
        case FEE: plan.feeVout = (int)i; break;
        case CHANGE: plan.changeVout = (int)i; assignments.push_back(Assignment((uint8_t)i, (uint32_t)s.changeCents)); break;
        case ATTEST: plan.attestFeeVout = (int)i; break;
        case RESIDUAL: plan.residualVout = (int)i; break;
        default: break;
        }
    }
    std::vector<unsigned char> payload = EncodePayload(Payload::Redeem((uint32_t)s.refHeight, plan.feeVout < 0 ? FEE_VOUT_NONE : (uint8_t)plan.feeVout, assignments,
                                                                       plan.attestFeeVout < 0 ? FEE_VOUT_NONE : (uint8_t)plan.attestFeeVout));
    if (payload.empty()) throw std::runtime_error("cannot encode the redeem payload");
    for (Slot slot : order) {
        switch (slot) {
        case COLLATERAL: plan.vout.push_back(CTxOut(plan.collateralOut, s.collateralScript.value())); break;
        case FEE: plan.vout.push_back(CTxOut(s.feeZat, GetScriptForDestination(s.payee.value()))); break;
        case CHANGE: plan.vout.push_back(CTxOut(TOKEN_VALUE, s.changeScript)); break;
        case ATTEST: plan.vout.push_back(CTxOut(s.attestFeeZat, GetScriptForDestination(s.attestPayee.value()))); break;
        case RESIDUAL: plan.vout.push_back(CTxOut(s.residualZat, GetScriptForDestination(s.ownerPubKey.GetID()))); break;
        case PAYLOAD: plan.vout.push_back(CTxOut(0, PayloadScript(payload))); break;
        }
    }
    return plan;
}

namespace {
/**
 * 6.20.0 (plan P-3): every sighash takes a PrecomputedTransactionData. The overlay builds Sapling v4
 * transactions only (CreateNewContextualCMutableTransaction(..., requireV4 = true)), whose ZIP-243
 * digest never reads the spent outputs (script/interpreter.cpp SetPrecomputed), so no prevout list
 * is needed. A v5 transaction would need all of them (ZIP-244); refuse it here rather than sign over
 * an incomplete precompute, so nothing is silently wrong if NU5 ever activates.
 */
PrecomputedTransactionData V4TxData(const CTransaction& tx)
{
    if (!(tx.fOverwintered && tx.nVersionGroupId == SAPLING_VERSION_GROUP_ID && tx.nVersion == SAPLING_TX_VERSION)) {
        throw std::runtime_error("Yellowback signs Sapling v4 transactions only");
    }
    return PrecomputedTransactionData(tx, std::vector<CTxOut>());
}
} // namespace

void SignVaultSpend(BuiltTx& out, const CKeyStore& keystore, uint32_t branchId, bool ownerPath)
{
    if (out.builder) throw std::runtime_error("FinishSapling must run before SignVaultSpend");
    const size_t extra = out.carrierVin >= 0 ? 2 : 1;
    if (out.tx.vin.size() != out.yedPrevs.size() + extra) throw std::runtime_error("vault spend input count mismatch");
    if (ownerPath) {
        // Owner signature: ZIP-243 over the vault script with the vault's nValue and the epoch
        // branch id (both bound by the digest, mapping §13.1), as rpc/atomicswap.cpp signs by hand.
        CKey ownerKey;
        if (!keystore.GetKey(out.ownerPubKey.GetID(), ownerKey)) throw std::runtime_error("vault-not-owned: owner key not available");
        const CTransaction txc(out.tx);
        uint256 hash = SignatureHash(out.vaultScript, txc, 0, SIGHASH_ALL, out.vaultValue, branchId, V4TxData(txc));
        valtype ownerSig;
        if (!ownerKey.Sign(hash, ownerSig)) throw std::runtime_error("owner signature failed");
        ownerSig.push_back((unsigned char)SIGHASH_ALL);
        out.tx.vin[0].scriptSig = OwnerScriptSig(ownerSig, out.vaultScript);
    } else {
        out.tx.vin[0].scriptSig = ClaimScriptSig(out.vaultScript);
    }
    for (size_t i = 0; i < out.yedPrevs.size(); i++) {
        if (!SignSignature(keystore, out.yedPrevs[i].first, out.tx, V4TxData(CTransaction(out.tx)), i + 1, out.yedPrevs[i].second, SIGHASH_ALL, branchId)) {
            throw std::runtime_error(strprintf("failed to sign YED input %u", (unsigned)i));
        }
    }
    if (out.carrierVin >= 0) SignCarrierInput(out.tx, (unsigned int)out.carrierVin, out.carrier.value(), keystore, branchId);
    out.path = ownerPath ? "owner" : "claim";
    out.ownYedOutputs.clear();
    if (out.changeVout >= 0) out.ownYedOutputs.push_back(COutPoint(CTransaction(out.tx).GetHash(), out.changeVout));
}

// ---------------------------------------------------------------- P-2: the network fee under ZIP-317

CAmount NetworkFee(const CMutableTransaction& probe, size_t saplingSpends, size_t saplingOutputs)
{
    // sapling-crypto BundleType::DEFAULT: a bundle with any spend or output has at least two outputs.
    if (saplingSpends + saplingOutputs > 0) saplingOutputs = std::max<size_t>(saplingOutputs, 2);
    const size_t actions = CalculateLogicalActionCount(probe.vin, probe.vout, probe.vJoinSplit.size(), saplingSpends, saplingOutputs, 0);
    return std::max(g_yellowbackFee, CalculateConventionalFee(actions));
}

CScript PendingP2PKHSig(const CScript& spentScript, const CKeyStore& keystore)
{
    CTxDestination dest;
    CPubKey pk;
    if (ExtractDestination(spentScript, dest)) {
        if (const CKeyID* id = std::get_if<CKeyID>(&dest)) {
            if (keystore.GetPubKey(*id, pk)) return CScript() << valtype(MAX_SIG_SIZE, 0x30) << ToByteVector(pk);
        }
    }
    return CScript() << valtype(MAX_SIG_SIZE, 0x30) << valtype(CPubKey::PUBLIC_KEY_SIZE, 0x04);   // unknown key: count it uncompressed
}

CScript PendingCarrierSig(const CarrierRecord& c)
{
    return CarrierScriptSig(c.bundle, valtype(MAX_SIG_SIZE, 0x30), CarrierScript(c.pk, BundleHash(c.bundle)));
}

VaultSpendPlan PlanPricedVaultSpend(VaultSpendShape& shape, const CKeyStore& keystore, const std::optional<CarrierRecord>& carrier)
{
    // The fee moves collateralOut alone, never the shape, so one repricing settles it.
    VaultSpendPlan plan = PlanVaultSpend(shape);
    CMutableTransaction probe;
    probe.vin = plan.vin;
    probe.vout = plan.vout;
    probe.vin[0].scriptSig = shape.ownerPath ? OwnerScriptSig(valtype(MAX_SIG_SIZE, 0x30), shape.vaultScript) : ClaimScriptSig(shape.vaultScript);
    for (size_t i = 0; i < shape.yedInputs.size(); i++) probe.vin[i + 1].scriptSig = PendingP2PKHSig(shape.yedInputs[i].token.scriptPubKey, keystore);
    if (carrier.has_value()) probe.vin.push_back(CTxIn(carrier->outpoint, PendingCarrierSig(carrier.value())));
    const CAmount fee = NetworkFee(probe, 0, shape.collateralScript.has_value() ? 0 : 1);
    if (fee > shape.networkFee) {
        shape.networkFee = fee;
        plan = PlanVaultSpend(shape);
    }
    return plan;
}

// ---------------------------------------------------------------- v3 pure pieces (§3.4, §3.5, §4.6)

uint256 BundleHash(const std::vector<unsigned char>& bundle)
{
    uint256 h;
    CSHA256().Write(bundle.data(), bundle.size()).Finalize(h.begin());
    return h;
}

CTxOut CarrierOutput(const CPubKey& pk, const std::vector<unsigned char>& bundle, CAmount value)
{
    const CScript redeem = CarrierScript(pk, BundleHash(bundle));
    if (redeem.empty()) throw std::runtime_error("carrier key is not compressed");
    return CTxOut(value, P2SHScript(redeem));
}

void SignCarrierInput(CMutableTransaction& mtx, unsigned int nIn, const CarrierRecord& c, const CKeyStore& keystore, uint32_t branchId)
{
    if (nIn >= mtx.vin.size()) throw std::runtime_error("carrier input index out of range");
    CKey key;
    if (!keystore.GetKey(c.pk.GetID(), key)) throw std::runtime_error("carrier-key-missing: the carrier key is not in this wallet");
    const CScript redeem = CarrierScript(c.pk, BundleHash(c.bundle));
    if (redeem.empty()) throw std::runtime_error("carrier key is not compressed");
    const CTransaction txc(mtx);
    const uint256 hash = SignatureHash(redeem, txc, nIn, SIGHASH_ALL, CARRIER_VALUE, branchId, V4TxData(txc));
    valtype sig;
    if (!key.Sign(hash, sig)) throw std::runtime_error("carrier signature failed");
    sig.push_back((unsigned char)SIGHASH_ALL);
    mtx.vin[nIn].scriptSig = CarrierScriptSig(c.bundle, sig, redeem);
}

void SignBondInput(CMutableTransaction& mtx, unsigned int nIn, const CPubKey& pk, uint32_t locktime, CAmount value,
                   const CKeyStore& keystore, uint32_t branchId)
{
    if (nIn >= mtx.vin.size()) throw std::runtime_error("bond input index out of range");
    CKey key;
    if (!keystore.GetKey(pk.GetID(), key)) throw std::runtime_error("attest-key-not-held: the bond key is not in this wallet");
    const CScript bond = BondScript(pk, locktime);
    if (bond.empty()) throw std::runtime_error("cannot build the bond script");
    const CTransaction txc(mtx);
    const uint256 hash = SignatureHash(bond, txc, nIn, SIGHASH_ALL, value, branchId, V4TxData(txc));
    valtype sig;
    if (!key.Sign(hash, sig)) throw std::runtime_error("bond signature failed");
    sig.push_back((unsigned char)SIGHASH_ALL);
    mtx.vin[nIn].scriptSig = CScript() << sig << valtype(bond.begin(), bond.end());
}

std::optional<TxLogRecord> DryRun(StateView& view, const Params& params, const CTransaction& tx, int height, SigCache* cache)
{
    // The same pseudo-block MempoolCheck and yed_validaterawtransaction evaluate (K7).
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout.SetNull();
    cb.vin[0].scriptSig = CScript() << height;
    CBlock pseudo;
    pseudo.vtx.push_back(CTransaction(cb));
    pseudo.vtx.push_back(tx);
    OverlayStateView overlay(view);
    BlockEvaluation ev = EvaluateBlock(overlay, params, pseudo, height, uint256(), 0, cache);
    const uint256 txid = tx.GetHash();
    for (const auto& e : ev.txlogs) if (e.first == txid) return e.second;
    return std::nullopt;
}

BundleVerdict VerifyBundleBytes(const StateView& view, const Params& params, const std::vector<unsigned char>& bundle,
                                int refHeight, const std::vector<unsigned char>& selector, std::vector<uint16_t>* selected)
{
    // A one-input skeleton whose carrier scriptSig carries the bundle; the key and signature are
    // placeholders (BUNDLE-1 reads the shape and the hash, never the carrier signature).
    std::vector<unsigned char> pkBytes(33, 0x01);
    pkBytes[0] = 0x02;
    const CPubKey pk(pkBytes);
    CMutableTransaction skel;
    skel.vin.push_back(CTxIn(COutPoint(), CarrierScriptSig(bundle, valtype(71, 0x30), CarrierScript(pk, BundleHash(bundle)))));
    return VerifyTxBundle(view, params, CTransaction(skel), refHeight, selector, false, nullptr, selected);
}

// ---------------------------------------------------------------- wallet builders

namespace {

/** At most this many Sapling notes in one mint (one spend proof each, seconds apiece). */
const size_t MAX_SAPLING_SPENDS = 20;

/** A funding source or collateral destination given as an address string (§4.6). */
struct AddressChoice
{
    enum Kind { NONE, TRANSPARENT, SAPLING } kind;
    CKeyID keyId;                                   //!< TRANSPARENT
    libzcash::SaplingPaymentAddress sapling;        //!< SAPLING
    std::string text;
    AddressChoice() : kind(NONE) {}
};

/** Parse "" / s1… / ys1…; anything else (a Yellowback ye… address, a Sprout zc… address) is refused. */
AddressChoice ParseAddressChoice(const std::string& s, const char* what)
{
    AddressChoice c;
    c.text = s;
    if (s.empty()) return c;
    KeyIO keyIO(::Params());
    CTxDestination dest = keyIO.DecodeDestination(s);
    if (const CKeyID* id = std::get_if<CKeyID>(&dest)) {
        c.kind = AddressChoice::TRANSPARENT;
        c.keyId = *id;
        return c;
    }
    if (keyIO.IsValidPaymentAddressString(s)) {
        std::optional<libzcash::PaymentAddress> pa = keyIO.DecodePaymentAddress(s);   // 6.20.0: optional
        if (pa.has_value()) {
            if (const libzcash::SaplingPaymentAddress* sa = std::get_if<libzcash::SaplingPaymentAddress>(&pa.value())) {
                c.kind = AddressChoice::SAPLING;
                c.sapling = *sa;
                return c;
            }
            if (std::holds_alternative<libzcash::SproutPaymentAddress>(pa.value())) {
                throw std::runtime_error(std::string("bad-address: ") + what + ": Sprout addresses are not supported; use an s1… or ys1… address");
            }
        }
    }
    throw std::runtime_error(std::string("bad-address: ") + what + ": not a transparent (s1…) or Sapling (ys1…) address of this network");
}

struct Context
{
    YellowbackWallet& yw;
    CWallet& wallet;
    YellowbackIndex& index;
    const Params& params;
    State st;
    int chainHeight;
    int indexHeight;
    int refHeight;                          //!< R for a MINT / TRANSFER: indexTip - REF_LAG (§3.5)
    int spendRefHeight;                     //!< R for a vault spend: the index tip (the snapshot yed_listclaimable reads; RED-1's window holds at H = tip + 1)
    uint32_t branchId;
    CAmount fee;                            //!< P-2: the network fee the builder is pricing at (Reprice raises it)

    explicit Context(YellowbackWallet& yw_)
        : yw(yw_), wallet(*yw_.Wallet()), index(*yw_.Index()), params(yw_.Index()->GetParams()), st(yw_.Index()->View()),
          chainHeight(0), indexHeight(-1), refHeight(-1), spendRefHeight(-1), branchId(0), fee(g_yellowbackFee)
    {
        AssertLockHeld(cs_main);
        AssertLockHeld(wallet.cs_wallet);
        AssertLockHeld(index.cs_yellowback);
        if (!index.IsHealthy()) throw std::runtime_error("yellowback-unhealthy: " + index.UnhealthyReason() + "; restart with -reindex-yellowback");
        chainHeight = chainActive.Height();
        std::optional<TipRecord> tip = st.GetTip();
        if (!tip.has_value()) throw std::runtime_error("index-below-start: the index has not reached the start height");
        indexHeight = tip->height;
        refHeight = indexHeight - g_yellowbackMintLag;
        spendRefHeight = indexHeight;
        if (refHeight < params.startHeight) throw std::runtime_error(strprintf("index-below-start: the index must reach height %d first", params.startHeight + g_yellowbackMintLag));
        branchId = SignerBranchId();
        if (wallet.IsLocked()) throw std::runtime_error("wallet-locked: walletpassphrase first");
    }

    /** nExpiryHeight = R + REF_WINDOW (V11; the MP-1 bound for a vault spend, N5). */
    uint32_t Expiry(int r) const { return (uint32_t)(r + REF_WINDOW); }

    void CheckExpiry(uint32_t expiry) const
    {
        if ((int64_t)expiry < (int64_t)chainHeight + 1 + (int64_t)TX_EXPIRING_SOON_THRESHOLD) {
            throw std::runtime_error("expiring-too-soon: the transaction would expire too soon; the index is too far behind the chain");
        }
    }

    CMutableTransaction NewTx(uint32_t expiry) const
    {
        CheckExpiry(expiry);
        CMutableTransaction mtx = CreateNewContextualCMutableTransaction(::Params().GetConsensus(), chainHeight + 1, /* requireV4 */ true);
        mtx.nExpiryHeight = expiry;
        return mtx;
    }

    /**
     * A TransactionBuilder for the Sapling shapes, constructed in place in `slot`: same expiry/fee as
     * NewTx, no keystore, no Orchard anchor (so a v4 transaction while NU5 is inactive). 6.20.0 takes
     * the Sapling anchor in the constructor: the spend shapes pass the one their witnesses were taken
     * at, the output-only shapes the tip's (as the stock wallet does). Never moved afterwards: the
     * 6.20.0 builder is move-only and its move constructor does not carry firstSaplingSpendAddr
     * (F-2), which is why BuiltTx holds it through a unique_ptr (audit B-5).
     */
    TransactionBuilder& NewBuilder(std::unique_ptr<TransactionBuilder>& slot, uint32_t expiry,
                                   std::optional<uint256> saplingAnchor = std::nullopt) const
    {
        CheckExpiry(expiry);
        const uint256 anchor = saplingAnchor.has_value() ? saplingAnchor.value() : pcoinsTip->GetBestAnchor(SAPLING);
        slot = std::make_unique<TransactionBuilder>(::Params(), chainHeight + 1, std::nullopt, anchor);
        TransactionBuilder& b = *slot;
        b.SetExpiryHeight(expiry);
        b.SetFee(fee);
        return b;
    }

    /**
     * P-2: the NetworkFee() of `probe` once signed — vin[first .. first + prevs.size()) as P2PKH of
     * prevs, the carrier at `carrierVin` — with the Sapling spends/outputs still to come.
     */
    CAmount FeeOf(CMutableTransaction probe, const std::vector<std::pair<CScript, CAmount>>& prevs, unsigned int first,
                  const CarrierRecord* carrier = nullptr, int carrierVin = -1, size_t saplingSpends = 0, size_t saplingOutputs = 0) const
    {
        for (size_t i = 0; i < prevs.size(); i++) probe.vin[first + i].scriptSig = PendingP2PKHSig(prevs[i].first, wallet);
        if (carrier && carrierVin >= 0) probe.vin[carrierVin].scriptSig = PendingCarrierSig(*carrier);
        return NetworkFee(probe, saplingSpends, saplingOutputs);
    }

    /** P-2: raise the fee to `needed`; true when it rose, and the caller rebuilds at the new fee (it only rises, so this ends). */
    bool Reprice(CAmount needed)
    {
        if (needed <= fee) return false;
        fee = needed;
        return true;
    }

    /** The real scriptPubKey of a coin the transaction spends unsigned (needed by the 6.20.0 builder), else `fallback`. */
    CScript SpentScript(const COutPoint& o, const CScript& fallback) const
    {
        const CCoins* c = pcoinsTip->AccessCoins(o.hash);
        return (c && c->IsAvailable(o.n)) ? c->vout[o.n].scriptPubKey : fallback;
    }

    CPubKey FreshKey(const std::string& purpose) const
    {
        if (wallet.IsLocked()) throw std::runtime_error("wallet-locked: unlock the wallet first (walletpassphrase)");
        CPubKey key = wallet.GenerateNewKey(true);   // 6.20.0: a fresh HD key, as stock getnewaddress
        wallet.SetAddressBook(key.GetID(), "", purpose);
        return key;
    }

    /** The payee of §3.7 FEE-W (or the configured preference, the index's L6 values) for `selector` at `r`; nullopt under FEE-0. */
    std::optional<CKeyID> Payee(int r, const std::vector<unsigned char>& selector) const
    {
        return DefaultPayee(st.View(), params, r, selector, index.GetPayeePolicy());
    }

    // ---- v3
    /** AFEE-W's knob: -yellowbackpreferredattestor (read here, never in the pure layer; §3.10). */
    AttestPolicy AttestPol() const
    {
        AttestPolicy a;
        if (mapArgs.count("-yellowbackpreferredattestor")) a.preferred = (uint16_t)GetArg("-yellowbackpreferredattestor", 0);
        return a;
    }
    /** Is `out` a confirmed unspent coin at the chain tip? (cs_main) */
    bool CoinAvailable(const COutPoint& out) const
    {
        const CCoins* c = pcoinsTip->AccessCoins(out.hash);
        return c && c->IsAvailable(out.n);
    }
    /** The P2PKH key of attestor seq's bondPubKey (the fee payee, bondKeyAddress). */
    std::optional<CKeyID> BondKeyOf(uint16_t seq) const
    {
        std::optional<AttestorRecord> rec = st.GetAttestor(seq);
        if (!rec.has_value()) return std::nullopt;
        const CPubKey k = rec->BondKey();
        if (!k.IsValid()) return std::nullopt;
        return k.GetID();
    }
    /** blockHash(h) from the active chain (cs_main); the index stores the same hash for h >= startHeight. */
    uint256 BlockHashAt(int h) const
    {
        const CBlockIndex* pindex = (h >= 0 && h <= chainHeight) ? chainActive[h] : nullptr;
        return pindex ? pindex->GetBlockHash() : uint256();
    }
    /** A carrier must be a confirmed unspent coin whose R still fits the window at the next height. */
    void CheckCarrier(const CarrierRecord& c) const
    {
        if (!CoinAvailable(c.outpoint)) throw std::runtime_error("carrier-unconfirmed: the carrier " + c.outpoint.ToString() + " is not a confirmed unspent output");
        if (c.refHeight < params.startHeight || (int64_t)chainHeight + 1 - REF_WINDOW > (int64_t)c.refHeight) {
            throw std::runtime_error(strprintf("carrier-lapsed: the carrier's reference height %d is outside the window at height %d; yed_sweepcarriers reclaims it", c.refHeight, chainHeight + 1));
        }
    }

    /**
     * Smallest-first confirmed YEC inputs covering `needed`; returns the amount selected.
     * `only`: restrict to outputs paying that script (an s1… funding address).
     */
    CAmount SelectYec(CAmount needed, CMutableTransaction& mtx, std::vector<std::pair<CScript, CAmount>>& prevs,
                      const CScript* only = nullptr, const std::string& onlyText = "") const
    {
        if (needed <= 0) return 0;
        yw.SettleYecLocks();   // F-1: hand back the inputs of a spender that failed
        std::vector<COutput> coins;
        wallet.AvailableCoins(coins, std::nullopt, true, nullptr, false, true, false, 1);
        std::sort(coins.begin(), coins.end(), [](const COutput& a, const COutput& b) { return a.Value() < b.Value(); });
        CAmount selected = 0;
        for (const COutput& c : coins) {
            if (!c.fSpendable) continue;
            if (only && c.tx->vout[c.i].scriptPubKey != *only) continue;
            // Never spend a YED-bearing output or a vault as plain YEC (belt and braces: locked coins are already excluded),
            // and never any P2SH output: a carrier or a bond is not IsMine (R6) so AvailableCoins never offers one, and
            // this line keeps that true if the wallet ever learns to solve them.
            if (c.tx->vout[c.i].scriptPubKey.IsPayToScriptHash()) continue;
            COutPoint o(c.tx->GetHash(), c.i);
            if (st.GetToken(o).has_value() || st.GetVault(o).has_value()) continue;
            // F-1: a coin the chainstate has already spent. Its spender is mined but the notifier has
            // not stamped it yet (wallet depth -1), so IsSpent no longer counts it and AvailableCoins
            // offers the coin again; choosing it would make the commit fail as a double spend.
            if (!CoinAvailable(o)) continue;
            mtx.vin.push_back(CTxIn(o));
            prevs.push_back(std::make_pair(c.tx->vout[c.i].scriptPubKey, c.Value()));
            selected += c.Value();
            if (selected >= needed) break;
        }
        if (selected < needed) {
            throw std::runtime_error(strprintf("insufficient-yec: need %s, have %s confirmed and unlocked%s",
                                               FormatMoney(needed), FormatMoney(selected), only ? " at " + onlyText : ""));
        }
        return selected;
    }

    /**
     * Sapling notes of `addr` (§4.6), largest-first as z_sendmany, covering `needed`. Fills the
     * spending key, the anchor and one witness per note; requires cs_main and cs_wallet.
     */
    void SelectSapling(const AddressChoice& addr, CAmount needed, libzcash::SaplingExtendedSpendingKey& extsk,
                       std::vector<SaplingNoteEntry>& sel, std::vector<SaplingWitness>& witnesses, uint256& anchor) const
    {
        if (!wallet.HaveSaplingSpendingKeyForAddress(addr.sapling) || !wallet.GetSaplingExtendedSpendingKey(addr.sapling, extsk)) {
            throw std::runtime_error("bad-address: no spending key for " + addr.text + " in this wallet");
        }

        std::vector<SproutNoteEntry> sprout;
        std::vector<SaplingNoteEntry> notes;
        std::vector<OrchardNoteMetadata> orchard;
        const NoteFilter filter = NoteFilter::ForPaymentAddresses({libzcash::PaymentAddress(addr.sapling)});
        wallet.GetFilteredNotes(sprout, notes, orchard, filter, std::nullopt, 1, INT_MAX, true, true, true);
        std::sort(notes.begin(), notes.end(), [](const SaplingNoteEntry& a, const SaplingNoteEntry& b) { return a.note.value() > b.note.value(); });
        CAmount sum = 0;
        CAmount available = 0;
        for (const SaplingNoteEntry& e : notes) available += e.note.value();
        for (const SaplingNoteEntry& e : notes) {
            if (sum >= needed) break;
            sel.push_back(e);
            sum += e.note.value();
        }
        if (sum < needed) {
            throw std::runtime_error(strprintf("insufficient-yec: need %s, have %s in confirmed Sapling notes at %s", FormatMoney(needed), FormatMoney(available), addr.text));
        }
        if (sel.size() > MAX_SAPLING_SPENDS) {
            throw std::runtime_error(strprintf("too-many-notes: the mint would spend %u Sapling notes (limit %u); consolidate with z_mergetoaddress first", (unsigned)sel.size(), (unsigned)MAX_SAPLING_SPENDS));
        }
        std::vector<SaplingOutPoint> ops;
        for (const SaplingNoteEntry& e : sel) ops.push_back(e.op);
        std::vector<std::optional<SaplingWitness>> maybe;
        if (!wallet.GetSaplingNoteWitnesses(ops, 1, maybe, anchor)) {   // 1 = the newest witness, as v4.5.0
            throw std::runtime_error("missing witness for a Sapling note; retry after the next block");
        }
        for (size_t i = 0; i < maybe.size(); i++) {
            if (!maybe[i].has_value()) throw std::runtime_error("missing witness for a Sapling note; retry after the next block");
            witnesses.push_back(maybe[i].value());
        }
    }

    /** Sign vin[first .. first + prevs.size()) as P2PKH (the inputs after them — a carrier — are signed separately, after this). */
    void SignInputs(CMutableTransaction& mtx, const std::vector<std::pair<CScript, CAmount>>& prevs, unsigned int first) const
    {
        for (unsigned int i = first; i < first + prevs.size() && i < mtx.vin.size(); i++) {
            const auto& p = prevs[i - first];
            if (!SignSignature(wallet, p.first, mtx, V4TxData(CTransaction(mtx)), i, p.second, SIGHASH_ALL, branchId)) {
                throw std::runtime_error(strprintf("failed to sign input %u", i));
            }
        }
    }

    /** The vault `vaultTxid:0`, or `vault-not-found`. */
    VaultRecord GetVault(const COutPoint& vaultOut) const
    {
        std::optional<VaultRecord> vault = st.GetVault(vaultOut);
        if (!vault.has_value()) throw std::runtime_error("vault-not-found: no vault at " + vaultOut.ToString());
        return vault.value();
    }

    /** The keypool-low nag of §4.6 (the wallet.dat backup rule). */
    std::string KeypoolWarning() const
    {
        const unsigned int n = wallet.GetKeyPoolSize();
        if (n >= 10) return "";
        return strprintf("keypool low (%u keys left): keypoolrefill and back up wallet.dat — the vault owner key lives only there", n);
    }
};

/** The spendable YED coins in the selector's canonical order: (cents, txid, vout) — H1, determinism. */
std::vector<YedCoin> RankedCoins(const Context& ctx)
{
    std::vector<YedCoin> coins = ctx.yw.SpendableCoins();
    std::sort(coins.begin(), coins.end(), [](const YedCoin& a, const YedCoin& b) {
        if (a.token.cents != b.token.cents) return a.token.cents < b.token.cents;
        if (a.outpoint.hash != b.outpoint.hash) return a.outpoint.hash < b.outpoint.hash;
        return a.outpoint.n < b.outpoint.n;
    });
    return coins;
}

/** The H2 refusal: the request, and the nearest workable amounts below and above it. */
std::string ChangeFloorMessage(const std::vector<int64_t>& cents, int64_t needed, const yellowback::Params& p)
{
    const Alternatives alt = NearestWorkable(cents, needed, p.minOutput, MAX_YED_INPUTS);
    return strprintf("change-floor: %d cents cannot be sent from these coins without change below the $%d.%02d minimum output; "
                     "nearest workable amounts: below %s, above %s",
                     needed, p.minOutput / 100, p.minOutput % 100,
                     alt.below.has_value() ? strprintf("%d", alt.below.value()) : std::string("none"),
                     alt.above.has_value() ? strprintf("%d", alt.above.value()) : std::string("none"));
}

/**
 * Select YED coins for `needed` cents with the floor-aware selector (H1). `allowBurn` (a REDEEM
 * or a CLAIM, H4) accepts a sub-dollar remainder — reported in `extraBurn`, bounded by
 * MIN_OUTPUT - 1 — when no selection leaves change of 0 or >= MIN_OUTPUT; a TRANSFER never burns
 * and refuses instead (H2). Throws the identifier of doc/yellowback-rpc.md in every refusal.
 */
std::vector<YedCoin> SelectYed(const Context& ctx, int64_t needed, int64_t& change, bool allowBurn, int64_t& extraBurn)
{
    const std::vector<YedCoin> coins = RankedCoins(ctx);
    std::vector<int64_t> cents;
    int64_t have = 0;
    for (const YedCoin& c : coins) {
        cents.push_back(c.token.cents);
        have += c.token.cents;
    }
    const Selection s = SelectFloorAware(cents, needed, ctx.params.minOutput, MAX_YED_INPUTS, allowBurn);
    if (!s.ok) {
        if (s.insufficient) throw std::runtime_error(strprintf("insufficient-yed: need %d cents, have %d confirmed and spendable", needed, have));
        if (s.tooManyInputs) throw std::runtime_error(strprintf("too-many-inputs: more than %u YED inputs would be needed; consolidate first", (unsigned)MAX_YED_INPUTS));
        throw std::runtime_error(ChangeFloorMessage(cents, needed, ctx.params));
    }
    change = s.change;
    extraBurn = s.extraBurn;
    std::vector<YedCoin> sel;
    for (size_t i : s.inputs) sel.push_back(coins[i]);
    return sel;
}

/** The TRANSFER selector: never burns (H2). */
std::vector<YedCoin> SelectYed(const Context& ctx, int64_t needed, int64_t& change)
{
    int64_t extraBurn = 0;
    return SelectYed(ctx, needed, change, false, extraBurn);
}

/** v3: what a claim's spend adds to the vault-spend body (the carrier, the attestor fee, the residual). */
struct ClaimExtras
{
    CarrierRecord carrier;
    std::optional<CKeyID> attestKey;
    CAmount attestFeeZat;
    CAmount residualZat;
    ClaimExtras() : attestFeeZat(0), residualZat(0) {}
};

/**
 * The shared body of BuildRedeem (ACTIVE and VOID), BuildClaim and BuildSweep: a vault spend of
 * `vault` with `burn` = the debt (REDEEM/CLAIM) or none (release/sweep), to `to`, with payload
 * refHeight `R` (the index tip for an owner-path spend, the carrier's R for a claim).
 */
BuiltTx BuildVaultSpend(Context& ctx, BuiltKind kind, const COutPoint& vaultOut, const VaultRecord& vault, const std::string& to, int R,
                        const ClaimExtras* extras = nullptr)
{
    const AddressChoice dest = ParseAddressChoice(to, "to");
    const bool ownerPath = kind != BuiltKind::CLAIM;
    const bool withPayload = kind == BuiltKind::REDEEM || kind == BuiltKind::CLAIM;

    const CPubKey owner = vault.OwnerKey();
    VaultSpendShape shape;
    shape.vaultOut = vaultOut;
    shape.vaultScript = VaultScript((uint32_t)vault.lockHeight, owner, (uint32_t)vault.claimHeight);
    if (shape.vaultScript.empty()) throw std::runtime_error("vault-not-found: cannot reconstruct the vault script");
    shape.vaultValue = vault.collateralZat;
    shape.lockHeight = (uint32_t)vault.lockHeight;
    shape.claimHeight = (uint32_t)vault.claimHeight;
    shape.ownerPath = ownerPath;
    shape.withPayload = withPayload;
    shape.refHeight = R;
    shape.networkFee = ctx.fee;
    if (extras) {
        shape.attestPayee = extras->attestKey;
        shape.attestFeeZat = extras->attestFeeZat;
        shape.residualZat = extras->residualZat;
        shape.ownerPubKey = owner;
        shape.carrierValue = CARRIER_VALUE;
    }

    BuiltTx out;
    out.kind = kind;
    out.refHeight = R;
    out.termClass = vault.termClass;
    out.lockHeight = shape.lockHeight;
    out.claimHeight = shape.claimHeight;
    out.vaultScript = shape.vaultScript;
    out.vaultValue = vault.collateralZat;
    out.ownerPubKey = owner;
    out.path = ownerPath ? "owner" : "claim";
    if (extras) {
        out.carrier = extras->carrier;
        out.attestPayeeKey = extras->attestKey;
        out.attestFeeZat = extras->attestKey.has_value() ? extras->attestFeeZat : 0;
        out.residualZat = extras->residualZat;
    }

    if (withPayload) {
        // RED-2: the burn is exactly the debt (V20); RED-3: the fee from the collateral.
        int64_t change = 0;
        int64_t extraBurn = 0;   // H4: a sub-dollar remainder burned on top of the debt (RED-2 allows over-burning)
        std::vector<YedCoin> sel = SelectYed(ctx, vault.mintedCents, change, true, extraBurn);
        out.extraBurnCents = extraBurn;
        shape.yedInputs = sel;
        shape.changeCents = change;
        if (change > 0) {
            CPubKey changeKey = ctx.FreshKey("yellowback-change");
            out.freshKey = changeKey;
            shape.changeScript = GetScriptForDestination(changeKey.GetID());
        }
        shape.payee = ctx.Payee(R, OutPointSelector(vaultOut));
        shape.feeZat = shape.payee.has_value() ? FeeZat(vault.collateralZat, ctx.params.feeMin, ctx.params.feeBps) : 0;
        for (const YedCoin& c : sel) {
            out.yedInputs.insert(c.outpoint);
            out.yedPrevs.push_back(std::make_pair(c.token.scriptPubKey, c.token.nValue));
        }
        out.changeCents = change;
        out.payee = shape.payee;
        out.feeZat = shape.feeZat;
    }

    const uint32_t expiry = ctx.Expiry(R);
    if (dest.kind == AddressChoice::TRANSPARENT) {
        shape.collateralScript = GetScriptForDestination(dest.keyId);
        out.collateralTo = dest.text;
    } else if (dest.kind != AddressChoice::SAPLING) {
        CPubKey fresh = ctx.FreshKey("yellowback-collateral");
        if (!out.freshKey.IsValid()) out.freshKey = fresh;
        shape.collateralScript = GetScriptForDestination(fresh.GetID());
        out.collateralTo = KeyIO(::Params()).EncodeDestination(CTxDestination(fresh.GetID()));
    }
    // P-2: the fee is the conventional fee of this shape; it comes out of the collateral.
    VaultSpendPlan plan = PlanPricedVaultSpend(shape, ctx.wallet, extras ? std::optional<CarrierRecord>(extras->carrier) : std::nullopt);
    ctx.fee = shape.networkFee;
    if (dest.kind == AddressChoice::SAPLING) {
        // Sapling shape (§4.6): the collateral is one Sapling note; vault, YED and carrier inputs go
        // in unsigned and are signed by SignVaultSpend() after FinishSapling().
        TransactionBuilder& b = ctx.NewBuilder(out.builder, expiry);
        b.SetLockTime(plan.nLockTime);
        b.AddTransparentInputUnsigned(vaultOut, ctx.SpentScript(vaultOut, P2SHScript(shape.vaultScript)), vault.collateralZat, 0xFFFFFFFE);
        for (const YedCoin& c : shape.yedInputs) b.AddTransparentInputUnsigned(c.outpoint, c.token.scriptPubKey, c.token.nValue);
        if (extras) {
            const CarrierRecord& cr = extras->carrier;
            b.AddTransparentInputUnsigned(cr.outpoint, ctx.SpentScript(cr.outpoint, CarrierOutput(cr.pk, cr.bundle, CARRIER_VALUE).scriptPubKey), CARRIER_VALUE);
            out.carrierVin = 1 + (int)shape.yedInputs.size();
        }
        for (const CTxOut& o : plan.vout) b.AddTransparentOutput(o.scriptPubKey, o.nValue);
        // Encrypt the note under the seed-derived key z_sendmany uses for t->z, so it is recoverable
        // from the seed whether or not the destination belongs to this wallet.
        HDSeed seed = ctx.wallet.GetHDSeedForRPC();
        b.AddSaplingOutput(ovkForShieldingFromTaddr(seed), dest.sapling, plan.collateralOut, std::nullopt);
        out.collateralTo = dest.text;
        out.collateralOut = plan.collateralOut;
        out.burnCents = plan.burnCents;
        out.feeVout = plan.feeVout;
        out.changeVout = plan.changeVout;
        out.attestFeeVout = plan.attestFeeVout;
        out.residualVout = plan.residualVout;
        return out;
    }

    CMutableTransaction mtx = ctx.NewTx(expiry);
    mtx.nLockTime = plan.nLockTime;
    mtx.vin = plan.vin;
    if (extras) {
        mtx.vin.push_back(CTxIn(extras->carrier.outpoint));   // never vin[0] (§3.5)
        out.carrierVin = (int)mtx.vin.size() - 1;
    }
    mtx.vout = plan.vout;
    out.tx = mtx;
    out.collateralOut = plan.collateralOut;
    out.burnCents = plan.burnCents;
    out.feeVout = plan.feeVout;
    out.changeVout = plan.changeVout;
    out.attestFeeVout = plan.attestFeeVout;
    out.residualVout = plan.residualVout;
    return out;
}

// ---------------------------------------------------------------- v3 shared facts (the bundle, the prices, the clauses)

/** What the bundle at (R, selector) decided, when ARMED at R. */
struct BundleFactsW
{
    bool armed;
    std::vector<unsigned char> bundle;
    std::vector<uint16_t> seqs;          //!< A
    std::vector<uint16_t> selected;
    std::optional<MicroUsd> aMint, aClaim;
    BundleFactsW() : armed(false) {}
};

/**
 * The bundle for (R, selector): unarmed => empty facts and the bundle is ignored (the carrier is
 * still built, one code path); armed => the explicit bytes must verify under BUNDLE-1 with both
 * statistics defined, else `bundle-insufficient` in the contract's grammar. No bytes while armed
 * takes the node's pool path (BuildBundleInfo); an explicit bundleHex overrides it.
 */
BundleFactsW BundleAt(const Context& ctx, int R, const std::vector<unsigned char>& selector, const std::optional<std::vector<unsigned char>>& bundle)
{
    BundleFactsW f;
    f.armed = ArmedAt(ctx.st.View(), ctx.params, R);
    if (!f.armed) return f;
    std::vector<unsigned char> bytes;
    if (bundle.has_value() && !bundle->empty()) {
        bytes = bundle.value();                       // bundleHex overrides the pool
    } else {
        // The pool path: the bundle this node would build from its attestation pool (W6), then the
        // same verification as explicit bytes so the two paths cannot disagree.
        BuiltBundle built = ctx.index.BuildBundleInfo(R, selector);
        if (!built.sufficient) throw std::runtime_error(built.InsufficientMessage());
        bytes = EncodeBundle(built.bundle);
    }
    std::optional<Bundle> decoded = DecodeBundle(bytes, (size_t)std::max(0, ctx.params.bundleMax));
    if (!decoded.has_value()) throw std::runtime_error("bundle-malformed: bundleHex is not \"YA\" 0x01 count followed by count x 74-byte attestations");
    BundleVerdict v = VerifyBundleBytes(ctx.st.View(), ctx.params, bytes, R, selector, &f.selected);
    if (!v.ok || !v.aMint.has_value() || !v.aClaim.has_value()) {
        std::set<uint16_t> have;
        for (const Attestation& a : decoded->atts) have.insert(a.seq);
        std::string missing;
        unsigned count = 0;
        for (uint16_t q : f.selected) {
            if (have.count(q)) { count++; continue; }
            if (!missing.empty()) missing += ",";
            missing += std::to_string(q);
        }
        throw std::runtime_error(strprintf("bundle-insufficient: %u of %u selected attestors have a fresh attestation; missing seq %s (BUNDLE-1 at %d: %s)",
                                           count, (unsigned)f.selected.size(), missing.empty() ? "none" : missing, R, v.ok ? verdict::BUNDLE_STAT : v.reason.c_str()));
    }
    f.bundle = bytes;
    for (const Attestation& a : v.C) f.seqs.push_back(a.seq);
    f.aMint = v.aMint;
    f.aClaim = v.aClaim;
    return f;
}

/** AFEE-W: the attestor payee and fee for a transaction of `collateral` at (R, selector); nothing under AFEE-0. */
void AttestFeeFor(const Context& ctx, int R, const std::vector<unsigned char>& selector, const BundleFactsW& f, CAmount collateral, BuiltTx& out)
{
    out.armed = f.armed;
    out.bundleSeqs = f.seqs;
    out.aMint = f.aMint;
    out.aClaim = f.aClaim;
    if (!f.armed || f.seqs.empty()) return;
    std::optional<uint16_t> payee = DefaultAttestPayee(ctx.st.View(), ctx.params, R, selector, f.seqs, ctx.AttestPol());
    if (!payee.has_value()) return;
    std::optional<CKeyID> key = ctx.BondKeyOf(payee.value());
    if (!key.has_value()) throw std::runtime_error(strprintf("attest-unknown-seq: attestor %u has no bond key", (unsigned)payee.value()));
    out.attestPayee = payee;
    out.attestPayeeKey = key;
    out.attestFeeZat = AttestFeeZat(FeeZat(collateral, ctx.params.feeMin, ctx.params.feeBps), ctx.params.attestFeeBps);
}

/** MINTPOL-1 and the class / lock arithmetic of a mint at R (§4.6). */
struct MintGateFacts
{
    int termClass;
    int64_t lockHeight, claimHeight;
    Snapshot S;
    std::optional<MicroUsd> xMint;
    MintGateFacts() : termClass(0), lockHeight(0), claimHeight(0) {}
};

/** The cents of every MINT payload in the mempool (mempool.cs is held by the RPC layer, N25: before cs_yellowback). */
Cents MempoolMintCents()
{
    AssertLockHeld(mempool.cs);
    Cents total = 0;
    for (CTxMemPool::indexed_transaction_set::const_iterator it = mempool.mapTx.begin(); it != mempool.mapTx.end(); ++it) {
        std::optional<FoundPayload> fp = FindPayload(it->GetTx());
        if (fp.has_value() && fp->payload.type == PayloadType::MINT) total += (Cents)fp->payload.cents;
    }
    return total;
}

MintGateFacts MintGate(const Context& ctx, Cents cents, int lockBlocks, int R)
{
    const Params& p = ctx.params;
    MintGateFacts g;
    if (cents < p.minMint || cents > p.maxMint) throw std::runtime_error(strprintf("bad-mint-amount: cents must be between %d and %d", p.minMint, p.maxMint));
    g.termClass = p.ClassForLockBlocks(lockBlocks);
    if (g.termClass < 0) throw std::runtime_error(strprintf("mint-bad-lock: %d blocks is outside every term class (A %d-%d, B %d-%d, C %d-%d)", lockBlocks,
                                                            p.classMin[0], p.classMax[0], p.classMin[1], p.classMax[1], p.classMin[2], p.classMax[2]));
    g.lockHeight = (int64_t)R + lockBlocks;
    g.claimHeight = g.lockHeight + p.grace;
    if (g.claimHeight >= (int64_t)LOCKTIME_THRESHOLD) throw std::runtime_error("mint-bad-lock: lockHeight + GRACE reaches LOCKTIME_THRESHOLD");

    // MINTPOL-1 (§4.6): Snapshots[R].activation == ACTIVE, haltMask == 0, the cap has room.
    std::optional<Snapshot> S = SnapshotAt(ctx.st, p, R);
    if (!S.has_value() || !S->activation.IsActive() || (S->haltMask & HALT_NOT_ACTIVE)) throw std::runtime_error("mintpol-not-active: Yellowback is not active at the reference height");
    if (S->haltMask & HALT_NO_PRICE) throw std::runtime_error("mintpol-no-price: no defined price at the reference height (PRICE-1 fill)");
    if (S->haltMask & (HALT_PARTICIPATION | HALT_ENFORCEMENT)) throw std::runtime_error("mintpol-participation: minting is halted while miner participation is low (ACT-4)");
    // W16 / W20: the classes whose minimum ratio reaches the recapitalisation floor -- they mint through a
    // global-ratio halt and above the supply cap; the refusals below name them.
    const bool recap = MinRatioBps(ctx.params.baseRatioBps[g.termClass], S->sigmaMultBps) >= ctx.params.recapRatioBps;
    std::string open;
    for (int c = 0; c < NUM_CLASSES; c++) if (MinRatioBps(ctx.params.baseRatioBps[c], S->sigmaMultBps) >= ctx.params.recapRatioBps) open += (open.empty() ? "" : ", ") + std::string(1, (char)('A' + c));
    const std::string openClasses = open.empty() ? "" : " (class " + open + ")";
    if ((S->haltMask & HALT_GLOBAL_RATIO) && !recap) {
        throw std::runtime_error(strprintf("mintpol-global-ratio: the global collateral ratio is below %d %% (HALT-2); only a term class whose minimum ratio is at least %d %% can mint until it recovers%s",
                                           ctx.params.globalRatioHaltBps / 100, ctx.params.recapRatioBps / 100, openClasses));
    }
    if (S->haltMask & HALT_DIVERGENCE) throw std::runtime_error("mintpol-divergence: minting is halted while the price windows diverge (HALT-3)");
    if ((S->haltMask & ~HALT_GLOBAL_RATIO) != 0) throw std::runtime_error("mintpol-not-active: an unknown halt bit is set at the reference height");
    g.S = S.value();
    g.xMint = S->PMint();
    if (!g.xMint.has_value()) throw std::runtime_error("mintpol-no-price: pMint is undefined at the reference height");
    const Totals totals = ctx.st.GetTotals();
    // MINT-6 (W20): above the cap only a class at or over the recapitalisation floor mints; the message
    // names the classes that would go through.
    std::optional<Cents> cap = SupplyCapCents(S->issuedZat, g.xMint, p.supplyCapBps);
    if (cap.has_value() && !recap && totals.supplyCents + cents > cap.value()) {
        throw std::runtime_error(strprintf("mintpol-cap: supply cap headroom is %d cents; above the cap only a term class whose minimum ratio is at least %d %% can mint%s",
                                           std::max<Cents>(0, cap.value() - totals.supplyCents), p.recapRatioBps / 100, openClasses));
    }
    // MINT-6 is judged at inclusion against live totals: mints already in the mempool land first and a
    // mint that passed this gate could confirm VOID, locking its collateral (audit C-3). Count them here;
    // the residual race (a competing mint that arrives later or pays more) is documented under yed_mint.
    const Cents pending = MempoolMintCents();
    if (cap.has_value() && !recap && pending > 0 && totals.supplyCents + pending + cents > cap.value()) {
        throw std::runtime_error(strprintf("mintpol-cap: supply cap headroom is %d cents after %d cents of mints in the mempool; above the cap only a term class whose minimum ratio is at least %d %% can mint%s",
                                           std::max<Cents>(0, cap.value() - totals.supplyCents - pending), pending, p.recapRatioBps / 100, openClasses));
    }
    return g;
}

/** MINT-10 and PRICE-2 for a mint: pMint = min(xMint, aMint) when armed, else xMint. */
void CombineMint(const Context& ctx, const MintGateFacts& g, const BundleFactsW& f, std::optional<MicroUsd>& pMint, std::string& source)
{
    pMint = g.xMint;
    source = "x";
    if (!f.armed) return;
    const MicroUsd x = g.xMint.value(), a = f.aMint.value();
    const MicroUsd fast = g.S.PFast().value_or(x);         // W17: the agreement test reads the fast median
    const arith_uint256 diff = fast >= a ? arith_uint256(fast - a) : arith_uint256(a - fast);
    if (diff * arith_uint256(BPS) > arith_uint256(std::max(0, ctx.params.divergeBpsAttest)) * arith_uint256(std::min(fast, a))) {
        throw std::runtime_error(strprintf("mint10-diverged: the pools' fast median %d and the attestors' %d micro-USD differ by more than %d bps, so minting is paused until they agree", fast, a, ctx.params.divergeBpsAttest));
    }
    pMint = std::min(x, a);
    source = a < x ? "a" : "x";
}

/** RED-4 by clause, PRICE-2 and RED-5 for a claim of `vault` at R with the bundle facts. Throws `claim-not-underwater`. */
struct ClaimFacts
{
    std::optional<MicroUsd> xClaim, aClaim, pClaim, pEmerg, xMint, aMint;
    std::string claimPath;
    CAmount residualZat;
    ClaimFacts() : residualZat(0) {}
};

ClaimFacts ClaimAt(const Context& ctx, const COutPoint& vaultOut, const VaultRecord& vault, int R, const BundleFactsW& f)
{
    const Params& p = ctx.params;
    ClaimFacts c;
    std::optional<Snapshot> S = SnapshotAt(ctx.st, p, R);
    c.xClaim = S.has_value() ? S->PClaim() : std::nullopt;
    c.xMint = S.has_value() ? S->PMint() : std::nullopt;
    c.pClaim = c.xClaim;
    if (f.armed) {
        CombinedPrices cp = PriceCombine(c.xMint, c.xClaim, f.aMint, f.aClaim);
        c.aMint = f.aMint;
        c.aClaim = f.aClaim;
        c.pClaim = cp.pClaim;
        c.pEmerg = cp.pEmerg;
    }
    if (IsUnderwater(vault.collateralZat, c.pClaim, vault.mintedCents, p.claimThresholdBps)) {
        c.claimPath = "a";
    } else {
        std::optional<NoticeRecord> notice = f.armed ? ctx.st.GetNotice(vaultOut) : std::nullopt;
        const bool persisted = notice.has_value() && (int64_t)R - notice->refHeight >= p.emergencyPersist && (int64_t)R - notice->refHeight <= p.emergencyNoticeTtl;
        if (!persisted || !IsUnderwater(vault.collateralZat, c.pEmerg, vault.mintedCents, p.emergencyRatioBps)) {
            throw std::runtime_error(strprintf("claim-not-underwater: the vault is not underwater at the reference height %d by either clause (pClaim %s, pEmerg %s, notice %s)",
                                               R, c.pClaim.has_value() ? std::to_string(c.pClaim.value()) : std::string("undefined"),
                                               c.pEmerg.has_value() ? std::to_string(c.pEmerg.value()) : std::string("undefined"),
                                               notice.has_value() ? strprintf("at refHeight %d", notice->refHeight) : std::string("none")));
        }
        c.claimPath = "b";
    }
    if (!c.pClaim.has_value()) throw std::runtime_error("claim-not-underwater: pClaim is undefined at the reference height");
    const int marginBps = c.claimPath == "a" ? p.claimThresholdBps : (int)BPS;   // R1: no margin under (b) alone
    const CAmount residual = ResidualZat(vault.collateralZat, ClaimantMaxZat(vault.mintedCents, marginBps, c.pClaim.value()));
    c.residualZat = residual >= p.residualMinZat ? residual : 0;
    return c;
}

/** NOT-1's preconditions for a notice on `vault` at R (the wallet's view of them): `notice-standing`, `notice-not-underwater`. */
struct NoticeFacts
{
    std::optional<MicroUsd> xClaim, aClaim, pEmerg;
};

NoticeFacts NoticeAt(const Context& ctx, const COutPoint& vaultOut, const VaultRecord& vault, int R, const BundleFactsW& f)
{
    const Params& p = ctx.params;
    NoticeFacts n;
    std::optional<NoticeRecord> standing = ctx.st.GetNotice(vaultOut);
    if (standing.has_value() && (int64_t)ctx.indexHeight + 1 - standing->height <= p.emergencyNoticeTtl) {
        throw std::runtime_error(strprintf("notice-standing: a notice for this vault stands since height %d (refHeight %d); another may be posted %d blocks after it",
                                           standing->height, standing->refHeight, p.emergencyNoticeTtl));
    }
    if (!f.armed) throw std::runtime_error(strprintf("notice-not-underwater: the snapshot at %d is not armed; a notice is meaningless before arming", R));
    std::optional<Snapshot> S = SnapshotAt(ctx.st, p, R);
    n.xClaim = S.has_value() ? S->PClaim() : std::nullopt;
    n.aClaim = f.aClaim;
    n.pEmerg = PriceCombine(S.has_value() ? S->PMint() : std::nullopt, n.xClaim, f.aMint, f.aClaim).pEmerg;
    if (!IsUnderwater(vault.collateralZat, n.pEmerg, vault.mintedCents, p.emergencyRatioBps)) {
        throw std::runtime_error(strprintf("notice-not-underwater: collateral %d zat at pEmerg %s covers %d cents at %d bps", vault.collateralZat,
                                           n.pEmerg.has_value() ? std::to_string(n.pEmerg.value()) : std::string("undefined"), vault.mintedCents, p.emergencyRatioBps));
    }
    return n;
}

/** The verdict a dry run must reach for a built transaction; throws the identifier on refusal. */
void DryRunOrThrow(Context& ctx, const BuiltTx& out)
{
    const int H = ctx.indexHeight + 1;
    std::optional<TxLogRecord> log = DryRun(ctx.index.MutableView(), ctx.index.ParamsAt(H), CTransaction(out.tx), H);
    switch (out.kind) {
    case BuiltKind::MINT:
        if (!log.has_value() || log->Type() != TxLogType::MINT) throw std::runtime_error("mint-dry-run: the dry run saw no mint");
        if (log->verdict != verdict::OK) throw std::runtime_error(log->verdict + ": the wallet's dry run of MINT-1..10 refused this mint at height " + std::to_string(H));
        return;
    case BuiltKind::CLAIM:
    case BuiltKind::REDEEM:
        if (!log.has_value() || log->Type() != TxLogType::REDEEM) throw std::runtime_error("vault-spend-malformed: the dry run saw no vault spend");
        if (log->verdict != verdict::OK) throw std::runtime_error(log->verdict + ": the wallet's dry run of RED-1..5 refused this spend at height " + std::to_string(H));
        return;
    case BuiltKind::NOTICE:
        if (!log.has_value() || log->Type() != TxLogType::CLAIM_NOTICE || !log->notice) throw std::runtime_error("notice-not-underwater: NOT-1 would not register this notice at height " + std::to_string(H));
        return;
    case BuiltKind::EQUIVOCATION:
        if (!log.has_value() || log->Type() != TxLogType::EQUIVOCATION) throw std::runtime_error("not-equivocation: EQV-1 would not eject at height " + std::to_string(H));
        return;
    case BuiltKind::REVIVE:
        if (!log.has_value() || log->Type() != TxLogType::ATTESTOR_REVIVE) throw std::runtime_error("not-dormant: REV-1 would not revive at height " + std::to_string(H));
        return;
    case BuiltKind::REGISTER:
        if (!log.has_value() || log->Type() != TxLogType::ATTESTOR_REGISTER) throw std::runtime_error("register-refused: REG-A1 would not admit this registration at height " + std::to_string(H));
        return;
    default:
        return;
    }
}

/** DER (r, s) -> compact r||s, 32 bytes each. */
std::array<unsigned char, 64> DerToCompact(const std::vector<unsigned char>& der)
{
    std::array<unsigned char, 64> out;
    out.fill(0);
    size_t pos = 3;
    for (int part = 0; part < 2 && pos < der.size(); part++) {
        size_t len = der[pos++];
        if (pos + len > der.size()) break;
        size_t skip = len > 32 ? len - 32 : 0;
        std::copy(der.begin() + pos + skip, der.begin() + pos + len, out.begin() + part * 32 + (32 - (len - skip)));
        pos += len + 1;
    }
    return out;
}

} // namespace

// ---------------------------------------------------------------- v3 preflights (before the carrier step)

namespace {

/** vout[0] of a MINT of `cents` in `g`'s class at pMint: max(required, 4 * FEE_MIN) rounded up to 1000 (MINT-5, K14). */
CAmount MintCollateral(const Context& ctx, Cents cents, const MintGateFacts& g, MicroUsd pMint)
{
    const Params& p = ctx.params;
    std::optional<CAmount> required = RequiredCollateralRounded(cents, MinRatioBps(p.baseRatioBps[g.termClass], g.S.sigmaMultBps), pMint);
    if (!required.has_value()) throw std::runtime_error("mint-unsatisfiable: the collateral requirement exceeds MAX_MONEY (K14)");
    CAmount collateral = std::max(required.value(), 4 * p.feeMin);
    if (collateral % 1000 != 0) collateral += 1000 - collateral % 1000;
    return collateral;
}

/** Audit F-1: the caller's bound on vout[0]; 0 = unbounded. */
void CheckMaxCollateral(CAmount collateral, CAmount maxCollateralZat)
{
    if (maxCollateralZat > 0 && collateral > maxCollateralZat) {
        throw std::runtime_error(strprintf("collateral-above-max: the mint needs %d zat of collateral, above the maxCollateralZat of %d", collateral, maxCollateralZat));
    }
}

/** Audit F-1: the claimant's floor on what reaches `to`; 0 = unbounded. */
void CheckMinOut(CAmount out, CAmount minOutZat)
{
    if (minOutZat > 0 && out < minOutZat) {
        throw std::runtime_error(strprintf("claim-out-below-min: the claim would pay %d zat to the destination, below the minOutZat of %d", out, minOutZat));
    }
}

} // namespace

MintPreflight PreflightMint(YellowbackWallet& yw, Cents cents, int lockBlocks, const std::optional<std::vector<unsigned char>>& bundle,
                            const std::string& from, CAmount maxCollateralZat)
{
    Context ctx(yw);
    // The funding address is judged before any price: bad-address precedes bundle-insufficient.
    const AddressChoice source = ParseAddressChoice(from, "from");
    if (source.kind == AddressChoice::SAPLING && !ctx.wallet.HaveSaplingSpendingKeyForAddress(source.sapling)) {
        throw std::runtime_error("bad-address: from: no spending key for " + source.text + " in this wallet");
    }
    MintPreflight pf;
    pf.refHeight = ctx.refHeight;
    const MintGateFacts g = MintGate(ctx, cents, lockBlocks, pf.refHeight);
    const BundleFactsW f = BundleAt(ctx, pf.refHeight, std::vector<unsigned char>(), bundle);
    pf.armed = f.armed;
    pf.bundle = f.bundle;
    pf.bundleSeqs = f.seqs;
    pf.xMint = g.xMint;
    pf.aMint = f.aMint;
    CombineMint(ctx, g, f, pf.pMint, pf.source);
    CheckMaxCollateral(MintCollateral(ctx, cents, g, pf.pMint.value()), maxCollateralZat);
    return pf;
}

ClaimPreflight PreflightClaim(YellowbackWallet& yw, const uint256& vaultTxid, const std::optional<std::vector<unsigned char>>& bundle,
                              CAmount minOutZat)
{
    Context ctx(yw);
    const COutPoint vaultOut(vaultTxid, 0);
    const VaultRecord vault = ctx.GetVault(vaultOut);
    if (vault.Status() != VaultStatus::ACTIVE) throw std::runtime_error(strprintf("vault-not-active: the vault is %s", VaultStatusName(vault.Status())));
    if ((int64_t)ctx.indexHeight < (int64_t)vault.claimHeight) {
        throw std::runtime_error(strprintf("claim-not-yet: the claim path opens at height %d (tip %d)", vault.claimHeight, ctx.indexHeight));
    }
    ClaimPreflight pf;
    pf.refHeight = ctx.spendRefHeight;
    pf.selector = OutPointSelector(vaultOut);
    const BundleFactsW f = BundleAt(ctx, pf.refHeight, pf.selector, bundle);
    const ClaimFacts c = ClaimAt(ctx, vaultOut, vault, pf.refHeight, f);
    pf.armed = f.armed;
    pf.bundle = f.bundle;
    pf.bundleSeqs = f.seqs;
    pf.xClaim = c.xClaim; pf.aClaim = c.aClaim; pf.pClaim = c.pClaim; pf.pEmerg = c.pEmerg; pf.xMint = c.xMint; pf.aMint = c.aMint;
    pf.claimPath = c.claimPath;
    pf.residualZat = c.residualZat;
    if (minOutZat > 0) {
        BuiltTx probe;
        AttestFeeFor(ctx, pf.refHeight, pf.selector, f, vault.collateralZat, probe);
        CheckMinOut(vault.collateralZat - FeeZat(vault.collateralZat, ctx.params.feeMin, ctx.params.feeBps) - probe.attestFeeZat - c.residualZat, minOutZat);
    }
    return pf;
}

NoticePreflight PreflightNotice(YellowbackWallet& yw, const uint256& vaultTxid, const std::optional<std::vector<unsigned char>>& bundle)
{
    Context ctx(yw);
    const COutPoint vaultOut(vaultTxid, 0);
    const VaultRecord vault = ctx.GetVault(vaultOut);
    if (vault.Status() != VaultStatus::ACTIVE) throw std::runtime_error(strprintf("vault-not-active: the vault is %s", VaultStatusName(vault.Status())));
    NoticePreflight pf;
    pf.refHeight = ctx.spendRefHeight;
    pf.selector = OutPointSelector(vaultOut);
    const BundleFactsW f = BundleAt(ctx, pf.refHeight, pf.selector, bundle);
    const NoticeFacts n = NoticeAt(ctx, vaultOut, vault, pf.refHeight, f);
    pf.bundle = f.bundle;
    pf.bundleSeqs = f.seqs;
    pf.xClaim = n.xClaim; pf.aClaim = n.aClaim; pf.pEmerg = n.pEmerg;
    pf.emergencyOpenAt = pf.refHeight + ctx.params.emergencyPersist;
    return pf;
}

// ---------------------------------------------------------------- v3 builders

BuiltTx BuildCarrier(YellowbackWallet& yw, const std::vector<unsigned char>& bundle, int refHeight,
                     const std::vector<unsigned char>& selector, CReserveKey& reservekey, const std::string& from)
{
    Context ctx(yw);
    const AddressChoice source = ParseAddressChoice(from, "from");
    if (refHeight < ctx.params.startHeight || refHeight > ctx.indexHeight) throw std::runtime_error(strprintf("index-below-start: reference height %d is not indexed", refHeight));
    const CPubKey key = ctx.FreshKey("yellowback-carrier");
    const CTxOut carrierOut = CarrierOutput(key, bundle, CARRIER_VALUE);
    const uint32_t expiry = ctx.Expiry(refHeight);

    BuiltTx out;
    out.kind = BuiltKind::CARRIER;
    out.freshKey = key;
    out.refHeight = refHeight;
    CarrierRecord rec;
    rec.refHeight = refHeight;
    rec.selector = selector;
    rec.bundle = bundle;
    rec.pk = key;
    rec.createdHeight = ctx.chainHeight;

    if (source.kind == AddressChoice::SAPLING) {
        libzcash::SaplingExtendedSpendingKey extsk;
        std::vector<SaplingNoteEntry> notes;
        std::vector<SaplingWitness> witnesses;
        uint256 anchor;
        do {   // P-2: priced at the conventional fee of the notes the fee itself selects
            notes.clear();
            witnesses.clear();
            ctx.SelectSapling(source, CARRIER_VALUE + ctx.fee, extsk, notes, witnesses, anchor);
            CMutableTransaction probe;
            probe.vout.push_back(carrierOut);
            if (!ctx.Reprice(NetworkFee(probe, notes.size(), 1))) break;
        } while (true);
        TransactionBuilder& b = ctx.NewBuilder(out.builder, expiry, anchor);
        for (size_t i = 0; i < notes.size(); i++) b.AddSaplingSpend(extsk, notes[i].note, witnesses[i]);
        b.AddTransparentOutput(carrierOut.scriptPubKey, carrierOut.nValue);
        b.SendChangeTo(source.sapling, extsk.expsk.full_viewing_key().ovk);
        out.fundedFrom = "sapling";
        out.carrier = rec;   // the outpoint is filled by FinishSapling()
        return out;
    }

    CMutableTransaction mtx;
    std::vector<std::pair<CScript, CAmount>> prevs;
    CScript onlyScript;
    if (source.kind == AddressChoice::TRANSPARENT) onlyScript = GetScriptForDestination(source.keyId);
    do {   // P-2: rebuilt at the conventional fee until the fee covers the shape it selects
        mtx = ctx.NewTx(expiry);
        mtx.vout.push_back(carrierOut);
        prevs.clear();
        const CAmount needed = CARRIER_VALUE + ctx.fee;
        const CAmount selected = ctx.SelectYec(needed, mtx, prevs, onlyScript.empty() ? nullptr : &onlyScript, source.text);
        const CAmount change = selected - needed;
        if (change > 0) {
            // An s1... `from` keeps its change: the main transaction is funded "from this address" too.
            if (source.kind == AddressChoice::TRANSPARENT) {
                mtx.vout.push_back(CTxOut(change, onlyScript));
            } else {
                CPubKey changeKey;
                if (!reservekey.GetReservedKey(changeKey)) throw std::runtime_error("keypool-empty: keypool ran out");
                mtx.vout.push_back(CTxOut(change, GetScriptForDestination(changeKey.GetID())));
            }
        }
    } while (ctx.Reprice(ctx.FeeOf(mtx, prevs, 0)));
    ctx.SignInputs(mtx, prevs, 0);
    out.tx = mtx;
    out.fundedFrom = "transparent";
    rec.outpoint = COutPoint(CTransaction(mtx).GetHash(), 0);
    out.carrier = rec;
    return out;
}

BuiltTx BuildMint(YellowbackWallet& yw, Cents cents, int lockBlocks, CReserveKey& reservekey, const std::string& from, const CarrierRecord& carrier,
                  CAmount maxCollateralZat)
{
    Context ctx(yw);
    const Params& p = ctx.params;
    const AddressChoice source = ParseAddressChoice(from, "from");
    ctx.CheckCarrier(carrier);
    const int R = carrier.refHeight;
    const MintGateFacts g = MintGate(ctx, cents, lockBlocks, R);
    const BundleFactsW f = BundleAt(ctx, R, std::vector<unsigned char>(), carrier.bundle.empty() ? std::nullopt : std::optional<std::vector<unsigned char>>(carrier.bundle));

    BuiltTx out;
    out.kind = BuiltKind::MINT;
    out.refHeight = R;
    out.carrier = carrier;
    out.xMint = g.xMint;
    CombineMint(ctx, g, f, out.pMint, out.source);
    const CAmount collateral = MintCollateral(ctx, cents, g, out.pMint.value());   // MINT-5, K14
    CheckMaxCollateral(collateral, maxCollateralZat);                              // before any key is drawn
    AttestFeeFor(ctx, R, std::vector<unsigned char>(), f, collateral, out);

    CPubKey owner = ctx.FreshKey("yellowback-vault");
    MintShape shape;
    shape.cents = cents;
    shape.termClass = g.termClass;
    shape.lockHeight = (uint32_t)g.lockHeight;
    shape.claimHeight = (uint32_t)g.claimHeight;
    shape.refHeight = R;
    shape.owner = owner;
    shape.collateralZat = collateral;
    shape.payee = ctx.Payee(R, std::vector<unsigned char>(owner.begin(), owner.end()));
    shape.feeZat = shape.payee.has_value() ? FeeZat(collateral, p.feeMin, p.feeBps) : 0;
    shape.attestPayee = out.attestPayeeKey;
    shape.attestFeeZat = out.attestFeeZat;
    int feeVout = -1, attestFeeVout = -1;
    std::vector<CTxOut> vout = MintOutputs(shape, feeVout, &attestFeeVout);
    CAmount outputs = 0;
    for (const CTxOut& o : vout) outputs += o.nValue;
    // P-2: the outputs plus the network fee, less CARRIER_VALUE (the carrier input pays it); ctx.fee is repriced below.

    out.freshKey = owner;
    out.termClass = g.termClass;
    out.lockHeight = shape.lockHeight;
    out.claimHeight = shape.claimHeight;
    out.collateralZat = collateral;
    out.feeZat = shape.feeZat;
    out.payee = shape.payee;
    out.feeVout = feeVout;
    out.attestFeeVout = attestFeeVout;
    out.ownerPubKey = owner;
    out.warning = ctx.KeypoolWarning();
    const uint32_t expiry = ctx.Expiry(R);

    if (source.kind == AddressChoice::SAPLING) {
        // Sapling shape (§4.6): notes of `from` fund the outputs; the carrier is the only transparent
        // input, signed after FinishSapling() (SignBuiltInputs), then dry-run (DryRunBuilt).
        libzcash::SaplingExtendedSpendingKey extsk;
        std::vector<SaplingNoteEntry> notes;
        std::vector<SaplingWitness> witnesses;
        uint256 anchor;
        do {   // P-2: priced at the conventional fee of the notes the fee itself selects
            notes.clear();
            witnesses.clear();
            ctx.SelectSapling(source, std::max<CAmount>(outputs + ctx.fee - CARRIER_VALUE, 0), extsk, notes, witnesses, anchor);
            CMutableTransaction probe;
            probe.vin.push_back(CTxIn(carrier.outpoint));
            probe.vout = vout;
            if (!ctx.Reprice(ctx.FeeOf(probe, {}, 0, &carrier, 0, notes.size(), 1))) break;
        } while (true);
        TransactionBuilder& b = ctx.NewBuilder(out.builder, expiry, anchor);
        for (size_t i = 0; i < notes.size(); i++) b.AddSaplingSpend(extsk, notes[i].note, witnesses[i]);
        b.AddTransparentInputUnsigned(carrier.outpoint, ctx.SpentScript(carrier.outpoint, CarrierOutput(carrier.pk, carrier.bundle, CARRIER_VALUE).scriptPubKey), CARRIER_VALUE);
        for (const CTxOut& o : vout) b.AddTransparentOutput(o.scriptPubKey, o.nValue);
        b.SendChangeTo(source.sapling, extsk.expsk.full_viewing_key().ovk);
        out.carrierVin = 0;
        out.fundedFrom = "sapling";
        return out;
    }

    CMutableTransaction mtx;
    std::vector<std::pair<CScript, CAmount>> prevs;
    CScript onlyScript;
    if (source.kind == AddressChoice::TRANSPARENT) onlyScript = GetScriptForDestination(source.keyId);
    do {   // P-2: rebuilt at the conventional fee until the fee covers the shape it selects
        mtx = ctx.NewTx(expiry);
        mtx.vout = vout;
        prevs.clear();
        const CAmount needed = outputs + ctx.fee - CARRIER_VALUE;
        const CAmount selected = ctx.SelectYec(std::max<CAmount>(needed, 0), mtx, prevs, onlyScript.empty() ? nullptr : &onlyScript, source.text);
        const CAmount change = selected - needed;
        if (change > 0) {
            CPubKey changeKey;
            if (!reservekey.GetReservedKey(changeKey)) throw std::runtime_error("keypool-empty: keypool ran out");
            mtx.vout.push_back(CTxOut(change, GetScriptForDestination(changeKey.GetID())));
        }
        mtx.vin.push_back(CTxIn(carrier.outpoint));   // vin[last] (§3.5); appended before any signature, since ZIP-243 commits to every prevout
        out.carrierVin = (int)mtx.vin.size() - 1;
    } while (ctx.Reprice(ctx.FeeOf(mtx, prevs, 0, &carrier, out.carrierVin)));
    ctx.SignInputs(mtx, prevs, 0);
    SignCarrierInput(mtx, (unsigned int)out.carrierVin, carrier, ctx.wallet, ctx.branchId);

    out.tx = mtx;
    out.fundedFrom = "transparent";
    out.ownYedOutputs.push_back(COutPoint(CTransaction(mtx).GetHash(), 1));
    DryRunOrThrow(ctx, out);   // MINT-1..10 with the bundle (§4.6): a VOID mint is unbuildable
    return out;
}

SendEstimate EstimateTransfer(YellowbackWallet& yw, int64_t amountCents, size_t recipients)
{
    Context ctx(yw);
    const yellowback::Params& p = ctx.params;
    SendEstimate e;
    e.amountCents = amountCents;
    e.recipients = recipients;
    const std::vector<YedCoin> coins = RankedCoins(ctx);
    std::vector<int64_t> cents;
    for (const YedCoin& c : coins) {
        cents.push_back(c.token.cents);
        e.spendableCents += c.token.cents;
    }
    const Selection s = SelectFloorAware(cents, amountCents, p.minOutput, MAX_YED_INPUTS, false);
    e.stage = SelectStageName(s.stage);
    if (s.ok) {
        e.workable = true;
        for (size_t i : s.inputs) e.inputs.push_back(coins[i]);
        e.selectedCents = s.selected;
        e.changeCents = s.change;
        return e;
    }
    e.error = s.insufficient ? "insufficient-yed" : (s.tooManyInputs ? "too-many-inputs" : "change-floor");
    const Alternatives alt = NearestWorkable(cents, amountCents, p.minOutput, MAX_YED_INPUTS);
    e.below = alt.below;
    e.above = alt.above;
    return e;
}

BuiltTx BuildTransfer(YellowbackWallet& yw, const std::vector<std::pair<CScript, int64_t>>& recipients, CReserveKey& reservekey)
{
    Context ctx(yw);
    const Params& p = ctx.params;
    if (recipients.empty()) throw std::runtime_error("no recipients");
    if (recipients.size() > MAX_ASSIGNMENTS - 1) throw std::runtime_error(strprintf("at most %u recipients per transaction", (unsigned)(MAX_ASSIGNMENTS - 1)));
    int64_t needed = 0;
    for (const auto& r : recipients) {
        if (r.second < p.minOutput || r.second > p.maxOutput) {
            throw std::runtime_error(strprintf("bad-xfer-amount: each amount must be between %d and %d cents", p.minOutput, p.maxOutput));
        }
        needed += r.second;
    }
    int64_t change = 0;
    std::vector<YedCoin> sel = SelectYed(ctx, needed, change);

    CMutableTransaction mtx = ctx.NewTx(ctx.Expiry(ctx.refHeight));
    BuiltTx out;
    out.kind = BuiltKind::TRANSFER;
    out.refHeight = ctx.refHeight;
    for (const YedCoin& c : sel) {
        mtx.vin.push_back(CTxIn(c.outpoint));
        out.yedInputs.insert(c.outpoint);
    }
    std::vector<Assignment> assignments;
    for (size_t i = 0; i < recipients.size(); i++) {
        mtx.vout.push_back(CTxOut(TOKEN_VALUE, recipients[i].first));
        assignments.push_back(Assignment((uint8_t)i, (uint32_t)recipients[i].second));
    }
    if (change > 0) {
        CPubKey changeKey = ctx.FreshKey("yellowback-change");
        out.freshKey = changeKey;
        mtx.vout.push_back(CTxOut(TOKEN_VALUE, GetScriptForDestination(changeKey.GetID())));
        assignments.push_back(Assignment((uint8_t)recipients.size(), (uint32_t)change));
    }
    std::vector<unsigned char> payload = EncodePayload(Payload::Transfer(assignments));
    if (payload.empty()) throw std::runtime_error("cannot encode the transfer payload");
    mtx.vout.push_back(CTxOut(0, PayloadScript(payload)));

    // YEC accounting: token inputs carry TOKEN_VALUE each; outputs need TOKEN_VALUE each plus the fee.
    const CAmount tokenIn = (CAmount)sel.size() * TOKEN_VALUE;
    const CAmount tokenOut = (CAmount)(recipients.size() + (change > 0 ? 1 : 0)) * TOKEN_VALUE;
    std::vector<std::pair<CScript, CAmount>> prevs;
    const unsigned int firstYec = mtx.vin.size();
    std::vector<std::pair<CScript, CAmount>> yedPrevs;
    for (const YedCoin& c : sel) yedPrevs.push_back(std::make_pair(c.token.scriptPubKey, c.token.nValue));
    std::vector<std::pair<CScript, CAmount>> allPrevs;
    const CMutableTransaction unfunded = mtx;
    do {   // P-2: rebuilt at the conventional fee until the fee covers the shape it selects
        mtx = unfunded;
        prevs.clear();
        const CAmount yecNeeded = tokenOut + ctx.fee - tokenIn;
        CAmount selectedYec = ctx.SelectYec(yecNeeded, mtx, prevs);
        CAmount yecChange = selectedYec - yecNeeded;
        if (yecChange > 0) {
            CPubKey changeKey;
            if (!reservekey.GetReservedKey(changeKey)) throw std::runtime_error("keypool-empty: keypool ran out");
            mtx.vout.push_back(CTxOut(yecChange, GetScriptForDestination(changeKey.GetID())));
        }
        allPrevs = yedPrevs;   // vin[0 .. firstYec) are the YED inputs, the YEC inputs follow
        allPrevs.insert(allPrevs.end(), prevs.begin(), prevs.end());
    } while (ctx.Reprice(ctx.FeeOf(mtx, allPrevs, 0)));
    // Sign YED inputs (P2PKH, mine) then YEC inputs.
    for (size_t i = 0; i < sel.size(); i++) {
        if (!SignSignature(ctx.wallet, sel[i].token.scriptPubKey, mtx, V4TxData(CTransaction(mtx)), i, sel[i].token.nValue, SIGHASH_ALL, ctx.branchId)) {
            throw std::runtime_error(strprintf("failed to sign YED input %u", (unsigned)i));
        }
    }
    ctx.SignInputs(mtx, prevs, firstYec);

    out.tx = mtx;
    const uint256 txid = CTransaction(mtx).GetHash();
    for (size_t i = 0; i < recipients.size(); i++) {
        if (yw.IsMineScript(recipients[i].first)) out.ownYedOutputs.push_back(COutPoint(txid, i));
    }
    if (change > 0) {
        out.changeVout = (int)recipients.size();
        out.ownYedOutputs.push_back(COutPoint(txid, recipients.size()));
    }
    out.changeCents = change;
    return out;
}

BuiltTx BuildRedeem(YellowbackWallet& yw, const uint256& vaultTxid, const std::string& to)
{
    Context ctx(yw);
    const COutPoint vaultOut(vaultTxid, 0);
    const VaultRecord vault = ctx.GetVault(vaultOut);
    if (!vault.IsOpen()) throw std::runtime_error(strprintf("vault-not-active: the vault is %s", VaultStatusName(vault.Status())));
    if (!yw.IsMineVault(vault)) throw std::runtime_error("vault-not-owned: the vault owner key is not in this wallet");
    if ((int64_t)ctx.indexHeight < (int64_t)vault.lockHeight) {
        throw std::runtime_error(strprintf("vault-locked: the vault is locked until height %d (tip %d)", vault.lockHeight, ctx.indexHeight));
    }
    // ACTIVE: the owner-path REDEEM; VOID: the release (L14, K3): an ordinary spend no rule polices.
    const BuiltKind kind = vault.Status() == VaultStatus::ACTIVE ? BuiltKind::REDEEM : BuiltKind::RELEASE;
    return BuildVaultSpend(ctx, kind, vaultOut, vault, to, ctx.spendRefHeight);
}

BuiltTx BuildClaim(YellowbackWallet& yw, const uint256& vaultTxid, const std::string& to, const CarrierRecord& carrier, CAmount minOutZat)
{
    Context ctx(yw);
    const COutPoint vaultOut(vaultTxid, 0);
    const VaultRecord vault = ctx.GetVault(vaultOut);
    if (vault.Status() != VaultStatus::ACTIVE) throw std::runtime_error(strprintf("vault-not-active: the vault is %s", VaultStatusName(vault.Status())));
    if ((int64_t)ctx.indexHeight < (int64_t)vault.claimHeight) {
        throw std::runtime_error(strprintf("claim-not-yet: the claim path opens at height %d (tip %d)", vault.claimHeight, ctx.indexHeight));
    }
    ctx.CheckCarrier(carrier);
    const int R = carrier.refHeight;
    const std::vector<unsigned char> selector = OutPointSelector(vaultOut);
    if (carrier.selector != selector) throw std::runtime_error("carrier-selector: the carrier was built for another selector");
    const BundleFactsW f = BundleAt(ctx, R, selector, carrier.bundle.empty() ? std::nullopt : std::optional<std::vector<unsigned char>>(carrier.bundle));
    const ClaimFacts c = ClaimAt(ctx, vaultOut, vault, R, f);
    ClaimExtras extras;
    extras.carrier = carrier;
    extras.residualZat = c.residualZat;
    BuiltTx probe;
    AttestFeeFor(ctx, R, selector, f, vault.collateralZat, probe);
    extras.attestKey = probe.attestPayeeKey;
    extras.attestFeeZat = probe.attestFeeZat;
    BuiltTx out = BuildVaultSpend(ctx, BuiltKind::CLAIM, vaultOut, vault, to, R, &extras);
    CheckMinOut(out.collateralOut, minOutZat);   // unsigned so far: nothing is committed or locked
    out.armed = f.armed;
    out.bundleSeqs = f.seqs;
    out.attestPayee = probe.attestPayee;
    out.xClaim = c.xClaim; out.aClaim = c.aClaim; out.pClaim = c.pClaim; out.pEmerg = c.pEmerg; out.xMint = c.xMint; out.aMint = c.aMint;
    out.claimPath = c.claimPath;
    return out;
}

BuiltTx BuildClaimNotice(YellowbackWallet& yw, const uint256& vaultTxid, CReserveKey& reservekey, const CarrierRecord& carrier)
{
    Context ctx(yw);
    const COutPoint vaultOut(vaultTxid, 0);
    const VaultRecord vault = ctx.GetVault(vaultOut);
    if (vault.Status() != VaultStatus::ACTIVE) throw std::runtime_error(strprintf("vault-not-active: the vault is %s", VaultStatusName(vault.Status())));
    ctx.CheckCarrier(carrier);
    const int R = carrier.refHeight;
    const std::vector<unsigned char> selector = OutPointSelector(vaultOut);
    if (carrier.selector != selector) throw std::runtime_error("carrier-selector: the carrier was built for another selector");
    const BundleFactsW f = BundleAt(ctx, R, selector, carrier.bundle.empty() ? std::nullopt : std::optional<std::vector<unsigned char>>(carrier.bundle));
    const NoticeFacts n = NoticeAt(ctx, vaultOut, vault, R, f);

    BuiltTx out;
    out.kind = BuiltKind::NOTICE;
    out.refHeight = R;
    out.carrier = carrier;
    out.armed = f.armed;
    out.bundleSeqs = f.seqs;
    out.xClaim = n.xClaim; out.aClaim = n.aClaim; out.pEmerg = n.pEmerg;
    out.emergencyOpenAt = R + ctx.params.emergencyPersist;
    std::vector<unsigned char> payload = EncodePayload(Payload::ClaimNotice(vaultOut, (uint32_t)R));
    if (payload.empty()) throw std::runtime_error("cannot encode the notice payload");
    CMutableTransaction mtx;
    std::vector<std::pair<CScript, CAmount>> prevs;
    do {   // P-2: rebuilt at the conventional fee until the fee covers the shape it selects
        mtx = ctx.NewTx(ctx.Expiry(R));
        mtx.vout.push_back(CTxOut(0, PayloadScript(payload)));
        prevs.clear();
        const CAmount needed = ctx.fee - CARRIER_VALUE;
        const CAmount selected = ctx.SelectYec(std::max<CAmount>(needed, 0), mtx, prevs);
        const CAmount change = selected - needed;
        if (change > 0) {
            CPubKey changeKey;
            if (!reservekey.GetReservedKey(changeKey)) throw std::runtime_error("keypool-empty: keypool ran out");
            mtx.vout.push_back(CTxOut(change, GetScriptForDestination(changeKey.GetID())));
        }
        mtx.vin.push_back(CTxIn(carrier.outpoint));
        out.carrierVin = (int)mtx.vin.size() - 1;
    } while (ctx.Reprice(ctx.FeeOf(mtx, prevs, 0, &carrier, out.carrierVin)));
    ctx.SignInputs(mtx, prevs, 0);
    SignCarrierInput(mtx, (unsigned int)out.carrierVin, carrier, ctx.wallet, ctx.branchId);
    out.tx = mtx;
    DryRunOrThrow(ctx, out);   // NOT-1 at the next height
    return out;
}

BuiltTx BuildRegisterAttestor(YellowbackWallet& yw, CAmount bondZat, int lockBlocks, uint8_t flags, CReserveKey& reservekey)
{
    Context ctx(yw);
    const Params& p = ctx.params;
    if (bondZat < p.bondMin) throw std::runtime_error(strprintf("bond-below-min: the bond must be at least %s YEC", FormatMoney(p.bondMin)));
    if (lockBlocks < p.bondMinLock) throw std::runtime_error(strprintf("lock-below-min: the lock must be at least %d blocks", p.bondMinLock));
    const int64_t locktime = (int64_t)ctx.chainHeight + 1 + lockBlocks;
    if (locktime >= (int64_t)LOCKTIME_THRESHOLD) throw std::runtime_error("lock-below-min: bondLocktime reaches LOCKTIME_THRESHOLD");
    const CPubKey hot = ctx.FreshKey("yellowback-attestor");
    const CPubKey bond = ctx.FreshKey("yellowback-bond");
    const CScript bondScript = BondScript(bond, (uint32_t)locktime);
    if (bondScript.empty()) throw std::runtime_error("cannot build the bond script");
    std::vector<unsigned char> payload = EncodePayload(Payload::AttestorRegister(hot, bond, (uint32_t)locktime, flags));
    if (payload.empty()) throw std::runtime_error("cannot encode the registration payload");

    BuiltTx out;
    out.kind = BuiltKind::REGISTER;
    out.refHeight = ctx.indexHeight;
    out.attestorPubKey = hot;
    out.bondPubKey = bond;
    out.bondScript = bondScript;
    out.bondZat = bondZat;
    out.bondLocktime = (uint32_t)locktime;
    out.flags = flags;
    out.warning = ctx.KeypoolWarning();
    CMutableTransaction mtx;
    std::vector<std::pair<CScript, CAmount>> prevs;
    do {   // P-2: rebuilt at the conventional fee until the fee covers the shape it selects
        mtx = ctx.NewTx(ctx.Expiry(ctx.chainHeight));
        mtx.vout.push_back(CTxOut(bondZat, P2SHScript(bondScript)));       // vout[0] the bond
        mtx.vout.push_back(CTxOut(0, PayloadScript(payload)));             // vout[1] the payload
        prevs.clear();
        const CAmount needed = bondZat + ctx.fee;
        const CAmount selected = ctx.SelectYec(needed, mtx, prevs);
        const CAmount change = selected - needed;
        if (change > 0) {
            CPubKey changeKey;
            if (!reservekey.GetReservedKey(changeKey)) throw std::runtime_error("keypool-empty: keypool ran out");
            mtx.vout.push_back(CTxOut(change, GetScriptForDestination(changeKey.GetID())));
        }
    } while (ctx.Reprice(ctx.FeeOf(mtx, prevs, 0)));
    ctx.SignInputs(mtx, prevs, 0);
    out.tx = mtx;
    DryRunOrThrow(ctx, out);   // REG-A1 at the next height
    return out;
}

BuiltTx BuildWithdrawBond(YellowbackWallet& yw, uint16_t seq, const std::string& to)
{
    Context ctx(yw);
    const AddressChoice dest = ParseAddressChoice(to, "to");
    std::optional<AttestorRecord> rec = ctx.st.GetAttestor(seq);
    if (!rec.has_value()) throw std::runtime_error(strprintf("attest-unknown-seq: no attestor with seq %u", (unsigned)seq));
    const CPubKey bond = rec->BondKey();
    if (!bond.IsValid() || !ctx.wallet.HaveKey(bond.GetID())) throw std::runtime_error(strprintf("attest-key-not-held: the bond key of seq %u is not in this wallet", (unsigned)seq));
    if (rec->bondSpentHeight != 0 || !ctx.CoinAvailable(rec->bondOutpoint)) throw std::runtime_error(strprintf("bond-spent: the bond of seq %u is already spent", (unsigned)seq));
    if ((int64_t)ctx.chainHeight < (int64_t)rec->bondLocktime) {
        throw std::runtime_error(strprintf("bond-locked: the bond is locked until height %u (tip %d)", rec->bondLocktime, ctx.chainHeight));
    }
    // P-2: one bond input, one P2PKH output or one (padded) Sapling note; the fee never moves the shape.
    CMutableTransaction probe;
    probe.vin.push_back(CTxIn(rec->bondOutpoint, CScript() << valtype(MAX_SIG_SIZE, 0x30) << ToByteVector(BondScript(bond, rec->bondLocktime))));
    if (dest.kind != AddressChoice::SAPLING) probe.vout.push_back(CTxOut(0, GetScriptForDestination(CKeyID())));
    ctx.Reprice(NetworkFee(probe, 0, dest.kind == AddressChoice::SAPLING ? 1 : 0));
    const CAmount bondOut = rec->bondZat - ctx.fee;
    if (bondOut <= 0) throw std::runtime_error("vault-value-too-small: the bond does not cover the network fee");

    BuiltTx out;
    out.kind = BuiltKind::WITHDRAW;
    out.refHeight = ctx.indexHeight;
    out.seq = seq;
    out.bondPubKey = bond;
    out.bondZat = rec->bondZat;
    out.bondLocktime = rec->bondLocktime;
    out.bondScript = BondScript(bond, rec->bondLocktime);
    out.collateralOut = bondOut;
    out.bondVin = 0;
    const uint32_t expiry = ctx.Expiry(ctx.chainHeight);
    if (dest.kind == AddressChoice::SAPLING) {
        TransactionBuilder& b = ctx.NewBuilder(out.builder, expiry);
        b.SetLockTime(rec->bondLocktime);
        b.AddTransparentInputUnsigned(rec->bondOutpoint, ctx.SpentScript(rec->bondOutpoint, P2SHScript(out.bondScript)), rec->bondZat, 0xFFFFFFFE);
        HDSeed seed = ctx.wallet.GetHDSeedForRPC();
        b.AddSaplingOutput(ovkForShieldingFromTaddr(seed), dest.sapling, bondOut, std::nullopt);
        out.collateralTo = dest.text;
        return out;
    }
    CScript destScript;
    if (dest.kind == AddressChoice::TRANSPARENT) {
        destScript = GetScriptForDestination(dest.keyId);
        out.collateralTo = dest.text;
    } else {
        const CPubKey fresh = ctx.FreshKey("yellowback-bond-withdrawal");
        out.freshKey = fresh;
        destScript = GetScriptForDestination(fresh.GetID());
        out.collateralTo = KeyIO(::Params()).EncodeDestination(CTxDestination(fresh.GetID()));
    }
    CMutableTransaction mtx = ctx.NewTx(expiry);
    mtx.nLockTime = rec->bondLocktime;
    mtx.vin.push_back(CTxIn(rec->bondOutpoint, CScript(), 0xFFFFFFFE));
    mtx.vout.push_back(CTxOut(bondOut, destScript));
    SignBondInput(mtx, 0, bond, rec->bondLocktime, rec->bondZat, ctx.wallet, ctx.branchId);
    out.tx = mtx;
    return out;
}

Attestation SignAttestationGuarded(YellowbackWallet& yw, uint16_t seq, MicroUsd priceMicroUsd, int citedHeight, bool& reused)
{
    Context ctx(yw);
    const Params& p = ctx.params;
    reused = false;
    std::optional<AttestorRecord> rec = ctx.st.GetAttestor(seq);
    if (!rec.has_value()) throw std::runtime_error(strprintf("attest-unknown-seq: no attestor with seq %u", (unsigned)seq));
    const CPubKey hot = rec->AttestorKey();
    CKey key;
    if (!hot.IsValid() || !ctx.wallet.GetKey(hot.GetID(), key)) throw std::runtime_error(strprintf("attest-key-not-held: the hot key of seq %u is not in this wallet", (unsigned)seq));
    if (priceMicroUsd < PRICE_MIN || priceMicroUsd > PRICE_MAX) throw std::runtime_error(strprintf("attest-range: priceMicroUsd must be in [%d, %d]", PRICE_MIN, PRICE_MAX));
    if (citedHeight < p.startHeight || citedHeight > ctx.chainHeight) {
        throw std::runtime_error(strprintf("attest-stale: citedHeight %d must be in [%d, %d]", citedHeight, p.startHeight, ctx.chainHeight));
    }
    Attestation a;
    a.seq = seq;
    a.priceMicroUsd = (uint32_t)priceMicroUsd;
    a.citedHeight = (uint32_t)citedHeight;
    // S16: the persisted guard decides before anything is signed. Keyed on the cited block's hash as well
    // (audit C-5): after a reorg across citedHeight the earlier line is for another block, so a fresh
    // signature for this one is not equivocation (EQV-1 binds the hash too).
    const uint256 citedHash = ctx.BlockHashAt(citedHeight);
    std::optional<SignedAttestation> prior = yw.LookupSigned(seq, (uint32_t)citedHeight, citedHash);
    if (prior.has_value()) {
        if (prior->priceMicroUsd != (uint32_t)priceMicroUsd) {
            throw std::runtime_error(strprintf("equivocation-guard: seq %u already signed %u for height %d", (unsigned)seq, prior->priceMicroUsd, citedHeight));
        }
        a.sig = prior->sig;
        reused = true;
        return a;
    }
    const uint256 msg = AttestMessage(seq, a.priceMicroUsd, a.citedHeight, citedHash);
    std::vector<unsigned char> der;
    if (!key.Sign(msg, der)) throw std::runtime_error("attestation signature failed");
    a.sig = DerToCompact(der);   // libsecp256k1 signs low-S; the compact form is r || s
    if (!VerifyCompactSig(hot, msg, a.sig)) throw std::runtime_error("attestation signature does not verify");
    SignedAttestation recSigned;
    recSigned.seq = seq;
    recSigned.citedHeight = a.citedHeight;
    recSigned.priceMicroUsd = a.priceMicroUsd;
    recSigned.sig = a.sig;
    recSigned.blockHash = citedHash;
    if (!yw.RecordSigned(recSigned)) {
        // Audit C-9: the datadir path goes to the log, never into the RPC error text.
        LogPrintf("yellowback: guard-write-failed: cannot append to %s\n", YellowbackWallet::SignedFile().string());
        throw std::runtime_error("guard-write-failed: the equivocation guard could not be written; nothing was returned");
    }
    return a;
}

BuiltTx BuildRevive(YellowbackWallet& yw, uint16_t seq, MicroUsd priceMicroUsd, CReserveKey& reservekey)
{
    Context ctx(yw);
    std::optional<AttestorRecord> rec = ctx.st.GetAttestor(seq);
    if (!rec.has_value()) throw std::runtime_error(strprintf("attest-unknown-seq: no attestor with seq %u", (unsigned)seq));
    if (rec->Status() != AttestorStatus::DORMANT) throw std::runtime_error(strprintf("not-dormant: seq %u is %s", (unsigned)seq, AttestorStatusName(rec->Status())));
    const CPubKey hot = rec->AttestorKey();
    if (!hot.IsValid() || !ctx.wallet.HaveKey(hot.GetID())) throw std::runtime_error(strprintf("attest-key-not-held: the hot key of seq %u is not in this wallet", (unsigned)seq));
    const int cited = ctx.indexHeight - g_yellowbackMintLag;
    bool reused = false;
    const Attestation a = SignAttestationGuarded(yw, seq, priceMicroUsd, cited, reused);

    BuiltTx out;
    out.kind = BuiltKind::REVIVE;
    out.refHeight = cited;
    out.seq = seq;
    out.attestation = a;
    std::vector<unsigned char> payload = EncodePayload(Payload::AttestorRevive(a.seq, a.priceMicroUsd, a.citedHeight, a.sig));
    if (payload.empty()) throw std::runtime_error("cannot encode the revive payload");
    CMutableTransaction mtx;
    std::vector<std::pair<CScript, CAmount>> prevs;
    do {   // P-2: rebuilt at the conventional fee until the fee covers the shape it selects
        mtx = ctx.NewTx(ctx.Expiry(cited));
        mtx.vout.push_back(CTxOut(0, PayloadScript(payload)));
        prevs.clear();
        const CAmount selected = ctx.SelectYec(ctx.fee, mtx, prevs);
        const CAmount change = selected - ctx.fee;
        if (change > 0) {
            CPubKey changeKey;
            if (!reservekey.GetReservedKey(changeKey)) throw std::runtime_error("keypool-empty: keypool ran out");
            mtx.vout.push_back(CTxOut(change, GetScriptForDestination(changeKey.GetID())));
        }
    } while (ctx.Reprice(ctx.FeeOf(mtx, prevs, 0)));
    ctx.SignInputs(mtx, prevs, 0);
    out.tx = mtx;
    DryRunOrThrow(ctx, out);   // REV-1 at the next height
    return out;
}

void CheckEquivocation(YellowbackWallet& yw, const Attestation& a, const Attestation& b)
{
    Context ctx(yw);
    if (a.seq != b.seq) throw std::runtime_error(strprintf("not-equivocation: different seqs (%u, %u)", (unsigned)a.seq, (unsigned)b.seq));
    if (a.citedHeight != b.citedHeight) throw std::runtime_error(strprintf("not-equivocation: different cited heights (%u, %u)", a.citedHeight, b.citedHeight));
    if (a.priceMicroUsd == b.priceMicroUsd) throw std::runtime_error("not-equivocation: the prices are equal");
    std::optional<AttestorRecord> rec = ctx.st.GetAttestor(a.seq);
    if (!rec.has_value()) throw std::runtime_error(strprintf("not-equivocation: no attestor with seq %u", (unsigned)a.seq));
    if (rec->Status() == AttestorStatus::WITHDRAWN || rec->Status() == AttestorStatus::EJECTED) {
        throw std::runtime_error(strprintf("not-equivocation: seq %u is %s", (unsigned)a.seq, AttestorStatusName(rec->Status())));
    }
    if ((int64_t)a.citedHeight < ctx.params.startHeight || (int64_t)a.citedHeight > ctx.chainHeight) {
        throw std::runtime_error(strprintf("not-equivocation: cited height %u is not in this chain's index", a.citedHeight));
    }
    const uint256 blockHash = ctx.BlockHashAt((int)a.citedHeight);
    const CPubKey hot = rec->AttestorKey();
    if (!VerifyCompactSig(hot, AttestMessage(a.seq, a.priceMicroUsd, a.citedHeight, blockHash), a.sig)) throw std::runtime_error("not-equivocation: attestation A does not verify on this chain");
    if (!VerifyCompactSig(hot, AttestMessage(b.seq, b.priceMicroUsd, b.citedHeight, blockHash), b.sig)) throw std::runtime_error("not-equivocation: attestation B does not verify on this chain");
}

BuiltTx BuildEquivocation(YellowbackWallet& yw, const Attestation& a, const Attestation& b, CReserveKey& reservekey, const CarrierRecord& carrier)
{
    CheckEquivocation(yw, a, b);
    Context ctx(yw);
    ctx.CheckCarrier(carrier);
    Bundle bundle;
    bundle.atts = { a, b };
    if (carrier.bundle != EncodeBundle(bundle)) throw std::runtime_error("carrier-selector: the carrier does not commit to these two attestations");

    BuiltTx out;
    out.kind = BuiltKind::EQUIVOCATION;
    out.refHeight = carrier.refHeight;
    out.carrier = carrier;
    out.seq = a.seq;
    out.attestation = a;
    out.attestationB = b;
    std::vector<unsigned char> payload = EncodePayload(Payload::Equivocation());
    if (payload.empty()) throw std::runtime_error("cannot encode the equivocation payload");
    CMutableTransaction mtx;
    std::vector<std::pair<CScript, CAmount>> prevs;
    do {   // P-2: rebuilt at the conventional fee until the fee covers the shape it selects
        mtx = ctx.NewTx(ctx.Expiry(carrier.refHeight));
        mtx.vout.push_back(CTxOut(0, PayloadScript(payload)));
        prevs.clear();
        const CAmount needed = ctx.fee - CARRIER_VALUE;
        const CAmount selected = ctx.SelectYec(std::max<CAmount>(needed, 0), mtx, prevs);
        const CAmount change = selected - needed;
        if (change > 0) {
            CPubKey changeKey;
            if (!reservekey.GetReservedKey(changeKey)) throw std::runtime_error("keypool-empty: keypool ran out");
            mtx.vout.push_back(CTxOut(change, GetScriptForDestination(changeKey.GetID())));
        }
        mtx.vin.push_back(CTxIn(carrier.outpoint));
        out.carrierVin = (int)mtx.vin.size() - 1;
    } while (ctx.Reprice(ctx.FeeOf(mtx, prevs, 0, &carrier, out.carrierVin)));
    ctx.SignInputs(mtx, prevs, 0);
    SignCarrierInput(mtx, (unsigned int)out.carrierVin, carrier, ctx.wallet, ctx.branchId);
    out.tx = mtx;
    DryRunOrThrow(ctx, out);   // EQV-1 at the next height
    return out;
}

BuiltTx BuildSweepCarriers(YellowbackWallet& yw, const std::vector<CarrierRecord>& lapsed)
{
    Context ctx(yw);
    BuiltTx out;
    out.kind = BuiltKind::SWEEP_CARRIERS;
    out.refHeight = ctx.indexHeight;
    for (const CarrierRecord& c : lapsed) {
        if (ctx.CoinAvailable(c.outpoint)) out.sweptRecords.push_back(c);
        else out.staleRecords.push_back(c);
    }
    if (out.sweptRecords.empty()) throw std::runtime_error("nothing-to-sweep: no lapsed carrier is spendable");
    const CAmount total = (CAmount)out.sweptRecords.size() * CARRIER_VALUE;
    // P-2: the carriers in, one P2PKH out; the fee never moves the shape.
    CMutableTransaction probe;
    for (const CarrierRecord& c : out.sweptRecords) probe.vin.push_back(CTxIn(c.outpoint, PendingCarrierSig(c)));
    probe.vout.push_back(CTxOut(0, GetScriptForDestination(CKeyID())));
    ctx.Reprice(NetworkFee(probe));
    const CAmount value = total - ctx.fee;
    if (value <= 0) throw std::runtime_error("nothing-to-sweep: the carriers do not cover the network fee");
    const CPubKey dest = ctx.FreshKey("yellowback-carrier-sweep");
    out.freshKey = dest;
    out.collateralOut = value;
    out.collateralTo = KeyIO(::Params()).EncodeDestination(CTxDestination(dest.GetID()));
    CMutableTransaction mtx = ctx.NewTx(ctx.Expiry(ctx.chainHeight));
    for (const CarrierRecord& c : out.sweptRecords) mtx.vin.push_back(CTxIn(c.outpoint));
    mtx.vout.push_back(CTxOut(value, GetScriptForDestination(dest.GetID())));
    for (size_t i = 0; i < out.sweptRecords.size(); i++) SignCarrierInput(mtx, (unsigned int)i, out.sweptRecords[i], ctx.wallet, ctx.branchId);
    out.tx = mtx;
    out.sweptCarriers = out.sweptRecords.size();
    return out;
}

void SignBuiltInputs(BuiltTx& out, const CKeyStore& keystore, uint32_t branchId)
{
    if (out.builder) throw std::runtime_error("FinishSapling must run before SignBuiltInputs");
    if (out.carrierVin >= 0 && out.carrier.has_value() && out.tx.vin[out.carrierVin].scriptSig.empty()) {
        SignCarrierInput(out.tx, (unsigned int)out.carrierVin, out.carrier.value(), keystore, branchId);
    }
    if (out.bondVin >= 0 && out.tx.vin[out.bondVin].scriptSig.empty()) {
        SignBondInput(out.tx, (unsigned int)out.bondVin, out.bondPubKey, out.bondLocktime, out.bondZat, keystore, branchId);
    }
    if (out.kind == BuiltKind::MINT) {
        out.ownYedOutputs.clear();
        out.ownYedOutputs.push_back(COutPoint(CTransaction(out.tx).GetHash(), 1));
    }
}

void DryRunBuilt(YellowbackWallet& yw, const BuiltTx& out)
{
    Context ctx(yw);
    DryRunOrThrow(ctx, out);
}

BuiltTx BuildSweep(YellowbackWallet& yw, const uint256& vaultTxid, const std::string& to)
{
    Context ctx(yw);
    const COutPoint vaultOut(vaultTxid, 0);
    const VaultRecord vault = ctx.GetVault(vaultOut);
    if (vault.Status() != VaultStatus::ACTIVE) throw std::runtime_error(strprintf("vault-not-active: the vault is %s", VaultStatusName(vault.Status())));
    if (!yw.IsMineVault(vault)) throw std::runtime_error("vault-not-owned: the vault owner key is not in this wallet");
    if ((int64_t)ctx.indexHeight < (int64_t)vault.lockHeight) {
        throw std::runtime_error(strprintf("vault-locked: the vault is locked until height %d (tip %d)", vault.lockHeight, ctx.indexHeight));
    }
    return BuildVaultSpend(ctx, BuiltKind::SWEEP, vaultOut, vault, to, ctx.spendRefHeight);
}

void FinishSapling(BuiltTx& out)
{
    if (!out.builder) return;
    TransactionBuilderResult r = out.builder->Build();
    if (r.IsError()) throw std::runtime_error("Sapling build failed: " + r.GetError());
    out.tx = CMutableTransaction(r.GetTxOrThrow());
    out.builder.reset();
    const uint256 txid = CTransaction(out.tx).GetHash();
    if (out.kind == BuiltKind::MINT) out.ownYedOutputs.push_back(COutPoint(txid, 1));   // provisional: SignBuiltInputs recomputes after the carrier is signed
    if (out.kind == BuiltKind::CARRIER && out.carrier.has_value()) out.carrier->outpoint = COutPoint(txid, 0);
}

} // namespace yellowback
