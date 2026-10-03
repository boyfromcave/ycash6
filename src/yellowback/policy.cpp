// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yellowback/policy.h"

#include "chainparams.h"
#include "consensus/upgrades.h"
#include "main.h"
#include "policy/policy.h"
#include "script/interpreter.h"
#include "script/script_error.h"
#include "txmempool.h"
#include "util/time.h"
#include "yellowback/math.h"
#include "yellowback/payload.h"
#include "yellowback/state.h"
#include "yellowback/tag.h"

namespace yellowback {

namespace policy {

CScript BuildTagScript(const YellowbackIndex& index, int64_t now)
{
    const MinerStatus s = index.GetMinerStatus(now);
    if (s.kind == "none" || !s.payoutKey.has_value()) return CScript();
    const QuoteHolder q = index.GetQuote();
    CoinbaseTag tag;
    tag.flags = s.signal ? 0x01 : 0x00;
    tag.priceMicroUsd = s.kind == "quote" ? q.priceMicroUsd : TAG_PRICE_SIGNAL_ONLY;
    tag.sourceMask = s.kind == "quote" ? q.sourceMask : 0;
    tag.payoutKey = s.payoutKey.value();
    if (!IsValidTag(tag)) return CScript();
    return TagPush(tag);
}

CScript TagScript(const YellowbackIndex& index)
{
    // The miner's own clock, deciding what it publishes; read by no rule (M11).
    return BuildTagScript(index, GetTime());
}

namespace {

/** The MP-1 expiry bound (N5), as MempoolCheck applies it: a REDEEM payload's refHeight and nExpiryHeight in (0, refHeight + REF_WINDOW]. */
bool HasMempoolExpiry(const CTransaction& tx, const std::optional<FoundPayload>& fp, const Params& p)
{
    if (!fp.has_value() || fp->payload.type != PayloadType::REDEEM) return false;
    const int64_t refHeight = fp->payload.refHeight;
    return tx.nExpiryHeight != 0 && (int64_t)tx.nExpiryHeight <= refHeight + p.refWindow;
}

/** TPL-2: exactly the wallet's `<sig> OP_1 <script>` or `OP_0 <script>` (§3.4), byte for byte. */
bool IsWalletSpendShape(const CScript& scriptSig)
{
    std::optional<VaultSpendPath> path = ParseVaultSpendPath(scriptSig);
    if (!path.has_value()) return false;
    if (path->pushes == 3 && path->ownerPath) return scriptSig == OwnerScriptSig(path->ownerSig, path->vaultScript);
    if (path->pushes == 2 && !path->ownerPath) return scriptSig == ClaimScriptSig(path->vaultScript);
    return false;
}

} // namespace

static bool FilterTemplateInner(TemplateView& view, const CTransaction& tx, int nHeight, YellowbackIndex& index, const Params& p);

bool FilterTemplate(TemplateView& view, const CTransaction& tx, int nHeight)
{
    YellowbackIndex& index = view.Index();
    if (index.IsStopped() || !index.IsHealthy()) return true;     // BLK-3: nothing is policed while unhealthy
    if (tx.IsCoinBase()) return true;                              // TX-0
    const Params& p = index.ParamsAt(nHeight);
    if (nHeight < p.startHeight) return true;

    // BLK-3's storage boundary on the template path (audit A-3): a storage failure keeps the candidate
    // (fail-open) and marks the index unhealthy instead of unwinding CreateNewBlock.
    try {
        return FilterTemplateInner(view, tx, nHeight, index, p);
    } catch (const std::exception& e) {
        index.SetUnhealthy(std::string("storage failure in FilterTemplate: ") + e.what());
    } catch (...) {
        index.SetUnhealthy("storage failure in FilterTemplate");
    }
    return true;
}

static bool FilterTemplateInner(TemplateView& view, const CTransaction& tx, int nHeight, YellowbackIndex& index, const Params& p)
{
    // Relevance in O(inputs) lookups (N6): only a Tokens/Vaults input or a payload can touch the state.
    State base(view.Overlay());
    bool relevant = false, spendsVoid = false;
    for (const CTxIn& in : tx.vin) {
        if (base.GetToken(in.prevout).has_value()) relevant = true;
        if (std::optional<VaultRecord> v = base.GetVault(in.prevout)) {
            relevant = true;
            if (v->Status() == VaultStatus::VOIDED) spendsVoid = true;
        }
    }
    const std::optional<FoundPayload> fp = FindPayload(tx);
    if (!relevant && !fp.has_value()) return true;

    // The dry run (one per Yellowback-relevant candidate), on a nested overlay. `templateOverlay` is
    // bound as a StateView& on purpose: OverlayStateView sub(view.Overlay()) would pick the copy
    // constructor (an exact match) and `sub` would then share the *index* as its base, so Commit()
    // would write into the database (docs/mapping.md section 13.6).
    StateView& templateOverlay = view.Overlay();
    OverlayStateView sub(templateOverlay);
    State st(sub);
    const TxOutcome out = ProcessTx(st, p, tx, nHeight, index.GetSigCache());   // W8: the dry run fills the cache ConnectBlock will hit
    const bool strict = index.GetMinerConfig().templatePolicy != "consensus";
    const bool abandoned = index.IsAbandoned();                    // L13: TPL-1/2 stand down for vault spends
    std::string why;
    if (out.vaultSpend && !abandoned) {
        if (out.redFailed) {
            why = out.log.verdict;                                 // TPL-1: BLK-1's condition, any activation state
        } else if (strict) {
            if (!HasMempoolExpiry(tx, fp, p)) why = "mempool-expiry";
            else if (!IsWalletSpendShape(tx.vin[0].scriptSig)) why = "vault-spend-shape";
        }
    }
    if (why.empty() && strict) {                                   // TPL-2 (v3: a VOID by MINT-9/10 is a VOID mint like any other; a
                                                                   // claim failing RED-5 is TPL-1's redFailed above; a CLAIM_NOTICE that
                                                                   // NOT-1 would not register is skipped here)
        if (out.log.Type() == TxLogType::MINT && out.log.verdict != verdict::OK) why = "void-mint:" + out.log.verdict;
        else if (out.log.Type() == TxLogType::TRANSFER && out.log.burned > 0) why = "transfer-burns";
        else if (fp.has_value() && fp->payload.type == PayloadType::CLAIM_NOTICE && out.log.Type() != TxLogType::CLAIM_NOTICE) why = "notice-fails-not1";
        else if (spendsVoid && !abandoned && !tx.vin.empty()) {
            std::optional<VaultSpendPath> path = ParseVaultSpendPath(tx.vin[0].scriptSig);
            if (path.has_value() && !path->ownerPath) why = "vault-claim-void";
        }
    }
    if (!why.empty() && out.redFailed && index.ConsumeTemplateFault()) {
        LogPrintf("yellowback: -yellowbacktestfault=template: keeping block-invalid %s in the template\n", tx.GetHash().ToString());
        why.clear();
    }
    if (!why.empty()) {
        LogPrint("yellowback", "FilterTemplate: skipping %s at %d: %s\n", tx.GetHash().ToString(), nHeight, why);
        return false;
    }
    sub.Commit();
    return true;
}

} // namespace policy

void FetchInputs(const CTransaction& tx, CCoinsViewCache& view)
{
    AssertLockHeld(cs_main);
    LOCK(mempool.cs);
    CCoinsViewMemPool viewMempool(pcoinsTip, mempool);
    CCoinsViewCache tmp(&viewMempool);
    for (const CTxIn& txin : tx.vin) {
        const CCoins* coins = tmp.AccessCoins(txin.prevout.hash);
        if (coins) {
            *view.ModifyCoins(txin.prevout.hash) = *coins;
        }
    }
}

uint32_t SignerBranchId()
{
    AssertLockHeld(cs_main);
    return CurrentEpochBranchId(chainActive.Height() + 1, ::Params().GetConsensus());
}

bool VerifyAllInputs(const CTransaction& tx, const CCoinsViewCache& view, uint32_t branchId, std::string& error)
{
    // 6.20.0: PrecomputedTransactionData needs every spent output (ZIP-244), so gather them first.
    std::vector<CTxOut> prevouts;
    prevouts.reserve(tx.vin.size());
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CCoins* coins = view.AccessCoins(tx.vin[i].prevout.hash);
        if (!coins || !coins->IsAvailable(tx.vin[i].prevout.n)) {
            error = strprintf("input %u is unknown or spent", i);
            return false;
        }
        prevouts.push_back(coins->vout[tx.vin[i].prevout.n]);
    }
    const PrecomputedTransactionData txdata(tx, prevouts);
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CTxOut& prev = prevouts[i];
        ScriptError serror = SCRIPT_ERR_OK;
        if (!VerifyScript(tx.vin[i].scriptSig, prev.scriptPubKey, STANDARD_SCRIPT_VERIFY_FLAGS,
                          TransactionSignatureChecker(&tx, txdata, i, prev.nValue), branchId, &serror)) {
            error = strprintf("input %u fails script verification: %s", i, ScriptErrorString(serror));
            return false;
        }
    }
    return true;
}

} // namespace yellowback
