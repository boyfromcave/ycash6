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
    tag.flags = 0x00;                                              // no signal bit (ACT-1 left with the upgrade, §6)
    tag.priceMicroUsd = q.priceMicroUsd;
    tag.sourceMask = q.sourceMask;
    tag.payoutKey = s.payoutKey.value();
    if (!IsValidTag(tag)) return CScript();
    return TagPush(tag);
}

CScript TagScript(const YellowbackIndex& index)
{
    // The miner's own clock, deciding what it publishes; read by no rule (M11).
    return BuildTagScript(index, GetTime());
}

static bool FilterTemplateInner(TemplateView& view, const CTransaction& tx, int nHeight, YellowbackIndex& index, const Params& p);

bool FilterTemplate(TemplateView& view, const CTransaction& tx, int nHeight)
{
    YellowbackIndex& index = view.Index();
    if (index.IsStopped()) return true;
    if (!index.IsHealthy()) return false;                          // the module cannot be evaluated: skip every candidate (the next block aborts the node)
    if (tx.IsCoinBase()) return true;                              // TX-0
    const Params& p = index.ParamsAt(nHeight);
    if (nHeight < p.startHeight) return true;

    // The storage boundary on the template path (audit A-3): a storage failure skips the candidate and
    // marks the index unhealthy instead of unwinding CreateNewBlock.
    try {
        return FilterTemplateInner(view, tx, nHeight, index, p);
    } catch (const std::exception& e) {
        index.SetUnhealthy(std::string("storage failure in FilterTemplate: ") + e.what());
    } catch (...) {
        index.SetUnhealthy("storage failure in FilterTemplate");
    }
    return false;
}

static bool FilterTemplateInner(TemplateView& view, const CTransaction& tx, int nHeight, YellowbackIndex& index, const Params& p)
{
    // The dry run (one per candidate), on a nested overlay. `templateOverlay` is bound as a StateView& on
    // purpose: OverlayStateView sub(view.Overlay()) would pick the copy constructor (an exact match) and
    // `sub` would then share the *index* as its base, so Commit() would write into the database
    // (docs/mapping.md section 13.6). Since the vault upgrade the template follows validity (§6: TPL-1/2
    // and the strict policy are gone): a candidate is skipped iff it is invalid under the module at this
    // height, after the candidates before it (in-block chaining and first-claim-wins exactly as
    // ConnectBlock evaluates them). A non-Yellowback transaction applies as a no-op.
    StateView& templateOverlay = view.Overlay();
    OverlayStateView sub(templateOverlay);
    State st(sub);
    const TxOutcome out = ProcessTx(st, p, tx, nHeight, index.GetSigCache());   // W8: the dry run fills the cache ConnectBlock will hit
    if (out.invalid && index.ConsumeTemplateFault()) {
        LogPrintf("yellowback: -yellowbacktestfault=template: keeping invalid %s in the template\n", tx.GetHash().ToString());
    } else if (out.invalid) {
        LogPrint("yellowback", "FilterTemplate: skipping %s at %d: %s\n", tx.GetHash().ToString(), nHeight, out.log.verdict);
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
