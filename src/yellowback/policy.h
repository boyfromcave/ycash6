// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_YELLOWBACK_POLICY_H
#define YCASH_YELLOWBACK_POLICY_H

#include "amount.h"
#include "coins.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "yellowback/index.h"
#include "yellowback/script.h"
#include "yellowback/view.h"

#include <string>

/**
 * The miner-side glue (plan §4.2, §4.4; libbitcoin_server) and the chain-side
 * helpers the wallet builder needs (cs_main): the coinbase tag a template
 * carries (MINER-1..3), a coins view built as signrawtransaction does, the
 * signer branch ID and full script verification before broadcast. The
 * prototype's co-signer rule set was removed with the federation; v2's
 * RED-1..4 are block-validity rules and live in state.cpp.
 *
 * policy::TagScript is the one wall-clock read outside rpc/yellowback.cpp
 * (M11, §3.10): it decides what *this* miner publishes and is read by no rule.
 */
namespace yellowback {

namespace policy {

/**
 * MINER-1..3 with the clock as a parameter: a quote tag iff a quote younger
 * than -yellowbackquotemaxage is held, else an empty script (the signal-only
 * tag and the signal bit left with ACT-1, upgrade plan §6); payoutKey from
 * -yellowbackpayoutaddress (MINER-2; none => empty script); empty while the
 * index is unhealthy (MINER-3). Returns the push `0x24 ‖ 36 bytes`
 * (TagPush) that COINBASE_FLAGS carries (V5).
 */
CScript BuildTagScript(const YellowbackIndex& index, int64_t now);

/** = BuildTagScript(index, now) with the wall clock. Called by CreateNewBlock under cs_main. */
CScript TagScript(const YellowbackIndex& index);

/**
 * The template's validity filter (§3.9, §4.4; since the vault upgrade TPL-1/2 and the strict policy
 * are gone, upgrade plan §6). Called by CreateNewBlock for every candidate, in selection order,
 * immediately before UpdateCoins, on the TemplateView it holds inside LOCK2(cs_main, mempool.cs).
 * Dry-runs ProcessTx on a nested overlay; true keeps the transaction and commits its effect to the
 * template overlay so later candidates see it; false skips a transaction that is invalid under the
 * module at this height (and every candidate while the index is unhealthy, or on a storage failure).
 * The dry run goes through the index's W8 signature cache. -yellowbacktestfault=template lets one
 * invalid transaction through (TestBlockValidity then refuses the template).
 */
bool FilterTemplate(TemplateView& view, const CTransaction& tx, int nHeight);

} // namespace policy

/**
 * Populate `view` with the transaction's inputs from pcoinsTip behind the
 * mempool, as signrawtransaction does (rawtransaction.cpp:906-921).
 * Requires cs_main.
 */
void FetchInputs(const CTransaction& tx, CCoinsViewCache& view);

/** The branch ID every Yellowback signer uses (§3.4): CurrentEpochBranchId(chainActive.Height() + 1). Requires cs_main. */
uint32_t SignerBranchId();

/**
 * True iff every input of `tx` passes VerifyScript against `view` under STANDARD_SCRIPT_VERIFY_FLAGS
 * plus GetVaultScriptFlags(tip + 1), with OP_CHECKSETSIG / OP_CHECKSETDORMANT read from the set state
 * at the tip, and, once UPGRADE_VAULT is active at tip + 1, the BIP68 sequence locks hold at tip + 1
 * (`error` "non-BIP68-final" or "bad-txns-vault-timelock"). Requires cs_main.
 */
bool VerifyAllInputs(const CTransaction& tx, const CCoinsViewCache& view, uint32_t branchId, std::string& error);

} // namespace yellowback

#endif // YCASH_YELLOWBACK_POLICY_H
