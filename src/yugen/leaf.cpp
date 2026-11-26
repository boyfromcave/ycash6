// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yugen/leaf.h"

#include "amount.h"
#include "consensus/validation.h"
#include "serialize.h"
#include "streams.h"
#include "util/system.h"
#include "version.h"

namespace yugen {

bool CheckLeafTransferStructure(const CTransaction& tx, CValidationState& state)
{
    std::string why;
    if (tx.IsYugenBundle()) {
        // §15.1 (the transfers and their VB records; the verifier helper runs the whole of rule B1),
        // W5's byte bound, and rule B1a's first part: no transparent input or output of its own (its
        // transparent inputs and outputs are its VB records', spent and created by rule B6 only).
        std::vector<Transfer> ts;
        std::vector<uint8_t> slots;
        if (!DecodeBundleTransfers(tx.yugen.transfer, ts, slots, why) || ts.empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-yugen-" + why);
        if (!tx.vin.empty() || !tx.vout.empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-yugen-bundle-transparent");
        if (!tx.yugen.proofA.empty() || !tx.yugen.proofB.empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-yugen-bundle-inline-proofs",
                             BodyCorruption::Possible);   // proofs are outside the txid (N-D7, N-D8)
        if (::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) > BLOCK_BYTES_MAX - LEAF_BYTES_RESERVE)
            return state.DoS(100, false, REJECT_INVALID, "bad-yugen-bundle-weight");
        return true;
    }
    auto t = Decode(tx.yugen.transfer, why);
    if (!t) {
        return state.DoS(100, false, REJECT_INVALID, "bad-yugen-transfer-" + why);
    }
    // Review L-3: vb and the fee together within MAX_MONEY, so no value sum can throw.
    if (t->valueBalance > MAX_MONEY - (CAmount)t->Fee() || t->valueBalance < -MAX_MONEY + (CAmount)t->Fee()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-yugen-vb-range");
    }
    if (!(t->flags & LEAFFEE)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-yugen-leaf-without-leaffee");
    }
    if (t->flags & (CANARY | CANARY_A | CANARY_B)) {
        // §13.2 / §13.2.1 decide canary claims; not implemented on this line yet.
        return state.DoS(0, false, REJECT_INVALID, "bad-yugen-canary-unsupported");
    }
    if (tx.yugen.proofA.empty() || tx.yugen.proofB.empty()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-yugen-proof-missing",
                         BodyCorruption::Possible);   // proofs are outside the txid (N-D7)
    }
    if (tx.yugen.proofA.size() > LEAF_PROOF_MAX_A || tx.yugen.proofB.size() > LEAF_PROOF_MAX_B) {
        return state.DoS(100, false, REJECT_INVALID, "bad-yugen-proof-too-long",
                         BodyCorruption::Possible);   // proofs are outside the txid (N-D7)
    }
    const size_t total = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
    const size_t proofs = tx.yugen.proofA.size() + tx.yugen.proofB.size();
    if (total - proofs > LEAF_BYTES_RESERVE) {
        // The excess is in bytes the txid commits to: a verdict on the transaction.
        return state.DoS(100, false, REJECT_INVALID, "bad-yugen-leaf-weight");
    }
    if (total > LEAF_RESERVE) {
        return state.DoS(100, false, REJECT_INVALID, "bad-yugen-leaf-weight",
                         BodyCorruption::Possible);   // the excess is in the proofs, outside the txid (N-D7)
    }
    return true;
}

// Every Yugen transaction: no Sprout or Sapling part (checked after `Transparent`, as §15.1 and
// §7.9 rule 1a order the envelope's errors).
static bool NoShieldedParts(const CTransaction& tx, CValidationState& state)
{
    if (tx.GetSaplingBundle().IsPresent() || !tx.vJoinSplit.empty())
        return state.DoS(100, error("ContextualCheckTransaction(): Yugen transaction with Sapling or Sprout parts"),
                         REJECT_INVALID, "bad-yugen-tx-shielded-parts");
    return true;
}

bool CheckLeafEnvelope(const CTransaction& tx, int nHeight, int activationHeight, CValidationState& state)
{
    if (tx.IsYugenBundle()) {
        // Spec 0.5.4 rule B1a (§15.1, as §7.9 rule 1a for a leaf): a bundle transaction has no transparent
        // input or output of its own (CheckLeafTransferStructure), no Sprout or Sapling part, lock time 0,
        // and expiry height h_a + ANCHOR_WINDOW, h_a the anchor height of its first anchor table entry
        // (the lowest, rule B1).
        if (!NoShieldedParts(tx, state)) return false;
        if (tx.nLockTime != 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-yugen-bundle-locktime");
        if (tx.yugen.transfer.size() < 3) return true;   // refused by CheckLeafTransferStructure
        const int ha = ResolveAnchor(tx.yugen.transfer[2], nHeight, activationHeight);
        if (ha >= 0 && tx.nExpiryHeight != (uint32_t)(ha + ANCHOR_WINDOW))
            return state.DoS(100, false, REJECT_INVALID, "bad-yugen-bundle-expiry");
        return true;
    }
    std::string why;
    auto t = Decode(tx.yugen.transfer, why);
    if (!t) return NoShieldedParts(tx, state);   // the transfer is refused by CheckLeafTransferStructure
    // §7.9 rule 1a (spec 0.5.3). Without VB the transfer hash covers no output (§7.3: tout_hash is zero) and the transaction
    // moves no transparent value; with no transparent input no signature covers the transaction's
    // other fields. Each such field is fixed to what wallets write, so no relay can change the
    // transaction (a new txid with the same nullifiers, or an output paying itself the fee).
    if (!(t->flags & VB) && (!tx.vin.empty() || !tx.vout.empty()))
        return state.DoS(100, false, REJECT_INVALID, "bad-yugen-leaf-transparent-without-vb");
    if (!NoShieldedParts(tx, state)) return false;
    if (tx.vin.empty()) {
        if (tx.nLockTime != 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-yugen-leaf-locktime");
        const int ha = ResolveAnchor(t->anchorSlot, nHeight, activationHeight);
        if (ha >= 0 && tx.nExpiryHeight != (uint32_t)(ha + ANCHOR_WINDOW))
            return state.DoS(100, false, REJECT_INVALID, "bad-yugen-leaf-expiry");
    }
    return true;
}

} // namespace yugen
