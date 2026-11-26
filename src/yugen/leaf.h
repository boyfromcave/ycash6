// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Node rules for a Yugen leaf transfer (yugen-spec 0.5.1 §7.9, d25a89c).

#ifndef YCASH_YUGEN_LEAF_H
#define YCASH_YUGEN_LEAF_H

#include "primitives/transaction.h"

class CValidationState;

namespace yugen {

// Context-free parts of §7.9 rule 1 and §7.1: the transfer decodes, LEAFFEE is set, the proofs
// and the transaction bytes are within W4. Canary claims are refused on this line until §13.2 lands.
bool CheckLeafTransferStructure(const CTransaction& tx, CValidationState& state);

// Spec 0.5.3 §7.9 rule 1a (the leaf envelope; doc/yugen-node.md N-D9): the fields of a leaf's
// transaction that neither the transfer hash nor a signature covers are fixed. A leaf without flag
// VB has no transparent input or output; a leaf without a transparent input has nLockTime 0 and
// nExpiryHeight h_a + ANCHOR_WINDOW, h_a its anchor height at nHeight (§8.2; an unresolvable anchor
// is refused by the anchor rule, §7.9 rule 2, instead).
bool CheckLeafEnvelope(const CTransaction& tx, int nHeight, int activationHeight, CValidationState& state);

} // namespace yugen

#endif
