// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_RPC_YELLOWBACKRPC_H
#define YCASH_RPC_YELLOWBACKRPC_H

#include "amount.h"
#include "primitives/transaction.h"
#include "yellowback/index.h"
#include "yellowback/params.h"
#include "yellowback/view.h"

#include <optional>
#include <string>
#include <vector>

class UniValue;

/**
 * Helpers shared by the node-context (rpc/yellowback.cpp) and wallet-context
 * (rpc/yellowbackwallet.cpp) Yellowback RPCs: the v3 fields yed_getvault,
 * yed_listvaults, yed_listclaimable and yed_listpositions render in common
 * (doc/yellowback-rpc.md, rpcversion 3). Every function expects cs_yellowback
 * held by the caller (the index's own methods take it recursively).
 */
namespace yellowback {
namespace rpc {

/** `noticed`, `noticeHeight`, `emergencyOpenAt` (v3 §3.6 Notices; null when no record stands). */
void PushNoticeFields(UniValue& o, const State& st, const Params& p, const COutPoint& vault, const VaultRecord& v);

/**
 * What a claim of `vault` would see at R = the index tip (the wallet's spendRefHeight for a
 * vault spend; RED-1's window holds at H = tip + 1): unarmed, exactly v2 — RED-4 (a) under the
 * tip snapshot's pClaim;
 * armed, RED-4 (a) under the combined pClaim with the bundle this node would build for the vault
 * (selector = the outpoint), or (b) when a notice has persisted and the emergency inequality
 * holds under pEmerg. With no buildable bundle the cross-section alone is read and claimPath is
 * "" (the contract's yed_listclaimable text).
 */
struct ClaimEstimate
{
    int refHeight;
    bool armed;                         //!< ArmedAt(R)
    bool bundleOk;                      //!< a bundle with a defined aClaim could be built
    std::optional<MicroUsd> xClaim, aClaim, pClaim, pEmerg;
    std::vector<uint16_t> bundleSeqs;
    bool claimable;                     //!< tip >= claimHeight and RED-4 by (a) or (b)
    std::string claimPath;              //!< "a" | "b" | ""
    CAmount residualZat;                //!< RED-5's amount when claimable, else 0
    CAmount attestFeeZat;               //!< AFEE-1 when a bundle exists, else 0
    bool canNotice;                     //!< yed_listpositions.canNotice (v3 §4.8)

    ClaimEstimate() : refHeight(0), armed(false), bundleOk(false), claimable(false), residualZat(0), attestFeeZat(0), canNotice(false) {}
};

ClaimEstimate EstimateClaim(YellowbackIndex& index, const COutPoint& vault, const VaultRecord& v, int tipHeight);

} // namespace rpc
} // namespace yellowback

#endif // YCASH_RPC_YELLOWBACKRPC_H
