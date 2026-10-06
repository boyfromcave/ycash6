// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "vault/checker.h"

#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "vault/act.h"

#include <stdexcept>

namespace vault {

SetSigChecker::SetSigChecker(const CTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, bool storeIn,
                             PrecomputedTransactionData& txdataIn, std::shared_ptr<const SetSnapshot> snapshotIn, int64_t heightIn)
    : CachingTransactionSignatureChecker(txToIn, txdataIn, nInIn, amountIn, storeIn),
      txTo(txToIn), nIn(nInIn), amount(amountIn), txdata(&txdataIn), snapshot(std::move(snapshotIn)), height(heightIn)
{
}

std::optional<int> SetSigChecker::SetThreshold(const uint256& setId, uint8_t role) const
{
    if (!snapshot) return std::nullopt;
    return snapshot->Threshold(setId, role);
}

bool SetSigChecker::CheckSetSigs(const uint256& setId, uint8_t role, const std::vector<valtype>& sigs,
                                 const CScript& scriptCode, uint32_t consensusBranchId) const
{
    if (!snapshot || !txTo || nIn >= txTo->vin.size()) return false;
    uint256 sighash;
    try {
        sighash = SignatureHash(scriptCode, *txTo, nIn, SIGHASH_ALL, amount, consensusBranchId, *txdata);
    } catch (const std::logic_error&) {
        return false;
    }
    const uint256 msg = SetSigMsg(setId, role, txTo->vin[nIn].prevout, sighash);
    return snapshot->CheckSetSigs(setId, role, msg, sigs, height);
}

bool SetSigChecker::IsSetReleased(const uint256& setId) const
{
    if (!snapshot) return false;
    return snapshot->IsReleased(setId, height);
}

} // namespace vault
