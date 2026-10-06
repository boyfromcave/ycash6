// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_VAULT_CHECKER_H
#define YCASH_VAULT_CHECKER_H

#include "script/sigcache.h"
#include "vault/state.h"

#include <memory>
#include <optional>
#include <vector>

/**
 * The script checker that answers OP_CHECKSETSIG / OP_CHECKSETDORMANT
 * (docs/plans/yellowback-upgrade-plan.md §15.2 "Checker interface") from an immutable set
 * snapshot at the spending height. Ordinary signatures still go through the signature cache;
 * set signatures are never cached (their validity depends on set state, not only on bytes).
 *
 * The three methods override the BaseSignatureChecker virtuals in script/interpreter.h.
 */
namespace vault {

class SetSigChecker : public CachingTransactionSignatureChecker
{
public:
    typedef std::vector<unsigned char> valtype;

    SetSigChecker(const CTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, bool storeIn,
                  PrecomputedTransactionData& txdataIn, std::shared_ptr<const SetSnapshot> snapshotIn, int64_t heightIn);

    /** The set's threshold for `role` (1 unlock, 2 cancel); nullopt for an unknown set/role. */
    std::optional<int> SetThreshold(const uint256& setId, uint8_t role) const override;
    /** §15.2 steps 3–5 over sighash = SignatureHash(scriptCode, tx, nIn, SIGHASH_ALL, amount, branch). */
    bool CheckSetSigs(const uint256& setId, uint8_t role, const std::vector<valtype>& sigs,
                      const CScript& scriptCode, uint32_t consensusBranchId) const override;
    /** Dormant, wound down past its liveness window, or unknown (§15.4). */
    bool IsSetReleased(const uint256& setId) const override;

    int64_t Height() const { return height; }

private:
    const CTransaction* txTo;
    unsigned int nIn;
    CAmount amount;
    const PrecomputedTransactionData* txdata;
    std::shared_ptr<const SetSnapshot> snapshot;
    int64_t height;
};

} // namespace vault

#endif // YCASH_VAULT_CHECKER_H
