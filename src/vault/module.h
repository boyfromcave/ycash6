// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_VAULT_MODULE_H
#define YCASH_VAULT_MODULE_H

#include "pubkey.h"
#include "vault/template.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

class CBlock;
class CBlockIndex;
class CTransaction;

/**
 * Application modules (docs/plans/yellowback-upgrade-plan.md §3.8, §15.7). Registration is
 * this compile-time table, not a transaction: adding a module is a network upgrade. A module
 * runs after the primitive's rules for a template input or V output whose tag it owns, and
 * can only reject. P4 registers {'Y','E','D',0x00} (yellowback::Module); `WYEC` is never
 * registered (§4).
 */
namespace vault {

class KVReader;

/** The hash of the block at a height below the one being validated, on the chain being
 *  validated (the block's own ancestors; the tip's in the mempool and the miner), or nullopt. */
typedef std::function<std::optional<uint256>(int64_t)> BlockHashFn;

struct ModuleContext
{
    /** The block height being validated (tip+1 in the mempool). */
    int64_t height = 0;
    /** The running set state, including the effects of earlier transactions in the block. */
    const KVReader* state = nullptr;
    /** Ancestor block hashes (may be empty: a module then finds nothing that needs them). */
    BlockHashFn blockHashAt;
};

class Module
{
public:
    virtual ~Module() {}
    virtual std::optional<std::string> ValidateCreate(const CTransaction& tx, size_t vout, const VaultParams& params, const ModuleContext& ctx) const
    {
        return std::nullopt;
    }
    virtual std::optional<std::string> ValidateSpend(const CTransaction& tx, size_t vin, const TemplateSpend& spend, const ModuleContext& ctx) const
    {
        return std::nullopt;
    }
    virtual std::optional<std::string> CheckBlock(const CBlock& block, const CBlockIndex* pindex, const ModuleContext& ctx) const
    {
        return std::nullopt;
    }

    /**
     * The module ejection hook (U-25, P4-b). A module may name **one** signer set it governs
     * (the set its vaults name; nullopt = none, the default). For every non-coinbase
     * transaction the primitive asks each such module, after the transaction's own rules and
     * act, which members of that set the transaction proves to have broken a rule of the
     * module; each named key that is a member of the governed set with an unspent, unfrozen
     * bond is EJECTED and its bond frozen, exactly as SET_EQUIVOCATION does (§15.5), in the
     * same overlay, so the block's undo covers it. A key that is not such a member is ignored:
     * the hook never makes a transaction invalid and never touches another set. The primitive
     * stays agnostic: it does not know why (for YED: EQV-1, two signed prices at one height).
     */
    virtual std::optional<SetId> GovernedSet() const { return std::nullopt; }
    virtual std::vector<CPubKey> Ejections(const CTransaction& tx, const ModuleContext& ctx) const { return {}; }
};

/** The registered module for `tag`, or nullptr (the primitive alone governs the vault). */
const Module* FindModule(const std::array<unsigned char, 4>& tag);
/** Every registered module, in table order. */
const std::vector<std::pair<Tag, const Module*>>& Modules();

} // namespace vault

#endif // YCASH_VAULT_MODULE_H
