// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_VAULT_MODULE_H
#define YCASH_VAULT_MODULE_H

#include "vault/template.h"

#include <cstddef>
#include <cstdint>
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

struct ModuleContext
{
    /** The block height being validated (tip+1 in the mempool). */
    int64_t height = 0;
    /** The running set state, including the effects of earlier transactions in the block. */
    const KVReader* state = nullptr;
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
};

/** The registered module for `tag`, or nullptr (the primitive alone governs the vault). */
const Module* FindModule(const std::array<unsigned char, 4>& tag);
/** Every registered module, in table order. */
const std::vector<std::pair<Tag, const Module*>>& Modules();

} // namespace vault

#endif // YCASH_VAULT_MODULE_H
