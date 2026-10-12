// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_VAULT_MODULE_H
#define YCASH_VAULT_MODULE_H

#include "pubkey.h"
#include "vault/act.h"
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
    /** The node-local verification cache the module asked for (vault::SetModuleCache; YED: its yellowback::SigCache),
     *  opaque to the primitive; nullptr = none. Never state: a hit and a cold verification always agree. */
    void* moduleCache = nullptr;
};

/** Set once at init (the node's YED index), read by every ModuleContext the primitive builds. */
void SetModuleCache(void* cache);
void* ModuleCache();

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

    /**
     * The module displacement hook (owner, 2026-10-11). A SET_JOIN into the module's GovernedSet() when that set
     * already has `seats` ACTIVE members is refused (bad-vault-act-seats) unless this names a member to make room:
     * the primitive then checks that the key is an ACTIVE member of the set, not the joining key, whose bond is
     * unspent (indexed) and not frozen, sets it MEMBER_REMOVED without freezing its bond (it is spendable from
     * exitHeight + the set's maturity, the bond exit delay) and admits the join, in the same overlay. Any other answer, or nullopt (the default), refuses the
     * join as before. Asked only for a full governed set; a set no module governs is unchanged. The primitive does
     * not know why the module picks a member (for YED: the eviction rule, a larger bond or a member not live).
     */
    virtual std::optional<CPubKey> Displace(const CTransaction& tx, const SetJoinBody& join, const ModuleContext& ctx) const { return std::nullopt; }

    /**
     * The module liveness hook (seats review B2, 2026-10-11). For every non-coinbase transaction, after the
     * ejection hook, the primitive asks each module for (key, height) pairs: the transaction proves that the key
     * signed, for the module, something bound to the block at `height` (for YED: a price attestation citing it).
     * A pair whose key is an ACTIVE member of the module's GovernedSet() with an unspent, unfrozen bond and
     * lastAct < height < the block's height sets lastAct = height, as a SET_HEARTBEAT would have; any other pair
     * is ignored. The hook never makes a transaction invalid and never touches another set. Default: none.
     */
    virtual std::vector<std::pair<CPubKey, int64_t>> Liveness(const CTransaction& tx, const ModuleContext& ctx) const { return {}; }
};

/** The registered module for `tag`, or nullptr (the primitive alone governs the vault). */
const Module* FindModule(const std::array<unsigned char, 4>& tag);
/** Every registered module, in table order. */
const std::vector<std::pair<Tag, const Module*>>& Modules();

} // namespace vault

#endif // YCASH_VAULT_MODULE_H
