// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_YELLOWBACK_MODULE_H
#define YCASH_YELLOWBACK_MODULE_H

#include "vault/module.h"
#include "yellowback/params.h"

/**
 * yellowback::Module, the YED rule module of the vault primitive (docs/plans/yellowback-upgrade-plan.md
 * §3.8, §5.3, §15.7, §15.10), registered for the tag {'Y','E','D',0x00} in vault/module.cpp's
 * compile-time table.
 *
 * The module's rules are split by what they read:
 *
 * - ValidateCreate / ValidateSpend (this class) need only the network's YED parameters, so the
 *   primitive runs them per transaction, in blocks and in the mempool, after its own rules: a YED
 *   vault must name the attestor set as both its sets, CLAIM_DELAY as its delay and lockHeight +
 *   GRACE as its appHeight; a YED vault is never unlocked by the set (selector 1: attestors never
 *   spend anything, §5.2); a YED intent is never taken by its owner on set release (selector 3: the
 *   claimant can always release after the delay, and the residual is the owner's anyway).
 * - Everything that reads the module's own state (MINT-1..10, RED-1..5 at the claim intent's
 *   creation, TRANSFER, the intent release/cancel, the token index, SNAP) is EvaluateBlock in
 *   yellowback/state.cpp over the index's state, run by the index's ConnectBlock hook as a
 *   consensus rejection (DoS 100, `bad-yellowback-<verdict>`; U-21) and by its mempool check.
 *   CheckBlock therefore holds only the structural attestor-set rule (no SET_REMOVE or SET_WINDDOWN of the
 *   attestor set): the primitive's per-block module hook runs over the vault database, which holds none of
 *   the module's state, and the index's hook already sees the whole block.
 *
 * Until SetParams is called with a configured parameter set (a network with an UPGRADE_VAULT
 * height and an attestor set, U-22) the module accepts everything: the YED tag is then governed by
 * the primitive alone, which is the §5.4 fallback.
 */
namespace yellowback {

class Module final : public vault::Module
{
public:
    std::optional<std::string> ValidateCreate(const CTransaction& tx, size_t vout, const vault::VaultParams& params, const vault::ModuleContext& ctx) const override;
    std::optional<std::string> ValidateSpend(const CTransaction& tx, size_t vin, const vault::TemplateSpend& spend, const vault::ModuleContext& ctx) const override;
    /** P4-b (U-25): the attestor set. */
    std::optional<vault::SetId> GovernedSet() const override;
    /**
     * P4-b (U-25): EQV-1 on the primitive side. An EQUIVOCATION transaction whose two attestations (one seq, one
     * citedHeight in [START_HEIGHT, height), two prices) both verify under a member key of the attestor set, over the
     * block hash at citedHeight, names that member (the first in key order whose bond is unspent and not frozen), so
     * the primitive ejects it and freezes its bond in the same block. The module's own EQV-1 (state.cpp) ejects the
     * same member's Attestors record.
     */
    std::vector<CPubKey> Ejections(const CTransaction& tx, const vault::ModuleContext& ctx) const override;
    /**
     * Owner, 2026-10-11: the attestor set is open and never shrinks by vote. A block holding a SET_REMOVE or
     * SET_WINDDOWN of the attestor set is invalid (RefusedAttestorSetAct; the index's mirror refuses the same
     * transaction, so the mempool never takes one).
     */
    std::optional<std::string> CheckBlock(const CBlock& block, const CBlockIndex* pindex, const vault::ModuleContext& ctx) const override;
    /**
     * Owner, 2026-10-11 (the primitive's displacement hook): a SET_JOIN into the full attestor set, when the set is
     * the one the module adopts (OPEN, ATTESTOR_SEATS seats), displaces EvictionVictim over its ACTIVE members with
     * an unfrozen bond (state.h); the module's mirror makes the same member's record WITHDRAWN (evicted).
     */
    std::optional<CPubKey> Displace(const CTransaction& tx, const vault::SetJoinBody& join, const vault::ModuleContext& ctx) const override;
    /**
     * Seats review B2 (2026-10-11): a member's price attestation carried by a MINT, CLAIM_NOTICE or REDEEM transaction
     * counts as liveness: AttestationLiveness (state.h) over the ACTIVE members of the attestor set with an unfrozen
     * bond; the module's mirror applies the same update to the members' Attestors records.
     */
    std::vector<std::pair<CPubKey, int64_t>> Liveness(const CTransaction& tx, const vault::ModuleContext& ctx) const override;
};

/** The registered instance (vault/module.cpp's table entry). */
const vault::Module* RegisteredModule();

/** Configure the module with the network's YED parameters (init, after ParamsFromArgs; unit tests). An unconfigured set turns it off. */
void SetModuleParams(const Params& p);
/** Turn the module off again (unit tests, shutdown). */
void ClearModuleParams();

} // namespace yellowback

#endif // YCASH_YELLOWBACK_MODULE_H
