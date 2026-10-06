// Copyright (c) 2018-2023 The Zcash developers
// Copyright (c) 2019-present The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "consensus/upgrades.h"

/**
 * General information about each network upgrade.
 * Ordered by Consensus::UpgradeIndex.
 */
const struct NUInfo NetworkUpgradeInfo[Consensus::MAX_NETWORK_UPGRADES] = {
    {
        .nBranchId = 0,
        .strName = "Sprout",
        .strInfo = "The Zcash network at launch",
    },
    {
        .nBranchId = 0x74736554,
        .strName = "Test dummy",
        .strInfo = "Test dummy info",
    },
    {
        .nBranchId = 0x5ba81b19,
        .strName = "Overwinter",
        .strInfo = "See https://z.cash/upgrade/overwinter/ for details.",
    },
    {
        .nBranchId = 0x76b809bb,
        .strName = "Sapling",
        .strInfo = "See https://z.cash/upgrade/sapling/ for details.",
    },
    {
        .nBranchId = 0x374d694f,
        .strName = "Ycash",
        .strInfo = "Ycash fork from Zcash. See https://y.cash/ for details.",
        // Ycash forked Equihash from (200, 9) to (192, 7) at this upgrade.
        // The override remains in effect through all later upgrades unless
        // they explicitly set a new value, because EquihashN/K(nHeight)
        // walks back from CurrentEpoch(nHeight) to the most recent entry
        // whose override is non-zero.
        .nEquihashN = 192,
        .nEquihashK =   7,
    },
    {
        // Branch IDs for Ycash post-fork upgrades. The patched
        // zcash_protocol crate (see Cargo.toml [patch.crates-io]) defines and
        // recognizes Ycash-specific values for Blossom, Heartwood, Canopy and
        // NU5; these MUST match BranchId in the fork's consensus.rs or
        // zcash_transaction_digests rejects the transaction ("invalid
        // consensus branch id"). NU6/NU6.1/NU6.2 keep the upstream Zcash values
        // (the fork uses the same), and remain inactive on Ycash.
        .nBranchId = 0x8e471bd6,
        .strName = "Blossom",
        .strInfo = "See https://z.cash/upgrade/blossom/ for details.",
    },
    {
        .nBranchId = 0x66314da3,
        .strName = "Heartwood",
        .strInfo = "See https://z.cash/upgrade/heartwood/ for details.",
    },
    {
        .nBranchId = 0x19bd2d2f,
        .strName = "Canopy",
        .strInfo = "See https://z.cash/upgrade/canopy/ for details.",
    },
    {
        .nBranchId = 0xf919a198,
        .strName = "NU5",
        .strInfo = "See https://z.cash/upgrade/nu5/ for details.",
    },
    {
        .nBranchId = 0xc8e71055,
        .strName = "NU6",
        .strInfo = "See https://z.cash/upgrade/nu6/ for details.",
    },
    {
        .nBranchId = 0x4dec4df0,
        .strName = "NU6.1",
        .strInfo = "See https://z.cash/upgrade/nu6.1/ for details.",
    },
    {
        .nBranchId = 0x5437f330,
        .strName = "NU6.2",
        .strInfo = "See https://z.cash/upgrade/nu6.2/ for details.",
    },
    {
        // No Equihash override: the epoch inherits (192, 7) from the Ycash entry,
        // the same parameters as the epoch before it (plan §15.1).
        .nBranchId = 0x6d5b7a31,
        .strName = "Vault",
        .strInfo = "Ycash vault primitive (docs/plans/yellowback-upgrade-plan.md)",
    },
    {
        .nBranchId = 0xffffffff,
        .strName = "ZFUTURE",
        .strInfo = "Future network upgrade (integration testing only)",
    }
};

const uint32_t SPROUT_BRANCH_ID = NetworkUpgradeInfo[Consensus::BASE_SPROUT].nBranchId;

UpgradeState NetworkUpgradeState(
    int nHeight,
    const Consensus::Params& params,
    Consensus::UpgradeIndex idx)
{
    assert(nHeight >= 0);
    assert(idx >= Consensus::BASE_SPROUT && idx < Consensus::MAX_NETWORK_UPGRADES);
    auto nActivationHeight = params.vUpgrades[idx].nActivationHeight;

    if (nActivationHeight == Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT) {
        return UPGRADE_DISABLED;
    } else if (nHeight >= nActivationHeight) {
        // From ZIP 200:
        //
        // ACTIVATION_HEIGHT
        //     The non-zero block height at which the network upgrade rules will come
        //     into effect, and be enforced as part of the blockchain consensus.
        //
        //     For removal of ambiguity, the block at height ACTIVATION_HEIGHT - 1 is
        //     subject to the pre-upgrade consensus rules, and would be the last common
        //     block in the event of a persistent pre-upgrade branch.
        return UPGRADE_ACTIVE;
    } else {
        return UPGRADE_PENDING;
    }
}

int CurrentEpoch(int nHeight, const Consensus::Params& params) {
    for (auto idxInt = Consensus::MAX_NETWORK_UPGRADES - 1; idxInt >= Consensus::BASE_SPROUT; idxInt--) {
        if (params.NetworkUpgradeActive(nHeight, Consensus::UpgradeIndex(idxInt))) {
            return idxInt;
        }
    }
    // Base case
    return Consensus::BASE_SPROUT;
}

uint32_t CurrentEpochBranchId(int nHeight, const Consensus::Params& params) {
    return NetworkUpgradeInfo[CurrentEpoch(nHeight, params)].nBranchId;
}

uint32_t PrevEpochBranchId(uint32_t currentBranchId, const Consensus::Params& params) {
    for (int idx = Consensus::BASE_SPROUT + 1; idx < Consensus::MAX_NETWORK_UPGRADES; idx++) {
        if (currentBranchId == NetworkUpgradeInfo[idx].nBranchId) {
            // Vault follows NU5..NU6.2, which Ycash never activates (NO_ACTIVATION_HEIGHT on every
            // network): its previous epoch is the highest upgrade below it that has an
            // activation height, so a signature under that epoch's branch ID is diagnosed as
            // "old-consensus-branch-id" (plan §15.1).
            if (idx == Consensus::UPGRADE_VAULT) {
                for (int prev = idx - 1; prev > Consensus::BASE_SPROUT; prev--) {
                    if (params.vUpgrades[prev].nActivationHeight != Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT) {
                        return NetworkUpgradeInfo[prev].nBranchId;
                    }
                }
                return NetworkUpgradeInfo[Consensus::BASE_SPROUT].nBranchId;
            }
            return NetworkUpgradeInfo[idx - 1].nBranchId;
        }
    }
    // Base case
    return NetworkUpgradeInfo[Consensus::BASE_SPROUT].nBranchId;
}

bool IsConsensusBranchId(int branchId) {
    for (int idx = Consensus::BASE_SPROUT; idx < Consensus::MAX_NETWORK_UPGRADES; idx++) {
        if (branchId == NetworkUpgradeInfo[idx].nBranchId) {
            return true;
        }
    }
    return false;
}

bool IsActivationHeight(
    int nHeight,
    const Consensus::Params& params,
    Consensus::UpgradeIndex idx)
{
    assert(idx >= Consensus::BASE_SPROUT && idx < Consensus::MAX_NETWORK_UPGRADES);

    // Don't count Sprout as an activation height
    if (idx == Consensus::BASE_SPROUT) {
        return false;
    }

    return nHeight >= 0 && nHeight == params.vUpgrades[idx].nActivationHeight;
}

bool IsActivationHeightForAnyUpgrade(
    int nHeight,
    const Consensus::Params& params)
{
    if (nHeight < 0) {
        return false;
    }

    // Don't count Sprout as an activation height
    for (int idx = Consensus::BASE_SPROUT + 1; idx < Consensus::MAX_NETWORK_UPGRADES; idx++) {
        if (nHeight == params.vUpgrades[idx].nActivationHeight)
            return true;
    }

    return false;
}

std::optional<int> NextEpoch(int nHeight, const Consensus::Params& params) {
    if (nHeight < 0) {
        return std::nullopt;
    }

    // Sprout is never pending
    for (auto idx = Consensus::BASE_SPROUT + 1; idx < Consensus::MAX_NETWORK_UPGRADES; idx++) {
        if (NetworkUpgradeState(nHeight, params, Consensus::UpgradeIndex(idx)) == UPGRADE_PENDING) {
            return idx;
        }
    }

    return std::nullopt;
}

std::optional<int> NextActivationHeight(
    int nHeight,
    const Consensus::Params& params)
{
    auto idx = NextEpoch(nHeight, params);
    if (idx) {
        return params.vUpgrades[idx.value()].nActivationHeight;
    }
    return std::nullopt;
}
