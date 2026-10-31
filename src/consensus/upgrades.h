// Copyright (c) 2018-2023 The Zcash developers
// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef ZCASH_CONSENSUS_UPGRADES_H
#define ZCASH_CONSENSUS_UPGRADES_H

#include "consensus/params.h"

#include <optional>

enum UpgradeState {
    UPGRADE_DISABLED,
    UPGRADE_PENDING,
    UPGRADE_ACTIVE
};

struct NUInfo {
    /** Branch ID (a random non-zero 32-bit value) */
    uint32_t nBranchId;
    /** User-facing name for the upgrade */
    std::string strName;
    /** User-facing information string about the upgrade */
    std::string strInfo;
    /**
     * Equihash (N,K) override applied from this upgrade onwards. A value of 0
     * means "fall back to the chainparams default (nEquihashN/nEquihashK)".
     */
    static constexpr unsigned int EQUIHASH_DEFAULT = 0;
    unsigned int nEquihashN = EQUIHASH_DEFAULT;
    unsigned int nEquihashK = EQUIHASH_DEFAULT;
};

extern const struct NUInfo NetworkUpgradeInfo[];

/**
 * The testnet shadow fork's own branch IDs (docs/plans/yellowback-testnet-shadow-fork-plan.md §2):
 * testnet-yb-slow and testnet-legacy copy mainnet through H_S, so every ID they sign under after H_S
 * is one mainnet has never had and never will, and differs between the two networks. Each collides
 * with no Zcash or Ycash branch ID (Sprout 0, the test dummy, Overwinter, Sapling, Ycash, Zcash's and
 * Ycash's Blossom, Heartwood, Canopy and NU5, NU6, NU6.1, NU6.2, NU7, Vault, ZFUTURE) and with no
 * network magic. librustzcash6's BranchId knows the same three values.
 */
static const uint32_t SLOW_SHADOW_BRANCH_ID = 0x57a24d5d;     // testnet-yb-slow, UPGRADE_SHADOW
static const uint32_t SLOW_VAULT_BRANCH_ID = 0xe1f1cc08;      // testnet-yb-slow, UPGRADE_VAULT
static const uint32_t LEGACY_SHADOW_BRANCH_ID = 0x35706728;   // testnet-legacy, UPGRADE_SHADOW

// Consensus branch id to identify pre-overwinter (Sprout) consensus rules.
extern const uint32_t SPROUT_BRANCH_ID;

/**
 * Checks the state of a given network upgrade based on block height.
 * Caller must check that the height is >= 0 (and handle unknown heights).
 */
UpgradeState NetworkUpgradeState(
    int nHeight,
    const Consensus::Params& params,
    Consensus::UpgradeIndex idx);

/**
 * Returns the index of the most recent upgrade as of the given block height
 * (corresponding to the current "epoch"). Consensus::BASE_SPROUT is the
 * default value if no upgrades are active. Caller must check that the height
 * is >= 0 (and handle unknown heights).
 */
int CurrentEpoch(int nHeight, const Consensus::Params& params);

/**
 * Returns the branch ID the given network signs and checks under for the given upgrade: the
 * network's own (NetworkUpgrade::nBranchId, the testnet shadow fork) when it has one, otherwise
 * NetworkUpgradeInfo's. The upgrade's rules do not depend on it.
 */
uint32_t NetworkBranchId(Consensus::UpgradeIndex idx, const Consensus::Params& params);

/**
 * Returns the branch ID of the most recent upgrade as of the given block height
 * (corresponding to the current "epoch"), or 0 if no upgrades are active.
 * Caller must check that the height is >= 0 (and handle unknown heights).
 */
uint32_t CurrentEpochBranchId(int nHeight, const Consensus::Params& params);

/**
 * Returns the branch ID that preceded currentBranchId, or 0 if no upgrade
 * matches currentBranchId.
 */
uint32_t PrevEpochBranchId(uint32_t currentBranchId, const Consensus::Params& params);

/**
 * Returns true if a given branch id is a valid nBranchId for one of the network
 * upgrades contained in NetworkUpgradeInfo.
 */
bool IsConsensusBranchId(int branchId);

/**
 * Returns true if a given branch id is the branch ID one of the network upgrades has on the given
 * network (NetworkBranchId): a network's own ID replaces the global one for that upgrade.
 */
bool IsConsensusBranchId(int branchId, const Consensus::Params& params);

/**
 * Returns true if the given block height is the activation height for the given
 * upgrade.
 */
bool IsActivationHeight(
    int nHeight,
    const Consensus::Params& params,
    Consensus::UpgradeIndex upgrade);

/**
 * Returns true if the given block height is the activation height for any upgrade.
 */
bool IsActivationHeightForAnyUpgrade(
    int nHeight,
    const Consensus::Params& params);

/**
 * Returns the index of the next upgrade after the given block height, or
 * std::nullopt if there are no more known upgrades.
 */
std::optional<int> NextEpoch(int nHeight, const Consensus::Params& params);

/**
 * Returns the activation height for the next upgrade after the given block height,
 * or std::nullopt if there are no more known upgrades.
 */
std::optional<int> NextActivationHeight(
    int nHeight,
    const Consensus::Params& params);

#endif // ZCASH_CONSENSUS_UPGRADES_H
