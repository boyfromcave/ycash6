// Copyright (c) 2017-2023 The Zcash developers
// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef ZCASH_DEPRECATION_H
#define ZCASH_DEPRECATION_H

#include "chainparams.h"
#include "consensus/params.h"
#include "util/time.h"

#include <limits>

// Deprecation policy:
// Upstream Zcash (per ZIP-200) shuts a node down RELEASE_TO_DEPRECATION_WEEKS
// after the release height to force users onto newer versions. Ycash does not
// enforce this -- there is no foundation pushing upgrades on a fixed schedule,
// and stale nodes are preferable to nodes that stop relaying blocks on a
// hardcoded date. DEPRECATION_HEIGHT is pinned to INT_MAX so the shutdown
// branch in EnforceNodeDeprecation is unreachable and the 14-day warning fires
// at a height no real chain will ever see.
//
// APPROX_RELEASE_HEIGHT is unrelated to deprecation: it is used by
// signrawtransaction to pick a consensus branch ID for offline signing when
// the local chain tip is behind the real network. It must therefore reflect a
// height in the *currently active* Ycash epoch (Canopy at 1100006 on mainnet
// at the time of this release).
static const int APPROX_RELEASE_HEIGHT = 1500000;
static const int EXPECTED_BLOCKS_PER_HOUR = 3600 / Consensus::POST_BLOSSOM_POW_TARGET_SPACING;
static_assert(EXPECTED_BLOCKS_PER_HOUR == 48, "The value of Consensus::POST_BLOSSOM_POW_TARGET_SPACING was chosen such that this assertion holds.");
static const int DEPRECATION_HEIGHT = std::numeric_limits<int>::max();

// Number of blocks before deprecation to warn users
static const int DEPRECATION_WARN_LIMIT = 14 * 24 * EXPECTED_BLOCKS_PER_HOUR;

//! Defaults for -allowdeprecated
//
// Ycash policy: every deprecated feature is allowed by default. The
// compatibility-layer thesis is that closed-source exchange/explorer
// software was integrated against a 2018-era API surface and cannot
// be expected to update on a schedule; turning off RPCs upstream chose
// to retire (in favor of unified addresses, ZIP-244 templates, etc.)
// would break those integrations without a path to fix them.
//
// Users who want stricter modern defaults can pass `-allowdeprecated=none`
// or selectively re-enable only the features they need.
static const std::set<std::string> DEFAULT_ALLOW_DEPRECATED{{
    // Node-level features
    "createrawtransaction",
    "signrawtransaction",
    "getnetworkhashps",
    "gbt_oldhashes",
    "deprecationinfo_deprecationheight",
    "addrtype",

    // Wallet-level features
#ifdef ENABLE_WALLET
    "fundrawtransaction",
    "keypoolrefill",
    "settxfee",
    "getnewaddress",
    "getrawchangeaddress",
    "z_getnewaddress",
    "z_getbalance",
    "z_gettotalbalance",
    "z_listaddresses",
    "legacy_privacy",
    "wallettxvjoinsplit",

    // Legacy Bitcoin-Core-style accounts API (single-bucket emulation).
    // Removed upstream in favor of unified addresses, but exchanges and
    // explorers integrated against the 2018-era ycashd API still call
    // these. See wallet/rpcwallet.cpp legacy-accounts-compat section.
    "accounts",
#endif
}};
static const std::set<std::string> DEFAULT_DENY_DEPRECATED{{
    // (empty -- see DEFAULT_ALLOW_DEPRECATED rationale above)
}};

// Flags that enable deprecated functionality.
extern bool fEnableGbtOldHashes;
extern bool fEnableDeprecationInfoDeprecationHeight;
extern bool fEnableAddrTypeField;
extern bool fEnableGetNetworkHashPS;
extern bool fEnableCreateRawTransaction;
extern bool fEnableSignRawTransaction;
#ifdef ENABLE_WALLET
extern bool fEnableGetNewAddress;
extern bool fEnableGetRawChangeAddress;
extern bool fEnableZGetNewAddress;
extern bool fEnableZGetBalance;
extern bool fEnableZGetTotalBalance;
extern bool fEnableZListAddresses;
extern bool fEnableLegacyPrivacyStrategy;
extern bool fEnableWalletTxVJoinSplit;
extern bool fEnableFundRawTransaction;
extern bool fEnableKeyPoolRefill;
extern bool fEnableSetTxFee;
extern bool fEnableLegacyAccounts;
#endif

/**
 * Returns the estimated time, in seconds since the epoch, at which deprecation
 * enforcement will take effect for this node.
 */
int64_t EstimatedNodeDeprecationTime(const CClock& clock, int nHeight);

/**
 * Checks whether the node is deprecated based on the current block height, and
 * shuts down the node with an error if so (and deprecation is not disabled for
 * the current client version). Warning and error messages are sent to the debug
 * log, the metrics UI, and (if configured) -alertnofity.
 *
 * fThread means run -alertnotify in a free-running thread.
 */
void EnforceNodeDeprecation(const CChainParams& params, int nHeight, bool forceLogging=false, bool fThread=true);

/**
 * Checks config options for enabling and/or disabling of deprecated
 * features and sets flags that enable deprecated features accordingly.
 *
 * @return std::nullopt if successful, or an error message indicating what
 * values are permitted for `-allowdeprecated`.
 */
std::optional<std::string> LoadAllowedDeprecatedFeatures();

/**
 * Returns a comma-separated list of the valid arguments to the -allowdeprecated
 * CLI option.
 */
std::string GetAllowableDeprecatedFeatures();

/**
 * Returns a string to be included in the help text of a deprecated RPC method that has a
 * better alternative on Ycash (`instead` says what to use).
 */
std::string Deprecated(bool enabled, std::string method, std::string instead);

/**
 * Returns a string to be included in the help text of an RPC method that upstream Zcash
 * deprecated but that is a supported call on Ycash, usually because its replacement needs
 * NU5 (unified-address accounts), which has no activation height on Ycash. `note` says why.
 *
 * `enabled` false gives the DISABLED message. Which methods -allowdeprecated=none can turn off
 * is fixed by LoadAllowedDeprecatedFeatures, not by these helpers, and is unchanged here:
 *   - turned off by -allowdeprecated=none: getnewaddress, getrawchangeaddress, z_getnewaddress,
 *     z_getbalance, z_gettotalbalance, z_listaddresses and the nine legacy account RPCs
 *     ("accounts");
 *   - never turned off (their flags are always true; the feature names are accepted and have no
 *     effect): createrawtransaction, signrawtransaction, fundrawtransaction, keypoolrefill,
 *     settxfee and getnetworkhashps.
 */
std::string SupportedOnYcash(bool enabled, std::string method, std::string note);

#endif // ZCASH_DEPRECATION_H
