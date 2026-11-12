// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_YELLOWBACK_ADDRESS_H
#define YCASH_YELLOWBACK_ADDRESS_H

#include "pubkey.h"
#include "script/standard.h"
#include "yellowback/params.h"

#include <string>

/**
 * Yellowback addresses (plan D10): Base58Check(version || 20-byte key hash) with
 * version bytes 0x1FDD (mainnet, "yb…", D-Q-21), 0x2007 (testnet, "yt…"), 0x2002
 * (regtest, "yr…"), decoding to an ordinary P2PKH destination. A distinct
 * format stops users from sending Yellowback to a plain s1… address by accident
 * (an unaware wallet would burn it, plan D2). No chainparams.cpp edit:
 * the version bytes live in yellowback::Params.
 *
 * Mirrors DigiByte's DD/TD/RD prefixes (DIGIDOLLAR_ARCHITECTURE.md §3.2).
 */
namespace yellowback {

std::string EncodeAddress(const CKeyID& keyID, const Params& params);

/** False if the string is not a Yellowback address of this network. */
bool DecodeAddress(const std::string& str, const Params& params, CKeyID& keyID);

bool IsValidAddress(const std::string& str, const Params& params);

/**
 * PQ keys (quantum spec §4, D-9): Base58Check(version || 32-byte keyHash), one 3-byte version per
 * scheme (Params::pqAddressVersions), so the prefix names it: "ybf…"/"ybs…" main, "ytf…"/"yts…" test,
 * "yrf…"/"yrs…" regtest (FN-DSA-512 / SLH-DSA-SHA2-128s), 53 characters. Empty for a scheme outside
 * the registry (crypto/pq/scheme.h).
 */
std::string EncodeAddress(const CPQKeyID& id, const Params& params);

/** False unless the string is a PQ Yellowback address of this network with a registered scheme (the pre-D-9
 *  2-byte-version form is refused). */
bool DecodeAddress(const std::string& str, const Params& params, CPQKeyID& id);

/** Either form: a CKeyID (35-character) or a CPQKeyID (53-character) address; false otherwise. */
bool DecodeAddress(const std::string& str, const Params& params, CTxDestination& dest);

} // namespace yellowback

#endif // YCASH_YELLOWBACK_ADDRESS_H
