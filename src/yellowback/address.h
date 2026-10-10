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
 * version bytes 0x1FE4 (mainnet, "ye…"), 0x2007 (testnet, "yt…"), 0x2002
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
 * PQ keys (quantum spec §4): Base58Check(pqAddressVersion || scheme || 32-byte keyHash), versions
 * 0x56BF / 0x571E / 0x5710, also "ye…"/"yt…"/"yr…" but 53 characters long. Empty for a scheme
 * outside the registry (crypto/pq/scheme.h).
 */
std::string EncodeAddress(const CPQKeyID& id, const Params& params);

/** False unless the string is a PQ Yellowback address of this network with a registered scheme. */
bool DecodeAddress(const std::string& str, const Params& params, CPQKeyID& id);

/** Either form: a CKeyID (35-character) or a CPQKeyID (53-character) address; false otherwise. */
bool DecodeAddress(const std::string& str, const Params& params, CTxDestination& dest);

} // namespace yellowback

#endif // YCASH_YELLOWBACK_ADDRESS_H
