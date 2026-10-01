// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_YELLOWBACK_ADDRESS_H
#define YCASH_YELLOWBACK_ADDRESS_H

#include "pubkey.h"
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

} // namespace yellowback

#endif // YCASH_YELLOWBACK_ADDRESS_H
