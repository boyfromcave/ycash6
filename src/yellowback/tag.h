// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_YELLOWBACK_TAG_H
#define YCASH_YELLOWBACK_TAG_H

#include "script/script.h"
#include "uint256.h"
#include "yellowback/params.h"

#include <cstdint>
#include <optional>
#include <vector>

/**
 * The coinbase tag (plan §3.2, V4, V5): 36 bytes carried in the coinbase
 * scriptSig as one direct push (0x24 ‖ tag) somewhere after the BIP34 height
 * push. Little-endian throughout.
 *
 *   magic 4 ("YED!") | version 1 | flags 1 | priceMicroUsd 8 | sourceMask 2 | payoutKey 20
 *
 * DigiByte carries its oracle bundle as an extra OP_RETURN coinbase output
 * (ref/digibyte/src/oracle/bundle_manager.cpp:815-828); Ycash's coinbase output
 * layout is fixed by the funding-stream rules and getblocktemplate reads
 * vout[1] as foundersreward (ref/ycash/src/rpc/mining.cpp:733), while its
 * scriptSig is free after the height prefix within 100 bytes
 * (ref/ycash/src/main.cpp:1456-1458, 4477-4481). The reader is a byte-level
 * scan, never a script parse: pools write raw extranonce bytes (V4). No
 * property of a tag makes a block invalid (TAG-4).
 */
namespace yellowback {

struct CoinbaseTag
{
    uint8_t flags;            //!< bit 0 = activation signal; bits 1-7 reserved, must be zero (TAG-2)
    uint64_t priceMicroUsd;   //!< YEC/USD quote; 0 = signal-only (V9)
    uint16_t sourceMask;      //!< informational bitfield of price sources
    uint160 payoutKey;        //!< Hash160 of the miner's enforcement-fee key (P2PKH); any 20 bytes (TAG-3)

    CoinbaseTag() : flags(0), priceMicroUsd(0), sourceMask(0) {}

    bool Signal() const { return (flags & 0x01) != 0; }
    /** TAG-3: a valid tag with a price is a quote tag; with price 0 it is signal-only. */
    bool IsQuote() const { return priceMicroUsd != TAG_PRICE_SIGNAL_ONLY; }

    friend bool operator==(const CoinbaseTag& a, const CoinbaseTag& b)
    {
        return a.flags == b.flags && a.priceMicroUsd == b.priceMicroUsd && a.sourceMask == b.sourceMask && a.payoutKey == b.payoutKey;
    }
};

/** TAG-2: version 1, reserved flag bits clear, price 0 or within [PRICE_MIN, PRICE_MAX]. */
bool IsValidTag(const CoinbaseTag& tag);

/** The 36 tag bytes (magic ‖ version ‖ body). Never fails: any field values serialise. */
std::vector<unsigned char> EncodeTag(const CoinbaseTag& tag);

/** The scriptSig fragment a miner appends: 0x24 ‖ 36 bytes (one direct push; COINBASE_FLAGS carries it, V5). */
CScript TagPush(const CoinbaseTag& tag);

/**
 * TAG-1..5. Skips the BIP34 height prefix `CScript() << nHeight` (the exact
 * bytes ContextualCheckBlock expects, ref/ycash/src/main.cpp:4477); if the
 * scriptSig does not start with it there is no tag. Scans the remaining bytes
 * for the first occurrence of the 5-byte pattern 24 59 45 44 21 (push opcode
 * ‖ magic, P10) and reads the 32 bytes after it as version ‖ body. Fewer than
 * 32 bytes after the first occurrence, or a TAG-2 failure on them, is "no
 * tag"; the scan never continues past the first occurrence (TAG-5, M2).
 */
std::optional<CoinbaseTag> FindTag(const CScript& scriptSig, int nHeight);

} // namespace yellowback

#endif // YCASH_YELLOWBACK_TAG_H
