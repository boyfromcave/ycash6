// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_YELLOWBACK_TAG_H
#define YCASH_YELLOWBACK_TAG_H

#include "script/script.h"
#include "script/standard.h"
#include "uint256.h"
#include "yellowback/params.h"

#include <cstdint>
#include <ios>
#include <optional>
#include <vector>

/**
 * The coinbase tag (plan §3.2, V4, V5): 36 bytes carried in the coinbase
 * scriptSig as one direct push (0x24 ‖ tag) somewhere after the BIP34 height
 * push. Little-endian throughout.
 *
 *   v1: magic 4 ("YED!") | version 1 | flags 1 | priceMicroUsd 8 | sourceMask 2 | payoutKey 20
 *
 * Tag v2 (docs/plans/beta4/price-feed.md §4.3, D-8, D-10): 49 bytes, pushed as
 * 0x31 ‖ tag, for a post-quantum payout key; v1 stays for P2PKH payees.
 *
 *   v2: magic 4 | 0x02 | flags 1 | priceMicroUsd 8 | sourceMask 2 | payoutScheme 1 | payoutHash 32
 *
 * payoutScheme is pq::SCHEME_SLH_DSA_SHA2_128S (0x01) or pq::SCHEME_FN_DSA_512
 * (0x02); payoutHash is the CPQKeyID hash SHA256(scheme ‖ pk).
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

static const unsigned char TAG_VERSION_V2 = 0x02;
static const size_t TAG_SIZE_V2 = 49;
static const uint8_t PAYEE_P2PKH = 0x00;   //!< Payee kind 0; kinds 0x01/0x02 are the pq:: scheme bytes

/**
 * A fee payee (beta4 P1 spec §2): kind 0 = P2PKH with a 20-byte Hash160, kind
 * 1/2 = the post-quantum scheme byte with the 32-byte CPQKeyID hash. Nothing
 * else is a payee. Ordered by kind, then the hash bytes (memcmp; kind 0
 * compares its 20 bytes, the unused tail of `hash` is always zero), so a
 * v1-only ordering is unchanged. Serialised as kind u8 then the 20 or 32 raw
 * hash bytes, no length prefix (SCHEMA_VERSION 16).
 */
struct Payee
{
    uint8_t kind;
    uint256 hash;   //!< kind 0: bytes [0, 20) are the Hash160, [20, 32) zero

    Payee() : kind(PAYEE_P2PKH) {}

    static Payee FromKeyID(const CKeyID& key);
    static Payee FromPQ(const CPQKeyID& id);   //!< the caller passes a registered scheme
    /** The payee a fee output pays: exactly `76 a9 14 <20> 88 ac` or exactly GetScriptForPQKey of a known scheme. */
    static std::optional<Payee> FromScript(const CScript& scriptPubKey);
    /** A CKeyID or a CPQKeyID of a known scheme; nothing else (P2SH, no destination). */
    static std::optional<Payee> FromDestination(const CTxDestination& dest);

    bool IsP2PKH() const { return kind == PAYEE_P2PKH; }
    bool IsValid() const;                            //!< kind 0, or a known scheme
    size_t HashSize() const { return IsP2PKH() ? 20 : 32; }
    CKeyID KeyID() const;                            //!< kind 0 only
    CPQKeyID PQKeyID() const;                        //!< kind 1/2 only
    /** kind 0: the 25-byte P2PKH; kind s: GetScriptForPQKey(CPQKeyID(s, hash)), 35 bytes. */
    CScript Script() const;
    CTxDestination Destination() const;
    /** yed_gettag.payoutScheme (rpcversion 11): "p2pkh", "slh-dsa-sha2-128s" or "fn-dsa-512". */
    std::string SchemeName() const;

    friend bool operator==(const Payee& a, const Payee& b) { return a.kind == b.kind && a.hash == b.hash; }
    friend bool operator!=(const Payee& a, const Payee& b) { return !(a == b); }
    friend bool operator<(const Payee& a, const Payee& b) { return a.kind != b.kind ? a.kind < b.kind : a.hash < b.hash; }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, kind);
        s.write((const char*)hash.begin(), HashSize());
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, kind);
        hash.SetNull();
        if (!IsValid()) throw std::ios_base::failure("Payee: unknown kind");
        s.read((char*)hash.begin(), HashSize());
    }
};

struct CoinbaseTag
{
    uint8_t version;          //!< TAG_VERSION (v1, a P2PKH payee) or TAG_VERSION_V2 (a post-quantum payee)
    uint8_t flags;            //!< bit 0 = activation signal; bits 1-7 reserved, must be zero (TAG-2)
    uint64_t priceMicroUsd;   //!< YEC/USD quote; 0 = signal-only (V9)
    uint16_t sourceMask;      //!< informational bitfield of price sources
    Payee payee;              //!< v1: kind 0 / payoutKey (any 20 bytes, TAG-3); v2: kind payoutScheme / payoutHash

    CoinbaseTag() : version(TAG_VERSION), flags(0), priceMicroUsd(0), sourceMask(0) {}

    bool Signal() const { return (flags & 0x01) != 0; }
    /** TAG-3: a valid tag with a price is a quote tag; with price 0 it is signal-only. */
    bool IsQuote() const { return priceMicroUsd != TAG_PRICE_SIGNAL_ONLY; }

    friend bool operator==(const CoinbaseTag& a, const CoinbaseTag& b)
    {
        return a.version == b.version && a.flags == b.flags && a.priceMicroUsd == b.priceMicroUsd && a.sourceMask == b.sourceMask && a.payee == b.payee;
    }
};

/** The tag a node emits for a payee: v1 for P2PKH, v2 for a post-quantum payee (version set from the payee's kind). */
CoinbaseTag MakeTag(uint8_t flags, uint64_t priceMicroUsd, uint16_t sourceMask, const Payee& payee);

/** TAG-2: version 1 with a P2PKH payee or version 2 with a known scheme, reserved flag bits clear, price 0 or within [PRICE_MIN, PRICE_MAX]. */
bool IsValidTag(const CoinbaseTag& tag);

/** The 36 (v1) or 49 (v2, any version but 1) tag bytes (magic ‖ version ‖ body). Never fails: any field values serialise. */
std::vector<unsigned char> EncodeTag(const CoinbaseTag& tag);

/** The scriptSig fragment a miner appends: 0x24 ‖ 36 bytes or 0x31 ‖ 49 bytes (one direct push; COINBASE_FLAGS carries it, V5). */
CScript TagPush(const CoinbaseTag& tag);

/**
 * TAG-1..5. Skips the BIP34 height prefix `CScript() << nHeight` (the exact
 * bytes ContextualCheckBlock expects, ref/ycash/src/main.cpp:4477); if the
 * scriptSig does not start with it there is no tag. Scans the remaining bytes
 * for the first occurrence of either 5-byte pattern, 24 59 45 44 21 (v1) or
 * 31 59 45 44 21 (v2) (push opcode ‖ magic, P10), whichever comes first by
 * position, and reads the 32 (v1) or 45 (v2) bytes after it as version ‖
 * body. A v1 pattern must carry version 1 and a v2 pattern version 2. Fewer
 * bytes than the body after the first occurrence, or a TAG-2 failure on
 * them, is "no tag"; the scan never continues past the first occurrence
 * (TAG-5, M2).
 */
std::optional<CoinbaseTag> FindTag(const CScript& scriptSig, int nHeight);

} // namespace yellowback

#endif // YCASH_YELLOWBACK_TAG_H
