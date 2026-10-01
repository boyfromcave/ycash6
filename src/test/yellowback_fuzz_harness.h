// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_TEST_YELLOWBACK_FUZZ_HARNESS_H
#define YCASH_TEST_YELLOWBACK_FUZZ_HARNESS_H

// The bodies of the YellowbackEvaluate and YellowbackPayee fuzz targets
// (plan §7 "Fuzzing", N34), shared by src/fuzzing/<Target>/fuzz.cpp and
// the Boost replay cases in yellowback_fuzz_tests.cpp so the corpus is
// exercised by `make check` without a fuzzing build. Header-only, no Boost.
//
// YellowbackEvaluate decodes its input with a fixed prefix grammar (every
// read past the end yields zero, so decoding itself is total):
//
//   u8  nTags (mod 65)         then nTags x { u8 dh, u8 flags, u64 price, u16 mask, u8 keyIdx }
//                              Tags[START + dh] = { key(keyIdx), price, flags & 1, mask }
//   u8  nVaults (mod 17)       then nVaults x { u8 status, u8 termClass, u32 lock, i64 collateral,
//                              i64 minted, u32 refHeight }      Vaults[fill(i + 1):0], owner = KEY
//   u8  nTokens (mod 17)       then nTokens x { i64 cents }      Tokens[fill(0x80 + i):0]
//   snapshot for H - 1:        u8 status, u32 haltMask, i64 pFast, i64 pMid, i64 pSlow, i32 sigma, i64 issued
//   activation record:         u8 status, i32 lockIn, i32 activate
//   u8  hsel                   H = START - 2 + (hsel mod (VOL_WINDOW + 11))   (START - 2 .. START + VOL_WINDOW + 8)
//   rest                       a serialised CBlock; a deserialisation failure discards the input (M10)
//
// Totals are seeded consistently (supply = sum of the tokens, collateral =
// sum of the ACTIVE vaults), regtest params are fixed at {1, 0, 0, 0} and
// the block hash is SHA256 of the whole input. Then the four properties
// (N34): (i) apply -> undo byte identity, (ii) overlay evaluation equals the
// base result, (iii) blockInvalid => enforcementOn was computed at H,
// (iv) supplyCents == sum of the Tokens.
//
// YellowbackPayee: u8 nTags (mod 65) x { u8 dh, u64 price, u8 keyIdx, u8 judgementBits (1 = written,
// 2 = evaluated, 4 = inBand, 8 = penalized) }, u8 rsel (R = START + rsel), u8 selLen + selector bytes,
// u8 penaltyBlocks, u8 accuracyWindow, u16 tiltBps, u8 preferredIdx (0xFF = none). Properties: the
// pick is in E(R), and it is nullopt iff E(R) is empty.

#include "yellowback/params.h"
#include "yellowback/state.h"
#include "yellowback/view.h"

#include "crypto/sha256.h"
#include "primitives/block.h"
#include "streams.h"
#include "version.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace yellowback_fuzz {

/** Bounds-checked little-endian reader; a read past the end yields zero. */
class Reader
{
public:
    explicit Reader(const std::vector<unsigned char>& d) : data(d), pos(0) {}
    uint8_t U8() { return pos < data.size() ? data[pos++] : (pos++, 0); }
    uint16_t U16() { uint16_t v = U8(); v |= (uint16_t)U8() << 8; return v; }
    uint32_t U32() { uint32_t v = U16(); v |= (uint32_t)U16() << 16; return v; }
    uint64_t U64() { uint64_t v = U32(); v |= (uint64_t)U32() << 32; return v; }
    int32_t I32() { return (int32_t)U32(); }
    int64_t I64() { return (int64_t)U64(); }
    std::vector<unsigned char> Rest() const
    {
        if (pos >= data.size()) return {};
        return std::vector<unsigned char>(data.begin() + pos, data.end());
    }
    std::vector<unsigned char> Bytes(size_t n)
    {
        std::vector<unsigned char> out;
        for (size_t i = 0; i < n; i++) out.push_back(U8());
        return out;
    }

private:
    const std::vector<unsigned char>& data;
    size_t pos;
};

inline uint160 KeyOf(uint8_t idx)
{
    return uint160(std::vector<unsigned char>(20, idx));
}

inline uint256 Fill(uint8_t b)
{
    return uint256(std::vector<unsigned char>(32, b));
}

/** The fixed, syntactically valid compressed key of the corpus generator. */
inline std::vector<unsigned char> FixedKey()
{
    static const unsigned char k[33] = { 0x02, 0xcb, 0x81, 0xcc, 0x02, 0x69, 0x78, 0x3e, 0xbd, 0x9e, 0x64, 0x84, 0xb5, 0x49, 0x53, 0x43, 0x03,
                                         0x68, 0x74, 0xa4, 0x07, 0x85, 0x6f, 0x23, 0x0a, 0x8e, 0xe0, 0x38, 0x49, 0x86, 0x75, 0x9e, 0x70 };
    return std::vector<unsigned char>(k, k + 33);
}

inline uint256 InputHash(const std::vector<unsigned char>& data)
{
    unsigned char d[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(data.data(), data.size()).Finalize(d);
    return uint256(std::vector<unsigned char>(d, d + 32));
}

inline int64_t SumTokens(const yellowback::StateView& view)
{
    int64_t sum = 0;
    view.Iterate("K", [&](const std::string&, const std::string& raw) {
        yellowback::TokenRecord t;
        if (yellowback::DeserializeRecord(raw, t)) sum += t.cents;
        return true;
    });
    return sum;
}

/**
 * Seed the view per the grammar and return the height and block. Returns
 * false when the CBlock does not deserialise (the input is discarded).
 */
inline bool SeedEvaluate(const std::vector<unsigned char>& data, const yellowback::Params& P, yellowback::MemoryStateView& view, int& height, CBlock& block)
{
    using namespace yellowback;
    Reader r(data);
    State st(view);
    const uint8_t nTags = r.U8() % 65;
    for (int i = 0; i < nTags; i++) {
        const uint8_t dh = r.U8();
        TagRecord t;
        t.signal = (r.U8() & 1) != 0;
        t.priceMicroUsd = r.U64();
        t.sourceMask = r.U16();
        t.payoutKey = KeyOf(r.U8());
        st.Put(keys::Tag((uint32_t)(P.startHeight + dh)), t);
    }
    Totals totals;
    const uint8_t nVaults = r.U8() % 17;
    for (int i = 0; i < nVaults; i++) {
        VaultRecord v;
        v.status = r.U8() % 4;
        v.termClass = r.U8();
        v.lockHeight = (int32_t)r.U32();
        v.claimHeight = (int32_t)((int64_t)v.lockHeight + P.grace);
        v.collateralZat = r.I64();
        v.mintedCents = r.I64();
        v.refHeight = (int32_t)r.U32();
        v.ownerPubKey = FixedKey();
        v.mintHeight = P.startHeight;
        st.Put(keys::Vault(COutPoint(Fill((uint8_t)(i + 1)), 0)), v);
        switch (v.Status()) {
        case VaultStatus::ACTIVE: totals.activeVaults++; totals.collateralZat += v.collateralZat; break;
        case VaultStatus::VOID: totals.voidVaults++; break;
        case VaultStatus::CLOSED: totals.closedVaults++; break;
        case VaultStatus::CLAIMED: totals.claimedVaults++; break;
        }
    }
    const uint8_t nTokens = r.U8() % 17;
    for (int i = 0; i < nTokens; i++) {
        TokenRecord t;
        t.cents = r.I64();
        t.nValue = TOKEN_VALUE;
        t.height = P.startHeight;
        st.Put(keys::Token(COutPoint(Fill((uint8_t)(0x80 + i)), 0)), t);
        totals.supplyCents += t.cents;
    }
    st.Put(keys::Totals(), totals);
    Snapshot prev;
    prev.activation.status = r.U8() % 3;
    prev.haltMask = r.U32();
    prev.pFast = r.I64();
    prev.pMid = r.I64();
    prev.pSlow = r.I64();
    prev.sigmaMultBps = r.I32();
    prev.issuedZat = r.I64();
    if (prev.pFast > 0 && prev.pMid > 0 && prev.pSlow > 0) prev.pMint = std::min(prev.pFast, std::min(prev.pMid, prev.pSlow));
    if (prev.pMid > 0 && prev.pSlow > 0) prev.pClaim = std::max(prev.pMid, prev.pSlow);
    Activation a;
    a.status = r.U8() % 3;
    a.lockInHeight = r.I32();
    a.activateHeight = r.I32();
    st.Put(keys::Activation(), a);
    const uint8_t hsel = r.U8();
    height = P.startHeight - 2 + (int)(hsel % (uint8_t)(P.volWindow + 11));
    if (height - 1 >= P.startHeight) st.Put(keys::Snapshot((uint32_t)(height - 1)), prev);
    st.Put(keys::Params(), ParamsRecord(P));
    std::vector<unsigned char> rest = r.Rest();
    try {
        CDataStream ss(rest, SER_NETWORK, PROTOCOL_VERSION);
        ss >> block;
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

/**
 * The YellowbackEvaluate body. Returns 0 (ok), 1 (input discarded: the
 * block did not deserialise), or a negative code naming the violated
 * property: -1 apply/undo identity, -2 overlay equivalence, -3 the
 * enforcement flag, -4 supply == sum of tokens. An exception is the
 * caller's failure (the target is total).
 */
inline int RunEvaluate(const std::vector<unsigned char>& data)
{
    using namespace yellowback;
    const Params P = RegtestParams(1, 0, 0, 0);
    MemoryStateView base;
    int height = 0;
    CBlock block;
    if (!SeedEvaluate(data, P, base, height, block)) return 1;
    const uint256 blockHash = InputHash(data);
    const MemoryStateView before = base;
    const int64_t supplyBefore = State(base).GetTotals().supplyCents;
    const int64_t tokensBefore = SumTokens(base);
    const bool enforcing = EnforcementOn(State(base), P, height);

    // (ii) the overlay evaluation, committed into a copy
    MemoryStateView viaOverlay = base;
    BlockEvaluation ev;
    {
        OverlayStateView overlay(viaOverlay);
        ev = EvaluateBlock(overlay, P, block, height, blockHash, 625000000);
        overlay.Commit();
    }
    UndoRecord undo;
    ApplyBlock(base, P, block, height, blockHash, 625000000, undo);
    if (!(viaOverlay == base)) return -2;
    if (!(SerializeRecord(undo) == SerializeRecord(ev.undo))) return -2;
    // (iii)
    if (ev.blockInvalid && ev.enforcementOn != enforcing) return -3;
    if (ev.enforcementOn != enforcing) return -3;
    // (iv), given a consistent seed
    if (supplyBefore == tokensBefore && State(base).GetTotals().supplyCents != SumTokens(base)) return -4;
    // (i)
    UndoBlock(base, undo);
    if (!(base == before)) return -1;
    return 0;
}

/** The YellowbackPayee body: 0 ok, -1 the pick is outside E(R), -2 nullopt with a non-empty E(R) (or the reverse). */
inline int RunPayee(const std::vector<unsigned char>& data)
{
    using namespace yellowback;
    const Params P = RegtestParams(1, 0, 0, 0);
    MemoryStateView view;
    State st(view);
    Reader r(data);
    const uint8_t nTags = r.U8() % 65;
    for (int i = 0; i < nTags; i++) {
        const uint8_t dh = r.U8();
        TagRecord t;
        t.priceMicroUsd = r.U64();
        t.payoutKey = KeyOf(r.U8() % 8);
        t.signal = true;
        const uint8_t jb = r.U8();
        st.Put(keys::Tag((uint32_t)(P.startHeight + dh)), t);
        if (jb & 1) {
            Judgement j;
            j.evaluated = (jb & 2) != 0;
            j.inBand = (jb & 4) != 0;
            j.penalized = (jb & 8) != 0;
            st.Put(keys::Judgement((uint32_t)(P.startHeight + dh)), j);
        }
    }
    const int R = P.startHeight + r.U8();
    const std::vector<unsigned char> selector = r.Bytes(r.U8());
    PayeePolicy policy;
    policy.penaltyBlocks = r.U8();
    policy.accuracyWindow = r.U8();
    policy.tiltBps = r.U16();
    const uint8_t pref = r.U8();
    if (pref != 0xFF) policy.preferred = CKeyID(KeyOf(pref % 8));
    Snapshot s;
    s.blockHash = InputHash(data);
    st.Put(keys::Snapshot((uint32_t)R), s);

    const std::vector<CKeyID> eligible = EligiblePayees(view, P, R);
    std::optional<CKeyID> pick = DefaultPayee(view, P, R, selector, policy);
    if (pick.has_value() != !eligible.empty()) return -2;
    if (pick.has_value()) {
        bool found = false;
        for (const CKeyID& k : eligible) found = found || k == pick.value();
        if (!found) return -1;
    }
    return 0;
}

} // namespace yellowback_fuzz

#endif // YCASH_TEST_YELLOWBACK_FUZZ_HARNESS_H
