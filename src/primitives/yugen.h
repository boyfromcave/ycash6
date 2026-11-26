// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Yugen leaf transfer decoding (yugen-spec 0.5.1 §7.1, d25a89c) and the constants the node rules
// of §7.9 / §16 use. Header only, so the transaction value functions can use it.

#ifndef YCASH_PRIMITIVES_YUGEN_H
#define YCASH_PRIMITIVES_YUGEN_H

#include <array>
#include <set>
#include <functional>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace yugen {

static constexpr int64_t MAX_MONEY_ZAT = 2100000000000000LL;
static constexpr uint64_t BASE_FEE = 100000;              // §2, provisional
static constexpr uint64_t LEAF_PROOF_FEE = 155600;        // §2
static constexpr size_t LEAF_PROOF_MAX_A = 719116;        // §2
static constexpr size_t LEAF_PROOF_MAX_B = 817736;        // §2
static constexpr size_t LEAF_BYTES_RESERVE = 18480;       // §2
static constexpr size_t LEAF_RESERVE = 1556000;           // §2
static constexpr int ANCHOR_GRID = 16;
static constexpr int ANCHOR_WINDOW = 96;
static constexpr size_t FIXED_LEN = 232;
static constexpr size_t PKG_SHORT = 1674, PKG_LONG = 2186;
// §15.1 (spec 0.5.3): a bundle's first byte, and the kind marker of the Yugen field: a field whose
// first byte is BUNDLE_VERSION is a bundle, any other a leaf transfer (whose first byte is
// fee_class, at most 3, §7.1).
static constexpr uint8_t BUNDLE_VERSION = 0x80;

enum Flag : uint16_t {
    PKG1 = 1 << 0, PKG2 = 1 << 1, PKG1_MEMO = 1 << 2, PKG2_MEMO = 1 << 3, VB = 1 << 4,
    CANARY = 1 << 5, LEAFFEE = 1 << 6, CANARY_A = 1 << 7, CANARY_B = 1 << 8, SCHEME2 = 1 << 9,
};

// A bundle's VB record (§15.1, spec 0.5.4): the transfer's transparent outputs (`vout`, iff flag VB)
// and, for a deposit (value_balance < 0), its inputs (`vin`). A leaf's are the transaction's own.
struct RecordOut {
    uint64_t value{0};
    std::vector<unsigned char> script;
};
struct RecordIn {
    std::array<uint8_t, 32> txid{};
    uint32_t index{0};
    std::vector<unsigned char> scriptSig;
};

struct Transfer {
    uint8_t feeClass{0};
    uint8_t anchorSlot{0};
    uint16_t flags{0};
    std::array<std::array<uint8_t, 32>, 2> nf{};
    std::array<std::array<uint8_t, 48>, 2> cm{};
    int64_t valueBalance{0};
    std::vector<RecordOut> vout;   // bundled transfers only (§15.1 VB record)
    std::vector<RecordIn> vin;

    uint64_t Fee() const {
        return (BASE_FEE << feeClass) + ((flags & LEAFFEE) ? LEAF_PROOF_FEE : 0);
    }
    // What the transfer gives to the transaction's transparent value: a withdrawal (positive
    // value_balance) and the transfer's fee, which the miner collects as transaction fee.
    int64_t TransparentDelta() const { return valueBalance + (int64_t)Fee(); }
};

// Decodes under §7.1. Returns the reason on failure (the reject code suffix).
inline std::optional<Transfer> Decode(const std::vector<unsigned char>& b, std::string& why)
{
    if (b.size() < FIXED_LEN) { why = "length"; return std::nullopt; }
    Transfer t;
    t.feeClass = b[0];
    t.anchorSlot = b[1];
    t.flags = (uint16_t)b[2] | ((uint16_t)b[3] << 8);
    size_t o = 4;
    for (int j = 0; j < 2; j++) { std::copy(b.begin() + o, b.begin() + o + 32, t.nf[j].begin()); o += 32; }
    for (int j = 0; j < 2; j++) { std::copy(b.begin() + o, b.begin() + o + 48, t.cm[j].begin()); o += 48; }
    o = FIXED_LEN;
    if (t.feeClass > 3) { why = "fee-class"; return std::nullopt; }
    if (t.flags & 0xfe00) { why = "reserved-flag"; return std::nullopt; }   // bits 9 (SCHEME2) to 15
    if ((t.flags & PKG1_MEMO) && !(t.flags & PKG1)) { why = "memo-flag"; return std::nullopt; }
    if ((t.flags & PKG2_MEMO) && !(t.flags & PKG2)) { why = "memo-flag"; return std::nullopt; }
    int canaries = !!(t.flags & CANARY) + !!(t.flags & CANARY_A) + !!(t.flags & CANARY_B);
    if (canaries > 1) { why = "canary-flags"; return std::nullopt; }
    if (t.nf[0] == t.nf[1]) { why = "nf-equal"; return std::nullopt; }
    if (t.flags & VB) {
        if (b.size() < o + 8) { why = "length"; return std::nullopt; }
        uint64_t u = 0;
        for (int i = 7; i >= 0; i--) u = (u << 8) | b[o + i];
        t.valueBalance = (int64_t)u;
        o += 8;
        if (t.valueBalance == 0) { why = "vb-zero"; return std::nullopt; }
        if (t.valueBalance < -MAX_MONEY_ZAT || t.valueBalance > MAX_MONEY_ZAT) { why = "vb-range"; return std::nullopt; }
    }
    for (int j = 0; j < 2; j++) {
        if (!(t.flags & (j == 0 ? PKG1 : PKG2))) continue;
        size_t len = (t.flags & (j == 0 ? PKG1_MEMO : PKG2_MEMO)) ? PKG_LONG : PKG_SHORT;
        if (b.size() < o + len) { why = "length"; return std::nullopt; }
        uint16_t bucket = (uint16_t)b[o] | ((uint16_t)b[o + 1] << 8);
        if (bucket >= 256) { why = "pkg-bucket"; return std::nullopt; }   // 2^PKG_BUCKET_BITS
        o += len;
    }
    if (o != b.size()) { why = "length"; return std::nullopt; }
    return t;
}

static constexpr size_t PROOF_BYTES_MAX = 1835008;        // §16.2 W1
static constexpr size_t BLOCK_BYTES_MAX = 2000000;        // §16.2 W2
static constexpr size_t BLOCK_WEIGHT_MAX = 4000000;       // §16.2 W3 (W)

// §13.3.1 (provisional, plan step 1.7): the value-cap ratchet (§13.3.6) and the outflow window's gross
// cap K (§13.3.5). Amounts in zatoshi.
static constexpr uint64_t RATCHET_C0 = 2100000000000ULL;   // 21,000 YEC
static constexpr uint32_t RATCHET_P = 103680;
static constexpr uint64_t RATCHET_CMAX = 64 * RATCHET_C0;
static constexpr uint32_t OUTFLOW_WINDOW = 1152;
static constexpr uint64_t OUTFLOW_CAP_PERMILLE = 125;

// §13.3.6: cap(h) from c0 at h0, doubling every p blocks, linear in between, never above cmax (no
// frozen mode on this line, so h' = h). yugen-ref safety::ratchet_cap.
inline uint64_t RatchetCap(int64_t h, int64_t h0, uint64_t c0, uint32_t p, uint64_t cmax)
{
    if (h <= h0) return c0;
    const uint64_t q = (uint64_t)(h - h0) / p, r = (uint64_t)(h - h0) % p;
    if (q >= 64) return cmax;
    const unsigned __int128 x = (unsigned __int128)c0 << q;
    if (x >= cmax) return cmax;
    const unsigned __int128 cap = x + x * r / p;
    return cap < cmax ? (uint64_t)cap : cmax;
}
inline uint64_t ValueCap(int h, int act) { return RatchetCap(h, act, RATCHET_C0, RATCHET_P, RATCHET_CMAX); }
// §13.3.5: K = floor(cap(h_w) * OUTFLOW_CAP_PERMILLE / 1000), h_w the first height of h's window.
inline uint64_t OutflowK(uint64_t capAtWindowStart) { return (uint64_t)((unsigned __int128)capAtWindowStart * OUTFLOW_CAP_PERMILLE / 1000); }
inline uint64_t GrossCap(int h, int act)
{
    const int hw = h <= act ? act : act + (h - act) / (int)OUTFLOW_WINDOW * (int)OUTFLOW_WINDOW;
    return OutflowK(ValueCap(hw, act));
}

// §15.1 (spec 0.5.4): Ycash's compact size in its shortest form only. 0: read; 1: the field ends
// first (`Truncated`); 2: a longer form than needed (the caller's `Vout` or `Vin`).
inline int ReadCompact(const std::vector<unsigned char>& b, size_t& o, uint64_t& n)
{
    if (o >= b.size()) return 1;
    uint8_t c = b[o++];
    size_t k = c < 253 ? 0 : c == 253 ? 2 : c == 254 ? 4 : 8;
    if (k == 0) { n = c; return 0; }
    if (b.size() - o < k) return 1;
    n = 0;
    for (size_t i = 0; i < k; i++) n |= (uint64_t)b[o + i] << (8 * i);
    o += k;
    const uint64_t min = k == 2 ? 253 : k == 4 ? 0x10000 : 0x100000000ULL;
    return n < min ? 2 : 0;
}

// §15.1 (spec 0.5.4): the VB record after a bundled transfer `t`, read from offset `o` in field order;
// the first failure wins, named as bundle.json names it: `Truncated` ("bundle-truncated"), `Vout`
// ("bundle-vout"), `Vin` ("bundle-vin"), `WithdrawalSum` ("bundle-withdrawal-sum"). Nothing is sized
// from a count before its bytes are read.
inline bool DecodeRecord(const std::vector<unsigned char>& b, size_t& o, Transfer& t, std::string& why)
{
    auto le = [&](size_t at, size_t len) { uint64_t v = 0; for (size_t i = 0; i < len; i++) v |= (uint64_t)b[at + i] << (8 * i); return v; };
    auto bad = [&](int rc, const char* err) { why = rc == 1 ? "bundle-truncated" : err; return false; };
    if (t.valueBalance == 0) return true;
    uint64_t n, l;
    int rc = ReadCompact(b, o, n);
    if (rc) return bad(rc, "bundle-vout");
    uint64_t sum = 0;
    for (uint64_t i = 0; i < n; i++) {
        if (b.size() - o < 8) return bad(1, "");
        const uint64_t v = le(o, 8);
        o += 8;
        if (v > (uint64_t)MAX_MONEY_ZAT || sum + v > (uint64_t)MAX_MONEY_ZAT) return bad(2, "bundle-vout");
        sum += v;
        if ((rc = ReadCompact(b, o, l))) return bad(rc, "bundle-vout");
        if (b.size() - o < l) return bad(1, "");
        t.vout.push_back({v, std::vector<unsigned char>(b.begin() + o, b.begin() + o + l)});
        o += l;
    }
    if (t.valueBalance > 0) {
        if (sum != (uint64_t)t.valueBalance) return bad(2, "bundle-withdrawal-sum");
        return true;
    }
    if ((rc = ReadCompact(b, o, n))) return bad(rc, "bundle-vin");
    if (n == 0) return bad(2, "bundle-vin");
    // A repeated prevout within the record, as yugen-ref's BTreeSet: O(n log n), not a scan (review C-1).
    std::set<std::pair<std::array<uint8_t, 32>, uint32_t>> seen;
    for (uint64_t i = 0; i < n; i++) {
        if (b.size() - o < 36) return bad(1, "");
        RecordIn in;
        std::copy(b.begin() + o, b.begin() + o + 32, in.txid.begin());
        in.index = (uint32_t)le(o + 32, 4);
        o += 36;
        if (!seen.emplace(in.txid, in.index).second) return bad(2, "bundle-vin");
        if ((rc = ReadCompact(b, o, l))) return bad(rc, "bundle-vin");
        if (b.size() - o < l) return bad(1, "");
        in.scriptSig.assign(b.begin() + o, b.begin() + o + l);
        o += l;
        t.vin.push_back(std::move(in));
    }
    return true;
}

// §15.5 (spec 0.5.4): the coin a deposit in a bundle may spend: exactly P2PKH or TX_PQPKH (scheme 1
// or 2), byte for byte; any other coin, P2SH among them, deposits by a leaf transfer.
inline bool DepositScriptOk(const std::vector<unsigned char>& s)
{
    if (s.size() == 25) return s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 && s[23] == 0x88 && s[24] == 0xac;
    if (s.size() == 35) return s[0] == 0x20 && (s[33] == 0x51 || s[33] == 0x52) && s[34] == 0xc2;
    return false;
}

// The transfers of a bundle's Yugen field (§15.1, §15.2), for the node's own bookkeeping (fees,
// nullifiers, anchor slots) and, since spec 0.5.4, their VB records (`Transfer::vout`, `vin`), which
// are decoded exactly. The rest of rule B1 (payee table, tree rules, anchor table order and use,
// the funded canary nullifier, mixed schemes) runs in the verifier helper (yugen-ref
// Bundle::decode), which every bundle passes before it is accepted anywhere. `raw` gets each
// transfer's own bytes (§7.1), without its record.
inline bool DecodeBundleTransfers(const std::vector<unsigned char>& b, std::vector<Transfer>& out,
                                  std::vector<uint8_t>& slots, std::string& why,
                                  std::vector<std::vector<unsigned char>>* raw = nullptr)
{
    why = "bundle-encoding";
    size_t o = 0;
    if (b.size() < 2 || b[0] != BUNDLE_VERSION || b[1] < 1 || b[1] > 6) return false;
    size_t na = b[1];
    o = 2;
    if (b.size() < o + 129 * na) return false;
    for (size_t i = 0; i < na; i++) { slots.push_back(b[o]); o += 129; }
    if (o + 2 > b.size()) return false;
    size_t P = b[o] | (b[o + 1] << 8);
    o += 2;
    for (size_t i = 0; i < P; i++) { if (o >= b.size()) return false; o += 1 + b[o]; }
    size_t n = 0;
    std::function<bool(int)> node = [&](int depth) -> bool {
        if (depth > 6 || o + 2 > b.size()) return false;
        uint8_t tag = b[o], k = b[o + 1];
        o += 2;
        if (k < 1 || k > 4) return false;
        if (tag == 0x00) { n += k; o += 2 * (k <= 2 ? 3 : 4); return o <= b.size(); }
        if (tag != 0x01) return false;
        if (k >= 2) o += 2 * (k <= 2 ? 3 : 4);
        for (int i = 0; i < k; i++) if (!node(depth + 1)) return false;
        return o <= b.size();
    };
    if (!node(0)) return false;
    for (size_t i = 0; i < n; i++) {
        size_t start = o;
        if (o + FIXED_LEN > b.size()) return false;
        uint16_t flags = b[o + 2] | (b[o + 3] << 8);
        size_t len = FIXED_LEN + ((flags & VB) ? 8 : 0);
        for (int j = 0; j < 2; j++)
            if (flags & (j == 0 ? PKG1 : PKG2)) len += (flags & (j == 0 ? PKG1_MEMO : PKG2_MEMO)) ? PKG_LONG : PKG_SHORT;
        if (o + len > b.size()) return false;
        std::vector<unsigned char> tb(b.begin() + start, b.begin() + start + len);
        std::string w;
        auto t = Decode(tb, w);
        if (!t) { why = "bundle-transfer-" + w; return false; }
        o += len;
        // B1: canary claims are leaf transactions (SPEC-79), refused here in field order.
        if (t->flags & (CANARY | CANARY_A | CANARY_B)) { why = "bundle-canary"; return false; }
        if (!DecodeRecord(b, o, *t, why)) return false;
        out.push_back(*t);
        if (raw) raw->push_back(tb);
    }
    if (o + 64 != b.size()) return false;
    why.clear();
    return true;
}

// Whether a Yugen field's `transfer` bytes are a bundle (§15.1) rather than a leaf transfer (§7.1).
// Spec 0.5.3 §15.1: the kind is the first byte, `bundle_version` = 0x80 for a bundle; any other first
// byte is a leaf's `fee_class` (a leaf with one above 3 is refused by §7.1). The byte is committed by
// the txid and the signature hash; the proof fields, which neither covers, never decide the kind
// (doc/yugen-node.md N-D7, N-D8): a relay that empties a leaf's proofs or adds proofs to a bundle
// changes no verdict on the transaction's kind. A field that begins with 0x80 and does not parse as
// §15.1 is a malformed bundle, never a leaf.
inline bool IsBundleEncoding(const std::vector<unsigned char>& b)
{
    return !b.empty() && b[0] == BUNDLE_VERSION;
}

// §8.1: anchor height ha is valid in a block at height h (activation height `act`).
inline bool AnchorValid(int ha, int h, int act)
{
    return ha >= act && ha % ANCHOR_GRID == 0 && ha < h && h - ha <= ANCHOR_WINDOW;
}

// §8.2, as yugen-ref transfer.rs resolve_anchor: the one valid anchor height with this slot, or -1.
inline int ResolveAnchor(uint8_t slot, int h, int act)
{
    if (h < 1) return -1;
    for (int ha = (h - 1) / ANCHOR_GRID * ANCHOR_GRID; ha >= 0; ha -= ANCHOR_GRID) {
        if (!AnchorValid(ha, h, act)) return -1;
        if (((ha / ANCHOR_GRID) & 0xff) == slot) return ha;
    }
    return -1;
}

} // namespace yugen

#endif // YCASH_PRIMITIVES_YUGEN_H
