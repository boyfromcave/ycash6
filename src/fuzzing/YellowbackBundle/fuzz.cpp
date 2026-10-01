// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Fuzz target for the Yellowback attestation bundle codec and BUNDLE-1
// verifier (v3 plan §3.8, §7 "Fuzzing"). Same layout as the other targets
// under src/fuzzing/: an AFL main reading a file, and a libFuzzer entry
// point. Input grammar: byte 0 selects the shape (0 = one carrier input at
// vin[1], 1 = OP_RETURN tail, 2 = two carriers, 3 = carrier with a wrong
// hash commitment, other = no carrier); the rest is the bundle bytes. The
// verifier runs with a stub pubkeyOf (one fixed key for every seq) and a
// stub blockHashAt (SHA256 of the height), so the signature step is
// exercised and must never crash; no input can produce a valid signature
// for the fixed key except by finding one, so `ok` is reported as -3 for
// a corpus-level sanity check. Codec: a decoded bundle re-encodes to the
// input; every prefix decodes without fault. Corpus:
// src/fuzzing/YellowbackBundle/input (src/test/gen_yellowback_attest_vectors.py).

#include "yellowback/attest.h"
#include "yellowback/bundle.h"
#include "yellowback/script.h"

#include "crypto/sha256.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/script.h"

#include <cstdint>
#include <cstdio>
#include <vector>

namespace {

CPubKey FixedKey()
{
    // The generator's key for seq 0 (src/test/data/yellowback_attest_vectors.json).
    static const unsigned char k[33] = { 0x02, 0x2a, 0x5e, 0x8d, 0xd4, 0x63, 0x96, 0x26, 0xd6, 0x7b, 0x9d, 0xa1, 0x23, 0x73, 0xca, 0x77,
                                         0x96, 0x0e, 0xf7, 0x6d, 0x04, 0x65, 0xee, 0x1c, 0x9b, 0x2a, 0x5d, 0x33, 0x7d, 0x37, 0xe0, 0xc2, 0x91 };
    return CPubKey(k, k + 33);
}

uint256 Sha256(const std::vector<unsigned char>& d)
{
    uint256 out;
    CSHA256().Write(d.empty() ? nullptr : d.data(), d.size()).Finalize(out.begin());
    return out;
}

CTxIn CarrierIn(const std::vector<unsigned char>& bundle, const uint256& commit, uint32_t n)
{
    const CScript redeem = yellowback::CarrierScript(FixedKey(), commit);
    return CTxIn(COutPoint(uint256(), n), yellowback::CarrierScriptSig(bundle, std::vector<unsigned char>(71, 0x30), redeem));
}

} // namespace

int fuzz_YellowbackBundle(const std::vector<unsigned char>& data)
{
    if (data.empty()) return 0;
    const unsigned char shape = data[0];
    const std::vector<unsigned char> bundle(data.begin() + 1, data.end());

    // Codec.
    if (std::optional<yellowback::Bundle> b = yellowback::DecodeBundle(bundle, 255)) {
        if (yellowback::EncodeBundle(*b) != bundle) return -2;
    }
    for (size_t n = 0; n < bundle.size() && n < 8; n++) {
        yellowback::DecodeBundle(std::vector<unsigned char>(bundle.begin(), bundle.begin() + n));
    }
    if (bundle.size() >= yellowback::ATTESTATION_SIZE) {
        yellowback::DecodeAttestation(bundle.data(), yellowback::ATTESTATION_SIZE);
    }

    // The transaction.
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn(COutPoint(uint256(), 9), CScript() << std::vector<unsigned char>(71, 0x30) << std::vector<unsigned char>(33, 0x02)));
    std::vector<unsigned char> tail;
    uint256 wrong = Sha256(bundle);
    *wrong.begin() ^= 1;
    switch (shape) {
    case 0: mtx.vin.push_back(CarrierIn(bundle, Sha256(bundle), 0)); break;
    case 1: tail = bundle; break;
    case 2: mtx.vin.push_back(CarrierIn(bundle, Sha256(bundle), 0)); mtx.vin.push_back(CarrierIn(bundle, Sha256(bundle), 1)); break;
    case 3: mtx.vin.push_back(CarrierIn(bundle, wrong, 0)); break;
    default: break;
    }
    mtx.vout.push_back(CTxOut(0, CScript() << OP_RETURN));
    const CTransaction tx(mtx);

    yellowback::BundleLimits limits;
    limits.attestMaxAge = 8;
    limits.mSelect = 2;
    limits.bundleMax = 6;
    limits.startHeight = 1000;
    limits.priceMin = yellowback::PRICE_MIN;
    limits.priceMax = yellowback::PRICE_MAX;
    const std::vector<uint16_t> selected = { 0, 1, 2, 3, 4, 5 };
    auto pubkeyOf = [](uint16_t) -> std::optional<CPubKey> { return FixedKey(); };
    auto blockHashAt = [](int h) -> std::optional<uint256> {
        std::vector<unsigned char> pre = { (unsigned char)h, (unsigned char)(h >> 8), (unsigned char)(h >> 16), (unsigned char)(h >> 24) };
        return Sha256(pre);
    };
    int rc = 0;
    for (yellowback::BundleCarrier mode : { yellowback::BundleCarrier::SCRIPTSIG, yellowback::BundleCarrier::OP_RETURN, yellowback::BundleCarrier::EITHER }) {
        for (bool skip : { false, true }) {
            std::string reason;
            yellowback::ExtractBundle(tx, mode, skip, tail, &reason);
            yellowback::BundleVerdict v = yellowback::VerifyBundle(tx, mode, skip, tail, 1003, selected, limits, pubkeyOf, blockHashAt, nullptr);
            if (v.ok) {
                rc = -3;   // a valid signature under the fixed key: impossible without the secret, worth a look
                std::vector<arith_uint256> w(v.C.size(), arith_uint256(1));
                yellowback::BundleStat(v.C, w, limits.mSelect, 3333, 6667);
            } else if (v.reason.empty()) {
                return -4;   // every failure names a reason
            }
        }
    }
    yellowback::FindCarrierInput(tx, false);
    yellowback::FindCarrierInput(tx, true);
    return rc;
}

#ifdef FUZZ_WITH_AFL

int main(int argc, char* argv[])
{
    FILE* f = fopen(argv[1], "rb");
    if (!f) return -1;
    std::vector<unsigned char> data;
    unsigned char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) data.insert(data.end(), buf, buf + n);
    fclose(f);
    return fuzz_YellowbackBundle(data);
}

#endif // FUZZ_WITH_AFL
#ifdef FUZZ_WITH_LIBFUZZER

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    fuzz_YellowbackBundle(std::vector<unsigned char>(Data, Data + Size));
    return 0;
}

#endif
