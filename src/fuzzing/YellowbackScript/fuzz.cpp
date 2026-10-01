// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Fuzz target for the Yellowback script parsers (plan §3.4, §7 "Fuzzing"):
// ParseVaultScript, ParseVaultSpendPath and ExtractRedeemScript over
// arbitrary bytes. They must never throw; a parsed vault script rebuilds to
// the input. Corpus: src/fuzzing/YellowbackScript/input
// (src/test/gen_yellowback_corpus.py).

#include "yellowback/script.h"

#include "script/script.h"

#include <cstdint>
#include <cstdio>
#include <vector>

int fuzz_YellowbackScript(const std::vector<unsigned char>& data)
{
    CScript script(data.begin(), data.end());
    uint32_t lock, claim;
    CPubKey owner;
    if (yellowback::ParseVaultScript(script, lock, owner, claim)) {
        if (yellowback::VaultScript(lock, owner, claim) != script) return -2;
        if (claim <= lock) return -3;
    }
    std::optional<yellowback::VaultSpendPath> path = yellowback::ParseVaultSpendPath(script);
    CScript redeem;
    bool hasRedeem = yellowback::ExtractRedeemScript(script, redeem);
    if (path.has_value()) {
        if (!hasRedeem || path->vaultScript != redeem) return -4;
        if (path->pushes < 2) return -5;
    }
    for (size_t n = 0; n < data.size(); n++) {
        CScript prefix(data.begin(), data.begin() + n);
        yellowback::ParseVaultScript(prefix, lock, owner, claim);
        yellowback::ParseVaultSpendPath(prefix);
        yellowback::ExtractRedeemScript(prefix, redeem);
    }
    return 0;
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
    return fuzz_YellowbackScript(data);
}

#endif // FUZZ_WITH_AFL
#ifdef FUZZ_WITH_LIBFUZZER

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    fuzz_YellowbackScript(std::vector<unsigned char>(Data, Data + Size));
    return 0;
}

#endif
