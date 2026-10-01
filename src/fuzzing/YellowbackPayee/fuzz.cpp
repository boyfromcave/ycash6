// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Fuzz target for the wallet's default payee (plan §3.7 FEE-W, §7
// "Fuzzing", N34): DefaultPayee over random Tags/Judgements must pick a
// key of E(R), and must return nothing iff E(R) is empty (the all-
// penalised fallback is never empty). It guards the one wallet-side
// function that can make the wallet and the validator disagree. Body in
// src/test/yellowback_fuzz_harness.h; corpus in
// src/fuzzing/YellowbackPayee/input (src/test/gen_yellowback_corpus.py).

#include "test/yellowback_fuzz_harness.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <vector>

int fuzz_YellowbackPayee(const std::vector<unsigned char>& data)
{
    int rc;
    try {
        rc = yellowback_fuzz::RunPayee(data);
    } catch (const std::exception& e) {
        fprintf(stderr, "YellowbackPayee: exception: %s\n", e.what());
        abort();
    } catch (...) {
        fprintf(stderr, "YellowbackPayee: unknown exception\n");
        abort();
    }
    if (rc < 0) {
        fprintf(stderr, "YellowbackPayee: property %d violated\n", -rc);
        abort();
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
    return fuzz_YellowbackPayee(data);
}

#endif // FUZZ_WITH_AFL
#ifdef FUZZ_WITH_LIBFUZZER

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    fuzz_YellowbackPayee(std::vector<unsigned char>(Data, Data + Size));
    return 0;
}

#endif
