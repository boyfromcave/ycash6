// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Fuzz target for the Yellowback state machine (plan §3.8, §7 "Fuzzing",
// K1, N34): EvaluateBlock over a seeded in-memory view and an arbitrary
// serialised block, under a try/catch that fails the run on any exception
// (the evaluator is total), asserting the four properties of
// src/test/yellowback_fuzz_harness.h (apply/undo identity, overlay
// equivalence, the enforcement flag, supply == tokens). Same layout as the
// other targets under src/fuzzing/: an AFL main reading a file, and a
// libFuzzer entry point. Corpus: src/fuzzing/YellowbackEvaluate/input
// (src/test/gen_yellowback_corpus.py).

#include "test/yellowback_fuzz_harness.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <vector>

int fuzz_YellowbackEvaluate(const std::vector<unsigned char>& data)
{
    int rc;
    try {
        rc = yellowback_fuzz::RunEvaluate(data);
    } catch (const std::exception& e) {
        fprintf(stderr, "YellowbackEvaluate: exception: %s\n", e.what());
        abort();
    } catch (...) {
        fprintf(stderr, "YellowbackEvaluate: unknown exception\n");
        abort();
    }
    if (rc < 0) {
        fprintf(stderr, "YellowbackEvaluate: property %d violated\n", -rc);
        abort();
    }
    return rc == 1 ? -1 : 0;
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
    return fuzz_YellowbackEvaluate(data);
}

#endif // FUZZ_WITH_AFL
#ifdef FUZZ_WITH_LIBFUZZER

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    fuzz_YellowbackEvaluate(std::vector<unsigned char>(Data, Data + Size));
    return 0;
}

#endif
