// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Fuzz target for OP_CHECKPQSIG (docs/plans/yellowback-quantum-plan.md §4.2): the interpreter
// against an independent model of the scheme, key-hash, chunking, size and hashtype rules, over
// stacks described compactly by the input. The grammar and the properties are in
// src/test/pq_fuzz_harness.h; the same body replays the corpus in vault_fuzz_tests (make check).
// Corpus: src/fuzzing/PQScript/input (src/test/gen_pq_corpus.py).

#include "test/pq_fuzz_harness.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <vector>

int fuzz_PQScript(const std::vector<unsigned char>& data)
{
    int rc;
    try {
        rc = pq_fuzz::RunPQScript(data);
    } catch (const std::exception& e) {
        fprintf(stderr, "PQScript: exception: %s\n", e.what());
        abort();
    } catch (...) {
        fprintf(stderr, "PQScript: unknown exception\n");
        abort();
    }
    if (rc < 0) {
        fprintf(stderr, "PQScript: property %d violated\n", -rc);
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
    return fuzz_PQScript(data);
}

#endif // FUZZ_WITH_AFL
#ifdef FUZZ_WITH_LIBFUZZER

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    fuzz_PQScript(std::vector<unsigned char>(Data, Data + Size));
    return 0;
}

#endif
