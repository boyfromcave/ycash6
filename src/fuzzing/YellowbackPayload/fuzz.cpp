// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Fuzz target for the Yellowback payload decoder, version 2 (plan §3.3, §7
// "Fuzzing"). Same layout as the other targets under src/fuzzing/: an AFL
// main reading a file, and a libFuzzer entry point. The decoder must never
// throw or read out of bounds; a malformed payload is simply "not
// Yellowback"; a decoded payload re-encodes to the input. Corpus:
// src/fuzzing/YellowbackPayload/input (src/test/gen_yellowback_corpus.py).

#include "yellowback/payload.h"

#include "primitives/transaction.h"
#include "script/script.h"

#include <cstdint>
#include <cstdio>
#include <vector>

int fuzz_YellowbackPayload(const std::vector<unsigned char>& data)
{
    yellowback::Payload p;
    if (yellowback::DecodePayload(data, p)) {
        // Round trip: re-encoding a decoded payload must reproduce the input.
        std::vector<unsigned char> again = yellowback::EncodePayload(p);
        if (again != data) return -2;
    }
    // The same bytes as an OP_RETURN script and inside a transaction.
    CScript script = yellowback::PayloadScript(data);
    yellowback::ExtractOpReturnData(script);
    CMutableTransaction mtx;
    mtx.vout.push_back(CTxOut(0, CScript(data.begin(), data.end())));
    mtx.vout.push_back(CTxOut(0, script));
    yellowback::FindPayload(CTransaction(mtx));
    // Every prefix must be safe too.
    for (size_t n = 0; n < data.size(); n++) {
        yellowback::Payload q;
        yellowback::DecodePayload(std::vector<unsigned char>(data.begin(), data.begin() + n), q);
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
    return fuzz_YellowbackPayload(data);
}

#endif // FUZZ_WITH_AFL
#ifdef FUZZ_WITH_LIBFUZZER

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    fuzz_YellowbackPayload(std::vector<unsigned char>(Data, Data + Size));
    return 0;
}

#endif
