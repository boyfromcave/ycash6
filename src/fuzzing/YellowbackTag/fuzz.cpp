// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Fuzz target for the coinbase tag reader (plan §3.2, §7 "Fuzzing"). Input:
// LE32(nHeight) ‖ scriptSig. FindTag must never throw or read out of bounds
// on any bytes, and a tag it finds must re-encode to bytes that are present
// in the scriptSig (0x24 ‖ EncodeTag(tag) after the height prefix). Same
// layout as the other targets under src/fuzzing/: an AFL main reading a file
// and a libFuzzer entry point. Corpus: src/fuzzing/YellowbackTag/input
// (src/test/gen_yellowback_corpus.py).

#include "yellowback/tag.h"

#include "script/script.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <vector>

int fuzz_YellowbackTag(const std::vector<unsigned char>& data)
{
    int nHeight = 1;
    size_t start = 0;
    if (data.size() >= 4) {
        nHeight = (int)(((uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24)) & 0x7FFFFFFF);
        start = 4;
    }
    CScript scriptSig(data.begin() + start, data.end());
    std::optional<yellowback::CoinbaseTag> tag = yellowback::FindTag(scriptSig, nHeight);
    if (tag.has_value()) {
        // Round trip: the found tag's push must occur in the scriptSig after the height prefix.
        CScript push = yellowback::TagPush(tag.value());
        const CScript prefix = CScript() << nHeight;
        if (std::search(scriptSig.begin() + prefix.size(), scriptSig.end(), push.begin(), push.end()) == scriptSig.end()) return -2;
        if (!yellowback::IsValidTag(tag.value())) return -3;
        if (yellowback::EncodeTag(tag.value()).size() != yellowback::TAG_SIZE) return -4;
    }
    // The whole input as a scriptSig at a few fixed heights, and every prefix.
    for (int h : { 0, 1, 16, 17, 65535, 1234567 }) {
        yellowback::FindTag(CScript(data.begin(), data.end()), h);
    }
    for (size_t n = 0; n < scriptSig.size(); n++) {
        yellowback::FindTag(CScript(scriptSig.begin(), scriptSig.begin() + n), nHeight);
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
    return fuzz_YellowbackTag(data);
}

#endif // FUZZ_WITH_AFL
#ifdef FUZZ_WITH_LIBFUZZER

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    fuzz_YellowbackTag(std::vector<unsigned char>(Data, Data + Size));
    return 0;
}

#endif
