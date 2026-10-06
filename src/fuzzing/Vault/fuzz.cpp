// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Fuzz target for the vault primitive's parsers (upgrade plan §15.3, §15.5): the V / I templates,
// the bond redeem script, the YV act codec and the template-spend parser, over arbitrary bytes.
// The grammar and the properties are in src/test/vault_fuzz_harness.h; the same body replays the
// corpus in vault_fuzz_tests (make check). Corpus: src/fuzzing/Vault/input
// (src/test/gen_vault_corpus.py).

#include "test/vault_fuzz_harness.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <vector>

int fuzz_Vault(const std::vector<unsigned char>& data)
{
    int rc;
    try {
        rc = vault_fuzz::RunVault(data);
    } catch (const std::exception& e) {
        fprintf(stderr, "Vault: exception: %s\n", e.what());
        abort();
    } catch (...) {
        fprintf(stderr, "Vault: unknown exception\n");
        abort();
    }
    if (rc < 0) {
        fprintf(stderr, "Vault: property %d violated\n", -rc);
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
    return fuzz_Vault(data);
}

#endif // FUZZ_WITH_AFL
#ifdef FUZZ_WITH_LIBFUZZER

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    fuzz_Vault(std::vector<unsigned char>(Data, Data + Size));
    return 0;
}

#endif
