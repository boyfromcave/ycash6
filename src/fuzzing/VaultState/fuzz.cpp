// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Fuzz target for the vault primitive's state rules (upgrade plan §15.4-§15.6): a byte stream decoded into
// transactions (set acts, V / I outputs, template and bond spends) over an in-memory base, applied with
// VaultState::ApplyTx one by one and as blocks (ApplyBlock), with the invariants checked after every block:
// atomicity, known reject reasons, running copy = block apply, determinism, undo round-trip, lockedValue,
// S-1. The grammar and the properties are in src/test/vault_state_fuzz_harness.h; the same body replays the
// corpus in vault_fuzz_tests (make check). Corpus: src/fuzzing/VaultState/input
// (src/test/gen_vault_state_corpus.py).

#include "key.h"
#include "test/vault_state_fuzz_harness.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <vector>

static void VaultStateInit()
{
    static bool done = false;
    if (done) return;
    ECC_Start();   // the acts are signed and recovered with secp256k1 (6.20.0: no ECCVerifyHandle)
    done = true;
}

int fuzz_VaultState(const std::vector<unsigned char>& data)
{
    VaultStateInit();
    int rc;
    try {
        rc = vault_state_fuzz::RunVaultState(data);
    } catch (const std::exception& e) {
        fprintf(stderr, "VaultState: exception: %s\n", e.what());
        abort();
    } catch (...) {
        fprintf(stderr, "VaultState: unknown exception\n");
        abort();
    }
    if (rc < 0) {
        fprintf(stderr, "VaultState: property %d violated\n", -rc);
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
    return fuzz_VaultState(data);
}

#endif // FUZZ_WITH_AFL
#ifdef FUZZ_WITH_LIBFUZZER

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    fuzz_VaultState(std::vector<unsigned char>(Data, Data + Size));
    return 0;
}

#endif
