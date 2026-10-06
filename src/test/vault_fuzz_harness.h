// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_TEST_VAULT_FUZZ_HARNESS_H
#define YCASH_TEST_VAULT_FUZZ_HARNESS_H

// The body of the Vault fuzz target (src/fuzzing/Vault/fuzz.cpp), shared with the Boost replay
// in vault_fuzz_tests.cpp so `make check` runs every seed and every found-and-fixed crash without
// a fuzzing build. Header-only, no Boost.
//
// Input: u16 LE n ‖ spk (the next min(n, rest) bytes) ‖ scriptSig (the rest). An input shorter
// than two bytes is the spk alone (empty scriptSig).
//
// Over the spk the parsers of the vault primitive (upgrade plan §15.3, §15.5) run:
// vault::MatchVault / ParseVault, MatchIntent / ParseIntent, ParseBondRedeem, IsActOutput /
// DecodeAct (and ActFieldsValid on what decodes), and DecodePayload over the spk bytes as a bare
// payload P; over (spk, scriptSig) ParseSelector and ParseTemplateSpend. Properties (negative
// return codes):
//   -1  a parsed V rebuilds byte-identically (BuildVault) and its fields are in range
//   -2  a parsed I rebuilds byte-identically (BuildIntent) and its fields are in range
//   -3  Parse* is true exactly when Match* is MATCH (V and I); an spk is never both
//   -4  a parsed bond redeem rebuilds byte-identically (BuildBondRedeem)
//   -5  DecodeAct succeeds only on an act output and re-encodes byte-identically (EncodeAct)
//   -6  DecodePayload re-encodes byte-identically (EncodePayload), or else (a key with a header
//       other than 02/03) the payload fails ActFieldsValid and DecodeAct
//   -7  ParseTemplateSpend returns a spend only for a template spk, with the selector and the
//       pushes ParseSelector reports, and the template's fields
// Every parser must be total: an exception is the caller's failure.

#include "script/script.h"
#include "vault/act.h"
#include "vault/template.h"

#include <cstdint>
#include <vector>

namespace vault_fuzz {

inline void Split(const std::vector<unsigned char>& data, CScript& spk, CScript& scriptSig)
{
    if (data.size() < 2) {
        spk = CScript(data.begin(), data.end());
        scriptSig = CScript();
        return;
    }
    size_t n = (size_t)data[0] | ((size_t)data[1] << 8);
    if (n > data.size() - 2) n = data.size() - 2;
    spk = CScript(data.begin() + 2, data.begin() + 2 + n);
    scriptSig = CScript(data.begin() + 2 + n, data.end());
}

inline int RunVault(const std::vector<unsigned char>& data)
{
    using namespace vault;
    CScript spk, scriptSig;
    Split(data, spk, scriptSig);

    VaultParams vp, vm;
    const bool isV = ParseVault(spk, vp);
    const Shape vs = MatchVault(spk, vm);
    if (isV && (BuildVault(vp) != spk || !VaultParamsValid(vp))) return -1;
    IntentParams ip, im;
    const bool isI = ParseIntent(spk, ip);
    const Shape is = MatchIntent(spk, im);
    if (isI && (BuildIntent(ip) != spk || !IntentParamsValid(ip))) return -2;
    if (isV != (vs == Shape::MATCH) || isI != (is == Shape::MATCH) || (isV && isI)) return -3;

    uint32_t locktime;
    CPubKey member;
    if (ParseBondRedeem(spk, locktime, member) && BuildBondRedeem(locktime, member) != spk) return -4;

    Act act;
    const bool actOk = !DecodeAct(spk, act).has_value();
    if (actOk) {
        if (!IsActOutput(spk) || EncodeAct(act) != spk) return -5;
        (void)ActFieldsValid(act);
    }
    Act bare;
    const std::vector<unsigned char> P(spk.begin(), spk.end());
    if (!DecodePayload(P, bare).has_value() && EncodePayload(bare) != P) {
        // DecodePayload reads a 33-byte key whose header is not 02/03 as an invalid CPubKey, which
        // re-encodes as 33 zero bytes. Such a payload must never be an act: the field rules refuse it
        // and so does DecodeAct (its round-trip check), so consensus sees no non-canonical act.
        Act viaScript;
        CScript s;
        s << OP_RETURN << P;
        if (ActFieldsValid(bare) || !DecodeAct(s, viaScript).has_value()) return -6;
    }

    std::vector<std::vector<unsigned char>> pushes;
    const std::optional<uint8_t> sel = ParseSelector(scriptSig, &pushes);
    const std::optional<TemplateSpend> ts = ParseTemplateSpend(spk, scriptSig);
    if (ts) {
        if (!(isV || isI) || !sel || *sel != ts->selector || pushes != ts->sigs) return -7;
        if (ts->kind == TemplateKind::VAULT ? (!isV || !(ts->vault == vp)) : !isI) return -7;
    }
    return 0;
}

} // namespace vault_fuzz

#endif // YCASH_TEST_VAULT_FUZZ_HARNESS_H
