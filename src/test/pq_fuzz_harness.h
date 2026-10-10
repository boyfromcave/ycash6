// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_TEST_PQ_FUZZ_HARNESS_H
#define YCASH_TEST_PQ_FUZZ_HARNESS_H

// The body of the PQScript fuzz target (src/fuzzing/PQScript/fuzz.cpp), shared with the Boost
// replay in vault_fuzz_tests.cpp so `make check` runs every seed without a fuzzing build.
// Header-only, no Boost.
//
// OP_CHECKPQSIG (docs/plans/yellowback-quantum-plan.md §4.2) is run over a stack the input
// describes compactly, so a 7,857-byte SLH-DSA signature costs a few input bytes:
//
//   byte 0   flags: bit 0 STRICTENC, bit 1 PQ_FALCON, bit 2 VAULT, bit 3 the key hash is
//            SHA256(scheme ‖ the reassembled key) (else 32 bytes of 0x5a), bits 4-5 the key-hash
//            length (0: 32, 1: 31, 2: 33, 3: 0), bit 6 the mock checker answers true,
//            bit 7 the script is OP_CHECKPQSIG OP_CHECKPQSIG (a second execution is SCRIPT_ERR_PQ_COUNT, R-B1)
//   byte 1   the scheme element: 0xff = empty, else the one byte
//   then     items of 3 bytes, bottom of the stack first: u16 LE v, fill.
//            v & 0x8000: the one-byte element {v & 0xff} (a count);
//            else an element of (v & 0x7ff) bytes, byte i = fill + i.
//   (at most 400 items; a trailing partial item is ignored)
//
// The interpreter's result (error, final stack, what the checker was asked) is compared with an
// independent model of §4.2 written here. Properties (negative return codes):
//   -1  the error differs from the model's
//   -2  the final stack, or the checker call, differs from the model's
//   -3  the real TransactionSignatureChecker (pq::Verify over a fixed transaction) disagrees with
//       the model on the error, or accepts a signature (no valid one can be built from the grammar)

#include "crypto/pq/scheme.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "uint256.h"

#include <cstdint>
#include <vector>

namespace pq_fuzz {

typedef std::vector<unsigned char> valtype;

class RecordingChecker : public BaseSignatureChecker
{
public:
    bool answer = false;
    mutable int calls = 0;
    mutable uint8_t scheme = 0;
    mutable valtype sig, pk;

    bool CheckPQSig(uint8_t s, const valtype& vchSig, const valtype& vchPubKey,
                    const CScript&, uint32_t) const override
    {
        calls++;
        scheme = s;
        sig = vchSig;
        pk = vchPubKey;
        return answer;
    }
};

struct Model {
    ScriptError err = SCRIPT_ERR_OK;
    bool checkerCalled = false;
    uint8_t scheme = 0;
    valtype pk, sig;
    std::vector<valtype> stack;   // the final stack when err == OK (result on top, checker answer assumed)
};

/** A count element: one byte 1..maxChunks, else 0. */
inline int ModelCount(const valtype& c, size_t len)
{
    const size_t maxChunks = len / 520 + (len % 520 ? 1 : 0);
    return (c.size() == 1 && c[0] >= 1 && c[0] <= maxChunks) ? c[0] : 0;
}

/**
 * §4.2 with the frozen error order (QUANTUM-SPEC A-7), read with plain indices from the bottom:
 * counts (both), then canonical chunks (both), then sizes (both). `top` indexes the key's count.
 */
inline bool ModelArgs(const std::vector<valtype>& st, long top, const size_t lens[2], valtype out[2],
                      long& rest, ScriptError& err)
{
    long first[2], count[2];
    long pos = top;
    for (int part = 0; part < 2; part++) {
        if (pos < 0) { err = SCRIPT_ERR_INVALID_STACK_OPERATION; return false; }
        count[part] = ModelCount(st[pos], lens[part]);
        if (count[part] == 0) { err = SCRIPT_ERR_PQ_CHUNK; return false; }
        first[part] = pos - count[part];
        if (first[part] < 0) { err = SCRIPT_ERR_INVALID_STACK_OPERATION; return false; }
        pos = first[part] - 1;
    }
    for (int part = 0; part < 2; part++) {
        for (long j = first[part]; j < first[part] + count[part]; j++) {
            const bool last = (j == first[part] + count[part] - 1);
            if (st[j].size() > 520 || (!last && st[j].size() != 520)) { err = SCRIPT_ERR_PQ_CHUNK; return false; }
        }
    }
    for (int part = 0; part < 2; part++) {
        for (long j = first[part]; j < first[part] + count[part]; j++)
            out[part].insert(out[part].end(), st[j].begin(), st[j].end());
        if (out[part].size() != lens[part]) { err = SCRIPT_ERR_PQ_SIZE; return false; }
    }
    rest = pos;   // index of the highest item left under the arguments (-1: none)
    return true;
}

inline Model RunModel(const std::vector<valtype>& st, unsigned int flags, bool answer)
{
    Model m;
    if (!(flags & SCRIPT_VERIFY_VAULT)) { m.err = SCRIPT_ERR_BAD_OPCODE; return m; }
    const long n = (long)st.size();
    if (n < 2) { m.err = SCRIPT_ERR_INVALID_STACK_OPERATION; return m; }
    const valtype& sch = st[n - 1];
    if (sch.size() != 1 || (sch[0] != 1 && !(sch[0] == 2 && (flags & SCRIPT_VERIFY_PQ_FALCON)))) {
        m.err = SCRIPT_ERR_PQ_SCHEME;
        return m;
    }
    m.scheme = sch[0];
    const valtype& kh = st[n - 2];
    if (kh.size() != 32) { m.err = SCRIPT_ERR_PQ_SIZE; return m; }
    const size_t lens[2] = {m.scheme == 1 ? 32u : 897u, (m.scheme == 1 ? 7856u : 666u) + 1};
    valtype out[2];
    long rest;
    if (!ModelArgs(st, n - 3, lens, out, rest, m.err)) return m;
    m.pk = out[0];
    m.sig = out[1];
    if (flags & SCRIPT_VERIFY_STRICTENC) {
        const unsigned char ht = m.sig.back() & 0x7f;
        if (ht < 1 || ht > 3) { m.err = SCRIPT_ERR_SIG_HASHTYPE; return m; }
    }
    const uint256 h = pq::KeyHash(m.scheme, m.pk);
    const bool match = valtype(h.begin(), h.end()) == kh;
    m.checkerCalled = match;
    m.stack.assign(st.begin(), st.begin() + (rest + 1));
    m.stack.push_back(match && answer ? valtype(1, 1) : valtype());
    return m;
}

inline int RunPQScript(const std::vector<unsigned char>& data)
{
    if (data.size() < 2) return 0;
    const uint8_t f = data[0];
    unsigned int flags = 0;
    if (f & 0x01) flags |= SCRIPT_VERIFY_STRICTENC;
    if (f & 0x02) flags |= SCRIPT_VERIFY_PQ_FALCON;
    if (f & 0x04) flags |= SCRIPT_VERIFY_VAULT | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    const bool hashRight = f & 0x08;
    const int khLenSel = (f >> 4) & 3;
    const bool answer = f & 0x40;
    const bool twice = f & 0x80;

    std::vector<valtype> stack;
    for (size_t i = 2; i + 3 <= data.size() && stack.size() < 400; i += 3) {
        const uint16_t v = (uint16_t)(data[i] | (data[i + 1] << 8));
        const uint8_t fill = data[i + 2];
        if (v & 0x8000) {
            stack.push_back(valtype(1, (unsigned char)v));
        } else {
            valtype e(v & 0x7ff);
            for (size_t k = 0; k < e.size(); k++) e[k] = (unsigned char)(fill + k);
            stack.push_back(e);
        }
    }
    const valtype scheme = data[1] == 0xff ? valtype() : valtype(1, data[1]);

    // The key hash: the right one needs the key the model reassembles from this stack.
    valtype kh(32, 0x5a);
    if (hashRight && scheme.size() == 1 && (scheme[0] == 1 || scheme[0] == 2)) {
        std::vector<valtype> probe = stack;
        probe.push_back(valtype(32, 0));
        probe.push_back(scheme);
        const Model probeModel = RunModel(probe, SCRIPT_VERIFY_VAULT | SCRIPT_VERIFY_PQ_FALCON, false);
        if (probeModel.err == SCRIPT_ERR_OK) {
            const uint256 h = pq::KeyHash(scheme[0], probeModel.pk);
            kh.assign(h.begin(), h.end());
        }
    }
    static const size_t KH_LEN[4] = {32, 31, 33, 0};
    kh.resize(KH_LEN[khLenSel], 0x5a);
    stack.push_back(kh);
    stack.push_back(scheme);

    Model m = RunModel(stack, flags, answer);
    CScript script = CScript() << OP_CHECKPQSIG;
    int expectCallsOnError = 0;   // the first check's call, when the second is the error
    if (twice) {
        // the first runs as modelled; if it succeeds, the second fails before reading the stack
        script << OP_CHECKPQSIG;
        if (m.err == SCRIPT_ERR_OK) {
            expectCallsOnError = m.checkerCalled ? 1 : 0;
            m.err = SCRIPT_ERR_PQ_COUNT;
            m.stack.clear();
        }
    }

    RecordingChecker checker;
    checker.answer = answer;
    std::vector<valtype> st = stack;
    ScriptError err;
    EvalScript(st, script, flags, checker, 0x6d5b7a31, &err);
    if (err != m.err) return -1;
    if (err == SCRIPT_ERR_OK) {
        if (st != m.stack) return -2;
        if ((checker.calls == 1) != m.checkerCalled || checker.calls > 1) return -2;
        if (checker.calls == 1 && (checker.scheme != m.scheme || checker.pk != m.pk || checker.sig != m.sig)) return -2;
    } else if (checker.calls != expectCallsOnError) {
        return -2;
    }

    // The real checker: pq::Verify on whatever the grammar built, over a fixed v4 transaction.
    CMutableTransaction mtx;
    mtx.fOverwintered = true;
    mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    mtx.nVersion = SAPLING_TX_VERSION;
    mtx.vin.resize(1);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 0;   // 6.20.0: CTransaction parses through Rust, which refuses the default -1
    const CTransaction tx(mtx);
    const PrecomputedTransactionData txdata(tx, {CTxOut(0, CScript())});
    TransactionSignatureChecker real(&tx, txdata, 0, 0);
    std::vector<valtype> st2 = stack;
    ScriptError err2;
    EvalScript(st2, script, flags, real, 0x6d5b7a31, &err2);
    if (err2 != m.err) return -3;
    if (err2 == SCRIPT_ERR_OK && st2.back() != valtype()) return -3;
    return 0;
}

} // namespace pq_fuzz

#endif // YCASH_TEST_PQ_FUZZ_HARNESS_H
