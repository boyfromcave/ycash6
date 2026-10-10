// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// OP_CHECKPQSIG (0xc2), docs/plans/yellowback-quantum-plan.md §4.1, §4.2, §4.8: the activation
// gate, the scheme registry and SCRIPT_VERIFY_PQ_FALCON, canonical chunking, exact sizes, the key
// hash, hashtypes, the failure semantics, the error order, the policy sigop count and the flag plumbing, against a mock
// checker (the real one is TransactionSignatureChecker::CheckPQSig over pq::Verify).

#include "chainparams.h"
#include "coins.h"
#include "consensus/upgrades.h"
#include "crypto/pq/scheme.h"
#include "crypto/pq/sign.h"
#include "key.h"
#include "main.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/standard.h"
#include "test/data/pq_vectors.json.h"
#include "test/test_bitcoin.h"
#include "util/strencodings.h"
#include "uint256.h"
#include "util/system.h"
#include "vault/checker.h"

#include <boost/test/unit_test.hpp>

#include <univalue.h>

#include <string>
#include <vector>

typedef std::vector<unsigned char> valtype;

namespace {

const uint32_t VAULT_BRANCH_ID = 0x6d5b7a31;
const uint8_t SLH = pq::SCHEME_SLH_DSA_SHA2_128S;
const uint8_t FALCON = pq::SCHEME_FN_DSA_512;
const unsigned int PQ_FLAGS = SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_VAULT;
const unsigned int PQ_FALCON_FLAGS = PQ_FLAGS | SCRIPT_VERIFY_PQ_FALCON;

/** A checker whose answer the test sets, recording what the interpreter hands it. */
class MockPQChecker : public BaseSignatureChecker
{
public:
    bool ok = true;
    mutable int calls = 0;
    mutable uint8_t lastScheme = 0;
    mutable valtype lastSig, lastPubKey;
    mutable CScript lastScriptCode;
    mutable uint32_t lastBranch = 0;

    bool CheckPQSig(uint8_t scheme, const valtype& vchSig, const valtype& vchPubKey,
                    const CScript& scriptCode, uint32_t consensusBranchId) const override
    {
        calls++;
        lastScheme = scheme;
        lastSig = vchSig;
        lastPubKey = vchPubKey;
        lastScriptCode = scriptCode;
        lastBranch = consensusBranchId;
        return ok;
    }
};

/** n bytes, byte i = seed + i (so a chunk out of order or a dropped byte shows). */
valtype Pattern(size_t n, unsigned char seed)
{
    valtype v(n);
    for (size_t i = 0; i < n; i++) v[i] = (unsigned char)(seed + i * 7);
    return v;
}

/** A public key of the registry size for `scheme`. */
valtype PubKey(uint8_t scheme, unsigned char seed = 0x11) { return Pattern(pq::PubKeySize(scheme), seed); }

/** A signature of the registry size plus the hashtype byte. */
valtype Sig(uint8_t scheme, unsigned char hashType = SIGHASH_ALL, unsigned char seed = 0x22)
{
    valtype v = Pattern(pq::SigSize(scheme), seed);
    v.push_back(hashType);
    return v;
}

valtype KeyHashBytes(uint8_t scheme, const valtype& pk)
{
    const uint256 h = pq::KeyHash(scheme, pk);
    return valtype(h.begin(), h.end());
}

/** Canonical chunks of `data`: 520-byte pushes, the last one the remainder. */
std::vector<valtype> Chunks(const valtype& data)
{
    std::vector<valtype> out;
    for (size_t i = 0; i < data.size(); i += pq::MAX_CHUNK)
        out.emplace_back(data.begin() + i, data.begin() + std::min(data.size(), i + pq::MAX_CHUNK));
    return out;
}

/** Push the chunks then their count as OP_N (or as the raw element `count` when given). */
void PushSeq(CScript& s, const std::vector<valtype>& chunks, const valtype* count = nullptr)
{
    for (const valtype& c : chunks) s << c;
    if (count)
        s << *count;
    else
        s << (int64_t)chunks.size();
}

/** The scriptSig of plan §4.3: <sig_1>..<sig_s> <s> <pk_1>..<pk_p> <p>. */
CScript ScriptSig(const std::vector<valtype>& sigChunks, const std::vector<valtype>& pkChunks)
{
    CScript s;
    PushSeq(s, sigChunks);
    PushSeq(s, pkChunks);
    return s;
}

/** TX_PQPKH (plan §4.3): <keyHash:32> <schemeId> OP_CHECKPQSIG, the scheme as OP_N (MINIMALDATA). */
CScript PQPKH(const valtype& keyHash, uint8_t scheme)
{
    return CScript() << keyHash << (int64_t)scheme << OP_CHECKPQSIG;
}

CScript Cat(const CScript& a, const CScript& b)
{
    CScript s(a);
    s.insert(s.end(), b.begin(), b.end());
    return s;
}

ScriptError Eval(const CScript& script, unsigned int flags, const BaseSignatureChecker& checker,
                 std::vector<valtype>* stackOut = nullptr)
{
    std::vector<valtype> stack;
    ScriptError err;
    EvalScript(stack, script, flags, checker, VAULT_BRANCH_ID, &err);
    if (stackOut) *stackOut = stack;
    return err;
}

/** Evaluate scriptSig ‖ OP_CHECKPQSIG over a well-formed key/sig of `scheme`, the key hash right. */
ScriptError EvalGood(uint8_t scheme, unsigned int flags, const BaseSignatureChecker& checker,
                     std::vector<valtype>* stackOut = nullptr, unsigned char hashType = SIGHASH_ALL)
{
    const valtype pk = PubKey(scheme);
    CScript s = Cat(ScriptSig(Chunks(Sig(scheme, hashType)), Chunks(pk)), PQPKH(KeyHashBytes(scheme, pk), scheme));
    return Eval(s, flags, checker, stackOut);
}

bool IsTrue(const std::vector<valtype>& stack) { return stack.size() == 1 && stack[0] == valtype(1, 1); }
bool IsFalse(const std::vector<valtype>& stack) { return stack.size() == 1 && stack[0].empty(); }

CMutableTransaction SaplingTx()
{
    CMutableTransaction mtx;
    mtx.fOverwintered = true;
    mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    mtx.nVersion = SAPLING_TX_VERSION;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(uint256S("01"), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1;
    return mtx;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_script_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pq_constants)
{
    BOOST_CHECK_EQUAL((int)OP_CHECKPQSIG, 0xc2);
    BOOST_CHECK_EQUAL(std::string(GetOpName(OP_CHECKPQSIG)), "OP_CHECKPQSIG");
    BOOST_CHECK_EQUAL(pq::MAX_CHUNK, (size_t)MAX_SCRIPT_ELEMENT_SIZE);
    BOOST_CHECK_EQUAL(pq::KEYHASH_SIZE, 32U);
    BOOST_CHECK_EQUAL(pq::SIGOP_COST, 20U);
    BOOST_CHECK_EQUAL(pq::PubKeySize(SLH), 32U);
    BOOST_CHECK_EQUAL(pq::SigSize(SLH), 7856U);
    BOOST_CHECK_EQUAL(pq::PubKeySize(FALCON), 897U);
    BOOST_CHECK_EQUAL(pq::SigSize(FALCON), 666U);
    // The chunk counts of plan §4.2: SLH-DSA p=1, s=16 (15x520 + 57); Falcon p=2 (520+377), s=2 (520+147).
    BOOST_CHECK_EQUAL(Chunks(PubKey(SLH)).size(), 1U);
    BOOST_CHECK_EQUAL(Chunks(Sig(SLH)).size(), 16U);
    BOOST_CHECK_EQUAL(Chunks(Sig(SLH)).back().size(), 57U);
    BOOST_CHECK_EQUAL(Chunks(PubKey(FALCON)).size(), 2U);
    BOOST_CHECK_EQUAL(Chunks(PubKey(FALCON)).back().size(), 377U);
    BOOST_CHECK_EQUAL(Chunks(Sig(FALCON)).size(), 2U);
    BOOST_CHECK_EQUAL(Chunks(Sig(FALCON)).back().size(), 147U);
    // The flag is its own bit.
    BOOST_CHECK_EQUAL(SCRIPT_VERIFY_PQ_FALCON & (STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_VAULT), 0U);
    for (ScriptError e : {SCRIPT_ERR_PQ_SCHEME, SCRIPT_ERR_PQ_CHUNK, SCRIPT_ERR_PQ_SIZE, SCRIPT_ERR_PQ_COUNT})
        BOOST_CHECK(std::string(ScriptErrorString(e)) != "unknown error");
    // SHA256(scheme || pk): the scheme byte is bound into the hash.
    const valtype pk = PubKey(SLH);
    BOOST_CHECK(pq::KeyHash(SLH, pk) != pq::KeyHash(FALCON, pk));
    // The TX_PQPKH shape with the scheme as OP_N is 35 bytes.
    BOOST_CHECK_EQUAL(PQPKH(KeyHashBytes(SLH, pk), SLH).size(), 35U);
}

BOOST_AUTO_TEST_CASE(pq_pre_activation_bad_opcode)
{
    MockPQChecker checker;
    for (unsigned int flags : {0U, (unsigned int)SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
                               (unsigned int)SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, STANDARD_SCRIPT_VERIFY_FLAGS,
                               (unsigned int)SCRIPT_VERIFY_PQ_FALCON}) {
        BOOST_CHECK_EQUAL(EvalGood(SLH, flags, checker), SCRIPT_ERR_BAD_OPCODE);
        BOOST_CHECK_EQUAL(Eval(CScript() << OP_CHECKPQSIG, flags, checker), SCRIPT_ERR_BAD_OPCODE);
        // Unexecuted, it is skipped, as any unknown byte is today.
        std::vector<valtype> stack;
        BOOST_CHECK_EQUAL(Eval(CScript() << OP_0 << OP_IF << OP_CHECKPQSIG << OP_ENDIF << OP_1, flags, checker, &stack), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1U);
    }
    BOOST_CHECK_EQUAL(checker.calls, 0);
    // With the vault flag it is an opcode (an empty stack is now a stack error, not BAD_OPCODE);
    // 0xc3 and up stay BAD_OPCODE.
    BOOST_CHECK_EQUAL(Eval(CScript() << OP_CHECKPQSIG, PQ_FLAGS, checker), SCRIPT_ERR_INVALID_STACK_OPERATION);
    for (int op = 0xc3; op <= 0xc8; op++)
        BOOST_CHECK_EQUAL(Eval(CScript() << (opcodetype)op, PQ_FALCON_FLAGS, checker), SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(pq_good_shapes)
{
    // SLH-DSA: the interpreter reassembles exactly the key and the signature, in push order,
    // hands the checker the scheme, the executing script and the branch, and leaves one true.
    {
        MockPQChecker checker;
        const valtype pk = PubKey(SLH);
        const valtype sig = Sig(SLH);
        const CScript spk = PQPKH(KeyHashBytes(SLH, pk), SLH);
        const CScript s = Cat(ScriptSig(Chunks(sig), Chunks(pk)), spk);
        std::vector<valtype> stack;
        BOOST_CHECK_EQUAL(Eval(s, PQ_FLAGS, checker, &stack), SCRIPT_ERR_OK);
        BOOST_CHECK(IsTrue(stack));
        BOOST_CHECK_EQUAL(checker.calls, 1);
        BOOST_CHECK_EQUAL(checker.lastScheme, SLH);
        BOOST_CHECK(checker.lastPubKey == pk);
        BOOST_CHECK(checker.lastSig == sig);
        BOOST_CHECK(checker.lastScriptCode == s);
        BOOST_CHECK_EQUAL(checker.lastBranch, VAULT_BRANCH_ID);

        // Through VerifyScript (scriptSig, then the scriptPubKey) under the standard flags.
        BOOST_CHECK_EQUAL(checker.calls, 1);
        ScriptError err;
        BOOST_CHECK(VerifyScript(ScriptSig(Chunks(sig), Chunks(pk)), spk, STANDARD_SCRIPT_VERIFY_FLAGS | PQ_FLAGS,
                                 checker, VAULT_BRANCH_ID, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
        BOOST_CHECK(checker.lastScriptCode == spk);
    }
    // Falcon, with the flag.
    {
        MockPQChecker checker;
        std::vector<valtype> stack;
        BOOST_CHECK_EQUAL(EvalGood(FALCON, PQ_FALCON_FLAGS, checker, &stack), SCRIPT_ERR_OK);
        BOOST_CHECK(IsTrue(stack));
        BOOST_CHECK_EQUAL(checker.lastScheme, FALCON);
        BOOST_CHECK(checker.lastPubKey == PubKey(FALCON));
        BOOST_CHECK(checker.lastSig == Sig(FALCON));
    }
    // Items under the arguments are left alone.
    {
        MockPQChecker checker;
        const valtype pk = PubKey(SLH);
        CScript s = CScript() << valtype{0xaa, 0xbb};
        s = Cat(s, Cat(ScriptSig(Chunks(Sig(SLH)), Chunks(pk)), PQPKH(KeyHashBytes(SLH, pk), SLH)));
        std::vector<valtype> stack;
        BOOST_CHECK_EQUAL(Eval(s, PQ_FLAGS, checker, &stack), SCRIPT_ERR_OK);
        BOOST_REQUIRE_EQUAL(stack.size(), 2U);
        BOOST_CHECK(stack[0] == (valtype{0xaa, 0xbb}));
        BOOST_CHECK(stack[1] == valtype(1, 1));
    }
    // The scheme pushed as a one-byte data push (not OP_N) is the same element and works without
    // MINIMALDATA; with it, the push itself fails (a template must use OP_1 / OP_2).
    {
        MockPQChecker checker;
        const valtype pk = PubKey(SLH);
        const CScript spk = CScript() << KeyHashBytes(SLH, pk) << valtype(1, SLH) << OP_CHECKPQSIG;
        BOOST_CHECK_EQUAL(spk.size(), 36U);
        const CScript s = Cat(ScriptSig(Chunks(Sig(SLH)), Chunks(pk)), spk);
        BOOST_CHECK_EQUAL(Eval(s, PQ_FLAGS, checker), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(Eval(s, PQ_FLAGS | SCRIPT_VERIFY_MINIMALDATA, checker), SCRIPT_ERR_MINIMALDATA);
    }
}

BOOST_AUTO_TEST_CASE(pq_scheme_errors)
{
    MockPQChecker checker;
    const valtype pk = PubKey(SLH);
    const CScript ss = ScriptSig(Chunks(Sig(SLH)), Chunks(pk));
    const valtype kh = KeyHashBytes(SLH, pk);
    auto withScheme = [&](const valtype& scheme) {
        return Cat(ss, CScript() << kh << scheme << OP_CHECKPQSIG);
    };
    for (const valtype& bad : {valtype{}, valtype{0x00}, valtype{0x03}, valtype{0x7f}, valtype{0x81}, valtype{0xff},
                               valtype{0x01, 0x00}, valtype{0x02, 0x00}, valtype{0x00, 0x01}})
        BOOST_CHECK_EQUAL(Eval(withScheme(bad), PQ_FALCON_FLAGS, checker), SCRIPT_ERR_PQ_SCHEME);
    // Falcon without SCRIPT_VERIFY_PQ_FALCON is an unknown scheme, whatever the stack below.
    BOOST_CHECK_EQUAL(EvalGood(FALCON, PQ_FLAGS, checker), SCRIPT_ERR_PQ_SCHEME);
    BOOST_CHECK_EQUAL(EvalGood(FALCON, PQ_FLAGS | STANDARD_SCRIPT_VERIFY_FLAGS, checker), SCRIPT_ERR_PQ_SCHEME);
    BOOST_CHECK_EQUAL(Eval(CScript() << kh << OP_2 << OP_CHECKPQSIG, PQ_FLAGS, checker), SCRIPT_ERR_PQ_SCHEME);
    BOOST_CHECK_EQUAL(checker.calls, 0);
    // The flag admits only 0x02: SLH-DSA is active either way.
    BOOST_CHECK_EQUAL(EvalGood(SLH, PQ_FLAGS, checker), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(EvalGood(SLH, PQ_FALCON_FLAGS, checker), SCRIPT_ERR_OK);
    // Too few items for the scheme and the key hash.
    BOOST_CHECK_EQUAL(Eval(CScript() << OP_1 << OP_CHECKPQSIG, PQ_FLAGS, checker), SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(pq_keyhash_size)
{
    MockPQChecker checker;
    const valtype pk = PubKey(SLH);
    const CScript ss = ScriptSig(Chunks(Sig(SLH)), Chunks(pk));
    valtype kh = KeyHashBytes(SLH, pk);
    for (size_t n : {0, 1, 20, 31, 33, 64}) {
        valtype bad = kh;
        bad.resize(n, 0x00);
        BOOST_CHECK_EQUAL(Eval(Cat(ss, PQPKH(bad, SLH)), PQ_FLAGS, checker), SCRIPT_ERR_PQ_SIZE);
    }
    // The key hash is checked before the count below it.
    BOOST_CHECK_EQUAL(Eval(CScript() << valtype(31, 1) << OP_1 << OP_CHECKPQSIG, PQ_FLAGS, checker), SCRIPT_ERR_PQ_SIZE);
    BOOST_CHECK_EQUAL(Eval(CScript() << kh << OP_1 << OP_CHECKPQSIG, PQ_FLAGS, checker), SCRIPT_ERR_INVALID_STACK_OPERATION);
    BOOST_CHECK_EQUAL(checker.calls, 0);
}

BOOST_AUTO_TEST_CASE(pq_canonical_chunking)
{
    MockPQChecker checker;
    const valtype spk_pk = PubKey(FALCON);
    const valtype kh = KeyHashBytes(FALCON, spk_pk);
    const CScript spk = PQPKH(kh, FALCON);
    const std::vector<valtype> sigChunks = Chunks(Sig(FALCON));
    const std::vector<valtype> pkChunks = Chunks(spk_pk);
    auto run = [&](const CScript& sigPart, const CScript& pkPart) {
        return Eval(Cat(Cat(sigPart, pkPart), spk), PQ_FALCON_FLAGS, checker);
    };
    auto seq = [](const std::vector<valtype>& chunks, const valtype* count = nullptr) {
        CScript s;
        PushSeq(s, chunks, count);
        return s;
    };
    const CScript goodSig = seq(sigChunks), goodPk = seq(pkChunks);
    BOOST_CHECK_EQUAL(run(goodSig, goodPk), SCRIPT_ERR_OK);

    // --- the key's count p: a minimal number 1..ceil(897/520) = 2
    for (const valtype& p : {valtype{}, valtype{0x00}, valtype{0x03}, valtype{0x10}, valtype{0x11}, valtype{0x81},
                             valtype{0xff}, valtype{0x02, 0x00}, valtype{0x01, 0x00}, valtype{0x02, 0x80}}) {
        BOOST_CHECK_EQUAL(run(goodSig, seq(pkChunks, &p)), SCRIPT_ERR_PQ_CHUNK);
    }
    // p = 1 with the whole key cannot be pushed (over 520 bytes)
    BOOST_CHECK_EQUAL(run(goodSig, CScript() << spk_pk << OP_1), SCRIPT_ERR_PUSH_SIZE);
    // p = 1 with the first chunk alone: canonical, but 520 bytes is not the key's size
    BOOST_CHECK_EQUAL(run(goodSig, CScript() << pkChunks[0] << OP_1), SCRIPT_ERR_PQ_SIZE);
    // p = 2 with a short non-last chunk (519 + 378)
    {
        std::vector<valtype> c = {valtype(spk_pk.begin(), spk_pk.begin() + 519), valtype(spk_pk.begin() + 519, spk_pk.end())};
        BOOST_CHECK_EQUAL(run(goodSig, seq(c)), SCRIPT_ERR_PQ_CHUNK);
    }
    // a key one byte long or short (the last chunk 378 / 376)
    {
        std::vector<valtype> c = pkChunks;
        c.back().push_back(0x00);
        BOOST_CHECK_EQUAL(run(goodSig, seq(c)), SCRIPT_ERR_PQ_SIZE);
        c = pkChunks;
        c.back().pop_back();
        BOOST_CHECK_EQUAL(run(goodSig, seq(c)), SCRIPT_ERR_PQ_SIZE);
    }
    // an oversize chunk is refused at the push
    {
        std::vector<valtype> c = {valtype(521, 0x01), valtype(376, 0x02)};
        BOOST_CHECK_EQUAL(run(goodSig, seq(c)), SCRIPT_ERR_PUSH_SIZE);
    }
    // p = 2 with only one item under it
    BOOST_CHECK_EQUAL(Eval(CScript() << pkChunks[1] << OP_2 << kh << OP_2 << OP_CHECKPQSIG, PQ_FALCON_FLAGS, checker),
                      SCRIPT_ERR_INVALID_STACK_OPERATION);

    // --- the signature's count s: 1..ceil(667/520) = 2
    for (const valtype& s : {valtype{}, valtype{0x00}, valtype{0x03}, valtype{0x81}, valtype{0x02, 0x00}}) {
        BOOST_CHECK_EQUAL(run(seq(sigChunks, &s), goodPk), SCRIPT_ERR_PQ_CHUNK);
    }
    {
        std::vector<valtype> c = sigChunks;
        c[0].pop_back();                                   // 519 + 147
        BOOST_CHECK_EQUAL(run(seq(c), goodPk), SCRIPT_ERR_PQ_CHUNK);
        c = sigChunks;
        c.back().push_back(SIGHASH_ALL);                   // 668 bytes
        BOOST_CHECK_EQUAL(run(seq(c), goodPk), SCRIPT_ERR_PQ_SIZE);
        c = sigChunks;
        c.back().pop_back();                               // 666 bytes: the hashtype byte is not optional
        BOOST_CHECK_EQUAL(run(seq(c), goodPk), SCRIPT_ERR_PQ_SIZE);
    }
    // no s at all: the key's chunks then nothing
    BOOST_CHECK_EQUAL(run(CScript(), goodPk), SCRIPT_ERR_INVALID_STACK_OPERATION);
    // s = 2 with one chunk under it
    BOOST_CHECK_EQUAL(run(CScript() << sigChunks[1] << OP_2, goodPk), SCRIPT_ERR_INVALID_STACK_OPERATION);
    BOOST_CHECK_EQUAL(checker.calls, 1);

    // --- SLH-DSA: p must be 1, s must be 16, the last signature chunk 57 bytes
    {
        MockPQChecker c2;
        const valtype pk = PubKey(SLH);
        const CScript spk2 = PQPKH(KeyHashBytes(SLH, pk), SLH);
        const std::vector<valtype> sc = Chunks(Sig(SLH));
        auto run2 = [&](const CScript& sigPart, const CScript& pkPart) {
            return Eval(Cat(Cat(sigPart, pkPart), spk2), PQ_FLAGS, c2);
        };
        BOOST_CHECK_EQUAL(run2(seq(sc), seq({pk})), SCRIPT_ERR_OK);
        const valtype two{0x02}, seventeen{0x11};
        BOOST_CHECK_EQUAL(run2(seq(sc), seq({valtype(pk.begin(), pk.begin() + 16), valtype(pk.begin() + 16, pk.end())}, &two)),
                          SCRIPT_ERR_PQ_CHUNK);
        BOOST_CHECK_EQUAL(run2(seq(sc), seq({valtype(31, 1)})), SCRIPT_ERR_PQ_SIZE);
        BOOST_CHECK_EQUAL(run2(seq(sc), seq({valtype(33, 1)})), SCRIPT_ERR_PQ_SIZE);
        BOOST_CHECK_EQUAL(run2(seq(sc, &seventeen), seq({pk})), SCRIPT_ERR_PQ_CHUNK);
        std::vector<valtype> c = sc;
        c.pop_back();                                      // 15 x 520 = 7800 bytes
        BOOST_CHECK_EQUAL(run2(seq(c), seq({pk})), SCRIPT_ERR_PQ_SIZE);
        c = sc;
        c[7].pop_back();                                   // a short middle chunk
        BOOST_CHECK_EQUAL(run2(seq(c), seq({pk})), SCRIPT_ERR_PQ_CHUNK);
        c = sc;                                            // the 57 bytes split as 56 + 1: s = 17
        c.back().pop_back();
        c.push_back(valtype(1, SIGHASH_ALL));
        BOOST_CHECK_EQUAL(run2(seq(c), seq({pk})), SCRIPT_ERR_PQ_CHUNK);
        BOOST_CHECK_EQUAL(c2.calls, 1);
    }
}

BOOST_AUTO_TEST_CASE(pq_keyhash_mismatch_pushes_false)
{
    MockPQChecker checker;
    const valtype pk = PubKey(SLH);
    const CScript ss = ScriptSig(Chunks(Sig(SLH)), Chunks(pk));
    valtype wrong = KeyHashBytes(SLH, pk);
    wrong[31] ^= 0x01;
    std::vector<valtype> stack;
    BOOST_CHECK_EQUAL(Eval(Cat(ss, PQPKH(wrong, SLH)), PQ_FLAGS, checker, &stack), SCRIPT_ERR_OK);
    BOOST_CHECK(IsFalse(stack));
    // the key hash of the other scheme over the same key does not match either
    BOOST_CHECK_EQUAL(Eval(Cat(ss, PQPKH(KeyHashBytes(FALCON, pk), SLH)), PQ_FLAGS, checker, &stack), SCRIPT_ERR_OK);
    BOOST_CHECK(IsFalse(stack));
    // the checker is never asked about a key that does not hash to the committed hash
    BOOST_CHECK_EQUAL(checker.calls, 0);
    // false composes: OP_NOT / OP_IF branches see it, OP_VERIFY fails, VerifyScript is EVAL_FALSE
    BOOST_CHECK_EQUAL(Eval(Cat(ss, PQPKH(wrong, SLH) << OP_NOT), PQ_FLAGS, checker, &stack), SCRIPT_ERR_OK);
    BOOST_CHECK(IsTrue(stack));
    BOOST_CHECK_EQUAL(Eval(Cat(ss, PQPKH(wrong, SLH) << OP_IF << OP_0 << OP_ELSE << OP_1 << OP_ENDIF), PQ_FLAGS, checker, &stack), SCRIPT_ERR_OK);
    BOOST_CHECK(IsTrue(stack));
    BOOST_CHECK_EQUAL(Eval(Cat(ss, PQPKH(wrong, SLH) << OP_VERIFY), PQ_FLAGS, checker), SCRIPT_ERR_VERIFY);
    ScriptError err;
    BOOST_CHECK(!VerifyScript(ss, PQPKH(wrong, SLH), STANDARD_SCRIPT_VERIFY_FLAGS | PQ_FLAGS, checker, VAULT_BRANCH_ID, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);
    BOOST_CHECK_EQUAL(checker.calls, 0);
}

BOOST_AUTO_TEST_CASE(pq_failed_signature_semantics)
{
    // Ycash has no NULLFAIL flag: OP_CHECKSIG with a signature that does not verify pushes false and
    // the script goes on. OP_CHECKPQSIG does the same, under the standard flags too.
    MockPQChecker checker;
    checker.ok = false;
    const valtype pk = PubKey(SLH);
    const CScript ss = ScriptSig(Chunks(Sig(SLH)), Chunks(pk));
    const CScript spk = PQPKH(KeyHashBytes(SLH, pk), SLH);
    const unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS | PQ_FLAGS;
    std::vector<valtype> stack;
    BOOST_CHECK_EQUAL(Eval(Cat(ss, spk), flags, checker, &stack), SCRIPT_ERR_OK);
    BOOST_CHECK(IsFalse(stack));
    BOOST_CHECK_EQUAL(checker.calls, 1);
    BOOST_CHECK_EQUAL(Eval(Cat(ss, CScript(spk) << OP_NOT), flags, checker, &stack), SCRIPT_ERR_OK);
    BOOST_CHECK(IsTrue(stack));
    ScriptError err;
    BOOST_CHECK(!VerifyScript(ss, spk, flags, checker, VAULT_BRANCH_ID, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);

    // The same construct with OP_CHECKSIG and a non-verifying (empty) signature, for comparison.
    BaseSignatureChecker base;
    const valtype ecKey = ParseHex("031183c51c1afcff31c73cf5031b7015683cb723ff6f4a61e7795e8d4c5adefcb8");
    BOOST_CHECK_EQUAL(Eval(CScript() << OP_0 << ecKey << OP_CHECKSIG << OP_NOT, flags, base, &stack), SCRIPT_ERR_OK);
    BOOST_CHECK(IsTrue(stack));
    // The base checker refuses every PQ signature.
    BOOST_CHECK_EQUAL(EvalGood(SLH, PQ_FLAGS, base, &stack), SCRIPT_ERR_OK);
    BOOST_CHECK(IsFalse(stack));
}

BOOST_AUTO_TEST_CASE(pq_hashtypes)
{
    // The hashtype is the signature's last byte. Without STRICTENC any byte reaches the checker
    // (as for OP_CHECKSIG); with it, only 1..3 with or without ANYONECANPAY.
    for (int ht = 0; ht < 256; ht++) {
        const bool defined = ((ht & ~SIGHASH_ANYONECANPAY) >= SIGHASH_ALL && (ht & ~SIGHASH_ANYONECANPAY) <= SIGHASH_SINGLE);
        for (uint8_t scheme : {SLH, FALCON}) {
            MockPQChecker checker;
            std::vector<valtype> stack;
            BOOST_CHECK_EQUAL(EvalGood(scheme, PQ_FALCON_FLAGS, checker, &stack, (unsigned char)ht), SCRIPT_ERR_OK);
            BOOST_CHECK_EQUAL(checker.calls, 1);
            BOOST_CHECK_EQUAL(checker.lastSig.back(), ht);
            BOOST_CHECK(IsTrue(stack));
            const ScriptError strict = EvalGood(scheme, PQ_FALCON_FLAGS | SCRIPT_VERIFY_STRICTENC, checker, &stack, (unsigned char)ht);
            BOOST_CHECK_EQUAL(strict, defined ? SCRIPT_ERR_OK : SCRIPT_ERR_SIG_HASHTYPE);
            BOOST_CHECK_EQUAL(checker.calls, defined ? 2 : 1);
        }
    }
    // An undefined hashtype under STRICTENC fails the script even when the key hash does not
    // match (OP_CHECKSIG checks its encodings before it verifies; so does OP_CHECKPQSIG).
    MockPQChecker checker;
    const valtype pk = PubKey(SLH);
    valtype wrong = KeyHashBytes(SLH, pk);
    wrong[0] ^= 0x80;
    const CScript ss = ScriptSig(Chunks(Sig(SLH, 0x00)), Chunks(pk));
    BOOST_CHECK_EQUAL(Eval(Cat(ss, PQPKH(wrong, SLH)), PQ_FLAGS | SCRIPT_VERIFY_STRICTENC, checker), SCRIPT_ERR_SIG_HASHTYPE);
    std::vector<valtype> stack;
    BOOST_CHECK_EQUAL(Eval(Cat(ss, PQPKH(wrong, SLH)), PQ_FLAGS, checker, &stack), SCRIPT_ERR_OK);
    BOOST_CHECK(IsFalse(stack));
    BOOST_CHECK_EQUAL(checker.calls, 0);
}

BOOST_AUTO_TEST_CASE(pq_transaction_checker)
{
    // TransactionSignatureChecker::CheckPQSig: an empty signature, or one that does not verify, is
    // false (never an exception); an input index out of range is false.
    CMutableTransaction mtx = SaplingTx();
    const CTransaction tx(mtx);
    const valtype pk = PubKey(SLH);
    const CScript spk = PQPKH(KeyHashBytes(SLH, pk), SLH);
    const PrecomputedTransactionData txdata(tx, {CTxOut(1, CScript())});
    TransactionSignatureChecker checker(&tx, txdata, 0, 1);
    BOOST_CHECK(!checker.CheckPQSig(SLH, valtype(), pk, spk, VAULT_BRANCH_ID));
    BOOST_CHECK(!checker.CheckPQSig(SLH, Sig(SLH), pk, spk, VAULT_BRANCH_ID));
    BOOST_CHECK(!checker.CheckPQSig(FALCON, Sig(FALCON), PubKey(FALCON), spk, VAULT_BRANCH_ID));
    BOOST_CHECK(!checker.CheckPQSig(0x07, Sig(SLH), pk, spk, VAULT_BRANCH_ID));
    TransactionSignatureChecker outOfRange(&tx, txdata, 5, 1);
    BOOST_CHECK(!outOfRange.CheckPQSig(SLH, Sig(SLH), pk, spk, VAULT_BRANCH_ID));
    // Through the interpreter: a well-formed garbage signature is false, not an error.
    std::vector<valtype> stack;
    BOOST_CHECK_EQUAL(EvalGood(SLH, STANDARD_SCRIPT_VERIFY_FLAGS | PQ_FLAGS, checker, &stack), SCRIPT_ERR_OK);
    BOOST_CHECK(IsFalse(stack));
    BOOST_CHECK_EQUAL(EvalGood(FALCON, STANDARD_SCRIPT_VERIFY_FLAGS | PQ_FALCON_FLAGS, checker, &stack), SCRIPT_ERR_OK);
    BOOST_CHECK(IsFalse(stack));
}

BOOST_AUTO_TEST_CASE(pq_sigops)
{
    // Consensus does not count OP_CHECKPQSIG (QUANTUM-SPEC F-5 as decided: a context-free count would
    // reprice historical blocks; 0xc2 is uncounted as OP_CHECKSETSIG is). Policy counts
    // pq::SIGOP_COST per OP_CHECKPQSIG a spend executes (GetPQSigOpCount), in the mempool and the
    // block template.
    const valtype pk = PubKey(SLH);
    const CScript spk = PQPKH(KeyHashBytes(SLH, pk), SLH);
    BOOST_CHECK_EQUAL(spk.GetSigOpCount(false), 0U);
    BOOST_CHECK_EQUAL(spk.GetSigOpCount(true), 0U);
    const CScript mixed = CScript() << OP_CHECKSIG << OP_CHECKPQSIG << OP_CHECKSIGVERIFY << OP_CHECKPQSIG;
    BOOST_CHECK_EQUAL(mixed.GetSigOpCount(false), 2U);
    BOOST_CHECK_EQUAL(mixed.GetSigOpCount(true), 2U);

    CCoinsViewDummy dummy;
    CCoinsViewCache view(&dummy);
    CMutableTransaction fund = SaplingTx();
    fund.vin[0].prevout = COutPoint(uint256S("02"), 0);
    fund.vout.resize(4);
    fund.vout[0].scriptPubKey = spk;                                           // TX_PQPKH
    fund.vout[1].scriptPubKey = GetScriptForDestination(CScriptID(spk));       // P2SH of it
    fund.vout[2].scriptPubKey = CScript() << OP_TRUE;                          // anything
    fund.vout[3].scriptPubKey = mixed;                                         // two PQ ops among ECDSA ones
    for (auto& o : fund.vout) o.nValue = 1;
    const CTransaction fundTx(fund);
    // Creating PQ outputs costs no consensus sigops beyond OP_CHECKSIG's.
    BOOST_CHECK_EQUAL(GetLegacySigOpCount(fundTx), 2U);
    view.ModifyCoins(fundTx.GetHash())->FromTx(fundTx, 1);

    const CScript ss = ScriptSig(Chunks(Sig(SLH)), Chunks(pk));
    auto spend = [&](uint32_t n, const CScript& scriptSig) {
        CMutableTransaction mtx = SaplingTx();
        mtx.vin[0].prevout = COutPoint(fundTx.GetHash(), n);
        mtx.vin[0].scriptSig = scriptSig;
        return CTransaction(mtx);
    };
    // the prevout's script holds one: 20; the chunk bytes (0xc2 inside pushes) count nothing
    const CScript ssC2 = ScriptSig(Chunks(valtype(pq::SigSize(SLH) + 1, 0xc2)), Chunks(valtype(32, 0xc2)));
    BOOST_CHECK_EQUAL(GetPQSigOpCount(spend(0, ss), view), pq::SIGOP_COST);
    BOOST_CHECK_EQUAL(GetPQSigOpCount(spend(0, ssC2), view), pq::SIGOP_COST);
    // P2SH: the redeem script (the scriptSig's last push) counts; consensus P2SH counting does not
    CScript p2shSig = ss;
    p2shSig << ToByteVector(spk);
    BOOST_CHECK_EQUAL(GetPQSigOpCount(spend(1, p2shSig), view), pq::SIGOP_COST);
    BOOST_CHECK_EQUAL(GetP2SHSigOpCount(spend(1, p2shSig), view), 0U);
    // an OP_CHECKPQSIG executed from the scriptSig counts too; two in the prevout count 40
    BOOST_CHECK_EQUAL(GetPQSigOpCount(spend(2, CScript() << OP_CHECKPQSIG << OP_CHECKPQSIG), view), 2 * pq::SIGOP_COST);
    BOOST_CHECK_EQUAL(GetPQSigOpCount(spend(2, CScript() << OP_1), view), 0U);
    BOOST_CHECK_EQUAL(GetPQSigOpCount(spend(3, CScript()), view), 2 * pq::SIGOP_COST);
    // a coinbase counts nothing
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout.SetNull();
    cb.vin[0].scriptSig = CScript() << OP_CHECKPQSIG << OP_1;
    cb.vout.resize(1);
    cb.vout[0].nValue = 0;   // 6.20.0: CTransaction parses through Rust, which refuses the default -1
    BOOST_CHECK(CTransaction(cb).IsCoinBase());
    BOOST_CHECK_EQUAL(GetPQSigOpCount(CTransaction(cb), view), 0U);
    // the standard per-transaction budget (4,000) holds 200 PQ checks
    BOOST_CHECK_EQUAL(MAX_STANDARD_TX_SIGOPS / pq::SIGOP_COST, 200U);
}

BOOST_AUTO_TEST_CASE(pq_p2sh_policy)
{
    // Quantum spec R-B2: AreInputsStandard counts OP_CHECKPQSIG's 20 policy sigops toward a P2SH
    // redeem script's MAX_P2SH_SIGOPS (15), so a redeem script holding one is non-standard.
    const valtype pk = PubKey(SLH);
    const CScript pqpkh = PQPKH(KeyHashBytes(SLH, pk), SLH);
    BOOST_CHECK_EQUAL(GetPQSigOpCount(pqpkh), pq::SIGOP_COST);
    BOOST_CHECK_EQUAL(GetPQSigOpCount(CScript() << valtype(1, OP_CHECKPQSIG)), 0U);   // inside a push
    CScript fifteen;
    for (int j = 0; j < 15; j++) fifteen << OP_CHECKSIG;
    const CScript fifteenPlusPQ = CScript(fifteen) << OP_CHECKPQSIG;
    const CScript plain = CScript() << OP_DROP << OP_1;   // no sigops, not a Solver type

    CCoinsViewDummy dummy;
    CCoinsViewCache view(&dummy);
    CMutableTransaction fund = SaplingTx();
    fund.vin[0].prevout = COutPoint(uint256S("03"), 0);
    const std::vector<CScript> redeems = {pqpkh, plain, fifteen, fifteenPlusPQ};
    fund.vout.resize(redeems.size());
    for (size_t i = 0; i < redeems.size(); i++) {
        fund.vout[i].scriptPubKey = GetScriptForDestination(CScriptID(redeems[i]));
        fund.vout[i].nValue = 1;
    }
    const CTransaction fundTx(fund);
    view.ModifyCoins(fundTx.GetHash())->FromTx(fundTx, 1);
    auto spend = [&](uint32_t n, const CScript& scriptSig) {
        CMutableTransaction mtx = SaplingTx();
        mtx.vin[0].prevout = COutPoint(fundTx.GetHash(), n);
        mtx.vin[0].scriptSig = scriptSig;
        return CTransaction(mtx);
    };
    CScript ssPQ = ScriptSig(Chunks(Sig(SLH)), Chunks(pk));
    ssPQ << ToByteVector(pqpkh);
    BOOST_CHECK(!AreInputsStandard(spend(0, ssPQ), view, VAULT_BRANCH_ID));
    BOOST_CHECK(AreInputsStandard(spend(1, CScript() << OP_1 << ToByteVector(plain)), view, VAULT_BRANCH_ID));
    BOOST_CHECK(AreInputsStandard(spend(2, CScript() << ToByteVector(fifteen)), view, VAULT_BRANCH_ID));
    BOOST_CHECK(!AreInputsStandard(spend(3, CScript() << ToByteVector(fifteenPlusPQ)), view, VAULT_BRANCH_ID));
    // the transaction-level count sees the same redeem script
    BOOST_CHECK_EQUAL(GetPQSigOpCount(spend(0, ssPQ), view), pq::SIGOP_COST);
}

BOOST_AUTO_TEST_CASE(pq_error_order)
{
    // The frozen order (QUANTUM-SPEC A-7): scheme -> registered/Falcon gate -> key hash 32 bytes ->
    // p/s counts -> canonical chunks -> total sizes -> (STRICTENC hashtype) -> key-hash compare (false)
    // -> verify. Each case carries two faults; the earlier one is reported.
    MockPQChecker checker;
    const valtype pk = PubKey(FALCON);
    const valtype kh = KeyHashBytes(FALCON, pk);
    const std::vector<valtype> sc = Chunks(Sig(FALCON)), pc = Chunks(pk);
    auto seqS = [](const std::vector<valtype>& chunks, const valtype* count = nullptr) {
        CScript s;
        PushSeq(s, chunks, count);
        return s;
    };
    auto run = [&](const CScript& sigPart, const CScript& pkPart, const valtype& khv, const valtype& scheme, unsigned int flags) {
        return Eval(Cat(Cat(sigPart, pkPart), CScript() << khv << scheme << OP_CHECKPQSIG), flags, checker);
    };
    const valtype two{0x02}, three{0x03};
    std::vector<valtype> shortChunk = sc, longPk = pc;
    shortChunk[0].pop_back();                 // a canonical-chunking fault in the signature
    longPk.back().push_back(0);               // a size fault in the key
    // unregistered / gated scheme before a bad key hash
    BOOST_CHECK_EQUAL(run(seqS(sc), seqS(pc), valtype(31, 0), valtype{0x03}, PQ_FALCON_FLAGS), SCRIPT_ERR_PQ_SCHEME);
    BOOST_CHECK_EQUAL(run(seqS(sc), seqS(pc), valtype(31, 0), two, PQ_FLAGS), SCRIPT_ERR_PQ_SCHEME);
    // key hash size before the counts
    BOOST_CHECK_EQUAL(run(seqS(sc), seqS(pc, &three), valtype(31, 0), two, PQ_FALCON_FLAGS), SCRIPT_ERR_PQ_SIZE);
    // the signature's count before the key's chunking and size
    BOOST_CHECK_EQUAL(run(seqS(sc, &three), seqS(longPk), kh, two, PQ_FALCON_FLAGS), SCRIPT_ERR_PQ_CHUNK);
    BOOST_CHECK_EQUAL(run(CScript() << OP_2, seqS(longPk), kh, two, PQ_FALCON_FLAGS), SCRIPT_ERR_INVALID_STACK_OPERATION);
    // the signature's chunking before the key's size
    BOOST_CHECK_EQUAL(run(seqS(shortChunk), seqS(longPk), kh, two, PQ_FALCON_FLAGS), SCRIPT_ERR_PQ_CHUNK);
    // the key's size before the signature's
    std::vector<valtype> longSig = sc;
    longSig.back().push_back(SIGHASH_ALL);
    BOOST_CHECK_EQUAL(run(seqS(longSig), seqS(longPk), kh, two, PQ_FALCON_FLAGS), SCRIPT_ERR_PQ_SIZE);
    // sizes before the hashtype; the hashtype before the key-hash compare
    std::vector<valtype> badHt = sc;
    badHt.back().back() = 0x00;
    BOOST_CHECK_EQUAL(run(seqS(badHt), seqS(longPk), kh, two, PQ_FALCON_FLAGS | SCRIPT_VERIFY_STRICTENC), SCRIPT_ERR_PQ_SIZE);
    valtype wrong = kh;
    wrong[5] ^= 1;
    BOOST_CHECK_EQUAL(run(seqS(badHt), seqS(pc), wrong, two, PQ_FALCON_FLAGS | SCRIPT_VERIFY_STRICTENC), SCRIPT_ERR_SIG_HASHTYPE);
    BOOST_CHECK_EQUAL(checker.calls, 0);
    // the key-hash compare before the verifier: false, checker not asked
    std::vector<valtype> stack;
    BOOST_CHECK_EQUAL(Eval(Cat(Cat(seqS(sc), seqS(pc)), CScript() << wrong << two << OP_CHECKPQSIG), PQ_FALCON_FLAGS, checker, &stack), SCRIPT_ERR_OK);
    BOOST_CHECK(IsFalse(stack));
    BOOST_CHECK_EQUAL(checker.calls, 0);
    BOOST_CHECK_EQUAL(run(seqS(sc), seqS(pc), kh, two, PQ_FALCON_FLAGS), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(checker.calls, 1);
}

BOOST_AUTO_TEST_CASE(pq_flag_plumbing)
{
    const int NONE = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
    // pqFalconHeight is unset on mainnet and testnet, and on regtest without -pqfalcon / -pqfalconheight.
    BOOST_CHECK_EQUAL(Params(CBaseChainParams::MAIN).GetConsensus().pqFalconHeight, NONE);
    BOOST_CHECK_EQUAL(Params(CBaseChainParams::TESTNET).GetConsensus().pqFalconHeight, NONE);
    BOOST_CHECK_EQUAL(Params(CBaseChainParams::REGTEST).GetConsensus().pqFalconHeight, NONE);

    // IsPQFalconActive and GetVaultScriptFlags: the vault upgrade at 100, Falcon from pqFalconHeight
    // (quantum spec R-A2); a Falcon height below the upgrade's waits for the upgrade.
    Consensus::Params params = Params(CBaseChainParams::REGTEST).GetConsensus();
    params.vUpgrades[Consensus::UPGRADE_VAULT].nActivationHeight = 100;
    struct Row { int falconHeight; int height; bool falcon; };
    for (const Row& r : std::vector<Row>{{NONE, 99, false}, {NONE, 100, false}, {NONE, 100000, false},
                                         {0, 99, false}, {0, 100, true}, {50, 100, true},
                                         {150, 100, false}, {150, 149, false}, {150, 150, true}, {150, 151, true}}) {
        params.pqFalconHeight = r.falconHeight;
        BOOST_CHECK_EQUAL(IsPQFalconActive(params, r.height), r.falcon);
        const unsigned int f = GetVaultScriptFlags(r.height, params);
        if (r.height < 100) {
            BOOST_CHECK_EQUAL(f, 0U);
        } else {
            BOOST_CHECK(f & SCRIPT_VERIFY_VAULT);
            BOOST_CHECK(f & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY);
        }
        BOOST_CHECK_EQUAL((f & SCRIPT_VERIFY_PQ_FALCON) != 0, r.falcon);
    }
    // without the vault upgrade at all, never
    params.vUpgrades[Consensus::UPGRADE_VAULT].nActivationHeight = NONE;
    params.pqFalconHeight = 0;
    BOOST_CHECK(!IsPQFalconActive(params, 1000000));

    // Regtest flags, read by SelectParams: -pqfalcon=1 is height 0, -pqfalconheight=<h> sets it (and
    // wins over -pqfalcon); neither reaches mainnet (init.cpp refuses them there, R-B3).
    mapArgs["-pqfalcon"] = "1";
    SelectParams(CBaseChainParams::REGTEST);
    BOOST_CHECK_EQUAL(Params().GetConsensus().pqFalconHeight, 0);
    SelectParams(CBaseChainParams::MAIN);
    BOOST_CHECK_EQUAL(Params().GetConsensus().pqFalconHeight, NONE);
    mapArgs["-pqfalconheight"] = "250";
    SelectParams(CBaseChainParams::REGTEST);
    BOOST_CHECK_EQUAL(Params().GetConsensus().pqFalconHeight, 250);
    mapArgs.erase("-pqfalcon");
    SelectParams(CBaseChainParams::REGTEST);
    BOOST_CHECK_EQUAL(Params().GetConsensus().pqFalconHeight, 250);
    mapArgs["-pqfalcon"] = "0";
    mapArgs.erase("-pqfalconheight");
    SelectParams(CBaseChainParams::REGTEST);
    BOOST_CHECK_EQUAL(Params().GetConsensus().pqFalconHeight, NONE);
    mapArgs.erase("-pqfalcon");
    SelectParams(CBaseChainParams::REGTEST);
    BOOST_CHECK_EQUAL(Params().GetConsensus().pqFalconHeight, NONE);
    SelectParams(CBaseChainParams::MAIN);
}

namespace {

struct PQKey {
    uint8_t scheme;
    valtype pk, sk;
};

PQKey MakeKey(uint8_t scheme, unsigned char seedByte)
{
    PQKey k{scheme, {}, {}};
    BOOST_REQUIRE(pq::KeyGen(scheme, valtype(pq::SeedSize(scheme), seedByte), k.pk, k.sk));
    BOOST_REQUIRE_EQUAL(k.pk.size(), pq::PubKeySize(scheme));
    return k;
}

/** A signature over SignatureHash(scriptCode, tx, 0, hashType, amount, branch) plus the hashtype byte. */
valtype SignPQ(const PQKey& k, const CScript& scriptCode, const CTransaction& tx, int hashType,
               CAmount amount, uint32_t branch, unsigned char entropyByte = 0x33)
{
    const PrecomputedTransactionData txdata(tx, {CTxOut(amount, scriptCode)});
    const uint256 sighash = SignatureHash(scriptCode, tx, 0, hashType, amount, branch, txdata);
    valtype sig;
    const valtype entropy = k.scheme == FALCON ? valtype(pq::FALCON_SIGN_ENTROPY_SIZE, entropyByte) : valtype();
    BOOST_REQUIRE(pq::SignWithEntropy(k.scheme, k.sk, sighash, entropy, sig));
    BOOST_REQUIRE_EQUAL(sig.size(), pq::SigSize(k.scheme));
    sig.push_back((unsigned char)hashType);
    return sig;
}

ScriptError VerifyPQ(const CScript& scriptSig, const CScript& spk, const CTransaction& tx, CAmount amount,
                     unsigned int flags, uint32_t branch = VAULT_BRANCH_ID)
{
    const PrecomputedTransactionData txdata(tx, {CTxOut(amount, spk)});
    TransactionSignatureChecker checker(&tx, txdata, 0, amount);
    ScriptError err;
    VerifyScript(scriptSig, spk, flags, checker, branch, &err);
    return err;
}

} // namespace

BOOST_AUTO_TEST_CASE(pq_valid_signatures)
{
    // Real keys and signatures (crypto/pq/sign.h, the wallet side) verified by the interpreter through
    // TransactionSignatureChecker::CheckPQSig and pq::Verify over the ZIP-243 sighash.
    const CAmount amount = 123456;
    const unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS | PQ_FALCON_FLAGS;
    for (uint8_t scheme : {SLH, FALCON}) {
        const PQKey key = MakeKey(scheme, scheme == SLH ? 0x41 : 0x42);
        const CScript spk = PQPKH(KeyHashBytes(scheme, key.pk), scheme);
        CMutableTransaction mtx = SaplingTx();
        mtx.vout.resize(2);
        mtx.vout[1].nValue = 2;
        const CTransaction tx(mtx);

        const valtype sig = SignPQ(key, spk, tx, SIGHASH_ALL, amount, VAULT_BRANCH_ID);
        const CScript ss = ScriptSig(Chunks(sig), Chunks(key.pk));
        BOOST_CHECK_EQUAL(VerifyPQ(ss, spk, tx, amount, flags), SCRIPT_ERR_OK);
        // without PQ_FALCON, Falcon is an unknown scheme; SLH-DSA does not need it
        BOOST_CHECK_EQUAL(VerifyPQ(ss, spk, tx, amount, STANDARD_SCRIPT_VERIFY_FLAGS | PQ_FLAGS),
                          scheme == SLH ? SCRIPT_ERR_OK : SCRIPT_ERR_PQ_SCHEME);
        // before the upgrade it is BAD_OPCODE
        BOOST_CHECK_EQUAL(VerifyPQ(ss, spk, tx, amount, STANDARD_SCRIPT_VERIFY_FLAGS), SCRIPT_ERR_BAD_OPCODE);
        // the size of the scriptSig of §2.1 (QUANTUM-SPEC): SLH 7,938 B, Falcon 1,577 B
        BOOST_CHECK_EQUAL(ss.size(), scheme == SLH ? 7938U : 1577U);

        // anything the sighash binds breaks it: a signature byte, the amount, the branch, the
        // hashtype byte, an output; and the key hash binds the key
        valtype bad = sig;
        bad[10] ^= 0x01;
        BOOST_CHECK_EQUAL(VerifyPQ(ScriptSig(Chunks(bad), Chunks(key.pk)), spk, tx, amount, flags), SCRIPT_ERR_EVAL_FALSE);
        BOOST_CHECK_EQUAL(VerifyPQ(ss, spk, tx, amount + 1, flags), SCRIPT_ERR_EVAL_FALSE);
        BOOST_CHECK_EQUAL(VerifyPQ(ss, spk, tx, amount, flags, NetworkUpgradeInfo[Consensus::UPGRADE_NU5].nBranchId), SCRIPT_ERR_EVAL_FALSE);
        bad = sig;
        bad.back() = SIGHASH_NONE;
        BOOST_CHECK_EQUAL(VerifyPQ(ScriptSig(Chunks(bad), Chunks(key.pk)), spk, tx, amount, flags), SCRIPT_ERR_EVAL_FALSE);
        CMutableTransaction mtx2 = mtx;
        mtx2.vout[1].nValue = 3;
        const CTransaction tx2(mtx2);
        BOOST_CHECK_EQUAL(VerifyPQ(ss, spk, tx2, amount, flags), SCRIPT_ERR_EVAL_FALSE);
        const PQKey other = MakeKey(scheme, 0x7e);
        BOOST_CHECK_EQUAL(VerifyPQ(ScriptSig(Chunks(sig), Chunks(other.pk)), spk, tx, amount, flags), SCRIPT_ERR_EVAL_FALSE);
        // another key's script with this key's signature: the key hash does not match
        const CScript spkOther = PQPKH(KeyHashBytes(scheme, other.pk), scheme);
        BOOST_CHECK_EQUAL(VerifyPQ(ss, spkOther, tx, amount, flags), SCRIPT_ERR_EVAL_FALSE);
        // the signature is over the executing script: signing another scriptCode fails
        const valtype sigOther = SignPQ(key, spkOther, tx, SIGHASH_ALL, amount, VAULT_BRANCH_ID);
        BOOST_CHECK_EQUAL(VerifyPQ(ScriptSig(Chunks(sigOther), Chunks(key.pk)), spk, tx, amount, flags), SCRIPT_ERR_EVAL_FALSE);

        // SIGHASH_NONE | ANYONECANPAY: the outputs are free, the signature still binds this input
        const int htNone = SIGHASH_NONE | SIGHASH_ANYONECANPAY;
        const valtype sigNone = SignPQ(key, spk, tx, htNone, amount, VAULT_BRANCH_ID);
        const CScript ssNone = ScriptSig(Chunks(sigNone), Chunks(key.pk));
        BOOST_CHECK_EQUAL(VerifyPQ(ssNone, spk, tx, amount, flags), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(VerifyPQ(ssNone, spk, tx2, amount, flags), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(VerifyPQ(ssNone, spk, tx, amount - 1, flags), SCRIPT_ERR_EVAL_FALSE);
        // with an undefined hashtype the signature verifies by consensus, not under STRICTENC
        const valtype sigOdd = SignPQ(key, spk, tx, 0x04, amount, VAULT_BRANCH_ID);
        const CScript ssOdd = ScriptSig(Chunks(sigOdd), Chunks(key.pk));
        BOOST_CHECK_EQUAL(VerifyPQ(ssOdd, spk, tx, amount, PQ_FALCON_FLAGS), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(VerifyPQ(ssOdd, spk, tx, amount, flags), SCRIPT_ERR_SIG_HASHTYPE);
        // the vault primitive's checker (the one blocks and the mempool use under UPGRADE_VAULT)
        // answers OP_CHECKPQSIG by inheritance, without a set snapshot
        PrecomputedTransactionData txdata(tx, {CTxOut(amount, spk)});
        vault::SetSigChecker vaultChecker(&tx, 0, amount, false, txdata, nullptr, 1);
        ScriptError err;
        BOOST_CHECK(VerifyScript(ss, spk, flags, vaultChecker, VAULT_BRANCH_ID, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
        BOOST_CHECK(VerifyScript(ssNone, spk, flags, vaultChecker, VAULT_BRANCH_ID, &err));
    }
}

BOOST_AUTO_TEST_CASE(pq_hashtype_matrix_real)
{
    // 6.20.0 (ycash6 port of q/op): OP_CHECKPQSIG computes the sighash through the C++ SignatureHash
    // that OP_CHECKSIG uses; for a v4 (Sapling) transaction that is the ZIP-243 branch, which accepts
    // every hashtype byte (ZIP-244's strict hashtype parse applies only to v5). So with real keys and
    // signatures an undefined hashtype (0x00, 0x04, 0x41, 0xff) is consensus-valid and only STRICTENC
    // (policy) rejects it, exactly as on ycash-dd, and exactly as OP_CHECKSIG behaves on this line
    // (consensus review B's hashtype matrix).
    const CAmount amount = 5000;
    const unsigned int consensusFlags = PQ_FALCON_FLAGS;
    const unsigned int policyFlags = STANDARD_SCRIPT_VERIFY_FLAGS | PQ_FALCON_FLAGS;
    const std::vector<int> hashtypes = {0x00, 0x01, 0x03, 0x04, 0x41, 0x83, 0xff};
    CMutableTransaction mtx = SaplingTx();
    mtx.vout.resize(2);
    mtx.vout[1].nValue = 2;
    const CTransaction tx(mtx);

    const CKey ecKey = CKey::TestOnlyRandomKey(true);
    const CScript p2pkh = GetScriptForDestination(ecKey.GetPubKey().GetID());
    for (int ht : hashtypes) {
        const bool defined = ((ht & ~SIGHASH_ANYONECANPAY) >= SIGHASH_ALL && (ht & ~SIGHASH_ANYONECANPAY) <= SIGHASH_SINGLE);
        // the OP_CHECKSIG reference on this line
        const PrecomputedTransactionData txdata(tx, {CTxOut(amount, p2pkh)});
        const uint256 sighash = SignatureHash(p2pkh, tx, 0, ht, amount, VAULT_BRANCH_ID, txdata);
        valtype ecSig;
        BOOST_REQUIRE(ecKey.Sign(sighash, ecSig));
        ecSig.push_back((unsigned char)ht);
        const CScript ecSS = CScript() << ecSig << ToByteVector(ecKey.GetPubKey());
        BOOST_CHECK_EQUAL(VerifyPQ(ecSS, p2pkh, tx, amount, consensusFlags), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(VerifyPQ(ecSS, p2pkh, tx, amount, policyFlags), defined ? SCRIPT_ERR_OK : SCRIPT_ERR_SIG_HASHTYPE);

        for (uint8_t scheme : {SLH, FALCON}) {
            const PQKey key = MakeKey(scheme, scheme == SLH ? 0x51 : 0x52);
            const CScript spk = PQPKH(KeyHashBytes(scheme, key.pk), scheme);
            const valtype sig = SignPQ(key, spk, tx, ht, amount, VAULT_BRANCH_ID);
            const CScript ss = ScriptSig(Chunks(sig), Chunks(key.pk));
            BOOST_CHECK_EQUAL(VerifyPQ(ss, spk, tx, amount, consensusFlags), SCRIPT_ERR_OK);
            BOOST_CHECK_EQUAL(VerifyPQ(ss, spk, tx, amount, policyFlags), defined ? SCRIPT_ERR_OK : SCRIPT_ERR_SIG_HASHTYPE);
            // the hashtype byte is bound: the same signature under another hashtype byte is false
            valtype other = sig;
            other.back() = (unsigned char)(ht ^ 0x02);
            BOOST_CHECK_EQUAL(VerifyPQ(ScriptSig(Chunks(other), Chunks(key.pk)), spk, tx, amount, consensusFlags), SCRIPT_ERR_EVAL_FALSE);
        }
    }

    // A v5 (ZIP-225) transaction takes ZIP-244, whose undefined-hashtype throw makes both opcodes
    // false (6.20.0 only: ycash-dd has no v5; NU5 has no activation height on any Ycash network).
    CMutableTransaction mtx5 = SaplingTx();
    mtx5.nVersionGroupId = ZIP225_VERSION_GROUP_ID;
    mtx5.nVersion = ZIP225_TX_VERSION;
    mtx5.nConsensusBranchId = NetworkUpgradeInfo[Consensus::UPGRADE_NU5].nBranchId;
    const CTransaction tx5(mtx5);
    {
        const PrecomputedTransactionData txdata(tx5, {CTxOut(amount, p2pkh)});
        valtype ecSig;
        BOOST_REQUIRE(ecKey.Sign(SignatureHash(p2pkh, tx5, 0, SIGHASH_ALL, amount, 0, txdata), ecSig));
        ecSig.push_back(SIGHASH_ALL);
        BOOST_CHECK_EQUAL(VerifyPQ(CScript() << ecSig << ToByteVector(ecKey.GetPubKey()), p2pkh, tx5, amount, consensusFlags), SCRIPT_ERR_OK);
        ecSig.back() = 0x04;
        BOOST_CHECK_EQUAL(VerifyPQ(CScript() << ecSig << ToByteVector(ecKey.GetPubKey()), p2pkh, tx5, amount, consensusFlags), SCRIPT_ERR_EVAL_FALSE);
    }
    for (uint8_t scheme : {SLH, FALCON}) {
        const PQKey key = MakeKey(scheme, scheme == SLH ? 0x51 : 0x52);
        const CScript spk = PQPKH(KeyHashBytes(scheme, key.pk), scheme);
        valtype sig = SignPQ(key, spk, tx5, SIGHASH_ALL, amount, 0);
        BOOST_CHECK_EQUAL(VerifyPQ(ScriptSig(Chunks(sig), Chunks(key.pk)), spk, tx5, amount, consensusFlags), SCRIPT_ERR_OK);
        sig.back() = 0x04;
        BOOST_CHECK_EQUAL(VerifyPQ(ScriptSig(Chunks(sig), Chunks(key.pk)), spk, tx5, amount, consensusFlags), SCRIPT_ERR_EVAL_FALSE);
    }
}

namespace {

/** Verifies OP_CHECKPQSIG over a fixed message (a golden vector's msg), as CheckPQSig does over the sighash. */
class FixedMsgChecker : public BaseSignatureChecker
{
public:
    uint256 msg;
    bool CheckPQSig(uint8_t scheme, const valtype& vchSig, const valtype& vchPubKey,
                    const CScript&, uint32_t) const override
    {
        if (vchSig.empty()) return false;
        return pq::Verify(scheme, vchPubKey, valtype(vchSig.begin(), vchSig.end() - 1), msg);
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(pq_golden_spends)
{
    // src/test/data/pq_vectors.json "spends": whole TX_PQPKH scriptPubKeys and chunked scriptSigs
    // (byte-identical on both node lines, YEW and the Python framework) through the interpreter.
    UniValue doc;
    BOOST_REQUIRE(doc.read(std::string(json_tests::pq_vectors, json_tests::pq_vectors + sizeof(json_tests::pq_vectors))));
    const UniValue& keys = doc["keys"];
    const UniValue& spends = doc["spends"];
    BOOST_REQUIRE_EQUAL(spends.size(), 2U);
    for (size_t i = 0; i < spends.size(); i++) {
        const UniValue& sp = spends[i];
        const UniValue& key = keys[sp["key"].get_int()];
        const uint8_t scheme = sp["scheme"].get_int();
        BOOST_REQUIRE_EQUAL(key["scheme"].get_int(), scheme);
        const valtype spkBytes = ParseHex(sp["scriptPubKey"].get_str());
        const valtype ssBytes = ParseHex(sp["scriptSig"].get_str());
        const CScript spk(spkBytes.begin(), spkBytes.end());
        const CScript ss(ssBytes.begin(), ssBytes.end());
        const valtype pk = ParseHex(key["pk"].get_str());
        valtype sig = ParseHex(key["sig"].get_str());
        sig.push_back((unsigned char)sp["hashtype"].get_int());
        BOOST_CHECK_EQUAL(ss.size(), (size_t)sp["scriptSigSize"].get_int());
        // this file's builders produce the vector's bytes
        BOOST_CHECK(PQPKH(KeyHashBytes(scheme, pk), scheme) == spk);
        BOOST_CHECK(ParseHex(key["keyhash"].get_str()) == KeyHashBytes(scheme, pk));
        BOOST_CHECK(ScriptSig(Chunks(sig), Chunks(pk)) == ss);
        BOOST_CHECK_EQUAL(Chunks(sig).size(), (size_t)sp["sigChunks"].get_int());
        BOOST_CHECK_EQUAL(Chunks(pk).size(), (size_t)sp["pkChunks"].get_int());

        FixedMsgChecker checker;
        const valtype msg = ParseHex(key["msg"].get_str());
        checker.msg = uint256(msg);
        const unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS | PQ_FALCON_FLAGS;
        ScriptError err;
        BOOST_CHECK(VerifyScript(ss, spk, flags, checker, VAULT_BRANCH_ID, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
        // Falcon is rejected without the flag; SLH-DSA is not
        VerifyScript(ss, spk, STANDARD_SCRIPT_VERIFY_FLAGS | PQ_FLAGS, checker, VAULT_BRANCH_ID, &err);
        BOOST_CHECK_EQUAL(err, scheme == SLH ? SCRIPT_ERR_OK : SCRIPT_ERR_PQ_SCHEME);
        VerifyScript(ss, spk, STANDARD_SCRIPT_VERIFY_FLAGS, checker, VAULT_BRANCH_ID, &err);
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
        // one bit of the signature (inside the first chunk), or another message, is false
        valtype bad = ssBytes;
        bad[3 + 100] ^= 0x01;
        BOOST_CHECK(!VerifyScript(CScript(bad.begin(), bad.end()), spk, flags, checker, VAULT_BRANCH_ID, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);
        checker.msg = uint256S("01");
        BOOST_CHECK(!VerifyScript(ss, spk, flags, checker, VAULT_BRANCH_ID, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);
    }
}

namespace {

/** The argument items of one OP_CHECKPQSIG (sig chunks, s, pk chunks, p, keyHash, scheme) as a script. */
CScript ArgItems(uint8_t scheme)
{
    const valtype pk = PubKey(scheme);
    return Cat(ScriptSig(Chunks(Sig(scheme)), Chunks(pk)), CScript() << KeyHashBytes(scheme, pk) << (int64_t)scheme);
}

/** `copies` x (<n-1> OP_PICK x n, OP_CHECKPQSIG, OP_DROP): re-checks the n items on top `copies` times. */
CScript Amplify(int n, int copies)
{
    CScript s;
    for (int c = 0; c < copies; c++) {
        for (int j = 0; j < n; j++) s << (int64_t)(n - 1) << OP_PICK;
        s << OP_CHECKPQSIG << OP_DROP;
    }
    return s;
}

} // namespace

BOOST_AUTO_TEST_CASE(pq_one_per_evaluation)
{
    // Quantum spec R-B1: at most one executed OP_CHECKPQSIG per EvalScript under SCRIPT_VERIFY_VAULT,
    // else SCRIPT_ERR_PQ_COUNT (the OP_CHECKSETSIG precedent). It bounds PQ verifications to three
    // per input (scriptSig, scriptPubKey, P2SH redeem script).
    MockPQChecker checker;
    const unsigned int flags = PQ_FALCON_FLAGS;

    // Reviewer B's amplification: the scriptSig pushes the 21 items of an SLH-DSA check, then
    // re-picks and re-checks them; the scriptPubKey repeats it and ends OP_CHECKPQSIG OP_NOT.
    const CScript items = ArgItems(SLH);
    {
        int n = 0;
        std::vector<valtype> st;
        BOOST_CHECK_EQUAL(Eval(items, flags, checker, &st), SCRIPT_ERR_OK);
        n = st.size();
        BOOST_REQUIRE_EQUAL(n, 21);
        const CScript scriptSig = Cat(items, Amplify(21, 3));
        BOOST_CHECK_EQUAL(Eval(scriptSig, flags, checker), SCRIPT_ERR_PQ_COUNT);
        const CScript spk = Cat(Amplify(21, 3), CScript() << OP_CHECKPQSIG << OP_NOT);
        ScriptError err;
        BOOST_CHECK(!VerifyScript(scriptSig, spk, flags, checker, VAULT_BRANCH_ID, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQ_COUNT);
        // a push-only scriptSig moves the loop into the scriptPubKey: the same error there
        BOOST_CHECK(!VerifyScript(items, spk, flags, checker, VAULT_BRANCH_ID, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQ_COUNT);
        // exactly one copy is fine
        BOOST_CHECK_EQUAL(Eval(Cat(items, Amplify(21, 1)), flags, checker), SCRIPT_ERR_OK);
    }
    // Reviewer A's: 16 items (8 filler + a Falcon check's 8), 16 x OP_PICK per copy, 11 copies
    // (198 ops, under the 201 limit).
    {
        CScript s;
        for (int j = 0; j < 8; j++) s << valtype(1, (unsigned char)(0x40 + j));
        s = Cat(s, ArgItems(FALCON));
        std::vector<valtype> st;
        BOOST_CHECK_EQUAL(Eval(s, flags, checker, &st), SCRIPT_ERR_OK);
        BOOST_REQUIRE_EQUAL(st.size(), 16U);
        const int callsBefore = checker.calls;
        BOOST_CHECK_EQUAL(Eval(Cat(s, Amplify(16, 11)), flags, checker), SCRIPT_ERR_PQ_COUNT);
        BOOST_CHECK_EQUAL(checker.calls, callsBefore + 1);   // the second never reaches the verifier
    }
    // Without SCRIPT_VERIFY_VAULT the opcode is BAD_OPCODE before any count.
    BOOST_CHECK_EQUAL(Eval(Cat(items, Amplify(21, 2)), SCRIPT_VERIFY_P2SH, checker), SCRIPT_ERR_BAD_OPCODE);
    // Unexecuted branches do not count.
    {
        const CScript s = Cat(items, CScript() << OP_0 << OP_IF << OP_CHECKPQSIG << OP_CHECKPQSIG << OP_ENDIF
                                               << OP_CHECKPQSIG << OP_0 << OP_IF << OP_CHECKPQSIG << OP_ENDIF);
        std::vector<valtype> st;
        BOOST_CHECK_EQUAL(Eval(s, flags, checker, &st), SCRIPT_ERR_OK);
        BOOST_CHECK(IsTrue(st));
    }
    // One in the scriptSig and one in the scriptPubKey are two evaluations: both run (documented
    // behaviour; the scriptSig is not push-only, so this is non-standard under SIGPUSHONLY policy).
    {
        MockPQChecker c2;
        const CScript scriptSig = Cat(items, CScript() << OP_CHECKPQSIG);
        const CScript spk = Cat(items, CScript() << OP_CHECKPQSIG << OP_BOOLAND);
        ScriptError err;
        BOOST_CHECK(VerifyScript(scriptSig, spk, flags, c2, VAULT_BRANCH_ID, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(c2.calls, 2);
    }
}

BOOST_AUTO_TEST_CASE(pq_p2sh_wrapped_real_signature)
{
    // A PQPKH script as a P2SH redeem script with a real SLH-DSA signature: one OP_CHECKPQSIG in the
    // redeem evaluation, so R-B1 lets it pass (consensus; R-B2 makes it non-standard).
    const CAmount amount = 5000;
    const PQKey key = MakeKey(SLH, 0x51);
    const CScript redeem = PQPKH(KeyHashBytes(SLH, key.pk), SLH);
    const CScript p2sh = GetScriptForDestination(CScriptID(redeem));
    const CTransaction tx(SaplingTx());
    const valtype sig = SignPQ(key, redeem, tx, SIGHASH_ALL, amount, VAULT_BRANCH_ID);
    CScript ss = ScriptSig(Chunks(sig), Chunks(key.pk));
    ss << ToByteVector(redeem);
    BOOST_CHECK_EQUAL(VerifyPQ(ss, p2sh, tx, amount, STANDARD_SCRIPT_VERIFY_FLAGS | PQ_FLAGS), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(VerifyPQ(ss, p2sh, tx, amount + 1, STANDARD_SCRIPT_VERIFY_FLAGS | PQ_FLAGS), SCRIPT_ERR_EVAL_FALSE);
}

BOOST_AUTO_TEST_SUITE_END()
