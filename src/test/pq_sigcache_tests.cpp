// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The signature cache for OP_CHECKPQSIG (quantum plan §6, doc/yellowback-pq-dos.md follow-up a):
// CachingTransactionSignatureChecker memoizes pq::Verify under the ECDSA store rule. A cache must
// never change a verdict: a hit needs a stored success on the same scheme, key, signature and
// sighash; failures are never stored; PQ and ECDSA entries never meet.

#include "crypto/pq/scheme.h"
#include "crypto/pq/sign.h"
#include "key.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sigcache.h"
#include "script/standard.h"
#include "test/test_bitcoin.h"
#include "uint256.h"
#include "vault/checker.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <memory>
#include <vector>

typedef std::vector<unsigned char> valtype;

namespace {

const uint32_t VAULT_BRANCH_ID = 0x6d5b7a31;
const uint8_t SLH = pq::SCHEME_SLH_DSA_SHA2_128S;
const uint8_t FALCON = pq::SCHEME_FN_DSA_512;
const unsigned int FLAGS = STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
                           SCRIPT_VERIFY_VAULT | SCRIPT_VERIFY_PQ_FALCON;
const CAmount AMOUNT = 123456;

struct PQKey {
    uint8_t scheme;
    valtype pk, sk;
};

PQKey MakeKey(uint8_t scheme, unsigned char seedByte)
{
    PQKey k{scheme, {}, {}};
    BOOST_REQUIRE(pq::KeyGen(scheme, valtype(pq::SeedSize(scheme), seedByte), k.pk, k.sk));
    return k;
}

CScript PQPKH(const PQKey& k)
{
    const uint256 h = pq::KeyHash(k.scheme, k.pk);
    return CScript() << valtype(h.begin(), h.end()) << (int64_t)k.scheme << OP_CHECKPQSIG;
}

/** A spend of one input; `tag` changes an output, so each tag gives another sighash. */
CTransaction Tx(CAmount tag)
{
    CMutableTransaction mtx;
    mtx.fOverwintered = true;
    mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    mtx.nVersion = SAPLING_TX_VERSION;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(uint256S("01"), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = tag;
    return CTransaction(mtx);
}

// The two node lines differ only in these constructors (6.20.0 takes the spent outputs).
std::unique_ptr<PrecomputedTransactionData> TxData(const CTransaction& tx, const CScript& spk)
{
    return std::make_unique<PrecomputedTransactionData>(tx, std::vector<CTxOut>{CTxOut(AMOUNT, spk)});
}

uint256 Sighash(const CTransaction& tx, const CScript& spk, int hashType)
{
    return SignatureHash(spk, tx, 0, hashType, AMOUNT, VAULT_BRANCH_ID, *TxData(tx, spk));
}

/** The checker blocks and the mempool use, with the store flag the caller chooses. */
struct Checker {
    std::unique_ptr<PrecomputedTransactionData> txdata;
    std::unique_ptr<CachingTransactionSignatureChecker> c;
    Checker(const CTransaction& tx, const CScript& spk, bool store) : txdata(TxData(tx, spk))
    {
        c = std::make_unique<CachingTransactionSignatureChecker>(&tx, *txdata, 0, AMOUNT, store);
    }
};

/** sig (without hashtype) + hashtype byte, over (tx, spk). */
valtype Sign(const PQKey& k, const CTransaction& tx, const CScript& spk, int hashType = SIGHASH_ALL)
{
    valtype sig;
    const valtype entropy = k.scheme == FALCON ? valtype(pq::FALCON_SIGN_ENTROPY_SIZE, 0x33) : valtype();
    BOOST_REQUIRE(pq::SignWithEntropy(k.scheme, k.sk, Sighash(tx, spk, hashType), entropy, sig));
    sig.push_back((unsigned char)hashType);
    return sig;
}

valtype Strip(const valtype& sig) { return valtype(sig.begin(), sig.end() - 1); }

/** One OP_CHECKPQSIG through CachingTransactionSignatureChecker::CheckPQSig. */
bool Check(const PQKey& k, const valtype& sig, const CTransaction& tx, const CScript& spk, bool store)
{
    Checker ch(tx, spk, store);
    return ch.c->CheckPQSig(k.scheme, sig, k.pk, spk, VAULT_BRANCH_ID);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_sigcache_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pq_sigcache_hit_miss_store)
{
    // Each case uses its own keys: the cache is process-wide and outlives a test case.
    for (uint8_t scheme : {SLH, FALCON}) {
        const PQKey k = MakeKey(scheme, scheme == SLH ? 0x51 : 0x52);
        const CScript spk = PQPKH(k);
        const CTransaction tx = Tx(1);
        const valtype sig = Sign(k, tx, spk);

        // store=false (block connect) never adds an entry: two misses
        uint64_t h = GetPQSigCacheHits();
        BOOST_CHECK(Check(k, sig, tx, spk, false));
        BOOST_CHECK(Check(k, sig, tx, spk, false));
        BOOST_CHECK_EQUAL(GetPQSigCacheHits(), h);

        // store=true (mempool, TestBlockValidity): a miss that stores, then a hit
        BOOST_CHECK(Check(k, sig, tx, spk, true));
        BOOST_CHECK_EQUAL(GetPQSigCacheHits(), h);
        BOOST_CHECK(Check(k, sig, tx, spk, true));
        BOOST_CHECK_EQUAL(GetPQSigCacheHits(), h + 1);

        // store=false consults the cache and releases the entry, as for ECDSA. 6.20.0's
        // CuckooCache only marks it erasable (contains(e, erase) -> allow_erase), so it still
        // hits until a later insert reuses the slot; v4.5.0's set erases it at once.
        BOOST_CHECK(Check(k, sig, tx, spk, false));
        BOOST_CHECK_EQUAL(GetPQSigCacheHits(), h + 2);
        BOOST_CHECK(Check(k, sig, tx, spk, false));
        BOOST_CHECK_EQUAL(GetPQSigCacheHits(), h + 3);
    }
}

BOOST_AUTO_TEST_CASE(pq_sigcache_binds_message_key_scheme)
{
    for (uint8_t scheme : {SLH, FALCON}) {
        const PQKey k = MakeKey(scheme, scheme == SLH ? 0x61 : 0x62);
        const PQKey other = MakeKey(scheme, 0x6f);
        const CScript spk = PQPKH(k);
        const CTransaction txA = Tx(1), txB = Tx(2);
        const valtype sig = Sign(k, txA, spk);

        // (pk, sig, msgA) cached and hit
        BOOST_CHECK(Check(k, sig, txA, spk, true));
        const uint64_t h = GetPQSigCacheHits();
        BOOST_CHECK(Check(k, sig, txA, spk, true));
        BOOST_CHECK_EQUAL(GetPQSigCacheHits(), h + 1);

        // the same key and signature over another message (another output, another hashtype
        // byte) does not validate and does not hit, with either store flag
        for (bool store : {true, false}) {
            BOOST_CHECK(!Check(k, sig, txB, spk, store));
            valtype ht = sig;
            ht.back() = SIGHASH_ALL | SIGHASH_ANYONECANPAY;
            BOOST_CHECK(!Check(k, ht, txA, spk, store));
        }
        BOOST_CHECK_EQUAL(GetPQSigCacheHits(), h + 1);

        // the memoized function directly: msgB, another key, another scheme byte, a flipped
        // signature byte all miss and fail
        Checker ch(txA, spk, true);
        const uint256 msgA = Sighash(txA, spk, SIGHASH_ALL), msgB = Sighash(txB, spk, SIGHASH_ALL);
        BOOST_CHECK(ch.c->VerifyPQSignature(scheme, Strip(sig), k.pk, msgA));
        BOOST_CHECK_EQUAL(GetPQSigCacheHits(), h + 2);
        BOOST_CHECK(!ch.c->VerifyPQSignature(scheme, Strip(sig), k.pk, msgB));
        BOOST_CHECK(!ch.c->VerifyPQSignature(scheme, Strip(sig), other.pk, msgA));
        BOOST_CHECK(!ch.c->VerifyPQSignature(scheme == SLH ? FALCON : SLH, Strip(sig), k.pk, msgA));
        BOOST_CHECK(!ch.c->VerifyPQSignature(0x00, Strip(sig), k.pk, msgA));
        valtype flipped = Strip(sig);
        flipped[17] ^= 0x01;
        BOOST_CHECK(!ch.c->VerifyPQSignature(scheme, flipped, k.pk, msgA));
        BOOST_CHECK_EQUAL(GetPQSigCacheHits(), h + 2);
    }
}

BOOST_AUTO_TEST_CASE(pq_sigcache_failures_never_stored)
{
    for (uint8_t scheme : {SLH, FALCON}) {
        const PQKey k = MakeKey(scheme, scheme == SLH ? 0x71 : 0x72);
        const CScript spk = PQPKH(k);
        const CTransaction tx = Tx(1);
        const valtype sig = Sign(k, tx, spk);
        valtype bad = sig;
        bad[40] ^= 0x80;
        const valtype empty;

        const uint64_t h = GetPQSigCacheHits();
        for (int i = 0; i < 3; i++) {
            BOOST_CHECK(!Check(k, bad, tx, spk, true));
            BOOST_CHECK(!Check(k, empty, tx, spk, true));
            // a signature over another transaction, offered for this one
            BOOST_CHECK(!Check(k, Sign(k, Tx(9), spk), tx, spk, true));
        }
        BOOST_CHECK_EQUAL(GetPQSigCacheHits(), h);
        // and the good signature is still a first-time miss
        BOOST_CHECK(Check(k, sig, tx, spk, true));
        BOOST_CHECK_EQUAL(GetPQSigCacheHits(), h);
    }
}

BOOST_AUTO_TEST_CASE(pq_sigcache_ecdsa_separation)
{
    // ECDSA and PQ entries live in one set under two independent nonces. Cache an ECDSA success on
    // (H, P, S), then ask the PQ path about the very same bytes under every scheme byte: never a hit
    // (an equal key space would answer "valid" without verifying), and the reverse.
    const CKey key = CKey::TestOnlyRandomKey(true);
    const CPubKey pub = key.GetPubKey();
    const uint256 H = uint256S("5e1f00d5c0ffee000000000000000000000000000000000000000000000000ab");
    valtype S;
    BOOST_REQUIRE(key.Sign(H, S));
    const valtype P(pub.begin(), pub.end());

    const CTransaction tx = Tx(1);
    const CScript spk = CScript() << OP_TRUE;
    Checker ch(tx, spk, true);
    BOOST_CHECK(ch.c->VerifySignature(S, pub, H));     // miss, stored
    BOOST_CHECK(ch.c->VerifySignature(S, pub, H));     // (an ECDSA hit)
    const uint64_t h = GetPQSigCacheHits();
    for (int scheme = 0; scheme < 256; scheme++)
        BOOST_CHECK(!ch.c->VerifyPQSignature((uint8_t)scheme, S, P, H));
    BOOST_CHECK_EQUAL(GetPQSigCacheHits(), h);

    // and a PQ success stores and hits in its own key space beside the ECDSA entry
    const PQKey k = MakeKey(SLH, 0x81);
    const CScript pspk = PQPKH(k);
    const valtype sig = Sign(k, tx, pspk);
    const uint256 msg = Sighash(tx, pspk, SIGHASH_ALL);
    BOOST_CHECK(ch.c->VerifyPQSignature(SLH, Strip(sig), k.pk, msg));
    BOOST_CHECK(ch.c->VerifyPQSignature(SLH, Strip(sig), k.pk, msg));
    BOOST_CHECK_EQUAL(GetPQSigCacheHits(), h + 1);
    BOOST_CHECK(ch.c->VerifySignature(S, pub, H));     // the ECDSA entry is still there
}

BOOST_AUTO_TEST_CASE(pq_sigcache_interpreter_path)
{
    // End to end through VerifyScript and vault::SetSigChecker (derived from the caching
    // checker), the checker blocks and the mempool use under UPGRADE_VAULT: the verdicts with a
    // warm cache equal the cold ones.
    for (uint8_t scheme : {SLH, FALCON}) {
        const PQKey k = MakeKey(scheme, scheme == SLH ? 0x91 : 0x92);
        const CScript spk = PQPKH(k);
        const CTransaction tx = Tx(1), txB = Tx(2);
        const valtype sig = Sign(k, tx, spk);
        valtype bad = sig;
        bad[3] ^= 0x04;

        auto chunks = [](const valtype& d) {
            CScript s;
            size_t n = 0;
            for (size_t i = 0; i < d.size(); i += pq::MAX_CHUNK, n++)
                s << valtype(d.begin() + i, d.begin() + std::min(d.size(), i + pq::MAX_CHUNK));
            s << (int64_t)n;
            return s;
        };
        auto scriptSig = [&](const valtype& s) {
            CScript a = chunks(s), b = chunks(k.pk);
            a.insert(a.end(), b.begin(), b.end());
            return a;
        };
        auto run = [&](const CScript& ss, const CTransaction& t, bool store, unsigned int flags = FLAGS) {
            auto txdata = TxData(t, spk);
            vault::SetSigChecker checker(&t, 0, AMOUNT, store, *txdata, nullptr, 1);
            ScriptError err;
            VerifyScript(ss, spk, flags, checker, VAULT_BRANCH_ID, &err);
            return err;
        };

        const uint64_t h = GetPQSigCacheHits();
        for (int i = 0; i < 2; i++) {
            BOOST_CHECK_EQUAL(run(scriptSig(sig), tx, true), SCRIPT_ERR_OK);
            BOOST_CHECK_EQUAL(run(scriptSig(bad), tx, true), SCRIPT_ERR_EVAL_FALSE);
            BOOST_CHECK_EQUAL(run(scriptSig(sig), txB, true), SCRIPT_ERR_EVAL_FALSE);
        }
        BOOST_CHECK_EQUAL(GetPQSigCacheHits(), h + 1);     // the second good run only
        // a warm entry never lifts a gate the interpreter applies before CheckPQSig: Falcon
        // without SCRIPT_VERIFY_PQ_FALCON (a reorg below pqFalconHeight) and OP_CHECKPQSIG
        // without SCRIPT_VERIFY_VAULT keep their errors, and do not consult the cache
        BOOST_CHECK_EQUAL(run(scriptSig(sig), tx, true, FLAGS & ~SCRIPT_VERIFY_PQ_FALCON),
                          scheme == SLH ? SCRIPT_ERR_OK : SCRIPT_ERR_PQ_SCHEME);
        BOOST_CHECK_EQUAL(run(scriptSig(sig), tx, true, FLAGS & ~(SCRIPT_VERIFY_PQ_FALCON | SCRIPT_VERIFY_VAULT)),
                          SCRIPT_ERR_BAD_OPCODE);
        BOOST_CHECK_EQUAL(GetPQSigCacheHits(), h + (scheme == SLH ? 2 : 1));
        const uint64_t h2 = GetPQSigCacheHits();
        BOOST_CHECK_EQUAL(run(scriptSig(sig), tx, false), SCRIPT_ERR_OK);   // hit, marked erasable
        BOOST_CHECK_EQUAL(run(scriptSig(sig), tx, false), SCRIPT_ERR_OK);   // still a hit (CuckooCache)
        BOOST_CHECK_EQUAL(GetPQSigCacheHits(), h2 + 2);
    }
}

BOOST_AUTO_TEST_CASE(pq_sigcache_disabled)
{
    // 6.20.0 refuses -maxsigcachesize=0 at startup (init.cpp: "must be at least 1"), so the
    // disabled cache is the store=false caller: the verdicts are those of the plain checker.
    for (uint8_t scheme : {SLH, FALCON}) {
        const PQKey k = MakeKey(scheme, scheme == SLH ? 0xa1 : 0xa2);
        const CScript spk = PQPKH(k);
        const CTransaction tx = Tx(1), txB = Tx(2);
        const valtype sig = Sign(k, tx, spk);
        valtype bad = sig;
        bad[5] ^= 0x10;
        const uint64_t h = GetPQSigCacheHits();
        for (int i = 0; i < 3; i++) {
            auto txdata = TxData(tx, spk);
            TransactionSignatureChecker plain(&tx, *txdata, 0, AMOUNT);
            BOOST_CHECK_EQUAL(Check(k, sig, tx, spk, false), plain.CheckPQSig(scheme, sig, k.pk, spk, VAULT_BRANCH_ID));
            BOOST_CHECK_EQUAL(Check(k, bad, tx, spk, false), plain.CheckPQSig(scheme, bad, k.pk, spk, VAULT_BRANCH_ID));
            BOOST_CHECK(Check(k, sig, tx, spk, false));
            BOOST_CHECK(!Check(k, bad, tx, spk, false));
            BOOST_CHECK(!Check(k, sig, txB, spk, false));
        }
        BOOST_CHECK_EQUAL(GetPQSigCacheHits(), h);
    }
}

BOOST_AUTO_TEST_SUITE_END()
