// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The post-quantum signature library (src/crypto/pq/, docs/plans/yellowback-quantum-plan.md
// §4.1, §4.7): sizes, key hash, sign/verify round trips, rejects, conformance against NIST ACVP
// (SLH-DSA-SHA2-128s) and the Falcon-512 KATs (NIST round 3, PQClean falcon-padded-512), the
// golden vectors src/test/data/pq_vectors.json (recomputed in full), and timings.
//
// Regenerate the golden vectors (only when their definition changes; every other node line and
// client must then follow byte for byte):
//   PQ_VECTORS_WRITE=src/test/data/pq_vectors.json src/test/test_bitcoin --run_test=pq_crypto_tests/pq_golden_vectors

#include "crypto/aes.h"
#include "crypto/pq/falcon/ycash_falcon.h"
#include "crypto/pq/scheme.h"
#include "crypto/pq/sign.h"
#include "crypto/pq/slhdsa/slh_dsa.h"
#include "crypto/sha256.h"
#include "crypto/sha512.h"
#include "key.h"
#include "pubkey.h"
#include "script/script.h"
#include "test/data/pq_acvp_slhdsa.json.h"
#include "test/data/pq_falcon_kat.json.h"
#include "test/data/pq_vectors.json.h"
#include "test/test_bitcoin.h"
#include "univalue.h"
#include "util/strencodings.h"
#include "util/time.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

typedef std::vector<unsigned char> Bytes;

UniValue ReadJson(const unsigned char* begin, size_t size)
{
    UniValue doc;
    BOOST_REQUIRE(doc.read(std::string(begin, begin + size)));
    return doc;
}

Bytes Hex(const UniValue& v) { return ParseHex(v.get_str()); }

uint256 Msg(const Bytes& b)
{
    BOOST_REQUIRE_EQUAL(b.size(), 32U);
    uint256 m;
    std::copy(b.begin(), b.end(), m.begin());
    return m;
}

std::string HexOf(const uint256& h) { return HexStr(h.begin(), h.end()); }

// Expand(label, n): the first n bytes of SHA512(label || 0x00) || SHA512(label || 0x01) || ...
// Only the generator uses it; consumers read the hex in the file.
Bytes Expand(const std::string& label, size_t n)
{
    Bytes out;
    for (unsigned char ctr = 0; out.size() < n; ++ctr) {
        unsigned char h[CSHA512::OUTPUT_SIZE];
        CSHA512().Write((const unsigned char*)label.data(), label.size()).Write(&ctr, 1).Finalize(h);
        out.insert(out.end(), h, h + sizeof(h));
    }
    out.resize(n);
    return out;
}

// The NIST PQC KAT generator's AES-256 CTR DRBG (rng.c of the NIST submission package), so the
// Falcon KATs can be replayed from their 48-byte seeds.
class NistDrbg
{
    unsigned char key[32];
    unsigned char v[16];

    void IncV()
    {
        for (int j = 15; j >= 0; j--) {
            if (v[j] == 0xff) {
                v[j] = 0x00;
            } else {
                v[j]++;
                break;
            }
        }
    }
    void Update(const unsigned char* provided)
    {
        unsigned char temp[48];
        AES256Encrypt aes(key);
        for (int i = 0; i < 3; i++) {
            IncV();
            aes.Encrypt(temp + 16 * i, v);
        }
        if (provided) {
            for (int i = 0; i < 48; i++) temp[i] ^= provided[i];
        }
        memcpy(key, temp, 32);
        memcpy(v, temp + 32, 16);
    }

public:
    explicit NistDrbg(const Bytes& seed)
    {
        BOOST_REQUIRE_EQUAL(seed.size(), 48U);
        memset(key, 0, sizeof(key));
        memset(v, 0, sizeof(v));
        Update(seed.data());
    }
    Bytes Get(size_t n)
    {
        Bytes out;
        while (out.size() < n) {
            unsigned char block[16];
            IncV();
            AES256Encrypt(key).Encrypt(block, v);
            out.insert(out.end(), block, block + std::min<size_t>(16, n - out.size()));
        }
        Update(nullptr);
        return out;
    }
};

// The chunked scriptSig of a PQPKH spend (briefing / plan §4.2): <sig_1>..<sig_s> <s> <pk_1>..<pk_p> <p>,
// the hashtype on the signature only; every chunk but the last exactly 520 bytes; s and p as
// OP_1..OP_16; each push minimal (CScript::operator<<).
CScript ChunkedScriptSig(const Bytes& sigWithHashtype, const Bytes& pk, size_t& s, size_t& p)
{
    CScript out;
    s = 0;
    for (size_t i = 0; i < sigWithHashtype.size(); i += pq::MAX_CHUNK, ++s) {
        out << Bytes(sigWithHashtype.begin() + i, sigWithHashtype.begin() + std::min(sigWithHashtype.size(), i + pq::MAX_CHUNK));
    }
    out << (int64_t)s;
    p = 0;
    for (size_t i = 0; i < pk.size(); i += pq::MAX_CHUNK, ++p) {
        out << Bytes(pk.begin() + i, pk.begin() + std::min(pk.size(), i + pq::MAX_CHUNK));
    }
    out << (int64_t)p;
    return out;
}

// TX_PQPKH (plan §4.3, coordinator 2026-10-10): 0x20 <keyHash:32> OP_1|OP_2 OP_CHECKPQSIG (0xc2),
// 35 bytes; the scheme id is a minimal push so the script runs under SCRIPT_VERIFY_MINIMALDATA.
Bytes PQPKHScript(uint8_t scheme, const Bytes& keyHash)
{
    CScript s;
    s << keyHash << (int64_t)scheme << (opcodetype)0xc2;
    return Bytes(s.begin(), s.end());
}

struct KeyPair {
    Bytes pk, sk;
};

KeyPair Gen(uint8_t scheme, const std::string& label)
{
    KeyPair kp;
    BOOST_REQUIRE(pq::KeyGen(scheme, Expand(label, pq::SeedSize(scheme)), kp.pk, kp.sk));
    return kp;
}

const char* SchemeName(uint8_t scheme)
{
    return scheme == pq::SCHEME_SLH_DSA_SHA2_128S ? "SLH-DSA-SHA2-128s" : "FN-DSA-512 (Falcon-512, PQClean padded)";
}

// The golden vectors, computed from their labels.
UniValue BuildVectors()
{
    UniValue doc(UniValue::VOBJ);
    doc.pushKV("format", "ycash-pq-vectors-1");
    doc.pushKV("comment",
        "Golden vectors of the Ycash post-quantum signature library (src/crypto/pq/README.md has the format). "
        "Every field is lower-case hex of bytes in the order they appear on the wire or in memory; msg is the 32 bytes "
        "of a ZIP-243 sighash in memory order (uint256 begin..end). seed/entropy were derived from label "
        "(SHA512(label||ctr) chain), but consumers take the hex as given. Recomputed by src/test/pq_crypto_tests.cpp.");
    UniValue keys(UniValue::VARR);
    struct Spec {
        uint8_t scheme;
        int count;
    };
    const Spec specs[] = {{pq::SCHEME_SLH_DSA_SHA2_128S, 2}, {pq::SCHEME_FN_DSA_512, 3}};
    for (const Spec& spec : specs) {
        for (int i = 0; i < spec.count; i++) {
            const std::string label = strprintf("ycash-pq-vectors-1 scheme %d key %d", spec.scheme, i);
            const Bytes seed = Expand(label + " seed", pq::SeedSize(spec.scheme));
            KeyPair kp;
            BOOST_REQUIRE(pq::KeyGen(spec.scheme, seed, kp.pk, kp.sk));
            const Bytes msgBytes = Expand(label + " msg", 32);
            const uint256 msg = Msg(msgBytes);
            const Bytes entropy = spec.scheme == pq::SCHEME_FN_DSA_512 ? Expand(label + " entropy", pq::FALCON_SIGN_ENTROPY_SIZE) : Bytes();
            Bytes sig;
            BOOST_REQUIRE(pq::SignWithEntropy(spec.scheme, kp.sk, msg, entropy, sig));
            BOOST_REQUIRE(pq::Verify(spec.scheme, kp.pk, sig, msg));
            UniValue e(UniValue::VOBJ);
            e.pushKV("scheme", (int)spec.scheme);
            e.pushKV("name", SchemeName(spec.scheme));
            e.pushKV("label", label);
            e.pushKV("seed", HexStr(seed));
            e.pushKV("pk", HexStr(kp.pk));
            e.pushKV("keyhash", HexOf(pq::KeyHash(spec.scheme, kp.pk)));
            e.pushKV("msg", HexStr(msgBytes));
            e.pushKV("entropy", HexStr(entropy));
            e.pushKV("sig", HexStr(sig));
            keys.push_back(e);
        }
    }
    doc.pushKV("keys", keys);

    UniValue spends(UniValue::VARR);
    for (size_t k = 0; k < keys.size(); k++) {
        const UniValue& e = keys[k];
        // One spend per scheme: the first key of each.
        if (k > 0 && keys[k - 1]["scheme"].get_int() == e["scheme"].get_int()) continue;
        Bytes sig = Hex(e["sig"]);
        sig.push_back(0x01); // SIGHASH_ALL
        size_t s, p;
        const CScript scriptSig = ChunkedScriptSig(sig, Hex(e["pk"]), s, p);
        UniValue sp(UniValue::VOBJ);
        sp.pushKV("scheme", e["scheme"].get_int());
        sp.pushKV("key", (int)k);
        sp.pushKV("scriptPubKey", HexStr(PQPKHScript((uint8_t)e["scheme"].get_int(), Hex(e["keyhash"]))));
        sp.pushKV("hashtype", 1);
        sp.pushKV("sigChunks", (int)s);
        sp.pushKV("pkChunks", (int)p);
        sp.pushKV("scriptSigSize", (int)scriptSig.size());
        sp.pushKV("scriptSig", HexStr(scriptSig.begin(), scriptSig.end()));
        spends.push_back(sp);
    }
    doc.pushKV("spends", spends);
    return doc;
}

Bytes Flip(Bytes b, size_t byte, int bit = 0)
{
    b[byte] ^= (unsigned char)(1 << bit);
    return b;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_crypto_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pq_sizes_and_registry)
{
    BOOST_CHECK_EQUAL(pq::SCHEME_SLH_DSA_SHA2_128S, 0x01);
    BOOST_CHECK_EQUAL(pq::SCHEME_FN_DSA_512, 0x02);
    BOOST_CHECK_EQUAL(pq::KEYHASH_SIZE, 32U);
    BOOST_CHECK_EQUAL(pq::MAX_CHUNK, 520U);
    BOOST_CHECK_EQUAL(pq::MAX_CHUNK, (size_t)MAX_SCRIPT_ELEMENT_SIZE);
    BOOST_CHECK_EQUAL(pq::SIGOP_COST, 20U);

    BOOST_CHECK_EQUAL(pq::PubKeySize(0x01), 32U);
    BOOST_CHECK_EQUAL(pq::SigSize(0x01), 7856U);
    BOOST_CHECK_EQUAL(pq::PubKeySize(0x02), 897U);
    BOOST_CHECK_EQUAL(pq::SigSize(0x02), 666U);
    BOOST_CHECK_EQUAL(pq::SeedSize(0x01), 48U);
    BOOST_CHECK_EQUAL(pq::SeedSize(0x02), 48U);
    BOOST_CHECK_EQUAL(pq::SecretKeySize(0x01), 64U);
    BOOST_CHECK_EQUAL(pq::SecretKeySize(0x02), 1281U);
    // The library's own idea of the sizes agrees with the registry.
    BOOST_CHECK_EQUAL(slh_pk_sz(&slh_dsa_sha2_128s), 32U);
    BOOST_CHECK_EQUAL(slh_sig_sz(&slh_dsa_sha2_128s), 7856U);
    BOOST_CHECK_EQUAL(slh_sk_sz(&slh_dsa_sha2_128s), 64U);
    BOOST_CHECK_EQUAL(std::string(slh_alg_id(&slh_dsa_sha2_128s)), "SLH-DSA-SHA2-128s");

    for (int s = 0; s < 256; s++) {
        const bool known = s == 1 || s == 2;
        BOOST_CHECK_EQUAL(pq::IsKnownScheme((uint8_t)s), known);
        if (!known) {
            BOOST_CHECK_EQUAL(pq::PubKeySize((uint8_t)s), 0U);
            BOOST_CHECK_EQUAL(pq::SigSize((uint8_t)s), 0U);
            BOOST_CHECK_EQUAL(pq::SeedSize((uint8_t)s), 0U);
            BOOST_CHECK_EQUAL(pq::SecretKeySize((uint8_t)s), 0U);
        }
    }

    // The chunk counts the plan names (plan §4.2 / briefing): SLH-DSA s=16 (15x520 + 57), p=1;
    // Falcon s=2 (520 + 147), p=2 (520 + 377).
    size_t s, p;
    ChunkedScriptSig(Bytes(7857), Bytes(32), s, p);
    BOOST_CHECK_EQUAL(s, 16U);
    BOOST_CHECK_EQUAL(p, 1U);
    BOOST_CHECK_EQUAL(7857 - 15 * 520, 57);
    ChunkedScriptSig(Bytes(667), Bytes(897), s, p);
    BOOST_CHECK_EQUAL(s, 2U);
    BOOST_CHECK_EQUAL(p, 2U);
}

BOOST_AUTO_TEST_CASE(pq_keyhash)
{
    const Bytes pk = ParseHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    for (uint8_t scheme : {(uint8_t)1, (uint8_t)2, (uint8_t)7}) {
        Bytes pre(1, scheme);
        pre.insert(pre.end(), pk.begin(), pk.end());
        uint256 expect;
        CSHA256().Write(pre.data(), pre.size()).Finalize(expect.begin());
        BOOST_CHECK(pq::KeyHash(scheme, pk) == expect);
    }
    // The scheme byte is committed: the same key bytes under another scheme hash differently.
    BOOST_CHECK(pq::KeyHash(1, pk) != pq::KeyHash(2, pk));
    uint256 empty;
    const unsigned char one = 1;
    CSHA256().Write(&one, 1).Finalize(empty.begin());
    BOOST_CHECK(pq::KeyHash(1, Bytes()) == empty);
}

BOOST_AUTO_TEST_CASE(pq_round_trip_and_rejects)
{
    for (uint8_t scheme : {pq::SCHEME_SLH_DSA_SHA2_128S, pq::SCHEME_FN_DSA_512}) {
        BOOST_TEST_MESSAGE(SchemeName(scheme));
        const KeyPair kp = Gen(scheme, strprintf("round trip %d", scheme));
        BOOST_REQUIRE_EQUAL(kp.pk.size(), pq::PubKeySize(scheme));
        BOOST_REQUIRE_EQUAL(kp.sk.size(), pq::SecretKeySize(scheme));
        // KeyGen is deterministic.
        const KeyPair again = Gen(scheme, strprintf("round trip %d", scheme));
        BOOST_CHECK(again.pk == kp.pk);
        BOOST_CHECK(again.sk == kp.sk);
        BOOST_CHECK(Gen(scheme, "another seed").pk != kp.pk);

        const uint256 msg = Msg(Expand("round trip msg", 32));
        Bytes sig;
        BOOST_REQUIRE(pq::Sign(scheme, kp.sk, msg, sig));
        BOOST_REQUIRE_EQUAL(sig.size(), pq::SigSize(scheme));
        BOOST_CHECK(pq::Verify(scheme, kp.pk, sig, msg));

        Bytes sig2;
        BOOST_REQUIRE(pq::Sign(scheme, kp.sk, msg, sig2));
        BOOST_CHECK(pq::Verify(scheme, kp.pk, sig2, msg));
        if (scheme == pq::SCHEME_SLH_DSA_SHA2_128S) {
            // Deterministic (opt_rand = PK.seed); the hedged variant differs and verifies.
            BOOST_CHECK(sig2 == sig);
            Bytes hedged;
            BOOST_REQUIRE(pq::SignWithEntropy(scheme, kp.sk, msg, Expand("opt_rand", 16), hedged));
            BOOST_CHECK(hedged != sig);
            BOOST_CHECK(pq::Verify(scheme, kp.pk, hedged, msg));
            BOOST_CHECK(!pq::SignWithEntropy(scheme, kp.sk, msg, Bytes(15), hedged));
        } else {
            // Randomized: a fresh nonce each time.
            BOOST_CHECK(sig2 != sig);
            BOOST_CHECK(!pq::SignWithEntropy(scheme, kp.sk, msg, Bytes(87), sig2));
            BOOST_CHECK(!pq::SignWithEntropy(scheme, kp.sk, msg, Bytes(), sig2));
        }

        // Wrong message.
        BOOST_CHECK(!pq::Verify(scheme, kp.pk, sig, Msg(Expand("other msg", 32))));
        for (size_t byte : {(size_t)0, (size_t)17, (size_t)31}) {
            uint256 m = msg;
            *(m.begin() + byte) ^= 0x01;
            BOOST_CHECK(!pq::Verify(scheme, kp.pk, sig, m));
        }
        // Wrong key.
        BOOST_CHECK(!pq::Verify(scheme, Gen(scheme, "wrong key").pk, sig, msg));
        // The other scheme's id with these bytes.
        const uint8_t other = scheme == 1 ? 2 : 1;
        BOOST_CHECK(!pq::Verify(other, kp.pk, sig, msg));
        // Unknown schemes.
        for (int u : {0, 3, 0x51, 0xff}) {
            BOOST_CHECK(!pq::Verify((uint8_t)u, kp.pk, sig, msg));
            Bytes pk, sk, out;
            BOOST_CHECK(!pq::KeyGen((uint8_t)u, Bytes(48), pk, sk));
            BOOST_CHECK(!pq::Sign((uint8_t)u, kp.sk, msg, out));
        }

        // Lengths: every length but the registry's fails, both for pk and sig.
        for (long d : {-1L, 1L, -(long)sig.size(), 32L}) {
            Bytes s = sig;
            if (d < 0) s.resize(s.size() + d); else s.insert(s.end(), (size_t)d, 0);
            BOOST_CHECK(!pq::Verify(scheme, kp.pk, s, msg));
        }
        {
            // The hashtype byte belongs to the caller: a signature with it appended fails.
            Bytes s = sig;
            s.push_back(0x01);
            BOOST_CHECK(!pq::Verify(scheme, kp.pk, s, msg));
        }
        for (long d : {-1L, 1L, -(long)kp.pk.size()}) {
            Bytes k = kp.pk;
            if (d < 0) k.resize(k.size() + d); else k.insert(k.end(), (size_t)d, 0);
            BOOST_CHECK(!pq::Verify(scheme, k, sig, msg));
        }

        // Flipped bits in the signature: the first byte, a sweep through it, the last byte.
        std::vector<size_t> positions = {0, 1, sig.size() / 2, sig.size() - 1};
        for (size_t i = 0; i < sig.size(); i += sig.size() / 40) positions.push_back(i);
        for (size_t pos : positions) {
            for (int bit : {0, 7}) {
                BOOST_CHECK_MESSAGE(!pq::Verify(scheme, kp.pk, Flip(sig, pos, bit), msg),
                                    strprintf("sig flip at %u bit %d", pos, bit));
            }
        }
        // Flipped bits in the public key.
        for (size_t pos : {(size_t)0, (size_t)1, kp.pk.size() / 2, kp.pk.size() - 1}) {
            BOOST_CHECK(!pq::Verify(scheme, Flip(kp.pk, pos), sig, msg));
        }

        // Sign rejects a secret key of the wrong length; KeyGen a seed of the wrong length.
        Bytes out;
        BOOST_CHECK(!pq::Sign(scheme, Bytes(kp.sk.begin(), kp.sk.end() - 1), msg, out));
        Bytes pk, sk;
        BOOST_CHECK(!pq::KeyGen(scheme, Bytes(pq::SeedSize(scheme) - 1), pk, sk));
        BOOST_CHECK(!pq::KeyGen(scheme, Bytes(pq::SeedSize(scheme) + 1), pk, sk));
        BOOST_CHECK(!pq::KeyGen(scheme, Bytes(), pk, sk));
    }
}

BOOST_AUTO_TEST_CASE(pq_falcon_padding_is_canonical)
{
    // A padded Falcon signature is 0x39 || nonce(40) || compressed s || zeros. Any non-zero
    // padding byte, a wrong header, or a compressed s that does not fill to the padding (the
    // unpadded "compact" form PQClean's verifier also accepts at its own length) is rejected
    // at the registry's exact length, so one (pk, sig) has one encoding.
    const KeyPair kp = Gen(pq::SCHEME_FN_DSA_512, "padding");
    const uint256 msg = Msg(Expand("padding msg", 32));
    Bytes sig;
    BOOST_REQUIRE(pq::SignWithEntropy(pq::SCHEME_FN_DSA_512, kp.sk, msg, Expand("padding entropy", 88), sig));
    BOOST_REQUIRE(pq::Verify(pq::SCHEME_FN_DSA_512, kp.pk, sig, msg));
    BOOST_CHECK_EQUAL(sig[0], 0x39);
    size_t end = sig.size();
    while (end > 0 && sig[end - 1] == 0) end--;
    BOOST_REQUIRE(end < sig.size()); // this signature has padding
    for (size_t i = end; i < sig.size(); i++) {
        BOOST_CHECK(!pq::Verify(pq::SCHEME_FN_DSA_512, kp.pk, Flip(sig, i), msg));
    }
    for (unsigned char h : {0x29, 0x3a, 0x00, 0xb9}) {
        Bytes s = sig;
        s[0] = h;
        BOOST_CHECK(!pq::Verify(pq::SCHEME_FN_DSA_512, kp.pk, s, msg));
    }
    // The compact (unpadded) form verifies in the raw library at its own length, never through
    // the registry.
    const Bytes compact(sig.begin(), sig.begin() + end);
    BOOST_CHECK_EQUAL(ycash_falcon512_verify(compact.data(), compact.size(), msg.begin(), 32, kp.pk.data()), 0);
    BOOST_CHECK(!pq::Verify(pq::SCHEME_FN_DSA_512, kp.pk, compact, msg));
    // Public key header byte must be 0x09.
    BOOST_CHECK_EQUAL(kp.pk[0], 0x09);
}

BOOST_AUTO_TEST_CASE(pq_slhdsa_acvp)
{
    const UniValue doc = ReadJson(json_tests::pq_acvp_slhdsa, sizeof(json_tests::pq_acvp_slhdsa));
    int n = 0;

    // keyGen through the wallet API: seed = SK.seed || SK.prf || PK.seed.
    for (const UniValue& tc : doc["keyGen"].getValues()) {
        Bytes seed = Hex(tc["skSeed"]);
        const Bytes prf = Hex(tc["skPrf"]), pkSeed = Hex(tc["pkSeed"]);
        seed.insert(seed.end(), prf.begin(), prf.end());
        seed.insert(seed.end(), pkSeed.begin(), pkSeed.end());
        Bytes pk, sk;
        BOOST_REQUIRE(pq::KeyGen(pq::SCHEME_SLH_DSA_SHA2_128S, seed, pk, sk));
        BOOST_CHECK_MESSAGE(HexStr(pk) == tc["pk"].get_str(), "keyGen pk tcId " << tc["tcId"].get_int());
        BOOST_CHECK_MESSAGE(HexStr(sk) == tc["sk"].get_str(), "keyGen sk tcId " << tc["tcId"].get_int());
        n++;
    }
    BOOST_CHECK_EQUAL(n, 4);

    // sigGen, external interface, pure, with the vector's context (FIPS 205 Algorithm 22).
    // Deterministic cases sign with opt_rand = PK.seed, hedged ones with additionalRandomness.
    n = 0;
    int emptyContext = 0;
    for (const UniValue& tc : doc["sigGen"].getValues()) {
        const Bytes sk = Hex(tc["sk"]), m = Hex(tc["message"]), ctx = Hex(tc["context"]);
        const Bytes rnd = Hex(tc["additionalRandomness"]);
        const uint8_t dummy = 0;
        Bytes sig(slh_sig_sz(&slh_dsa_sha2_128s));
        const size_t len = slh_sign(sig.data(), m.empty() ? &dummy : m.data(), m.size(), ctx.empty() ? &dummy : ctx.data(), ctx.size(),
                                    sk.data(), tc["deterministic"].get_bool() ? nullptr : rnd.data(), &slh_dsa_sha2_128s);
        BOOST_CHECK_EQUAL(len, sig.size());
        BOOST_CHECK_MESSAGE(HexStr(sig) == tc["signature"].get_str(), "sigGen tcId " << tc["tcId"].get_int());
        // And the signature verifies against the vector's public key.
        const Bytes pk = Hex(tc["pk"]);
        BOOST_CHECK_EQUAL(slh_verify(m.empty() ? &dummy : m.data(), m.size(), sig.data(), sig.size(), ctx.empty() ? &dummy : ctx.data(), ctx.size(), pk.data(), &slh_dsa_sha2_128s), 1);
        if (ctx.empty()) emptyContext++;
        n++;
    }
    BOOST_CHECK_EQUAL(n, 5);
    BOOST_CHECK_EQUAL(emptyContext, 2);

    // sigVer, external interface, pure (FIPS 205 Algorithm 24): pass and every fail reason.
    n = 0;
    int passed = 0;
    for (const UniValue& tc : doc["sigVer"].getValues()) {
        const Bytes pk = Hex(tc["pk"]), m = Hex(tc["message"]), ctx = Hex(tc["context"]), sig = Hex(tc["signature"]);
        const uint8_t dummy = 0;
        const int ok = slh_verify(m.empty() ? &dummy : m.data(), m.size(), sig.empty() ? &dummy : sig.data(), sig.size(),
                                  ctx.empty() ? &dummy : ctx.data(), ctx.size(), pk.data(), &slh_dsa_sha2_128s);
        BOOST_CHECK_MESSAGE((ok == 1) == tc["testPassed"].get_bool(),
                            "sigVer tcId " << tc["tcId"].get_int() << " (" << tc["reason"].get_str() << ")");
        if (tc["testPassed"].get_bool()) passed++;
        n++;
    }
    BOOST_CHECK_EQUAL(n, 9);
    BOOST_CHECK_EQUAL(passed, 2);
}

BOOST_AUTO_TEST_CASE(pq_falcon_kat)
{
    const UniValue doc = ReadJson(json_tests::pq_falcon_kat, sizeof(json_tests::pq_falcon_kat));

    // NIST round-3 Falcon-512 KAT: keys reproduce exactly from the DRBG; the signature, drawn
    // with the same nonce and sampler seed, is the round-3 compressed signature in the padded
    // layout (when it fits 625 bytes, which every entry here does).
    int n = 0;
    for (const UniValue& e : doc["r3"].getValues()) {
        NistDrbg drbg(Hex(e["seed"]));
        const Bytes kseed = drbg.Get(48);
        Bytes pk(YCASH_FALCON512_PUBLICKEYBYTES), sk(YCASH_FALCON512_SECRETKEYBYTES);
        BOOST_REQUIRE_EQUAL(ycash_falcon512_keygen_from_seed(pk.data(), sk.data(), kseed.data(), kseed.size()), 0);
        BOOST_CHECK_MESSAGE(HexStr(pk) == e["pk"].get_str(), "r3 pk count " << e["count"].get_int());
        BOOST_CHECK_MESSAGE(HexStr(sk) == e["sk"].get_str(), "r3 sk count " << e["count"].get_int());
        Bytes apiPk, apiSk;
        BOOST_REQUIRE(pq::KeyGen(pq::SCHEME_FN_DSA_512, kseed, apiPk, apiSk));
        BOOST_CHECK(apiPk == pk && apiSk == sk);

        const Bytes msg = Hex(e["msg"]);
        const Bytes nonce = drbg.Get(40);
        const Bytes sseed = drbg.Get(48);
        Bytes sig(YCASH_FALCON512_SIGBYTES);
        BOOST_REQUIRE_EQUAL(ycash_falcon512_sign(sig.data(), msg.data(), msg.size(), sk.data(), nonce.data(), sseed.data()), 0);

        const Bytes sm = Hex(e["sm"]);
        const size_t siglen = ((size_t)sm[0] << 8) | sm[1];
        BOOST_REQUIRE_EQUAL(sm.size(), 2 + 40 + msg.size() + siglen);
        BOOST_CHECK(Bytes(sm.begin() + 2, sm.begin() + 42) == nonce);
        BOOST_CHECK(Bytes(sm.begin() + 42, sm.begin() + 42 + msg.size()) == msg);
        BOOST_CHECK_EQUAL(sm[42 + msg.size()], 0x29);
        const Bytes comp(sm.begin() + 43 + msg.size(), sm.end());
        BOOST_REQUIRE(comp.size() <= YCASH_FALCON512_SIGBYTES - 41);
        Bytes padded(1, 0x39);
        padded.insert(padded.end(), nonce.begin(), nonce.end());
        padded.insert(padded.end(), comp.begin(), comp.end());
        padded.resize(YCASH_FALCON512_SIGBYTES, 0);
        BOOST_CHECK_MESSAGE(sig == padded, "r3 signature count " << e["count"].get_int());
        BOOST_CHECK_EQUAL(ycash_falcon512_verify(sig.data(), sig.size(), msg.data(), msg.size(), pk.data()), 0);
        n++;
    }
    BOOST_CHECK_EQUAL(n, 5);

    // PQClean falcon-padded-512 KAT (count 0): sm = signature(666) || msg.
    n = 0;
    for (const UniValue& e : doc["padded"].getValues()) {
        NistDrbg drbg(Hex(e["seed"]));
        const Bytes kseed = drbg.Get(48);
        Bytes pk(YCASH_FALCON512_PUBLICKEYBYTES), sk(YCASH_FALCON512_SECRETKEYBYTES);
        BOOST_REQUIRE_EQUAL(ycash_falcon512_keygen_from_seed(pk.data(), sk.data(), kseed.data(), kseed.size()), 0);
        BOOST_CHECK(HexStr(pk) == e["pk"].get_str());
        BOOST_CHECK(HexStr(sk) == e["sk"].get_str());
        const Bytes msg = Hex(e["msg"]);
        const Bytes nonce = drbg.Get(40), sseed = drbg.Get(48);
        Bytes sig(YCASH_FALCON512_SIGBYTES);
        BOOST_REQUIRE_EQUAL(ycash_falcon512_sign(sig.data(), msg.data(), msg.size(), sk.data(), nonce.data(), sseed.data()), 0);
        Bytes sm = sig;
        sm.insert(sm.end(), msg.begin(), msg.end());
        BOOST_CHECK(HexStr(sm) == e["sm"].get_str());
        BOOST_CHECK_EQUAL(ycash_falcon512_verify(sig.data(), sig.size(), msg.data(), msg.size(), pk.data()), 0);
        n++;
    }
    BOOST_CHECK_EQUAL(n, 1);
}

BOOST_AUTO_TEST_CASE(pq_golden_vectors)
{
    const UniValue built = BuildVectors();
    const std::string text = built.write(1) + "\n";
    if (const char* path = std::getenv("PQ_VECTORS_WRITE")) {
        std::ofstream(path, std::ios::binary) << text;
        BOOST_TEST_MESSAGE("wrote " << path);
    }
    const std::string file(json_tests::pq_vectors, json_tests::pq_vectors + sizeof(json_tests::pq_vectors));
    // Byte for byte: every key, signature and scriptSig recomputed from the seeds, messages and
    // entropy, and the serialization identical.
    BOOST_CHECK_MESSAGE(file == text, "src/test/data/pq_vectors.json differs from the recomputed vectors");

    // And independently of the generator: every entry verifies and hashes as recorded, and every
    // spend's scriptSig is the chunked encoding of its key's signature (hashtype appended) and pk.
    const UniValue doc = ReadJson(json_tests::pq_vectors, sizeof(json_tests::pq_vectors));
    const std::vector<UniValue>& keys = doc["keys"].getValues();
    int perScheme[3] = {0, 0, 0};
    for (const UniValue& e : keys) {
        const uint8_t scheme = (uint8_t)e["scheme"].get_int();
        BOOST_REQUIRE(pq::IsKnownScheme(scheme));
        perScheme[scheme]++;
        Bytes pk, sk;
        BOOST_REQUIRE(pq::KeyGen(scheme, Hex(e["seed"]), pk, sk));
        BOOST_CHECK(HexStr(pk) == e["pk"].get_str());
        BOOST_CHECK(HexOf(pq::KeyHash(scheme, pk)) == e["keyhash"].get_str());
        const uint256 msg = Msg(Hex(e["msg"]));
        const Bytes sig = Hex(e["sig"]);
        BOOST_CHECK_EQUAL(sig.size(), pq::SigSize(scheme));
        BOOST_CHECK(pq::Verify(scheme, pk, sig, msg));
        Bytes resig;
        BOOST_REQUIRE(pq::SignWithEntropy(scheme, sk, msg, Hex(e["entropy"]), resig));
        BOOST_CHECK(resig == sig);
    }
    BOOST_CHECK(perScheme[1] >= 2);
    BOOST_CHECK(perScheme[2] >= 2);
    int spends = 0;
    for (const UniValue& sp : doc["spends"].getValues()) {
        const UniValue& e = keys.at(sp["key"].get_int());
        BOOST_CHECK_EQUAL(sp["scheme"].get_int(), e["scheme"].get_int());
        Bytes sig = Hex(e["sig"]);
        sig.push_back((unsigned char)sp["hashtype"].get_int());
        size_t s, p;
        const CScript scriptSig = ChunkedScriptSig(sig, Hex(e["pk"]), s, p);
        BOOST_CHECK(HexStr(scriptSig.begin(), scriptSig.end()) == sp["scriptSig"].get_str());
        BOOST_CHECK_EQUAL((int)s, sp["sigChunks"].get_int());
        BOOST_CHECK_EQUAL((int)p, sp["pkChunks"].get_int());
        BOOST_CHECK_EQUAL((int)scriptSig.size(), sp["scriptSigSize"].get_int());
        BOOST_CHECK(scriptSig.IsPushOnly());
        const Bytes spk = PQPKHScript((uint8_t)sp["scheme"].get_int(), Hex(e["keyhash"]));
        BOOST_CHECK(HexStr(spk) == sp["scriptPubKey"].get_str());
        BOOST_CHECK_EQUAL(spk.size(), 35U);
        BOOST_CHECK_EQUAL(spk[0], 0x20);
        BOOST_CHECK_EQUAL(spk[33], sp["scheme"].get_int() == 1 ? 0x51 : 0x52);
        BOOST_CHECK_EQUAL(spk[34], 0xc2);
        // Parse the scriptSig back: chunks of exactly 520 bytes but the last, counts as OP_n.
        CScript::const_iterator pc = scriptSig.begin();
        opcodetype op;
        Bytes data, sigOut, pkOut;
        std::vector<Bytes> elems;
        std::vector<int> counts;
        while (scriptSig.GetOp(pc, op, data)) {
            elems.push_back(data); // OP_n counts arrive as empty data; their positions are checked below
            if (op >= OP_1 && op <= OP_16) counts.push_back((int)(op - OP_1 + 1));
        }
        BOOST_REQUIRE_EQUAL(elems.size(), s + 1 + p + 1);
        BOOST_REQUIRE_EQUAL(counts.size(), 2U);
        BOOST_CHECK_EQUAL(counts[0], (int)s);
        BOOST_CHECK_EQUAL(counts[1], (int)p);
        for (size_t i = 0; i < s; i++) {
            BOOST_CHECK(i + 1 == s || elems[i].size() == pq::MAX_CHUNK);
            sigOut.insert(sigOut.end(), elems[i].begin(), elems[i].end());
        }
        for (size_t i = 0; i < p; i++) {
            const Bytes& c = elems[s + 1 + i];
            BOOST_CHECK(i + 1 == p || c.size() == pq::MAX_CHUNK);
            pkOut.insert(pkOut.end(), c.begin(), c.end());
        }
        BOOST_CHECK(sigOut == sig);
        BOOST_CHECK(HexStr(pkOut) == e["pk"].get_str());
        spends++;
    }
    BOOST_CHECK_EQUAL(spends, 2);
}

BOOST_AUTO_TEST_CASE(pq_timings)
{
    // Not a gate: prints per-operation timings (run with --log_level=message). Each figure is
    // the mean over its iteration count, wall clock, single thread.
    struct Row {
        std::string what;
        int iters;
        int64_t micros;
    };
    std::vector<Row> rows;
    auto time = [&](const std::string& what, int iters, const std::function<void()>& f) {
        const int64_t start = GetTimeMicros();
        for (int i = 0; i < iters; i++) f();
        rows.push_back({what, iters, GetTimeMicros() - start});
    };
    const uint256 msg = Msg(Expand("timings", 32));

    for (uint8_t scheme : {pq::SCHEME_SLH_DSA_SHA2_128S, pq::SCHEME_FN_DSA_512}) {
        const bool slh = scheme == pq::SCHEME_SLH_DSA_SHA2_128S;
        const std::string name = slh ? "SLH-DSA-SHA2-128s" : "Falcon-512 (padded)";
        KeyPair kp;
        time(name + " keygen", slh ? 3 : 20, [&] { kp = Gen(scheme, "timings key"); });
        Bytes sig;
        time(name + " sign", slh ? 3 : 200, [&] { BOOST_REQUIRE(pq::Sign(scheme, kp.sk, msg, sig)); });
        bool ok = true;
        time(name + " verify", slh ? 200 : 2000, [&] { ok &= pq::Verify(scheme, kp.pk, sig, msg); });
        BOOST_CHECK(ok);
    }
    {
        const CKey key = CKey::TestOnlyRandomKey(true);
        const CPubKey pub = key.GetPubKey();
        std::vector<unsigned char> sig;
        time("ECDSA secp256k1 sign", 2000, [&] { BOOST_REQUIRE(key.Sign(msg, sig)); });
        bool ok = true;
        time("ECDSA secp256k1 verify", 2000, [&] { ok &= pub.Verify(msg, sig); });
        BOOST_CHECK(ok);
    }
    for (const Row& r : rows) {
        BOOST_TEST_MESSAGE(strprintf("pq_timings: %-28s %8.1f us/op (%d iterations)", r.what, (double)r.micros / r.iters, r.iters));
    }
}

BOOST_AUTO_TEST_SUITE_END()
