// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The node wallet's post-quantum keys (docs/plans/yellowback-quantum-plan.md §4.5-§4.6, Q5;
// docs/plans/yellowback-quantum-spec.md §1.5, §2.1, §2.4, ruling A-12): HKDF-SHA256 seed
// derivation, CPQKey, the keystores (plain and encrypted), the walletdb records, GetNewPQKey,
// TX_PQPKH signing through ProduceSignature, size estimation, and the vault owner signer.

#include "chainparams.h"
#include "consensus/upgrades.h"
#include "crypto/pq/scheme.h"
#include "crypto/pq/sign.h"
#include "keystore.h"
#include "main.h"
#include "policy/policy.h"
#include "pqkey.h"
#include "script/interpreter.h"
#include "script/ismine.h"
#include "script/sign.h"
#include "script/standard.h"
#include "test/test_bitcoin.h"
#include "util/strencodings.h"
#include "vault/template.h"
#include "wallet/crypter.h"
#include "wallet/db.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "zcash/address/mnemonic.h"
#include "zcash/address/zip32.h"

#include <boost/test/unit_test.hpp>

typedef std::vector<unsigned char> valtype;

namespace {

/** The test HD seed: bytes 0x00..0x1f. */
RawHDSeed TestRawSeed()
{
    RawHDSeed s;
    for (int i = 0; i < 32; i++) s.push_back((unsigned char)i);
    return s;
}

CPQKey::Secret Sec(const std::string& hex)
{
    const valtype b = ParseHex(hex);
    return CPQKey::Secret(b.begin(), b.end());
}

std::string Hex(const CPQKey::Secret& s) { return HexStr(s.begin(), s.end()); }

// Independent vectors: the workspace Python (hmac/hashlib HKDF + test_framework/pq.py slh_keygen).
const char* SEED_1_0 = "335a7ef8fa0ab4fc9faeff290ce40ea4fce101b983c70cc23ac4893354fbda10d5fcce4ade352f727cfa37db588a9e1f";
const char* SEED_1_1 = "b4e9e97fedc3632dec77709ed522bab4fbc8d65f6ebf6359418d4d2f854b02c7d01ca11d6fdc81b91cddd1ada728fccf";
const char* SEED_2_0 = "16f91ba800e9d23d547e5e45f588464fa5102f3caa75fcb0dd3fd8cad5aa608f8368b05457b73d98aff51f5725c998b3";
const char* PK_1_0 = "d5fcce4ade352f727cfa37db588a9e1f3803cb0b132b60db35f26e8343f0500a";
const char* KEYHASH_1_0 = "73efa99cd22fe553222b1db6a6a021b3cba29dafd4fb4dfb50be69abcfcf9364";

CPQKey DerivedFrom(const RawHDSeed& raw, uint8_t scheme, uint32_t index)
{
    CPQKey k;
    BOOST_REQUIRE(k.Set(scheme, DerivePQSeed(raw.data(), raw.size(), scheme, index), index));
    return k;
}

/** 6.20.0: the wallet's seed is a BIP39 MnemonicSeed; the test wallet's is the one with entropy 0x00..0x1f,
 *  and its IKM is that mnemonic's 64-byte raw seed (quantum spec, Q5 as implemented). */
MnemonicSeed TestMnemonicSeed()
{
    std::optional<MnemonicSeed> m = MnemonicSeed::FromEntropy(TestRawSeed(), Params().BIP44CoinType());
    BOOST_REQUIRE(m.has_value());
    return m.value();
}

CPQKey WalletDerived(uint8_t scheme, uint32_t index)
{
    return DerivedFrom(TestMnemonicSeed().RawSeed(), scheme, index);
}

CPQKey Derived(uint8_t scheme, uint32_t index)
{
    const RawHDSeed raw = TestRawSeed();
    CPQKey k;
    BOOST_REQUIRE(k.Set(scheme, DerivePQSeed(raw.data(), raw.size(), scheme, index), index));
    return k;
}

/** A crypto keystore whose encryption entry points the tests can call. */
class TestCryptoKeyStore : public CCryptoKeyStore
{
public:
    bool EncryptKeys(CKeyingMaterial& k) { return CCryptoKeyStore::EncryptKeys(k); }
    bool Unlock(const CKeyingMaterial& k) { return CCryptoKeyStore::Unlock(k); }
};

CKeyingMaterial MasterKey(unsigned char b) { return CKeyingMaterial(32, b); }

CMutableTransaction SpendTx(const CScript& to, CAmount value)
{
    CMutableTransaction mtx;
    mtx.fOverwintered = true;
    mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    mtx.nVersion = SAPLING_TX_VERSION;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0x77"), 0), CScript(), CTxIn::SEQUENCE_FINAL));
    mtx.vout.push_back(CTxOut(value, to));
    return mtx;
}

/** 6.20.0: precomputed data for a one-input v4 spend of `spk` (signers and checkers take it on this line). */
PrecomputedTransactionData TxData6(const CMutableTransaction& mtx, CAmount amount, const CScript& spk)
{
    return PrecomputedTransactionData(CTransaction(mtx), std::vector<CTxOut>(mtx.vin.size(), CTxOut(amount, spk)));
}

const unsigned int VAULT_FLAGS = STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_VAULT;

uint32_t VaultBranch() { return NetworkUpgradeInfo[Consensus::UPGRADE_VAULT].nBranchId; }

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_wallet_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(hkdf_rfc5869)
{
    // RFC 5869 A.1 (salt and info) and A.3 (empty salt and info), SHA-256.
    const valtype ikm(22, 0x0b);
    valtype salt, info, out(42);
    for (int i = 0; i <= 0x0c; i++) salt.push_back((unsigned char)i);
    for (int i = 0xf0; i <= 0xf9; i++) info.push_back((unsigned char)i);
    HKDF_SHA256(salt.data(), salt.size(), ikm.data(), ikm.size(), info.data(), info.size(), out.data(), out.size());
    BOOST_CHECK_EQUAL(HexStr(out), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    HKDF_SHA256(nullptr, 0, ikm.data(), ikm.size(), nullptr, 0, out.data(), out.size());
    BOOST_CHECK_EQUAL(HexStr(out), "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
}

BOOST_AUTO_TEST_CASE(derivation_vector)
{
    // A-12: HKDF-SHA256(IKM = HD seed, salt = "", info = "Ycash PQ key" || scheme || index_be32, L = 48).
    const RawHDSeed raw = TestRawSeed();
    BOOST_CHECK_EQUAL(Hex(DerivePQSeed(raw.data(), raw.size(), 1, 0)), SEED_1_0);
    BOOST_CHECK_EQUAL(Hex(DerivePQSeed(raw.data(), raw.size(), 1, 1)), SEED_1_1);
    BOOST_CHECK_EQUAL(Hex(DerivePQSeed(raw.data(), raw.size(), 2, 0)), SEED_2_0);
    BOOST_CHECK_EQUAL(DerivePQSeed(raw.data(), raw.size(), 1, 0).size(), 48U);

    const CPQKey k = Derived(pq::SCHEME_SLH_DSA_SHA2_128S, 0);
    BOOST_CHECK_EQUAL(HexStr(k.PubKey()), PK_1_0);
    BOOST_CHECK(k.GetID() == CPQKeyID(1, uint256(ParseHex(KEYHASH_1_0))));
    BOOST_CHECK_EQUAL(k.SecretKey().size(), pq::SecretKeySize(1));
    BOOST_CHECK_EQUAL(k.Index(), 0U);
    // deterministic: the same seed gives the same key, another index another key
    BOOST_CHECK(Derived(1, 0) == k);
    BOOST_CHECK(Derived(1, 1).GetID() != k.GetID());

    const CPQKey f = Derived(pq::SCHEME_FN_DSA_512, 0);
    BOOST_CHECK_EQUAL(f.PubKey().size(), 897U);
    BOOST_CHECK_EQUAL(f.SecretKey().size(), pq::SecretKeySize(2));
    BOOST_CHECK(f.GetID() == CPQKeyID(2, pq::KeyHash(2, f.PubKey())));
    BOOST_CHECK(Derived(2, 0).GetID() == f.GetID());   // Falcon keygen from the seed is deterministic here

    // both schemes sign and verify
    const uint256 msg = uint256S("0x1234");
    for (const CPQKey* key : {&k, &f}) {
        valtype sig;
        BOOST_REQUIRE(key->Sign(msg, sig));
        BOOST_CHECK_EQUAL(sig.size(), pq::SigSize(key->Scheme()));
        BOOST_CHECK(pq::Verify(key->Scheme(), key->PubKey(), sig, msg));
    }

    // refused: an unknown scheme, a short seed
    CPQKey bad;
    BOOST_CHECK(!bad.Set(3, Sec(SEED_1_0)));
    BOOST_CHECK(!bad.Set(1, Sec("00")));
    BOOST_CHECK(!bad.IsValid());
}

BOOST_AUTO_TEST_CASE(basic_keystore)
{
    CBasicKeyStore ks;
    const CPQKey a = Derived(1, 0), b = Derived(2, 0);
    BOOST_CHECK(!ks.HavePQKey(a.GetID()));
    BOOST_CHECK(!ks.AddPQKey(CPQKey()));
    BOOST_CHECK(ks.AddPQKey(a));
    BOOST_CHECK(ks.AddPQKey(b));
    BOOST_CHECK(ks.HavePQKey(a.GetID()) && ks.HavePQKey(b.GetID()));
    BOOST_CHECK_EQUAL(ks.GetPQKeys().size(), 2U);
    CPQKey out;
    BOOST_CHECK(ks.GetPQKey(b.GetID(), out) && out == b);
    valtype pk;
    BOOST_CHECK(ks.GetPQPubKey(a.GetID(), pk) && pk == a.PubKey());
    // the same hash under the other scheme is another key
    BOOST_CHECK(!ks.HavePQKey(CPQKeyID(2, a.GetID().hash)));
    // IsMine: TX_PQPKH of a held key is spendable, of another key not
    BOOST_CHECK_EQUAL(IsMine(ks, GetScriptForDestination(a.GetID())), ISMINE_SPENDABLE);
    BOOST_CHECK_EQUAL(IsMine(ks, GetScriptForDestination(CTxDestination(a.GetID()))), ISMINE_SPENDABLE);
    BOOST_CHECK_EQUAL(IsMine(ks, GetScriptForDestination(Derived(1, 1).GetID())), ISMINE_NO);
    // A V whose owner the keystore holds stays out of IsMine (spent through the vault RPCs only).
    vault::VaultParams vp;
    vp.tag = {'T', 'E', 'S', 'T'};
    vp.setId = vp.cancelSetId = uint256S("0x80");
    vp.delay = 5;
    vp.ownerHeight = 1000;
    vp.owner = a.GetID();
    const CScript v = vault::BuildVault(vp);
    BOOST_REQUIRE(!v.empty());
    BOOST_CHECK_EQUAL(IsMine(ks, v), ISMINE_NO);
}

BOOST_AUTO_TEST_CASE(crypto_keystore)
{
    TestCryptoKeyStore ks;
    const CPQKey a = Derived(1, 0), b = Derived(1, 1);
    BOOST_REQUIRE(ks.AddPQKey(a));
    CKeyingMaterial mk = MasterKey(0x42);
    BOOST_REQUIRE(ks.EncryptKeys(mk));
    BOOST_CHECK(ks.IsCrypted());
    BOOST_CHECK(ks.HavePQKey(a.GetID()));
    BOOST_CHECK_EQUAL(ks.GetPQKeys().size(), 1U);
    BOOST_REQUIRE(ks.Unlock(mk));
    CPQKey out;
    BOOST_CHECK(ks.GetPQKey(a.GetID(), out) && out == a);
    // a key added while encrypted and unlocked is stored encrypted
    BOOST_CHECK(ks.AddPQKey(b));
    BOOST_CHECK(ks.GetPQKey(b.GetID(), out) && out == b);
    valtype pk;
    uint32_t index = 0;
    BOOST_CHECK(ks.GetPQKeyInfo(b.GetID(), pk, index) && pk == b.PubKey() && index == 1);
    // locked: the public part stays readable, the secret does not, and no key can be added
    BOOST_REQUIRE(ks.Lock());
    BOOST_CHECK(ks.HavePQKey(b.GetID()));
    BOOST_CHECK(ks.GetPQPubKey(b.GetID(), pk) && pk == b.PubKey());
    BOOST_CHECK(!ks.GetPQKey(b.GetID(), out));
    BOOST_CHECK(!ks.AddPQKey(Derived(1, 2)));
    // a wrong master key does not unlock
    BOOST_CHECK(!ks.Unlock(MasterKey(0x43)));
    BOOST_CHECK(ks.Unlock(mk));
    BOOST_CHECK(ks.GetPQKey(a.GetID(), out) && out == a);
}

BOOST_AUTO_TEST_CASE(pqpkh_sign_and_size)
{
    // TX_PQPKH through ProduceSignature/SignSignature: the pushes of spec §2.1, verified under the vault
    // flags; STANDARD flags alone make OP_CHECKPQSIG a bad opcode (spec §5.2).
    const uint32_t branch = VaultBranch();
    const CAmount amount = 3 * COIN;
    for (uint8_t scheme : {pq::SCHEME_SLH_DSA_SHA2_128S, pq::SCHEME_FN_DSA_512}) {
        CBasicKeyStore ks;
        const CPQKey key = Derived(scheme, 7);
        BOOST_REQUIRE(ks.AddPQKey(key));
        const CScript spk = GetScriptForDestination(key.GetID());
        BOOST_CHECK_EQUAL(spk.size(), 35U);
        const unsigned int flags = VAULT_FLAGS | (scheme == pq::SCHEME_FN_DSA_512 ? SCRIPT_VERIFY_PQ_FALCON : 0);
        const size_t expected = scheme == pq::SCHEME_SLH_DSA_SHA2_128S ? 7938 : 1577;   // spec §2.1

        CMutableTransaction mtx = SpendTx(CScript() << OP_TRUE, amount - 1000);
        BOOST_CHECK(!SignSignature(ks, spk, mtx, TxData6(mtx, amount, spk), 0, amount, SIGHASH_ALL, branch));   // STANDARD only: bad opcode
        BOOST_CHECK(SignSignature(ks, spk, mtx, TxData6(mtx, amount, spk), 0, amount, SIGHASH_ALL, branch, flags));
        BOOST_CHECK_EQUAL(mtx.vin[0].scriptSig.size(), expected);
        BOOST_CHECK(mtx.vin[0].scriptSig.IsPushOnly());
        const CTransaction tx(mtx);
        ScriptError err;
        BOOST_CHECK(VerifyScript(tx.vin[0].scriptSig, spk, flags, TransactionSignatureChecker(&tx, TxData6(mtx, amount, spk), 0, amount), branch, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
        BOOST_CHECK(IsPQInputScript(spk));

        // size estimation: the dummy creator makes a scriptSig of exactly the signed size
        SignatureData dummy;
        BOOST_CHECK(ProduceSignature(DummySignatureCreator(&ks), spk, dummy, branch, flags));
        BOOST_CHECK_EQUAL(dummy.scriptSig.size(), expected);
        // a PQ key the keystore does not hold cannot be dummy-signed or signed
        CBasicKeyStore empty;
        BOOST_CHECK(!ProduceSignature(DummySignatureCreator(&empty), spk, dummy, branch, flags));
        CMutableTransaction m2 = SpendTx(CScript() << OP_TRUE, amount - 1000);
        BOOST_CHECK(!SignSignature(empty, spk, m2, TxData6(m2, amount, spk), 0, amount, SIGHASH_ALL, branch, flags));
    }
    // Falcon without SCRIPT_VERIFY_PQ_FALCON does not pass the signer's own check
    CBasicKeyStore ks;
    const CPQKey f = Derived(2, 0);
    BOOST_REQUIRE(ks.AddPQKey(f));
    CMutableTransaction mtx = SpendTx(CScript() << OP_TRUE, 1000);
    BOOST_CHECK(!SignSignature(ks, GetScriptForDestination(f.GetID()), mtx, TxData6(mtx, 2000, GetScriptForDestination(f.GetID())), 0, 2000, SIGHASH_ALL, VaultBranch(), VAULT_FLAGS));
    BOOST_CHECK(!IsPQInputScript(GetScriptForDestination(CKeyID())));
}

BOOST_AUTO_TEST_CASE(vault_owner_signer)
{
    // SignPQOwnerSpend: selector 2 of a V with a wallet SLH-DSA owner (7,939 bytes, spec §1.5), and the
    // refusals: a key the keystore lacks, a selector other than 2 / 3, nLockTime below ownerHeight.
    const uint32_t branch = VaultBranch();
    const CAmount amount = 5 * COIN;
    for (uint8_t scheme : {pq::SCHEME_SLH_DSA_SHA2_128S, pq::SCHEME_FN_DSA_512}) {
        CBasicKeyStore ks;
        const CPQKey key = Derived(scheme, 3);
        BOOST_REQUIRE(ks.AddPQKey(key));
        vault::VaultParams vp;
        vp.tag = {'T', 'E', 'S', 'T'};
        vp.setId = vp.cancelSetId = uint256S("0x80");
        vp.delay = 5;
        vp.ownerHeight = 1000;
        vp.owner = key.GetID();
        const CScript v = vault::BuildVault(vp);
        BOOST_REQUIRE(!v.empty());
        const unsigned int flags = VAULT_FLAGS | (scheme == pq::SCHEME_FN_DSA_512 ? SCRIPT_VERIFY_PQ_FALCON : 0);

        CMutableTransaction mtx = SpendTx(GetScriptForDestination(CKeyID()), amount - 10000);
        mtx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL - 1;
        mtx.nLockTime = (uint32_t)vp.ownerHeight;
        ScriptError err;
        BOOST_CHECK(SignPQOwnerSpend(ks, key.GetID(), v, mtx, 0, amount, 2, branch, flags, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(mtx.vin[0].scriptSig.size(), scheme == pq::SCHEME_SLH_DSA_SHA2_128S ? 7939U : 1578U);
        auto sel = vault::ParseSelector(mtx.vin[0].scriptSig);
        BOOST_CHECK(sel && *sel == vault::SEL_OWNER);
        const CTransaction tx(mtx);
        BOOST_CHECK(VerifyScript(tx.vin[0].scriptSig, v, flags, TransactionSignatureChecker(&tx, TxData6(mtx, amount, v), 0, amount), branch, &err));

        BOOST_CHECK(!SignPQOwnerSpend(ks, key.GetID(), v, mtx, 0, amount, 1, branch, flags, &err));
        BOOST_CHECK(!SignPQOwnerSpend(ks, Derived(scheme, 4).GetID(), v, mtx, 0, amount, 2, branch, flags, &err));
        CMutableTransaction early = mtx;
        early.nLockTime = (uint32_t)vp.ownerHeight - 1;
        BOOST_CHECK(!SignPQOwnerSpend(ks, key.GetID(), v, early, 0, amount, 2, branch, flags, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        // without the vault flags the signer's check fails (OP_CHECKPQSIG is a bad opcode)
        BOOST_CHECK(!SignPQOwnerSpend(ks, key.GetID(), v, mtx, 0, amount, 2, branch, STANDARD_SCRIPT_VERIFY_FLAGS, &err));
    }
}

BOOST_AUTO_TEST_CASE(pq_size_fee)
{
    // max(floor, -pqfeerate x size) (quantum plan §4.5); the default rate is 1x the 100 zat/kB relay floor.
    const CFeeRate saved = pqFeeRate;
    pqFeeRate = CFeeRate(100);
    BOOST_CHECK_EQUAL(PQSizeFee(LEGACY_DEFAULT_FEE, 8100), LEGACY_DEFAULT_FEE);     // 810 < 1,000 (C-5)
    pqFeeRate = CFeeRate(1000);
    BOOST_CHECK_EQUAL(PQSizeFee(LEGACY_DEFAULT_FEE, 8100), 8100);
    BOOST_CHECK_EQUAL(PQSizeFee(10000, 8100), 10000);
    pqFeeRate = saved;
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(pq_wallet_db_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(wallet_derivation_and_walletdb)
{
    // GetNewPQKey derives from the wallet's HD seed (index 0, 1, ...), writes "pqkey", and a reloaded
    // wallet holds the same keys and continues at the next index; after EncryptWallet the records are
    // "cpqkey", a reloaded encrypted wallet holds them, and a locked wallet cannot derive or sign.
    bitdb.MakeMock();
    const std::string file = "pq_wallet_test.dat";
    CPQKeyID k0, k1, k2, f0;
    {
        CWallet w(Params(), file);
        bool fFirstRun;
        BOOST_REQUIRE_EQUAL(w.LoadWallet(fFirstRun), DB_LOAD_OK);
        LOCK(w.cs_wallet);
        CPQKeyID none;
        BOOST_CHECK(!w.GetNewPQKey(1, none));                 // no HD seed yet
        BOOST_REQUIRE(w.SetMnemonicSeed(TestMnemonicSeed()));   // 6.20.0: the mnemonic seed
        BOOST_CHECK(!w.GetNewPQKey(3, none));                 // unknown scheme
        BOOST_REQUIRE(w.GetNewPQKey(1, k0));
        BOOST_REQUIRE(w.GetNewPQKey(1, k1));
        BOOST_REQUIRE(w.GetNewPQKey(2, f0));
        BOOST_CHECK(k0 == WalletDerived(1, 0).GetID());   // 6.20.0: IKM = the mnemonic raw seed (the HD-seed vector is ycash-dd's)
        BOOST_CHECK(k1 == WalletDerived(1, 1).GetID());
        BOOST_CHECK(f0 == WalletDerived(2, 0).GetID());
        BOOST_CHECK_EQUAL(w.GetPQKeys().size(), 3U);
        BOOST_CHECK(w.mapPQKeyCreateTime.count(k0));
    }
    {
        CWallet w(Params(), file);
        bool fFirstRun;
        BOOST_REQUIRE_EQUAL(w.LoadWallet(fFirstRun), DB_LOAD_OK);
        LOCK(w.cs_wallet);
        BOOST_CHECK(w.HavePQKey(k0) && w.HavePQKey(k1) && w.HavePQKey(f0));
        CPQKey key;
        BOOST_CHECK(w.GetPQKey(k1, key) && key == WalletDerived(1, 1) && key.Index() == 1);
        BOOST_REQUIRE(w.GetNewPQKey(1, k2));
        BOOST_CHECK(k2 == WalletDerived(1, 2).GetID());             // continues after the stored indices
        BOOST_REQUIRE(w.EncryptWallet(SecureString("pq-pass")));
        BOOST_CHECK(w.IsCrypted() && w.IsLocked());
        BOOST_CHECK(w.HavePQKey(k2));
        BOOST_CHECK(!w.GetPQKey(k2, key));
        CPQKeyID none;
        BOOST_CHECK(!w.GetNewPQKey(1, none));                 // locked
    }
    {
        CWallet w(Params(), file);
        bool fFirstRun;
        BOOST_REQUIRE_EQUAL(w.LoadWallet(fFirstRun), DB_LOAD_OK);
        LOCK(w.cs_wallet);
        BOOST_CHECK(w.IsCrypted() && w.IsLocked());
        BOOST_CHECK(w.HavePQKey(k0) && w.HavePQKey(k1) && w.HavePQKey(k2) && w.HavePQKey(f0));
        CPQKey key;
        BOOST_CHECK(!w.GetPQKey(k0, key));
        BOOST_REQUIRE(w.Unlock(SecureString("pq-pass")));
        BOOST_CHECK(w.GetPQKey(k0, key) && key == WalletDerived(1, 0));
        BOOST_CHECK(w.GetPQKey(f0, key) && key == WalletDerived(2, 0));
        CPQKeyID k3;
        BOOST_REQUIRE(w.GetNewPQKey(1, k3));                  // unlocked: derives from the encrypted seed
        BOOST_CHECK(k3 == WalletDerived(1, 3).GetID());
    }
    {
        CWallet w(Params(), file);
        bool fFirstRun;
        BOOST_REQUIRE_EQUAL(w.LoadWallet(fFirstRun), DB_LOAD_OK);
        LOCK(w.cs_wallet);
        BOOST_CHECK_EQUAL(w.GetPQKeys().size(), 5U);
        BOOST_REQUIRE(w.Unlock(SecureString("pq-pass")));
        CPQKey key;
        BOOST_CHECK(w.GetPQKey(WalletDerived(1, 3).GetID(), key));
    }
    bitdb.Flush(true);
    bitdb.Reset();
    // EncryptWallet's CDB::Rewrite writes the file beside the mock environment (the working directory)
    boost::system::error_code ec;
    fs::remove(fs::current_path() / file, ec);
}

BOOST_AUTO_TEST_SUITE_END()
