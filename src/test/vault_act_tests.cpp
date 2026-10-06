// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The `YV` OP_RETURN act codec and the two signed messages
// (docs/plans/yellowback-upgrade-plan.md §15.2 step 4, §15.5).

#include "vault/act.h"

#include "crypto/sha256.h"
#include "key.h"
#include "test/test_bitcoin.h"
#include "util/strencodings.h"

#include <boost/test/unit_test.hpp>

using namespace vault;

namespace {

typedef std::vector<unsigned char> valtype;

CKey TestCKey(unsigned char seed)
{
    CKey k;
    std::vector<unsigned char> secret(32, 0);
    secret[31] = seed;
    secret[0] = 0x22;
    k.Set(secret.begin(), secret.end(), true);
    return k;
}

uint256 U(unsigned char b)
{
    uint256 h;
    for (int i = 0; i < 32; i++) h.begin()[i] = (unsigned char)(b ^ i);
    return h;
}

SetCreateBody SampleCreate()
{
    SetCreateBody c;
    c.seats = 9;
    c.unlockThreshold = 6;
    c.cancelThreshold = 1;
    c.slashThreshold = 7;
    c.flags = 0;
    c.rateLimitBps = 2500;
    c.rateWindow = 1440;
    c.livenessWindow = 2880;
    c.bondMin = 100 * COIN;
    c.bondLockMin = 10000;
    c.maturity = 100;
    c.admitKey = TestCKey(1).GetPubKey();
    return c;
}

std::vector<Act> SampleActs()
{
    std::vector<Act> acts;
    Act a;
    a.type = ACT_SET_CREATE;
    a.create = SampleCreate();
    acts.push_back(a);

    Act j;
    j.type = ACT_SET_JOIN;
    j.join.setId = U(1);
    j.join.memberKey = TestCKey(2).GetPubKey();
    j.join.bondLocktime = 123456;
    j.join.bondVout = 1;
    acts.push_back(j);

    Act h;
    h.type = ACT_SET_HEARTBEAT;
    h.heartbeat.setId = U(2);
    h.heartbeat.memberKey = TestCKey(3).GetPubKey();
    acts.push_back(h);

    Act r;
    r.type = ACT_SET_REMOVE;
    r.remove.setId = U(3);
    r.remove.memberKey = TestCKey(4).GetPubKey();
    r.remove.burn = 1;
    acts.push_back(r);

    Act e;
    e.type = ACT_SET_EQUIVOCATION;
    e.equivocation.setId = U(4);
    e.equivocation.prevout = COutPoint(U(5), 7);
    e.equivocation.roleA = 1;
    e.equivocation.sighashA = U(6);
    e.equivocation.sigA = valtype(65, 0x1f);
    e.equivocation.roleB = 2;
    e.equivocation.sighashB = U(7);
    e.equivocation.sigB = valtype(65, 0x20);
    acts.push_back(e);

    Act w;
    w.type = ACT_SET_WINDDOWN;
    w.winddown.setId = U(8);
    acts.push_back(w);
    return acts;
}

uint256 Sha256d(const valtype& b)
{
    unsigned char h1[32];
    CSHA256().Write(b.data(), b.size()).Finalize(h1);
    uint256 out;
    CSHA256().Write(h1, 32).Finalize(out.begin());
    return out;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(vault_act_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(body_sizes)
{
    BOOST_CHECK_EQUAL(ActBodySize(ACT_SET_CREATE), 64U);
    BOOST_CHECK_EQUAL(ActBodySize(ACT_SET_JOIN), 70U);
    BOOST_CHECK_EQUAL(ActBodySize(ACT_SET_HEARTBEAT), 65U);
    BOOST_CHECK_EQUAL(ActBodySize(ACT_SET_REMOVE), 66U);
    BOOST_CHECK_EQUAL(ActBodySize(ACT_SET_EQUIVOCATION), 264U);
    BOOST_CHECK_EQUAL(ActBodySize(ACT_SET_WINDDOWN), 32U);
    BOOST_CHECK_EQUAL(ActBodySize(0), 0U);
    BOOST_CHECK_EQUAL(ActBodySize(7), 0U);
}

BOOST_AUTO_TEST_CASE(roundtrip_all_types)
{
    for (Act a : SampleActs()) {
        a.sigs = {valtype(65, 0x21), valtype(65, 0x22)};
        valtype P = EncodePayload(a);
        BOOST_CHECK_EQUAL(P.size(), 4 + ActBodySize(a.type));
        BOOST_CHECK_EQUAL(P[0], 'Y');
        BOOST_CHECK_EQUAL(P[1], 'V');
        BOOST_CHECK_EQUAL(P[2], 0x01);
        BOOST_CHECK_EQUAL(P[3], a.type);
        CScript s = EncodeAct(a);
        BOOST_CHECK(IsActOutput(s));
        Act b;
        auto err = DecodeAct(s, b);
        BOOST_CHECK_MESSAGE(!err, (err ? *err : std::string()));
        BOOST_CHECK_EQUAL(b.type, a.type);
        BOOST_CHECK(EncodePayload(b) == P);
        BOOST_CHECK(b.sigs == a.sigs);
        BOOST_CHECK(EncodeAct(b) == s);
    }
}

BOOST_AUTO_TEST_CASE(create_layout)
{
    Act a;
    a.type = ACT_SET_CREATE;
    a.create = SampleCreate();
    valtype P = EncodePayload(a);
    // seats unlock cancel slash flags | bps u16 | rateWindow u32 | livenessWindow u32 | bondMin i64 | bondLockMin u32 | maturity u32 | admitKey 33
    BOOST_CHECK_EQUAL(HexStr(P.begin(), P.begin() + 4 + 5), "59560101" "0906010700");
    BOOST_CHECK_EQUAL(HexStr(P.begin() + 9, P.begin() + 11), "c409");                 // 2500
    BOOST_CHECK_EQUAL(HexStr(P.begin() + 11, P.begin() + 15), "a0050000");            // 1440
    BOOST_CHECK_EQUAL(HexStr(P.begin() + 15, P.begin() + 19), "400b0000");            // 2880
    BOOST_CHECK_EQUAL(HexStr(P.begin() + 19, P.begin() + 27), "00e40b5402000000");    // 100 COIN
    BOOST_CHECK_EQUAL(HexStr(P.begin() + 27, P.begin() + 31), "10270000");            // 10000
    BOOST_CHECK_EQUAL(HexStr(P.begin() + 31, P.begin() + 35), "64000000");            // 100
    CPubKey admit = SampleCreate().admitKey;
    BOOST_CHECK(valtype(P.begin() + 35, P.end()) == valtype(admit.begin(), admit.end()));
    Act b;
    BOOST_CHECK(!DecodePayload(P, b));
    BOOST_CHECK_EQUAL(b.create.rateLimitBps, 2500);
    BOOST_CHECK_EQUAL(b.create.bondMin, 100 * COIN);
    BOOST_CHECK(b.create.admitKey == admit);
}

BOOST_AUTO_TEST_CASE(decode_rejects)
{
    Act a = SampleActs()[2]; // heartbeat
    valtype P = EncodePayload(a);
    Act out;

    valtype badVersion = P;
    badVersion[2] = 0x02;
    BOOST_CHECK_EQUAL(*DecodePayload(badVersion, out), "bad-vault-act-version");
    valtype badType = P;
    badType[3] = 0x07;
    BOOST_CHECK_EQUAL(*DecodePayload(badType, out), "bad-vault-act-type");
    badType[3] = 0x00;
    BOOST_CHECK_EQUAL(*DecodePayload(badType, out), "bad-vault-act-type");
    valtype trailing = P;
    trailing.push_back(0);
    BOOST_CHECK_EQUAL(*DecodePayload(trailing, out), "bad-vault-act-malformed");
    valtype truncated(P.begin(), P.end() - 1);
    BOOST_CHECK_EQUAL(*DecodePayload(truncated, out), "bad-vault-act-malformed");
    BOOST_CHECK_EQUAL(*DecodePayload(valtype{'Y', 'V'}, out), "bad-vault-act-malformed");
    BOOST_CHECK_EQUAL(*DecodePayload(valtype{'Y', 'V', 0x01}, out), "bad-vault-act-malformed");

    // Signature pushes must be exactly 65 bytes.
    CScript s;
    s << OP_RETURN << P << valtype(64, 0x01);
    BOOST_CHECK_EQUAL(*DecodeAct(s, out), "bad-vault-act-malformed");
    // A non-push after P.
    CScript s2;
    s2 << OP_RETURN << P << OP_DUP;
    BOOST_CHECK_EQUAL(*DecodeAct(s2, out), "bad-vault-act-malformed");
    // P pushed non-minimally (OP_PUSHDATA1 for a 69-byte payload).
    valtype raw = {OP_RETURN, OP_PUSHDATA1, (unsigned char)P.size()};
    raw.insert(raw.end(), P.begin(), P.end());
    CScript s3(raw.begin(), raw.end());
    BOOST_CHECK(IsActOutput(s3));
    BOOST_CHECK_EQUAL(*DecodeAct(s3, out), "bad-vault-act-malformed");
    // Truncated script.
    CScript s4 = EncodeAct(a);
    CScript s5(s4.begin(), s4.end() - 3);
    BOOST_CHECK(DecodeAct(s5, out).has_value());
    // A bad key header inside the body does not round-trip.
    valtype badKey = P;
    badKey[4 + 32] = 0x05;
    CScript s6;
    s6 << OP_RETURN << badKey;
    BOOST_CHECK_EQUAL(*DecodeAct(s6, out), "bad-vault-act-malformed");
}

BOOST_AUTO_TEST_CASE(is_act_output)
{
    CScript a;
    a << OP_RETURN << valtype{'Y', 'V'};
    BOOST_CHECK(IsActOutput(a));
    CScript b;
    b << OP_RETURN << valtype{'Y', 'X', 1};
    BOOST_CHECK(!IsActOutput(b));
    CScript c;
    c << OP_RETURN;
    BOOST_CHECK(!IsActOutput(c));
    CScript d;
    d << valtype{'Y', 'V', 1, 1};
    BOOST_CHECK(!IsActOutput(d));
    CScript e;
    e << OP_RETURN << OP_DUP;
    BOOST_CHECK(!IsActOutput(e));
    BOOST_CHECK(!IsActOutput(CScript()));
}

BOOST_AUTO_TEST_CASE(create_params)
{
    BOOST_CHECK(SampleCreate().Valid());
    SetCreateBody c = SampleCreate();
    c.seats = 0;
    BOOST_CHECK(!c.Valid());
    c = SampleCreate();
    c.seats = 16;
    BOOST_CHECK(!c.Valid());
    c.seats = 15;
    BOOST_CHECK(c.Valid());
    c = SampleCreate();
    c.slashThreshold = 10;
    BOOST_CHECK(!c.Valid());
    c = SampleCreate();
    c.unlockThreshold = 0;
    BOOST_CHECK(!c.Valid());
    c = SampleCreate();
    c.flags = 0x02;
    BOOST_CHECK(!c.Valid());
    c.flags = SET_FLAG_OPEN;
    BOOST_CHECK(c.Valid() && c.IsOpen());
    c = SampleCreate();
    c.rateLimitBps = 10001;
    BOOST_CHECK(!c.Valid());
    c.rateLimitBps = 0;
    BOOST_CHECK(c.Valid());
    c = SampleCreate();
    c.rateWindow = 0;
    BOOST_CHECK(!c.Valid());
    c.rateWindow = 1048577;
    BOOST_CHECK(!c.Valid());
    c.rateWindow = 1048576;
    BOOST_CHECK(c.Valid());
    c = SampleCreate();
    c.livenessWindow = 0;
    BOOST_CHECK(!c.Valid());
    c = SampleCreate();
    c.bondMin = 0;
    BOOST_CHECK(!c.Valid());
    c.bondMin = MAX_MONEY + 1;
    BOOST_CHECK(!c.Valid());
    c = SampleCreate();
    c.admitKey = CPubKey();
    BOOST_CHECK(!c.Valid());
}

BOOST_AUTO_TEST_CASE(messages)
{
    valtype P = EncodePayload(SampleActs()[1]);
    COutPoint op(U(9), 0x01020304);
    const std::string actTag = "YcashSetAct";
    valtype buf(actTag.begin(), actTag.end());
    BOOST_CHECK_EQUAL(buf.size(), 11U);
    buf.insert(buf.end(), P.begin(), P.end());
    buf.insert(buf.end(), op.hash.begin(), op.hash.end());
    buf.insert(buf.end(), {0x04, 0x03, 0x02, 0x01});
    BOOST_CHECK(ActMsg(P, op) == Sha256d(buf));

    uint256 setId = U(10), sighash = U(11);
    std::string tag = "YcashSetSig";
    valtype b2(tag.begin(), tag.end());
    b2.insert(b2.end(), setId.begin(), setId.end());
    b2.push_back(2);
    b2.insert(b2.end(), op.hash.begin(), op.hash.end());
    b2.insert(b2.end(), {0x04, 0x03, 0x02, 0x01});
    b2.insert(b2.end(), sighash.begin(), sighash.end());
    BOOST_CHECK(SetSigMsg(setId, 2, op, sighash) == Sha256d(b2));
    BOOST_CHECK(SetSigMsg(setId, 1, op, sighash) != SetSigMsg(setId, 2, op, sighash));
    BOOST_CHECK(SetSigMsg(setId, 1, op, sighash) != SetSigMsg(setId, 1, COutPoint(op.hash, 0), sighash));
}

BOOST_AUTO_TEST_CASE(recoverable_signatures)
{
    CKey k = TestCKey(5);
    uint256 msg = U(12);
    valtype sig;
    BOOST_REQUIRE(SignRecoverable(k, msg, sig));
    BOOST_CHECK_EQUAL(sig.size(), 65U);
    BOOST_CHECK(sig[0] >= 31 && sig[0] <= 34);
    CPubKey rec;
    BOOST_CHECK(RecoverSig(msg, sig, rec));
    BOOST_CHECK(rec == k.GetPubKey());
    BOOST_CHECK(rec.IsCompressed());
    // A different message recovers a different key (or fails).
    CPubKey other;
    if (RecoverSig(U(13), sig, other)) BOOST_CHECK(other != k.GetPubKey());

    // Uncompressed headers 27..30 are refused, and anything outside 27..34.
    valtype unc = sig;
    unc[0] -= 4;
    BOOST_CHECK(!RecoverSig(msg, unc, rec));
    valtype bad = sig;
    bad[0] = 35;
    BOOST_CHECK(!RecoverSig(msg, bad, rec));
    BOOST_CHECK(!RecoverSig(msg, valtype(64, 1), rec));
    BOOST_CHECK(!RecoverSig(msg, valtype(), rec));
    BOOST_CHECK(!RecoverSig(msg, valtype(65, 0), rec));
    valtype ff(65, 0xff);
    ff[0] = 31;
    BOOST_CHECK(!RecoverSig(msg, ff, rec));

    // High S: s' = n - s with the recovery id's parity flipped recovers the same key in
    // libsecp256k1, and is refused here.
    static const unsigned char N[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};
    valtype high = sig;
    int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int d = (int)N[i] - (int)sig[33 + i] - borrow;
        borrow = d < 0 ? 1 : 0;
        high[33 + i] = (unsigned char)(d + (borrow ? 256 : 0));
    }
    high[0] = (unsigned char)(31 + (((sig[0] - 31) & 3) ^ 1));
    CPubKey viaLib;
    BOOST_CHECK(viaLib.RecoverCompact(msg, high));
    BOOST_CHECK(viaLib == k.GetPubKey());
    BOOST_CHECK(!RecoverSig(msg, high, rec));

    // Uncompressed keys do not sign set messages.
    CKey u = CKey::TestOnlyRandomKey(false);
    BOOST_CHECK(!SignRecoverable(u, msg, sig));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(vault_act_field_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(act_fields_valid)
{
    for (const Act& a : SampleActs()) {
        Act b = a;
        if (b.type == ACT_SET_EQUIVOCATION) {
            b.equivocation.sigA[0] = 31;
            b.equivocation.sigB[0] = 34;
        }
        BOOST_CHECK(ActFieldsValid(b));
    }
    Act j = SampleActs()[1];
    j.join.bondLocktime = 500000000;
    BOOST_CHECK(!ActFieldsValid(j));
    j.join.bondLocktime = 499999999;
    BOOST_CHECK(ActFieldsValid(j));
    j.sigs = {valtype(65, 30)};
    BOOST_CHECK(!ActFieldsValid(j));
    j.sigs = {valtype(65, 33)};
    BOOST_CHECK(ActFieldsValid(j));
    Act r = SampleActs()[3];
    r.remove.burn = 2;
    BOOST_CHECK(!ActFieldsValid(r));
    Act e = SampleActs()[4];
    e.equivocation.sigA[0] = 31;
    e.equivocation.sigB[0] = 31;
    BOOST_CHECK(ActFieldsValid(e));
    e.equivocation.roleA = 0;
    BOOST_CHECK(!ActFieldsValid(e));
    e.equivocation.roleA = 1;
    e.equivocation.sigB[0] = 27;
    BOOST_CHECK(!ActFieldsValid(e));
    Act c = SampleActs()[0];
    c.create.seats = 0;
    BOOST_CHECK(!ActFieldsValid(c));
}

BOOST_AUTO_TEST_SUITE_END()
