// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The vault primitive's script templates (docs/plans/yellowback-upgrade-plan.md §15.3):
// exact shapes, minimal pushes, field ranges, the selector, the bond redeem script.

#include "vault/template.h"

#include "key.h"
#include "script/standard.h"
#include "test/test_bitcoin.h"
#include "util/strencodings.h"

#include <boost/test/unit_test.hpp>

using namespace vault;

namespace {

typedef std::vector<unsigned char> valtype;

CPubKey TestKey(unsigned char seed)
{
    CKey k;
    std::vector<unsigned char> secret(32, 0);
    secret[31] = seed;
    secret[0] = 0x11;
    k.Set(secret.begin(), secret.end(), true);
    return k.GetPubKey();
}

uint256 U(unsigned char b)
{
    uint256 h;
    for (int i = 0; i < 32; i++) h.begin()[i] = (unsigned char)(b + i);
    return h;
}

VaultParams SampleVault()
{
    VaultParams p;
    p.tag = {'T', 'E', 'S', 'T'};
    p.cancelSetId = U(0x40);
    p.delay = 5;
    p.setId = U(0x80);
    p.ownerHeight = 1000;
    p.ownerKey = TestKey(1);
    p.appHeight = 2000;
    return p;
}

IntentParams SampleIntent()
{
    IntentParams p;
    p.tag = {'T', 'E', 'S', 'T'};
    p.recipientHash = U(0x10);
    p.vaultHash = U(0x20);
    p.delay = 144;
    p.cancelSetId = U(0x40);
    p.setId = U(0x80);
    p.ownerKey = TestKey(2);
    return p;
}

/** Replace `len` bytes at `pos` with `with`. */
CScript Splice(const CScript& s, size_t pos, size_t len, const valtype& with)
{
    valtype b(s.begin(), s.end());
    b.erase(b.begin() + pos, b.begin() + pos + len);
    b.insert(b.begin() + pos, with.begin(), with.end());
    return CScript(b.begin(), b.end());
}

// Byte offsets in a V script: tag push (5), cancelSetId push (33), then the delay push.
const size_t V_DELAY_POS = 5 + 33;

} // namespace

BOOST_FIXTURE_TEST_SUITE(vault_template_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(vault_roundtrip_and_shape)
{
    VaultParams p = SampleVault();
    CScript v = BuildVault(p);
    BOOST_REQUIRE(!v.empty());
    VaultParams q;
    BOOST_CHECK(ParseVault(v, q));
    BOOST_CHECK(q == p);
    BOOST_CHECK(MatchVault(v, q) == Shape::MATCH);
    // Not an intent.
    IntentParams ip;
    BOOST_CHECK(MatchIntent(v, ip) == Shape::NONE);

    // The opcode bytes of the new script additions appear; 0xbb..0xbf never do.
    valtype b(v.begin(), v.end());
    BOOST_CHECK(std::count(b.begin(), b.end(), 0xc0) >= 1);
    BOOST_CHECK(std::count(b.begin(), b.end(), 0xc1) >= 1);
    // Layout prefix: <04 tag> <20 cancelSetId> <OP_5> OP_2DROP OP_DROP OP_DUP OP_1 OP_EQUAL OP_IF
    BOOST_CHECK_EQUAL(b[0], 0x04);
    BOOST_CHECK_EQUAL(b[5], 0x20);
    BOOST_CHECK_EQUAL(b[V_DELAY_POS], (unsigned char)OP_5);
    BOOST_CHECK_EQUAL(b[V_DELAY_POS + 1], (unsigned char)OP_2DROP);
    BOOST_CHECK_EQUAL(b[V_DELAY_POS + 2], (unsigned char)OP_DROP);
    // The tail: OP_4 OP_EQUALVERIFY <appHeight> OP_CHECKLOCKTIMEVERIFY OP_ENDIF*3
    BOOST_CHECK_EQUAL(b[b.size() - 1], (unsigned char)OP_ENDIF);
    BOOST_CHECK_EQUAL(b[b.size() - 4], (unsigned char)OP_CHECKLOCKTIMEVERIFY);
}

BOOST_AUTO_TEST_CASE(vault_minimal_pushes)
{
    VaultParams p = SampleVault();
    // delay 16 → OP_16; 17 → a one-byte push.
    p.delay = 16;
    CScript v16 = BuildVault(p);
    BOOST_CHECK_EQUAL(v16[V_DELAY_POS], (unsigned char)OP_16);
    p.delay = 17;
    CScript v17 = BuildVault(p);
    BOOST_CHECK_EQUAL(v17[V_DELAY_POS], 0x01);
    BOOST_CHECK_EQUAL(v17[V_DELAY_POS + 1], 17);
    VaultParams q;
    BOOST_CHECK(ParseVault(v17, q));

    // Non-minimal: delay 5 pushed as 01 05 → V-shaped but malformed.
    CScript v = BuildVault(SampleVault());
    CScript nm = Splice(v, V_DELAY_POS, 1, {0x01, 0x05});
    BOOST_CHECK(MatchVault(nm, q) == Shape::MALFORMED);
    BOOST_CHECK(!ParseVault(nm, q));
    // Non-minimal: delay 5 pushed as 02 05 00.
    BOOST_CHECK(MatchVault(Splice(v, V_DELAY_POS, 1, {0x02, 0x05, 0x00}), q) == Shape::MALFORMED);
    // A 32-byte push through OP_PUSHDATA1.
    valtype cancel(v.begin() + 6, v.begin() + 38);
    valtype pd1 = {OP_PUSHDATA1, 0x20};
    pd1.insert(pd1.end(), cancel.begin(), cancel.end());
    BOOST_CHECK(MatchVault(Splice(v, 5, 33, pd1), q) == Shape::MALFORMED);
}

BOOST_AUTO_TEST_CASE(vault_field_ranges)
{
    VaultParams q;
    CScript v = BuildVault(SampleVault());
    // delay 0 (OP_0) and 65536 (03 00 00 01) are out of range.
    BOOST_CHECK(MatchVault(Splice(v, V_DELAY_POS, 1, {OP_0}), q) == Shape::MALFORMED);
    BOOST_CHECK(MatchVault(Splice(v, V_DELAY_POS, 1, {0x03, 0x00, 0x00, 0x01}), q) == Shape::MALFORMED);
    // delay 65535 (03 ff ff 00) is in range.
    BOOST_CHECK(MatchVault(Splice(v, V_DELAY_POS, 1, {0x03, 0xff, 0xff, 0x00}), q) == Shape::MATCH);
    BOOST_CHECK_EQUAL(q.delay, 65535);
    // Negative delay (OP_1NEGATE).
    BOOST_CHECK(MatchVault(Splice(v, V_DELAY_POS, 1, {OP_1NEGATE}), q) == Shape::MALFORMED);

    VaultParams p = SampleVault();
    p.delay = 0;
    BOOST_CHECK(BuildVault(p).empty());
    p = SampleVault();
    p.ownerHeight = 0;
    BOOST_CHECK(BuildVault(p).empty());
    p.ownerHeight = 500000000;
    BOOST_CHECK(BuildVault(p).empty());
    p.ownerHeight = 499999999;
    BOOST_CHECK(!BuildVault(p).empty());
    p.appHeight = 0; // APP branch disabled, still a template
    CScript v0 = BuildVault(p);
    BOOST_REQUIRE(!v0.empty());
    BOOST_CHECK(ParseVault(v0, q));
    BOOST_CHECK_EQUAL(q.appHeight, 0);
    p.appHeight = 500000000;
    BOOST_CHECK(BuildVault(p).empty());

    // Uncompressed / bad-header owner key.
    p = SampleVault();
    CKey k = CKey::TestOnlyRandomKey(false);
    p.ownerKey = k.GetPubKey();
    BOOST_CHECK(BuildVault(p).empty());
    // Replace the owner key's header byte inside the script with 0x04: malformed.
    CScript good = BuildVault(SampleVault());
    valtype b(good.begin(), good.end());
    const CPubKey ownerKey = SampleVault().ownerKey;
    valtype key(ownerKey.begin(), ownerKey.end());
    auto it = std::search(b.begin(), b.end(), key.begin(), key.end());
    BOOST_REQUIRE(it != b.end());
    *it = 0x04;
    BOOST_CHECK(MatchVault(CScript(b.begin(), b.end()), q) == Shape::MALFORMED);
}

BOOST_AUTO_TEST_CASE(vault_inconsistent_fields)
{
    // setId appears twice and ownerKey twice; they must agree.
    VaultParams p = SampleVault();
    CScript v = BuildVault(p);
    valtype b(v.begin(), v.end());
    valtype setId(p.setId.begin(), p.setId.end());
    auto first = std::search(b.begin(), b.end(), setId.begin(), setId.end());
    BOOST_REQUIRE(first != b.end());
    auto second = std::search(first + 1, b.end(), setId.begin(), setId.end());
    BOOST_REQUIRE(second != b.end());
    *second ^= 0x01;
    VaultParams q;
    BOOST_CHECK(MatchVault(CScript(b.begin(), b.end()), q) == Shape::MALFORMED);
}

BOOST_AUTO_TEST_CASE(not_a_template)
{
    VaultParams q;
    IntentParams i;
    CScript p2pkh = GetScriptForDestination(TestKey(3).GetID());
    BOOST_CHECK(MatchVault(p2pkh, q) == Shape::NONE);
    BOOST_CHECK(MatchIntent(p2pkh, i) == Shape::NONE);
    BOOST_CHECK(MatchVault(CScript(), q) == Shape::NONE);
    // A V with one opcode changed is not V-shaped.
    CScript v = BuildVault(SampleVault());
    valtype b(v.begin(), v.end());
    b[V_DELAY_POS + 1] = OP_NIP;
    BOOST_CHECK(MatchVault(CScript(b.begin(), b.end()), q) == Shape::NONE);
    // Truncated.
    BOOST_CHECK(MatchVault(CScript(v.begin(), v.begin() + 20), q) == Shape::NONE);
    // A trailing opcode.
    CScript longer = v;
    longer << OP_NOP;
    BOOST_CHECK(MatchVault(longer, q) == Shape::NONE);
}

BOOST_AUTO_TEST_CASE(intent_roundtrip_and_ranges)
{
    IntentParams p = SampleIntent();
    CScript s = BuildIntent(p);
    BOOST_REQUIRE(!s.empty());
    IntentParams q;
    BOOST_CHECK(ParseIntent(s, q));
    BOOST_CHECK(q.tag == p.tag);
    BOOST_CHECK(q.recipientHash == p.recipientHash);
    BOOST_CHECK(q.vaultHash == p.vaultHash);
    BOOST_CHECK_EQUAL(q.delay, 144);
    BOOST_CHECK(q.cancelSetId == p.cancelSetId);
    BOOST_CHECK(q.setId == p.setId);
    BOOST_CHECK(q.ownerKey == p.ownerKey);
    VaultParams v;
    BOOST_CHECK(MatchVault(s, v) == Shape::NONE);
    // CSV byte 0xb2 follows the delay push.
    valtype b(s.begin(), s.end());
    BOOST_CHECK(std::find(b.begin(), b.end(), 0xb2) != b.end());

    p.delay = 0;
    BOOST_CHECK(BuildIntent(p).empty());
    p.delay = 65536;
    BOOST_CHECK(BuildIntent(p).empty());
    // delay 144 is pushed as 02 90 00; a non-minimal 03 90 00 00 is malformed.
    const size_t pos = 5 + 33 + 33 + 2 + 4 + 1; // tag, rh, vh, 2DROP DROP, DUP 1 EQUAL IF, DROP
    BOOST_REQUIRE_EQUAL(b[pos], 0x02);
    CScript nm = Splice(s, pos, 3, {0x03, 0x90, 0x00, 0x00});
    BOOST_CHECK(MatchIntent(nm, q) == Shape::MALFORMED);
}

BOOST_AUTO_TEST_CASE(intent_for_vault)
{
    VaultParams v = SampleVault();
    CScript vs = BuildVault(v);
    CScript recipient = GetScriptForDestination(TestKey(9).GetID());
    IntentParams i = IntentFor(v, vs, recipient);
    BOOST_CHECK(i.vaultHash == ScriptHash256(vs));
    BOOST_CHECK(i.recipientHash == ScriptHash256(recipient));
    BOOST_CHECK(i.setId == v.setId && i.cancelSetId == v.cancelSetId && i.delay == v.delay && i.ownerKey == v.ownerKey);
    // SHA256 single, of the raw script bytes: SHA256("") check.
    const uint256 empty = ScriptHash256(CScript());
    BOOST_CHECK_EQUAL(HexStr(empty.begin(), empty.end()),
                      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

BOOST_AUTO_TEST_CASE(selector_parsing)
{
    std::vector<valtype> pushes;
    valtype sig(65, 0x30);
    CScript s;
    s << sig << sig << OP_1;
    auto sel = ParseSelector(s, &pushes);
    BOOST_REQUIRE(sel);
    BOOST_CHECK_EQUAL(*sel, 1);
    BOOST_CHECK_EQUAL(pushes.size(), 2U);
    BOOST_CHECK(pushes[0] == sig);

    for (int n = 1; n <= 4; n++) {
        CScript t;
        t << CScript::EncodeOP_N(n);
        BOOST_CHECK(ParseSelector(t) && *ParseSelector(t) == n);
    }
    CScript five;
    five << OP_5;
    BOOST_CHECK(!ParseSelector(five));
    CScript zero;
    zero << OP_0;
    BOOST_CHECK(!ParseSelector(zero));
    // The byte 0x01 pushed as data is not OP_1.
    CScript pushed;
    pushed << valtype{0x01};
    BOOST_CHECK(!ParseSelector(pushed));
    // Not push-only.
    CScript np;
    np << OP_DUP << OP_1;
    BOOST_CHECK(!ParseSelector(np));
    BOOST_CHECK(!ParseSelector(CScript()));
    // Selector not last.
    CScript notlast;
    notlast << OP_1 << sig;
    BOOST_CHECK(!ParseSelector(notlast));
}

BOOST_AUTO_TEST_CASE(template_spend_parse)
{
    CScript vs = BuildVault(SampleVault());
    CScript is = BuildIntent(SampleIntent());
    CScript s4;
    s4 << OP_4;
    auto ts = ParseTemplateSpend(vs, s4);
    BOOST_REQUIRE(ts);
    BOOST_CHECK(ts->kind == TemplateKind::VAULT);
    BOOST_CHECK_EQUAL(ts->selector, 4);
    // Selector 4 on an intent does not parse.
    BOOST_CHECK(!ParseTemplateSpend(is, s4));
    CScript s3;
    s3 << valtype(72, 0x30) << OP_3;
    auto ti = ParseTemplateSpend(is, s3);
    BOOST_REQUIRE(ti);
    BOOST_CHECK(ti->kind == TemplateKind::INTENT);
    BOOST_CHECK_EQUAL(ti->sigs.size(), 1U);
    BOOST_CHECK(!ParseTemplateSpend(GetScriptForDestination(TestKey(3).GetID()), s3));
}

BOOST_AUTO_TEST_CASE(bond_redeem)
{
    CPubKey key = TestKey(4);
    CScript r = BuildBondRedeem(5000, key);
    BOOST_REQUIRE(!r.empty());
    uint32_t lt = 0;
    CPubKey k2;
    BOOST_CHECK(ParseBondRedeem(r, lt, k2));
    BOOST_CHECK_EQUAL(lt, 5000U);
    BOOST_CHECK(k2 == key);
    // <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <key> OP_CHECKSIG
    CScript expect;
    expect << (int64_t)5000 << OP_CHECKLOCKTIMEVERIFY << OP_DROP << ToByteVector(key) << OP_CHECKSIG;
    BOOST_CHECK(r == expect);
    BOOST_CHECK(BondScriptPubKey(5000, key) == GetScriptForDestination(CScriptID(r)));
    BOOST_CHECK(BondScriptPubKey(5000, key).IsPayToScriptHash());

    BOOST_CHECK(BuildBondRedeem(0, key).empty());
    BOOST_CHECK(BuildBondRedeem(500000000, key).empty());
    BOOST_CHECK(BondScriptPubKey(0, key).empty());
    // Small locktime uses OP_N.
    CScript r7 = BuildBondRedeem(7, key);
    BOOST_CHECK_EQUAL(r7[0], (unsigned char)OP_7);
    BOOST_CHECK(ParseBondRedeem(r7, lt, k2) && lt == 7);
    // Non-minimal locktime push.
    valtype b(r7.begin(), r7.end());
    b[0] = 0x07;
    b.insert(b.begin(), 0x01);
    BOOST_CHECK(!ParseBondRedeem(CScript(b.begin(), b.end()), lt, k2));
}

BOOST_AUTO_TEST_SUITE_END()
