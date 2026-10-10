// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The vault primitive's script templates (docs/plans/yellowback-upgrade-plan.md §15.3):
// exact shapes, minimal pushes, field ranges, the selector, the bond redeem script. Owners are
// post-quantum key ids (docs/plans/yellowback-quantum-spec.md §1): the slot <ownerHash:32>
// OP_1|OP_2 OP_CHECKPQSIG is the only owner shape.

#include "vault/template.h"

#include "consensus/upgrades.h"
#include "crypto/pq/scheme.h"
#include "crypto/pq/sign.h"
#include "key.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
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

CPQKeyID TestOwner(unsigned char seed, uint8_t scheme = pq::SCHEME_SLH_DSA_SHA2_128S)
{
    return CPQKeyID(scheme, U(seed));
}

VaultParams SampleVault()
{
    VaultParams p;
    p.tag = {'T', 'E', 'S', 'T'};
    p.cancelSetId = U(0x40);
    p.delay = 5;
    p.setId = U(0x80);
    p.ownerHeight = 1000;
    p.owner = TestOwner(0xa1);
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
    p.owner = TestOwner(0xa2);
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

    // Unregistered owner schemes do not build.
    for (uint8_t scheme : {0, 3, 16, 255}) {
        p = SampleVault();
        p.owner.scheme = scheme;
        BOOST_CHECK(BuildVault(p).empty());
    }
    // Replace the owner's scheme opcode (OP_1, both slots) inside the script: OP_3 / OP_0 are
    // malformed (V-shaped, unregistered scheme), the one-byte push 01 01 is malformed too (rebuild).
    CScript good = BuildVault(SampleVault());
    valtype b(good.begin(), good.end());
    const uint256 ownerHash = SampleVault().owner.hash;
    const valtype hash(ownerHash.begin(), ownerHash.end());
    std::vector<size_t> schemePos;
    for (auto it = std::search(b.begin(), b.end(), hash.begin(), hash.end()); it != b.end();
         it = std::search(it + 1, b.end(), hash.begin(), hash.end())) {
        schemePos.push_back((it - b.begin()) + 32);
    }
    BOOST_REQUIRE_EQUAL(schemePos.size(), 2U);
    for (size_t pos : schemePos) {
        BOOST_CHECK_EQUAL(b[pos], (unsigned char)OP_1);
        BOOST_CHECK_EQUAL(b[pos + 1], 0xc2);
    }
    for (opcodetype op : {OP_3, OP_0, OP_16}) {
        valtype c = b;
        c[schemePos[0]] = op;
        c[schemePos[1]] = op;
        BOOST_CHECK(MatchVault(CScript(c.begin(), c.end()), q) == Shape::MALFORMED);
    }
    {
        CScript pushed = Splice(good, schemePos[1], 1, {0x01, 0x01});
        pushed = Splice(pushed, schemePos[0], 1, {0x01, 0x01});
        BOOST_CHECK(MatchVault(pushed, q) == Shape::MALFORMED);
    }
}

BOOST_AUTO_TEST_CASE(vault_pq_owner_shape)
{
    // Both registered schemes build and parse (A-1: scheme 2 is a template whatever the Falcon flag).
    for (uint8_t scheme : {pq::SCHEME_SLH_DSA_SHA2_128S, pq::SCHEME_FN_DSA_512}) {
        VaultParams p = SampleVault();
        p.owner = TestOwner(0x33, scheme);
        CScript v = BuildVault(p);
        BOOST_REQUIRE(!v.empty());
        VaultParams q;
        BOOST_CHECK(ParseVault(v, q));
        BOOST_CHECK(q == p);
        BOOST_CHECK(q.owner == p.owner);
        IntentParams ip = SampleIntent();
        ip.owner = p.owner;
        CScript i = BuildIntent(ip);
        IntentParams iq;
        BOOST_REQUIRE(!i.empty());
        BOOST_CHECK(ParseIntent(i, iq) && iq.owner == p.owner);
        txnouttype type;
        std::vector<valtype> sol;
        BOOST_CHECK(Solver(v, type, sol) && type == TX_VAULT);
        BOOST_CHECK(Solver(i, type, sol) && type == TX_VAULT_INTENT);
    }

    // Byte layout (quantum spec §1.1, §1.2): the owner slot is 20 <32> 5n c2 (35 bytes), twice in V,
    // at token indices 22..24 and 34..36; setId's second copy at 31, appHeight at 40.
    VaultParams p = SampleVault();
    CScript v = BuildVault(p);
    std::vector<std::pair<opcodetype, valtype>> toks;
    CScript::const_iterator pc = v.begin();
    opcodetype op;
    valtype data;
    while (pc < v.end()) {
        BOOST_REQUIRE(v.GetOp(pc, op, data));
        toks.push_back({op, data});
    }
    BOOST_REQUIRE_EQUAL(toks.size(), 45U);
    const valtype hash(p.owner.hash.begin(), p.owner.hash.end());
    const valtype setId(p.setId.begin(), p.setId.end());
    BOOST_CHECK(toks[22].second == hash);
    BOOST_CHECK_EQUAL(toks[23].first, OP_1);
    BOOST_CHECK_EQUAL(toks[24].first, OP_CHECKPQSIG);
    BOOST_CHECK(toks[31].second == setId);
    BOOST_CHECK(toks[34].second == hash);
    BOOST_CHECK_EQUAL(toks[35].first, OP_1);
    BOOST_CHECK_EQUAL(toks[36].first, OP_CHECKPQSIG);
    BOOST_CHECK_EQUAL(toks[39].first, OP_EQUALVERIFY);
    CScriptNum appHeight(toks[40].second, true, 5);
    BOOST_CHECK_EQUAL(appHeight.getint(), 2000);
    // No OP_CHECKSIG (0xac) opcode anywhere in V (pushes aside).
    for (const auto& t : toks) BOOST_CHECK(t.first != OP_CHECKSIG);

    // Intent: 32 tokens, the owner slot at 27..29.
    IntentParams ip = SampleIntent();
    CScript is = BuildIntent(ip);
    toks.clear();
    pc = is.begin();
    while (pc < is.end()) {
        BOOST_REQUIRE(is.GetOp(pc, op, data));
        toks.push_back({op, data});
    }
    BOOST_REQUIRE_EQUAL(toks.size(), 32U);
    BOOST_CHECK(toks[27].second == valtype(ip.owner.hash.begin(), ip.owner.hash.end()));
    BOOST_CHECK_EQUAL(toks[28].first, OP_1);
    BOOST_CHECK_EQUAL(toks[29].first, OP_CHECKPQSIG);

    // Lengths are unchanged from the EC owner (quantum spec §1.1: V 209..220, I 196..199).
    BOOST_CHECK(v.size() >= 209 && v.size() <= 220);
    BOOST_CHECK(is.size() >= 196 && is.size() <= 199);

    // The two owner slots must agree: hash and scheme.
    valtype b(v.begin(), v.end());
    auto first = std::search(b.begin(), b.end(), hash.begin(), hash.end());
    auto second = std::search(first + 1, b.end(), hash.begin(), hash.end());
    BOOST_REQUIRE(second != b.end());
    VaultParams q;
    {
        valtype c = b;
        c[(second - b.begin()) + 5] ^= 0x01;
        BOOST_CHECK(MatchVault(CScript(c.begin(), c.end()), q) == Shape::MALFORMED);
    }
    {
        valtype c = b;
        c[(second - b.begin()) + 32] = OP_2;
        BOOST_CHECK(MatchVault(CScript(c.begin(), c.end()), q) == Shape::MALFORMED);
    }
}

BOOST_AUTO_TEST_CASE(vault_ec_owner_is_not_a_template)
{
    // Today's (upgrade plan §15.3) owner slot <ownerKey:33> OP_CHECKSIG is not V-shaped any more:
    // the token count differs, so it is Shape::NONE, and Solver leaves it nonstandard.
    VaultParams p = SampleVault();
    const valtype tag(p.tag.begin(), p.tag.end()), setId(p.setId.begin(), p.setId.end()),
        cancel(p.cancelSetId.begin(), p.cancelSetId.end());
    const valtype key = ToByteVector(TestKey(1));
    CScript ec;
    ec << tag << cancel << p.delay << OP_2DROP << OP_DROP;
    ec << OP_DUP << OP_1 << OP_EQUAL << OP_IF;
    ec << OP_DROP << setId << OP_1 << OP_CHECKSETSIG;
    ec << OP_ELSE << OP_DUP << OP_2 << OP_EQUAL << OP_IF;
    ec << OP_DROP << p.ownerHeight << OP_CHECKLOCKTIMEVERIFY << OP_DROP << key << OP_CHECKSIG;
    ec << OP_ELSE << OP_DUP << OP_3 << OP_EQUAL << OP_IF;
    ec << OP_DROP << setId << OP_CHECKSETDORMANT << OP_VERIFY << key << OP_CHECKSIG;
    ec << OP_ELSE << OP_4 << OP_EQUALVERIFY << p.appHeight << OP_CHECKLOCKTIMEVERIFY;
    ec << OP_ENDIF << OP_ENDIF << OP_ENDIF;
    VaultParams q;
    BOOST_CHECK(MatchVault(ec, q) == Shape::NONE);
    txnouttype type;
    std::vector<valtype> sol;
    BOOST_CHECK(!Solver(ec, type, sol));
    BOOST_CHECK_EQUAL(type, TX_NONSTANDARD);
    // A 33-byte "hash" with OP_1 OP_CHECKPQSIG in the slots is V-shaped but malformed.
    CScript v = BuildVault(p);
    valtype b(v.begin(), v.end());
    const valtype hash(p.owner.hash.begin(), p.owner.hash.end());
    std::vector<size_t> at;
    for (auto it = std::search(b.begin(), b.end(), hash.begin(), hash.end()); it != b.end();
         it = std::search(it + 1, b.end(), hash.begin(), hash.end())) {
        at.push_back((it - b.begin()) - 1);
    }
    BOOST_REQUIRE_EQUAL(at.size(), 2U);
    valtype c = b;
    valtype push33 = {0x21};
    push33.insert(push33.end(), key.begin(), key.end());
    c.erase(c.begin() + at[1], c.begin() + at[1] + 33);
    c.insert(c.begin() + at[1], push33.begin(), push33.end());
    c.erase(c.begin() + at[0], c.begin() + at[0] + 33);
    c.insert(c.begin() + at[0], push33.begin(), push33.end());
    BOOST_CHECK(MatchVault(CScript(c.begin(), c.end()), q) == Shape::MALFORMED);
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
    BOOST_CHECK(q.owner == p.owner);
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
    BOOST_CHECK(i.setId == v.setId && i.cancelSetId == v.cancelSetId && i.delay == v.delay && i.owner == v.owner);
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

namespace {

/** <sig_1>..<sig_s> <s> <pk_1>..<pk_p> <p> <selector> (quantum plan §4.2): canonical 520-byte chunks. */
CScript OwnerScriptSig(const valtype& sigWithHashtype, const valtype& pk, int selector)
{
    CScript ss;
    int s = 0, p = 0;
    for (size_t i = 0; i < sigWithHashtype.size(); i += pq::MAX_CHUNK, s++)
        ss << valtype(sigWithHashtype.begin() + i, sigWithHashtype.begin() + std::min(sigWithHashtype.size(), i + pq::MAX_CHUNK));
    ss << CScript::EncodeOP_N(s);
    for (size_t i = 0; i < pk.size(); i += pq::MAX_CHUNK, p++)
        ss << valtype(pk.begin() + i, pk.begin() + std::min(pk.size(), i + pq::MAX_CHUNK));
    ss << CScript::EncodeOP_N(p) << CScript::EncodeOP_N(selector);
    return ss;
}

} // namespace

BOOST_AUTO_TEST_CASE(owner_branch_real_signatures)
{
    // The V's OWNER branch (selector 2: CLTV then OP_CHECKPQSIG) with real SLH-DSA and Falcon keys
    // (crypto/pq/sign.h), through VerifyScript and TransactionSignatureChecker::CheckPQSig.
    const uint32_t branch = NetworkUpgradeInfo[Consensus::UPGRADE_VAULT].nBranchId;
    const unsigned int vaultFlags = STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_VAULT;
    const CAmount amount = 5 * COIN;
    for (uint8_t scheme : {pq::SCHEME_SLH_DSA_SHA2_128S, pq::SCHEME_FN_DSA_512}) {
        valtype pk, sk;
        BOOST_REQUIRE(pq::KeyGen(scheme, valtype(pq::SeedSize(scheme), 0x5a + scheme), pk, sk));
        VaultParams vp = SampleVault();
        vp.owner = CPQKeyID(scheme, pq::KeyHash(scheme, pk));
        const CScript spk = BuildVault(vp);
        BOOST_REQUIRE(!spk.empty());

        CMutableTransaction mtx;
        mtx.fOverwintered = true;
        mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
        mtx.nVersion = SAPLING_TX_VERSION;
        mtx.nLockTime = (uint32_t)vp.ownerHeight;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0x77"), 0), CScript(), CTxIn::SEQUENCE_FINAL - 1));
        mtx.vout.push_back(CTxOut(amount - 10000, GetScriptForDestination(CPQKeyID(scheme, pq::KeyHash(scheme, pk)))));
        const CTransaction unsigned_(mtx);
        const uint256 sighash = SignatureHash(spk, unsigned_, 0, SIGHASH_ALL, amount, branch, PrecomputedTransactionData(unsigned_, {CTxOut(amount, spk)}));
        valtype sig;
        BOOST_REQUIRE(pq::Sign(scheme, sk, sighash, sig));
        sig.push_back(SIGHASH_ALL);
        mtx.vin[0].scriptSig = OwnerScriptSig(sig, pk, SEL_OWNER);
        const CTransaction tx(mtx);
        const PrecomputedTransactionData txdata(tx, {CTxOut(amount, spk)});
        TransactionSignatureChecker checker(&tx, txdata, 0, amount);
        ScriptError err;

        auto sel = ParseSelector(tx.vin[0].scriptSig);
        BOOST_CHECK(sel && *sel == SEL_OWNER);
        if (scheme == pq::SCHEME_SLH_DSA_SHA2_128S) {
            BOOST_CHECK_EQUAL(tx.vin[0].scriptSig.size(), 7939U);           // quantum spec §1.5
            BOOST_CHECK(VerifyScript(tx.vin[0].scriptSig, spk, vaultFlags, checker, branch, &err));
            BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
        } else {
            BOOST_CHECK_EQUAL(tx.vin[0].scriptSig.size(), 1578U);
            // Falcon is SCRIPT_ERR_PQ_SCHEME without SCRIPT_VERIFY_PQ_FALCON, valid with it (A-1)
            BOOST_CHECK(!VerifyScript(tx.vin[0].scriptSig, spk, vaultFlags, checker, branch, &err));
            BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQ_SCHEME);
            BOOST_CHECK(VerifyScript(tx.vin[0].scriptSig, spk, vaultFlags | SCRIPT_VERIFY_PQ_FALCON, checker, branch, &err));
            BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
        }
        const unsigned int okFlags = vaultFlags | SCRIPT_VERIFY_PQ_FALCON;
        // before the upgrade: OP_CHECKPQSIG is a bad opcode (the V's own 0xc0 is skipped in a false branch)
        BOOST_CHECK(!VerifyScript(tx.vin[0].scriptSig, spk, STANDARD_SCRIPT_VERIFY_FLAGS, checker, branch, &err));
        // another owner's V: the key hash does not match, OP_CHECKPQSIG pushes false
        VaultParams other = vp;
        other.owner.hash = uint256S("0x1234");
        BOOST_CHECK(!VerifyScript(tx.vin[0].scriptSig, BuildVault(other), okFlags, checker, branch, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);
        // the same key under the other scheme id is another owner
        other = vp;
        other.owner.scheme = scheme == pq::SCHEME_SLH_DSA_SHA2_128S ? pq::SCHEME_FN_DSA_512 : pq::SCHEME_SLH_DSA_SHA2_128S;
        BOOST_CHECK(!VerifyScript(tx.vin[0].scriptSig, BuildVault(other), okFlags, checker, branch, &err));
        // CLTV: nLockTime below ownerHeight fails
        CMutableTransaction early = mtx;
        early.nLockTime = (uint32_t)vp.ownerHeight - 1;
        const CTransaction etx(early);
        const PrecomputedTransactionData etxdata(etx, {CTxOut(amount, spk)});
        TransactionSignatureChecker echecker(&etx, etxdata, 0, amount);
        BOOST_CHECK(!VerifyScript(etx.vin[0].scriptSig, spk, okFlags, echecker, branch, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        // a tampered signature byte
        valtype bad = sig;
        bad[7] ^= 0x01;
        CMutableTransaction tampered = mtx;
        tampered.vin[0].scriptSig = OwnerScriptSig(bad, pk, SEL_OWNER);
        const CTransaction ttx(tampered);
        const PrecomputedTransactionData ttxdata(ttx, {CTxOut(amount, spk)});
        TransactionSignatureChecker tchecker(&ttx, ttxdata, 0, amount);
        BOOST_CHECK(!VerifyScript(ttx.vin[0].scriptSig, spk, okFlags, tchecker, branch, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);
    }
}

BOOST_AUTO_TEST_SUITE_END()
