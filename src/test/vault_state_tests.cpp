// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Signer-set state and the template rules on synthetic blocks over an in-memory base
// (docs/plans/yellowback-upgrade-plan.md §15.4-§15.6): join, admission, maturity,
// heartbeat, dormancy, release, wind-down, removal, equivocation, bonds, rate epochs,
// covenants, S-1, undo, the DB and the checker.

#include "vault/act.h"
#include "vault/checker.h"
#include "vault/db.h"
#include "vault/module.h"
#include "vault/node.h"
#include "vault/state.h"
#include "vault/template.h"

#include "chain.h"
#include "key.h"
#include "primitives/block.h"
#include "script/interpreter.h"
#include "script/standard.h"
#include "test/test_bitcoin.h"
#include "undo.h"

#include <boost/test/unit_test.hpp>

using namespace vault;

namespace {

typedef std::vector<unsigned char> valtype;

CKey MakeKey(unsigned char seed)
{
    CKey k;
    std::vector<unsigned char> secret(32, 0);
    secret[0] = 0x33;
    secret[31] = seed;
    k.Set(secret.begin(), secret.end(), true);
    return k;
}

SetCreateBody Params(bool open)
{
    SetCreateBody c;
    c.seats = 5;
    c.unlockThreshold = 2;
    c.cancelThreshold = 1;
    c.slashThreshold = 2;
    c.flags = open ? SET_FLAG_OPEN : 0;
    c.rateLimitBps = 0;
    c.rateWindow = 100;
    c.livenessWindow = 50;
    c.bondMin = 1000;
    c.bondLockMin = 10;
    c.maturity = 5;
    c.admitKey = MakeKey(200).GetPubKey();
    return c;
}

/** A rule result: *r is the reject reason, or "OK". */
struct Res {
    std::optional<std::string> e;
    Res(std::optional<std::string> e) : e(std::move(e)) {}
    Res(std::nullopt_t) {}
    std::string operator*() const { return e ? *e : std::string("OK"); }
    explicit operator bool() const { return e.has_value(); }
    bool operator!() const { return !e.has_value(); }
};

/** A tiny chain: an in-memory base, coins for every output created, one VaultState per block. */
struct Chain {
    MemoryKV kv;
    MapCoinAccessor coins;
    int64_t h = 100;
    uint32_t fundCounter = 0;
    std::vector<std::pair<std::map<std::string, std::string>, BlockUndo>> history;

    COutPoint Fund(CAmount value = 10 * COIN)
    {
        uint256 hash;
        ++fundCounter;
        for (int i = 0; i < 4; i++) hash.begin()[i] = (fundCounter >> (8 * i)) & 0xff;
        hash.begin()[31] = 0xfe;
        COutPoint op(hash, 0);
        SpentCoin c;
        c.scriptPubKey = GetScriptForDestination(MakeKey(250).GetPubKey().GetID());
        c.value = value;
        c.height = 1;
        coins.coins[op] = c;
        return op;
    }

    /** Apply a block of transactions at height h; on success commit and advance h. */
    Res Block(const std::vector<CMutableTransaction>& txs)
    {
        CBlock block;
        for (const auto& m : txs) block.vtx.push_back(CTransaction(m));
        VaultState st(kv);
        BlockUndo undo;
        auto err = st.ApplyBlock(block, h, coins, undo);
        if (err) return err;
        history.emplace_back(kv.data, undo);
        kv.Apply(st.Changes());
        for (const auto& tx : block.vtx) {
            for (size_t o = 0; o < tx.vout.size(); o++) {
                SpentCoin c;
                c.scriptPubKey = tx.vout[o].scriptPubKey;
                c.value = tx.vout[o].nValue;
                c.height = h;
                coins.coins[COutPoint(tx.GetHash(), o)] = c;
            }
        }
        h++;
        return std::nullopt;
    }
    Res Block1(const CMutableTransaction& tx) { return Block({tx}); }
    void Empty(int n)
    {
        for (int i = 0; i < n; i++) BOOST_REQUIRE(!Block({}));
    }
    /** Reject check that does not advance. */
    Res Try(const CMutableTransaction& tx)
    {
        VaultState st(kv);
        return st.ApplyTx(CTransaction(tx), h, coins);
    }
};

/** A transaction carrying one act, signed by `signers` over actMsg; extra outputs first. */
CMutableTransaction ActTx(Chain& c, Act act, const std::vector<CKey>& signers, const std::vector<CTxOut>& extra = {})
{
    CMutableTransaction m;
    m.vin.push_back(CTxIn(c.Fund(), CScript(), 0xffffffff));
    m.vout = extra;
    valtype P = EncodePayload(act);
    uint256 msg = ActMsg(P, m.vin[0].prevout);
    act.sigs.clear();
    for (const CKey& k : signers) {
        valtype sig;
        BOOST_REQUIRE(SignRecoverable(k, msg, sig));
        act.sigs.push_back(sig);
    }
    m.vout.push_back(CTxOut(0, EncodeAct(act)));
    return m;
}

SetId CreateSet(Chain& c, const SetCreateBody& p)
{
    Act a;
    a.type = ACT_SET_CREATE;
    a.create = p;
    CMutableTransaction m = ActTx(c, a, {});
    BOOST_REQUIRE(!c.Block1(m));
    return CTransaction(m).GetHash();
}

CMutableTransaction JoinTx(Chain& c, const SetId& setId, const CKey& member, const std::vector<CKey>& cosigners,
                           CAmount bond = 1000, int64_t locktimeAhead = 1000)
{
    Act a;
    a.type = ACT_SET_JOIN;
    a.join.setId = setId;
    a.join.memberKey = member.GetPubKey();
    a.join.bondLocktime = (uint32_t)(c.h + locktimeAhead);
    a.join.bondVout = 0;
    std::vector<CKey> signers = {member};
    signers.insert(signers.end(), cosigners.begin(), cosigners.end());
    return ActTx(c, a, signers, {CTxOut(bond, BondScriptPubKey(a.join.bondLocktime, member.GetPubKey()))});
}

CMutableTransaction HeartbeatTx(Chain& c, const SetId& setId, const CKey& member)
{
    Act a;
    a.type = ACT_SET_HEARTBEAT;
    a.heartbeat.setId = setId;
    a.heartbeat.memberKey = member.GetPubKey();
    return ActTx(c, a, {member});
}

CMutableTransaction RemoveTx(Chain& c, const SetId& setId, const CPubKey& target, bool burn, const std::vector<CKey>& signers)
{
    Act a;
    a.type = ACT_SET_REMOVE;
    a.remove.setId = setId;
    a.remove.memberKey = target;
    a.remove.burn = burn ? 1 : 0;
    return ActTx(c, a, signers);
}

CMutableTransaction WindDownTx(Chain& c, const SetId& setId, const std::vector<CKey>& signers)
{
    Act a;
    a.type = ACT_SET_WINDDOWN;
    a.winddown.setId = setId;
    return ActTx(c, a, signers);
}

/** A spend of `prevout` with scriptSig `<dummy sig>... <selector>` and the given outputs. */
CMutableTransaction SpendTx(Chain& c, const COutPoint& prevout, int selector, const std::vector<CTxOut>& outs, bool fee = true)
{
    CMutableTransaction m;
    CScript sig;
    sig << valtype(65, 0x20) << CScript::EncodeOP_N(selector);
    m.vin.push_back(CTxIn(prevout, sig, 0xfffffffe));
    if (fee) m.vin.push_back(CTxIn(c.Fund(), CScript() << valtype(72, 1), 0xffffffff));
    m.vout = outs;
    return m;
}

VaultParams VaultFor(const SetId& setId, const CKey& owner, int64_t appHeight = 0)
{
    VaultParams v;
    v.tag = {'T', 'E', 'S', 'T'};
    v.setId = setId;
    v.cancelSetId = setId;
    v.delay = 5;
    v.ownerHeight = 100000;
    v.ownerKey = owner.GetPubKey();
    v.appHeight = appHeight;
    return v;
}

COutPoint FindOut(const CMutableTransaction& m, const CScript& spk)
{
    CTransaction tx(m);
    for (size_t o = 0; o < tx.vout.size(); o++) {
        if (tx.vout[o].scriptPubKey == spk) return COutPoint(tx.GetHash(), o);
    }
    BOOST_FAIL("output not found");
    return COutPoint();
}

/** Lock `value` in a new vault; returns its outpoint. */
COutPoint Lock(Chain& c, const VaultParams& v, CAmount value)
{
    CMutableTransaction m;
    m.vin.push_back(CTxIn(c.Fund(value + COIN), CScript(), 0xffffffff));
    m.vout.push_back(CTxOut(value, BuildVault(v)));
    auto err = c.Block1(m);
    BOOST_REQUIRE_MESSAGE(!err, (err ? *err : std::string()));
    return COutPoint(CTransaction(m).GetHash(), 0);
}

CScript Recipient(unsigned char seed) { return GetScriptForDestination(MakeKey(seed).GetPubKey().GetID()); }

MemberRecord Member(const Chain& c, const SetId& s, const CKey& k)
{
    auto m = GetMember(c.kv, s, k.GetPubKey());
    BOOST_REQUIRE(m);
    return *m;
}

/** A set with members k[0..n-1] joined (open set) and matured. */
SetId SetWithMembers(Chain& c, const std::vector<CKey>& members, SetCreateBody p = Params(true))
{
    p.flags |= SET_FLAG_OPEN;
    SetId s = CreateSet(c, p);
    for (const CKey& k : members) {
        auto err = c.Block1(JoinTx(c, s, k, {}));
        BOOST_REQUIRE_MESSAGE(!err, (err ? *err : std::string()));
    }
    c.Empty(p.maturity);
    return s;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(vault_state_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(create_set)
{
    Chain c;
    SetId s = CreateSet(c, Params(false));
    auto rec = GetSet(c.kv, s);
    BOOST_REQUIRE(rec);
    BOOST_CHECK_EQUAL(rec->createHeight, 100);
    BOOST_CHECK_EQUAL(rec->params.seats, 5);
    BOOST_CHECK_EQUAL(rec->windDownHeight, 0);
    BOOST_CHECK_EQUAL(ListSets(c.kv).size(), 1U);

    Act a;
    a.type = ACT_SET_CREATE;
    a.create = Params(false);
    a.create.seats = 0;
    BOOST_CHECK_EQUAL(*c.Try(ActTx(c, a, {})), "bad-vault-act-params");
    a.create = Params(false);
    BOOST_CHECK_EQUAL(*c.Try(ActTx(c, a, {MakeKey(1)})), "bad-vault-act-sigs");

    // In a coinbase: refused.
    CMutableTransaction cb;
    cb.vin.push_back(CTxIn());
    cb.vout.push_back(CTxOut(0, EncodeAct(a)));
    BOOST_CHECK(CTransaction(cb).IsCoinBase());
    BOOST_CHECK_EQUAL(*c.Try(cb), "bad-vault-act-coinbase");
    // A transaction with two YV outputs.
    CMutableTransaction two = ActTx(c, a, {});
    two.vout.push_back(two.vout.back());
    BOOST_CHECK_EQUAL(*c.Try(two), "bad-vault-act-multi");
    // An unknown type.
    CMutableTransaction unk = ActTx(c, a, {});
    unk.vout.back().scriptPubKey = CScript() << OP_RETURN << valtype{'Y', 'V', 1, 9};
    BOOST_CHECK_EQUAL(*c.Try(unk), "bad-vault-act-type");
}

BOOST_AUTO_TEST_CASE(join_open)
{
    Chain c;
    CKey k1 = MakeKey(1), k2 = MakeKey(2);
    Act a;
    a.type = ACT_SET_CREATE;
    a.create = Params(true);
    CMutableTransaction create = ActTx(c, a, {});
    SetId s = CTransaction(create).GetHash();
    // A join in the creating block sees no set (created in an earlier block only).
    BOOST_CHECK_EQUAL(*c.Block({create, JoinTx(c, s, k1, {})}), "bad-vault-act-noset");
    BOOST_REQUIRE(!c.Block1(create));

    // Bond checks.
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s, k1, {}, 999)), "bad-vault-act-bond");
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s, k1, {}, 1000, 9)), "bad-vault-act-bond"); // < h + bondLockMin
    CMutableTransaction wrongBond = JoinTx(c, s, k1, {});
    wrongBond.vout[0].scriptPubKey = Recipient(5);
    BOOST_CHECK_EQUAL(*c.Try(wrongBond), "bad-vault-act-bond");
    // The member must sign first; an open set takes no second signature.
    Act j;
    j.type = ACT_SET_JOIN;
    j.join.setId = s;
    j.join.memberKey = k1.GetPubKey();
    j.join.bondLocktime = (uint32_t)(c.h + 1000);
    j.join.bondVout = 0;
    CTxOut bondOut(1000, BondScriptPubKey(j.join.bondLocktime, k1.GetPubKey()));
    BOOST_CHECK_EQUAL(*c.Try(ActTx(c, j, {k2}, {bondOut})), "bad-vault-act-sig");
    BOOST_CHECK_EQUAL(*c.Try(ActTx(c, j, {k1, k2}, {bondOut})), "bad-vault-act-sigs");
    j.join.bondVout = 5;
    BOOST_CHECK_EQUAL(*c.Try(ActTx(c, j, {k1}, {bondOut})), "bad-vault-act-bond");

    CMutableTransaction join = JoinTx(c, s, k1, {});
    BOOST_REQUIRE(!c.Block1(join));
    MemberRecord m = Member(c, s, k1);
    BOOST_CHECK_EQUAL(m.status, MEMBER_ACTIVE);
    BOOST_CHECK_EQUAL(m.joinHeight, 101);
    BOOST_CHECK_EQUAL(m.lastAct, 101 + 5);
    BOOST_CHECK_EQUAL(m.bondValue, 1000);
    BOOST_CHECK(m.bondOutpoint == COutPoint(CTransaction(join).GetHash(), 0));
    auto bond = GetBond(c.kv, m.bondOutpoint);
    BOOST_REQUIRE(bond);
    BOOST_CHECK(bond->setId == s && bond->memberKey == k1.GetPubKey() && !bond->frozen);
    // Joining again while ACTIVE.
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s, k1, {})), "bad-vault-act-join");
}

BOOST_AUTO_TEST_CASE(join_seats)
{
    Chain c;
    SetCreateBody p = Params(true);
    p.seats = 2;
    p.unlockThreshold = p.cancelThreshold = p.slashThreshold = 1;
    SetId s = CreateSet(c, p);
    BOOST_REQUIRE(!c.Block1(JoinTx(c, s, MakeKey(1), {})));
    BOOST_REQUIRE(!c.Block1(JoinTx(c, s, MakeKey(2), {})));
    // Immature members hold seats too.
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s, MakeKey(3), {})), "bad-vault-act-seats");
}

BOOST_AUTO_TEST_CASE(admission_closed)
{
    Chain c;
    CKey admit = MakeKey(200), k1 = MakeKey(1), k2 = MakeKey(2), k3 = MakeKey(3), k4 = MakeKey(4);
    SetId s = CreateSet(c, Params(false)); // slashThreshold 2, maturity 5
    // Fewer than slashThreshold current members: the admit key admits.
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s, k1, {})), "bad-vault-act-sigs");
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s, k1, {k2})), "bad-vault-act-sigs");
    BOOST_REQUIRE(!c.Block1(JoinTx(c, s, k1, {admit})));
    BOOST_REQUIRE(!c.Block1(JoinTx(c, s, k2, {admit})));
    // k1, k2 not mature yet: still the admit key.
    BOOST_REQUIRE(!c.Block1(JoinTx(c, s, k3, {admit})));
    c.Empty(5);
    // Now three current members ≥ slashThreshold: two of them must admit, the admit key no longer can.
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s, k4, {admit})), "bad-vault-act-sigs");
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s, k4, {k1})), "bad-vault-act-sigs");
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s, k4, {k1, k1})), "bad-vault-act-sigs");
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s, k4, {k1, admit})), "bad-vault-act-sigs");
    BOOST_CHECK(!c.Block1(JoinTx(c, s, k4, {k1, k2})));
}

BOOST_AUTO_TEST_CASE(maturity_heartbeat_dormancy)
{
    Chain c;
    CKey k1 = MakeKey(1);
    SetId s = CreateSet(c, Params(true)); // maturity 5, liveness 50, cancelThreshold 1
    BOOST_REQUIRE(!c.Block1(JoinTx(c, s, k1, {}))); // joined at 101
    SetSnapshot snap(c.kv);
    BOOST_CHECK(!snap.IsCurrentMember(s, k1.GetPubKey(), 105));
    BOOST_CHECK(snap.IsCurrentMember(s, k1.GetPubKey(), 106));
    BOOST_CHECK(snap.IsDormant(s, 105));      // no current member yet
    BOOST_CHECK(!snap.IsDormant(s, 106));
    BOOST_CHECK(!snap.IsDormant(s, 156));     // lastAct 106 ≥ 156 − 50
    BOOST_CHECK(snap.IsDormant(s, 157));
    BOOST_CHECK(snap.IsReleased(s, 157));
    BOOST_CHECK(!snap.IsReleased(s, 156));
    BOOST_CHECK(*snap.Threshold(s, ROLE_UNLOCK) == 2);
    BOOST_CHECK(*snap.Threshold(s, ROLE_CANCEL) == 1);
    BOOST_CHECK(!snap.Threshold(s, 3));
    BOOST_CHECK(!snap.Threshold(uint256(), 1));
    // Unknown sets are released, not dormant.
    BOOST_CHECK(snap.IsReleased(uint256(), 100));
    BOOST_CHECK(!snap.IsDormant(uint256(), 100));

    // Heartbeat while immature is refused.
    BOOST_CHECK_EQUAL(*c.Try(HeartbeatTx(c, s, k1)), "bad-vault-act-heartbeat"); // h = 102
    BOOST_CHECK_EQUAL(*c.Try(HeartbeatTx(c, s, MakeKey(9))), "bad-vault-act-heartbeat");
    // Signed by someone else.
    Act hb;
    hb.type = ACT_SET_HEARTBEAT;
    hb.heartbeat.setId = s;
    hb.heartbeat.memberKey = k1.GetPubKey();
    BOOST_CHECK_EQUAL(*c.Try(ActTx(c, hb, {MakeKey(9)})), "bad-vault-act-sig");
    c.Empty(60); // h = 162: dormant
    BOOST_CHECK(SetSnapshot(c.kv).IsDormant(s, c.h));
    BOOST_REQUIRE(!c.Block1(HeartbeatTx(c, s, k1))); // at 162
    BOOST_CHECK_EQUAL(Member(c, s, k1).lastAct, 162);
    SetSnapshot snap2(c.kv);
    BOOST_CHECK(!snap2.IsDormant(s, 163));
    BOOST_CHECK(!snap2.IsDormant(s, 212));
    BOOST_CHECK(snap2.IsDormant(s, 213));
}

BOOST_AUTO_TEST_CASE(winddown_release)
{
    Chain c;
    CKey k1 = MakeKey(1), k2 = MakeKey(2), k3 = MakeKey(3);
    SetId s = SetWithMembers(c, {k1, k2});
    BOOST_CHECK_EQUAL(*c.Try(WindDownTx(c, s, {k1})), "bad-vault-act-sigs");
    BOOST_CHECK_EQUAL(*c.Try(WindDownTx(c, s, {k1, k3})), "bad-vault-act-sigs");
    int64_t wd = c.h;
    BOOST_REQUIRE(!c.Block1(WindDownTx(c, s, {k1, k2})));
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->windDownHeight, wd);
    BOOST_CHECK_EQUAL(*c.Try(WindDownTx(c, s, {k1, k2})), "bad-vault-act-winddown");
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s, k3, {})), "bad-vault-act-winddown");
    // Keep the set live so only the wind-down releases it.
    BOOST_REQUIRE(!c.Block1(HeartbeatTx(c, s, k1)));
    SetSnapshot snap(c.kv);
    BOOST_CHECK(!snap.IsReleased(s, wd + 49));
    BOOST_CHECK(snap.IsReleased(s, wd + 50));
    BOOST_CHECK(!snap.IsDormant(s, wd + 50));
}

BOOST_AUTO_TEST_CASE(remove_without_and_with_burn)
{
    Chain c;
    CKey k1 = MakeKey(1), k2 = MakeKey(2), k3 = MakeKey(3);
    SetId s = SetWithMembers(c, {k1, k2, k3});
    // The target cannot sign its own removal; signers must be current and distinct.
    BOOST_CHECK_EQUAL(*c.Try(RemoveTx(c, s, k3.GetPubKey(), false, {k1, k3})), "bad-vault-act-sigs");
    BOOST_CHECK_EQUAL(*c.Try(RemoveTx(c, s, k3.GetPubKey(), false, {k1, k1})), "bad-vault-act-sigs");
    BOOST_CHECK_EQUAL(*c.Try(RemoveTx(c, s, k3.GetPubKey(), false, {k1})), "bad-vault-act-sigs");
    BOOST_CHECK_EQUAL(*c.Try(RemoveTx(c, s, MakeKey(9).GetPubKey(), false, {k1, k2})), "bad-vault-act-remove");

    // burn = 0 (O-6): REMOVED, bond returned (spendable).
    BOOST_REQUIRE(!c.Block1(RemoveTx(c, s, k3.GetPubKey(), false, {k1, k2})));
    MemberRecord m3 = Member(c, s, k3);
    BOOST_CHECK_EQUAL(m3.status, MEMBER_REMOVED);
    BOOST_CHECK(!m3.bondFrozen);
    BOOST_CHECK(!SetSnapshot(c.kv).IsCurrentMember(s, k3.GetPubKey(), c.h));
    BOOST_CHECK_EQUAL(*c.Try(RemoveTx(c, s, k3.GetPubKey(), false, {k1, k2})), "bad-vault-act-remove");
    CMutableTransaction spend3 = SpendTx(c, m3.bondOutpoint, 1, {CTxOut(900, Recipient(7))}, false);
    BOOST_REQUIRE(!c.Block1(spend3));
    BOOST_CHECK(!GetBond(c.kv, m3.bondOutpoint));
    BOOST_CHECK_EQUAL(Member(c, s, k3).status, MEMBER_REMOVED); // not WITHDRAWN: it was not ACTIVE

    // burn = 1: REMOVED and the bond frozen; spending it is invalid.
    CKey k4 = MakeKey(4);
    BOOST_REQUIRE(!c.Block1(JoinTx(c, s, k4, {})));
    c.Empty(5);
    BOOST_REQUIRE(!c.Block1(RemoveTx(c, s, k4.GetPubKey(), true, {k1, k2})));
    MemberRecord m4 = Member(c, s, k4);
    BOOST_CHECK_EQUAL(m4.status, MEMBER_REMOVED);
    BOOST_CHECK(m4.bondFrozen);
    BOOST_CHECK(!!GetBond(c.kv, m4.bondOutpoint)->frozen);
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, m4.bondOutpoint, 1, {CTxOut(900, Recipient(7))})), "bad-vault-bond-frozen");

    // burn must be 0 or 1.
    CKey k5 = MakeKey(5);
    Act r;
    r.type = ACT_SET_REMOVE;
    r.remove.setId = s;
    r.remove.memberKey = k1.GetPubKey();
    r.remove.burn = 2;
    BOOST_CHECK_EQUAL(*c.Try(ActTx(c, r, {k2, k5})), "bad-vault-act-params");
}

BOOST_AUTO_TEST_CASE(equivocation)
{
    Chain c;
    CKey k1 = MakeKey(1), k2 = MakeKey(2);
    SetId s = SetWithMembers(c, {k1, k2});
    COutPoint spent(uint256S("0x1234"), 3);
    uint256 shA = uint256S("0xaa"), shB = uint256S("0xbb");

    auto proof = [&](const CKey& signer, uint8_t roleA, const uint256& a, uint8_t roleB, const uint256& b) {
        Act e;
        e.type = ACT_SET_EQUIVOCATION;
        e.equivocation.setId = s;
        e.equivocation.prevout = spent;
        e.equivocation.roleA = roleA;
        e.equivocation.sighashA = a;
        e.equivocation.roleB = roleB;
        e.equivocation.sighashB = b;
        BOOST_REQUIRE(SignRecoverable(signer, SetSigMsg(s, roleA, spent, a), e.equivocation.sigA));
        BOOST_REQUIRE(SignRecoverable(signer, SetSigMsg(s, roleB, spent, b), e.equivocation.sigB));
        return e;
    };

    // Same (role, sighash) twice is not equivocation.
    BOOST_CHECK_EQUAL(*c.Try(ActTx(c, proof(k1, 1, shA, 1, shA), {})), "bad-vault-act-equivocation");
    // Two keys.
    Act mixed = proof(k1, 1, shA, 1, shB);
    Act fromK2 = proof(k2, 1, shA, 1, shB);
    mixed.equivocation.sigB = fromK2.equivocation.sigB;
    BOOST_CHECK_EQUAL(*c.Try(ActTx(c, mixed, {})), "bad-vault-act-equivocation");
    // A non-member.
    BOOST_CHECK_EQUAL(*c.Try(ActTx(c, proof(MakeKey(9), 1, shA, 1, shB), {})), "bad-vault-act-equivocation");
    // A bad role.
    BOOST_CHECK_EQUAL(*c.Try(ActTx(c, proof(k1, 3, shA, 1, shB), {})), "bad-vault-act-params");
    // Signed by the submitter: none expected.
    BOOST_CHECK_EQUAL(*c.Try(ActTx(c, proof(k1, 1, shA, 1, shB), {k2})), "bad-vault-act-sigs");

    // Unlock vs cancel on one outpoint, by k1: EJECTED, bond frozen.
    BOOST_REQUIRE(!c.Block1(ActTx(c, proof(k1, 1, shA, 2, shA), {})));
    MemberRecord m = Member(c, s, k1);
    BOOST_CHECK_EQUAL(m.status, MEMBER_EJECTED);
    BOOST_CHECK(m.bondFrozen);
    BOOST_CHECK(!!GetBond(c.kv, m.bondOutpoint)->frozen);
    BOOST_CHECK(!SetSnapshot(c.kv).IsCurrentMember(s, k1.GetPubKey(), c.h));
    // Again: the bond is already frozen.
    BOOST_CHECK_EQUAL(*c.Try(ActTx(c, proof(k1, 1, shA, 1, shB), {})), "bad-vault-act-equivocation");
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, m.bondOutpoint, 1, {CTxOut(900, Recipient(7))})), "bad-vault-bond-frozen");
}

BOOST_AUTO_TEST_CASE(withdraw_and_rejoin)
{
    Chain c;
    CKey k1 = MakeKey(1), k2 = MakeKey(2);
    SetId s = SetWithMembers(c, {k1, k2});
    MemberRecord m = Member(c, s, k1);
    BOOST_REQUIRE(!c.Block1(SpendTx(c, m.bondOutpoint, 1, {CTxOut(900, Recipient(7))}, false)));
    BOOST_CHECK_EQUAL(Member(c, s, k1).status, MEMBER_WITHDRAWN);
    BOOST_CHECK(!GetBond(c.kv, m.bondOutpoint));
    BOOST_CHECK_EQUAL(CountActive(GetMembers(c.kv, s)), 1);
    // A withdrawn member's old proof no longer slashes (bond spent).
    Act e;
    e.type = ACT_SET_EQUIVOCATION;
    e.equivocation.setId = s;
    e.equivocation.prevout = COutPoint(uint256S("0x99"), 0);
    e.equivocation.roleA = 1;
    e.equivocation.sighashA = uint256S("0x01");
    e.equivocation.roleB = 1;
    e.equivocation.sighashB = uint256S("0x02");
    SignRecoverable(k1, SetSigMsg(s, 1, e.equivocation.prevout, e.equivocation.sighashA), e.equivocation.sigA);
    SignRecoverable(k1, SetSigMsg(s, 1, e.equivocation.prevout, e.equivocation.sighashB), e.equivocation.sigB);
    BOOST_CHECK_EQUAL(*c.Try(ActTx(c, e, {})), "bad-vault-act-equivocation");
    // Rejoin with a new bond.
    BOOST_REQUIRE(!c.Block1(JoinTx(c, s, k1, {})));
    BOOST_CHECK_EQUAL(Member(c, s, k1).status, MEMBER_ACTIVE);
    BOOST_CHECK_EQUAL(Member(c, s, k1).joinHeight, c.h - 1);
}

BOOST_AUTO_TEST_CASE(vault_create_rules)
{
    Chain c;
    CKey owner = MakeKey(50);
    Act a;
    a.type = ACT_SET_CREATE;
    a.create = Params(true);
    CMutableTransaction create = ActTx(c, a, {});
    SetId s = CTransaction(create).GetHash();
    // V-1: a vault under a set created in the same block is invalid.
    CMutableTransaction lock;
    lock.vin.push_back(CTxIn(c.Fund(), CScript(), 0xffffffff));
    lock.vout.push_back(CTxOut(5000, BuildVault(VaultFor(s, owner))));
    BOOST_CHECK_EQUAL(*c.Block({create, lock}), "bad-txns-vault-noset");
    BOOST_REQUIRE(!c.Block1(create));
    // Unknown set / cancel set.
    VaultParams bad = VaultFor(s, owner);
    bad.cancelSetId = uint256S("0x77");
    CMutableTransaction lockBad = lock;
    lockBad.vout[0].scriptPubKey = BuildVault(bad);
    BOOST_CHECK_EQUAL(*c.Try(lockBad), "bad-txns-vault-noset");
    // A V-shaped output outside the field ranges.
    CScript v = BuildVault(VaultFor(s, owner));
    valtype b(v.begin(), v.end());
    b[5 + 33] = OP_0; // delay 0
    CMutableTransaction lockMal = lock;
    lockMal.vout[0].scriptPubKey = CScript(b.begin(), b.end());
    BOOST_CHECK_EQUAL(*c.Try(lockMal), "bad-txns-vault-malformed");
    // I-0: an intent output outside an UNLOCK/APP spend.
    CMutableTransaction lockI = lock;
    lockI.vout[0].scriptPubKey = BuildIntent(IntentFor(VaultFor(s, owner), v, Recipient(1)));
    BOOST_CHECK_EQUAL(*c.Try(lockI), "bad-txns-vault-intent");
    // Valid: lockedValue grows.
    BOOST_REQUIRE(!c.Block1(lock));
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->lockedValue, 5000);
}

BOOST_AUTO_TEST_CASE(unlock_release_cancel)
{
    Chain c;
    CKey owner = MakeKey(50);
    SetId s = SetWithMembers(c, {MakeKey(1), MakeKey(2)});
    VaultParams vp = VaultFor(s, owner, /*appHeight=*/0);
    CScript vspk = BuildVault(vp);
    COutPoint vout = Lock(c, vp, 10000);
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->lockedValue, 10000);

    CScript recipient = Recipient(60);
    CScript ispk = BuildIntent(IntentFor(vp, vspk, recipient));

    // S-2: value leaves to an ordinary output.
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, vout, 1, {CTxOut(10000, recipient)})), "bad-txns-vault-value");
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, vout, 1, {CTxOut(9999, ispk), CTxOut(1, recipient)})), "bad-txns-vault-value");
    // S-2: an intent with the wrong vault hash.
    IntentParams wrong = IntentFor(vp, vspk, recipient);
    wrong.vaultHash = uint256S("0x01");
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, vout, 1, {CTxOut(10000, BuildIntent(wrong))})), "bad-txns-vault-covenant");
    // S-2: an intent with a different delay.
    IntentParams wrongDelay = IntentFor(vp, vspk, recipient);
    wrongDelay.delay = 6;
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, vout, 1, {CTxOut(10000, BuildIntent(wrongDelay))})), "bad-txns-vault-covenant");
    // S-2: a re-lock into a different vault.
    VaultParams other = vp;
    other.ownerHeight = 99999;
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, vout, 1, {CTxOut(10000, BuildVault(other))})), "bad-txns-vault-covenant");
    // S-4: APP disabled.
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, vout, 4, {CTxOut(10000, ispk)})), "bad-txns-vault-app");
    // S-1: bad selector / not push-only.
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, vout, 5, {CTxOut(10000, ispk)})), "bad-txns-vault-selector");
    CMutableTransaction np = SpendTx(c, vout, 1, {CTxOut(10000, ispk)});
    np.vin[0].scriptSig = CScript() << OP_DUP << OP_1;
    BOOST_CHECK_EQUAL(*c.Try(np), "bad-txns-vault-selector");
    // I-0 holds for owner spends: selector 2 cannot create an intent.
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, vout, 2, {CTxOut(10000, ispk)})), "bad-txns-vault-intent");

    // Unlock: 4000 to an intent, 6000 re-locked, plus an ordinary change output and an OP_RETURN.
    CMutableTransaction unlock = SpendTx(c, vout, 1, {CTxOut(4000, ispk), CTxOut(6000, vspk), CTxOut(500, Recipient(61)),
                                                      CTxOut(0, CScript() << OP_RETURN << valtype{1, 2})});
    BOOST_REQUIRE(!c.Block1(unlock));
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->lockedValue, 6000);
    COutPoint iout = FindOut(unlock, ispk);
    COutPoint relock = FindOut(unlock, vspk);
    const int64_t ih = c.h - 1;

    // I-1: release must pay the recipient at least the intent's value.
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, iout, 1, {CTxOut(3999, recipient)})), "bad-txns-vault-release");
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, iout, 1, {CTxOut(4000, Recipient(62))})), "bad-txns-vault-release");
    // Selector 4 is not an intent branch.
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, iout, 4, {CTxOut(4000, recipient)})), "bad-txns-vault-selector");
    // S-1: two template inputs.
    CMutableTransaction both = SpendTx(c, iout, 1, {CTxOut(4000, recipient)});
    both.vin.push_back(CTxIn(relock, CScript() << OP_2, 0xffffffff));
    BOOST_CHECK_EQUAL(*c.Try(both), "bad-txns-vault-multi");
    BOOST_CHECK(!c.Try(SpendTx(c, iout, 1, {CTxOut(4000, recipient)})));
    // I-3: selector 3 has no template rule (script only).
    BOOST_CHECK(!c.Try(SpendTx(c, iout, 3, {CTxOut(4000, Recipient(80))})));

    // I-2: cancel must go back to the vault, and only before the delay has passed.
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, iout, 2, {CTxOut(4000, recipient)})), "bad-txns-vault-cancel");
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, iout, 2, {CTxOut(3999, vspk)})), "bad-txns-vault-cancel");
    CMutableTransaction cancel = SpendTx(c, iout, 2, {CTxOut(4000, vspk)});
    BOOST_CHECK(!c.Try(cancel));
    c.Empty((int)(ih + 4 - c.h)); // h − coinHeight = 4 < delay 5
    BOOST_CHECK(!c.Try(cancel));
    c.Empty(1); // = delay
    BOOST_CHECK_EQUAL(*c.Try(cancel), "bad-txns-vault-cancel");

    // Release after the delay; then the owner spends the re-lock (selector 2).
    BOOST_REQUIRE(!c.Block1(SpendTx(c, iout, 1, {CTxOut(4000, recipient)})));
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->lockedValue, 6000);
    BOOST_REQUIRE(!c.Block1(SpendTx(c, relock, 2, {CTxOut(6000, Recipient(63))})));
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->lockedValue, 0);
}

BOOST_AUTO_TEST_CASE(cancel_relocks)
{
    Chain c;
    CKey owner = MakeKey(50);
    SetId s = SetWithMembers(c, {MakeKey(1)});
    VaultParams vp = VaultFor(s, owner);
    CScript vspk = BuildVault(vp);
    COutPoint vout = Lock(c, vp, 10000);
    CScript ispk = BuildIntent(IntentFor(vp, vspk, Recipient(60)));
    CMutableTransaction unlock = SpendTx(c, vout, 1, {CTxOut(10000, ispk)});
    BOOST_REQUIRE(!c.Block1(unlock));
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->lockedValue, 0);
    COutPoint iout = FindOut(unlock, ispk);
    c.Empty(3);
    CMutableTransaction cancel = SpendTx(c, iout, 2, {CTxOut(10000, vspk)});
    BOOST_REQUIRE(!c.Block1(cancel));
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->lockedValue, 10000);
    // The re-created vault is byte-identical and spendable again.
    COutPoint back = FindOut(cancel, vspk);
    BOOST_CHECK(!c.Try(SpendTx(c, back, 2, {CTxOut(10000, Recipient(64))})));
}

BOOST_AUTO_TEST_CASE(template_out_index)
{
    // The 'v' index (vault_list; an intent's height for the start-up replay): every V / I output
    // created from activation, with its height, value and script (an intent also its
    // originating V script), erased when the output is spent, restored by the block undo.
    Chain c;
    CKey owner = MakeKey(50);
    SetId s = SetWithMembers(c, {MakeKey(1)});
    VaultParams vp = VaultFor(s, owner);
    CScript vspk = BuildVault(vp);
    COutPoint vout = Lock(c, vp, 10000);
    auto rv = GetTemplateOut(c.kv, vout);
    BOOST_REQUIRE(rv);
    BOOST_CHECK_EQUAL(rv->kind, 0);
    BOOST_CHECK_EQUAL(rv->height, c.h - 1);
    BOOST_CHECK_EQUAL(rv->value, 10000);
    BOOST_CHECK(rv->scriptPubKey == vspk);
    BOOST_CHECK(rv->origin.empty());

    CScript ispk = BuildIntent(IntentFor(vp, vspk, Recipient(60)));
    CMutableTransaction unlock = SpendTx(c, vout, 1, {CTxOut(4000, ispk), CTxOut(6000, vspk)});
    std::map<std::string, std::string> before = c.kv.data;
    BOOST_REQUIRE(!c.Block1(unlock));
    BOOST_CHECK(!GetTemplateOut(c.kv, vout));
    COutPoint iout = FindOut(unlock, ispk);
    COutPoint relock = FindOut(unlock, vspk);
    auto ri = GetTemplateOut(c.kv, iout);
    BOOST_REQUIRE(ri);
    BOOST_CHECK_EQUAL(ri->kind, 1);
    BOOST_CHECK_EQUAL(ri->height, c.h - 1);
    BOOST_CHECK_EQUAL(ri->value, 4000);
    BOOST_CHECK(ri->origin == vspk);
    BOOST_REQUIRE(GetTemplateOut(c.kv, relock));
    auto list = ListTemplateOuts(c.kv);
    BOOST_CHECK_EQUAL(list.size(), 2U);
    for (const auto& e : list) BOOST_CHECK(e.first == iout || e.first == relock);

    // The block undo restores the index byte for byte.
    {
        MemoryKV kv = c.kv;
        VaultState st(kv);
        st.ApplyUndo(c.history.back().second);
        kv.Apply(st.Changes());
        BOOST_CHECK(kv.data == before);
    }

    // A failed transaction leaves no index entry; a release erases the intent's.
    BOOST_CHECK(c.Try(SpendTx(c, iout, 1, {CTxOut(3999, Recipient(60))})));
    BOOST_CHECK(GetTemplateOut(c.kv, iout));
    c.Empty(4);
    BOOST_REQUIRE(!c.Block1(SpendTx(c, iout, 1, {CTxOut(4000, Recipient(60))})));
    BOOST_CHECK(!GetTemplateOut(c.kv, iout));
    BOOST_CHECK_EQUAL(ListTemplateOuts(c.kv).size(), 1U);
}

BOOST_AUTO_TEST_CASE(coins_from_undo)
{
    // vault::CoinsFromUndo (the start-up replay's accessor): scripts and values from the undo
    // record; heights from the record, the block itself, or the template-output index.
    Chain c;
    CKey owner = MakeKey(50);
    SetId s = SetWithMembers(c, {MakeKey(1)});
    VaultParams vp = VaultFor(s, owner);
    CScript vspk = BuildVault(vp);
    COutPoint vout = Lock(c, vp, 10000);
    CScript ispk = BuildIntent(IntentFor(vp, vspk, Recipient(60)));
    CMutableTransaction unlock = SpendTx(c, vout, 1, {CTxOut(10000, ispk)});
    BOOST_REQUIRE(!c.Block1(unlock));
    COutPoint iout = FindOut(unlock, ispk);
    const int64_t ih = c.h - 1;

    CMutableTransaction coinbase;
    coinbase.vin.push_back(CTxIn());
    coinbase.vout.push_back(CTxOut(1, Recipient(70)));
    CMutableTransaction cancel = SpendTx(c, iout, 2, {CTxOut(10000, vspk)}, false);
    CMutableTransaction child; // spends an output created earlier in the same block
    child.vin.push_back(CTxIn(COutPoint(CTransaction(cancel).GetHash(), 0), CScript() << OP_2, 0xffffffff));
    child.vout.push_back(CTxOut(9000, Recipient(71)));
    CBlock block;
    block.vtx = {CTransaction(coinbase), CTransaction(cancel), CTransaction(child)};

    CBlockUndo undo;
    undo.vtxundo.resize(2);
    undo.vtxundo[0].vprevout.push_back(CTxInUndo(CTxOut(10000, ispk))); // nHeight 0: not the tx's last output
    undo.vtxundo[1].vprevout.push_back(CTxInUndo(CTxOut(10000, vspk)));
    MapCoinAccessor coins;
    BOOST_REQUIRE(CoinsFromUndo(block, undo, c.h, c.kv, coins));
    SpentCoin got;
    BOOST_REQUIRE(coins.GetSpentCoin(iout, got));
    BOOST_CHECK_EQUAL(got.height, ih);            // from the 'v' index
    BOOST_CHECK(got.scriptPubKey == ispk);
    BOOST_REQUIRE(coins.GetSpentCoin(child.vin[0].prevout, got));
    BOOST_CHECK_EQUAL(got.height, c.h);           // created in the block
    BOOST_CHECK_EQUAL(got.value, 10000);

    // The undo record's height wins when it has one.
    undo.vtxundo[0].vprevout[0].nHeight = 7;
    MapCoinAccessor coins2;
    BOOST_REQUIRE(CoinsFromUndo(block, undo, c.h, c.kv, coins2));
    BOOST_REQUIRE(coins2.GetSpentCoin(iout, got));
    BOOST_CHECK_EQUAL(got.height, 7);

    // An intent with no height anywhere cannot be replayed; a mismatched undo is refused.
    undo.vtxundo[0].vprevout[0].nHeight = 0;
    MemoryKV empty;
    MapCoinAccessor coins3;
    BOOST_CHECK(!CoinsFromUndo(block, undo, c.h, empty, coins3));
    undo.vtxundo.pop_back();
    BOOST_CHECK(!CoinsFromUndo(block, undo, c.h, c.kv, coins3));
}

BOOST_AUTO_TEST_CASE(app_branch)
{
    Chain c;
    CKey owner = MakeKey(50);
    SetId s = SetWithMembers(c, {MakeKey(1)});
    VaultParams vp = VaultFor(s, owner, /*appHeight=*/500);
    CScript vspk = BuildVault(vp);
    COutPoint vout = Lock(c, vp, 8000);
    CScript ispk = BuildIntent(IntentFor(vp, vspk, Recipient(60)));
    // Selector 4 obeys S-2 like an unlock.
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, vout, 4, {CTxOut(8000, Recipient(60))})), "bad-txns-vault-value");
    BOOST_REQUIRE(!c.Block1(SpendTx(c, vout, 4, {CTxOut(8000, ispk)})));
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->lockedValue, 0);
}

BOOST_AUTO_TEST_CASE(rate_limit_epochs)
{
    Chain c; // h = 100
    CKey owner = MakeKey(50);
    SetCreateBody p = Params(true);
    p.rateLimitBps = 5000; // 50 % of the epoch's basis
    p.rateWindow = 20;     // epochs [100,120) = 5, [120,140) = 6, ...
    SetId s = SetWithMembers(c, {MakeKey(1)}, p); // created 100, joined 101, h = 107
    VaultParams vp = VaultFor(s, owner);
    CScript vspk = BuildVault(vp);
    CScript ispk = BuildIntent(IntentFor(vp, vspk, Recipient(60)));
    COutPoint v1 = Lock(c, vp, 1000);
    COutPoint v2 = Lock(c, vp, 1000);
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->lockedValue, 2000);
    // In the epoch the value was locked the basis is 0 (U-20): no unlock fits.
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, v1, 1, {CTxOut(1, ispk), CTxOut(999, vspk)})), "bad-txns-vault-rate");

    c.Empty((int)(120 - c.h)); // epoch 6: basis 2000, cap 1000
    BOOST_CHECK(!c.Try(SpendTx(c, v1, 1, {CTxOut(1000, ispk)})));
    CMutableTransaction u1 = SpendTx(c, v1, 1, {CTxOut(600, ispk), CTxOut(400, vspk)});
    BOOST_REQUIRE(!c.Block1(u1));
    auto rec = GetSet(c.kv, s);
    BOOST_CHECK_EQUAL(rec->epoch, 6);
    BOOST_CHECK_EQUAL(rec->epochBasis, 2000);
    BOOST_CHECK_EQUAL(rec->epochUsed, 600);
    BOOST_CHECK_EQUAL(rec->lockedValue, 1400);
    // 400 more fits exactly; 401 does not.
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, v2, 1, {CTxOut(401, ispk), CTxOut(599, vspk)})), "bad-txns-vault-rate");
    CMutableTransaction u2 = SpendTx(c, v2, 1, {CTxOut(400, ispk), CTxOut(600, vspk)});
    BOOST_REQUIRE(!c.Block1(u2));
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->epochUsed, 1000);
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->lockedValue, 1000);
    COutPoint r1 = FindOut(u1, vspk), r2 = FindOut(u2, vspk);
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, r1, 1, {CTxOut(1, ispk), CTxOut(399, vspk)})), "bad-txns-vault-rate");
    // Owner spends (selector 2) are not rate-limited.
    BOOST_CHECK(!c.Try(SpendTx(c, r2, 2, {CTxOut(600, Recipient(70))})));

    // Epoch 7: the basis is the locked value at the epoch's start (1000) even if a lock
    // lands first in the epoch; cap 500.
    c.Empty((int)(140 - c.h));
    Lock(c, vp, 5000);
    rec = GetSet(c.kv, s);
    BOOST_CHECK_EQUAL(rec->epoch, 7);
    BOOST_CHECK_EQUAL(rec->epochBasis, 1000);
    BOOST_CHECK_EQUAL(rec->lockedValue, 6000);
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, r2, 1, {CTxOut(501, ispk), CTxOut(99, vspk)})), "bad-txns-vault-rate");
    BOOST_REQUIRE(!c.Block1(SpendTx(c, r2, 1, {CTxOut(500, ispk), CTxOut(100, vspk)})));
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, r1, 1, {CTxOut(1, ispk), CTxOut(399, vspk)})), "bad-txns-vault-rate");
    BOOST_CHECK_EQUAL(RateCap(MAX_MONEY, 10000), MAX_MONEY);
    BOOST_CHECK_EQUAL(RateCap(MAX_MONEY, 3333), (CAmount)(((__int128)MAX_MONEY * 3333) / 10000));
    BOOST_CHECK_EQUAL(RateCap(9999, 1), 0);
}

BOOST_AUTO_TEST_CASE(apply_tx_is_atomic)
{
    Chain c;
    CKey k1 = MakeKey(1);
    SetId s = SetWithMembers(c, {k1});
    MemberRecord m = Member(c, s, k1);
    // Spends k1's bond (marks WITHDRAWN) but then fails I-0: nothing may stick.
    VaultParams vp = VaultFor(s, MakeKey(50));
    CScript ispk = BuildIntent(IntentFor(vp, BuildVault(vp), Recipient(1)));
    CMutableTransaction bad = SpendTx(c, m.bondOutpoint, 1, {CTxOut(900, ispk)}, false);
    VaultState st(c.kv);
    BOOST_CHECK_EQUAL(*Res(st.ApplyTx(CTransaction(bad), c.h, c.coins)), "bad-txns-vault-intent");
    BOOST_CHECK(st.Changes().empty());
    BOOST_CHECK_EQUAL(GetMember(st, s, k1.GetPubKey())->status, MEMBER_ACTIVE);
    // A missing input coin is a rejection, not a silent pass.
    CMutableTransaction orphan;
    orphan.vin.push_back(CTxIn(COutPoint(uint256S("0xdead"), 0), CScript(), 0xffffffff));
    orphan.vout.push_back(CTxOut(1, Recipient(1)));
    BOOST_CHECK_EQUAL(*Res(st.ApplyTx(CTransaction(orphan), c.h, c.coins)), "bad-txns-vault-inputs-missing");
    // CheckTx over a snapshot of the tip.
    SetSnapshot snap(c.kv);
    BOOST_CHECK(!CheckTx(CTransaction(HeartbeatTx(c, s, k1)), c.coins, c.h, snap));
    BOOST_CHECK_EQUAL(*Res(CheckTx(CTransaction(bad), c.coins, c.h, snap)), "bad-txns-vault-intent");
}

BOOST_AUTO_TEST_CASE(running_copy_sequential)
{
    // The miner's running copy: acts apply in order, a failing candidate is skipped.
    Chain c;
    CKey k1 = MakeKey(1), k2 = MakeKey(2);
    SetCreateBody p = Params(true);
    p.seats = 1;
    p.unlockThreshold = p.cancelThreshold = p.slashThreshold = 1;
    SetId s = CreateSet(c, p);
    VaultState running(c.kv);
    BOOST_CHECK(!running.ApplyTx(CTransaction(JoinTx(c, s, k1, {})), c.h, c.coins));
    BOOST_CHECK_EQUAL(*Res(running.ApplyTx(CTransaction(JoinTx(c, s, k2, {})), c.h, c.coins)), "bad-vault-act-seats");
    BOOST_CHECK(!!GetMember(running, s, k1.GetPubKey()));
    BOOST_CHECK(!GetMember(running, s, k2.GetPubKey()));
    BOOST_CHECK(!GetMember(c.kv, s, k1.GetPubKey())); // the base is untouched
    // A block with both joins is invalid (seats apply sequentially).
    BOOST_CHECK_EQUAL(*c.Block({JoinTx(c, s, k1, {}), JoinTx(c, s, k2, {})}), "bad-vault-act-seats");
}

BOOST_AUTO_TEST_CASE(undo_roundtrip_byte_identical)
{
    Chain c;
    CKey k1 = MakeKey(1), k2 = MakeKey(2), k3 = MakeKey(3), owner = MakeKey(50);
    SetCreateBody p = Params(true);
    p.rateLimitBps = 9000;
    p.rateWindow = 10;
    SetId s = SetWithMembers(c, {k1, k2, k3}, p);
    VaultParams vp = VaultFor(s, owner);
    CScript vspk = BuildVault(vp);
    CScript ispk = BuildIntent(IntentFor(vp, vspk, Recipient(60)));
    COutPoint vout = Lock(c, vp, 10000);
    c.Empty(10);
    CMutableTransaction unlock = SpendTx(c, vout, 1, {CTxOut(3000, ispk), CTxOut(7000, vspk)});
    BOOST_REQUIRE(!c.Block({unlock, HeartbeatTx(c, s, k1)}));
    BOOST_REQUIRE(!c.Block1(RemoveTx(c, s, k3.GetPubKey(), true, {k1, k2})));
    BOOST_REQUIRE(!c.Block1(SpendTx(c, Member(c, s, k2).bondOutpoint, 1, {CTxOut(900, Recipient(7))}, false)));
    BOOST_CHECK_EQUAL(*c.Try(WindDownTx(c, s, {k1, k3})), "bad-vault-act-sigs"); // k3 removed
    BOOST_CHECK(!c.kv.data.empty());

    // Disconnect every block in reverse; each step restores the exact prior bytes.
    MemoryKV kv = c.kv;
    for (auto it = c.history.rbegin(); it != c.history.rend(); ++it) {
        VaultState st(kv);
        st.ApplyUndo(it->second);
        kv.Apply(st.Changes());
        BOOST_CHECK(kv.data == it->first);
    }
    BOOST_CHECK(kv.data.empty());
}

BOOST_AUTO_TEST_CASE(db_connect_disconnect)
{
    Chain c; // used for funding coins and tx building only
    VaultDB db(fs::temp_directory_path() / "vault_db_test", 1 << 20, /*fMemory=*/true, /*fWipe=*/true);
    uint256 tip;
    int64_t tipHeight;
    BOOST_CHECK(!db.GetTip(tip, tipHeight));

    auto connect = [&](const std::vector<CMutableTransaction>& txs, const uint256& hash, const uint256& prev, int64_t h) {
        CBlock block;
        for (const auto& m : txs) block.vtx.push_back(CTransaction(m));
        VaultState st(db);
        BlockUndo undo;
        auto err = st.ApplyBlock(block, h, c.coins, undo);
        BOOST_REQUIRE_MESSAGE(!err, (err ? *err : std::string()));
        BOOST_REQUIRE(db.ConnectBlock(hash, h, prev, st, undo));
        for (const auto& tx : block.vtx)
            for (size_t o = 0; o < tx.vout.size(); o++)
                c.coins.coins[COutPoint(tx.GetHash(), o)] = SpentCoin{tx.vout[o].scriptPubKey, tx.vout[o].nValue, h};
    };
    auto snapshotAll = [&]() {
        std::map<std::string, std::string> all;
        for (char p : {KEY_SET, KEY_MEMBER, KEY_BOND}) {
            db.Iterate(std::string(1, p), [&](const std::string& k, const std::string& v) { all[k] = v; return true; });
        }
        return all;
    };
    const uint256 h0 = uint256S("0x100"), h1 = uint256S("0x101"), h2 = uint256S("0x102"), hx = uint256S("0x1ff");
    Act a;
    a.type = ACT_SET_CREATE;
    a.create = Params(true);
    CMutableTransaction create = ActTx(c, a, {});
    SetId s = CTransaction(create).GetHash();
    connect({create}, h1, h0, 100);
    BOOST_CHECK(db.GetTip(tip, tipHeight) && tip == h1 && tipHeight == 100);
    BOOST_CHECK(!!GetSet(db, s));
    const auto afterCreate = snapshotAll();

    c.h = 101;
    CKey k1 = MakeKey(1);
    CMutableTransaction join = JoinTx(c, s, k1, {});
    // Refused: wrong parent.
    {
        VaultState st(db);
        BlockUndo undo;
        BOOST_REQUIRE(!st.ApplyBlock(CBlock(), 101, c.coins, undo));
        BOOST_CHECK(!db.ConnectBlock(h2, 101, hx, st, undo));
    }
    connect({join}, h2, h1, 101);
    BOOST_CHECK(!!GetMember(db, s, k1.GetPubKey()));
    BOOST_CHECK_EQUAL(GetMembers(db, s).size(), 1U);
    BlockUndo u2;
    BOOST_CHECK(db.ReadUndo(h2, u2));
    BOOST_CHECK(!u2.entries.empty());

    // Disconnect: only the tip, and back to the exact prior state.
    BOOST_CHECK(!db.DisconnectBlock(h1, h0, 99));
    BOOST_CHECK(db.DisconnectBlock(h2, h1, 100));
    BOOST_CHECK(snapshotAll() == afterCreate);
    BOOST_CHECK(!GetMember(db, s, k1.GetPubKey()));
    BOOST_CHECK(db.GetTip(tip, tipHeight) && tip == h1 && tipHeight == 100);
    BOOST_CHECK(!db.ReadUndo(h2, u2));
    BOOST_CHECK(db.DisconnectBlock(h1, h0, 99));
    BOOST_CHECK(snapshotAll().empty());
    BOOST_CHECK(db.Flush());
    BOOST_CHECK(db.Wipe());
    BOOST_CHECK(!db.GetTip(tip, tipHeight));
}

BOOST_AUTO_TEST_CASE(set_sig_checker)
{
    Chain c;
    CKey k1 = MakeKey(1), k2 = MakeKey(2), k3 = MakeKey(3);
    SetId s = SetWithMembers(c, {k1, k2}); // unlock 2, cancel 1
    BOOST_REQUIRE(!c.Block1(JoinTx(c, s, k3, {}))); // k3 immature
    auto snap = std::make_shared<const SetSnapshot>(c.kv);

    CScript scriptCode = BuildVault(VaultFor(s, MakeKey(50)));
    CMutableTransaction m;
    m.vin.push_back(CTxIn(COutPoint(uint256S("0xabc"), 1), CScript(), 0xffffffff));
    m.vout.push_back(CTxOut(1000, Recipient(9)));
    CTransaction tx(m);
    const CAmount amount = 5000;
    PrecomputedTransactionData txdata(tx, {CTxOut(amount, scriptCode)});
    const uint32_t branch = 0;
    SetSigChecker checker(&tx, 0, amount, false, txdata, snap, c.h);
    BOOST_CHECK(*checker.SetThreshold(s, ROLE_UNLOCK) == 2);
    BOOST_CHECK(*checker.SetThreshold(s, ROLE_CANCEL) == 1);
    BOOST_CHECK(!checker.SetThreshold(uint256S("0x5"), ROLE_UNLOCK));
    BOOST_CHECK(!checker.IsSetReleased(s));
    BOOST_CHECK(checker.IsSetReleased(uint256S("0x5")));

    uint256 sighash = SignatureHash(scriptCode, tx, 0, SIGHASH_ALL, amount, branch, txdata);
    auto sign = [&](const CKey& k, uint8_t role, const uint256& sh) {
        valtype sig;
        BOOST_REQUIRE(SignRecoverable(k, SetSigMsg(s, role, tx.vin[0].prevout, sh), sig));
        return sig;
    };
    BOOST_CHECK(checker.CheckSetSigs(s, ROLE_UNLOCK, {sign(k1, 1, sighash), sign(k2, 1, sighash)}, scriptCode, branch));
    BOOST_CHECK(checker.CheckSetSigs(s, ROLE_UNLOCK, {sign(k2, 1, sighash), sign(k1, 1, sighash)}, scriptCode, branch));
    BOOST_CHECK(!checker.CheckSetSigs(s, ROLE_UNLOCK, {sign(k1, 1, sighash)}, scriptCode, branch));
    BOOST_CHECK(!checker.CheckSetSigs(s, ROLE_UNLOCK, {sign(k1, 1, sighash), sign(k1, 1, sighash)}, scriptCode, branch));
    BOOST_CHECK(!checker.CheckSetSigs(s, ROLE_UNLOCK, {sign(k1, 1, sighash), sign(k3, 1, sighash)}, scriptCode, branch)); // immature
    BOOST_CHECK(!checker.CheckSetSigs(s, ROLE_UNLOCK, {sign(k1, 1, sighash), sign(MakeKey(9), 1, sighash)}, scriptCode, branch));
    // Bound to the role, the sighash (hence scriptCode) and the outpoint.
    BOOST_CHECK(!checker.CheckSetSigs(s, ROLE_CANCEL, {sign(k1, 1, sighash)}, scriptCode, branch));
    BOOST_CHECK(checker.CheckSetSigs(s, ROLE_CANCEL, {sign(k1, 2, sighash)}, scriptCode, branch));
    BOOST_CHECK(!checker.CheckSetSigs(s, ROLE_CANCEL, {sign(k1, 2, sighash)}, Recipient(1), branch));
    BOOST_CHECK(!checker.CheckSetSigs(uint256S("0x5"), ROLE_CANCEL, {sign(k1, 2, sighash)}, scriptCode, branch));
    // A checker without a snapshot fails closed.
    SetSigChecker none(&tx, 0, amount, false, txdata, nullptr, c.h);
    BOOST_CHECK(!none.SetThreshold(s, ROLE_UNLOCK));
    BOOST_CHECK(!none.IsSetReleased(s));
    BOOST_CHECK(!none.CheckSetSigs(s, ROLE_CANCEL, {sign(k1, 2, sighash)}, scriptCode, branch));
}

BOOST_AUTO_TEST_CASE(module_table_empty)
{
    BOOST_CHECK(Modules().empty());
    BOOST_CHECK(FindModule(Tag{{'Y', 'E', 'D', 0x00}}) == nullptr);
    BOOST_CHECK(FindModule(Tag{{'W', 'Y', 'E', 'C'}}) == nullptr);
}

BOOST_AUTO_TEST_CASE(record_serialization)
{
    SetRecord r;
    r.params = Params(false);
    r.createHeight = 7;
    r.windDownHeight = 9;
    r.lockedValue = 123;
    r.epoch = 4;
    r.epochBasis = 99;
    r.epochUsed = 3;
    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << r;
    SetRecord q;
    ss >> q;
    BOOST_CHECK(EncodePayload(Act{ACT_SET_CREATE, q.params, {}, {}, {}, {}, {}, {}}) == EncodePayload(Act{ACT_SET_CREATE, r.params, {}, {}, {}, {}, {}, {}}));
    BOOST_CHECK_EQUAL(q.windDownHeight, 9);
    BOOST_CHECK_EQUAL(q.epochUsed, 3);
    MemberRecord m;
    m.bondOutpoint = COutPoint(uint256S("0x1"), 2);
    m.bondValue = 5;
    m.status = MEMBER_EJECTED;
    m.bondFrozen = true;
    CDataStream s2(SER_DISK, PROTOCOL_VERSION);
    s2 << m;
    MemberRecord n;
    s2 >> n;
    BOOST_CHECK(n.bondOutpoint == m.bondOutpoint && n.status == MEMBER_EJECTED && n.bondFrozen);
    BlockUndo u;
    u.entries.emplace_back("a", std::string("b"));
    u.entries.emplace_back("c", std::nullopt);
    CDataStream s3(SER_DISK, PROTOCOL_VERSION);
    s3 << u;
    BlockUndo v;
    s3 >> v;
    BOOST_CHECK(v.entries == u.entries);
}

/** A module that is not in the compile-time table (the table is empty until P4): it governs one
 *  set and names, as evidence, every member key pushed in an OP_RETURN output
 *  `OP_RETURN <pubkey> <block hash> <height LE32>` whose hash is the chain's block at that height. */
struct EjectingTestModule : public Module {
    std::optional<SetId> governed;
    mutable std::vector<int64_t> heightsSeen;
    std::optional<SetId> GovernedSet() const override { return governed; }
    std::vector<CPubKey> Ejections(const CTransaction& tx, const ModuleContext& ctx) const override
    {
        heightsSeen.push_back(ctx.height);
        std::vector<CPubKey> out;
        for (const CTxOut& o : tx.vout) {
            CScript::const_iterator pc = o.scriptPubKey.begin();
            opcodetype op;
            valtype key, hash, height;
            if (!o.scriptPubKey.GetOp(pc, op) || op != OP_RETURN) continue;
            if (!o.scriptPubKey.GetOp(pc, op, key) || !o.scriptPubKey.GetOp(pc, op, hash) || !o.scriptPubKey.GetOp(pc, op, height)) continue;
            if (hash.size() != 32 || height.size() != 4 || !ctx.blockHashAt) continue;
            const int64_t h = height[0] | (height[1] << 8) | (height[2] << 16) | ((int64_t)height[3] << 24);
            const std::optional<uint256> want = ctx.blockHashAt(h);
            if (!want || uint256(hash) != *want) continue;
            out.push_back(CPubKey(key.begin(), key.end()));
        }
        return out;
    }
};

BOOST_AUTO_TEST_CASE(module_ejection_hook_eqv1)
{
    // U-25 (P4-b, the primitive's half): a module names members of the one set it governs; the
    // primitive ejects each and freezes its bond (SET_EQUIVOCATION's effect) in the same overlay,
    // undo-covered, and never invalidates the transaction or touches another set. The YED module's
    // EQV-1 evidence is ported with the YED half; here a test module stands in for it.
    Chain c;
    const CKey k1 = MakeKey(61), k2 = MakeKey(62), k3 = MakeKey(65), outsider = MakeKey(63);
    const SetId s = SetWithMembers(c, {k1, k2});
    const SetId other = SetWithMembers(c, {k3});
    const COutPoint bond1 = Member(c, s, k1).bondOutpoint;
    const COutPoint bond3 = Member(c, other, k3).bondOutpoint;
    const int64_t cited = c.h - 3;
    auto fakeHash = [](int64_t h) { uint256 x; x.begin()[0] = (unsigned char)(h & 0xff); x.begin()[1] = (unsigned char)((h >> 8) & 0xff); x.begin()[31] = 0xab; return x; };
    BlockHashFn hashes = [&](int64_t h) -> std::optional<uint256> { if (h < 0 || h >= c.h) return std::nullopt; return fakeHash(h); };
    auto evidence = [&](const CKey& k, int64_t at, const uint256& hash) {
        const valtype le = {(unsigned char)(at & 0xff), (unsigned char)((at >> 8) & 0xff), (unsigned char)((at >> 16) & 0xff), (unsigned char)((at >> 24) & 0xff)};
        CMutableTransaction m;
        m.vin.push_back(CTxIn(c.Fund()));
        m.vout.push_back(CTxOut(0, CScript() << OP_RETURN << ToByteVector(k.GetPubKey()) << ToByteVector(hash) << le));
        return CTransaction(m);
    };
    const CTransaction e = evidence(k1, cited, fakeHash(cited));

    // Through ApplyTx the hook runs over the compile-time table (empty before P4; a registered
    // module names nothing for this transaction): nothing happens and the transaction is valid.
    { VaultState st(c.kv); st.SetBlockHashes(hashes); BOOST_CHECK_EQUAL(*Res(st.ApplyTx(e, c.h, c.coins)), "OK"); BOOST_CHECK(st.Changes().empty()); }

    EjectingTestModule mod;
    // No governed set; a governed set that does not exist: nothing happens, Ejections is not asked.
    { VaultState st(c.kv); st.SetBlockHashes(hashes); st.ApplyEjectionsOf(mod, e, c.h); BOOST_CHECK(st.Changes().empty()); }
    mod.governed = uint256S("0x5e7");
    { VaultState st(c.kv); st.SetBlockHashes(hashes); st.ApplyEjectionsOf(mod, e, c.h); BOOST_CHECK(st.Changes().empty()); }
    BOOST_CHECK(mod.heightsSeen.empty());
    mod.governed = s;
    // No block hashes: the module cannot check its evidence, nothing happens.
    { VaultState st(c.kv); st.ApplyEjectionsOf(mod, e, c.h); BOOST_CHECK(st.Changes().empty()); }
    // Evidence over the wrong hash; a key that is not a member; a member of another set: nothing happens.
    { VaultState st(c.kv); st.SetBlockHashes(hashes); st.ApplyEjectionsOf(mod, evidence(k1, cited, fakeHash(cited + 1)), c.h); BOOST_CHECK(st.Changes().empty()); }
    { VaultState st(c.kv); st.SetBlockHashes(hashes); st.ApplyEjectionsOf(mod, evidence(outsider, cited, fakeHash(cited)), c.h); BOOST_CHECK(st.Changes().empty()); }
    { VaultState st(c.kv); st.SetBlockHashes(hashes); st.ApplyEjectionsOf(mod, evidence(k3, cited, fakeHash(cited)), c.h); BOOST_CHECK(st.Changes().empty());
      BOOST_CHECK(!GetBond(st, bond3)->frozen); BOOST_CHECK_EQUAL(GetMember(st, other, k3.GetPubKey())->status, MEMBER_ACTIVE); }

    // The evidence: k1 EJECTED and its bond frozen; k2 untouched; the module saw the block height.
    VaultState st(c.kv);
    st.SetBlockHashes(hashes);
    mod.heightsSeen.clear();
    st.ApplyEjectionsOf(mod, e, c.h);
    BOOST_CHECK(mod.heightsSeen == std::vector<int64_t>{c.h});
    BOOST_CHECK_EQUAL(GetMember(st, s, k1.GetPubKey())->status, MEMBER_EJECTED);
    BOOST_CHECK(GetMember(st, s, k1.GetPubKey())->bondFrozen);
    BOOST_CHECK(GetBond(st, bond1)->frozen);
    BOOST_CHECK_EQUAL(GetMember(st, s, k2.GetPubKey())->status, MEMBER_ACTIVE);
    // In the same overlay a later spend of the frozen bond is invalid; a second report changes nothing.
    {
        CMutableTransaction spend;
        spend.vin.push_back(CTxIn(bond1));
        spend.vout.push_back(CTxOut(500, GetScriptForDestination(k1.GetPubKey().GetID())));
        BOOST_CHECK_EQUAL(*Res(st.ApplyTx(CTransaction(spend), c.h, c.coins)), "bad-vault-bond-frozen");
        const auto before = st.Changes();
        st.ApplyEjectionsOf(mod, evidence(k1, cited - 1, fakeHash(cited - 1)), c.h);
        BOOST_CHECK(st.Changes() == before);
        BOOST_CHECK(!EjectAndFreeze(st, s, k1.GetPubKey()));
        BOOST_CHECK(!EjectAndFreeze(st, s, outsider.GetPubKey()));
        BOOST_CHECK(st.Changes() == before);
    }
    // The block's undo restores the base byte for byte.
    const BlockUndo undo = st.MakeUndo();
    MemoryKV after = c.kv;
    after.Apply(st.Changes());
    VaultState back(after);
    back.ApplyUndo(undo);
    after.Apply(back.Changes());
    BOOST_CHECK(after.data == c.kv.data);

    // AncestorHashes (the node's provider): the block's ancestors, inclusive of `prev`; nothing above or below.
    std::vector<uint256> ids(5);
    std::vector<CBlockIndex> idx(5);
    for (int i = 0; i < 5; i++) {
        ids[i] = fakeHash(1000 + i);
        idx[i].phashBlock = &ids[i];
        idx[i].nHeight = i;
        idx[i].pprev = i ? &idx[i - 1] : nullptr;
        idx[i].BuildSkip();
    }
    const BlockHashFn anc = AncestorHashes(&idx[3]);
    BOOST_CHECK(anc(0) == std::optional<uint256>(ids[0]));
    BOOST_CHECK(anc(3) == std::optional<uint256>(ids[3]));
    BOOST_CHECK(!anc(4));
    BOOST_CHECK(!anc(-1));
    BOOST_CHECK(!AncestorHashes(nullptr)(0));
}

BOOST_AUTO_TEST_SUITE_END()
