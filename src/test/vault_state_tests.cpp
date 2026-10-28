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
#include "yellowback/attest.h"
#include "yellowback/bundle.h"
#include "yellowback/module.h"
#include "yellowback/payload.h"
#include "yellowback/script.h"
#include "vault/template.h"

#include "arith_uint256.h"
#include "chain.h"
#include "consensus/params.h"
#include "consensus/upgrades.h"
#include "crypto/pq/scheme.h"
#include "crypto/pq/sign.h"
#include "crypto/sha256.h"
#include "key.h"
#include "policy/policy.h"
#include "primitives/block.h"
#include "script/interpreter.h"
#include "script/standard.h"
#include "test/test_bitcoin.h"
#include "streams.h"
#include "undo.h"

#include <boost/test/unit_test.hpp>

using namespace vault;

namespace {

typedef std::vector<unsigned char> valtype;

/** The hashtype vault::SetSigChecker::CheckSetSigs computes the set-signature sighash under (plan §15.2 step 4:
 *  SignatureHash(scriptCode, tx, nIn, <this>, amount, branch)). set_sig_checker and vault_checksetsig_real_script sign
 *  with it, so a change of the consensus hashtype (MEDIUM-01-V-2: SIGHASH_ALL | SIGHASH_ANYONECANPAY) is this one line;
 *  every assertion below holds under either value, and the one that differs between them branches on it. */
const int SET_SIG_HASHTYPE = SIGHASH_ALL | SIGHASH_ANYONECANPAY;

/** UPGRADE_VAULT's consensus branch ID (0x6d5b7a31), the branch a set signature is made for. */
uint32_t VaultBranchId() { return NetworkUpgradeInfo[Consensus::UPGRADE_VAULT].nBranchId; }

/** A v4 (Sapling) transaction: the ZIP-243 sighash commits to the branch ID and the spent amount (a pre-Overwinter
 *  transaction's sighash commits to neither, so a binding test over one proves nothing). */
CMutableTransaction SaplingSpend(const std::vector<COutPoint>& prevouts, const std::vector<CTxOut>& outs)
{
    CMutableTransaction m;
    m.fOverwintered = true;
    m.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    m.nVersion = SAPLING_TX_VERSION;
    for (const COutPoint& op : prevouts) m.vin.push_back(CTxIn(op, CScript(), CTxIn::SEQUENCE_FINAL - 1));
    m.vout = outs;
    return m;
}

/** A post-quantum owner scriptSig: <sig chunks> <s> <pk chunks> <p> <selector> (quantum plan §4.2; as in
 *  vault_template_tests). */
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
    int64_t activation = 0;   // S-0's floor (VaultState::SetActivationHeight); 0 = none, the suite's default
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
        st.SetActivationHeight(activation);
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
        st.SetActivationHeight(activation);
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
    const CPubKey pk = owner.GetPubKey();
    v.owner = CPQKeyID(1, Hash(pk.begin(), pk.end()));   // a post-quantum owner id (quantum plan §4.3) per test key
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

/** The unit cases use small set maturities: D-Q-31's floor is lifted for the suite and checked in min_set_maturity. */
struct VaultTestingSetup : public BasicTestingSetup {
    VaultTestingSetup() { SetMinSetMaturity(0); }
    ~VaultTestingSetup() { SetMinSetMaturity(MIN_SET_MATURITY); }
};

BOOST_FIXTURE_TEST_SUITE(vault_state_tests, VaultTestingSetup)

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

    // burn = 0 (O-6): REMOVED, bond returned the set's maturity (5) after the removal (the bond exit delay).
    const int64_t removedAt = c.h;
    BOOST_REQUIRE(!c.Block1(RemoveTx(c, s, k3.GetPubKey(), false, {k1, k2})));
    MemberRecord m3 = Member(c, s, k3);
    BOOST_CHECK_EQUAL(m3.status, MEMBER_REMOVED);
    BOOST_CHECK(!m3.bondFrozen);
    BOOST_CHECK_EQUAL(GetBond(c.kv, m3.bondOutpoint)->exitHeight, removedAt);
    BOOST_CHECK(!SetSnapshot(c.kv).IsCurrentMember(s, k3.GetPubKey(), c.h));
    BOOST_CHECK_EQUAL(*c.Try(RemoveTx(c, s, k3.GetPubKey(), false, {k1, k2})), "bad-vault-act-remove");
    CMutableTransaction spend3 = SpendTx(c, m3.bondOutpoint, 1, {CTxOut(900, Recipient(7))}, false);
    c.Empty((int)(removedAt + 5 - 1 - c.h));
    BOOST_CHECK_EQUAL(c.h, removedAt + 4);
    BOOST_CHECK_EQUAL(*c.Try(spend3), "bad-vault-bond-locked");
    c.Empty(1);
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
    // The bond exit delay (owner 2026-10-11): an ACTIVE member's bond is locked; the member leaves first (the
    // SET_REMOVE of itself, signed by itself alone, without burn), then waits the set's maturity (5).
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, m.bondOutpoint, 1, {CTxOut(900, Recipient(7))}, false)), "bad-vault-bond-locked");
    BOOST_CHECK_EQUAL(*c.Try(RemoveTx(c, s, k1.GetPubKey(), true, {k1})), "bad-vault-act-sigs");    // no self-burn
    BOOST_CHECK_EQUAL(*c.Try(RemoveTx(c, s, k2.GetPubKey(), false, {k1})), "bad-vault-act-sigs");   // not another's
    const int64_t left = c.h;
    BOOST_REQUIRE(!c.Block1(RemoveTx(c, s, k1.GetPubKey(), false, {k1})));
    BOOST_CHECK_EQUAL(Member(c, s, k1).status, MEMBER_REMOVED);
    BOOST_CHECK_EQUAL(GetBond(c.kv, m.bondOutpoint)->exitHeight, left);
    BOOST_CHECK_EQUAL(CountActive(GetMembers(c.kv, s)), 1);
    c.Empty((int)(left + 4 - c.h));
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, m.bondOutpoint, 1, {CTxOut(900, Recipient(7))}, false)), "bad-vault-bond-locked");
    c.Empty(1);
    BOOST_REQUIRE(!c.Block1(SpendTx(c, m.bondOutpoint, 1, {CTxOut(900, Recipient(7))}, false)));   // at left + 5
    BOOST_CHECK_EQUAL(Member(c, s, k1).status, MEMBER_REMOVED);
    BOOST_CHECK(!GetBond(c.kv, m.bondOutpoint));
    // A departed member's old proof no longer slashes (bond spent).
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

BOOST_AUTO_TEST_CASE(exit_delay_slash_during_delay)
{
    // The bond exit delay (owner 2026-10-11): a member that left can still be slashed until its bond is spent:
    // SET_EQUIVOCATION during the delay ejects it and freezes the bond for good.
    Chain c;
    CKey k1 = MakeKey(1), k2 = MakeKey(2);
    SetId s = SetWithMembers(c, {k1, k2});
    const COutPoint bond = Member(c, s, k1).bondOutpoint;
    BOOST_REQUIRE(!c.Block1(RemoveTx(c, s, k1.GetPubKey(), false, {k1})));
    BOOST_CHECK(GetBond(c.kv, bond)->exitHeight > 0);
    Act e;
    e.type = ACT_SET_EQUIVOCATION;
    e.equivocation.setId = s;
    e.equivocation.prevout = COutPoint(uint256S("0x99"), 0);
    e.equivocation.roleA = 1;
    e.equivocation.sighashA = uint256S("0x01");
    e.equivocation.roleB = 1;
    e.equivocation.sighashB = uint256S("0x02");
    BOOST_REQUIRE(SignRecoverable(k1, SetSigMsg(s, 1, e.equivocation.prevout, e.equivocation.sighashA), e.equivocation.sigA));
    BOOST_REQUIRE(SignRecoverable(k1, SetSigMsg(s, 1, e.equivocation.prevout, e.equivocation.sighashB), e.equivocation.sigB));
    BOOST_REQUIRE(!c.Block1(ActTx(c, e, {})));
    BOOST_CHECK_EQUAL(Member(c, s, k1).status, MEMBER_EJECTED);
    BOOST_CHECK(GetBond(c.kv, bond)->frozen);
    c.Empty(10);
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, bond, 1, {CTxOut(900, Recipient(7))}, false)), "bad-vault-bond-frozen");
    // The record round-trips with its exit height; a record without one keeps its pre-exit bytes (67).
    BondRecord b = *GetBond(c.kv, bond);
    BondRecord back;
    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << b;
    ss >> back;
    BOOST_CHECK(back.exitHeight == b.exitHeight && back.frozen && back.setId == s);
    BondRecord plain;
    plain.setId = s;
    plain.memberKey = k2.GetPubKey();
    CDataStream ps(SER_DISK, PROTOCOL_VERSION);
    ps << plain;
    BOOST_CHECK_EQUAL(ps.size(), 67u);
}

BOOST_AUTO_TEST_CASE(exit_delay_no_slash_escape)
{
    // Review B1/A1 (2026-10-11), on a bridge-shaped (closed, ungoverned) set: a member that left cannot rejoin while
    // its old bond is unspent, and a cosigned SET_REMOVE with burn still reaches a bond in its exit delay.
    Chain c;
    const CKey admit = MakeKey(200);
    CKey k1 = MakeKey(1), k2 = MakeKey(2), k3 = MakeKey(3), k4 = MakeKey(4);
    SetId s = CreateSet(c, Params(false));
    for (const CKey& k : {k1, k2, k3, k4}) BOOST_REQUIRE(!c.Block1(JoinTx(c, s, k, {admit})));
    c.Empty(5);
    const COutPoint bond1 = Member(c, s, k1).bondOutpoint;
    // A1: k1 signs something fraudulent, then exits on its own before the burn vote lands
    const int64_t left = c.h;
    BOOST_REQUIRE(!c.Block1(RemoveTx(c, s, k1.GetPubKey(), false, {k1})));
    BOOST_CHECK_EQUAL(GetBond(c.kv, bond1)->exitHeight, left);
    // B1: no rejoin during the delay (the old bond is unspent), whatever the new bond
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s, k1, {k2, k3})), "bad-vault-act-join");
    // a burn = 0 vote on a member that already left stays refused; a burn by too few or by the target too
    BOOST_CHECK_EQUAL(*c.Try(RemoveTx(c, s, k1.GetPubKey(), false, {k2, k3})), "bad-vault-act-remove");
    BOOST_CHECK_EQUAL(*c.Try(RemoveTx(c, s, k1.GetPubKey(), true, {k2})), "bad-vault-act-sigs");
    BOOST_CHECK_EQUAL(*c.Try(RemoveTx(c, s, k1.GetPubKey(), true, {k1, k2})), "bad-vault-act-sigs");
    // the cosigned burn freezes the bond in its delay; the member stays REMOVED
    BOOST_REQUIRE(!c.Block1(RemoveTx(c, s, k1.GetPubKey(), true, {k2, k3})));
    BOOST_CHECK_EQUAL(Member(c, s, k1).status, MEMBER_REMOVED);
    BOOST_CHECK(Member(c, s, k1).bondFrozen);
    BOOST_CHECK(GetBond(c.kv, bond1)->frozen);
    BOOST_CHECK_EQUAL(*c.Try(RemoveTx(c, s, k1.GetPubKey(), true, {k2, k3})), "bad-vault-act-remove");   // already frozen
    c.Empty(10);
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, bond1, 1, {CTxOut(900, Recipient(7))}, false)), "bad-vault-bond-frozen");
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s, k1, {k2, k3})), "bad-vault-act-join");   // a frozen bond never leaves
    // k2 exits; its rejoin waits for its old bond's spend at exit + maturity, then succeeds
    const COutPoint bond2 = Member(c, s, k2).bondOutpoint;
    const int64_t left2 = c.h;
    BOOST_REQUIRE(!c.Block1(RemoveTx(c, s, k2.GetPubKey(), false, {k2})));
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s, k2, {k3, k4})), "bad-vault-act-join");
    c.Empty((int)(left2 + 5 - c.h));
    BOOST_REQUIRE(!c.Block1(SpendTx(c, bond2, 1, {CTxOut(900, Recipient(7))}, false)));
    BOOST_REQUIRE(!c.Block1(JoinTx(c, s, k2, {k3, k4})));
    BOOST_CHECK_EQUAL(Member(c, s, k2).status, MEMBER_ACTIVE);
    // equivocation evidence also reaches a bond in its exit delay (it already did; with the rejoin refused it is
    // always the bond the evidence's key posted)
}

BOOST_AUTO_TEST_CASE(min_set_maturity)
{
    // D-Q-31 (owner, 2026-10-11): every signer set has at least the network's exit window
    BOOST_CHECK_EQUAL(MIN_SET_MATURITY, 16128u);
    BOOST_CHECK_EQUAL(Consensus::Params().nVaultMinSetMaturity, 16128u);
    Chain c;
    SetMinSetMaturity(MIN_SET_MATURITY);
    Act a;
    a.type = ACT_SET_CREATE;
    a.create = Params(true);
    a.create.maturity = MIN_SET_MATURITY - 1;
    BOOST_CHECK_EQUAL(*c.Try(ActTx(c, a, {})), "bad-vault-act-params");
    a.create.maturity = MIN_SET_MATURITY;
    BOOST_CHECK_EQUAL(*c.Try(ActTx(c, a, {})), "OK");
    SetMinSetMaturity(8);                                  // regtest
    a.create.maturity = 7;
    BOOST_CHECK_EQUAL(*c.Try(ActTx(c, a, {})), "bad-vault-act-params");
    a.create.maturity = 8;
    BOOST_CHECK_EQUAL(*c.Try(ActTx(c, a, {})), "OK");
    SetMinSetMaturity(0);
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

// The set-state invariant audit (cf. DigiByte v9.26.7 19c8b1c272): every set's lockedValue equals the sum of its unspent V
// outputs through lock, unlock (intent + re-lock), cancel and spend; a corrupted lockedValue or V record is reported.
BOOST_AUTO_TEST_CASE(audit_locked_value)
{
    Chain c;
    CKey owner = MakeKey(50);
    SetId s = SetWithMembers(c, {MakeKey(1)});
    VaultParams vp = VaultFor(s, owner);
    CScript vspk = BuildVault(vp);
    BOOST_CHECK(AuditLockedValue(c.kv).empty());
    COutPoint vout = Lock(c, vp, 10000);
    std::vector<SetValueAudit> sets;
    BOOST_CHECK(AuditLockedValue(c.kv, &sets).empty());
    BOOST_REQUIRE_EQUAL(sets.size(), 1u);
    BOOST_CHECK(sets[0].setId == s);
    BOOST_CHECK_EQUAL(sets[0].stored, 10000);
    BOOST_CHECK_EQUAL(sets[0].derived, 10000);

    CScript ispk = BuildIntent(IntentFor(vp, vspk, Recipient(60)));
    CMutableTransaction unlock = SpendTx(c, vout, 1, {CTxOut(4000, ispk), CTxOut(6000, vspk)});
    BOOST_REQUIRE(!c.Block1(unlock));
    BOOST_CHECK(AuditLockedValue(c.kv).empty());     // the intent's 4000 left the set; the re-lock's 6000 stays
    COutPoint iout = FindOut(unlock, ispk);
    COutPoint relock = FindOut(unlock, vspk);
    c.Empty(2);
    BOOST_REQUIRE(!c.Block1(SpendTx(c, iout, 2, {CTxOut(4000, vspk)})));   // cancel: back into the set
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->lockedValue, 10000);
    BOOST_CHECK(AuditLockedValue(c.kv).empty());

    // A corrupted lockedValue is caught.
    const MemoryKV good = c.kv;
    SetRecord bad = *GetSet(c.kv, s);
    bad.lockedValue += 1;
    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << bad;
    c.kv.data[KeySet(s)] = std::string(ss.begin(), ss.end());
    std::vector<std::string> m = AuditLockedValue(c.kv);
    BOOST_REQUIRE_EQUAL(m.size(), 1u);
    BOOST_CHECK(m[0].find("lockedValue stored 10001, unspent V outputs 10000") != std::string::npos);

    // So is a lost V record (the index no longer lists an unspent vault the set still counts).
    c.kv = good;
    c.kv.data.erase(KeyTemplateOut(relock));
    m = AuditLockedValue(c.kv);
    BOOST_REQUIRE_EQUAL(m.size(), 1u);
    BOOST_CHECK(m[0].find("lockedValue stored 10000, unspent V outputs 4000") != std::string::npos);

    // Spending the vaults empties the set and the audit stays clean.
    c.kv = good;
    BOOST_REQUIRE(!c.Block1(SpendTx(c, relock, 2, {CTxOut(6000, Recipient(63))})));
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->lockedValue, 4000);
    BOOST_CHECK(AuditLockedValue(c.kv).empty());
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

    // An intent with no height anywhere (created before activation: never indexed, the undo of a
    // non-emptying spend has no height) replays with height 0 (audit 01/T-1: this used to be
    // `return false`, i.e. a node that could not start); S-0 then rejects its RELEASE and its
    // CANCEL exactly as the live path does with the real pre-activation height.
    undo.vtxundo[0].vprevout[0].nHeight = 0;
    MemoryKV empty;
    MapCoinAccessor coins3;
    BOOST_REQUIRE(CoinsFromUndo(block, undo, c.h, empty, coins3));
    BOOST_REQUIRE(coins3.GetSpentCoin(iout, got));
    BOOST_CHECK_EQUAL(got.height, 0);
    BOOST_CHECK(got.scriptPubKey == ispk);
    {
        VaultState st(c.kv);
        st.SetActivationHeight(c.h - 1);
        BOOST_CHECK_EQUAL(*Res(st.ApplyTx(CTransaction(SpendTx(c, iout, 1, {CTxOut(10000, Recipient(60))}, false)), c.h, coins3)),
                          "bad-txns-vault-preactivation");
        BOOST_CHECK_EQUAL(*Res(st.ApplyTx(CTransaction(cancel), c.h, coins3)), "bad-txns-vault-preactivation");
    }
    // A mismatched undo is still refused (the two structural checks).
    undo.vtxundo.pop_back();
    BOOST_CHECK(!CoinsFromUndo(block, undo, c.h, c.kv, coins3));
    CBlockUndo short_undo;
    short_undo.vtxundo.resize(2);
    short_undo.vtxundo[1].vprevout.push_back(CTxInUndo(CTxOut(10000, vspk)));
    BOOST_CHECK(!CoinsFromUndo(block, short_undo, c.h, c.kv, coins3));
}

BOOST_AUTO_TEST_CASE(preactivation_floor)
{
    // S-0 (audit 01/V-1, 01/V-3): a template input whose coin was created below the activation height is invalid.
    Chain c; // h = 100
    CKey owner = MakeKey(50);
    SetId s = SetWithMembers(c, {MakeKey(1)});
    const int64_t activation = c.h;
    c.activation = activation;

    // MATCH V and I coins created at activation - 1 (a miner's pre-activation preparation: policy refused them).
    VaultParams vp = VaultFor(s, owner, /*appHeight=*/activation + 1);  // an APP branch, for selector 4
    vp.ownerHeight = activation;
    CScript vspk = BuildVault(vp);
    CScript ispk = BuildIntent(IntentFor(vp, vspk, Recipient(60)));
    auto inject = [&](const CScript& spk, CAmount value, int64_t height, unsigned char seed) {
        uint256 hash;
        hash.begin()[0] = seed;
        hash.begin()[31] = 0xab;
        COutPoint op(hash, 0);
        SpentCoin coin;
        coin.scriptPubKey = spk;
        coin.value = value;
        coin.height = height;
        c.coins.coins[op] = coin;
        return op;
    };
    const COutPoint preV = inject(vspk, 5000, activation - 1, 1);
    const COutPoint preI = inject(ispk, 5000, activation - 1, 2);
    c.Empty(10);
    // V: OWNER (2), OWNER-RELEASED (3), APP (4) — the UNLOCK (1) too.
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, preV, 1, {CTxOut(5000, ispk)})), "bad-txns-vault-preactivation");
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, preV, 2, {CTxOut(5000, Recipient(70))})), "bad-txns-vault-preactivation");
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, preV, 3, {CTxOut(5000, Recipient(70))})), "bad-txns-vault-preactivation");
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, preV, 4, {CTxOut(5000, ispk)})), "bad-txns-vault-preactivation");
    // I: RELEASE (1), CANCEL (2), OWNER-RELEASED (3).
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, preI, 1, {CTxOut(5000, Recipient(60))})), "bad-txns-vault-preactivation");
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, preI, 2, {CTxOut(5000, vspk)})), "bad-txns-vault-preactivation");
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, preI, 3, {CTxOut(5000, Recipient(70))})), "bad-txns-vault-preactivation");
    // In a block too.
    BOOST_CHECK_EQUAL(*c.Block1(SpendTx(c, preI, 1, {CTxOut(5000, Recipient(60))})), "bad-txns-vault-preactivation");

    // The same shapes at the activation height pass the floor (and their rules apply as ever).
    const COutPoint atI = inject(ispk, 5000, activation, 3);
    BOOST_CHECK(!c.Try(SpendTx(c, atI, 1, {CTxOut(5000, Recipient(60))})));
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, atI, 1, {CTxOut(4999, Recipient(60))})), "bad-txns-vault-release");
    VaultParams vp0 = VaultFor(s, owner);   // a V locked at h >= activation: indexed, counted, spendable
    vp0.ownerHeight = activation;
    COutPoint atV = Lock(c, vp0, 7000);
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->lockedValue, 7000);
    BOOST_CHECK(!c.Block1(SpendTx(c, atV, 2, {CTxOut(7000, Recipient(70))})));
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->lockedValue, 0);

    // A MALFORMED-shaped pre-activation coin (delay 5 pushed non-minimally) is not a template input: no floor, no rule.
    valtype nmBytes(vspk.begin(), vspk.begin() + 38);    // tag, cancelSetId; then delay 5 as 01 05, not OP_5
    nmBytes.push_back(0x01);
    nmBytes.push_back(0x05);
    nmBytes.insert(nmBytes.end(), vspk.begin() + 39, vspk.end());
    const CScript nm(nmBytes.begin(), nmBytes.end());
    VaultParams q;
    BOOST_REQUIRE(MatchVault(nm, q) == Shape::MALFORMED);
    const COutPoint preM = inject(nm, 5000, activation - 1, 4);
    BOOST_CHECK(!c.Try(SpendTx(c, preM, 1, {CTxOut(5000, Recipient(70))})));

    // SetActivationHeight unset (0): no floor — the default every other case in this suite runs under.
    c.activation = 0;
    BOOST_CHECK(!c.Try(SpendTx(c, preV, 2, {CTxOut(5000, Recipient(70))})));
}

BOOST_AUTO_TEST_CASE(replay_parity)
{
    // A post-activation V whose creating transaction is only partly spent: the template spend's undo
    // has no height (CCoins undo: only the emptying spend carries one), CoinsFromUndo takes it from the
    // 'v' index, and the block applies over the replay accessor exactly as over the live coins.
    Chain c;
    CKey owner = MakeKey(50);
    SetId s = SetWithMembers(c, {MakeKey(1)});
    c.activation = 100;
    VaultParams vp = VaultFor(s, owner);
    CScript vspk = BuildVault(vp);
    CMutableTransaction lock;
    lock.vin.push_back(CTxIn(c.Fund(20000), CScript(), 0xffffffff));
    lock.vout.push_back(CTxOut(10000, vspk));
    lock.vout.push_back(CTxOut(9000, Recipient(80)));   // stays unspent
    BOOST_REQUIRE(!c.Block1(lock));
    const COutPoint vout(CTransaction(lock).GetHash(), 0);
    const int64_t vh = c.h - 1;
    c.Empty(2);
    CScript ispk = BuildIntent(IntentFor(vp, vspk, Recipient(60)));
    CMutableTransaction unlock = SpendTx(c, vout, 1, {CTxOut(10000, ispk)}, false);
    CMutableTransaction coinbase;
    coinbase.vin.push_back(CTxIn());
    coinbase.vout.push_back(CTxOut(1, Recipient(70)));
    CBlock block;
    block.vtx = {CTransaction(coinbase), CTransaction(unlock)};
    CBlockUndo undo;
    undo.vtxundo.resize(1);
    undo.vtxundo[0].vprevout.push_back(CTxInUndo(CTxOut(10000, vspk)));   // nHeight 0: not the emptying spend
    MapCoinAccessor replay;
    BOOST_REQUIRE(CoinsFromUndo(block, undo, c.h, c.kv, replay));
    SpentCoin got;
    BOOST_REQUIRE(replay.GetSpentCoin(vout, got));
    BOOST_CHECK_EQUAL(got.height, vh);

    VaultState live(c.kv), rep(c.kv);
    live.SetActivationHeight(c.activation);
    rep.SetActivationHeight(c.activation);
    BlockUndo u1, u2;
    BOOST_REQUIRE(!live.ApplyBlock(block, c.h, c.coins, u1));
    BOOST_REQUIRE(!rep.ApplyBlock(block, c.h, replay, u2));
    BOOST_CHECK(live.Changes() == rep.Changes());
    MemoryKV a = c.kv, b = c.kv;
    a.Apply(live.Changes());
    b.Apply(rep.Changes());
    BOOST_CHECK(StateHash(a) == StateHash(b));
}

BOOST_AUTO_TEST_CASE(app_branch)
{
    Chain c;
    CKey owner = MakeKey(50);
    SetId s = SetWithMembers(c, {MakeKey(1)});
    // V-1 (audit 01/V-5): an APP branch only on a tag a module governs. TEST has none: refused.
    VaultParams bad = VaultFor(s, owner, /*appHeight=*/500);
    CMutableTransaction lockBad;
    lockBad.vin.push_back(CTxIn(c.Fund(9000), CScript(), 0xffffffff));
    lockBad.vout.push_back(CTxOut(8000, BuildVault(bad)));
    BOOST_CHECK_EQUAL(*c.Try(lockBad), "bad-txns-vault-app");
    // ... also when a template spend creates it (any V output: here an owner spend paying into it).
    bad.appHeight = 0;
    COutPoint plain = Lock(c, bad, 8000);
    VaultParams badOut = bad;
    badOut.appHeight = 500;
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, plain, 2, {CTxOut(8000, BuildVault(badOut))})), "bad-txns-vault-app");
    // YED\0 has a registered module (its rules are not configured in this suite, so it governs nothing else here).
    VaultParams vp = VaultFor(s, owner, /*appHeight=*/500);
    vp.tag = yellowback::YED_TAG;
    BOOST_REQUIRE(FindModule(vp.tag));
    CScript vspk = BuildVault(vp);
    COutPoint vout = Lock(c, vp, 8000);
    CScript ispk = BuildIntent(IntentFor(vp, vspk, Recipient(60)));
    // Selector 4 obeys S-2 like an unlock.
    BOOST_CHECK_EQUAL(*c.Try(SpendTx(c, vout, 4, {CTxOut(8000, Recipient(60))})), "bad-txns-vault-value");
    BOOST_REQUIRE(!c.Block1(SpendTx(c, vout, 4, {CTxOut(8000, ispk)})));
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->lockedValue, 8000);   // only the plain V remains
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
    // k1 leaves; after the exit delay a spend of its bond then fails I-0: nothing may stick.
    BOOST_REQUIRE(!c.Block1(RemoveTx(c, s, k1.GetPubKey(), false, {k1})));
    c.Empty(5);
    m = Member(c, s, k1);
    VaultParams vp = VaultFor(s, MakeKey(50));
    CScript ispk = BuildIntent(IntentFor(vp, BuildVault(vp), Recipient(1)));
    CMutableTransaction bad = SpendTx(c, m.bondOutpoint, 1, {CTxOut(900, ispk)}, false);
    VaultState st(c.kv);
    BOOST_CHECK_EQUAL(*Res(st.ApplyTx(CTransaction(bad), c.h, c.coins)), "bad-txns-vault-intent");
    BOOST_CHECK(st.Changes().empty());
    BOOST_CHECK_EQUAL(GetMember(st, s, k1.GetPubKey())->status, MEMBER_REMOVED);
    BOOST_CHECK(GetBond(st, m.bondOutpoint));
    // A missing input coin is a rejection, not a silent pass.
    CMutableTransaction orphan;
    orphan.vin.push_back(CTxIn(COutPoint(uint256S("0xdead"), 0), CScript(), 0xffffffff));
    orphan.vout.push_back(CTxOut(1, Recipient(1)));
    BOOST_CHECK_EQUAL(*Res(st.ApplyTx(CTransaction(orphan), c.h, c.coins)), "bad-txns-vault-inputs-missing");
    // CheckTx over a snapshot of the tip.
    SetSnapshot snap(c.kv);
    BOOST_CHECK_EQUAL(*Res(CheckTx(CTransaction(HeartbeatTx(c, s, k1)), c.coins, c.h, snap)), "bad-vault-act-heartbeat");   // k1 left
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
    BOOST_REQUIRE(!c.Block1(RemoveTx(c, s, k2.GetPubKey(), false, {k2})));        // k2 leaves (the bond exit delay)
    c.Empty(5);
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
    BOOST_CHECK_EQUAL(db.GetVersion(), 1u);                 // no version key: a database from before it (review A3)
    BOOST_CHECK(!GetSet(db, s));                            // a miss, cached as absent (audit 01/V-6 contract) ...
    connect({create}, h1, h0, 100);
    BOOST_CHECK_EQUAL(db.GetVersion(), VAULT_DB_VERSION);   // written with every connected block
    BOOST_CHECK_EQUAL(VAULT_DB_VERSION, 3u);
    BOOST_CHECK(db.GetTip(tip, tipHeight) && tip == h1 && tipHeight == 100);
    BOOST_CHECK(!!GetSet(db, s));                           // ... replaced by the commit's value, never the stale read
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

BOOST_AUTO_TEST_CASE(db_undo_prune)
{
    // Audit 07/F-7: connecting block h erases the undo of block h - UNDO_KEEP in the same batch (the caller,
    // UndoToPrune, names it); disconnects within the horizon work, one past it fails on the missing undo —
    // the condition Reconcile turns into a wipe + replay.
    VaultDB db(fs::temp_directory_path() / "vault_db_prune_test", 1 << 20, /*fMemory=*/true, /*fWipe=*/true);
    const int64_t start = 100;
    auto hashAt = [](int64_t h) { return ArithToUint256(arith_uint256((uint64_t)h + 0x10000)); };
    const int n = UNDO_KEEP + 2;
    for (int64_t h = start; h < start + n; h++) {
        VaultState st(db);
        BlockUndo undo;
        BOOST_REQUIRE(!st.ApplyBlock(CBlock(), h, MapCoinAccessor(), undo));
        std::optional<uint256> prune;
        if (h - UNDO_KEEP >= start) prune = hashAt(h - UNDO_KEEP);
        BOOST_REQUIRE(db.ConnectBlock(hashAt(h), h, hashAt(h - 1), st, undo, prune));
    }
    const int64_t tipH = start + n - 1;
    BlockUndo u;
    BOOST_CHECK(!db.ReadUndo(hashAt(start), u));
    BOOST_CHECK(!db.ReadUndo(hashAt(start + 1), u));
    BOOST_CHECK(db.ReadUndo(hashAt(start + 2), u));
    BOOST_CHECK(db.ReadUndo(hashAt(tipH), u));
    size_t undos = 0;
    db.Iterate(std::string(1, KEY_UNDO), [&](const std::string&, const std::string&) { undos++; return true; });
    BOOST_CHECK_EQUAL(undos, (size_t)UNDO_KEEP);
    // Disconnect back through the horizon: every block still holding its undo, then the first without one.
    int64_t h = tipH;
    for (; h > tipH - UNDO_KEEP; h--) {
        BOOST_REQUIRE_MESSAGE(db.DisconnectBlock(hashAt(h), hashAt(h - 1), h - 1), "disconnect at " << h);
    }
    BOOST_CHECK_EQUAL(h, start + 1);
    BOOST_CHECK(!db.DisconnectBlock(hashAt(h), hashAt(h - 1), h - 1));   // pruned: Reconcile wipes and replays
    uint256 tip;
    int64_t tipHeight;
    BOOST_CHECK(db.GetTip(tip, tipHeight) && tip == hashAt(start + 1) && tipHeight == start + 1);
}

BOOST_AUTO_TEST_CASE(set_sig_checker)
{
    Chain c;
    CKey k1 = MakeKey(1), k2 = MakeKey(2), k3 = MakeKey(3);
    SetId s = SetWithMembers(c, {k1, k2}); // unlock 2, cancel 1
    BOOST_REQUIRE(!c.Block1(JoinTx(c, s, k3, {}))); // k3 immature
    auto snap = std::make_shared<const SetSnapshot>(c.kv);

    CScript scriptCode = BuildVault(VaultFor(s, MakeKey(50)));
    // A v4 spend: the sighash commits to the branch and the amount (T-2, 01/T-2).
    CMutableTransaction m = SaplingSpend({COutPoint(uint256S("0xabc"), 1)}, {CTxOut(1000, Recipient(9))});
    CTransaction tx(m);
    const CAmount amount = 5000;
    PrecomputedTransactionData txdata(tx, {CTxOut(amount, scriptCode)});
    const uint32_t branch = VaultBranchId();
    BOOST_REQUIRE_EQUAL(branch, 0x6d5b7a31U);
    SetSigChecker checker(&tx, 0, amount, false, txdata, snap, c.h);
    BOOST_CHECK(*checker.SetThreshold(s, ROLE_UNLOCK) == 2);
    BOOST_CHECK(*checker.SetThreshold(s, ROLE_CANCEL) == 1);
    BOOST_CHECK(!checker.SetThreshold(uint256S("0x5"), ROLE_UNLOCK));
    BOOST_CHECK(!checker.IsSetReleased(s));
    BOOST_CHECK(checker.IsSetReleased(uint256S("0x5")));

    uint256 sighash = SignatureHash(scriptCode, tx, 0, SET_SIG_HASHTYPE, amount, branch, txdata);
    auto signAt = [&](const CKey& k, uint8_t role, const COutPoint& prevout, const uint256& sh) {
        valtype sig;
        BOOST_REQUIRE(SignRecoverable(k, SetSigMsg(s, role, prevout, sh), sig));
        return sig;
    };
    auto sign = [&](const CKey& k, uint8_t role, const uint256& sh) { return signAt(k, role, tx.vin[0].prevout, sh); };
    BOOST_CHECK(checker.CheckSetSigs(s, ROLE_UNLOCK, {sign(k1, 1, sighash), sign(k2, 1, sighash)}, scriptCode, branch));
    BOOST_CHECK(checker.CheckSetSigs(s, ROLE_UNLOCK, {sign(k2, 1, sighash), sign(k1, 1, sighash)}, scriptCode, branch));
    BOOST_CHECK(!checker.CheckSetSigs(s, ROLE_UNLOCK, {sign(k1, 1, sighash)}, scriptCode, branch));
    BOOST_CHECK(!checker.CheckSetSigs(s, ROLE_UNLOCK, {sign(k1, 1, sighash), sign(k1, 1, sighash)}, scriptCode, branch));
    BOOST_CHECK(!checker.CheckSetSigs(s, ROLE_UNLOCK, {sign(k1, 1, sighash), sign(k3, 1, sighash)}, scriptCode, branch)); // immature
    BOOST_CHECK(!checker.CheckSetSigs(s, ROLE_UNLOCK, {sign(k1, 1, sighash), sign(MakeKey(9), 1, sighash)}, scriptCode, branch));
    // Bound to the role, the sighash (hence scriptCode, branch and amount) and the outpoint.
    BOOST_CHECK(!checker.CheckSetSigs(s, ROLE_CANCEL, {sign(k1, 1, sighash)}, scriptCode, branch));
    BOOST_CHECK(checker.CheckSetSigs(s, ROLE_CANCEL, {sign(k1, 2, sighash)}, scriptCode, branch));
    BOOST_CHECK(!checker.CheckSetSigs(s, ROLE_CANCEL, {sign(k1, 2, sighash)}, Recipient(1), branch));
    BOOST_CHECK(!checker.CheckSetSigs(uint256S("0x5"), ROLE_CANCEL, {sign(k1, 2, sighash)}, scriptCode, branch));

    // The branch ID: signatures over another branch's sighash (Sapling's, and 0) are refused under the Vault branch,
    // and the Vault branch's signatures are refused when the checker is asked for another branch.
    for (uint32_t other : {(uint32_t)0, NetworkUpgradeInfo[Consensus::UPGRADE_SAPLING].nBranchId}) {
        const uint256 sighashOther = SignatureHash(scriptCode, tx, 0, SET_SIG_HASHTYPE, amount, other, txdata);
        BOOST_REQUIRE(sighashOther != sighash);
        BOOST_CHECK(!checker.CheckSetSigs(s, ROLE_UNLOCK, {sign(k1, 1, sighashOther), sign(k2, 1, sighashOther)}, scriptCode, branch));
        BOOST_CHECK(!checker.CheckSetSigs(s, ROLE_CANCEL, {sign(k1, 2, sighashOther)}, scriptCode, branch));
        BOOST_CHECK(!checker.CheckSetSigs(s, ROLE_UNLOCK, {sign(k1, 1, sighash), sign(k2, 1, sighash)}, scriptCode, other));
        // ... and each is valid for the branch it was made for (the refusal above is the branch, not the signature)
        BOOST_CHECK(checker.CheckSetSigs(s, ROLE_UNLOCK, {sign(k1, 1, sighashOther), sign(k2, 1, sighashOther)}, scriptCode, other));
    }

    // The outpoint: signatures whose message names another prevout (same sighash) are refused; the checker binds
    // txTo->vin[nIn].prevout, not anything the signer chose.
    const COutPoint other(uint256S("0xabd"), 1);
    BOOST_CHECK(!checker.CheckSetSigs(s, ROLE_UNLOCK, {signAt(k1, 1, other, sighash), signAt(k2, 1, other, sighash)}, scriptCode, branch));
    BOOST_CHECK(!checker.CheckSetSigs(s, ROLE_CANCEL, {signAt(k1, 2, COutPoint(tx.vin[0].prevout.hash, 0), sighash)}, scriptCode, branch));

    // The amount: a checker for amount + 1 (the coin's real value differs from what the signers saw) refuses the
    // signatures made over `amount`, and accepts signatures over its own.
    SetSigChecker checkerAmount(&tx, 0, amount + 1, false, txdata, snap, c.h);
    BOOST_CHECK(!checkerAmount.CheckSetSigs(s, ROLE_UNLOCK, {sign(k1, 1, sighash), sign(k2, 1, sighash)}, scriptCode, branch));
    BOOST_CHECK(!checkerAmount.CheckSetSigs(s, ROLE_CANCEL, {sign(k1, 2, sighash)}, scriptCode, branch));
    const uint256 sighashAmount = SignatureHash(scriptCode, tx, 0, SET_SIG_HASHTYPE, amount + 1, branch, txdata);
    BOOST_CHECK(checkerAmount.CheckSetSigs(s, ROLE_UNLOCK, {sign(k1, 1, sighashAmount), sign(k2, 1, sighashAmount)}, scriptCode, branch));

    // The input index: in a two-input transaction, signatures made for input 0 do not verify for input 1.
    {
        CMutableTransaction m2 = SaplingSpend({COutPoint(uint256S("0xabc"), 1), COutPoint(uint256S("0xabe"), 0)}, {CTxOut(1000, Recipient(9))});
        CTransaction tx2(m2);
        PrecomputedTransactionData txdata2(tx2, {CTxOut(amount, scriptCode), CTxOut(amount, scriptCode)});
        const uint256 sh0 = SignatureHash(scriptCode, tx2, 0, SET_SIG_HASHTYPE, amount, branch, txdata2);
        const std::vector<valtype> sigs0 = {signAt(k1, 1, tx2.vin[0].prevout, sh0), signAt(k2, 1, tx2.vin[0].prevout, sh0)};
        SetSigChecker in0(&tx2, 0, amount, false, txdata2, snap, c.h);
        SetSigChecker in1(&tx2, 1, amount, false, txdata2, snap, c.h);
        BOOST_CHECK(in0.CheckSetSigs(s, ROLE_UNLOCK, sigs0, scriptCode, branch));
        BOOST_CHECK(!in1.CheckSetSigs(s, ROLE_UNLOCK, sigs0, scriptCode, branch));
        // nIn past the inputs fails closed (no throw)
        SetSigChecker in2(&tx2, 2, amount, false, txdata2, snap, c.h);
        BOOST_CHECK(!in2.CheckSetSigs(s, ROLE_UNLOCK, sigs0, scriptCode, branch));

        // The rest of the transaction: under SIGHASH_ALL another input (a builder's fee input) invalidates the
        // signatures; under SIGHASH_ALL|ANYONECANPAY (MEDIUM-01-V-2) it does not. Either way another output does.
        CMutableTransaction m3 = SaplingSpend({COutPoint(uint256S("0xabc"), 1), COutPoint(uint256S("0xfee"), 0)}, {CTxOut(1000, Recipient(9))});
        CTransaction tx3(m3);
        PrecomputedTransactionData txdata3(tx3, {CTxOut(amount, scriptCode), CTxOut(amount, Recipient(8))});
        SetSigChecker fee(&tx3, 0, amount, false, txdata3, snap, c.h);
        const bool anyoneCanPay = (SET_SIG_HASHTYPE & SIGHASH_ANYONECANPAY) != 0;
        BOOST_CHECK_EQUAL(fee.CheckSetSigs(s, ROLE_UNLOCK, sigs0, scriptCode, branch), anyoneCanPay);
        CMutableTransaction m4 = m2;
        m4.vout[0].nValue -= 1;
        CTransaction tx4(m4);
        PrecomputedTransactionData txdata4(tx4, {CTxOut(amount, scriptCode), CTxOut(amount, scriptCode)});
        SetSigChecker out(&tx4, 0, amount, false, txdata4, snap, c.h);
        BOOST_CHECK(!out.CheckSetSigs(s, ROLE_UNLOCK, sigs0, scriptCode, branch));
    }

    // A checker without a snapshot fails closed.
    SetSigChecker none(&tx, 0, amount, false, txdata, nullptr, c.h);
    BOOST_CHECK(!none.SetThreshold(s, ROLE_UNLOCK));
    BOOST_CHECK(!none.IsSetReleased(s));
    BOOST_CHECK(!none.CheckSetSigs(s, ROLE_CANCEL, {sign(k1, 2, sighash)}, scriptCode, branch));
}

BOOST_AUTO_TEST_CASE(vault_checksetsig_real_script)
{
    // T-3 (01/T-3): the templates' set branches through VerifyScript with the real SetSigChecker over a real
    // SetSnapshot, so the interpreter's pop order, k from the snapshot, the member/current check and the released
    // predicate are covered in the fast tier. Each negative names the §15.2 step (or the opcode gate) its error is.
    Chain c;
    CKey k1 = MakeKey(1), k2 = MakeKey(2), k3 = MakeKey(3);
    SetId s = SetWithMembers(c, {k1, k2}); // unlock 2, cancel 1, livenessWindow 50
    BOOST_REQUIRE(!c.Block1(JoinTx(c, s, k3, {}))); // k3 joined, immature at c.h
    auto snap = std::make_shared<const SetSnapshot>(c.kv);
    const int64_t hCurrent = c.h;
    const int64_t hReleased = c.h + 100; // no heartbeat for > livenessWindow: dormant, hence released
    BOOST_REQUIRE(!snap->IsReleased(s, hCurrent));
    BOOST_REQUIRE(snap->IsReleased(s, hReleased));

    const uint32_t branch = VaultBranchId();
    const unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_VAULT | SCRIPT_VERIFY_PQ_FALCON;
    const unsigned int preVault = STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    const CAmount amount = 5 * COIN;

    // The owner: a Falcon key (fast to sign), for the OWNER-RELEASED branch.
    const uint8_t scheme = pq::SCHEME_FN_DSA_512;
    valtype pk, sk;
    BOOST_REQUIRE(pq::KeyGen(scheme, valtype(pq::SeedSize(scheme), 0x3c), pk, sk));
    VaultParams vp = VaultFor(s, MakeKey(50));
    vp.owner = CPQKeyID(scheme, pq::KeyHash(scheme, pk));
    const CScript vspk = BuildVault(vp);
    const CScript ispk = BuildIntent(IntentFor(vp, vspk, Recipient(60)));
    BOOST_REQUIRE(!vspk.empty() && !ispk.empty());

    const COutPoint prevout(uint256S("0x7a"), 0);
    const CTransaction tx(SaplingSpend({prevout}, {CTxOut(amount - 10000, ispk)}));
    PrecomputedTransactionData txdata(tx, {CTxOut(amount, vspk)});
    auto setSigs = [&](const CScript& spk, uint8_t role, const std::vector<CKey>& keys) {
        const uint256 sh = SignatureHash(spk, tx, 0, SET_SIG_HASHTYPE, amount, branch, txdata);
        CScript ss;
        for (const CKey& k : keys) {
            valtype sig;
            BOOST_REQUIRE(SignRecoverable(k, SetSigMsg(s, role, prevout, sh), sig));
            ss << sig;
        }
        return ss;
    };
    SetSigChecker checker(&tx, 0, amount, false, txdata, snap, hCurrent);
    SetSigChecker released(&tx, 0, amount, false, txdata, snap, hReleased);
    SetSigChecker unknown(&tx, 0, amount, false, txdata, nullptr, hCurrent);
    ScriptError err;

    // ---- V, selector 1 (UNLOCK): <sig1> <sig2> OP_1; the branch pushes <setId> OP_1 and OP_CHECKSETSIG pops role,
    // setId, then k = unlockThreshold = 2 signatures.
    const CScript unlock = setSigs(vspk, ROLE_UNLOCK, {k1, k2}) << OP_1;
    auto parsed = ParseTemplateSpend(vspk, unlock);
    BOOST_REQUIRE(parsed && parsed->kind == TemplateKind::VAULT && parsed->selector == SEL_UNLOCK);
    BOOST_CHECK_EQUAL(parsed->sigs.size(), 2U);
    BOOST_CHECK(VerifyScript(unlock, vspk, flags, checker, branch, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    BOOST_CHECK(VerifyScript(setSigs(vspk, ROLE_UNLOCK, {k2, k1}) << OP_1, vspk, flags, checker, branch, &err)); // any member order
    // step 1/3: one signature where the threshold is two (k > the stack) -> SETSIG
    BOOST_CHECK(!VerifyScript(setSigs(vspk, ROLE_UNLOCK, {k1}) << OP_1, vspk, flags, checker, branch, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SETSIG);
    // step 5: a signature by k3, a member not yet current (immature) -> SETSIG
    BOOST_CHECK(!VerifyScript(setSigs(vspk, ROLE_UNLOCK, {k1, k3}) << OP_1, vspk, flags, checker, branch, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SETSIG);
    // step 5: the same member twice -> SETSIG
    BOOST_CHECK(!VerifyScript(setSigs(vspk, ROLE_UNLOCK, {k1, k1}) << OP_1, vspk, flags, checker, branch, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SETSIG);
    // step 4: the cancel role's signatures on the unlock branch (the message binds the role) -> SETSIG
    BOOST_CHECK(!VerifyScript(setSigs(vspk, ROLE_CANCEL, {k1, k2}) << OP_1, vspk, flags, checker, branch, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SETSIG);
    // step 4: signatures over the intent's scriptCode, not the V's -> SETSIG
    BOOST_CHECK(!VerifyScript(setSigs(ispk, ROLE_UNLOCK, {k1, k2}) << OP_1, vspk, flags, checker, branch, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SETSIG);
    // step 2: the set unknown to the checker (no snapshot: fails closed) -> SETSIG
    BOOST_CHECK(!VerifyScript(unlock, vspk, flags, unknown, branch, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SETSIG);
    // step 2: a V naming a set that does not exist -> SETSIG
    {
        VaultParams other = vp;
        other.setId = uint256S("0x5e7");
        BOOST_CHECK(!VerifyScript(unlock, BuildVault(other), flags, checker, branch, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SETSIG);
    }
    // step 3: a signature that is not a 65-byte compact recoverable signature -> SETSIG
    BOOST_CHECK(!VerifyScript(CScript() << valtype(64, 0x11) << valtype(65, 0x22) << OP_1, vspk, flags, checker, branch, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SETSIG);
    // the branch ID: the same scriptSig checked for the Sapling branch -> SETSIG
    BOOST_CHECK(!VerifyScript(unlock, vspk, flags, checker, NetworkUpgradeInfo[Consensus::UPGRADE_SAPLING].nBranchId, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SETSIG);
    // before the upgrade (no SCRIPT_VERIFY_VAULT): the executed 0xc0 is a bad opcode -> BAD_OPCODE
    BOOST_CHECK(!VerifyScript(unlock, vspk, preVault, checker, branch, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
    // a released set does not weaken the unlock branch: still two current members' signatures
    BOOST_CHECK(!VerifyScript(setSigs(vspk, ROLE_UNLOCK, {k1}) << OP_1, vspk, flags, released, branch, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SETSIG);

    // One executed OP_CHECKSETSIG per script (§15.2): a (non-template) script running it twice -> SETSIG_COUNT,
    // with signatures that would pass the first.
    {
        CScript twice = CScript() << valtype(s.begin(), s.end()) << OP_2 << VAULT_OP_CHECKSETSIG << OP_VERIFY
                                  << valtype(s.begin(), s.end()) << OP_2 << VAULT_OP_CHECKSETSIG;
        CScript ss = setSigs(twice, ROLE_CANCEL, {k1}) + setSigs(twice, ROLE_CANCEL, {k2});
        BOOST_CHECK(!VerifyScript(ss, twice, flags, checker, branch, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SETSIG_COUNT);
        CScript once = CScript() << valtype(s.begin(), s.end()) << OP_2 << VAULT_OP_CHECKSETSIG;
        BOOST_CHECK(VerifyScript(setSigs(once, ROLE_CANCEL, {k2}), once, flags, checker, branch, &err));
    }

    // ---- I, selector 2 (CANCEL): <sig> OP_2; the branch pushes <cancelSetId> OP_2, k = cancelThreshold = 1.
    const CScript cancel = setSigs(ispk, ROLE_CANCEL, {k2}) << OP_2;
    parsed = ParseTemplateSpend(ispk, cancel);
    BOOST_REQUIRE(parsed && parsed->kind == TemplateKind::INTENT && parsed->selector == SEL_OWNER);
    BOOST_CHECK(VerifyScript(cancel, ispk, flags, checker, branch, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    // no signature -> SETSIG (k = 1 > the empty stack)
    BOOST_CHECK(!VerifyScript(CScript() << OP_2, ispk, flags, checker, branch, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SETSIG);
    // the unlock role's signature on the cancel branch -> SETSIG
    BOOST_CHECK(!VerifyScript(setSigs(ispk, ROLE_UNLOCK, {k2}) << OP_2, ispk, flags, checker, branch, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SETSIG);
    // an immature member -> SETSIG
    BOOST_CHECK(!VerifyScript(setSigs(ispk, ROLE_CANCEL, {k3}) << OP_2, ispk, flags, checker, branch, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SETSIG);
    // a cancel signature over the V's scriptCode -> SETSIG
    BOOST_CHECK(!VerifyScript(setSigs(vspk, ROLE_CANCEL, {k2}) << OP_2, ispk, flags, checker, branch, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SETSIG);
    // before the upgrade -> BAD_OPCODE
    BOOST_CHECK(!VerifyScript(cancel, ispk, preVault, checker, branch, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);

    // ---- V, selector 3 (OWNER-RELEASED): <setId> OP_CHECKSETDORMANT OP_VERIFY, then the owner's OP_CHECKPQSIG.
    const uint256 ownerSighash = SignatureHash(vspk, tx, 0, SIGHASH_ALL, amount, branch, txdata);
    valtype ownerSig;
    BOOST_REQUIRE(pq::Sign(scheme, sk, ownerSighash, ownerSig));
    ownerSig.push_back(SIGHASH_ALL);
    const CScript ownerReleased = OwnerScriptSig(ownerSig, pk, SEL_RELEASED);
    parsed = ParseTemplateSpend(vspk, ownerReleased);
    BOOST_REQUIRE(parsed && parsed->kind == TemplateKind::VAULT && parsed->selector == SEL_RELEASED);
    BOOST_CHECK(VerifyScript(ownerReleased, vspk, flags, released, branch, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    // the set is current (not released): OP_CHECKSETDORMANT pushes false -> VERIFY
    BOOST_CHECK(!VerifyScript(ownerReleased, vspk, flags, checker, branch, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_VERIFY);
    // a checker without a snapshot answers "not released" (fails closed) -> VERIFY
    SetSigChecker unknownLater(&tx, 0, amount, false, txdata, nullptr, hReleased);
    BOOST_CHECK(!VerifyScript(ownerReleased, vspk, flags, unknownLater, branch, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_VERIFY);
    // before the upgrade: the executed 0xc1 -> BAD_OPCODE
    BOOST_CHECK(!VerifyScript(ownerReleased, vspk, preVault, released, branch, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
    // the released predicate opens only the owner's branch: another owner's signature still fails
    {
        valtype pk2, sk2, sig2;
        BOOST_REQUIRE(pq::KeyGen(scheme, valtype(pq::SeedSize(scheme), 0x3d), pk2, sk2));
        BOOST_REQUIRE(pq::Sign(scheme, sk2, ownerSighash, sig2));
        sig2.push_back(SIGHASH_ALL);
        BOOST_CHECK(!VerifyScript(OwnerScriptSig(sig2, pk2, SEL_RELEASED), vspk, flags, released, branch, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);
    }
}

BOOST_AUTO_TEST_CASE(set_sig_checker_refee)
{
    // 01/V-2: a set signature is over SIGHASH_ALL|SIGHASH_ANYONECANPAY, so it binds the template input and every
    // output but not the fee inputs: a re-funded spend verifies with the original signatures and has the same
    // sighash (no equivocation); anything else the signers agreed to does not.
    Chain c;
    CKey k1 = MakeKey(1), k2 = MakeKey(2);
    SetId s = SetWithMembers(c, {k1, k2});   // unlock 2, cancel 1
    SetId other = SetWithMembers(c, {k1, k2});
    BOOST_REQUIRE(other != s);
    auto snap = std::make_shared<const SetSnapshot>(c.kv);
    CScript scriptCode = BuildVault(VaultFor(s, MakeKey(50)));
    const CAmount amount = 5000;
    const uint32_t branch = 0x6d5b7a31;      // the Vault branch ID
    const COutPoint templ(uint256S("0xabc"), 1);

    CMutableTransaction a;
    a.fOverwintered = true;                  // a v4 (Sapling) transaction: ZIP-243, bound to the branch ID
    a.nVersion = SAPLING_TX_VERSION;
    a.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    a.vin.push_back(CTxIn(templ, CScript(), 0xffffffff));
    a.vin.push_back(CTxIn(COutPoint(uint256S("0xfee1"), 0), CScript(), 0xffffffff));
    a.vout.push_back(CTxOut(4000, Recipient(9)));
    a.vout.push_back(CTxOut(1000, scriptCode));
    a.vout.push_back(CTxOut(700, Recipient(8)));     // the builder's change
    const CTransaction ta(a);
    PrecomputedTransactionData da(ta, std::vector<CTxOut>(ta.vin.size(), CTxOut(amount, scriptCode)));
    const uint256 sh = SignatureHash(scriptCode, ta, 0, SIGHASH_ALL | SIGHASH_ANYONECANPAY, amount, branch, da);
    const uint256 shAll = SignatureHash(scriptCode, ta, 0, SIGHASH_ALL, amount, branch, da);
    BOOST_CHECK(sh != shAll);
    auto sign = [&](const CKey& k, const SetId& id, uint8_t role, const uint256& h) {
        valtype sig;
        BOOST_REQUIRE(SignRecoverable(k, SetSigMsg(id, role, templ, h), sig));
        return sig;
    };
    const std::vector<valtype> sigs = {sign(k1, s, 1, sh), sign(k2, s, 1, sh)};
    auto check = [&](const CMutableTransaction& m, const SetId& id, uint8_t role, const std::vector<valtype>& sg, uint32_t br) {
        const CTransaction t(m);
        PrecomputedTransactionData d(t, std::vector<CTxOut>(t.vin.size(), CTxOut(amount, scriptCode)));
        SetSigChecker checker(&t, 0, amount, false, d, snap, c.h);
        return checker.CheckSetSigs(id, role, sg, scriptCode, br);
    };
    auto digest = [&](const CMutableTransaction& m) {
        const CTransaction t(m);
        PrecomputedTransactionData d(t, std::vector<CTxOut>(t.vin.size(), CTxOut(amount, scriptCode)));
        return SignatureHash(scriptCode, t, 0, SIGHASH_ALL | SIGHASH_ANYONECANPAY, amount, branch, d);
    };
    BOOST_CHECK(check(a, s, ROLE_UNLOCK, sigs, branch));

    // Re-funded: the fee input replaced, then another added; same sighash, the same signatures verify.
    CMutableTransaction b = a;
    b.vin[1].prevout = COutPoint(uint256S("0xfee2"), 3);
    BOOST_CHECK(digest(b) == sh);
    BOOST_CHECK(check(b, s, ROLE_UNLOCK, sigs, branch));
    b.vin.push_back(CTxIn(COutPoint(uint256S("0xfee3"), 0), CScript(), 0xfffffffe));
    BOOST_CHECK(digest(b) == sh);
    BOOST_CHECK(check(b, s, ROLE_UNLOCK, sigs, branch));
    // The fee input's own scriptSig is not signed either (it is signed after the set signatures).
    b.vin[1].scriptSig = CScript() << OP_1;
    BOOST_CHECK(check(b, s, ROLE_UNLOCK, sigs, branch));

    // Negatives: an output changed (the change too), one added, the template prevout, its sequence, nLockTime,
    // another set, another role, another branch ID, a signature over the old SIGHASH_ALL digest.
    CMutableTransaction m = a;
    m.vout[0].nValue -= 1;
    BOOST_CHECK(!check(m, s, ROLE_UNLOCK, sigs, branch));
    m = a; m.vout[2].nValue -= 1;
    BOOST_CHECK(!check(m, s, ROLE_UNLOCK, sigs, branch));
    m = a; m.vout.push_back(CTxOut(1, Recipient(7)));
    BOOST_CHECK(!check(m, s, ROLE_UNLOCK, sigs, branch));
    m = a; m.vin[0].prevout = COutPoint(uint256S("0xabd"), 1);
    BOOST_CHECK(!check(m, s, ROLE_UNLOCK, sigs, branch));
    m = a; m.vin[0].nSequence = 0xfffffffe;
    BOOST_CHECK(!check(m, s, ROLE_UNLOCK, sigs, branch));
    m = a; m.nLockTime = 7;
    BOOST_CHECK(!check(m, s, ROLE_UNLOCK, sigs, branch));
    BOOST_CHECK(!check(a, other, ROLE_UNLOCK, sigs, branch));
    BOOST_CHECK(!check(a, other, ROLE_UNLOCK, {sign(k1, other, 1, sh), sign(k2, s, 1, sh)}, branch));
    BOOST_CHECK(check(a, other, ROLE_UNLOCK, {sign(k1, other, 1, sh), sign(k2, other, 1, sh)}, branch));
    BOOST_CHECK(!check(a, s, ROLE_CANCEL, {sigs[0]}, branch));
    BOOST_CHECK(check(a, s, ROLE_CANCEL, {sign(k1, s, 2, sh)}, branch));
    BOOST_CHECK(!check(a, s, ROLE_UNLOCK, sigs, 0));
    BOOST_CHECK(!check(a, s, ROLE_UNLOCK, sigs, 0x76b809bb));     // Sapling's branch ID
    BOOST_CHECK(!check(a, s, ROLE_UNLOCK, {sign(k1, s, 1, shAll), sign(k2, s, 1, shAll)}, branch));

    // Two re-funded builds have one sighash: SET_EQUIVOCATION over them is refused (equal is not equivocation).
    Act e;
    e.type = ACT_SET_EQUIVOCATION;
    e.equivocation.setId = s;
    e.equivocation.prevout = templ;
    e.equivocation.roleA = 1;
    e.equivocation.sighashA = sh;
    e.equivocation.sigA = sigs[0];
    e.equivocation.roleB = 1;
    e.equivocation.sighashB = digest(b);
    BOOST_REQUIRE(SignRecoverable(k1, SetSigMsg(s, 1, templ, e.equivocation.sighashB), e.equivocation.sigB));
    BOOST_CHECK_EQUAL(*c.Try(ActTx(c, e, {})), "bad-vault-act-equivocation");
}

BOOST_AUTO_TEST_CASE(module_table_registers_yed)
{
    // P4 (§15.7): the table holds exactly YED; WYEC is never registered (§4).
    BOOST_CHECK_EQUAL(Modules().size(), 1u);
    const Module* yed = FindModule(Tag{{'Y', 'E', 'D', 0x00}});
    BOOST_REQUIRE(yed != nullptr);
    BOOST_CHECK(yed == yellowback::RegisteredModule());
    BOOST_CHECK(FindModule(Tag{{'W', 'Y', 'E', 'C'}}) == nullptr);

    // Unconfigured (no attestor set, U-22): the module accepts everything (the §5.4 fallback).
    yellowback::ClearModuleParams();
    const uint256 set = uint256S("0x5e7");
    const yellowback::Params p = yellowback::RegtestParams(10, 0, 0, set);
    CKey owner = CKey::TestOnlyRandomKey(true);
    const CPubKey ownerPub = owner.GetPubKey();
    VaultParams good = yellowback::YedVaultParams(p, CPQKeyID(1, Hash(ownerPub.begin(), ownerPub.end())), 50);
    VaultParams other = good;
    other.setId = uint256S("0x99");
    CMutableTransaction mtx;
    const CTransaction tx(mtx);
    ModuleContext ctx;
    BOOST_CHECK(!yed->ValidateCreate(tx, 0, other, ctx).has_value());
    TemplateSpend unlock;
    unlock.kind = TemplateKind::VAULT;
    unlock.selector = SEL_UNLOCK;
    BOOST_CHECK(!yed->ValidateSpend(tx, 0, unlock, ctx).has_value());

    // Configured: the YED vault's shape, no set unlock of a YED vault, no owner-released spend of a YED intent.
    yellowback::SetModuleParams(p);
    BOOST_CHECK(!yed->ValidateCreate(tx, 0, good, ctx).has_value());
    BOOST_CHECK_EQUAL(yed->ValidateCreate(tx, 0, other, ctx).value_or(""), "bad-yellowback-vault-set");
    VaultParams cancel = good;
    cancel.cancelSetId = uint256S("0x98");
    BOOST_CHECK_EQUAL(yed->ValidateCreate(tx, 0, cancel, ctx).value_or(""), "bad-yellowback-vault-set");
    VaultParams delay = good;
    delay.delay = p.claimDelay + 1;
    BOOST_CHECK_EQUAL(yed->ValidateCreate(tx, 0, delay, ctx).value_or(""), "bad-yellowback-vault-delay");
    VaultParams app = good;
    app.appHeight = good.ownerHeight + p.grace + 1;                 // IT-1: later than the pre-plan term end
    BOOST_CHECK_EQUAL(yed->ValidateCreate(tx, 0, app, ctx).value_or(""), "bad-yellowback-vault-height");
    app.appHeight = 0;                                              // a disabled APP branch is no YED vault
    BOOST_CHECK_EQUAL(yed->ValidateCreate(tx, 0, app, ctx).value_or(""), "bad-yellowback-vault-height");
    app.appHeight = good.ownerHeight + p.grace;                     // the pre-plan shape is still a YED vault (spends)
    BOOST_CHECK(!yed->ValidateCreate(tx, 0, app, ctx).has_value());
    BOOST_CHECK_EQUAL(yed->ValidateSpend(tx, 0, unlock, ctx).value_or(""), "bad-yellowback-vault-unlock");
    for (uint8_t sel : { SEL_OWNER, SEL_RELEASED, SEL_APP }) {
        TemplateSpend s;
        s.kind = TemplateKind::VAULT;
        s.selector = sel;
        BOOST_CHECK(!yed->ValidateSpend(tx, 0, s, ctx).has_value());
    }
    TemplateSpend ownerIntent;
    ownerIntent.kind = TemplateKind::INTENT;
    ownerIntent.selector = SEL_RELEASED;
    BOOST_CHECK_EQUAL(yed->ValidateSpend(tx, 0, ownerIntent, ctx).value_or(""), "bad-yellowback-intent-owner");
    for (uint8_t sel : { SEL_UNLOCK, SEL_OWNER }) {
        TemplateSpend s;
        s.kind = TemplateKind::INTENT;
        s.selector = sel;
        BOOST_CHECK(!yed->ValidateSpend(tx, 0, s, ctx).has_value());
    }
    yellowback::ClearModuleParams();
    BOOST_CHECK(!yed->ValidateCreate(tx, 0, other, ctx).has_value());
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

BOOST_AUTO_TEST_CASE(module_ejection_hook_eqv1_yed)
{
    // P4-b (U-25, the YED half; ycash-dd's module_ejection_hook_eqv1): the YED module names the attestor-set member whose key signed two prices for one
    // (seq, citedHeight, blockHash) in an EQUIVOCATION transaction; the primitive ejects it and freezes its bond.
    Chain c;
    const CKey k1 = MakeKey(61), k2 = MakeKey(62), outsider = MakeKey(63);
    const SetId s = SetWithMembers(c, {k1, k2});
    const COutPoint bond1 = Member(c, s, k1).bondOutpoint;
    const int64_t cited = c.h - 3;
    auto fakeHash = [](int64_t h) { uint256 x; x.begin()[0] = (unsigned char)(h & 0xff); x.begin()[1] = (unsigned char)((h >> 8) & 0xff); x.begin()[31] = 0xab; return x; };
    BlockHashFn hashes = [&](int64_t h) -> std::optional<uint256> { if (h < 0 || h >= c.h) return std::nullopt; return fakeHash(h); };
    auto att = [&](const CKey& k, uint32_t price, int64_t at) {
        yellowback::Attestation a;
        a.seq = 7;
        a.priceMicroUsd = price;
        a.citedHeight = (uint32_t)at;
        std::vector<unsigned char> rec;
        BOOST_REQUIRE(k.SignCompact(yellowback::AttestMessage(a.seq, a.priceMicroUsd, a.citedHeight, fakeHash(at)), rec));
        std::copy(rec.begin() + 1, rec.end(), a.sig.begin());
        return a;
    };
    auto eqvTx = [&](const yellowback::Attestation& a, const yellowback::Attestation& b) {
        yellowback::Bundle bundle;
        bundle.atts = { a, b };
        const valtype raw = yellowback::EncodeBundle(bundle);
        uint256 h;
        CSHA256().Write(raw.data(), raw.size()).Finalize(h.begin());
        const CScript redeem = yellowback::CarrierScript(MakeKey(64).GetPubKey(), h);
        CMutableTransaction m;
        m.vin.push_back(CTxIn(c.Fund(), yellowback::CarrierScriptSig(raw, valtype(71, 0x30), redeem)));
        m.vout.push_back(CTxOut(0, yellowback::PayloadScript(yellowback::EncodePayload(yellowback::Payload::Equivocation()))));
        return m;
    };
    auto apply = [&](const CMutableTransaction& m, VaultState& st, bool withHashes) {
        if (withHashes) st.SetBlockHashes(hashes);
        return Res(st.ApplyTx(CTransaction(m), c.h, c.coins));
    };
    const CMutableTransaction e = eqvTx(att(k1, 50000, cited), att(k1, 51000, cited));

    // Unconfigured module: nothing happens (and the transaction is valid).
    yellowback::ClearModuleParams();
    { VaultState st(c.kv); BOOST_CHECK_EQUAL(*apply(e, st, true), "OK"); BOOST_CHECK(st.Changes().empty() || !GetBond(st, bond1)->frozen); }
    const yellowback::Params p = yellowback::RegtestParams(10, 0, 0, s);
    yellowback::SetModuleParams(p);
    BOOST_CHECK(yellowback::RegisteredModule()->GovernedSet() == std::optional<SetId>(s));
    // No block hashes: the module cannot verify, nothing happens.
    { VaultState st(c.kv); BOOST_CHECK_EQUAL(*apply(e, st, false), "OK"); BOOST_CHECK(!GetBond(st, bond1)->frozen); }
    // Not an equivocation (same price; another key; a cited height at or above the block): nothing happens, all valid.
    { VaultState st(c.kv); BOOST_CHECK_EQUAL(*apply(eqvTx(att(k1, 50000, cited), att(k1, 50000, cited)), st, true), "OK"); BOOST_CHECK(!GetBond(st, bond1)->frozen); }
    { VaultState st(c.kv); BOOST_CHECK_EQUAL(*apply(eqvTx(att(outsider, 50000, cited), att(outsider, 51000, cited)), st, true), "OK");
      BOOST_CHECK_EQUAL(Member(c, s, k1).status, MEMBER_ACTIVE); BOOST_CHECK(!GetBond(st, bond1)->frozen); }
    { VaultState st(c.kv); BOOST_CHECK_EQUAL(*apply(eqvTx(att(k1, 50000, c.h), att(k1, 51000, c.h)), st, true), "OK"); BOOST_CHECK(!GetBond(st, bond1)->frozen); }
    // The equivocation: k1 EJECTED and its bond frozen; k2 untouched; the undo restores the base byte for byte.
    VaultState st(c.kv);
    BOOST_CHECK_EQUAL(*apply(e, st, true), "OK");
    BOOST_CHECK_EQUAL(GetMember(st, s, k1.GetPubKey())->status, MEMBER_EJECTED);
    BOOST_CHECK(GetMember(st, s, k1.GetPubKey())->bondFrozen);
    BOOST_CHECK(GetBond(st, bond1)->frozen);
    BOOST_CHECK_EQUAL(GetMember(st, s, k2.GetPubKey())->status, MEMBER_ACTIVE);
    // In the same block a later spend of the frozen bond is invalid; a second report changes nothing.
    {
        CMutableTransaction spend;
        spend.vin.push_back(CTxIn(bond1));
        spend.vout.push_back(CTxOut(500, GetScriptForDestination(k1.GetPubKey().GetID())));
        BOOST_CHECK_EQUAL(*Res(st.ApplyTx(CTransaction(spend), c.h, c.coins)), "bad-vault-bond-frozen");
        const auto before = st.Changes();
        BOOST_CHECK_EQUAL(*Res(st.ApplyTx(CTransaction(eqvTx(att(k1, 50000, cited), att(k1, 52000, cited))), c.h, c.coins)), "OK");
        BOOST_CHECK(st.Changes() == before);
    }
    const BlockUndo undo = st.MakeUndo();
    MemoryKV after = c.kv;
    after.Apply(st.Changes());
    VaultState back(after);
    back.ApplyUndo(undo);
    after.Apply(back.Changes());
    BOOST_CHECK(after.data == c.kv.data);
    // The same through ApplyBlock with the provider (what ConnectBlock does).
    {
        CBlock block;
        block.vtx.push_back(CTransaction(e));
        VaultState sb(c.kv);
        sb.SetBlockHashes(hashes);
        BlockUndo bu;
        BOOST_CHECK(!sb.ApplyBlock(block, c.h, c.coins, bu));
        BOOST_CHECK(GetBond(sb, bond1)->frozen);
    }
    yellowback::ClearModuleParams();
}

BOOST_AUTO_TEST_CASE(module_ejection_hook_cancel_statement)
{
    // C4b (cancel-limit design, owner 2026-10-13): EQV-1's second evidence shape on the primitive side -- a member's
    // regular attestation and its cancel statement (the co-signature it gave a YED cancel, "YX") at one height with
    // different prices. The primitive ejects the member and freezes its bond in the same block as the module's mirror.
    Chain c;
    const CKey k1 = MakeKey(71), k2 = MakeKey(72);
    const SetId s = SetWithMembers(c, {k1, k2});
    const COutPoint bond1 = Member(c, s, k1).bondOutpoint;
    const int64_t cited = c.h - 3;
    auto fakeHash = [](int64_t h) { uint256 x; x.begin()[0] = (unsigned char)(h & 0xff); x.begin()[1] = (unsigned char)((h >> 8) & 0xff); x.begin()[31] = 0xab; return x; };
    BlockHashFn hashes = [&](int64_t h) -> std::optional<uint256> { if (h < 0 || h >= c.h) return std::nullopt; return fakeHash(h); };
    auto att = [&](const CKey& k, uint32_t price, int64_t at) {
        yellowback::Attestation a;
        a.seq = 3;
        a.priceMicroUsd = price;
        a.citedHeight = (uint32_t)at;
        std::vector<unsigned char> rec;
        BOOST_REQUIRE(k.SignCompact(yellowback::AttestMessage(a.seq, a.priceMicroUsd, a.citedHeight, fakeHash(at)), rec));
        std::copy(rec.begin() + 1, rec.end(), a.sig.begin());
        return a;
    };
    auto statement = [&](const CKey& k, uint32_t price, int64_t at, const uint256& set) {
        yellowback::CancelStatement st;
        st.intent = COutPoint(uint256S("0x99"), 1);
        st.priceMicroUsd = price;
        BOOST_REQUIRE(SignRecoverable(k, yellowback::CancelCosignMessage(set, st.intent.hash, st.intent.n, (uint32_t)at, price, fakeHash(at)), st.sig));
        return st;
    };
    auto eqvTx = [&](const yellowback::Attestation& a, const yellowback::CancelStatement& st) {
        const valtype raw = yellowback::EncodeCancelEvidence(a, st);
        uint256 h;
        CSHA256().Write(raw.data(), raw.size()).Finalize(h.begin());
        const CScript redeem = yellowback::CarrierScript(MakeKey(64).GetPubKey(), h);
        CMutableTransaction m;
        m.vin.push_back(CTxIn(c.Fund(), yellowback::CarrierScriptSig(raw, valtype(71, 0x30), redeem)));
        m.vout.push_back(CTxOut(0, yellowback::PayloadScript(yellowback::EncodePayload(yellowback::Payload::Equivocation()))));
        return m;
    };
    auto apply = [&](const CMutableTransaction& m, VaultState& st) {
        st.SetBlockHashes(hashes);
        return Res(st.ApplyTx(CTransaction(m), c.h, c.coins));
    };
    const yellowback::Params p = yellowback::RegtestParams(10, 0, 0, s);
    yellowback::SetModuleParams(p);
    // Not evidence: the same price (an honest canceller); another member's statement; a statement over another set.
    { VaultState st(c.kv); BOOST_CHECK_EQUAL(*apply(eqvTx(att(k1, 50000, cited), statement(k1, 50000, cited, s)), st), "OK"); BOOST_CHECK(!GetBond(st, bond1)->frozen); }
    { VaultState st(c.kv); BOOST_CHECK_EQUAL(*apply(eqvTx(att(k1, 50000, cited), statement(k2, 60000, cited, s)), st), "OK"); BOOST_CHECK(!GetBond(st, bond1)->frozen);
      BOOST_CHECK_EQUAL(GetMember(st, s, k2.GetPubKey())->status, MEMBER_ACTIVE); }
    { VaultState st(c.kv); BOOST_CHECK_EQUAL(*apply(eqvTx(att(k1, 50000, cited), statement(k1, 60000, cited, uint256S("0x42"))), st), "OK"); BOOST_CHECK(!GetBond(st, bond1)->frozen); }
    // The evidence: k1 EJECTED and its bond frozen; k2 untouched.
    VaultState st(c.kv);
    BOOST_CHECK_EQUAL(*apply(eqvTx(att(k1, 9000, cited), statement(k1, 50000, cited, s)), st), "OK");
    BOOST_CHECK_EQUAL(GetMember(st, s, k1.GetPubKey())->status, MEMBER_EJECTED);
    BOOST_CHECK(GetBond(st, bond1)->frozen);
    BOOST_CHECK_EQUAL(GetMember(st, s, k2.GetPubKey())->status, MEMBER_ACTIVE);
    yellowback::ClearModuleParams();
}

BOOST_AUTO_TEST_CASE(module_liveness_hook)
{
    // Seats review B2, bounded at the re-review: a CLAIM_NOTICE (or MINT, REDEEM) whose bundle passes BUNDLE-1 at its
    // refHeight R in everything but the selection credits its signers -- seq s is the member whose joinOrdinal is
    // s + 1, one verification each -- with lastAct = citedHeight; any failing attestation credits nobody.
    Chain c;
    const CKey k1 = MakeKey(61), k2 = MakeKey(62), outsider = MakeKey(63);
    SetCreateBody sp = Params(true);
    sp.maturity = 2;
    const SetId s = SetWithMembers(c, {k1, k2}, sp);
    BOOST_CHECK_EQUAL(Member(c, s, k1).joinOrdinal, 1u);   // seq 0
    BOOST_CHECK_EQUAL(Member(c, s, k2).joinOrdinal, 2u);   // seq 1
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->joinCount, 2u);
    c.Empty(60);
    auto fakeHash = [](int64_t h) { uint256 x; x.begin()[0] = (unsigned char)(h & 0xff); x.begin()[1] = (unsigned char)((h >> 8) & 0xff); x.begin()[31] = 0xcd; return x; };
    BlockHashFn hashes = [&](int64_t h) -> std::optional<uint256> { if (h < 0 || h >= c.h) return std::nullopt; return fakeHash(h); };
    auto att = [&](const CKey& k, uint16_t seq, int64_t at, bool forge = false) {
        yellowback::Attestation a;
        a.seq = seq;
        a.priceMicroUsd = 50000;
        a.citedHeight = (uint32_t)at;
        std::vector<unsigned char> rec;
        BOOST_REQUIRE(k.SignCompact(yellowback::AttestMessage(a.seq, a.priceMicroUsd, a.citedHeight, fakeHash(at)), rec));
        std::copy(rec.begin() + 1, rec.end(), a.sig.begin());
        if (forge) a.sig[5] ^= 1;
        return a;
    };
    auto carrierTx = [&](const std::vector<yellowback::Attestation>& atts, const yellowback::Payload& payload) {
        yellowback::Bundle bundle;
        bundle.atts = atts;
        const valtype raw = yellowback::EncodeBundle(bundle);
        uint256 h;
        CSHA256().Write(raw.data(), raw.size()).Finalize(h.begin());
        const CScript redeem = yellowback::CarrierScript(MakeKey(64).GetPubKey(), h);
        CMutableTransaction m;
        m.vin.push_back(CTxIn(c.Fund(), yellowback::CarrierScriptSig(raw, valtype(71, 0x30), redeem)));
        m.vout.push_back(CTxOut(0, yellowback::PayloadScript(yellowback::EncodePayload(payload))));
        return m;
    };
    const int64_t R = c.h - 2;
    const yellowback::Payload notice = yellowback::Payload::ClaimNotice(COutPoint(uint256S("0x77"), 0), (uint32_t)R);
    auto lastAct = [&](VaultState& st, const CKey& k) { return GetMember(st, s, k.GetPubKey())->lastAct; };
    const int64_t before1 = Member(c, s, k1).lastAct, before2 = Member(c, s, k2).lastAct;
    BOOST_REQUIRE(before1 < R - 1 && before2 < R - 1);
    yellowback::Params p = yellowback::RegtestParams(10, 0, 0, s);
    p.attestorLivenessMin = 1;
    p.attestorSeats = (int)sp.seats;                  // adopt this small test set (seats, maturity, thresholds: 03/I-3)
    p.bondMaturity = (int)sp.maturity;
    p.attestorUnlockThreshold = (int)sp.unlockThreshold;
    p.attestorCancelThreshold = (int)sp.cancelThreshold;
    yellowback::SetModuleParams(p);
    BOOST_REQUIRE_EQUAL(p.mSelect, 2);
    auto tryTx = [&](const CMutableTransaction& m, int64_t& a1, int64_t& a2) {
        VaultState st(c.kv);
        st.SetBlockHashes(hashes);
        BOOST_CHECK_EQUAL(*Res(st.ApplyTx(CTransaction(m), c.h, c.coins)), "OK");
        a1 = lastAct(st, k1);
        a2 = lastAct(st, k2);
    };
    int64_t a1 = 0, a2 = 0;
    // a bundle that passes: both signers credited at their cited heights
    tryTx(carrierTx({att(k1, 0, R), att(k2, 1, R - 1)}, notice), a1, a2);
    BOOST_CHECK_EQUAL(a1, R);
    BOOST_CHECK_EQUAL(a2, R - 1);
    {   // focused review: the hook verifies through the node's cache (vault::SetModuleCache): a second pass is all hits
        struct CountingCache : public yellowback::SigCache {
            std::map<uint256, bool> m;
            mutable int hits = 0;
            int inserts = 0;
            std::optional<bool> Lookup(const uint256& k) const override { auto it = m.find(k); if (it == m.end()) return std::nullopt; hits++; return it->second; }
            void Insert(const uint256& k, bool v) override { m[k] = v; inserts++; }
        } cc;
        SetModuleCache(static_cast<yellowback::SigCache*>(&cc));
        const CMutableTransaction pass = carrierTx({att(k1, 0, R), att(k2, 1, R - 1)}, notice);
        tryTx(pass, a1, a2);
        BOOST_CHECK_EQUAL(cc.inserts, 2);
        BOOST_CHECK_EQUAL(cc.hits, 0);
        tryTx(pass, a1, a2);
        BOOST_CHECK_EQUAL(cc.inserts, 2);
        BOOST_CHECK_EQUAL(cc.hits, 2);
        BOOST_CHECK_EQUAL(a1, R);
        SetModuleCache(nullptr);
    }
    // focused review: a refHeight older than REF_WINDOW credits nobody (no replay of an old public attestation)
    {
        const int64_t old = c.h - p.refWindow - 1;
        BOOST_REQUIRE(old > before1 && old > before2);
        const yellowback::Payload oldNotice = yellowback::Payload::ClaimNotice(COutPoint(uint256S("0x77"), 0), (uint32_t)old);
        tryTx(carrierTx({att(k1, 0, old), att(k2, 1, old)}, oldNotice), a1, a2);
        BOOST_CHECK_EQUAL(a1, before1);
        BOOST_CHECK_EQUAL(a2, before2);
        const yellowback::Payload edge = yellowback::Payload::ClaimNotice(COutPoint(uint256S("0x77"), 0), (uint32_t)(old + 1));
        tryTx(carrierTx({att(k1, 0, old + 1), att(k2, 1, old + 1)}, edge), a1, a2);   // c.h - R = REF_WINDOW: credited
        BOOST_CHECK_EQUAL(a1, old + 1);
    }
    // bundles that fail credit nobody: one attestation (count < M_SELECT); a forged signature; a key signing under
    // another member's seq; an unknown seq; an outsider; a stale citation (<= R - ATTEST_MAX_AGE); a duplicate seq;
    // an EQUIVOCATION payload
    const std::vector<CMutableTransaction> failing = {
        carrierTx({att(k1, 0, R)}, notice),
        carrierTx({att(k1, 0, R), att(k2, 1, R, true)}, notice),
        carrierTx({att(k1, 1, R), att(k2, 0, R)}, notice),
        carrierTx({att(k1, 0, R), att(k2, 7, R)}, notice),
        carrierTx({att(k1, 0, R), att(outsider, 1, R)}, notice),
        carrierTx({att(k1, 0, R), att(k2, 1, R - p.attestMaxAge)}, notice),
        carrierTx({att(k1, 0, R), att(k1, 0, R - 1)}, notice),
        carrierTx({att(k1, 0, R), att(k2, 1, R)}, yellowback::Payload::Equivocation()),
    };
    for (const auto& m : failing) {
        tryTx(m, a1, a2);
        BOOST_CHECK_EQUAL(a1, before1);
        BOOST_CHECK_EQUAL(a2, before2);
    }
    // the module does not adopt a set below ATTESTOR_LIVENESS_MIN (review B3), nor one of another shape: no update
    for (int variant = 0; variant < 2; variant++) {
        yellowback::Params q = p;
        if (variant == 0) q.attestorLivenessMin = (int)sp.livenessWindow + 1;
        else q.bondMaturity = 8;
        yellowback::SetModuleParams(q);
        tryTx(carrierTx({att(k1, 0, R), att(k2, 1, R)}, notice), a1, a2);
        BOOST_CHECK_EQUAL(a1, before1);
    }
    yellowback::ClearModuleParams();
}

BOOST_AUTO_TEST_CASE(join_ordinal_reorg)
{
    // focused review: a disconnected SET_JOIN gives back its ordinal (joinCount restored byte for byte by the undo);
    // on one chain no two joins share an ordinal
    Chain c;
    const CKey k1 = MakeKey(81), k2 = MakeKey(82), k3 = MakeKey(83);
    SetId s = SetWithMembers(c, {k1, k2});
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->joinCount, 2u);
    const MemoryKV before = c.kv;
    BOOST_REQUIRE(!c.Block1(JoinTx(c, s, k3, {})));
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->joinCount, 3u);
    BOOST_CHECK_EQUAL(Member(c, s, k3).joinOrdinal, 3u);
    {
        MemoryKV back = c.kv;
        VaultState u(back);
        u.ApplyUndo(c.history.back().second);
        back.Apply(u.Changes());
        BOOST_CHECK(back.data == before.data);
        BOOST_CHECK_EQUAL(GetSet(back, s)->joinCount, 2u);
        BOOST_CHECK(!GetMember(back, s, k3.GetPubKey()));
    }
    // a member that leaves, withdraws and rejoins takes a new ordinal
    BOOST_REQUIRE(!c.Block1(RemoveTx(c, s, k1.GetPubKey(), false, {k1})));
    const COutPoint bond1 = Member(c, s, k1).bondOutpoint;
    c.Empty(5);
    BOOST_REQUIRE(!c.Block1(SpendTx(c, bond1, 1, {CTxOut(900, Recipient(7))}, false)));
    BOOST_REQUIRE(!c.Block1(JoinTx(c, s, k1, {})));
    BOOST_CHECK_EQUAL(Member(c, s, k1).joinOrdinal, 4u);
    BOOST_CHECK_EQUAL(GetSet(c.kv, s)->joinCount, 4u);
}

BOOST_AUTO_TEST_CASE(module_displace_hook)
{
    // Owner 2026-10-11: a SET_JOIN into a full set the YED module governs displaces the member the module names
    // (MEMBER_REMOVED, the bond neither frozen nor unindexed); an ungoverned set, or one the module does not adopt
    // (not OPEN with 15 seats), refuses the join as before.
    Chain c;
    SetCreateBody p = Params(true);
    p.seats = 15;
    p.unlockThreshold = p.cancelThreshold = p.slashThreshold = 1;
    p.maturity = 8;                                   // regtest BOND_MATURITY: the module adopts only that (the bond exit delay)
    std::vector<CKey> keys;
    for (int i = 0; i < 15; i++) keys.push_back(MakeKey((unsigned char)(70 + i)));   // one join per block: keys[14] is the youngest
    const SetId s = SetWithMembers(c, keys, p);
    SetCreateBody small = Params(true);
    small.seats = 1;
    small.unlockThreshold = small.cancelThreshold = small.slashThreshold = 1;
    const SetId s1 = SetWithMembers(c, {MakeKey(69)}, small);
    BOOST_CHECK_EQUAL(CountActive(GetMembers(c.kv, s)), 15);

    // Ungoverned (the module unconfigured): full is full, whatever the bond.
    yellowback::ClearModuleParams();
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s, MakeKey(90), {}, 100000)), "bad-vault-act-seats");
    // Governed, but a set the module does not adopt (one seat): refused as before.
    yellowback::SetModuleParams(yellowback::RegtestParams(10, 0, 0, s1));
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s1, MakeKey(90), {}, 100000)), "bad-vault-act-seats");
    // Governed and adopted: a bond not above x1.05 the least seat weight is refused; a larger one displaces it.
    yellowback::Params yp = yellowback::RegtestParams(10, 0, 0, s);
    yp.bondMinFloorZat = 1500;                        // these bonds are in zat: the dust guard (review B2) at 1,500
    yellowback::SetModuleParams(yp);
    BOOST_CHECK(yellowback::RegisteredModule()->GovernedSet() == std::optional<SetId>(s));
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s, MakeKey(90), {}, 1000)), "bad-vault-act-seats");
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s, MakeKey(90), {}, 1050)), "bad-vault-act-seats");   // 1050 x 1.0 vs 1000 x f(age) x 1.05
    // A member's own join while ACTIVE is still bad-vault-act-join (after the displacement check).
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s, keys[0], {}, 5000)), "bad-vault-act-join");
    const COutPoint youngBond = Member(c, s, keys[14]).bondOutpoint;
    const CMutableTransaction big = JoinTx(c, s, MakeKey(90), {}, 2000);
    const MemoryKV before = c.kv;
    BOOST_REQUIRE(!c.Block1(big));
    BOOST_CHECK_EQUAL(Member(c, s, keys[14]).status, MEMBER_REMOVED);
    BOOST_CHECK(!Member(c, s, keys[14]).bondFrozen);
    BOOST_REQUIRE(GetBond(c.kv, youngBond));
    BOOST_CHECK(!GetBond(c.kv, youngBond)->frozen);
    BOOST_CHECK_EQUAL(Member(c, s, MakeKey(90)).status, MEMBER_ACTIVE);
    BOOST_CHECK_EQUAL(CountActive(GetMembers(c.kv, s)), 15);
    for (int i = 0; i < 14; i++) BOOST_CHECK_EQUAL(Member(c, s, keys[i]).status, MEMBER_ACTIVE);
    // The block's undo restores the base byte for byte.
    {
        MemoryKV back = c.kv;
        VaultState u(back);
        u.ApplyUndo(c.history.back().second);
        back.Apply(u.Changes());
        BOOST_CHECK(back.data == before.data);
    }
    // The displaced bond is returned the set's maturity (8) after the displacement (the bond exit delay): locked at
    // exit + 7, spendable at exit + 8 (the primitive drops its index entry; the member stays REMOVED).
    {
        const int64_t exit = c.h - 1;
        BOOST_CHECK_EQUAL(GetBond(c.kv, youngBond)->exitHeight, exit);
        CMutableTransaction spend;
        spend.vin.push_back(CTxIn(youngBond));
        spend.vout.push_back(CTxOut(500, Recipient(91)));
        VaultState early(c.kv);
        BOOST_CHECK_EQUAL(*Res(early.ApplyTx(CTransaction(spend), exit + 7, c.coins)), "bad-vault-bond-locked");
        VaultState st(c.kv);
        BOOST_CHECK_EQUAL(*Res(st.ApplyTx(CTransaction(spend), exit + 8, c.coins)), "OK");
        BOOST_CHECK(!GetBond(st, youngBond));
        BOOST_CHECK_EQUAL(GetMember(st, s, keys[14].GetPubKey())->status, MEMBER_REMOVED);
    }
    // A member that is not live goes first, whatever its weight: all but keys[0] (the oldest, the heaviest) heartbeat.
    c.Empty((int)p.livenessWindow + 1);
    std::vector<CMutableTransaction> beats;
    for (int i = 1; i < 14; i++) beats.push_back(HeartbeatTx(c, s, keys[i]));
    beats.push_back(HeartbeatTx(c, s, MakeKey(90)));
    BOOST_REQUIRE(!c.Block(beats));
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s, MakeKey(91), {}, 1499)), "bad-vault-act-seats");   // dust: below the floor (review B2)
    BOOST_REQUIRE(!c.Block1(JoinTx(c, s, MakeKey(91), {}, 1500)));
    BOOST_CHECK_EQUAL(Member(c, s, keys[0]).status, MEMBER_REMOVED);
    BOOST_CHECK_EQUAL(Member(c, s, MakeKey(91)).status, MEMBER_ACTIVE);
    // The module's CheckBlock: a block with a SET_REMOVE or SET_WINDDOWN of the attestor set is invalid; of another set, not.
    BOOST_CHECK_EQUAL(*c.Block({RemoveTx(c, s, keys[1].GetPubKey(), false, {keys[2]})}), "bad-yellowback-attestor-set-act");
    BOOST_CHECK_EQUAL(*c.Block({WindDownTx(c, s, {keys[2]})}), "bad-yellowback-attestor-set-act");
    BOOST_CHECK_EQUAL(*c.Try(RemoveTx(c, s, keys[1].GetPubKey(), false, {keys[2]})), "OK");   // per transaction the primitive admits it
    BOOST_CHECK_EQUAL(*c.Block({WindDownTx(c, s1, {MakeKey(69)})}), "OK");
    yellowback::ClearModuleParams();
    // Unconfigured again: no displacement.
    BOOST_CHECK_EQUAL(*c.Try(JoinTx(c, s, MakeKey(92), {}, 100000)), "bad-vault-act-seats");
}

BOOST_AUTO_TEST_SUITE_END()
