// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The hybrid payment channel TX_PQCHANNEL (docs/plans/yellowback-quantum-spec.md header, D-Q-19):
// the exact Solver match and its near misses, both spend paths with real keys (an SLH-DSA client and
// a secp256k1 server), the standardness rules (push counts, the scheme-2 client before Falcon, dust),
// and the YED holder reading (HolderKey: the client; TOK-PQ: a scheme-2 client from the Falcon height).

#include "chainparams.h"
#include "coins.h"
#include "consensus/upgrades.h"
#include "crypto/pq/scheme.h"
#include "crypto/pq/sign.h"
#include "key.h"
#include "main.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "random.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/standard.h"
#include "test/test_bitcoin.h"
#include "util/strencodings.h"
#include "yellowback/params.h"
#include "yellowback/script.h"

#include <boost/test/unit_test.hpp>

typedef std::vector<unsigned char> valtype;

namespace {

const uint32_t VAULT_BRANCH_ID = 0x6d5b7a31;
const unsigned int FLAGS = STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_VAULT;
const uint8_t SLH = pq::SCHEME_SLH_DSA_SHA2_128S;
const uint8_t FALCON = pq::SCHEME_FN_DSA_512;

struct PQKey {
    uint8_t scheme;
    valtype pk, sk;
    CPQKeyID Id() const { return CPQKeyID(scheme, pq::KeyHash(scheme, pk)); }
};

PQKey MakeKey(uint8_t scheme, unsigned char seedByte)
{
    PQKey k{scheme, {}, {}};
    BOOST_REQUIRE(pq::KeyGen(scheme, valtype(pq::SeedSize(scheme), seedByte), k.pk, k.sk));
    return k;
}

CPubKey ServerKey(CKey& key)
{
    key = CKey::TestOnlyRandomKey(true);
    return key.GetPubKey();
}

std::vector<valtype> Chunks(const valtype& data)
{
    std::vector<valtype> out;
    for (size_t i = 0; i < data.size(); i += pq::MAX_CHUNK)
        out.emplace_back(data.begin() + i, data.begin() + std::min(data.size(), i + pq::MAX_CHUNK));
    return out;
}

/** <sig_1>..<sig_s> <s> <pk_1>..<pk_p> <p> */
CScript PQPushes(const valtype& sigWithHashtype, const valtype& pk)
{
    CScript s;
    const std::vector<valtype> sc = Chunks(sigWithHashtype), pc = Chunks(pk);
    for (const valtype& c : sc) s << c;
    s << (int64_t)sc.size();
    for (const valtype& c : pc) s << c;
    s << (int64_t)pc.size();
    return s;
}

CMutableTransaction SpendTx(uint32_t lockTime, uint32_t sequence)
{
    CMutableTransaction mtx;
    mtx.fOverwintered = true;
    mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    mtx.nVersion = SAPLING_TX_VERSION;
    mtx.nLockTime = lockTime;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(uint256S("0c"), 0);
    mtx.vin[0].nSequence = sequence;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 90000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return mtx;
}

/** 6.20.0: SignatureHash takes precomputed data (every prevout as the spent one; v4 reads none of them). */
uint256 SigHash6(const CScript& spk, const CMutableTransaction& mtx, CAmount amount)
{
    const CTransaction tx(mtx);
    return SignatureHash(spk, tx, 0, SIGHASH_ALL, amount, VAULT_BRANCH_ID, PrecomputedTransactionData(tx, std::vector<CTxOut>(tx.vin.size(), CTxOut(amount, spk))));
}

ScriptError Verify(const CScript& scriptSig, const CScript& spk, const CMutableTransaction& mtx, CAmount amount, unsigned int flags = FLAGS)
{
    const CTransaction tx(mtx);
    // 6.20.0: the checker takes precomputed data (every prevout as the spent one)
    const PrecomputedTransactionData txdata(tx, std::vector<CTxOut>(tx.vin.size(), CTxOut(amount, spk)));
    TransactionSignatureChecker checker(&tx, txdata, 0, amount);
    ScriptError err;
    VerifyScript(scriptSig, spk, flags, checker, VAULT_BRANCH_ID, &err);
    return err;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_channel_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pqchannel_solver_exact_match)
{
    CKey server;
    const CPubKey serverPk = ServerKey(server);
    const CPQKeyID client(SLH, GetRandHash()), falcon(FALCON, GetRandHash());
    for (int64_t refund : {1LL, 16LL, 17LL, 127LL, 128LL, 32767LL, 400000LL, 499999999LL}) {
        for (const CPQKeyID& c : {client, falcon}) {
            const CScript s = GetScriptForPQChannel(c, serverPk, refund);
            BOOST_REQUIRE(!s.empty());
            BOOST_CHECK(s.size() >= 112 && s.size() <= 117);
            txnouttype type;
            std::vector<valtype> sol;
            BOOST_REQUIRE(Solver(s, type, sol));
            BOOST_CHECK_EQUAL(type, TX_PQCHANNEL);
            BOOST_CHECK_EQUAL(std::string(GetTxnOutputType(type)), "pqchannel");
            BOOST_REQUIRE_EQUAL(sol.size(), 3U);
            valtype want(1, c.scheme);
            want.insert(want.end(), c.hash.begin(), c.hash.end());
            BOOST_CHECK(sol[0] == want);
            BOOST_CHECK(sol[1] == valtype(serverPk.begin(), serverPk.end()));
            BOOST_CHECK_EQUAL(CScriptNum(sol[2], true, 5).getint(), refund);
            PQChannelParams cp;
            BOOST_REQUIRE(MatchPQChannel(s, cp));
            BOOST_CHECK(cp.client == c && cp.server == serverPk && cp.refundHeight == refund);
            BOOST_CHECK(IsStandard(s, type));
            BOOST_CHECK_EQUAL(ScriptSigArgsExpected(TX_PQCHANNEL, sol), -1);
            CTxDestination d;
            BOOST_CHECK(!ExtractDestination(s, d));                                  // no single address
            BOOST_CHECK(yellowback::HolderKey(s) == std::optional<CTxDestination>(CTxDestination(c)));
        }
    }
    // the frozen byte layout: 63 20<h> 51 c2 69 21<pk> ac 67 <num> b1 75 20<h> 51 c2 68
    const CScript s = GetScriptForPQChannel(client, serverPk, 400000);
    const std::string h = HexStr(client.hash.begin(), client.hash.end());
    BOOST_CHECK_EQUAL(HexStr(s.begin(), s.end()), "6320" + h + "51c26921" + HexStr(serverPk.begin(), serverPk.end()) +
                                                   "ac67" "03801a06" "b17520" + h + "51c268");
    // out-of-range fields do not build
    BOOST_CHECK(GetScriptForPQChannel(CPQKeyID(3, client.hash), serverPk, 100).empty());
    BOOST_CHECK(GetScriptForPQChannel(client, serverPk, 0).empty());
    BOOST_CHECK(GetScriptForPQChannel(client, serverPk, -1).empty());
    BOOST_CHECK(GetScriptForPQChannel(client, serverPk, LOCKTIME_THRESHOLD).empty());
    CKey unc = CKey::TestOnlyRandomKey(false);
    BOOST_CHECK(GetScriptForPQChannel(client, unc.GetPubKey(), 100).empty());
}

BOOST_AUTO_TEST_CASE(pqchannel_solver_near_misses)
{
    CKey server;
    const CPubKey serverPk = ServerKey(server);
    const CPQKeyID client(SLH, GetRandHash()), other(SLH, GetRandHash());
    const valtype h = ToByteVector(client.hash), h2 = ToByteVector(other.hash), pk = ToByteVector(serverPk);
    auto shape = [&](const valtype& ha, opcodetype sa, const valtype& key, const CScript& num, const valtype& hb, opcodetype sb) {
        CScript s = CScript() << OP_IF << ha << sa << OP_CHECKPQSIG << OP_VERIFY << key << OP_CHECKSIG << OP_ELSE;
        s.insert(s.end(), num.begin(), num.end());
        return s << OP_CHECKLOCKTIMEVERIFY << OP_DROP << hb << sb << OP_CHECKPQSIG << OP_ENDIF;
    };
    const CScript good = shape(h, OP_1, pk, CScript() << 400000, h, OP_1);
    BOOST_REQUIRE(good == GetScriptForPQChannel(client, serverPk, 400000));
    valtype badPoint = pk;
    badPoint[0] = 0x02;
    for (size_t i = 1; i < badPoint.size(); i++) badPoint[i] = 0xFF;      // x >= p: not a curve point
    valtype uncompressed = ToByteVector(CPubKey());
    std::vector<std::pair<std::string, CScript>> misses = {
        { "other client in the refund slot", shape(h, OP_1, pk, CScript() << 400000, h2, OP_1) },
        { "other scheme in the refund slot", shape(h, OP_1, pk, CScript() << 400000, h, OP_2) },
        { "unregistered scheme", shape(h, OP_3, pk, CScript() << 400000, h, OP_3) },
        { "scheme pushed as data", [&] { CScript s = CScript() << OP_IF << h << valtype(1, 0x01) << OP_CHECKPQSIG << OP_VERIFY << pk << OP_CHECKSIG << OP_ELSE << 400000 << OP_CHECKLOCKTIMEVERIFY << OP_DROP << h << valtype(1, 0x01) << OP_CHECKPQSIG << OP_ENDIF; return s; }() },
        { "server key not on the curve", shape(h, OP_1, badPoint, CScript() << 400000, h, OP_1) },
        { "refund zero", shape(h, OP_1, pk, CScript() << OP_0, h, OP_1) },
        { "refund negative", shape(h, OP_1, pk, CScript() << -5, h, OP_1) },
        { "refund non-minimal", shape(h, OP_1, pk, CScript() << valtype{0x80, 0x1a, 0x06, 0x00}, h, OP_1) },
        { "refund as a timestamp", shape(h, OP_1, pk, CScript() << (int64_t)LOCKTIME_THRESHOLD, h, OP_1) },
        { "refund 6 bytes", shape(h, OP_1, pk, CScript() << valtype{1, 2, 3, 4, 5, 6}, h, OP_1) },
        { "OP_NOTIF", [&] { CScript s = good; s[0] = OP_NOTIF; return s; }() },
        { "OP_CHECKSIGVERIFY", [&] { CScript s = good; s[72 - 1 + 0] = OP_CHECKSIGVERIFY; return s; }() },
        { "trailing byte", CScript(good) << OP_NOP },
        { "truncated", CScript(good.begin(), good.end() - 1) },
        { "no OP_VERIFY", [&] { CScript s = CScript() << OP_IF << h << OP_1 << OP_CHECKPQSIG << pk << OP_CHECKSIG << OP_ELSE << 400000 << OP_CHECKLOCKTIMEVERIFY << OP_DROP << h << OP_1 << OP_CHECKPQSIG << OP_ENDIF; return s; }() },
    };
    for (const auto& m : misses) {
        txnouttype type;
        std::vector<valtype> sol;
        Solver(m.second, type, sol);
        BOOST_CHECK_MESSAGE(type != TX_PQCHANNEL, m.first);
        PQChannelParams cp;
        BOOST_CHECK_MESSAGE(!MatchPQChannel(m.second, cp), m.first);
        BOOST_CHECK_MESSAGE(!yellowback::HolderKey(m.second).has_value(), m.first);
    }
}

BOOST_AUTO_TEST_CASE(pqchannel_spend_paths_real_keys)
{
    // Cooperative: <serverSig> <client PQ pushes> OP_1; refund after the CLTV: <client PQ pushes> OP_0.
    const PQKey client = MakeKey(SLH, 0x5c);
    CKey server;
    const CPubKey serverPk = ServerKey(server);
    const int64_t refund = 400;
    const CScript spk = GetScriptForPQChannel(client.Id(), serverPk, refund);
    BOOST_REQUIRE(!spk.empty());
    const CAmount amount = 100000;
    auto pqSig = [&](const CMutableTransaction& mtx) {
        const uint256 sighash = SigHash6(spk, mtx, amount);
        valtype sig;
        BOOST_REQUIRE(pq::Sign(SLH, client.sk, sighash, sig));
        sig.push_back(SIGHASH_ALL);
        return sig;
    };
    auto ecSig = [&](const CMutableTransaction& mtx) {
        const uint256 sighash = SigHash6(spk, mtx, amount);
        valtype sig;
        BOOST_REQUIRE(server.Sign(sighash, sig));
        sig.push_back(SIGHASH_ALL);
        return sig;
    };

    // cooperative: any lock time
    {
        CMutableTransaction mtx = SpendTx(0, 0xFFFFFFFF);
        const valtype ps = pqSig(mtx), es = ecSig(mtx);
        CScript ss = CScript() << es;
        const CScript pushes = PQPushes(ps, client.pk);
        ss.insert(ss.end(), pushes.begin(), pushes.end());
        ss << OP_1;
        BOOST_CHECK_EQUAL(Verify(ss, spk, mtx, amount), SCRIPT_ERR_OK);
        BOOST_CHECK(ss.size() > 8000 && ss.size() < MAX_STANDARD_PQ_SCRIPTSIG);
        // without the vault flags OP_CHECKPQSIG is BAD_OPCODE
        BOOST_CHECK_EQUAL(Verify(ss, spk, mtx, amount, STANDARD_SCRIPT_VERIFY_FLAGS), SCRIPT_ERR_BAD_OPCODE);
        // server-only (the client's signature wrong): the PQ check fails at OP_VERIFY
        valtype bad = ps;
        bad[3] ^= 1;
        CScript ss2 = CScript() << es;
        const CScript badPushes = PQPushes(bad, client.pk);
        ss2.insert(ss2.end(), badPushes.begin(), badPushes.end());
        ss2 << OP_1;
        BOOST_CHECK_EQUAL(Verify(ss2, spk, mtx, amount), SCRIPT_ERR_VERIFY);
        // client-only (the server's signature empty): OP_CHECKSIG leaves false
        CScript ss3 = CScript() << valtype();
        ss3.insert(ss3.end(), pushes.begin(), pushes.end());
        ss3 << OP_1;
        BOOST_CHECK_EQUAL(Verify(ss3, spk, mtx, amount), SCRIPT_ERR_EVAL_FALSE);
        // a server alone cannot take the refund branch either (no PQ pushes)
        BOOST_CHECK(Verify(CScript() << es << OP_0, spk, mtx, amount) != SCRIPT_ERR_OK);
    }
    // refund after the CLTV
    {
        CMutableTransaction mtx = SpendTx((uint32_t)refund, 0xFFFFFFFE);
        CScript ss = PQPushes(pqSig(mtx), client.pk);
        ss << OP_0;
        BOOST_CHECK_EQUAL(Verify(ss, spk, mtx, amount), SCRIPT_ERR_OK);
        BOOST_CHECK(ss.size() > 7900 && ss.size() < MAX_STANDARD_PQ_SCRIPTSIG);
    }
    // refund before the CLTV fails
    {
        CMutableTransaction mtx = SpendTx((uint32_t)refund - 1, 0xFFFFFFFE);
        CScript ss = PQPushes(pqSig(mtx), client.pk);
        ss << OP_0;
        BOOST_CHECK_EQUAL(Verify(ss, spk, mtx, amount), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        // and a final nSequence disables the lock time
        CMutableTransaction fin = SpendTx((uint32_t)refund, 0xFFFFFFFF);
        CScript ssf = PQPushes(pqSig(fin), client.pk);
        ssf << OP_0;
        BOOST_CHECK_EQUAL(Verify(ssf, spk, fin, amount), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    }
}

BOOST_AUTO_TEST_CASE(pqchannel_policy_and_tokpq)
{
    SelectParams(CBaseChainParams::REGTEST);
    CKey server;
    const CPubKey serverPk = ServerKey(server);
    const CPQKeyID slh(SLH, GetRandHash()), falcon(FALCON, GetRandHash());
    const CScript slhCh = GetScriptForPQChannel(slh, serverPk, 500), falconCh = GetScriptForPQChannel(falcon, serverPk, 500);

    // dust: the cooperative spend's size (the client's PQ spend, the server's signature push, the selector)
    const CTxOut out(10000, slhCh);
    BOOST_CHECK(GetPQDustThreshold(out, CFeeRate(ONE_THIRD_DUST_THRESHOLD_RATE)) > out.GetDustThreshold());   // 6.20.0: fixed dust rate
    BOOST_CHECK(GetPQDustThreshold(out, CFeeRate(ONE_THIRD_DUST_THRESHOLD_RATE)) < 10000);                  // TOKEN_VALUE clears it
    BOOST_CHECK(PQScriptScheme(falconCh, TX_PQCHANNEL) == std::optional<uint8_t>(FALCON));

    // TOK-PQ (D-Q-19): from the Falcon height a channel with a Falcon client holds YED, an SLH client does not
    yellowback::Params p = yellowback::RegtestParams(1, 0, 0, uint256S("5e75"));
    p.pqFalconHeight = 200;
    for (const CScript& s : { slhCh, falconCh }) BOOST_CHECK(yellowback::HolderAllowed(p, 199, s));
    BOOST_CHECK(yellowback::HolderAllowed(p, 200, falconCh));
    BOOST_CHECK(!yellowback::HolderAllowed(p, 200, slhCh));
    BOOST_CHECK(yellowback::HolderKey(falconCh) == std::optional<CTxDestination>(CTxDestination(falcon)));

    // AreInputsStandard: exact push counts (cooperative s + p + 4, refund s + p + 3) and the PQ scriptSig allowance
    CCoinsViewDummy base;
    CCoinsViewCache view(&base);
    CMutableTransaction fund;
    fund.vout.push_back(CTxOut(100000, slhCh));
    const uint256 fundHash = CTransaction(fund).GetHash();
    view.ModifyCoins(fundHash)->FromTx(CTransaction(fund), 0);
    const size_t s = (pq::SigSize(SLH) + 1 + pq::MAX_CHUNK - 1) / pq::MAX_CHUNK;   // 16
    auto spend = [&](const CScript& ss) {
        CMutableTransaction mtx = SpendTx(0, 0xFFFFFFFF);
        mtx.vin[0].prevout = COutPoint(fundHash, 0);
        mtx.vin[0].scriptSig = ss;
        return CTransaction(mtx);
    };
    auto pushes = [&](size_t n, bool coop) {
        CScript ss;
        if (coop) ss << valtype(72, 0x30);
        for (size_t i = 0; i + 1 < s; i++) ss << valtype(520, 0xAA);
        ss << valtype(57, 0xAA) << (int64_t)s << valtype(32, 0xBB) << OP_1;
        for (size_t i = 0; i < n; i++) ss << valtype(1, 0xCC);
        ss << (coop ? OP_1 : OP_0);
        return ss;
    };
    BOOST_CHECK(AreInputsStandard(spend(pushes(0, true)), view, VAULT_BRANCH_ID));
    BOOST_CHECK(AreInputsStandard(spend(pushes(0, false)), view, VAULT_BRANCH_ID));
    BOOST_CHECK(!AreInputsStandard(spend(pushes(1, true)), view, VAULT_BRANCH_ID));
    BOOST_CHECK(!AreInputsStandard(spend(pushes(1, false)), view, VAULT_BRANCH_ID));
    CScript wrongSel = pushes(0, false);
    wrongSel.back() = OP_2;
    BOOST_CHECK(!AreInputsStandard(spend(wrongSel), view, VAULT_BRANCH_ID));
    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_SUITE_END()
