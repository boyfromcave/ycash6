// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The version-3 payload codec (v3 plan §3.3, W14, V23): round trips, fixed-width
// little-endian layout, every malformed case, feeVout / attestFeeVout semantics,
// the four attestation types and the transaction-level shape rules FindPayload
// applies.

#include "yellowback/payload.h"

#include "key.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "test/test_bitcoin.h"
#include "util/strencodings.h"

#include <boost/test/unit_test.hpp>

using namespace yellowback;

namespace {

CPubKey TestKey()
{
    CKey key;
    key = CKey::TestOnlyRandomKey(true);
    return key.GetPubKey();
}

std::vector<unsigned char> Hex(const std::string& s) { return ParseHex(s); }

CMutableTransaction TxWithOutputs(size_t n, const CScript& opret, size_t opretIndex)
{
    CMutableTransaction mtx;
    for (size_t i = 0; i < n; i++) {
        mtx.vout.push_back(CTxOut(10000, CScript() << OP_TRUE));
    }
    mtx.vout[opretIndex].scriptPubKey = opret;
    mtx.vout[opretIndex].nValue = 0;
    return mtx;
}

/** A fixed syntactically valid compressed key, so hex vectors are reproducible. */
const std::string KEYHEX = "02cb81cc0269783ebd9e6484b5495343036874a407856f230a8ee0384986759e70";
/** A second one for the bond key of ATTESTOR_REGISTER. */
const std::string KEY2HEX = "03a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

std::array<unsigned char, COMPACT_SIG_SIZE> TestSig(unsigned char seed)
{
    std::array<unsigned char, COMPACT_SIG_SIZE> sig;
    for (size_t i = 0; i < sig.size(); i++) sig[i] = (unsigned char)(seed + i);
    return sig;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(yellowback_payload_tests, BasicTestingSetup)

// Rule: MINT-1
// Rule: XFER-1
// Rule: RED-1
BOOST_AUTO_TEST_CASE(mint1_roundtrip_table)
{
    CPubKey owner = TestKey();
    CPubKey bond = TestKey();
    std::vector<Assignment> thirteen, fifteen;
    for (uint8_t i = 0; i < 15; i++) {
        if (i < 13) thirteen.push_back(Assignment(i, 100 + i));
        fifteen.push_back(Assignment(i, 100 + i));
    }
    const uint256 vault = uint256S("0x1122334455667788990011223344556677889900112233445566778899001122");
    const std::vector<std::pair<Payload, size_t>> cases = {
        { Payload::Mint(0, 10000, 1000, 950, owner, 3), 52 },                     // attestFeeVout defaults to none (AFEE-0)
        { Payload::Mint(0, 10000, 1000, 950, owner, 3, 4), 52 },
        { Payload::Mint(2, 1000000, 0xFFFFFFFF, 0, owner, FEE_VOUT_NONE, FEE_VOUT_NONE), 52 },
        { Payload::Mint(0xFF, 0, 0, 0xFFFFFFFF, owner, 0, 0), 52 },               // the codec fixes the shape, MINT-2 the ranges
        { Payload::Transfer({}), 5 },
        { Payload::Transfer({ Assignment(1, 100) }), 10 },
        { Payload::Transfer({ Assignment(0, 100), Assignment(1, 200), Assignment(3, 0xFFFFFFFF) }), 20 },
        { Payload::Transfer(fifteen), 80 },                                       // the maximum, 80 bytes exactly
        { Payload::Redeem(950, 2, {}), 11 },                                      // count = 0 allowed (§3.5)
        { Payload::Redeem(950, 2, {}, 3), 11 },
        { Payload::Redeem(950, FEE_VOUT_NONE, { Assignment(2, 12345) }, 5), 16 },
        { Payload::Redeem(0xFFFFFFFF, 0, thirteen, 1), 76 },                      // the maximum count (13)
        { Payload::AttestorRegister(owner, bond, 420480, 0), 75 },
        { Payload::AttestorRegister(bond, owner, 0xFFFFFFFF, 0xFF), 75 },
        { Payload::ClaimNotice(vault, 1, 950), 41 },
        { Payload::ClaimNotice(COutPoint(vault, 2), 0xFFFFFFFF), 41 },
        { Payload::ClaimNotice(uint256(), 0, 0), 41 },
        { Payload::Equivocation(), 4 },
        { Payload::AttestorRevive(0, 0, 0, TestSig(0)), 78 },
        { Payload::AttestorRevive(0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, TestSig(0x80)), 78 },
    };
    for (const auto& c : cases) {
        std::vector<unsigned char> enc = EncodePayload(c.first);
        BOOST_CHECK_EQUAL(enc.size(), c.second);
        BOOST_REQUIRE(!enc.empty());
        BOOST_CHECK_EQUAL(enc[0], 0x59);
        BOOST_CHECK_EQUAL(enc[1], 0x42);
        BOOST_CHECK_EQUAL(enc[2], PAYLOAD_VERSION);
        BOOST_CHECK_EQUAL(enc[2], 0x03);
        BOOST_CHECK_EQUAL(enc[2], PayloadVersion());
        BOOST_CHECK_EQUAL(enc[3], (unsigned char)c.first.type);
        Payload dec;
        BOOST_REQUIRE(DecodePayload(enc, dec));
        BOOST_CHECK(dec == c.first);
        BOOST_CHECK_EQUAL(dec.version, PAYLOAD_VERSION);
        BOOST_CHECK_EQUAL(dec.AssignedCents(), c.first.AssignedCents());
        BOOST_CHECK(EncodePayload(dec) == enc);
    }
    // Sums fit int64: 15 x 2^32.
    std::vector<Assignment> big;
    for (uint8_t i = 0; i < 15; i++) big.push_back(Assignment(i, 0xFFFFFFFF));
    BOOST_CHECK_EQUAL(Payload::Transfer(big).AssignedCents(), 15LL * 0xFFFFFFFFLL);
    // The CLAIM_NOTICE outpoint accessor and the COutPoint factory agree.
    Payload n = Payload::ClaimNotice(COutPoint(vault, 2), 7);
    BOOST_CHECK(n.VaultOutPoint() == COutPoint(vault, 2));
    BOOST_CHECK(n == Payload::ClaimNotice(vault, 2, 7));
}

// Rule: MINT-1
// Rule: RED-1
BOOST_AUTO_TEST_CASE(mint1_fixed_width_little_endian_layout)
{
    CPubKey owner(Hex(KEYHEX));
    CPubKey bond(Hex(KEY2HEX));
    std::vector<unsigned char> enc = EncodePayload(Payload::Mint(2, 0x01020304, 0x0A0B0C0D, 0x11223344, owner, 0x03, 0x04));
    BOOST_REQUIRE_EQUAL(enc.size(), 52u);
    BOOST_CHECK_EQUAL(HexStr(enc), "59420301" "02" "04030201" "0d0c0b0a" "44332211" + KEYHEX + "03" "04");
    enc = EncodePayload(Payload::Mint(2, 0x01020304, 0x0A0B0C0D, 0x11223344, owner, 0x03));
    BOOST_CHECK_EQUAL(HexStr(enc), "59420301" "02" "04030201" "0d0c0b0a" "44332211" + KEYHEX + "03" "ff");
    enc = EncodePayload(Payload::Transfer({ Assignment(3, 0x0100) }));
    BOOST_CHECK_EQUAL(HexStr(enc), "59420302" "01" "03" "00010000");
    enc = EncodePayload(Payload::Redeem(0x11223344, 0xFF, { Assignment(2, 0x0100) }, 0x05));
    BOOST_CHECK_EQUAL(HexStr(enc), "59420303" "44332211" "ff" "05" "01" "02" "00010000");
    enc = EncodePayload(Payload::Redeem(7, 1, {}));
    BOOST_CHECK_EQUAL(HexStr(enc), "59420303" "07000000" "01" "ff" "00");
    enc = EncodePayload(Payload::AttestorRegister(owner, bond, 0x00066a80, 0x01));
    BOOST_REQUIRE_EQUAL(enc.size(), 75u);
    BOOST_CHECK_EQUAL(HexStr(enc), "59420305" + KEYHEX + KEY2HEX + "806a0600" "01");
    // The txid is the uint256's internal byte order (begin()..end()), not the displayed reversed hex (R13).
    const uint256 vault = uint256S("0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    enc = EncodePayload(Payload::ClaimNotice(vault, 0x02, 0x11223344));
    BOOST_REQUIRE_EQUAL(enc.size(), 41u);
    BOOST_CHECK_EQUAL(HexStr(enc), "59420306" "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100" "02" "44332211");
    BOOST_CHECK_EQUAL(HexStr(enc), "59420306" + HexStr(vault.begin(), vault.end()) + "02" "44332211");
    enc = EncodePayload(Payload::Equivocation());
    BOOST_CHECK_EQUAL(HexStr(enc), "59420307");
    const std::array<unsigned char, COMPACT_SIG_SIZE> sig = TestSig(0);
    enc = EncodePayload(Payload::AttestorRevive(0x0102, 0x0000c350, 0x000003b6, sig));
    BOOST_REQUIRE_EQUAL(enc.size(), 78u);
    BOOST_CHECK_EQUAL(HexStr(enc), "59420308" "0201" "50c30000" "b6030000" + HexStr(sig.begin(), sig.end()));
}

// Rule: MINT-1
// Rule: XFER-1
// Rule: RED-1
BOOST_AUTO_TEST_CASE(mint1_malformed_table)
{
    const std::string mintBody = "00" "10270000" "e8030000" "b6030000" + KEYHEX + "ff" "ff";   // 48 bytes
    const std::string sigHex(128, '1');
    const std::string txidHex(64, 'a');
    struct Case { const char* name; std::string hex; bool ok; };
    const std::vector<Case> cases = {
        { "mint_ok",             "59420301" + mintBody, true },
        { "bad_magic_0",         "58420301" + mintBody, false },
        { "bad_magic_1",         "59430301" + mintBody, false },
        { "version_0",           "59420001" + mintBody, false },
        { "version_1",           "59420101" + mintBody, false },
        { "version_2",           "59420201" + mintBody, false },                              // V23: the v2 header, even over a v3 body
        { "version_2_v2_body",   "59420201" + mintBody.substr(0, mintBody.size() - 2), false }, // a real v2 MINT (51 bytes)
        { "version_4",           "59420401" + mintBody, false },
        { "version_ff",          "5942ff01" + mintBody, false },
        { "unknown_type_04",     "59420304" "01000000", false },
        { "unknown_type_09",     "59420309" "00", false },
        { "retired_type_10",     "59420310" "50c3000000000000", false },   // the prototype's PRICE, reserved
        { "reserved_type_1f",    "5942031f" "00", false },
        { "reserved_type_20",    "59420320" "00", false },
        { "reserved_type_ff",    "594203ff" "00", false },
        { "type_00",             "59420300" "00", false },
        { "empty",               "", false },
        { "one_byte",            "59", false },
        { "header_only",         "594203", false },
        { "header_no_body",      "59420301", false },
        { "mint_short_by_one",   "59420301" + mintBody.substr(0, mintBody.size() - 2), false },   // the v2 length (no attestFeeVout)
        { "mint_no_feevout",     "59420301" "00" "10270000" "e8030000" "b6030000" + KEYHEX, false },   // the v1 length
        { "mint_trailing",       "59420301" + mintBody + "00", false },
        // Any 33 bytes decode as the owner key (the codec fixes the shape; MINT-3 gives bad-mint-owner-key
        // and a VOID vault records the bytes verbatim, SERIALISATION.md §3 C).
        { "mint_key_prefix_04",  "59420301" "00" "10270000" "e8030000" "b6030000" "04" + KEYHEX.substr(2) + "ff" "ff", true },
        { "mint_key_prefix_01",  "59420301" "00" "10270000" "e8030000" "b6030000" "01" + KEYHEX.substr(2) + "ff" "ff", true },
        { "mint_key_prefix_03",  "59420301" "00" "10270000" "e8030000" "b6030000" "03" + KEYHEX.substr(2) + "ff" "ff", true },
        { "transfer_empty",      "59420302" "00", true },
        { "transfer_short",      "59420302" "01" "01640000", false },
        { "transfer_long",       "59420302" "01" "0164000000" "00", false },
        { "transfer_count_short","59420302" "02" "0164000000", false },
        { "transfer_zero_cents", "59420302" "01" "0100000000", false },
        { "transfer_dup_vout",   "59420302" "02" "0164000000" "0164000000", false },
        { "transfer_two",        "59420302" "02" "0164000000" "0264000000", true },
        { "transfer_trailing",   "59420302" "00" "00", false },
        { "redeem_empty",        "59420303" "b6030000" "ff" "ff" "00", true },
        { "redeem_one",          "59420303" "b6030000" "03" "04" "01" "0139300000", true },
        { "redeem_v2_head",      "59420303" "b6030000" "ff" "00", false },                        // no attestFeeVout: the v2 head
        { "redeem_head_short",   "59420303" "b6030000" "ff" "ff", false },
        { "redeem_short",        "59420303" "b6030000" "ff" "ff" "01" "01393000", false },
        { "redeem_trailing",     "59420303" "b6030000" "ff" "ff" "00" "00", false },
        { "redeem_zero_cents",   "59420303" "b6030000" "ff" "ff" "01" "0100000000", false },
        { "redeem_dup_vout",     "59420303" "b6030000" "ff" "ff" "02" "0164000000" "0164000000", false },
        // ATTESTOR_REGISTER (75): any 33 + 33 bytes decode (REG-A1 judges the keys).
        { "register_ok",         "59420305" + KEYHEX + KEY2HEX + "806a0600" "00", true },
        { "register_key_04",     "59420305" "04" + KEYHEX.substr(2) + KEY2HEX + "806a0600" "00", true },
        { "register_short",      "59420305" + KEYHEX + KEY2HEX + "806a0600", false },
        { "register_trailing",   "59420305" + KEYHEX + KEY2HEX + "806a0600" "00" "00", false },
        { "register_empty",      "59420305", false },
        // CLAIM_NOTICE (41).
        { "notice_ok",           "59420306" + txidHex + "01" "b6030000", true },
        { "notice_short",        "59420306" + txidHex + "01" "b60300", false },
        { "notice_trailing",     "59420306" + txidHex + "01" "b6030000" "00", false },
        { "notice_empty",        "59420306", false },
        // EQUIVOCATION (4): the body is empty, a byte is malformed.
        { "equivocation_ok",     "59420307", true },
        { "equivocation_byte",   "59420307" "00", false },
        // ATTESTOR_REVIVE (78).
        { "revive_ok",           "59420308" "0100" "50c30000" "b6030000" + sigHex, true },
        { "revive_short",        "59420308" "0100" "50c30000" "b6030000" + sigHex.substr(0, 126), false },
        { "revive_trailing",     "59420308" "0100" "50c30000" "b6030000" + sigHex + "00", false },
        { "revive_no_sig",       "59420308" "0100" "50c30000" "b6030000", false },
    };
    for (const Case& c : cases) {
        Payload p;
        BOOST_CHECK_MESSAGE(DecodePayload(Hex(c.hex), p) == c.ok, c.name);
    }
    // TRANSFER count 16 = 85 bytes: over MAX_PAYLOAD and over the count bound; 15 is the maximum.
    {
        std::vector<unsigned char> sixteen = Hex("5942030210");
        for (uint8_t i = 0; i < 16; i++) { sixteen.push_back(i); sixteen.push_back(1); sixteen.push_back(0); sixteen.push_back(0); sixteen.push_back(0); }
        Payload p;
        BOOST_CHECK(!DecodePayload(sixteen, p));
        std::vector<unsigned char> fifteen = Hex("594203020f");
        for (uint8_t i = 0; i < 15; i++) { fifteen.push_back(i); fifteen.push_back(1); fifteen.push_back(0); fifteen.push_back(0); fifteen.push_back(0); }
        BOOST_CHECK_EQUAL(fifteen.size(), 80u);
        BOOST_CHECK(DecodePayload(fifteen, p));
        BOOST_CHECK_EQUAL(p.assignments.size(), 15u);
    }
    // REDEEM count 14 = 81 bytes: rejected; 13 = 76 bytes is the maximum (the v3 head costs two slots).
    {
        std::vector<unsigned char> fourteen = Hex("59420303" "b6030000" "ff" "ff" "0e");
        for (uint8_t i = 0; i < 14; i++) { fourteen.push_back(i); fourteen.push_back(1); fourteen.push_back(0); fourteen.push_back(0); fourteen.push_back(0); }
        BOOST_CHECK_EQUAL(fourteen.size(), 81u);
        Payload p;
        BOOST_CHECK(!DecodePayload(fourteen, p));
        std::vector<unsigned char> thirteen = Hex("59420303" "b6030000" "ff" "ff" "0d");
        for (uint8_t i = 0; i < 13; i++) { thirteen.push_back(i); thirteen.push_back(1); thirteen.push_back(0); thirteen.push_back(0); thirteen.push_back(0); }
        BOOST_CHECK_EQUAL(thirteen.size(), 76u);
        BOOST_CHECK(DecodePayload(thirteen, p));
        BOOST_CHECK_EQUAL(p.assignments.size(), 13u);
        BOOST_CHECK_EQUAL(MAX_REDEEM_ASSIGNMENTS, 13u);
        // The encoder refuses 14 for REDEEM but accepts 15 for TRANSFER.
        std::vector<Assignment> as;
        for (uint8_t i = 0; i < 14; i++) as.push_back(Assignment(i, 1));
        BOOST_CHECK(EncodePayload(Payload::Redeem(1, 0xFF, as)).empty());
        as.push_back(Assignment(14, 1));
        BOOST_CHECK_EQUAL(EncodePayload(Payload::Transfer(as)).size(), 80u);
    }
    // 81 bytes never decodes, whatever the header.
    {
        std::vector<unsigned char> long81 = Hex("59420302");
        long81.resize(81, 0);
        Payload p;
        BOOST_CHECK(!DecodePayload(long81, p));
    }
    // The encoder refuses what the decoder would refuse.
    BOOST_CHECK(EncodePayload(Payload::Transfer({ Assignment(1, 0) })).empty());
    BOOST_CHECK(EncodePayload(Payload::Transfer({ Assignment(1, 1), Assignment(1, 2) })).empty());
    CPubKey unc;
    { CKey k; k = CKey::TestOnlyRandomKey(false); unc = k.GetPubKey(); }
    const CPubKey good(Hex(KEYHEX));
    BOOST_CHECK(EncodePayload(Payload::Mint(0, 1, 1, 1, unc, 0xFF)).empty());
    BOOST_CHECK(EncodePayload(Payload::Mint(0, 1, 1, 1, CPubKey(), 0xFF)).empty());
    BOOST_CHECK(EncodePayload(Payload::AttestorRegister(unc, good, 1, 0)).empty());
    BOOST_CHECK(EncodePayload(Payload::AttestorRegister(good, CPubKey(), 1, 0)).empty());
    BOOST_CHECK(!EncodePayload(Payload::AttestorRegister(good, good, 1, 0)).empty());
}

// Rule: MINT-8
// Rule: RED-3
// Rule: AFEE-0
// Rule: AFEE-1
// feeVout / attestFeeVout: 0xFF = no such fee output; any other value is
// carried as is. The codec does not range-check either (K11): MINT-8/RED-3
// (and their AFEE-1 clause) compare them with vout.size() and the reserved
// indices, so FindPayload keeps a payload whose feeVout is out of range.
BOOST_AUTO_TEST_CASE(mint8_feevout_semantics)
{
    CPubKey owner = TestKey();
    for (uint8_t fv : { (uint8_t)0, (uint8_t)3, (uint8_t)0xFE, FEE_VOUT_NONE }) {
        Payload p;
        BOOST_REQUIRE(DecodePayload(EncodePayload(Payload::Mint(0, 10000, 1000, 950, owner, fv)), p));
        BOOST_CHECK_EQUAL(p.feeVout, fv);
        BOOST_CHECK_EQUAL(p.attestFeeVout, FEE_VOUT_NONE);
        BOOST_REQUIRE(DecodePayload(EncodePayload(Payload::Redeem(950, fv, {})), p));
        BOOST_CHECK_EQUAL(p.feeVout, fv);
        BOOST_CHECK_EQUAL(p.attestFeeVout, FEE_VOUT_NONE);
        // attestFeeVout is independent of feeVout and round-trips the same way.
        BOOST_REQUIRE(DecodePayload(EncodePayload(Payload::Mint(0, 10000, 1000, 950, owner, FEE_VOUT_NONE, fv)), p));
        BOOST_CHECK_EQUAL(p.attestFeeVout, fv);
        BOOST_CHECK_EQUAL(p.feeVout, FEE_VOUT_NONE);
        BOOST_REQUIRE(DecodePayload(EncodePayload(Payload::Redeem(950, 2, { Assignment(3, 1) }, fv)), p));
        BOOST_CHECK_EQUAL(p.attestFeeVout, fv);
        BOOST_CHECK_EQUAL(p.feeVout, 2);
    }
    BOOST_CHECK_EQUAL(FEE_VOUT_NONE, 0xFF);
    BOOST_CHECK_EQUAL(Payload().feeVout, FEE_VOUT_NONE);
    BOOST_CHECK_EQUAL(Payload().attestFeeVout, FEE_VOUT_NONE);
    // An attestFeeVout of 9 in a 3-output transaction still parses (AFEE-1, not the codec, rejects it).
    {
        CMutableTransaction mtx = TxWithOutputs(3, PayloadScript(EncodePayload(Payload::Mint(0, 10000, 1000, 950, owner, 1, 9))), 2);
        auto fp = FindPayload(CTransaction(mtx));
        BOOST_REQUIRE(fp.has_value());
        BOOST_CHECK_EQUAL(fp->payload.attestFeeVout, 9);
    }
    // A MINT with feeVout = 9 in a 3-output transaction still parses (the rule, not the codec, rejects it).
    CMutableTransaction mtx = TxWithOutputs(3, PayloadScript(EncodePayload(Payload::Mint(0, 10000, 1000, 950, owner, 9))), 2);
    auto fp = FindPayload(CTransaction(mtx));
    BOOST_REQUIRE(fp.has_value());
    BOOST_CHECK_EQUAL(fp->payload.feeVout, 9);
    BOOST_CHECK_EQUAL(fp->opReturnIndex, 2u);
}

// Rule: TX-0
BOOST_AUTO_TEST_CASE(tx0_opreturn_shape)
{
    std::vector<unsigned char> data = EncodePayload(Payload::Transfer({ Assignment(1, 100) }));
    // Exactly OP_RETURN <push>.
    BOOST_CHECK(ExtractOpReturnData(PayloadScript(data)).value() == data);
    // Not OP_RETURN.
    BOOST_CHECK(!ExtractOpReturnData(CScript() << data).has_value());
    BOOST_CHECK(!ExtractOpReturnData(CScript()).has_value());
    BOOST_CHECK(!ExtractOpReturnData(CScript() << OP_RETURN).has_value());
    // Two pushes.
    BOOST_CHECK(!ExtractOpReturnData(CScript() << OP_RETURN << data << data).has_value());
    // OP_N is not a data push.
    BOOST_CHECK(!ExtractOpReturnData(CScript() << OP_RETURN << OP_1).has_value());
    BOOST_CHECK(!ExtractOpReturnData(CScript() << OP_RETURN << OP_0).has_value());
    // Trailing opcode.
    BOOST_CHECK(!ExtractOpReturnData(CScript() << OP_RETURN << data << OP_DROP).has_value());
    // Length bounds on the push: 3 bytes and 81 bytes are out; 4 and 80 are in (decoding is separate).
    BOOST_CHECK(!ExtractOpReturnData(CScript() << OP_RETURN << std::vector<unsigned char>(3, 1)).has_value());
    BOOST_CHECK(!ExtractOpReturnData(CScript() << OP_RETURN << std::vector<unsigned char>(81, 1)).has_value());
    BOOST_CHECK(ExtractOpReturnData(CScript() << OP_RETURN << std::vector<unsigned char>(4, 1)).has_value());
    BOOST_CHECK(ExtractOpReturnData(CScript() << OP_RETURN << std::vector<unsigned char>(80, 1)).has_value());
    // A non-minimal push (OP_PUSHDATA1 for 10 bytes) is still one push of the bytes.
    {
        CScript s;
        s << OP_RETURN;
        s.push_back(OP_PUSHDATA1);
        s.push_back((unsigned char)data.size());
        s.insert(s.end(), data.begin(), data.end());
        BOOST_CHECK(ExtractOpReturnData(s).value() == data);
    }
    // Truncated PUSHDATA.
    {
        CScript s;
        s << OP_RETURN;
        s.push_back(OP_PUSHDATA1);
        s.push_back(50);
        s.push_back(1);
        BOOST_CHECK(!ExtractOpReturnData(s).has_value());
    }
}

// Rule: TX-0
// Rule: XFER-1
BOOST_AUTO_TEST_CASE(tx0_find_payload_in_transaction)
{
    CPubKey owner = TestKey();
    const CScript mint = PayloadScript(EncodePayload(Payload::Mint(0, 10000, 1000, 950, owner, 3)));
    const CScript xfer = PayloadScript(EncodePayload(Payload::Transfer({ Assignment(0, 100), Assignment(2, 200) })));

    // Found, with its index.
    {
        CMutableTransaction mtx = TxWithOutputs(4, mint, 2);
        auto fp = FindPayload(CTransaction(mtx));
        BOOST_REQUIRE(fp.has_value());
        BOOST_CHECK_EQUAL(fp->opReturnIndex, 2u);
        BOOST_CHECK(fp->payload.type == PayloadType::MINT);
        BOOST_CHECK_EQUAL(fp->payload.refHeight, 950u);
    }
    // No OP_RETURN.
    {
        CMutableTransaction mtx = TxWithOutputs(2, CScript() << OP_TRUE, 0);
        BOOST_CHECK(!FindPayload(CTransaction(mtx)).has_value());
        BOOST_CHECK(!FindOpReturn(CTransaction(mtx)).has_value());
    }
    // Two OP_RETURNs: non-Yellowback even if one is a good payload.
    {
        CMutableTransaction mtx = TxWithOutputs(4, mint, 2);
        mtx.vout[3].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>(4, 0);
        BOOST_CHECK(!FindPayload(CTransaction(mtx)).has_value());
        BOOST_CHECK(!FindOpReturn(CTransaction(mtx)).has_value());
    }
    // A bare OP_RETURN (no push) counts as the OP_RETURN output but carries no payload.
    {
        CMutableTransaction mtx = TxWithOutputs(2, CScript() << OP_RETURN, 1);
        BOOST_CHECK_EQUAL(FindOpReturn(CTransaction(mtx)).value(), 1u);
        BOOST_CHECK(!FindPayload(CTransaction(mtx)).has_value());
    }
    // Assigned vout beyond the outputs.
    {
        CMutableTransaction mtx = TxWithOutputs(2, xfer, 1);   // assigns vout 2, which does not exist
        BOOST_CHECK(!FindPayload(CTransaction(mtx)).has_value());
    }
    // Assigned vout is the OP_RETURN itself.
    {
        CMutableTransaction mtx = TxWithOutputs(3, xfer, 2);   // assigns vout 2 = the OP_RETURN
        BOOST_CHECK(!FindPayload(CTransaction(mtx)).has_value());
        CMutableTransaction ok = TxWithOutputs(4, xfer, 3);
        BOOST_CHECK(FindPayload(CTransaction(ok)).has_value());
    }
    // A REDEEM with count = 0 has no assignments to check.
    {
        CMutableTransaction mtx = TxWithOutputs(2, PayloadScript(EncodePayload(Payload::Redeem(1, 0xFF, {}))), 1);
        auto fp = FindPayload(CTransaction(mtx));
        BOOST_REQUIRE(fp.has_value());
        BOOST_CHECK(fp->payload.type == PayloadType::REDEEM);
        BOOST_CHECK(fp->payload.assignments.empty());
    }
    // An unknown-type payload is ignored at the transaction level too (V23; see the version cases below).
    {
        CMutableTransaction mtx = TxWithOutputs(2, PayloadScript(Hex("59420304" "00000000")), 1);
        BOOST_CHECK(!FindPayload(CTransaction(mtx)).has_value());
    }
    // The attestation types have no assignments: FindPayload keeps them whatever the output count.
    {
        CMutableTransaction mtx = TxWithOutputs(1, PayloadScript(EncodePayload(Payload::Equivocation())), 0);
        auto fp = FindPayload(CTransaction(mtx));
        BOOST_REQUIRE(fp.has_value());
        BOOST_CHECK(fp->payload.type == PayloadType::EQUIVOCATION);
        mtx = TxWithOutputs(2, PayloadScript(EncodePayload(Payload::ClaimNotice(uint256S("0x01"), 200, 950))), 1);
        fp = FindPayload(CTransaction(mtx));
        BOOST_REQUIRE(fp.has_value());
        BOOST_CHECK(fp->payload.type == PayloadType::CLAIM_NOTICE);
        BOOST_CHECK_EQUAL(fp->payload.vaultVout, 200);   // a vault outpoint index, not one of this transaction's vouts
        BOOST_CHECK_EQUAL(fp->payload.refHeight, 950u);
        mtx = TxWithOutputs(2, PayloadScript(EncodePayload(Payload::AttestorRegister(owner, owner, 5, 0))), 1);
        fp = FindPayload(CTransaction(mtx));
        BOOST_REQUIRE(fp.has_value());
        BOOST_CHECK(fp->payload.type == PayloadType::ATTESTOR_REGISTER);
        BOOST_CHECK(fp->payload.attestorPubKey == owner);
        BOOST_CHECK(fp->payload.bondPubKey == owner);
        mtx = TxWithOutputs(2, PayloadScript(EncodePayload(Payload::AttestorRevive(3, 50000, 949, TestSig(9)))), 1);
        fp = FindPayload(CTransaction(mtx));
        BOOST_REQUIRE(fp.has_value());
        BOOST_CHECK(fp->payload.type == PayloadType::ATTESTOR_REVIVE);
        BOOST_CHECK_EQUAL(fp->payload.seq, 3);
        BOOST_CHECK_EQUAL(fp->payload.priceMicroUsd, 50000u);
        BOOST_CHECK_EQUAL(fp->payload.citedHeight, 949u);
        BOOST_CHECK(fp->payload.sig == TestSig(9));
    }
    BOOST_CHECK_EQUAL(std::string(PayloadTypeName(PayloadType::MINT)), "mint");
    BOOST_CHECK_EQUAL(std::string(PayloadTypeName(PayloadType::TRANSFER)), "transfer");
    BOOST_CHECK_EQUAL(std::string(PayloadTypeName(PayloadType::REDEEM)), "redeem");
    BOOST_CHECK_EQUAL(std::string(PayloadTypeName(PayloadType::ATTESTOR_REGISTER)), "register");
    BOOST_CHECK_EQUAL(std::string(PayloadTypeName(PayloadType::CLAIM_NOTICE)), "notice");
    BOOST_CHECK_EQUAL(std::string(PayloadTypeName(PayloadType::EQUIVOCATION)), "equivocation");
    BOOST_CHECK_EQUAL(std::string(PayloadTypeName(PayloadType::ATTESTOR_REVIVE)), "revive");
}

// ---------------------------------------------------------------------------
// V23: version 1 (the prototype's layout, PRICE 0x10 included) and version 2
// (the v2 codec: 51-byte MINT, 10 + 5n REDEEM) are non-Yellowback under v3 (W14).
// Rule: MINT-1
// Rule: XFER-1
// Rule: RED-1
BOOST_AUTO_TEST_CASE(version1_is_non_yellowback)
{
    Payload p;
    BOOST_CHECK(!DecodePayload(Hex("59420101" "00" "10270000" "e8030000" "b6030000" + KEYHEX), p));
    BOOST_CHECK(!DecodePayload(Hex("59420110" "50c3000000000000"), p));
    BOOST_CHECK(!DecodePayload(Hex("59420103" "01" "0139300000"), p));
    BOOST_CHECK(!DecodePayload(Hex("59420310" "50c3000000000000"), p));   // 0x10 under version 3: reserved
}

// Rule: MINT-1
// Rule: XFER-1
// Rule: RED-1
BOOST_AUTO_TEST_CASE(version2_is_non_yellowback)
{
    Payload p;
    // The exact v2 encodings (the v2 test vectors), each well-formed under the v2 codec.
    BOOST_CHECK(!DecodePayload(Hex("59420201" "02" "04030201" "0d0c0b0a" "44332211" + KEYHEX + "03"), p));   // v2 MINT, 51 bytes
    BOOST_CHECK(!DecodePayload(Hex("59420202" "01" "03" "00010000"), p));                                     // v2 TRANSFER
    BOOST_CHECK(!DecodePayload(Hex("59420203" "44332211" "ff" "01" "02" "00010000"), p));                    // v2 REDEEM
    BOOST_CHECK(!DecodePayload(Hex("59420203" "07000000" "01" "00"), p));
    BOOST_CHECK(!DecodePayload(Hex("59420202" "00"), p));                                                     // a v2 empty TRANSFER
    // The same bodies under version 3: TRANSFER is unchanged and decodes; MINT and REDEEM need the extra byte.
    BOOST_CHECK(DecodePayload(Hex("59420302" "01" "03" "00010000"), p));
    BOOST_CHECK(!DecodePayload(Hex("59420301" "02" "04030201" "0d0c0b0a" "44332211" + KEYHEX + "03"), p));
    BOOST_CHECK(!DecodePayload(Hex("59420303" "44332211" "ff" "01" "02" "00010000"), p));
    // A version-2 payload is ignored at the transaction level too.
    CMutableTransaction mtx = TxWithOutputs(2, PayloadScript(Hex("59420202" "01" "00" "64000000")), 1);
    BOOST_CHECK(!FindPayload(CTransaction(mtx)).has_value());
    mtx = TxWithOutputs(2, PayloadScript(Hex("59420302" "01" "00" "64000000")), 1);
    BOOST_CHECK(FindPayload(CTransaction(mtx)).has_value());
    // A Payload built with version 2 is not encodable.
    Payload v2 = Payload::Transfer({ Assignment(1, 100) });
    v2.version = 2;
    BOOST_CHECK(EncodePayload(v2).empty());
    BOOST_CHECK_EQUAL(PAYLOAD_VERSION, 3);
}

// Rule: REG-A1
// Rule: NOT-1
// Rule: EQV-1
// Rule: REV-1
// The four attestation payloads: field-by-field round trips and the fixed sizes 75 / 41 / 4 / 78.
BOOST_AUTO_TEST_CASE(attestation_types_roundtrip)
{
    CPubKey attestor = TestKey();
    CPubKey bond = TestKey();
    Payload p;
    // ATTESTOR_REGISTER
    std::vector<unsigned char> enc = EncodePayload(Payload::AttestorRegister(attestor, bond, 420480, 0x01));
    BOOST_REQUIRE_EQUAL(enc.size(), 75u);
    BOOST_REQUIRE(DecodePayload(enc, p));
    BOOST_CHECK(p.type == PayloadType::ATTESTOR_REGISTER);
    BOOST_CHECK(p.attestorPubKey == attestor);
    BOOST_CHECK(p.bondPubKey == bond);
    BOOST_CHECK(p.attestorKeyBytes == std::vector<unsigned char>(attestor.begin(), attestor.end()));
    BOOST_CHECK(p.bondKeyBytes == std::vector<unsigned char>(bond.begin(), bond.end()));
    BOOST_CHECK_EQUAL(p.bondLocktime, 420480u);
    BOOST_CHECK_EQUAL(p.flags, 0x01);
    BOOST_CHECK(EncodePayload(p) == enc);
    // Any 33 bytes: the keys are carried verbatim and CPubKey reports them invalid (REG-A1 judges).
    {
        std::vector<unsigned char> bad = enc;
        bad[4] = 0x07;
        BOOST_REQUIRE(DecodePayload(bad, p));
        BOOST_CHECK(!p.attestorPubKey.IsValid());
        BOOST_CHECK_EQUAL(p.attestorKeyBytes[0], 0x07);
        BOOST_CHECK(p.bondPubKey == bond);
        BOOST_CHECK(EncodePayload(p) == bad);
    }
    // CLAIM_NOTICE
    const uint256 vault = uint256S("0xdeadbeef00000000000000000000000000000000000000000000000000000001");
    enc = EncodePayload(Payload::ClaimNotice(vault, 3, 12345));
    BOOST_REQUIRE_EQUAL(enc.size(), 41u);
    BOOST_REQUIRE(DecodePayload(enc, p));
    BOOST_CHECK(p.type == PayloadType::CLAIM_NOTICE);
    BOOST_CHECK(p.vaultTxid == vault);
    BOOST_CHECK_EQUAL(p.vaultVout, 3);
    BOOST_CHECK_EQUAL(p.refHeight, 12345u);
    BOOST_CHECK(p.VaultOutPoint() == COutPoint(vault, 3));
    BOOST_CHECK(EncodePayload(p) == enc);
    // The vout byte is the outpoint index: 0xFF is a value, not "none".
    BOOST_REQUIRE(DecodePayload(EncodePayload(Payload::ClaimNotice(vault, 0xFF, 1)), p));
    BOOST_CHECK_EQUAL(p.vaultVout, 0xFF);
    // The COutPoint factory truncates n to the byte the payload carries (a vault output is always vout 2 in practice).
    BOOST_CHECK(Payload::ClaimNotice(COutPoint(vault, 0x102), 1) == Payload::ClaimNotice(vault, 0x02, 1));
    // EQUIVOCATION
    enc = EncodePayload(Payload::Equivocation());
    BOOST_REQUIRE_EQUAL(enc.size(), 4u);
    BOOST_REQUIRE(DecodePayload(enc, p));
    BOOST_CHECK(p.type == PayloadType::EQUIVOCATION);
    BOOST_CHECK(p == Payload::Equivocation());
    BOOST_CHECK(EncodePayload(p) == enc);
    // ATTESTOR_REVIVE
    enc = EncodePayload(Payload::AttestorRevive(7, 50000, 9999, TestSig(0x40)));
    BOOST_REQUIRE_EQUAL(enc.size(), 78u);
    BOOST_REQUIRE(DecodePayload(enc, p));
    BOOST_CHECK(p.type == PayloadType::ATTESTOR_REVIVE);
    BOOST_CHECK_EQUAL(p.seq, 7);
    BOOST_CHECK_EQUAL(p.priceMicroUsd, 50000u);
    BOOST_CHECK_EQUAL(p.citedHeight, 9999u);
    BOOST_CHECK(p.sig == TestSig(0x40));
    BOOST_CHECK(EncodePayload(p) == enc);
    // seq is a u16 little-endian: 0x0102 encodes as 02 01.
    enc = EncodePayload(Payload::AttestorRevive(0x0102, 1, 1, TestSig(0)));
    BOOST_CHECK_EQUAL(enc[4], 0x02);
    BOOST_CHECK_EQUAL(enc[5], 0x01);
    // Inequality across every field the operator compares.
    BOOST_CHECK(!(Payload::AttestorRevive(7, 50000, 9999, TestSig(0x40)) == Payload::AttestorRevive(8, 50000, 9999, TestSig(0x40))));
    BOOST_CHECK(!(Payload::AttestorRevive(7, 50000, 9999, TestSig(0x40)) == Payload::AttestorRevive(7, 50000, 9999, TestSig(0x41))));
    BOOST_CHECK(!(Payload::ClaimNotice(vault, 3, 1) == Payload::ClaimNotice(vault, 4, 1)));
    BOOST_CHECK(!(Payload::AttestorRegister(attestor, bond, 1, 0) == Payload::AttestorRegister(bond, attestor, 1, 0)));
    BOOST_CHECK(!(Payload::AttestorRegister(attestor, bond, 1, 0) == Payload::AttestorRegister(attestor, bond, 1, 1)));
    BOOST_CHECK(!(Payload::Equivocation() == Payload::AttestorRegister(attestor, bond, 1, 0)));
}

BOOST_AUTO_TEST_SUITE_END()
