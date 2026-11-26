// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Yugen read RPCs (doc/yugen-node.md). rpcversion 12 (decision Y-6).

#include "chainparams.h"
#include "consensus/upgrades.h"
#include "core_io.h"
#include "main.h"
#include "txmempool.h"
#include "rpc/server.h"
#include "sync.h"
#include "util/strencodings.h"
#include "yugen/state.h"

#include <univalue.h>

static const int YUGEN_RPC_VERSION = 12;

static int YugenNetworkByte(const CChainParams& p)
{
    if (p.NetworkIDString() == CBaseChainParams::MAIN) return 0;
    if (p.NetworkIDString() == CBaseChainParams::REGTEST) return 2;
    return 1;
}

UniValue yugen_getinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "yugen_getinfo\n"
            "\nYugen upgrade state: rpcversion, activation height, branch id, whether the next block is under Yugen.\n"
            "\nResult:\n"
            "{ \"rpcversion\": 12, \"active\": bool, \"activation_height\": n (-1 if none), \"branch_id\": n,\n"
            "  \"network\": n, \"tip_height\": n, \"anchor_window\": 96, \"anchor_grid\": 16 }\n");
    const CChainParams& chainparams = Params();
    const auto& consensus = chainparams.GetConsensus();
    LOCK(cs_main);
    const int tip = chainActive.Height();
    UniValue o(UniValue::VOBJ);
    o.pushKV("rpcversion", YUGEN_RPC_VERSION);
    o.pushKV("active", consensus.NetworkUpgradeActive(tip + 1, Consensus::UPGRADE_YUGEN));
    o.pushKV("activation_height", consensus.vUpgrades[Consensus::UPGRADE_YUGEN].nActivationHeight);
    o.pushKV("branch_id", (int64_t)NetworkBranchId(Consensus::UPGRADE_YUGEN, consensus));
    o.pushKV("network", YugenNetworkByte(chainparams));
    o.pushKV("tip_height", tip);
    o.pushKV("anchor_window", 96);
    o.pushKV("anchor_grid", 16);
    const auto& st = yugen::Current(chainparams);
    if (st.tipHeight >= 0) {
        o.pushKV("tree_size", (int64_t)(1 + st.cms.size()));
        o.pushKV("root", yugen::HexRoot(st.blocks.at(st.tipHeight).rootAfter));
        o.pushKV("pool_balance", ValueFromAmount(st.balance));      // B, the turnstile (§13.3.2)
        o.pushKV("pool_balance_zat", st.balance);
    }
    return o;
}

static const yugen::BlockRecord& RecordAt(const UniValue& hv, int& h)
{
    h = hv.get_int();
    const auto& st = yugen::Current(Params());
    auto it = st.blocks.find(h);
    if (it == st.blocks.end())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "no Yugen state at that height (below activation or above the tip)");
    return it->second;
}

UniValue yugen_getblockdata(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "yugen_getblockdata height\n"
            "\nThe block's applied Yugen transfers (spec 0.5.1 §7.8), in block order; commitments are appended\n"
            "cm_1 then cm_2 per transfer after tree_size_before leaves (cm* is leaf 0 from activation).\n"
            "\nResult: { \"height\", \"hash\" (RPC byte order), \"tree_size_before\", \"root_after\" (hex48),\n"
            "  \"transfers\": [ { \"txid\", \"index_in_block\", \"transfer\" (hex, spec §7.1) } ],\n"
            "  \"bundles\": [ { \"txid\", \"stmt\" (bstmt hex32, null if unknown), \"proof_hash_a\", \"proof_hash_b\",\n"
            "    \"transfers\" (n in the bundle), \"applied\", \"transfer_indexes\" (into \"transfers\"), \"nf1\" (per applied\n"
            "    transfer), \"proof_a_bytes\", \"proof_b_bytes\" (null if not held), \"fee_zat\", \"skipped_fee_zat\" } ] }\n");
    LOCK(cs_main);
    int h;
    const auto& rec = RecordAt(params[0], h);
    UniValue o(UniValue::VOBJ);
    o.pushKV("height", h);
    o.pushKV("hash", chainActive[h]->GetBlockHash().GetHex());
    o.pushKV("tree_size_before", (int64_t)rec.treeSizeBefore);
    o.pushKV("root_after", yugen::HexRoot(rec.rootAfter));
    o.pushKV("pool_balance_before_zat", rec.balanceBefore);
    o.pushKV("pool_balance_after_zat", rec.balanceAfter);
    UniValue a(UniValue::VARR);
    int i = 0;
    for (const auto& [txid, bytes] : rec.transfers) {
        UniValue t(UniValue::VOBJ);
        t.pushKV("txid", txid.GetHex());
        t.pushKV("index_in_block", i++);
        t.pushKV("transfer", HexStr(bytes));
        a.push_back(t);
    }
    o.pushKV("transfers", a);
    // B-RPC-2: the block's bundles, in block order (RPC only; read from the block on disk).
    UniValue bs(UniValue::VARR);
    CBlock block;
    if (!ReadBlockFromDisk(block, chainActive[h], Params().GetConsensus()))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "can't read block from disk");
    for (const CTransaction& tx : block.vtx) {
        if (!tx.IsYugenBundle()) continue;
        std::vector<yugen::Transfer> ts;
        std::vector<uint8_t> slots;
        std::vector<std::vector<unsigned char>> raw;
        std::string why;
        if (!yugen::DecodeBundleTransfers(tx.yugen.transfer, ts, slots, why, &raw)) continue;
        std::vector<bool> applied(ts.size(), false);
        UniValue idx(UniValue::VARR), nfs(UniValue::VARR);
        CAmount fee = 0, skipped = 0;
        size_t napplied = 0;
        for (size_t k = 0; k < ts.size(); k++) {
            for (size_t j = 0; j < rec.transfers.size(); j++) {
                if (rec.transfers[j].first == tx.GetHash() && rec.transfers[j].second == raw[k]) {
                    applied[k] = true;
                    idx.push_back((int64_t)j);
                    nfs.push_back(HexStr(ts[k].nf[0].begin(), ts[k].nf[0].end()));
                    break;
                }
            }
            if (applied[k]) { fee += (CAmount)ts[k].Fee(); napplied++; } else skipped += (CAmount)ts[k].Fee();
        }
        const auto& b = tx.yugen.transfer;
        UniValue e(UniValue::VOBJ);
        e.pushKV("txid", tx.GetHash().GetHex());
        auto stmt = yugen::BundleStatement(tx, h, applied, Params());
        e.pushKV("stmt", stmt ? UniValue(*stmt) : NullUniValue);
        e.pushKV("proof_hash_a", HexStr(b.end() - 64, b.end() - 32));
        e.pushKV("proof_hash_b", HexStr(b.end() - 32, b.end()));
        e.pushKV("transfers", (int64_t)ts.size());
        e.pushKV("applied", (int64_t)napplied);
        e.pushKV("transfer_indexes", idx);
        e.pushKV("nf1", nfs);
        auto proofs = yugen::GetProofs(tx.GetHash());
        bool held = proofs && proofs->size() == 2;
        e.pushKV("proof_a_bytes", held ? UniValue((int64_t)(*proofs)[0].size()) : NullUniValue);
        e.pushKV("proof_b_bytes", held ? UniValue((int64_t)(*proofs)[1].size()) : NullUniValue);
        e.pushKV("fee_zat", fee);
        e.pushKV("skipped_fee_zat", skipped);
        bs.push_back(e);
    }
    o.pushKV("bundles", bs);
    return o;
}

UniValue yugen_getanchor(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "yugen_getanchor height\n"
            "\nThe note-tree root after block `height` and that block's hash in internal byte order (as the\n"
            "transfer hash binds it, spec §7.2).\n"
            "\nResult: { \"height\", \"root\" (hex48), \"block_hash\" (hex32, internal order), \"grid\": bool }\n");
    LOCK(cs_main);
    int h;
    const auto& rec = RecordAt(params[0], h);
    uint256 bh = chainActive[h]->GetBlockHash();
    UniValue o(UniValue::VOBJ);
    o.pushKV("height", h);
    o.pushKV("root", yugen::HexRoot(rec.rootAfter));
    o.pushKV("block_hash", HexStr(bh.begin(), bh.end()));
    o.pushKV("grid", h % 16 == 0);
    return o;
}

UniValue gettransferstatus(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "gettransferstatus nf\n"
            "\nThe state of the transfer that spends nullifier nf (either of its two spends).\n"
            "\nResult: { \"state\": \"mempool\" | \"mined\" | \"unknown\", \"height\" (when mined), \"txid\" (when known) }\n");
    auto b = ParseHex(params[0].get_str());
    if (b.size() != 32) throw JSONRPCError(RPC_INVALID_PARAMETER, "nf1: 32 bytes hex");
    std::array<uint8_t, 32> nf;
    std::copy(b.begin(), b.end(), nf.begin());
    LOCK2(cs_main, mempool.cs);
    UniValue o(UniValue::VOBJ);
    const auto& st = yugen::Current(Params());
    auto it = st.nfHeight.find(nf);
    if (it != st.nfHeight.end()) {
        o.pushKV("state", "mined");
        o.pushKV("height", it->second);
        return o;
    }
    for (const auto& e : mempool.mapTx) {
        if (auto t = e.GetTx().GetYugenTransfer()) {
            if (t->nf[0] == nf || t->nf[1] == nf) {  // either spend: a dummy can be the second
                o.pushKV("state", "mempool");
                o.pushKV("txid", e.GetTx().GetHash().GetHex());
                return o;
            }
        }
    }
    o.pushKV("state", "unknown");
    return o;
}

UniValue sendrawtransaction(const UniValue& params, bool fHelp);

UniValue submittransfer(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1 || !params[0].isObject())
        throw std::runtime_error(
            "submittransfer {\"tx\": hex, \"route\": \"leaf\"}\n"
            "\nSubmits a Yugen leaf transaction (the leaf route; \"bundle\" arrives with M2).\n"
            "\nResult: { \"txid\", \"nf1\" }\n");
    const UniValue& req = params[0];
    std::string route = req.exists("route") ? req["route"].get_str() : "leaf";
    if (route != "leaf") throw JSONRPCError(RPC_INVALID_PARAMETER, "only the leaf route is served on this node");
    UniValue p(UniValue::VARR);
    p.push_back(req["tx"]);
    UniValue txid = sendrawtransaction(p, false);
    CTransaction tx;
    DecodeHexTx(tx, req["tx"].get_str());
    UniValue o(UniValue::VOBJ);
    o.pushKV("txid", txid);
    if (auto t = tx.GetYugenTransfer()) o.pushKV("nf1", HexStr(t->nf[0].begin(), t->nf[0].end()));
    return o;
}

UniValue submitbundle(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1 || !params[0].isObject())
        throw std::runtime_error(
            "submitbundle {\"tx\": hex, \"proofs\": [proof_a hex, proof_b hex]}\n"
            "\nSubmits a finished Yugen bundle (spec 0.5.1 §15): the bundle transaction (its Yugen field\n"
            "holds the §15.1 encoding, both inline proof fields empty) and its two root proofs, which are\n"
            "kept as block sidecar data. The node verifies the bundle before it enters the mempool.\n"
            "\nResult: { \"accepted\": true, \"txid\", \"transfers\": n }; the identical transaction already in the\n"
            "mempool is answered the same way (a retry); a refusal is an error.\n");
    const UniValue& req = params[0];
    CTransaction tx;
    if (!req["tx"].isStr()) throw JSONRPCError(RPC_INVALID_PARAMETER, "tx: hex");
    DecodeHexTx(tx, req["tx"].get_str());
    if (!tx.IsYugenBundle()) throw JSONRPCError(RPC_INVALID_PARAMETER, "not a Yugen bundle transaction");
    if (!req["proofs"].isArray() || req["proofs"].size() != 2)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "proofs: two hex strings (System A, System B)");
    std::vector<std::vector<unsigned char>> proofs;
    for (const auto& p : req["proofs"].getValues()) {
        if (!p.isStr() || !IsHex(p.get_str())) throw JSONRPCError(RPC_INVALID_PARAMETER, "proof is not hex");
        proofs.push_back(ParseHex(p.get_str()));
        if (proofs.back().size() > yugen::PROOF_BYTES_MAX) throw JSONRPCError(RPC_INVALID_PARAMETER, "proof too long");
    }
    bool alreadyPooled = false;
    {
        LOCK(cs_main);
        // Idempotent: the identical transaction already pooled (e.g. a retry after a lost reply) is
        // accepted again; a different one spending the same nullifiers is still refused below.
        alreadyPooled = mempool.exists(tx.GetHash());
        if (!alreadyPooled) yugen::PutProofs(tx.GetHash(), proofs);
    }
    UniValue txid(tx.GetHash().GetHex());
    if (!alreadyPooled) {
        UniValue p(UniValue::VARR);
        p.push_back(req["tx"]);
        txid = sendrawtransaction(p, false);
    }
    UniValue o(UniValue::VOBJ);
    o.pushKV("accepted", true);
    o.pushKV("txid", txid);
    o.pushKV("transfers", (int64_t)tx.GetYugenTransfers().size());
    return o;
}

static const CRPCCommand commands[] =
{ //  category   name              actor (function)   okSafeMode
    { "yugen",   "yugen_getinfo",       &yugen_getinfo,       true  },
    { "yugen",   "yugen_getblockdata",  &yugen_getblockdata,  true  },
    { "yugen",   "yugen_getanchor",     &yugen_getanchor,     true  },
    { "yugen",   "gettransferstatus",   &gettransferstatus,   true  },
    { "yugen",   "submittransfer",      &submittransfer,      false },
    { "yugen",   "submitbundle",        &submitbundle,        false },
};

void RegisterYugenRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
