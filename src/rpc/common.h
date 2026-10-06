// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2019-2023 The Zcash developers
// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef ZCASH_RPC_COMMON_H
#define ZCASH_RPC_COMMON_H

#include "rpc/client.h"
#include "rpc/protocol.h"
#include "util/match.h"
#include "util/system.h"

#include <set>
#include <stdint.h>

#include <univalue.h>

enum class Conversion {
    /// passed as a JSON string, verbatim
    None,
    /// the literal string `null` is passed as JSON `null`, otherwise passed as a verbatim string
    /// NB: This needs to be used carefully, as it could discard the valid string “null”.
    NullableString,
    /// parsed as a JSON value
    JSON,
};

typedef std::pair<std::vector<Conversion>, std::vector<Conversion>> ParameterSpec;

typedef std::map<std::string, ParameterSpec> CRPCConvertTable;

// Single-character aliases for alignment and scannability in the table.
static constexpr Conversion s = Conversion::None;
static constexpr Conversion n = Conversion::NullableString;
static constexpr Conversion o = Conversion::JSON;

/// A table of operation parameters. The first element is the name of an RPC operation. All RPC
/// operations must be in this list. The second element is a pair of vectors – one for the required
/// parameters of the operation, one for the optional parameters. Each vector contains the
/// `Conversion` for the parameter at that position.
static const CRPCConvertTable rpcCvtTable =
{
    // operation {required params, optional params}
    // blockchain
    { "getblockcount",               {{}, {}} },
    { "getbestblockhash",            {{}, {}} },
    { "getdifficulty",               {{}, {}} },
    { "getrawmempool",               {{}, {o}} },
    { "getblockdeltas",              {{s}, {}} },
    { "getblockhashes",              {{o, o}, {o}} },
    { "getblockhash",                {{o}, {}} },
    { "getblockheader",              {{s}, {o}} },
    { "getblock",                    {{s}, {o}} },
    { "getcompactblock",             {{s}, {}} },
    { "getcompactblockrange",        {{o, o}, {}} },
    { "gettxoutsetinfo",             {{}, {}} },
    { "gettxout",                    {{s, o}, {o}} },
    { "verifychain",                 {{}, {o, o}} },
    { "getblockchaininfo",           {{}, {}} },
    { "getchaintips",                {{}, {}} },
    { "exportchain",                 {{}, {s}} },
    { "getexportchainstatus",        {{}, {}} },
    { "z_gettreestate",              {{s}, {}} },
    { "z_getsubtreesbyindex",        {{s, o}, {o}} },
    { "getmempoolinfo",              {{}, {}} },
    { "invalidateblock",             {{s}, {}} },
    { "reconsiderblock",             {{s}, {}} },
    // mining
    { "getlocalsolps",               {{}, {}} },
    { "getnetworksolps",             {{}, {o, o}} },
    { "getnetworkhashps",            {{}, {o, o}} },
    { "getgenerate",                 {{}, {}} },
    { "generate",                    {{o}, {}} },
    { "setgenerate",                 {{o}, {o}} },
    { "getmininginfo",               {{}, {}} },
    { "prioritisetransaction",       {{s, o, o}, {}} },
    { "getblocktemplate",            {{}, {o}} },
    // NB: The second argument _should_ be an object, but upstream treats it as a string, so we
    //     preserve that here.
    { "submitblock",                 {{s}, {s}} },
    { "getblocksubsidy",             {{}, {o}} },
    // misc
    { "getinfo",                     {{}, {}} },
    { "validateaddress",             {{s}, {}} },
    { "z_validateaddress",           {{s}, {}} },
    { "createmultisig",              {{o, o}, {}} },
    { "verifymessage",               {{s, s ,s}, {}} },
    { "setmocktime",                 {{o}, {}} },
    { "getexperimentalfeatures",     {{}, {}} },
    { "getaddressmempool",           {{o}, {}} },
    { "getaddressutxos",             {{o}, {}} },
    { "getaddressdeltas",            {{o}, {}} },
    { "getaddressbalance",           {{o}, {}} },
    { "getaddresstxids",             {{o}, {}} },
    { "getaddressfirstlastheight",   {{s}, {}} },
    { "getspentinfo",                {{o}, {}} },
    { "getmemoryinfo",               {{}, {}} },
    // net
    { "getconnectioncount",          {{}, {}} },
    { "ping",                        {{}, {}} },
    { "getpeerinfo",                 {{}, {}} },
    { "addnode",                     {{s, s}, {}} },
    { "disconnectnode",              {{s}, {}} },
    { "getaddednodeinfo",            {{o}, {s}} },
    { "getnettotals",                {{}, {}} },
    { "getdeprecationinfo",          {{}, {}} },
    { "getnetworkinfo",              {{}, {}} },
    { "setban",                      {{s, s}, {o, o}} },
    { "listbanned",                  {{}, {}} },
    { "clearbanned",                 {{}, {}} },
    // rawtransaction
    { "getrawtransaction",           {{s}, {o, s}} },
    { "gettxoutproof",               {{o}, {s}} },
    { "verifytxoutproof",            {{s}, {}} },
    { "createrawtransaction",        {{o, o}, {o, o}} },
    { "decoderawtransaction",        {{s}, {}} },
    { "decodescript",                {{s}, {}} },
    { "signrawtransaction",          {{s}, {o, o, s, s}} },
    { "sendrawtransaction",          {{s}, {o, o}} },   // Yellowback H7: allowyedburn
    // rpcdisclosure
    { "z_getpaymentdisclosure",      {{s, o, o}, {s}} },
    { "z_validatepaymentdisclosure", {{s}, {}} },
    // rpcdump
    { "importprivkey",               {{s}, {s, o}} },
    { "importaddress",               {{s}, {s, o, o}} },
    { "importpubkey",                {{s}, {s, o}} },
    { "z_importwallet",              {{s}, {}} },
    { "importwallet",                {{s}, {}} },
    { "dumpprivkey",                 {{s}, {}} },
    { "z_exportwallet",              {{s}, {}} },
    { "z_importkey",                 {{s}, {s, o}} },
    { "z_importviewingkey",          {{s}, {s, o}} },
    { "z_exportkey",                 {{s}, {}} },
    { "z_exportviewingkey",          {{s}, {}} },
    { "z_exportivk",                 {{s}, {}} },
    { "z_importivk",                 {{s, s}, {s, o}} },
    { "z_getalldiversifiedaddresses",{{s}, {}} },
    { "z_getnewdiversifiedaddress",  {{s}, {}} },
    // rpcwallet
    { "z_converttex",                {{s}, {}} },
    { "getnewaddress",               {{}, {s}} },
    { "getrawchangeaddress",         {{}, {}} },
    { "sendtoaddress",               {{s, o}, {s, s, o}} },
    { "listaddresses",               {{}, {}} },
    { "listaddressgroupings",        {{}, {o}} },
    { "signmessage",                 {{s, s}, {}} },
    { "getreceivedbyaddress",        {{s}, {o, o, o}} },
    { "getbalance",                  {{}, {s, o, o, o, o}} },
    { "sendmany",                    {{s, o}, {o, s, o}} },
    { "addmultisigaddress",          {{o, o}, {s}} },
    { "listreceivedbyaddress",       {{}, {o, o, o, s, o, o}} },
    { "listtransactions",            {{}, {s, o, o, o, o}} },
    { "listsinceblock",              {{}, {s, o, o, o, o, o}} },
    // wallet-legacy (accounts RPCs restored from deprecation)
    { "getaccount",                  {{s}, {}} },
    { "getaccountaddress",           {{s}, {}} },
    { "getaddressesbyaccount",       {{s}, {}} },
    { "getreceivedbyaccount",        {{s}, {o}} },
    { "listaccounts",                {{}, {o, o}} },
    { "listreceivedbyaccount",       {{}, {o, o, o}} },
    { "move",                        {{s, s, o}, {o, s}} },
    { "sendfrom",                    {{s, s, o}, {o, s, s}} },
    { "setaccount",                  {{s}, {s}} },
    { "gettransaction",              {{s}, {o, o, o}} },
    { "backupwallet",                {{s}, {}} },
    { "keypoolrefill",               {{}, {o}} },
    { "walletpassphrase",            {{s, o}, {}} },
    { "walletpassphrasechange",      {{s, s}, {}} },
    { "walletconfirmbackup",         {{s}, {}} },
    { "walletlock",                  {{}, {}} },
    { "encryptwallet",               {{s}, {}} },
    { "lockunspent",                 {{o, o}, {}} },
    { "listlockunspent",             {{}, {}} },
    { "settxfee",                    {{o}, {}} },
    { "getwalletinfo",               {{}, {o}} },
    { "resendwallettransactions",    {{}, {}} },
    { "listunspent",                 {{}, {o, o, o, o, o, o}} },
    { "z_listunspent",               {{}, {o, o, o, o, o}} },
    { "fundrawtransaction",          {{s}, {o}} },
    { "zcsamplejoinsplit",           {{}, {}} },
    { "zcbenchmark",                 {{s, o}, {o}} },
    { "z_getnewaddress",             {{}, {s}} },
    { "z_getnewaccount",             {{}, {}} },
    { "z_getaddressforaccount",      {{o}, {o, o}} },
    { "z_listaccounts",              {{}, {}} },
    { "z_listaddresses",             {{}, {o}} },
    { "z_listunifiedreceivers",      {{s}, {}} },
    { "z_listreceivedbyaddress",     {{s}, {o, o}} },
    { "z_getbalance",                {{s}, {o, o}} },
    { "z_getbalanceforviewingkey",   {{s}, {o, o}} },
    { "z_getbalanceforaccount",      {{o}, {o, o}} },
    { "z_gettotalbalance",           {{}, {o, o}} },
    { "z_viewtransaction",           {{s}, {}} },
    { "z_getoperationresult",        {{}, {o}} },
    { "z_getoperationstatus",        {{}, {o}} },
    { "z_sendmany",                  {{s, o}, {o, o, s}} },
    { "z_setmigration",              {{o}, {}} },
    { "z_getmigrationstatus",        {{}, {o}} },
    { "z_shieldcoinbase",            {{s, s}, {o, o, n, s}} },
    { "z_mergetoaddress",            {{o, s}, {o, o, o, n, s}} },
    { "z_listoperationids",          {{}, {s}} },
    { "z_getnotescount",             {{}, {o, o}} },
    // atomicswap
    { "initiateswap",                {{s, s, o, o}, {s}} },
    { "initiateswapfromhash",        {{s, s, o, o, s}, {}} },
    { "participateswap",             {{s, s, o, s}, {s}} },
    { "auditswap",                   {{s, s, o}, {}} },
    { "claimswap",                   {{s, s, o, s}, {s}} },
    { "refundswap",                  {{s, s, o}, {s}} },
    { "monitorswap",                 {{s}, {}} },
    { "listatomicswaps",             {{}, {s}} },
    { "getswapsecret",               {{s}, {}} },
    { "deleteswap",                  {{s}, {}} },
    // server
    { "help",                        {{}, {s}} },
    { "setlogfilter",                {{s}, {}} },
    { "stop",                        {{}, {o}} },
    // yellowback: generated by qa/yellowback-rpc-cvt.py from the handlers' arity guards; do not edit by hand
    { "yed_addattestation",          {{s}, {}} },
    { "yed_buildbundle",             {{o, s}, {}} },
    { "yed_claim",                   {{s}, {s, s, o, o}} },
    { "yed_claimnotice",             {{s}, {s, o}} },
    { "yed_decodepayload",           {{s}, {}} },
    { "yed_estimatecollateral",      {{o, o}, {o}} },
    { "yed_estimatefee",             {{o}, {}} },
    { "yed_estimatesend",            {{o}, {}} },
    { "yed_getactivation",           {{}, {}} },
    { "yed_getattestations",         {{}, {}} },
    { "yed_getbalance",              {{}, {s}} },
    { "yed_getblockverdict",         {{s}, {}} },
    { "yed_getfeepayee",             {{o, o}, {s}} },
    { "yed_gethistory",              {{o, o}, {}} },
    { "yed_getinfo",                 {{}, {}} },
    { "yed_getnewaddress",           {{}, {}} },
    { "yed_getnotice",               {{s}, {}} },
    { "yed_getprice",                {{}, {o}} },
    { "yed_getselection",            {{o, s}, {}} },
    { "yed_getstatehash",            {{}, {o}} },
    { "yed_getstats",                {{}, {}} },
    { "yed_gettag",                  {{s}, {}} },
    { "yed_gettxinfo",               {{s}, {}} },
    { "yed_getvault",                {{s}, {}} },
    { "yed_listattestors",           {{}, {o}} },
    { "yed_listclaimable",           {{}, {o, o}} },
    { "yed_listminers",              {{}, {o, o}} },
    { "yed_listpositions",           {{}, {s}} },
    { "yed_listtokens",              {{o}, {o, o, o}} },
    { "yed_listtransactions",        {{}, {o, o}} },
    { "yed_listunspent",             {{}, {s}} },
    { "yed_listvaults",              {{}, {s, o, o}} },
    { "yed_lockcoins",               {{}, {}} },
    { "yed_mint",                    {{o, o}, {s, s, o, o}} },
    { "yed_redeem",                  {{s}, {s}} },
    { "yed_registerattestor",        {{o, o}, {o}} },
    { "yed_reportequivocation",      {{s, s}, {o}} },
    { "yed_revive",                  {{o, o}, {}} },
    { "yed_send",                    {{s, o}, {}} },
    { "yed_sendmany",                {{o}, {}} },
    { "yed_setquote",                {{o, o}, {}} },
    { "yed_signattestation",         {{o, o}, {o}} },
    { "yed_sweep",                   {{s, s}, {s}} },
    { "yed_sweepcarriers",           {{}, {}} },
    { "yed_unlockcoin",              {{s, o, s}, {}} },
    { "yed_validateaddress",         {{s}, {}} },
    { "yed_validaterawtransaction",  {{s}, {}} },
    { "yed_withdrawbond",            {{o}, {s}} },
    // end yellowback
    // the vault primitive (doc/vault-rpc.md)
    { "vault_getinfo",               {{}, {}} },
    { "set_list",                    {{}, {}} },
    { "set_getinfo",                 {{s}, {o}} },
    { "vault_list",                  {{}, {o}} },
    { "vault_decodescript",          {{s}, {}} },
    { "set_create",                  {{o}, {}} },
    { "set_join",                    {{s, o, o}, {s}} },
    { "set_heartbeat",               {{s}, {s}} },
    { "set_buildact",                {{s, o}, {}} },
    { "set_signact",                 {{s}, {s}} },
    { "set_sendact",                 {{s}, {}} },
    { "set_equivocation",            {{o}, {}} },
    { "vault_lock",                  {{o}, {}} },
    { "vault_buildunlock",           {{s, o}, {}} },
    { "set_signunlock",              {{s}, {}} },
    { "vault_buildcancel",           {{s}, {}} },
    { "set_signcancel",              {{s}, {}} },
    { "vault_send",                  {{s}, {}} },
    { "vault_release",               {{s}, {s}} },
    { "vault_ownerspend",            {{s, s}, {}} },
    { "vault_app",                   {{s}, {o}} },
    // end vault
};

#endif // ZCASH_RPC_COMMON_H
