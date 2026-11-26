// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The Yugen account of the ycashd wallet (doc/yugen-node.md, decisions N-A1..N-A4). The account's
// keys, note scan, mailbox-host sync, transfer builder and provers are the wallet engine of yewd
// (yewd-yugen, yew yewd/yugen), run as a child process per call, the same binary
// -yugenprover names. Its seed is derived from the wallet's mnemonic seed (N-A2), kept in wallet.dat under the
// wallet's encryption (N-A5) and handed to the engine per call on fd 3 only while the wallet is unlocked.
//
// LOCKING: Call() runs a process that calls back into this node's RPC (yugen_getinfo,
// yugen_getblockdata, submittransfer, ...). Never call it with cs_main or cs_wallet held.

#ifndef BITCOIN_WALLET_YUGENACCOUNT_H
#define BITCOIN_WALLET_YUGENACCOUNT_H

#include <cassert>

#include "support/allocators/secure.h"

#include <univalue.h>

#include <optional>
#include <string>
#include <vector>

namespace yugenwallet {

//! The engine binary (-yugenwallet, else -yugenprover) is set and Yugen has a height.
bool Configured();
//! Configured() and the account exists (z_getnewaddress "yugen" or a restore created it).
bool Exists();
//! A Yugen address string of the decision Y-14 form (yqf/yqtf/yqrf, yqk...): the prefix only.
bool LooksLikeYugenAddress(const std::string& s);
//! N-A2: the account seed from the wallet's mnemonic seed; nullopt while the wallet is locked or has none.
std::optional<std::vector<unsigned char>> DerivedSeed();
//! Runs `yewd-yugen <method> <params>`; returns its JSON value; throws a JSONRPCError on refusal.
UniValue Call(const std::string& method, const UniValue& params, int64_t timeoutSecs = 0);
//! The account's state file (wallet.json), after a chain scan when `scan`.
UniValue State(bool scan);
//! The addresses handed out by z_getnewaddress (default first).
std::vector<std::string> Addresses();
//! True for an address in Addresses().
bool IsOwnAddress(const std::string& s);
//! z_getnewaddress "yugen": the default short address, or with `onetime` the one-time form.
std::string NewAddress(bool onetime);
//! Backup: the seed hex of the account from wallet.dat ("" when there is no Yugen account). Throws (never "")
//! when the account exists and its seed is not available, so a dump never silently leaves it out.
SecureString SeedHex();
//! Restore from a backup's seed line: creates the account from `seedHex` if none exists.
//! Returns false (and leaves the account) when one with another seed exists.
bool RestoreSeed(const SecureString& seedHex, std::string& err);
//! N-A5: move a seed left in the engine's state file by an earlier version into wallet.dat (encrypted when the
//! wallet is) and overwrite the file without it. False (with `err`) when the wallet is locked or the seeds differ.
bool MigrateLegacySeed(std::string& err);
//! The wallet is encrypted and locked: no engine call (reads use the last state), spends are refused.
bool Locked();
//! Rescan: forget the chain and host state (keeps counters, issued requests); the next call rebuilds it. A legacy
//! seed in the state file is first moved into wallet.dat; false (nothing changed) when it cannot be (a locked wallet).
bool ResetChainState(std::string& err);
//! The recovery step for a ResetChainState error, worded per cause (locked, another seed, malformed, not on disk).
std::string RescanRecovery(const std::string& err);
//! Balances in zatoshis: spendable (anchored, unspent), pending (found, not yet anchored, or change of a
//! spend not yet mined), outgoing (queued payments to short addresses).
struct Balances { int64_t spendable{0}, pending{0}, outgoing{0}; };
Balances GetBalances();
//! Note rows (z_listunspent / z_listreceivedbyaddress shape, "pool": "yugen"); `unspentOnly` drops spent
//! notes and change of value 0. `includeChange` keeps internal change notes.
UniValue NoteRows(bool unspentOnly, int minconf, bool includeChange);
//! Transaction rows (listtransactions shape, "pool": "yugen"): receive rows per received note, a send row per
//! own Yugen spend (amount = notes in - change - fee).
UniValue TxRows();
//! The Yugen rows of one transaction (gettransaction), or null.
UniValue TxDetail(const std::string& txid);
//! The scheduler thread (spec §17.8 item 1, decision Y-16): one sync per 16-block boundary.
void ThreadScheduledSync();

} // namespace yugenwallet

#endif // BITCOIN_WALLET_YUGENACCOUNT_H
