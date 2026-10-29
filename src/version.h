// Copyright (c) 2012-2014 The Bitcoin Core developers
// Copyright (c) 2016-2023 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_VERSION_H
#define BITCOIN_VERSION_H

/**
 * network protocol versioning
 */

//! 270200 = the Vault-era protocol version (UPGRADE_VAULT.nProtocolVersion on
//! every network, the same on ycash-dd), taken with 6.22.0-rc1 (testnet plan
//! T-8; upgrade plan P8 part D). It is above every latent upgrade's version
//! (NU5 270014/270015, NU6.x 2701xx, all NO_ACTIVATION_HEIGHT), so it collides
//! with none. Before Vault activates it gates nobody: peers are held to
//! MIN_PEER_PROTO_VERSION (the Canopy-era 270013 of ycashd v4.5.0 and Yolk).
//! Once Vault is the current epoch, a peer below 270200 is disconnected.
static const int PROTOCOL_VERSION = 270200;

//! initial proto version, to be increased after version/verack negotiation
static const int INIT_PROTO_VERSION = 209;

//! disconnect from peers older than this proto version.
//! 270013 = Ycash v4.4.4, the oldest protocol legitimately on the
//! Ycash network; agreed as the floor across ycashd and Yolk/Zebra.
static const int MIN_PEER_PROTO_VERSION = 270013;

//! nTime field added to CAddress, starting with this version.
//! This can't be removed because it affects the encoding of the
//! `addrFrom` field in a "version" message.
static const int CADDR_TIME_VERSION = 31402;

//! BIP 0031, pong message, is enabled for all versions AFTER this one
static const int BIP0031_VERSION = 60000;

//! "filter*" commands are disabled without NODE_BLOOM after and including this version
static const int NO_BLOOM_VERSION = 170004;

//! Protocol version at which MSG_WTX (wtxid) inventory becomes usable.
//! MSG_WTX (ZIP 239) only carries meaning for v5 transactions, which require
//! NU5 -- inactive on Ycash (NO_ACTIVATION_HEIGHT). The live Ycash network
//! (ycashd v4.5.0, Yolk) advertises the same Canopy-era 270013 PROTOCOL_VERSION
//! we do but does NOT speak MSG_WTX, so gating on PROTOCOL_VERSION would make
//! us send unparseable MSG_WTX inv to those peers. Pin to an unreachable
//! sentinel so MSG_WTX is never advertised or sent: InvForTransaction only
//! emits MSG_WTX for nVersion>=5 txs (which cannot exist here), and a peer
//! that sends us one is rejected at deserialization. The machinery stays
//! compiled but dormant; flip this to the appropriate bumped version if Ycash
//! ever activates NU5. 0x7FFFFFFF (INT_MAX) is the unreachable sentinel, the
//! same idiom UPGRADE_ZFUTURE.nProtocolVersion uses; no <limits> needed here.
static const int CINV_WTX_VERSION = 0x7FFFFFFF;

//! disconnect from testnet peers older than this proto version.
//! Same Ycash v4.4.4 floor (270013) as mainnet, aligned with
//! Yolk/Zebra.
static const int MIN_TESTNET_PEER_PROTO_VERSION = 270013;

#endif // BITCOIN_VERSION_H
