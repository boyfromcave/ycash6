// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016-2023 The Zcash developers
// Copyright (c) 2019-present The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_KEY_IO_H
#define BITCOIN_KEY_IO_H

#include <chainparams.h>
#include <key.h>
#include <pubkey.h>
#include <script/standard.h>
#include <zcash/Address.hpp>

#include <vector>
#include <string>

/** The plain-YEC PQ address version (D-Q-20) of a network ID: 4dd9 "sq…" main, 4f61 "tq…" test, 4c51 "rq…"
 *  regtest; empty for any other network. */
std::vector<unsigned char> PlainPQAddressVersion(const std::string& networkID);

class KeyIO {
private:
    const KeyConstants& keyConstants;

public:
    KeyIO(const KeyConstants& keyConstants): keyConstants(keyConstants) { }

    CKey DecodeSecret(const std::string& str) const;
    std::string EncodeSecret(const CKey& key) const;

    CExtKey DecodeExtKey(const std::string& str) const;
    std::string EncodeExtKey(const CExtKey& extkey) const;
    CExtPubKey DecodeExtPubKey(const std::string& str) const;
    std::string EncodeExtPubKey(const CExtPubKey& extpubkey) const;

    std::string EncodeDestination(const CTxDestination& dest) const;
    CTxDestination DecodeDestination(const std::string& str) const;
    /**
     * Decode a Zcash-encoded transparent address (using the LEGACY_* base58
     * prefixes). Used by pre-fork callsites such as founders reward decoding
     * and by ZecToYec() to convert legacy user input.
     */
    CTxDestination DecodeLegacyDestination(const std::string& str) const;
    /**
     * Re-encode a Zcash-encoded transparent address string under the Ycash
     * canonical prefixes. Returns the canonical encoding on success, or the
     * Ycash encoding of CNoDestination on failure.
     */
    std::string ZecToYec(const std::string& str) const;

    bool IsValidDestinationString(const std::string& str) const;

    std::string EncodePaymentAddress(const libzcash::PaymentAddress& zaddr) const;
    std::optional<libzcash::PaymentAddress> DecodePaymentAddress(const std::string& str) const;
    /**
     * Decode a Zcash-encoded shielded payment address (using the LEGACY_*
     * base58 / bech32 prefixes for Sprout and Sapling, respectively).
     */
    std::optional<libzcash::PaymentAddress> DecodeLegacyPaymentAddress(const std::string& str) const;
    /**
     * Re-encode a Zcash-encoded shielded payment address string under the
     * Ycash canonical prefixes. Returns the canonical encoding on success,
     * or an empty string on failure.
     */
    std::string ZecToYecShielded(const std::string& str) const;
    bool IsValidPaymentAddressString(const std::string& str) const;
    std::string EncodeTexAddress(const CKeyID& p2pkhAddr) const;

    std::string EncodeViewingKey(const libzcash::ViewingKey& vk) const;
    std::optional<libzcash::ViewingKey> DecodeViewingKey(const std::string& str) const;

    /**
     * Sapling incoming-viewing-key (`zivks...`) codec. Ported from
     * ycash-official to support exchanges and explorers that round-trip
     * IVK-only viewing keys via the legacy z_exportivk / z_importivk RPCs.
     * Distinct from EncodeViewingKey / DecodeViewingKey, which handle the
     * larger SaplingExtendedFullViewingKey (`zviews...`) form.
     */
    std::string EncodeIVK(const libzcash::SaplingIncomingViewingKey& ivk) const;
    std::optional<libzcash::SaplingIncomingViewingKey> DecodeIVK(const std::string& str) const;

    std::string EncodeSpendingKey(const libzcash::SpendingKey& zkey) const;
    std::optional<libzcash::SpendingKey> DecodeSpendingKey(const std::string& str) const;

};

#endif // BITCOIN_KEY_IO_H
