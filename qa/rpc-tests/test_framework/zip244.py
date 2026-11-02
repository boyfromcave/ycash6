#!/usr/bin/env python3
# Copyright (c) 2021 The Zcash developers
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

#
# zip244.py
#
# Functionality to create txids, auth digests, and signature digests.
#
# This file is modified from zcash/zcash-test-vectors.
#

import struct

from hashlib import blake2b

from .mininode import ser_string, ser_uint256
from .script import (
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    getHashOutputs,
    getHashPrevouts,
    getHashSequence,
)


# Transparent

def transparent_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdTranspaHash')

    if len(tx.vin) + len(tx.vout) > 0:
        digest.update(getHashPrevouts(tx, b'ZTxIdPrevoutHash'))
        digest.update(getHashSequence(tx, b'ZTxIdSequencHash'))
        digest.update(getHashOutputs(tx, b'ZTxIdOutputsHash'))

    return digest.digest()

def transparent_scripts_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxAuthTransHash')
    for x in tx.vin:
        digest.update(ser_string(x.scriptSig))
    return digest.digest()

# Sapling

def sapling_digest(saplingBundle):
    digest = blake2b(digest_size=32, person=b'ZTxIdSaplingHash')

    if len(saplingBundle.spends) + len(saplingBundle.outputs) > 0:
        digest.update(sapling_spends_digest(saplingBundle))
        digest.update(sapling_outputs_digest(saplingBundle))
        digest.update(struct.pack('<q', saplingBundle.valueBalance))

    return digest.digest()

def sapling_auth_digest(saplingBundle):
    digest = blake2b(digest_size=32, person=b'ZTxAuthSapliHash')

    if len(saplingBundle.spends) + len(saplingBundle.outputs) > 0:
        for desc in saplingBundle.spends:
            digest.update(desc.zkproof.serialize())
        for desc in saplingBundle.spends:
            digest.update(desc.spendAuthSig.serialize())
        for desc in saplingBundle.outputs:
            digest.update(desc.zkproof.serialize())
        digest.update(saplingBundle.bindingSig.serialize())

    return digest.digest()

# - Spends

def sapling_spends_digest(saplingBundle):
    digest = blake2b(digest_size=32, person=b'ZTxIdSSpendsHash')

    if len(saplingBundle.spends) > 0:
        digest.update(sapling_spends_compact_digest(saplingBundle))
        digest.update(sapling_spends_noncompact_digest(saplingBundle))

    return digest.digest()

def sapling_spends_compact_digest(saplingBundle):
    digest = blake2b(digest_size=32, person=b'ZTxIdSSpendCHash')
    for desc in saplingBundle.spends:
        digest.update(ser_uint256(desc.nullifier))
    return digest.digest()

def sapling_spends_noncompact_digest(saplingBundle):
    digest = blake2b(digest_size=32, person=b'ZTxIdSSpendNHash')
    for desc in saplingBundle.spends:
        digest.update(ser_uint256(desc.cv))
        digest.update(ser_uint256(saplingBundle.anchor))
        digest.update(ser_uint256(desc.rk))
    return digest.digest()

# - Outputs

def sapling_outputs_digest(saplingBundle):
    digest = blake2b(digest_size=32, person=b'ZTxIdSOutputHash')

    if len(saplingBundle.outputs) > 0:
        digest.update(sapling_outputs_compact_digest(saplingBundle))
        digest.update(sapling_outputs_memos_digest(saplingBundle))
        digest.update(sapling_outputs_noncompact_digest(saplingBundle))

    return digest.digest()

def sapling_outputs_compact_digest(saplingBundle):
    digest = blake2b(digest_size=32, person=b'ZTxIdSOutC__Hash')
    for desc in saplingBundle.outputs:
        digest.update(ser_uint256(desc.cmu))
        digest.update(ser_uint256(desc.ephemeralKey))
        digest.update(desc.encCiphertext[:52])
    return digest.digest()

def sapling_outputs_memos_digest(saplingBundle):
    digest = blake2b(digest_size=32, person=b'ZTxIdSOutM__Hash')
    for desc in saplingBundle.outputs:
        digest.update(desc.encCiphertext[52:564])
    return digest.digest()

def sapling_outputs_noncompact_digest(saplingBundle):
    digest = blake2b(digest_size=32, person=b'ZTxIdSOutN__Hash')
    for desc in saplingBundle.outputs:
        digest.update(ser_uint256(desc.cv))
        digest.update(desc.encCiphertext[564:])
        digest.update(desc.outCiphertext)
    return digest.digest()

# Orchard

def orchard_digest(orchardBundle):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrchardHash')

    if len(orchardBundle.actions) > 0:
        digest.update(orchard_actions_compact_digest(orchardBundle))
        digest.update(orchard_actions_memos_digest(orchardBundle))
        digest.update(orchard_actions_noncompact_digest(orchardBundle))
        digest.update(struct.pack('B', orchardBundle.flags()))
        digest.update(struct.pack('<q', orchardBundle.valueBalance))
        digest.update(ser_uint256(orchardBundle.anchor))

    return digest.digest()

def orchard_auth_digest(orchardBundle):
    digest = blake2b(digest_size=32, person=b'ZTxAuthOrchaHash')

    if len(orchardBundle.actions) > 0:
        digest.update(bytes(orchardBundle.proofs))
        for desc in orchardBundle.actions:
            digest.update(desc.spendAuthSig.serialize())
        digest.update(orchardBundle.bindingSig.serialize())

    return digest.digest()

# - Actions

def orchard_actions_compact_digest(orchardBundle):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrcActCHash')
    for desc in orchardBundle.actions:
        digest.update(ser_uint256(desc.nullifier))
        digest.update(ser_uint256(desc.cmx))
        digest.update(ser_uint256(desc.ephemeralKey))
        digest.update(desc.encCiphertext[:52])
    return digest.digest()

def orchard_actions_memos_digest(orchardBundle):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrcActMHash')
    for desc in orchardBundle.actions:
        digest.update(desc.encCiphertext[52:564])
    return digest.digest()

def orchard_actions_noncompact_digest(orchardBundle):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrcActNHash')
    for desc in orchardBundle.actions:
        digest.update(ser_uint256(desc.cv))
        digest.update(ser_uint256(desc.rk))
        digest.update(desc.encCiphertext[564:])
        digest.update(desc.outCiphertext)
    return digest.digest()

# Transaction

def header_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdHeadersHash')

    digest.update(struct.pack('<I', (int(tx.fOverwintered)<<31) | tx.nVersion))
    digest.update(struct.pack('<I', tx.nVersionGroupId))
    digest.update(struct.pack('<I', tx.nConsensusBranchId))
    digest.update(struct.pack('<I', tx.nLockTime))
    digest.update(struct.pack('<I', tx.nExpiryHeight))

    return digest.digest()

def txid_digest(tx):
    digest = blake2b(
        digest_size=32,
        person=b'ZcashTxHash_' + struct.pack('<I', tx.nConsensusBranchId),
    )

    digest.update(header_digest(tx))
    digest.update(transparent_digest(tx))
    digest.update(sapling_digest(tx.saplingBundle))
    digest.update(orchard_digest(tx.orchardBundle))

    return digest.digest()

# Authorizing Data Commitment

def auth_digest(tx):
    digest = blake2b(
        digest_size=32,
        person=b'ZTxAuthHash_' + struct.pack('<I', tx.nConsensusBranchId),
    )

    digest.update(transparent_scripts_digest(tx))
    digest.update(sapling_auth_digest(tx.saplingBundle))
    digest.update(orchard_auth_digest(tx.orchardBundle))

    return digest.digest()

# Signatures (ZIP 244 S.1-S.4, as specified; librustzcash
# zcash_primitives/src/transaction/sighash_v5.rs)
#
# Ycash, 2026: the transparent signature digest below replaces the draft
# version this file shipped with (which hashed a scriptCode per input, blanked
# the sequence digest for SINGLE/NONE, had no amounts or scriptPubKeys digests,
# and raised TypeError on bytes(COutPoint)). The final ZIP 244 S.2 commits, unless
# ANYONECANPAY is set, to the amounts and scriptPubKeys of *every* spent output,
# and per input to its prevout, value, scriptPubKey and nSequence. It is checked
# against the upstream vectors in src/test/data/zip0244.json by test_zip244.py.

class TransparentInput(object):
    """One spent transparent output as ZIP 244 S.2 sees it: the input index,
    the spent output's scriptPubKey (bytes) and its value (zatoshi)."""
    def __init__(self, nIn, scriptPubKey, amount):
        self.nIn = nIn
        self.scriptPubKey = bytes(scriptPubKey)
        self.amount = amount


def signature_digest(tx, t_inputs, nHashType, txin):
    """ZIP 244 signature digest.

    t_inputs: a TransparentInput for every transparent input of tx, in order
    (the verifier's view of all spent outputs; ignored for coinbase or a
    transaction without transparent inputs).
    txin: the TransparentInput being signed, or None for a shielded signature
    (Sapling spendAuthSig / bindingSig, Orchard), which uses SIGHASH_ALL.
    """
    digest = blake2b(
        digest_size=32,
        person=b'ZcashTxHash_' + struct.pack('<I', tx.nConsensusBranchId),
    )

    digest.update(header_digest(tx))
    digest.update(transparent_sig_digest(tx, t_inputs, nHashType, txin))
    digest.update(sapling_digest(tx.saplingBundle))
    digest.update(orchard_digest(tx.orchardBundle))

    return digest.digest()

def _is_coinbase(tx):
    return (len(tx.vin) == 1 and tx.vin[0].prevout.hash == 0
            and tx.vin[0].prevout.n == 0xFFFFFFFF)

def transparent_sig_digest(tx, t_inputs, nHashType, txin):
    # S.2: coinbase, or no transparent inputs: identical to T.2.
    if len(tx.vin) == 0 or _is_coinbase(tx):
        return transparent_digest(tx)

    if txin is None:
        # A shielded signature over a transaction with transparent inputs.
        nHashType = SIGHASH_ALL
    if len(t_inputs) != len(tx.vin):
        raise ValueError("ZIP 244: one TransparentInput per transparent input")

    digest = blake2b(digest_size=32, person=b'ZTxIdTranspaHash')

    digest.update(hash_type(nHashType))                       # S.2a
    digest.update(prevouts_sig_digest(tx, nHashType))         # S.2b
    digest.update(amounts_sig_digest(t_inputs, nHashType))    # S.2c
    digest.update(scriptpubkeys_sig_digest(t_inputs, nHashType))  # S.2d
    digest.update(sequence_sig_digest(tx, nHashType))         # S.2e
    digest.update(outputs_sig_digest(tx, nHashType, txin))    # S.2f
    digest.update(txin_sig_digest(tx, txin))                  # S.2g

    return digest.digest()

def hash_type(nHashType):
    # Defined hash types only (ycashd SignatureHash throws on any other).
    if nHashType not in (0x01, 0x02, 0x03, 0x81, 0x82, 0x83):
        raise ValueError("ZIP 244: undefined hash_type 0x%02x" % nHashType)
    return struct.pack('B', nHashType)

def prevouts_sig_digest(tx, nHashType):
    # If the SIGHASH_ANYONECANPAY flag is not set:
    if not (nHashType & SIGHASH_ANYONECANPAY):
        return getHashPrevouts(tx, b'ZTxIdPrevoutHash')
    else:
        return blake2b(digest_size=32, person=b'ZTxIdPrevoutHash').digest()

def amounts_sig_digest(t_inputs, nHashType):
    digest = blake2b(digest_size=32, person=b'ZTxTrAmountsHash')
    if not (nHashType & SIGHASH_ANYONECANPAY):
        for x in t_inputs:
            digest.update(struct.pack('<q', x.amount))
    return digest.digest()

def scriptpubkeys_sig_digest(t_inputs, nHashType):
    digest = blake2b(digest_size=32, person=b'ZTxTrScriptsHash')
    if not (nHashType & SIGHASH_ANYONECANPAY):
        for x in t_inputs:
            digest.update(ser_string(x.scriptPubKey))
    return digest.digest()

def sequence_sig_digest(tx, nHashType):
    # If the SIGHASH_ANYONECANPAY flag is not set (SINGLE and NONE keep it):
    if not (nHashType & SIGHASH_ANYONECANPAY):
        return getHashSequence(tx, b'ZTxIdSequencHash')
    else:
        return blake2b(digest_size=32, person=b'ZTxIdSequencHash').digest()

def outputs_sig_digest(tx, nHashType, txin):
    # If the sighash type is neither SIGHASH_SINGLE nor SIGHASH_NONE:
    if (nHashType & 0x1f) != SIGHASH_SINGLE and (nHashType & 0x1f) != SIGHASH_NONE:
        return getHashOutputs(tx, b'ZTxIdOutputsHash')

    # If the sighash type is SIGHASH_SINGLE and the signature hash is being computed for
    # the transparent input at a particular index, and a transparent output appears in the
    # transaction at that index:
    elif (nHashType & 0x1f) == SIGHASH_SINGLE and txin is not None and \
            0 <= txin.nIn and txin.nIn < len(tx.vout):
        digest = blake2b(digest_size=32, person=b'ZTxIdOutputsHash')
        digest.update(bytes(tx.vout[txin.nIn].serialize()))
        return digest.digest()

    else:
        return blake2b(digest_size=32, person=b'ZTxIdOutputsHash').digest()

def txin_sig_digest(tx, txin):
    digest = blake2b(digest_size=32, person=b'Zcash___TxInHash')
    if txin is not None:
        digest.update(tx.vin[txin.nIn].prevout.serialize())   # S.2g.i
        digest.update(struct.pack('<q', txin.amount))         # S.2g.ii
        digest.update(ser_string(txin.scriptPubKey))          # S.2g.iii
        digest.update(struct.pack('<I', tx.vin[txin.nIn].nSequence))  # S.2g.iv
    return digest.digest()
