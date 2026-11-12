# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""Post-quantum address text (quantum spec §4, D-9) for the functional tests.

An address is Base58Check(version || 32-byte keyHash), 53 characters, with one 3-byte version per
(network, coin, scheme): the third character names the scheme (f = FN-DSA-512, s = SLH-DSA-SHA2-128s).
The versions are read from src/test/data/pq_address_vectors.json, the file every component shares, so a
test never hard-codes them.
"""
import json
import os

from .yellowback_model import base58check_decode, base58check_encode

VECTORS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            '..', '..', '..', 'src', 'test', 'data', 'pq_address_vectors.json')

SLH_DSA = 1
FN_DSA = 2


def load_vectors():
    with open(VECTORS_PATH, encoding='utf8') as f:
        doc = json.load(f)
    assert doc['format'] == 'ycash-pq-address-vectors-1', doc.get('format')
    return doc


def _versions():
    out = {}
    for v in load_vectors()['valid']:
        out[(v['network'], v['coin'], v['scheme'])] = bytes.fromhex(v['version'])
    return out


VERSIONS = _versions()   # (network, coin, scheme) -> 3-byte version


def pq_version(scheme, network='regtest', coin='yec'):
    return VERSIONS[(network, coin, scheme)]


def pq_prefix(scheme, network='regtest', coin='yec'):
    """The 3-character prefix, e.g. 'rqf' or 'yrs'."""
    return base58check_encode(pq_version(scheme, network, coin) + bytes(32))[:3]


def encode_pq_address(scheme, keyhash, network='regtest', coin='yec'):
    assert len(keyhash) == 32
    return base58check_encode(pq_version(scheme, network, coin) + keyhash)


def decode_pq_address(addr):
    """(network, coin, scheme, keyhash) of a D-9 address, or None."""
    raw = base58check_decode(addr)
    if raw is None or len(raw) != 35:
        return None
    for (network, coin, scheme), ver in VERSIONS.items():
        if raw[:3] == ver:
            return network, coin, scheme, raw[3:]
    return None


def encode_legacy_pq_address(scheme, keyhash, network='regtest', coin='yec'):
    """The pre-D-9 form (2-byte version || scheme || keyHash), which every node refuses: for negative tests."""
    ver = {('main', 'yec'): '4dd9', ('test', 'yec'): '4f61', ('regtest', 'yec'): '4c51',
           ('main', 'yed'): '56ab', ('test', 'yed'): '571e', ('regtest', 'yed'): '5710'}[(network, coin)]
    return base58check_encode(bytes.fromhex(ver) + bytes([scheme]) + keyhash)
