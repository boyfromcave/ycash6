# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Live checks against doc/vault-rpc-contract.json (generated from doc/vault-rpc.md by
qa/vault-rpc-contract.py): a result matches its command's documented shape exactly (every
documented field present unless marked optional, nothing undocumented, each value of its
documented type), and an error carries a documented code and message.
"""

import os
import re
from decimal import Decimal

from test_framework.authproxy import JSONRPCException

CONTRACT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'doc', 'vault-rpc-contract.json')

HEX = re.compile(r'^(?:[0-9a-f]{2})*$')
HASH = re.compile(r'^[0-9a-f]{64}$')
KEY = re.compile(r'^0[23][0-9a-f]{64}$')
OUTPOINT = re.compile(r'^[0-9a-f]{64}:[0-9]+$')


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


SCALARS = {
    'str': lambda v: isinstance(v, str),
    'hex': lambda v: isinstance(v, str) and bool(HEX.match(v)),
    'hash': lambda v: isinstance(v, str) and bool(HASH.match(v)),
    'key': lambda v: isinstance(v, str) and bool(KEY.match(v)),
    'outpoint': lambda v: isinstance(v, str) and bool(OUTPOINT.match(v)),
    'address': lambda v: isinstance(v, str) and len(v) > 0,
    'int': _is_int,
    'height': _is_int,
    'bool': lambda v: isinstance(v, bool),
    # authproxy decodes JSON numbers with a fraction as Decimal; an integral amount may arrive as int.
    'yec': lambda v: (isinstance(v, Decimal) and v == v.quantize(Decimal('0.00000001'))) or _is_int(v),
    'zat': _is_int,
    'any': lambda v: True,
    'null': lambda v: v is None,
}


class Contract:
    def __init__(self, path=CONTRACT_PATH):
        import json
        with open(path, encoding='utf-8') as f:
            self.doc = json.load(f)
        self.methods = self.doc['methods']
        self.shapes = self.doc['shapes']
        self.checked = set()
        self.provoked = set()

    def mismatch(self, value, t, path):
        """None when `value` matches type `t`, else a description of the first mismatch."""
        if 'ref' in t:
            return self.mismatch(value, self.shapes[t['ref']], path)
        if 'const' in t:
            return None if value == t['const'] else '%s: %r is not %r' % (path, value, t['const'])
        if 'oneOf' in t:
            whys = []
            for alt in t['oneOf']:
                why = self.mismatch(value, alt, path)
                if why is None:
                    return None
                whys.append(why)
            return '%s matches no alternative: %s' % (path, '; '.join(sorted(set(whys))[:4]))
        kind = t['type']
        if kind == 'array':
            if not isinstance(value, list):
                return '%s: not an array' % path
            for i, v in enumerate(value):
                why = self.mismatch(v, t['items'], '%s[%d]' % (path, i))
                if why:
                    return why
            return None
        if kind == 'object':
            if not isinstance(value, dict):
                return '%s: not an object' % path
            extra = set(value) - set(t['fields'])
            if extra:
                return '%s: undocumented fields %s' % (path, sorted(extra))
            for k, ft in t['fields'].items():
                if k not in value:
                    if k in t['optional']:
                        continue
                    return '%s: documented field %r is absent' % (path, k)
                why = self.mismatch(value[k], ft, '%s.%s' % (path, k))
                if why:
                    return why
            return None
        if not SCALARS[kind](value):
            return '%s: %r is not %s' % (path, value, kind)
        return None

    def check(self, method, result):
        """Assert that `result` is what the contract says `method` returns; returns the result."""
        assert method in self.methods, '%s is not in the contract' % method
        why = self.mismatch(result, self.methods[method]['result'], method)
        assert why is None, why
        self.checked.add(method)
        return result

    def call(self, node, method, *args):
        return self.check(method, getattr(node, method)(*args))

    def error(self, message, node, method, *args):
        """Call `method` expecting the documented error whose message contains `message`."""
        rows = [e for e in self.doc['errors'] if e['message'] == message]
        assert rows, 'error %r is not in the contract' % message
        row = rows[0]
        assert method in row['raisedBy'] or row['raisedBy'] == ['every act and vault RPC'], \
            '%s is not documented as raising %r' % (method, message)
        try:
            getattr(node, method)(*args)
        except JSONRPCException as e:
            assert message in e.error['message'], 'expected %r in %r' % (message, e.error['message'])
            assert e.error['code'] == row['code'], '%s: code %d, documented %d' % (message, e.error['code'], row['code'])
            self.provoked.add(message)
            return e.error['message']
        raise AssertionError('%s did not fail with %r' % (method, message))

    def assert_complete(self):
        """Every documented command answered and every documented error provoked."""
        missing = sorted(set(self.methods) - self.checked)
        assert not missing, 'commands never checked against the contract: %s' % missing
        unprovoked = sorted(set(e['message'] for e in self.doc['errors']) - self.provoked)
        assert not unprovoked, 'documented errors never provoked: %s' % unprovoked
