#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Generate doc/vault-rpc-contract.json, the machine-readable contract of the vault primitive's
set_* / vault_* RPCs, from doc/vault-rpc.md (its "Contract notation", "Shapes", per-command
`Params:` / `Result:` lines and the "Error reasons" table).

    qa/vault-rpc-contract.py            write doc/vault-rpc-contract.json
    qa/vault-rpc-contract.py --check    fail if the committed JSON is stale, if a command
                                        registered in src/rpc/vault.cpp is not documented (or
                                        the reverse), if a command heading disagrees with its
                                        Params: line, or if ycash-cli's conversion table
                                        (src/rpc/client.cpp; on 6.20.0 src/rpc/common.h)
                                        disagrees with the parameter types

Standard library only (CI runs it with the system python3).
"""

import hashlib
import json
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
DOC = os.path.join(ROOT, 'doc', 'vault-rpc.md')
OUT = os.path.join(ROOT, 'doc', 'vault-rpc-contract.json')
RPC_SRC = os.path.join(ROOT, 'src', 'rpc', 'vault.cpp')
CLIENT_SRC = os.path.join(ROOT, 'src', 'rpc', 'client.cpp')
# 6.20.0 keeps ycash-cli's conversion table in src/rpc/common.h, one row per command:
# { "name", {{required...}, {optional...}} } with s (passed as a string) or o (parsed as JSON).
COMMON_SRC = os.path.join(ROOT, 'src', 'rpc', 'common.h')

# Types whose JSON form is a string: a parameter of one of these is passed as is by ycash-cli.
STRING_TYPES = {'str', 'hex', 'hash', 'key', 'pqkeyid', 'outpoint', 'address'}


class ContractError(Exception):
    pass


# ---- the type notation -------------------------------------------------------------------------

TOKEN = re.compile(r'\s*(?:(\.\.\.)|("(?:[^"\\]|\\.)*")|([A-Za-z_][A-Za-z0-9_]*)|([{}\[\]:,|?]))')


def tokenize(text):
    out, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise ContractError('cannot parse %r at %r' % (text, text[pos:pos + 20]))
        pos = m.end()
        if m.group(1):
            out.append(('spread', '...'))
        elif m.group(2):
            out.append(('str', json.loads(m.group(2))))
        elif m.group(3):
            out.append(('ident', m.group(3)))
        else:
            out.append(('punct', m.group(4)))
    return out


class Parser:
    def __init__(self, text, types, shapes):
        self.toks = tokenize(text)
        self.i = 0
        self.text = text
        self.types = types
        self.shapes = shapes        # name -> resolved type (only those defined so far)

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else (None, None)

    def take(self, kind=None, value=None):
        tok = self.peek()
        if tok[0] is None or (kind and tok[0] != kind) or (value is not None and tok[1] != value):
            raise ContractError('expected %s in %r, got %r' % (value or kind, self.text, tok[1]))
        self.i += 1
        return tok

    def done(self):
        if self.i != len(self.toks):
            raise ContractError('trailing input in %r: %r' % (self.text, self.toks[self.i:]))

    def union(self):
        alts = [self.primary()]
        while self.peek() == ('punct', '|'):
            self.take()
            alts.append(self.primary())
        if len(alts) == 1:
            return alts[0]
        flat = []
        for a in alts:
            flat.extend(a['oneOf'] if 'oneOf' in a else [a])
        return {'oneOf': flat}

    def primary(self):
        kind, val = self.peek()
        if kind == 'str':
            self.take()
            return {'const': val}
        if kind == 'ident':
            self.take()
            if val == 'null':
                return {'type': 'null'}
            if val in self.types:
                return {'type': val}
            if val in self.shapes:
                return {'ref': val}
            raise ContractError('unknown type or shape %r in %r' % (val, self.text))
        if (kind, val) == ('punct', '['):
            self.take()
            items = self.union()
            self.take('punct', ']')
            return {'type': 'array', 'items': items}
        if (kind, val) == ('punct', '{'):
            return self.obj()
        raise ContractError('unexpected %r in %r' % (val, self.text))

    def object_alternatives(self, name):
        """A shape spread into an object: its object alternatives (a union of objects multiplies)."""
        t = self.shapes.get(name)
        if t is None:
            raise ContractError('unknown shape %r spread in %r' % (name, self.text))
        alts = t['oneOf'] if 'oneOf' in t else [t]
        for a in alts:
            if a.get('type') != 'object':
                raise ContractError('shape %r is not an object (or a choice of objects)' % name)
        return alts

    def obj(self):
        self.take('punct', '{')
        alts = [({}, [])]          # (fields, optional) per alternative
        first = True
        while self.peek() != ('punct', '}'):
            if not first:
                self.take('punct', ',')
            first = False
            if self.peek()[0] == 'spread':
                self.take()
                name = self.take('ident')[1]
                new = []
                for fields, optional in alts:
                    for s in self.object_alternatives(name):
                        f = dict(fields)
                        for k, v in s['fields'].items():
                            if k in f:
                                raise ContractError('field %r twice in %r' % (k, self.text))
                            f[k] = v
                        new.append((f, optional + s['optional']))
                alts = new
                continue
            key = self.take('str')[1]
            opt = False
            if self.peek() == ('punct', '?'):
                self.take()
                opt = True
            self.take('punct', ':')
            t = self.union()
            for fields, optional in alts:
                if key in fields:
                    raise ContractError('field %r twice in %r' % (key, self.text))
                fields[key] = t
                if opt:
                    optional.append(key)
        self.take('punct', '}')
        objs = [{'type': 'object', 'fields': f, 'optional': sorted(o)} for f, o in alts]
        return objs[0] if len(objs) == 1 else {'oneOf': objs}

    def params(self):
        self.take('punct', '[')
        out = []
        while self.peek() != ('punct', ']'):
            if out:
                self.take('punct', ',')
            name = self.take('str')[1]
            required = True
            if self.peek() == ('punct', '?'):
                self.take()
                required = False
            self.take('punct', ':')
            out.append({'name': name, 'required': required, 'type': self.union()})
        self.take('punct', ']')
        for a, b in zip(out, out[1:]):
            if not a['required'] and b['required']:
                raise ContractError('a required parameter follows an optional one in %r' % self.text)
        return out


def parse(text, types, shapes, what='union'):
    p = Parser(text, types, shapes)
    r = p.params() if what == 'params' else p.union()
    p.done()
    return r


# ---- the document ------------------------------------------------------------------------------

def table_rows(lines, start):
    """The rows of the Markdown table that begins at or after line `start`."""
    i = start
    while i < len(lines) and not lines[i].startswith('|'):
        i += 1
    rows = []
    i += 2  # header + separator
    while i < len(lines) and lines[i].startswith('|'):
        rows.append([c.strip() for c in lines[i].strip().strip('|').split('|')])
        i += 1
    return rows


def unquote(cell):
    return cell[1:-1] if cell.startswith('`') and cell.endswith('`') else cell


def heading_args(sig):
    """`name a "b" ( c )` -> [(token, optional)] at bracket depth 0."""
    toks, depth, cur, opt = [], 0, '', False
    for ch in sig:
        if ch in '{[':
            depth += 1
        elif ch in '}]':
            depth -= 1
        if depth == 0 and ch in ' ()':
            if cur:
                toks.append((cur, opt))
                cur = ''
            if ch == '(':
                opt = True
            elif ch == ')':
                opt = False
            continue
        cur += ch
    if cur:
        toks.append((cur, opt))
    return toks


def build():
    with open(DOC, encoding='utf-8') as f:
        text = f.read()
    lines = text.split('\n')

    def section_line(title):
        for i, l in enumerate(lines):
            if l.strip() == title:
                return i
        raise ContractError('%s: no section %r' % (DOC, title))

    types = {}
    for row in table_rows(lines, section_line('## Contract notation')):
        types[unquote(row[0])] = {'json': row[1], 'meaning': row[2]}
    for t in ('str', 'hex', 'hash', 'key', 'pqkeyid', 'outpoint', 'int', 'height', 'bool', 'yec', 'zat'):
        if t not in types:
            raise ContractError('the notation table lacks type %r' % t)

    shapes = {}
    shape_re = re.compile(r'^- `([A-Za-z]+)` = `(.*)`$')
    for l in lines[section_line('### Shapes'):]:
        if l.startswith('## '):
            break
        m = shape_re.match(l)
        if m:
            if m.group(1) in shapes:
                raise ContractError('shape %r twice' % m.group(1))
            shapes[m.group(1)] = parse(m.group(2), types, shapes)

    methods = {}
    section = None
    head_re = re.compile(r'^### `((?:set|vault)_[a-z]+)(.*)`$')
    i = 0
    while i < len(lines):
        l = lines[i]
        if l.startswith('## '):
            section = l[3:].strip()
        m = head_re.match(l)
        if m:
            name, sig = m.group(1), m.group(2).strip()
            params = result = None
            j = i + 1
            while j < len(lines) and not lines[j].startswith('#'):
                pm = re.match(r'^Params: `(.*)`$', lines[j])
                rm = re.match(r'^Result: `(.*)`$', lines[j])
                if pm:
                    params = parse(pm.group(1), types, shapes, 'params')
                if rm:
                    result = parse(rm.group(1), types, shapes)
                j += 1
            if params is None or result is None:
                raise ContractError('%s: needs a Params: and a Result: line' % name)
            if name in methods:
                raise ContractError('%s documented twice' % name)
            check_heading(name, sig, params)
            methods[name] = {
                'wallet': section != 'Read RPCs (no wallet needed)',
                'signature': (name + ' ' + sig).strip(),
                'params': params,
                'result': result,
            }
            i = j
            continue
        i += 1

    errors = []
    for row in table_rows(lines, section_line('## Error reasons')):
        raised = [unquote(c.strip()) for c in row[2].split(',')]
        errors.append({'code': int(row[0]), 'message': unquote(row[1]), 'raisedBy': raised, 'provokedBy': row[3]})
        for r in raised:
            if r != 'every act and vault RPC' and r not in methods:
                raise ContractError('error %r is raised by an undocumented command %r' % (row[1], r))

    return {
        'contract': 'vault-rpc',
        'source': {'file': 'doc/vault-rpc.md', 'sha256': hashlib.sha256(text.encode('utf-8')).hexdigest()},
        'branchid': '6d5b7a31',
        'units': {
            'yec': 'amounts in RPC answers and parameters are YEC as a decimal JSON number (8 places), as in every '
                   'Ycash RPC, including the set rate fields and bondmin that the set state stores in zatoshi',
            'zat': 'fields named *zat are integer zatoshi (1 YEC = 100000000 zatoshi)',
        },
        'types': types,
        'shapes': shapes,
        'methods': methods,
        'errors': errors,
    }


def check_heading(name, sig, params):
    args = heading_args(sig)
    if len(args) != len(params):
        raise ContractError('%s: the heading has %d arguments, Params: %d' % (name, len(args), len(params)))
    for (tok, opt), p in zip(args, params):
        if opt == p['required']:
            raise ContractError('%s: %s is %s in the heading but not in Params:' % (name, p['name'], 'optional' if opt else 'required'))
        plain = tok.strip('"')
        if re.fullmatch(r'[a-z]+', plain) and plain != p['name']:
            raise ContractError('%s: heading argument %r is %r in Params:' % (name, plain, p['name']))


def is_string_param(t):
    if 'const' in t:
        return True
    if 'oneOf' in t:
        return all(is_string_param(a) for a in t['oneOf'])
    return t.get('type') in STRING_TYPES


def check_sources(contract):
    problems = []
    with open(RPC_SRC, encoding='utf-8') as f:
        registered = set(re.findall(r'\{\s*"vault",\s*"([a-z_]+)"', f.read()))
    documented = set(contract['methods'])
    for m in sorted(registered - documented):
        problems.append('%s is registered in src/rpc/vault.cpp but not documented in doc/vault-rpc.md' % m)
    for m in sorted(documented - registered):
        problems.append('%s is documented but not registered in src/rpc/vault.cpp' % m)
    with open(CLIENT_SRC, encoding='utf-8') as f:
        conv = set((m, int(n)) for m, n in re.findall(r'\{\s*"((?:set|vault)_[a-z]+)",\s*(\d+)\s*\}', f.read()))
    if os.path.exists(COMMON_SRC):
        with open(COMMON_SRC, encoding='utf-8') as f:
            for m, req, opt in re.findall(r'\{\s*"((?:set|vault)_[a-z]+)",\s*\{\{([^}]*)\},\s*\{([^}]*)\}\}\s*\}', f.read()):
                kinds = [k.strip() for k in (req.split(',') + opt.split(',')) if k.strip()]
                conv.update((m, i) for i, k in enumerate(kinds) if k == 'o')
    shapes = contract['shapes']
    for name, m in contract['methods'].items():
        for idx, p in enumerate(m['params']):
            t = p['type']
            while 'ref' in t:
                t = shapes[t['ref']]
            want = not is_string_param(t)
            if want and (name, idx) not in conv:
                problems.append('src/rpc/client.cpp lacks { "%s", %d } (%s is not a string)' % (name, idx, p['name']))
            if not want and (name, idx) in conv:
                problems.append('src/rpc/client.cpp converts { "%s", %d } but %s is a string' % (name, idx, p['name']))
    for name, idx in sorted(conv):
        if name not in contract['methods'] or idx >= len(contract['methods'][name]['params']):
            problems.append('src/rpc/client.cpp converts { "%s", %d }, which the contract does not have' % (name, idx))
    return problems


def render(contract):
    return json.dumps(contract, indent=2, sort_keys=False, ensure_ascii=False) + '\n'


def main(argv):
    try:
        contract = build()
    except ContractError as e:
        print('vault-rpc-contract: %s' % e, file=sys.stderr)
        return 1
    out = render(contract)
    if '--check' in argv:
        problems = check_sources(contract)
        try:
            with open(OUT, encoding='utf-8') as f:
                if f.read() != out:
                    problems.append('doc/vault-rpc-contract.json is stale: run qa/vault-rpc-contract.py')
        except FileNotFoundError:
            problems.append('doc/vault-rpc-contract.json is missing: run qa/vault-rpc-contract.py')
        for p in problems:
            print('vault-rpc-contract: %s' % p, file=sys.stderr)
        if not problems:
            print('vault-rpc-contract: %d commands, %d shapes, %d error reasons: OK'
                  % (len(contract['methods']), len(contract['shapes']), len(contract['errors'])))
        return 1 if problems else 0
    with open(OUT, 'w', encoding='utf-8') as f:
        f.write(out)
    print('wrote %s (%d commands)' % (os.path.relpath(OUT), len(contract['methods'])))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
