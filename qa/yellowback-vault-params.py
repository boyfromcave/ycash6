#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Extract and compare the Vault chain parameters of the two Yellowback node lines.

  yellowback-vault-params.py extract [--root DIR | --git-ref REF [--git-dir DIR]]
  yellowback-vault-params.py compare A.json B.json

Both node lines must activate the vault upgrade with the same parameters (upgrade plan P8; audit
W3-P-1). The extractor reads every parameter from the constructor body of each network class (never
the first match in the file) and fails closed (exit 2) on any shape it does not expect. This file is
byte-identical on ycash-dd and ycash6. Python 3 standard library only.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys

FILES = ("src/chainparams.cpp", "src/consensus/params.h", "src/version.h", "src/yellowback/params.cpp")
NETWORKS = (("main", "CMainParams"), ("test", "CTestNetParams"), ("regtest", "CRegTestParams"))
VERSION_CONSTANTS = ("PROTOCOL_VERSION", "MIN_PEER_PROTO_VERSION", "MIN_TESTNET_PEER_PROTO_VERSION")
# MIN_PEER_PROTO_VERSION differs between the lines today (audit W3-P-1, part D): reported, not compared.
VERSION_COMPARED = ("PROTOCOL_VERSION",)


class ParseError(Exception):
    pass


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def one(pattern, text, what):
    found = re.findall(pattern, text, flags=re.S)
    if len(found) != 1:
        raise ParseError("%s: expected exactly one match, found %d" % (what, len(found)))
    return found[0]


def optional(pattern, text, what):
    found = re.findall(pattern, text, flags=re.S)
    if len(found) > 1:
        raise ParseError("%s: expected at most one match, found %d" % (what, len(found)))
    return found[0] if found else None


def number(token):
    return int(token, 0)


def height(token):
    if token.split("::")[-1] == "NO_ACTIVATION_HEIGHT":
        return "NO_ACTIVATION_HEIGHT"
    return number(token)


def constructor_body(chainparams, cls):
    m = re.search(r"^    %s\(\) \{\n(.*?)^    \}$" % cls, chainparams, flags=re.S | re.M)
    if not m:
        raise ParseError("src/chainparams.cpp: constructor of %s not found" % cls)
    return m.group(1)


def brace_body(text, signature):
    start = text.find(signature)
    if start < 0:
        raise ParseError("src/yellowback/params.cpp: %s not found" % signature)
    open_at = text.index("{", start)
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_at:i + 1]
    raise ParseError("src/yellowback/params.cpp: unbalanced braces in %s" % signature)


def network_params(chainparams, params_h, cls, name):
    body = strip_comments(constructor_body(chainparams, cls))
    where = "%s (%s)" % (cls, name)
    vault = r"vUpgrades\[Consensus::UPGRADE_VAULT\]\.%s\s*=\s*([^;]+?)\s*;"
    falcon = optional(r"\bconsensus\.pqFalconHeight\s*=\s*([^;]+?)\s*;", body, where + " pqFalconHeight")
    maturity = optional(r"\bconsensus\.nVaultMinSetMaturity\s*=\s*([^;]+?)\s*;", body, where + " nVaultMinSetMaturity")
    if falcon is None:
        falcon = one(r"\bint\s+pqFalconHeight\s*=\s*([^;]+?)\s*;", params_h, "src/consensus/params.h pqFalconHeight")
    if maturity is None:
        maturity = one(r"\buint32_t\s+nVaultMinSetMaturity\s*=\s*([^;]+?)\s*;", params_h,
                       "src/consensus/params.h nVaultMinSetMaturity")
    return {
        "vault_protocol_version": number(one(vault % "nProtocolVersion", body, where + " nProtocolVersion")),
        "vault_activation_height": height(one(vault % "nActivationHeight", body, where + " nActivationHeight")),
        "pq_falcon_height": height(falcon),
        "vault_min_set_maturity": number(maturity),
    }


def extract(read):
    chainparams = read("src/chainparams.cpp")
    params_h = strip_comments(read("src/consensus/params.h"))
    version_h = strip_comments(read("src/version.h"))
    params_cpp = strip_comments(read("src/yellowback/params.cpp"))
    out = {"version": {}}
    for const in VERSION_CONSTANTS:
        tok = optional(r"static const int %s\s*=\s*([^;]+?)\s*;" % const, version_h, "src/version.h " + const)
        out["version"][const] = None if tok is None else number(tok)
    for name, cls in NETWORKS:
        out[name] = network_params(chainparams, params_h, cls, name)
    yb = {}
    for fn in ("MainParams", "TestParams"):
        body = brace_body(params_cpp, "const Params& %s()" % fn)
        yb[fn] = hashlib.sha256(re.sub(r"\s+", "", body).encode()).hexdigest()
        att = optional(r'attestorSetId\s*=\s*uint256S\(\s*"([0-9a-fA-F]+)"\s*\)', body, fn + " attestorSetId")
        yb[fn.replace("Params", "").lower() + "_attestor_set_id"] = att
    out["yellowback_params"] = yb
    return out


def flatten(d, prefix=""):
    for k, v in d.items():
        if isinstance(v, dict):
            yield from flatten(v, prefix + k + ".")
        else:
            yield prefix + k, v


def compare(a, b):
    fa, fb = dict(flatten(a)), dict(flatten(b))
    bad = []
    for key in sorted(set(fa) | set(fb)):
        if key.startswith("version.") and key[len("version."):] not in VERSION_COMPARED:
            continue
        if fa.get(key) != fb.get(key):
            bad.append("%s: %r != %r" % (key, fa.get(key), fb.get(key)))
    return bad


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    ex = sub.add_parser("extract")
    ex.add_argument("--root", default=None)
    ex.add_argument("--git-ref", default=None)
    ex.add_argument("--git-dir", default=".")
    cp = sub.add_parser("compare")
    cp.add_argument("a")
    cp.add_argument("b")
    args = ap.parse_args(argv)

    if args.cmd == "extract":
        if args.git_ref:
            def read(path):
                return subprocess.run(["git", "-C", args.git_dir, "show", "%s:%s" % (args.git_ref, path)],
                                      check=True, capture_output=True, text=True).stdout
        else:
            root = args.root or "."

            def read(path):
                with open("%s/%s" % (root, path), encoding="utf-8") as f:
                    return f.read()
        try:
            result = extract(read)
        except (ParseError, OSError, subprocess.CalledProcessError, ValueError) as e:
            print("yellowback-vault-params: %s" % e, file=sys.stderr)
            return 2
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    with open(args.a, encoding="utf-8") as fa, open(args.b, encoding="utf-8") as fb:
        bad = compare(json.load(fa), json.load(fb))
    for line in bad:
        print("DIFFERENT %s" % line)
    if bad:
        return 1
    print("Vault chain parameters identical on both lines")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
