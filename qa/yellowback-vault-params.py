#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Extract and compare the Vault chain parameters of the two Yellowback node lines.

  yellowback-vault-params.py extract [--root DIR | --git-ref REF [--git-dir DIR]]
  yellowback-vault-params.py compare A.json B.json [--release main]

Both node lines must activate the vault upgrade with the same parameters (upgrade plan P8; audit
W3-P-1). The extractor reads every parameter from the constructor body of each network class (never
the first match in the file) and fails closed (exit 2) on any shape it does not expect. The testnet
has three compiled-in profiles (testnet plan Revision 3, T-14): each is a subclass of CTestNetParams,
read as the base constructor's body plus its own, where every parameter is assigned exactly once.
`compare --release main` applies release rules R1-R7 to A (the tag guard). Part D, raising
PROTOCOL_VERSION, is deferred; R3-R5 still refuse a tag until that bump. This file is
byte-identical on ycash-dd and ycash6. Python 3 standard library only.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys

FILES = ("src/chainparams.cpp", "src/consensus/params.h", "src/version.h", "src/yellowback/params.cpp")
NETWORKS = (("main", "CMainParams"), ("regtest", "CRegTestParams"))
TESTNET_BASE = "CTestNetParams"
TESTNET_PROFILES = (("fast", "CTestNetFastParams"), ("slow", "CTestNetSlowParams"), ("legacy", "CTestNetLegacyParams"))
# The YED columns: MainParams (main), TestParams (testnet-yb-slow; testnet-legacy, inert), TestFastParams.
YB_COLUMNS = ("MainParams", "TestParams", "TestFastParams")
VERSION_CONSTANTS = ("PROTOCOL_VERSION", "MIN_PEER_PROTO_VERSION", "MIN_TESTNET_PEER_PROTO_VERSION")
# MIN_PEER_PROTO_VERSION differs between the lines today (audit W3-P-1, part D): reported, not compared.
VERSION_COMPARED = ("PROTOCOL_VERSION",)
# Live peer floor (version.h PROTOCOL_VERSION on both lines). R3 requires the Vault epoch above it.
# Cited by audit W3-P-1. Do not bump PROTOCOL_VERSION here; P8 does, and the tag guard enforces it.
LIVE_NETWORK_PROTOCOL_VERSION = 270013
# R6. A release that deliberately names another height changes this constant in the same change.
EXPECTED_PQ_FALCON_HEIGHT = 0


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


def network_params(chainparams, params_h, cls, name, base=None):
    body = strip_comments(constructor_body(chainparams, cls))
    if base is not None:
        body = strip_comments(constructor_body(chainparams, base)) + "\n" + body
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
    out["test"] = {}
    for profile, cls in TESTNET_PROFILES:
        out["test"][profile] = network_params(chainparams, params_h, cls, "test " + profile, base=TESTNET_BASE)
    yb = {}
    for fn in YB_COLUMNS:
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


def _height_set(value):
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _attestor_set(value):
    return isinstance(value, str) and bool(value) and not set(value) <= set("0")


def release_problems(doc):
    """R1-R7 for a tag of this tree (audit W3-P-1 part C). A parse failure never reaches here."""
    problems = []
    main = doc.get("main", {})
    version = doc.get("version", {})
    yb = doc.get("yellowback_params", {})
    if not _height_set(main.get("vault_activation_height")):
        problems.append("R1: the mainnet UPGRADE_VAULT activation height is unset")
    if not _attestor_set(yb.get("main_attestor_set_id")):
        problems.append("R2: the mainnet YED attestor set (MainParams attestorSetId) is unset")
    vault_v = main.get("vault_protocol_version")
    if not isinstance(vault_v, int) or isinstance(vault_v, bool) or vault_v <= LIVE_NETWORK_PROTOCOL_VERSION:
        problems.append("R3: main.vault_protocol_version must be greater than %d" % LIVE_NETWORK_PROTOCOL_VERSION)
    proto = version.get("PROTOCOL_VERSION")
    if not isinstance(proto, int) or isinstance(proto, bool) or not isinstance(vault_v, int) or proto < vault_v:
        problems.append("R4: PROTOCOL_VERSION must be >= main.vault_protocol_version")
    floor = version.get("MIN_PEER_PROTO_VERSION")
    if not isinstance(floor, int) or isinstance(floor, bool) or floor > LIVE_NETWORK_PROTOCOL_VERSION:
        problems.append("R5: MIN_PEER_PROTO_VERSION must be <= %d" % LIVE_NETWORK_PROTOCOL_VERSION)
    falcon = main.get("pq_falcon_height")
    if falcon != EXPECTED_PQ_FALCON_HEIGHT:
        if falcon in (None, "NO_ACTIVATION_HEIGHT"):
            problems.append("R6: the mainnet pqFalconHeight is unset")
        else:
            problems.append("R6: main.pq_falcon_height must be %s (got %r)" % (EXPECTED_PQ_FALCON_HEIGHT, falcon))
    # R7 per testnet profile (testnet plan Revision 3): a Vault height comes with that network's YED set.
    test = doc.get("test", {})
    for profile, key in (("fast", "testfast_attestor_set_id"), ("slow", "test_attestor_set_id")):
        test_height = _height_set(test.get(profile, {}).get("vault_activation_height"))
        test_att = _attestor_set(yb.get(key))
        if test_height != test_att:
            problems.append("R7: testnet-yb-%s activation height and %s must both be set or both be unset" % (profile, key))
    if test.get("legacy", {}).get("vault_activation_height") != "NO_ACTIVATION_HEIGHT":
        problems.append("R7: testnet-legacy must never set an UPGRADE_VAULT activation height")
    return problems


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
    cp.add_argument("--release", choices=("main",), default=None)
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
        loaded_a, loaded_b = json.load(fa), json.load(fb)
    bad = compare(loaded_a, loaded_b)
    if args.release == "main":
        bad.extend(release_problems(loaded_a))
    for line in bad:
        print("DIFFERENT %s" % line)
    if bad:
        return 1
    print("Vault chain parameters identical on both lines")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
