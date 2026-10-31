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
has three compiled-in profiles (testnet plan Revision 3, T-14). testnet-yb-fast is a subclass of
CTestNetParams, read as the base constructor's body plus its own, where every parameter is assigned
exactly once. testnet-yb-slow and testnet-legacy are shadow forks of mainnet
(docs/plans/yellowback-testnet-shadow-fork-plan.md): subclasses of CTestNetShadowParams, itself a
subclass of CMainParams, read as the three constructor bodies in construction order, where each body
assigns a parameter at most once and a later body overrides an earlier one (C++ constructor order:
mainnet's values, then the testnet's). Their split height H_S (TESTNET_SHADOW_SPLIT_HEIGHT) and every
network's Vault and shadow branch IDs (NetworkUpgradeInfo, or a network's own nBranchId) are read too.
`compare --release main` applies release rules R1-R8 to A (the tag guard). Part D, raising
PROTOCOL_VERSION, is deferred; R3-R5 still refuse a tag until that bump. This file is
byte-identical on ycash-dd and ycash6. Python 3 standard library only.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys

FILES = ("src/chainparams.cpp", "src/consensus/params.h", "src/version.h", "src/yellowback/params.cpp",
         "src/consensus/upgrades.h", "src/consensus/upgrades.cpp")
NETWORKS = (("main", "CMainParams"), ("regtest", "CRegTestParams"))
TESTNET_BASE = "CTestNetParams"
# The testnet shadow fork: slow and legacy are CMainParams, then CTestNetShadowParams, then their own body.
SHADOW_CHAIN = ("CMainParams", "CTestNetShadowParams")
TESTNET_PROFILES = (("fast", "CTestNetFastParams"), ("slow", "CTestNetSlowParams"), ("legacy", "CTestNetLegacyParams"))
SHADOW_PROFILES = ("slow", "legacy")
SHADOW_SPLIT_CONSTANT = "TESTNET_SHADOW_SPLIT_HEIGHT"
PROFILE_NAMES = {"fast": "testnet-yb-fast", "slow": "testnet-yb-slow", "legacy": "testnet-legacy"}
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


def branch_id(token, upgrades_h, what):
    """A branch ID token: a hex literal, or a constant defined in src/consensus/upgrades.h."""
    token = token.strip()
    if re.fullmatch(r"0x[0-9a-fA-F]{1,8}", token):
        return "%08x" % int(token, 16)
    if re.fullmatch(r"[A-Z][A-Z0-9_]*", token):
        value = one(r"static const uint32_t %s\s*=\s*(0x[0-9a-fA-F]{1,8})\s*;" % token, upgrades_h,
                    "src/consensus/upgrades.h " + token)
        return "%08x" % int(value, 16)
    raise ParseError("%s: unexpected branch ID %r" % (what, token))


def table_branch_id(upgrades_cpp, upgrades_h, name):
    """NetworkUpgradeInfo's branch ID for the upgrade named `name` (its .strName)."""
    tok = one(r"\.nBranchId\s*=\s*([^,]+?)\s*,\s*\.strName\s*=\s*\"%s\"" % re.escape(name), upgrades_cpp,
              "src/consensus/upgrades.cpp NetworkUpgradeInfo %s" % name)
    return branch_id(tok, upgrades_h, "NetworkUpgradeInfo " + name)


def network_params(chainparams, params_h, cls, name, base=None, chain=None, upgrades=None):
    """One network's Vault parameters. `base`: one extra body, each parameter assigned once across both.
    `chain`: bodies in construction order, each assigning a parameter at most once, the last one wins."""
    where = "%s (%s)" % (cls, name)
    if chain is not None:
        bodies = [strip_comments(constructor_body(chainparams, c)) for c in tuple(chain) + (cls,)]

        def find(pattern, what, required):
            found = None
            for b in bodies:
                v = optional(pattern, b, what)
                if v is not None:
                    found = v
            if found is None and required:
                raise ParseError("%s: expected a match, found none" % what)
            return found
    else:
        body = strip_comments(constructor_body(chainparams, cls))
        if base is not None:
            body = strip_comments(constructor_body(chainparams, base)) + "\n" + body

        def find(pattern, what, required):
            return one(pattern, body, what) if required else optional(pattern, body, what)
    vault = r"vUpgrades\[Consensus::UPGRADE_VAULT\]\.%s\s*=\s*([^;]+?)\s*;"
    falcon = find(r"\bconsensus\.pqFalconHeight\s*=\s*([^;]+?)\s*;", where + " pqFalconHeight", False)
    maturity = find(r"\bconsensus\.nVaultMinSetMaturity\s*=\s*([^;]+?)\s*;", where + " nVaultMinSetMaturity", False)
    if falcon is None:
        falcon = one(r"\bint\s+pqFalconHeight\s*=\s*([^;]+?)\s*;", params_h, "src/consensus/params.h pqFalconHeight")
    if maturity is None:
        maturity = one(r"\buint32_t\s+nVaultMinSetMaturity\s*=\s*([^;]+?)\s*;", params_h,
                       "src/consensus/params.h nVaultMinSetMaturity")
    out = {
        "vault_protocol_version": number(find(vault % "nProtocolVersion", where + " nProtocolVersion", True)),
        "vault_activation_height": height(find(vault % "nActivationHeight", where + " nActivationHeight", True)),
        "pq_falcon_height": height(falcon),
        "vault_min_set_maturity": number(maturity),
    }
    if upgrades is not None:
        upgrades_h, upgrades_cpp = upgrades
        own = find(vault % "nBranchId", where + " Vault nBranchId", False)
        out["vault_branch_id"] = (branch_id(own, upgrades_h, where + " Vault nBranchId") if own is not None
                                  else table_branch_id(upgrades_cpp, upgrades_h, "Vault"))
        if chain is not None:
            shadow = r"vUpgrades\[Consensus::UPGRADE_SHADOW\]\.nBranchId\s*=\s*([^;]+?)\s*;"
            own = find(shadow, where + " Shadow nBranchId", False)
            out["shadow_branch_id"] = (branch_id(own, upgrades_h, where + " Shadow nBranchId") if own is not None
                                       else table_branch_id(upgrades_cpp, upgrades_h, "Shadow"))
            split = find(r"\bSetShadowSplitHeight\(\s*([^)]+?)\s*\)\s*;", where + " SetShadowSplitHeight", True)
            if split == SHADOW_SPLIT_CONSTANT:
                split = one(r"static const int %s\s*=\s*([^;]+?)\s*;" % SHADOW_SPLIT_CONSTANT,
                            strip_comments(chainparams), "src/chainparams.cpp " + SHADOW_SPLIT_CONSTANT)
            out["shadow_split_height"] = height(split)
    return out


def extract(read):
    chainparams = read("src/chainparams.cpp")
    params_h = strip_comments(read("src/consensus/params.h"))
    version_h = strip_comments(read("src/version.h"))
    params_cpp = strip_comments(read("src/yellowback/params.cpp"))
    upgrades = (strip_comments(read("src/consensus/upgrades.h")), strip_comments(read("src/consensus/upgrades.cpp")))
    out = {"version": {}}
    for const in VERSION_CONSTANTS:
        tok = optional(r"static const int %s\s*=\s*([^;]+?)\s*;" % const, version_h, "src/version.h " + const)
        out["version"][const] = None if tok is None else number(tok)
    for name, cls in NETWORKS:
        out[name] = network_params(chainparams, params_h, cls, name, upgrades=upgrades)
    out["test"] = {}
    for profile, cls in TESTNET_PROFILES:
        if profile in SHADOW_PROFILES:
            out["test"][profile] = network_params(chainparams, params_h, cls, "test " + profile,
                                                  chain=SHADOW_CHAIN, upgrades=upgrades)
        else:
            out["test"][profile] = network_params(chainparams, params_h, cls, "test " + profile, base=TESTNET_BASE,
                                                  upgrades=upgrades)
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
    """R1-R8 for a tag of this tree (audit W3-P-1 part C). A parse failure never reaches here."""
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
    # R8 (docs/plans/yellowback-testnet-shadow-fork-plan.md): slow and legacy are shadow forks of mainnet.
    # A tag ships them only with their split height H_S set, and only under branch IDs of their own after
    # it: distinct from each other and from mainnet's, slow's Vault included.
    main_vault = main.get("vault_branch_id")
    shadow_ids = {}
    for profile in SHADOW_PROFILES:
        net = test.get(profile, {})
        label = PROFILE_NAMES[profile]
        if not _height_set(net.get("shadow_split_height")):
            problems.append("R8: %s shadow fork not ready: the split height H_S (%s) is unset"
                            % (label, SHADOW_SPLIT_CONSTANT))
        sid = net.get("shadow_branch_id")
        if not isinstance(sid, str) or sid in (main_vault, None):
            problems.append("R8: %s must sign after H_S under a branch ID of its own" % label)
        shadow_ids[profile] = sid
    if shadow_ids.get("slow") is not None and shadow_ids.get("slow") == shadow_ids.get("legacy"):
        problems.append("R8: testnet-yb-slow and testnet-legacy must not share a shadow branch ID")
    slow_vault = test.get("slow", {}).get("vault_branch_id")
    if not isinstance(slow_vault, str) or slow_vault == main_vault or slow_vault in shadow_ids.values():
        problems.append("R8: testnet-yb-slow must activate Vault under a branch ID of its own, not mainnet's")
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
