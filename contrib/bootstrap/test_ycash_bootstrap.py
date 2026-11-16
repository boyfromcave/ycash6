# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Unit tests of ycash-bootstrap (offline; standard library only).

    python3 -m unittest contrib/bootstrap/test_ycash_bootstrap.py

Synthetic blocks (a header, a solution, a payload; the hash chain is real) are packed into the
ycash-prefix/1 layout and restored through every check, including a stand-in ycashd/ycash-cli
pair that imports the framed files the way -loadblock reads them. The published
testnet-prefix-v1 SHA256SUMS and manifest.json (testdata/, copied from the ycash-infra release)
are checked against the three testnet profiles' pins. The real import runs in CI:
qa/rpc-tests/ycash_bootstrap.py and qa/rpc-tests/testnet_ceremony.py.
"""

import argparse
import contextlib
import gzip
import copy
import hashlib
import http.server
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import struct
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "ycash-bootstrap")
TESTDATA = os.path.join(HERE, "testdata", "testnet-prefix-v1")


def _load():
    loader = importlib.machinery.SourceFileLoader("ycash_bootstrap", TOOL)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


yb = _load()
ybprofile = yb._profiles_module()


def make_chain(count, salt=b""):
    """count linked synthetic blocks: (hash, bytes)."""
    chain, prev = [], "00" * 32
    for height in range(count):
        header = struct.pack("<i", 4) + bytes.fromhex(prev)[::-1] + hashlib.sha256(b"m%d" % height + salt).digest() + b"\0" * 32 \
            + struct.pack("<II", 1_600_000_000 + height, 0x200f0f0f) + hashlib.sha256(b"n%d" % height).digest()
        block = header + bytes([16]) + b"s" * 16 + b"\x01" + b"payload-%06d" % height
        h = yb.block_hash(block)
        chain.append((h, block))
        prev = h
    return chain


def test_profile(chain, **prefix):
    profile = copy.deepcopy(ybprofile.load("regtest"))
    profile["node"]["genesis"] = chain[0][0]
    profile["prefix"].update(prefix)
    return profile


def write(out, profile, chain):
    os.makedirs(out, exist_ok=True)
    return yb.write_bundle(out, profile, len(chain) - 1, lambda h: chain[h], {"test": "synthetic"})


def args_for(**kw):
    ns = dict(allow_unpinned=False, require_signature=False, key=yb.DEFAULT_KEY, minisign="minisign")
    ns.update(kw)
    return type("Args", (), ns)()


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def read_text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def read_framed(path):
    with open(path, "rb") as f:
        data = f.read()
    records, i = [], 0
    while i < len(data):
        magic, (n,) = data[i:i + 4], struct.unpack_from("<I", data, i + 4)
        records.append((magic, data[i + 8:i + 8 + n]))
        i += 8 + n
    return records


class Quiet(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ycash-bootstrap-test-")
        self._out = contextlib.redirect_stdout(io.StringIO())
        self._out.__enter__()

    def tearDown(self):
        self._out.__exit__(None, None, None)
        shutil.rmtree(self.tmp, ignore_errors=True)


class FormatTest(Quiet):
    def test_round_trip_frames_with_the_magic(self):
        chain = make_chain(7)
        profile = test_profile(chain)
        write(os.path.join(self.tmp, "b"), profile, chain)
        _, expect, files, record = yb.verify_bundle(yb.Source(os.path.join(self.tmp, "b")), profile, os.path.join(self.tmp, "w"), args_for())
        records = [r for f in files for r in read_framed(f)]
        self.assertEqual([b for _, b in records], [b for _, b in chain])
        self.assertTrue(all(m == bytes.fromhex("aae83f5f") for m, _ in records))
        self.assertEqual(record["tip"], chain[-1][0])
        self.assertEqual(sorted(expect), [0, 6])
        self.assertFalse(record["signed"])

    def test_chunk_rule(self):
        self.assertEqual(yb.chunk_ranges(510247)[-1], (500000, 510247))
        self.assertEqual(len(yb.chunk_ranges(510247)), 11)
        self.assertEqual(yb.chunk_ranges(4799), [(0, 4799)])
        self.assertEqual(yb.hash_heights(20001), [0, 10000, 20000, 20001])

    def test_published_testnet_prefix_matches_every_testnet_profile(self):
        """testdata/ is the testnet-prefix-v1 release's SHA256SUMS and manifest.json."""
        sums_sha = yb.sha256_file(os.path.join(TESTDATA, "SHA256SUMS"))[0]
        with open(os.path.join(TESTDATA, "SHA256SUMS")) as f:
            sums = yb.parse_sums(f.read(), "zcash-testnet-prefix-v1")
        with open(os.path.join(TESTDATA, "manifest.json")) as f:
            manifest = json.load(f)
        self.assertEqual(yb.sha256_file(os.path.join(TESTDATA, "manifest.json"))[0], sums["manifest.json"])
        for network in ("testnet-yb-fast", "testnet-yb-slow", "testnet-legacy"):
            profile = ybprofile.load(network)
            self.assertEqual(sums_sha, profile["prefix"]["sha256sums_sha256"], network)
            expect = yb.check_manifest(manifest, profile, sums)
            self.assertEqual(expect[510247], profile["prefix"]["last_hash"])
            self.assertEqual(expect[0], profile["node"]["genesis"])
            for item in profile["prefix"]["checkpoints"]:
                height, value = item.split(":")
                self.assertEqual(expect[int(height)], value)
        wrong = copy.deepcopy(ybprofile.load("testnet-yb-fast"))
        wrong["prefix"]["last_hash"] = "11" * 32
        with self.assertRaisesRegex(yb.BundleError, "checkpoint"):
            yb.check_manifest(manifest, wrong, sums)


class RefusalTest(Quiet):
    def bundle(self, count=5, **prefix):
        chain = make_chain(count)
        profile = test_profile(chain, **prefix)
        out = os.path.join(self.tmp, "b")
        write(out, profile, chain)
        return chain, profile, out

    def verify(self, profile, out, **kw):
        return yb.verify_bundle(yb.Source(out), profile, os.path.join(self.tmp, "w"), args_for(**kw))

    def rewrite_sums(self, out):
        names = sorted(n for n in os.listdir(out) if n != "SHA256SUMS")
        with open(os.path.join(out, "SHA256SUMS"), "w") as f:
            for n in names:
                f.write("%s  %s\n" % (yb.sha256_file(os.path.join(out, n))[0], n))

    def test_pinned_sums(self):
        chain, profile, out = self.bundle(sha256sums_sha256="00" * 32)
        with self.assertRaisesRegex(yb.BundleError, "pins"):
            self.verify(profile, out)
        self.verify(profile, out, allow_unpinned=True)

    def test_public_network_needs_a_pin(self):
        chain, profile, out = self.bundle()
        profile["node"]["private"] = False
        with self.assertRaisesRegex(yb.BundleError, "pins no prefix"):
            self.verify(profile, out)

    def test_tampered_chunk(self):
        chain, profile, out = self.bundle()
        name = [n for n in os.listdir(out) if n.endswith(".gz")][0]
        with open(os.path.join(out, name), "ab") as f:
            f.write(b"x")
        with self.assertRaisesRegex(yb.BundleError, "bytes sha256"):
            self.verify(profile, out)

    def test_broken_hash_chain_with_consistent_sums(self):
        chain = make_chain(5)
        other = make_chain(5, salt=b"fork")
        mixed = chain[:3] + other[3:]
        profile = test_profile(chain)
        out = os.path.join(self.tmp, "b")
        write(out, profile, mixed)
        with self.assertRaisesRegex(yb.BundleError, "does not link"):
            self.verify(profile, out)

    def test_wrong_genesis(self):
        chain, profile, out = self.bundle()
        profile["node"]["genesis"] = "22" * 32
        with self.assertRaisesRegex(yb.BundleError, "genesis"):
            self.verify(profile, out)

    def test_last_height_must_be_the_release_checkpoint(self):
        chain, profile, out = self.bundle(last_height=9)
        with self.assertRaisesRegex(yb.BundleError, "checkpoint is at 9"):
            self.verify(profile, out)

    def test_wrong_network(self):
        chain, profile, out = self.bundle()
        profile["prefix"]["network"] = "zcash-testnet"
        with self.assertRaisesRegex(yb.BundleError, "manifest network"):
            self.verify(profile, out)

    def test_unexpected_or_unsafe_names(self):
        chain, profile, out = self.bundle()
        with open(os.path.join(out, "SHA256SUMS"), "a") as f:
            f.write("%s  ../../etc/passwd\n" % ("00" * 32))
        with self.assertRaisesRegex(yb.BundleError, "unexpected file"):
            self.verify(profile, out)
        with self.assertRaisesRegex(yb.BundleError, "refusing the file name"):
            yb.Source(out).fetch("../x", os.path.join(self.tmp, "x"))

    def test_unsorted_sums(self):
        chain, profile, out = self.bundle()
        lines = read_text(os.path.join(out, "SHA256SUMS")).splitlines()
        with open(os.path.join(out, "SHA256SUMS"), "w") as f:
            f.write("\n".join(reversed(lines)) + "\n")
        with self.assertRaisesRegex(yb.BundleError, "sorted"):
            self.verify(profile, out)

    def test_manifest_hash_mismatch(self):
        chain, profile, out = self.bundle()
        m = load_json(os.path.join(out, "manifest.json"))
        m["hashes"]["4"] = "33" * 32
        with open(os.path.join(out, "manifest.json"), "w") as f:
            f.write(json.dumps(m, indent=2, sort_keys=True) + "\n")
        self.rewrite_sums(out)
        with self.assertRaisesRegex(yb.BundleError, "height 4: hash"):
            self.verify(profile, out)

    def test_signature(self):
        chain, profile, out = self.bundle()
        with self.assertRaisesRegex(yb.BundleError, "not signed"):
            self.verify(profile, out, require_signature=True)
        with open(os.path.join(out, "SHA256SUMS.minisig"), "w") as f:
            f.write("untrusted comment: signature\nRW...\n")
        with self.assertRaisesRegex(yb.BundleError, "not installed"):
            self.verify(profile, out, minisign="no-such-minisign-binary")
        bin_dir = os.path.join(self.tmp, "bin")
        os.makedirs(bin_dir)
        for name, code in (("good", 0), ("bad", 1)):
            path = os.path.join(bin_dir, name)
            with open(path, "w") as f:
                f.write("#!/bin/sh\necho \"$@\" > %s.args\nexit %d\n" % (path, code))
            os.chmod(path, 0o700)
        _, _, _, record = self.verify(profile, out, minisign=os.path.join(bin_dir, "good"))
        self.assertTrue(record["signed"])
        argv = read_text(os.path.join(bin_dir, "good.args")).split()
        self.assertEqual(argv[argv.index("-P") + 1], "RWQYr5PFpiPJAigk86vf89bPYrJCXj5tskgRAPRYFsEXyciZo8dveOGQ")
        with self.assertRaisesRegex(yb.BundleError, "does not verify"):
            self.verify(profile, out, minisign=os.path.join(bin_dir, "bad"))

    def test_release_key(self):
        self.assertEqual(yb.read_key(yb.DEFAULT_KEY), "RWQYr5PFpiPJAigk86vf89bPYrJCXj5tskgRAPRYFsEXyciZo8dveOGQ")


class HttpTest(Quiet):
    def test_http_source_and_optional_signature(self):
        chain = make_chain(4)
        profile = test_profile(chain)
        out = os.path.join(self.tmp, "b")
        write(out, profile, chain)
        handler = lambda *a, **kw: http.server.SimpleHTTPRequestHandler(*a, directory=out, **kw)   # noqa: E731
        http.server.SimpleHTTPRequestHandler.log_message = lambda *a: None
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        saved = {k: os.environ.pop(k) for k in list(os.environ) if k.lower() in ("http_proxy", "https_proxy", "all_proxy")}
        try:
            url = "http://127.0.0.1:%d/manifest.json" % server.server_address[1]
            _, _, files, record = yb.verify_bundle(yb.Source(url), profile, os.path.join(self.tmp, "w"), args_for())
            self.assertFalse(record["signed"])
            self.assertEqual(len(files), 1)
        finally:
            server.shutdown()
            server.server_close()
            os.environ.update(saved)


class Bucket(http.server.SimpleHTTPRequestHandler):
    """A static bucket. Not listable, it answers 403 for an object that is not there (S3, CloudFront
    without s3:ListBucket); `errors` maps a file name to a forced status."""
    absent, errors = 404, {}

    def log_message(self, *a):
        pass

    def send_error(self, code, message=None, explain=None):
        super().send_error(self.absent if code == 404 else code, message, explain)

    def do_GET(self):
        code = self.errors.get(os.path.basename(self.path))
        if code:
            return super().send_error(code)
        return super().do_GET()


class BucketTest(Quiet):
    """The optional SHA256SUMS.minisig: 403 and 404 both mean absent (and then a signature that is
    required is refused); any other error, or a 403 on a file the bundle needs, is a refusal."""

    def serve(self, absent, errors=None):
        chain = make_chain(4)
        self.profile = test_profile(chain)
        out = os.path.join(self.tmp, "b")
        write(out, self.profile, chain)
        handler_class = type("B", (Bucket,), {"absent": absent, "errors": errors or {}})
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), lambda *a, **kw: handler_class(*a, directory=out, **kw))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        saved = {k: os.environ.pop(k) for k in list(os.environ) if k.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
        self.addCleanup(os.environ.update, saved)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.source = yb.Source("http://127.0.0.1:%d/" % server.server_address[1])
        return out

    def verify(self, **kw):
        return yb.verify_bundle(self.source, self.profile, os.path.join(self.tmp, "w"), args_for(**kw))

    def test_absent_signature_on_403_and_404(self):
        for absent in (403, 404):
            with self.subTest(absent=absent):
                self.serve(absent)
                _, _, _, record = self.verify()
                self.assertFalse(record["signed"])
                with self.assertRaisesRegex(yb.BundleError, r"not signed \(SHA256SUMS.minisig: HTTP %d\) and --require-signature" % absent):
                    self.verify(require_signature=True)

    def test_403_on_a_needed_file_or_another_error_on_the_signature_is_a_refusal(self):
        out = self.serve(403)
        os.remove(os.path.join(out, "manifest.json"))
        with self.assertRaisesRegex(yb.BundleError, "manifest.json: HTTP 403"):
            self.verify()
        self.serve(403, {"SHA256SUMS.minisig": 500})
        with self.assertRaisesRegex(yb.BundleError, "SHA256SUMS.minisig: HTTP 500"):
            self.verify()

    def test_a_present_signature_behind_403_is_still_verified(self):
        out = self.serve(403)
        with open(os.path.join(out, "SHA256SUMS.minisig"), "w") as f:
            f.write("untrusted comment: signature\nRW...\n")
        bad = os.path.join(self.tmp, "bad-minisign")
        with open(bad, "w") as f:
            f.write("#!/bin/sh\nexit 1\n")
        os.chmod(bad, 0o700)
        with self.assertRaisesRegex(yb.BundleError, "does not verify"):
            self.verify(minisign=bad)


FAKE_YCASHD = r'''#!%(python)s
# A stand-in ycashd: "imports" every -loadblock file (magic, length, block) into fake-chain.json,
# logs the node's "Loaded N blocks from external file" line, and runs until ycash-cli stop.
import json, os, struct, sys, time
args = sys.argv[1:]
datadir = [a.split("=", 1)[1] for a in args if a.startswith("-datadir=")][0]
net = "regtest" if "-regtest" in args else "testnet-yb-" + [a.split("=", 1)[1] for a in args if a.startswith("-testnetprofile=")][0]
netdir = os.path.join(datadir, net)
os.makedirs(netdir, exist_ok=True)
with open(os.path.join(datadir, "fake-args.json"), "w") as f: json.dump(args, f)
# Peers the way ycashd 0.11-lineage arguments give them: -addnode and -connect from the command line
# and from the conf are appended to one list (the conf never overrides, it adds), and -connect=0 alone
# turns automatic connections off. A node with a peer syncs past the bundle: FAKE_PEER_BLOCKS more.
conf = ([a.split("=", 1)[1] for a in args if a.startswith("-conf=")] or [os.path.join(datadir, "ycash.conf")])[-1]
multi = {"addnode": [], "connect": [], "seednode": []}
for a in args:
    k, _, v = a.lstrip("-").partition("=")
    if k in multi: multi[k].append(v)
if os.path.exists(conf):
    with open(conf) as f: text = f.read()
    with open(os.path.join(datadir, "fake-conf-seen.txt"), "w") as f: f.write(text)
    for line in text.splitlines():
        k, _, v = line.strip().partition("=")
        if k.strip() in multi: multi[k.strip()].append(v.strip())
peers = multi["addnode"] + multi["seednode"] + ([] if multi["connect"] == ["0"] else [c for c in multi["connect"] if c != "0"])
peer_count = len(peers) or int(os.environ.get("FAKE_PEERS", "0"))
with open(os.path.join(netdir, "fake-peers.json"), "w") as f: json.dump(peer_count, f)
blocks, log = [], open(os.path.join(netdir, "debug.log"), "a")
refuse = os.environ.get("FAKE_REFUSE_HEIGHT")
for path in [a.split("=", 1)[1] for a in args if a.startswith("-loadblock=")]:
    data, i, n = open(path, "rb").read(), 0, 0
    while i < len(data):
        if data[i:i + 4] != bytes.fromhex(os.environ["FAKE_MAGIC"]): sys.exit("bad magic")
        (size,) = struct.unpack_from("<I", data, i + 4)
        if refuse is None or len(blocks) < int(refuse): blocks.append(data[i + 8:i + 8 + size].hex())
        i += 8 + size; n += 1
    log.write("Loaded %%d blocks from external file in 1ms\n" %% n); log.flush()
if peers: blocks += [blocks[-1]] * 3                   # synced from a peer, past the bundle's last height
with open(os.path.join(netdir, "fake-chain.json"), "w") as f: json.dump(blocks, f)
stop = os.path.join(netdir, "fake-stop")
while not os.path.exists(stop): time.sleep(0.05)
os.remove(stop)
'''

FAKE_CLI = r'''#!%(python)s
import hashlib, json, os, struct, sys
args = [a for a in sys.argv[1:] if not a.startswith("-")]
flags = [a for a in sys.argv[1:] if a.startswith("-")]
datadir = [a.split("=", 1)[1] for a in flags if a.startswith("-datadir=")][0]
net = "regtest" if "-regtest" in flags else "testnet-yb-" + [a.split("=", 1)[1] for a in flags if a.startswith("-testnetprofile=")][0]
netdir = os.path.join(datadir, net)
try: blocks = [bytes.fromhex(b) for b in json.load(open(os.path.join(netdir, "fake-chain.json")))]
except OSError: sys.exit(28)
def h(b):
    n = b[140]; end = 141 + n
    return hashlib.sha256(hashlib.sha256(b[:end]).digest()).digest()[::-1].hex()
cmd = args[0]
if cmd == "getblockchaininfo": print(json.dumps({"blocks": len(blocks) - 1, "chain": "regtest"}))
elif cmd == "getblockhash": print(h(blocks[int(args[1])]))
elif cmd == "getbestblockhash": print(h(blocks[-1]))
elif cmd == "getconnectioncount": print(json.load(open(os.path.join(netdir, "fake-peers.json"))))
elif cmd == "stop": open(os.path.join(netdir, "fake-stop"), "w").close(); print("stopping")
else: sys.exit("unknown " + cmd)
'''


class RestoreTest(Quiet):
    def setUp(self):
        super().setUp()
        self.chain = make_chain(9)
        self.profile = test_profile(self.chain)
        self.bundle = os.path.join(self.tmp, "bundle")
        write(self.bundle, self.profile, self.chain)
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        for name, text in (("ycashd", FAKE_YCASHD), ("ycash-cli", FAKE_CLI)):
            with open(os.path.join(self.bin, name), "w") as f:
                f.write(text % {"python": sys.executable})
            os.chmod(os.path.join(self.bin, name), 0o700)
        os.environ["FAKE_MAGIC"] = self.profile["node"]["magic"]
        self.datadir = os.path.join(self.tmp, "data")

    def run_restore(self, *extra):
        argv = ["--network", "regtest", "--datadir", self.datadir, "--source", self.bundle, "--ycashd", os.path.join(self.bin, "ycashd"),
                "--cli", os.path.join(self.bin, "ycash-cli"), "--poll", "0.1", "--done-grace", "1", "--node-arg=-nuparams=5ba81b19:1"] + list(extra)
        real = ybprofile.load
        ybprofile.load = lambda network, directory=None: copy.deepcopy(self.profile)
        try:
            with contextlib.redirect_stderr(io.StringIO()) as err:
                code = yb.main(argv)
            return code, err.getvalue()
        finally:
            ybprofile.load = real

    def test_restore_imports_checks_and_records(self):
        code, err = self.run_restore()
        self.assertEqual(code, 0, err)
        record = load_json(os.path.join(self.datadir, "regtest", "bootstrap.json"))
        self.assertEqual(record["tip"], self.chain[-1][0])
        self.assertEqual(record["import"]["checked"], 2)
        self.assertFalse(os.path.exists(os.path.join(self.datadir, "bootstrap-work")))
        args = load_json(os.path.join(self.datadir, "fake-args.json"))
        for flag in ("-connect=0", "-listen=0", "-disablewallet=1", "-regtest", "-nuparams=5ba81b19:1"):
            self.assertIn(flag, args)
        self.assertNotIn("-checkpoints=0", args)

    def test_refuses_a_datadir_with_a_chain_and_reset_wipes_it(self):
        os.makedirs(os.path.join(self.datadir, "regtest", "blocks"))
        open(os.path.join(self.datadir, "regtest", "blocks", "blk00000.dat"), "w").close()
        open(os.path.join(self.datadir, "regtest", "wallet.dat"), "w").close()
        code, err = self.run_restore()
        self.assertEqual(code, 2)
        self.assertIn("already holds a chain", err)
        code, err = self.run_restore("--reset", "--verify-full")
        self.assertEqual(code, 0, err)
        self.assertEqual(len([n for n in os.listdir(self.datadir) if n.startswith("wallet-before-reset-regtest-")]), 1)
        self.assertIn("-checkpoints=0", load_json(os.path.join(self.datadir, "fake-args.json")))

    def test_a_refused_block_fails_the_import(self):
        os.environ["FAKE_REFUSE_HEIGHT"] = "5"
        try:
            code, err = self.run_restore()
        finally:
            del os.environ["FAKE_REFUSE_HEIGHT"]
        self.assertEqual(code, 2)
        self.assertIn("stopped at height 4 of 8", err)

    def marker(self):
        return os.path.join(self.datadir, "regtest.bootstrap-incomplete")

    def test_peers_in_the_conf_do_not_reach_the_import(self):
        # beta3 item 8: an addnode in ycash.conf let the import node sync past the bundle; the
        # restore was then refused ("above the bundle's") and the next start used the datadir anyway.
        os.makedirs(self.datadir)
        user_conf = os.path.join(self.datadir, "ycash.conf")
        with open(user_conf, "w") as f:
            f.write("rpcuser=u\nrpcpassword=p\naddnode=203.0.113.7\n connect = 203.0.113.8\nseednode=203.0.113.9\n"
                    "listen=1\nbind=0.0.0.0\nnoconnect=0\ntxindex=1\n")
        for conf_arg in ((), ("--conf", user_conf)):
            with self.subTest(conf=conf_arg):
                shutil.rmtree(os.path.join(self.datadir, "regtest"), ignore_errors=True)
                code, err = self.run_restore(*conf_arg)
                self.assertEqual(code, 0, err)
                args = load_json(os.path.join(self.datadir, "fake-args.json"))
                confs = [a for a in args if a.startswith("-conf=")]
                self.assertEqual(len(confs), 1)
                self.assertNotEqual(confs[0], "-conf=%s" % user_conf)
                seen = read_text(os.path.join(self.datadir, "fake-conf-seen.txt"))
                for kept in ("rpcuser=u", "rpcpassword=p", "txindex=1"):
                    self.assertIn(kept, seen)
                for dropped in ("addnode", "connect", "seednode", "listen", "bind"):
                    self.assertNotIn(dropped + "=", seen.replace(" ", ""))
                self.assertFalse(os.path.exists(self.marker()))
        self.assertIn("addnode=203.0.113.7", read_text(user_conf))      # the user's file is not touched

    def test_a_peer_at_the_import_is_a_refusal(self):
        os.environ["FAKE_PEERS"] = "1"
        try:
            code, err = self.run_restore()
        finally:
            del os.environ["FAKE_PEERS"]
        self.assertEqual(code, 2)
        self.assertIn("1 peer", err)
        self.assertTrue(os.path.exists(self.marker()))

    def test_peer_flags_in_node_arg_are_refused(self):
        for flag in ("-addnode=203.0.113.7", "-connect=203.0.113.7", "-listen=1", "-seednode=x", "-noconnect=0"):
            with self.subTest(flag=flag), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.run_restore("--node-arg=%s" % flag)
        self.assertFalse(os.path.exists(self.marker()))

    def test_a_failed_restore_leaves_a_marker_until_one_succeeds(self):
        os.environ["FAKE_REFUSE_HEIGHT"] = "5"
        try:
            code, err = self.run_restore()
        finally:
            del os.environ["FAKE_REFUSE_HEIGHT"]
        self.assertEqual(code, 2)
        text = read_text(self.marker())
        self.assertIn("failed", text)
        self.assertIn("stopped at height 4 of 8", text)
        self.assertFalse(os.path.exists(os.path.join(self.datadir, "regtest", "bootstrap.json")))
        code, err = self.run_restore()                       # the fake left no blocks/: a retry may run
        self.assertEqual(code, 0, err)
        self.assertFalse(os.path.exists(self.marker()))

    def test_a_datadir_with_a_chain_gets_no_marker(self):
        os.makedirs(os.path.join(self.datadir, "regtest", "blocks"))
        open(os.path.join(self.datadir, "regtest", "blocks", "blk00000.dat"), "w").close()
        code, err = self.run_restore()
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(self.marker()))       # nothing was changed: the node may start

    def test_frame_only(self):
        out = os.path.join(self.tmp, "framed")
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            code, err = self.run_restore("--frame-only", out)
        self.assertEqual(code, 0, err)
        self.assertIn("-loadblock=%s" % os.path.join(out, "blk-0000000-0000008.dat"), printed.getvalue())


STATE_CLI = r"""#!%(python)s
# A stand-in ycash-cli for a restored state bundle: the chain lives in <net>/chainstate/fake-state.json.
import json, os, sys
args = [a for a in sys.argv[1:] if not a.startswith("-")]
flags = [a for a in sys.argv[1:] if a.startswith("-")]
datadir = [a.split("=", 1)[1] for a in flags if a.startswith("-datadir=")][0]
net = "testnet-yb-" + [a.split("=", 1)[1] for a in flags if a.startswith("-testnetprofile=")][0]
path = os.path.join(datadir, net, "chainstate", "fake-state.json")
st = json.load(open(path))
tip = st["tip"]
h = lambda n: "%%064x" %% n
cmd = args[0]
if cmd == "getblockcount" and os.environ.get("FAKE_WARMUP"): sys.exit("error code: -28")   # never leaves warm-up
elif cmd == "getblockcount": print(tip)
elif cmd == "getblockhash": print(h(int(args[1])))
elif cmd == "getblockheader": print(json.dumps({"chainwork": "%%064x" %% (int(args[1], 16) * 3)}))
elif cmd == "gettxoutsetinfo": print(json.dumps({"hash_serialized": "utxo-%%d" %% tip}))
elif cmd == "vault_getinfo": print(json.dumps({"dbtip": {"hash": h(tip), "height": tip}, "statehash": "vault-%%d" %% tip}))
elif cmd == "yed_getstatehash": print(json.dumps({"blockhash": h(int(args[1])), "statehash": "yed-%%s" %% args[1]}))
elif cmd == "invalidateblock": st["tip"] = int(args[1], 16) - 1; st["calls"].append(cmd); json.dump(st, open(path, "w"))
elif cmd == "reconsiderblock": st["tip"] = st["top"]; st["calls"].append(cmd); json.dump(st, open(path, "w"))
elif cmd == "getconnectioncount": print(json.load(open(os.path.join(datadir, net, "fake-peers.json"))))
elif cmd == "stop": open(os.path.join(datadir, net, "fake-stop"), "w").close()
else: sys.exit("unknown " + cmd)
"""


def make_state_bundle(out, height=510500, top=510503, statement_override=None, extra_entry=None, network="testnet-yb-fast"):
    """A ycash-state/1 bundle (ycash-infra bundles/state/FORMAT.md) of a stand-in datadir."""
    import tarfile
    os.makedirs(out)
    files = {"%s/blocks/blk00000.dat" % network: b"blocks", "%s/blocks/index/000001.ldb" % network: b"index",
             "%s/chainstate/fake-state.json" % network: json.dumps({"tip": top, "top": top, "calls": []}).encode()}
    if extra_entry:
        files[extra_entry] = b"x"
    dirs = sorted({os.path.dirname(n) for n in files} | {"%s/blocks" % network, "%s/chainstate" % network} - {network})
    tarball = "ycash6-%s-%d-full.tar.gz" % (network, height)
    tar_path = os.path.join(out, tarball)
    with open(tar_path, "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz, tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as t:
        for name in sorted(dirs + list(files), key=str.encode):
            info = tarfile.TarInfo(name)
            info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, "", ""
            if name in files:
                info.size, info.mode = len(files[name]), 0o644
                t.addfile(info, io.BytesIO(files[name]))
            else:
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                t.addfile(info)
    statement = {"network": network, "height": height, "blockhash": "%064x" % height, "chainwork": "%064x" % (height * 3),
                 "utxo_hash_serialized": "utxo-%d" % height, "vault_statehash": "vault-%d" % height, "yed_statehash": "yed-%d" % height}
    statement.update(statement_override or {})
    manifest = dict(statement, format="ycash-state/1", line="ycash6", profile=network.rsplit("-", 1)[1], version="6.22.0-rc1", flavour="full",
                    tarball=tarball, sha256=yb.sha256_file(tar_path)[0], bytes=yb.sha256_file(tar_path)[1], created="2026-11-01T00:00:00Z",
                    producer="ycash-infra/snapshotter", verifiers=["ycash-dd", "ycash6"])
    for name, value in (("manifest.json", manifest), ("statement-ycash-dd.json", statement), ("statement-ycash6.json", statement)):
        with open(os.path.join(out, name), "w") as f:
            f.write(yb.canonical(value))
    names = sorted(n for n in os.listdir(out))
    with open(os.path.join(out, "SHA256SUMS"), "w") as f:
        for n in names:
            f.write("%s  %s\n" % (yb.sha256_file(os.path.join(out, n))[0], n))
    return out


class StateTest(Quiet):
    def setUp(self):
        super().setUp()
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        for name, text in (("ycashd", FAKE_YCASHD), ("ycash-cli", STATE_CLI)):
            with open(os.path.join(self.bin, name), "w") as f:
                f.write(text % {"python": sys.executable})
            os.chmod(os.path.join(self.bin, name), 0o700)
        os.environ["FAKE_MAGIC"] = "f77962d3"
        self.datadir = os.path.join(self.tmp, "data")

    def restore(self, bundle, *extra):
        argv = ["--network", "testnet-yb-fast", "--datadir", self.datadir, "--state", "--source", bundle, "--ycashd", os.path.join(self.bin, "ycashd"),
                "--cli", os.path.join(self.bin, "ycash-cli"), "--poll", "0.05"] + list(extra)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            code = yb.main(argv)
        return code, err.getvalue()

    def chain_state(self):
        return load_json(os.path.join(self.datadir, "testnet-yb-fast", "chainstate", "fake-state.json"))

    def test_restore_rolls_back_compares_and_reconsiders(self):
        code, err = self.restore(make_state_bundle(os.path.join(self.tmp, "b")))
        self.assertEqual(code, 0, err)
        state = self.chain_state()
        self.assertEqual(state["calls"], ["invalidateblock", "reconsiderblock"])
        self.assertEqual(state["tip"], 510503)
        record = load_json(os.path.join(self.datadir, "testnet-yb-fast", "bootstrap.json"))
        self.assertEqual(record["check"]["rolled_back_from"], 510503)
        self.assertEqual(record["height"], 510500)

    def test_no_rollback_when_at_h_b(self):
        code, err = self.restore(make_state_bundle(os.path.join(self.tmp, "b"), top=510500))
        self.assertEqual(code, 0, err)
        self.assertEqual(self.chain_state()["calls"], [])

    def test_a_node_stuck_in_warm_up_times_out(self):
        os.environ["FAKE_WARMUP"] = "1"                      # alive, but getblockcount never answers
        try:
            code, err = self.restore(make_state_bundle(os.path.join(self.tmp, "b")), "--stall-timeout", "1")
        finally:
            del os.environ["FAKE_WARMUP"]
        self.assertEqual(code, 2)
        self.assertIn("did not settle within 1s (its RPC never answered)", err)
        self.assertFalse(os.path.exists(os.path.join(self.datadir, "testnet-yb-fast", "chainstate")))

    def test_disagreeing_node_removes_the_extracted_state(self):
        code, err = self.restore(make_state_bundle(os.path.join(self.tmp, "b"), statement_override={"utxo_hash_serialized": "other"}))
        self.assertEqual(code, 2)
        self.assertIn("disagrees with the statements", err)
        self.assertFalse(os.path.exists(os.path.join(self.datadir, "testnet-yb-fast", "chainstate")))

    def test_a_failed_state_restore_leaves_a_marker(self):
        marker = os.path.join(self.datadir, "testnet-yb-fast.bootstrap-incomplete")
        code, err = self.restore(make_state_bundle(os.path.join(self.tmp, "b"), statement_override={"utxo_hash_serialized": "other"}))
        self.assertEqual(code, 2)
        self.assertIn("disagrees with the statements", read_text(marker))
        shutil.rmtree(os.path.join(self.datadir, "testnet-yb-fast"), ignore_errors=True)
        code, err = self.restore(make_state_bundle(os.path.join(self.tmp, "b2")))
        self.assertEqual(code, 0, err)
        self.assertFalse(os.path.exists(marker))

    def test_refusals(self):
        code, err = self.restore(make_state_bundle(os.path.join(self.tmp, "b1"), extra_entry="testnet-yb-fast/wallet.dat"))
        self.assertIn("not under", err)                      # wallet.dat sits outside blocks/chainstate/vaults/yellowback
        code, err = self.restore(make_state_bundle(os.path.join(self.tmp, "b2"), extra_entry="testnet-yb-fast/chainstate/LOCK"))
        self.assertIn("leaves out", err)
        code, err = self.restore(make_state_bundle(os.path.join(self.tmp, "b3"), network="testnet-yb-slow"))
        self.assertIn("this is testnet-yb-fast", err)
        bundle = make_state_bundle(os.path.join(self.tmp, "b4"))
        with open(os.path.join(bundle, "statement-ycash6.json"), "a") as f:
            f.write(" ")
        code, err = self.restore(bundle)
        self.assertIn("statement-ycash6.json does not match", err)
        code, err = self.restore(make_state_bundle(os.path.join(self.tmp, "b5"), height=510000))
        self.assertIn("below the fork", err)
        self.assertEqual(code, 2)



# ---------------------------------------------------------------------------------- ycash-state/2 and /3 (beta3 item 9)

FAKE_STATE_YCASHD = r"""#!%(python)s
# A stand-in ycashd for a restored state bundle: records its arguments, has no peer, runs until stopped.
import json, os, sys, time
args = sys.argv[1:]
datadir = [a.split("=", 1)[1] for a in args if a.startswith("-datadir=")][0]
profile = [a.split("=", 1)[1] for a in args if a.startswith("-testnetprofile=")]
net = "regtest" if "-regtest" in args else ("testnet-yb-" + profile[0]) if profile else ""
netdir = os.path.join(datadir, net) if net else datadir
with open(os.path.join(datadir, "fake-args.json"), "w") as f: json.dump(args, f)
conf = [a.split("=", 1)[1] for a in args if a.startswith("-conf=")]
if conf:
    with open(os.path.join(datadir, "fake-conf-mode.json"), "w") as f: json.dump(os.stat(conf[-1]).st_mode & 0o777, f)
with open(os.path.join(netdir, "fake-peers.json"), "w") as f: json.dump(0, f)
stop = os.path.join(netdir, "fake-stop")
while not os.path.exists(stop): time.sleep(0.05)
os.remove(stop)
"""

FAKE_STATE_CLI = r"""#!%(python)s
# A stand-in ycash-cli for a restored state bundle: the chain is <netdir>/chainstate/fake-state.json.
import json, os, sys
args = [a for a in sys.argv[1:] if not a.startswith("-")]
flags = [a for a in sys.argv[1:] if a.startswith("-")]
datadir = [a.split("=", 1)[1] for a in flags if a.startswith("-datadir=")][0]
profile = [a.split("=", 1)[1] for a in flags if a.startswith("-testnetprofile=")]
net = "regtest" if "-regtest" in flags else ("testnet-yb-" + profile[0]) if profile else ""
netdir = os.path.join(datadir, net) if net else datadir
path = os.path.join(netdir, "chainstate", "fake-state.json")
st = json.load(open(path))
tip, H, f = st["tip"], st["H"], st["st"]
bh = lambda n: st["hashes"].get(str(n), "%%064x" %% n)
at_h = tip == H
cmd = args[0]
if cmd == "getblockcount": print(tip)
elif cmd == "getblockhash": print(bh(int(args[1])))
elif cmd == "getblockheader": print(json.dumps({"chainwork": f["chainwork"]}))
elif cmd == "gettxoutsetinfo": print(json.dumps({"hash_serialized": f["utxo_hash_serialized"] if at_h else "above"}))
elif cmd == "vault_getinfo": print(json.dumps({"dbtip": {"hash": bh(tip)}, "statehash": f["vault_statehash"] if at_h else "above"}))
elif cmd == "yed_getstatehash": print(json.dumps({"blockhash": bh(int(args[1])), "statehash": f["yed_statehash"]}))
elif cmd == "getblock": print(json.dumps({"finalsaplingroot": f["finalsaplingroot"], "chainSupply": {"chainValueZat": f["chainsupply_zat"]}}))
elif cmd == "invalidateblock": st["tip"] = H; st["calls"].append(cmd); json.dump(st, open(path, "w"))
elif cmd == "reconsiderblock": st["tip"] = st["top"]; st["calls"].append(cmd); json.dump(st, open(path, "w"))
elif cmd == "getconnectioncount": print(json.load(open(os.path.join(netdir, "fake-peers.json"))))
elif cmd == "stop": open(os.path.join(netdir, "fake-stop"), "w").close()
else: sys.exit("unknown " + cmd)
"""


def noise(n, seed=b"n"):
    """n bytes gzip cannot shrink (a hash chain), so a small datadir packs to several parts."""
    out, h = [], seed
    while sum(map(len, out)) < n:
        h = hashlib.sha256(h).digest()
        out.append(h)
    return b"".join(out)[:n]


def state_files(network, height, top=None, hashes=None, statement=None):
    """A stand-in datadir under <network>/ (FORMAT.md entries) whose chainstate the fake cli reads."""
    fake = {"tip": top or height, "top": top or height, "H": height, "calls": [], "hashes": hashes or {}, "st": statement}
    return {"%s/blocks/blk00000.dat" % network: noise(40000), "%s/blocks/rev00000.dat" % network: b"undo",
            "%s/blocks/index/000003.ldb" % network: b"index",
            "%s/chainstate/000005.ldb" % network: noise(9000, b"c"),
            "%s/chainstate/fake-state.json" % network: json.dumps(fake, sort_keys=True).encode(),
            "%s/vaults/CURRENT" % network: b"MANIFEST-000001\n"}


def tar_gz(files):
    """The tar.gz stream of FORMAT.md's encoding (GNU tar, bytewise order, fixed headers, gzip without a name or time)."""
    import tarfile
    dirs = set()
    for name in files:
        parts = name.split("/")
        for i in range(2, len(parts)):
            dirs.add("/".join(parts[:i]))
    raw = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=6) as gz, \
            tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as t:
        for name in sorted(list(dirs) + list(files), key=str.encode):
            info = tarfile.TarInfo(name)
            info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, "", ""
            if name in files:
                info.size, info.mode = len(files[name]), 0o644
                t.addfile(info, io.BytesIO(files[name]))
            else:
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                t.addfile(info)
    return raw.getvalue()


def tree_hash(files):
    h = hashlib.sha256()
    for name in sorted(files, key=str.encode):
        h.update(("%s  %s\n" % (hashlib.sha256(files[name]).hexdigest(), name)).encode())
    return h.hexdigest()


def write_state_bundle(out, files, network, height, blockhash, pins, fmt="ycash-state/3", parts=3, statement=None, signed=True, **override):
    """A ycash-state/2 (one tarball) or /3 bundle (the same stream in `parts` parts) of `files`."""
    os.makedirs(out)
    stream = tar_gz(files)
    tarball = "ycash6-%s-%d-full.tar.gz" % (network, height)
    manifest = dict(statement, format=fmt, line="ycash6", profile="", version="6.22.0-beta3", commit="0123456", flavour="full",
                    tarball=tarball, sha256=hashlib.sha256(stream).hexdigest(), bytes=len(stream), created="2026-11-15T00:00:00Z",
                    producer="ycash-infra/mainnet-snapshot", verifiers=["ycash6"], tree_sha256=tree_hash(files), pins=pins,
                    treestate="treestate.json")
    if fmt == "ycash-state/3":
        pb = -(-len(stream) // parts)
        chunks = [stream[i:i + pb] for i in range(0, len(stream), pb)]
        manifest.update(part_bytes=pb, unpacked_bytes=sum(len(v) for v in files.values()),
                        parts=[{"name": "%s.%03d" % (tarball, i), "bytes": len(c), "sha256": hashlib.sha256(c).hexdigest()}
                               for i, c in enumerate(chunks)])
        for i, c in enumerate(chunks):
            with open(os.path.join(out, "%s.%03d" % (tarball, i)), "wb") as f:
                f.write(c)
    else:
        with open(os.path.join(out, tarball), "wb") as f:
            f.write(stream)
    manifest.update(override)
    for name, value in (("manifest.json", manifest), ("statement-ycash6.json", statement), ("treestate.json", {"height": height})):
        with open(os.path.join(out, name), "w") as f:
            f.write(yb.canonical(value))
    names = sorted(os.listdir(out), key=str.encode)
    with open(os.path.join(out, "SHA256SUMS"), "w") as f:
        for n in names:
            f.write("%s  %s\n" % (yb.sha256_file(os.path.join(out, n))[0], n))
    if signed:
        with open(os.path.join(out, "SHA256SUMS.minisig"), "w") as f:
            f.write("untrusted comment: signature\nRW...\n")
    return manifest


class Ranged(http.server.BaseHTTPRequestHandler):
    """A static bucket that honours `Range: bytes=N-` (206), answers 416 past the end, can drop a file's
    first response halfway (`drop`), and records each request with the bytes of parts then in `watch`."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        srv = self.server
        name = os.path.basename(urllib.parse.urlparse(self.path).path)
        rel = urllib.parse.unquote(urllib.parse.urlparse(self.path).path).lstrip("/")
        held = 0
        if srv.watch and os.path.isdir(srv.watch):
            held = sum(os.path.getsize(os.path.join(srv.watch, n)) for n in os.listdir(srv.watch) if re.search(r"\.tar\.gz\.\d{3}", n))
        srv.log.append((rel, self.headers.get("Range"), held))
        path = os.path.join(srv.root, *rel.split("/"))
        if ".." in rel.split("/") or not os.path.isfile(path):
            self.send_error(404)
            return
        with open(path, "rb") as f:
            data = f.read()
        start, rng = 0, self.headers.get("Range")
        if rng:
            start = int(re.fullmatch(r"bytes=(\d+)-", rng).group(1))
            if start >= len(data):
                self.send_error(416)
                return
            self.send_response(206)
            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, len(data) - 1, len(data)))
        else:
            self.send_response(200)
        body = data[start:]
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if name in srv.drop:
            srv.drop.discard(name)
            self.wfile.write(body[:len(body) // 2])
            self.wfile.flush()
            self.close_connection = True
            return
        self.wfile.write(body)


import re  # noqa: E402
import urllib.parse  # noqa: E402

MAIN_H = 570000
MAIN_PINS = {str(h): x for h, x in yb.MAINNET_PINS.items() if h <= MAIN_H}


class PartsTest(Quiet):
    """A bundle in three parts restores to the same state as the one-file bundle; a corrupted, missing,
    truncated or over-long part is refused before it reaches the extractor; a broken download resumes."""

    def setUp(self):
        super().setUp()
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        for name, text in (("ycashd", FAKE_STATE_YCASHD), ("ycash-cli", FAKE_STATE_CLI)):
            with open(os.path.join(self.bin, name), "w") as f:
                f.write(text % {"python": sys.executable})
            os.chmod(os.path.join(self.bin, name), 0o700)
        self.minisign = os.path.join(self.bin, "minisign")
        with open(self.minisign, "w") as f:
            f.write("#!/bin/sh\necho \"$@\" > %s.args\nexit 0\n" % self.minisign)
        os.chmod(self.minisign, 0o700)
        self.datadir = os.path.join(self.tmp, "data")
        self.root = os.path.join(self.tmp, "bucket", "main")         # <base>/main/{latest,<H>}/
        self.statement = {"network": "main", "height": MAIN_H, "blockhash": yb.MAINNET_PINS[MAIN_H], "chainwork": "%064x" % 7,
                          "utxo_hash_serialized": "aa" * 32, "vault_statehash": "bb" * 32, "yed_statehash": None,
                          "finalsaplingroot": "cc" * 32, "chainsupply_zat": 123456789}
        self.hashes = dict(MAIN_PINS, **{str(MAIN_H + 1): "dd" * 32})
        self.files = state_files("main", MAIN_H, hashes=self.hashes, statement=self.statement)
        self.server = None

    def bundle(self, fmt="ycash-state/3", top=None, statement=None, files=None, **kw):
        statement = statement or self.statement
        files = files or (state_files("main", MAIN_H, top=top, hashes=self.hashes, statement=self.statement) if top else self.files)
        out = os.path.join(self.root, str(MAIN_H))
        pins = kw.pop("pins", MAIN_PINS)
        m = write_state_bundle(out, files, "main", MAIN_H, yb.MAINNET_PINS[MAIN_H], pins, fmt=fmt, statement=statement, **kw)
        os.makedirs(os.path.join(self.root, "latest"), exist_ok=True)
        shutil.copyfile(os.path.join(out, "manifest.json"), os.path.join(self.root, "latest", "manifest.json"))
        return out, m

    def serve(self, drop=()):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Ranged)
        server.root, server.drop, server.log = os.path.join(self.tmp, "bucket"), set(drop), []
        server.watch = os.path.join(self.datadir, "bootstrap-work", "download")
        threading.Thread(target=server.serve_forever, daemon=True).start()
        saved = {k: os.environ.pop(k) for k in list(os.environ) if k.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
        self.addCleanup(os.environ.update, saved)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.server = server
        return "http://127.0.0.1:%d/main/" % server.server_address[1]

    def restore(self, source, *extra, network="main"):
        argv = ["--network", network, "--datadir", self.datadir] + ([] if network == "main" else ["--state"]) + ["--source", source, "--ycashd", os.path.join(self.bin, "ycashd"),
                "--cli", os.path.join(self.bin, "ycash-cli"), "--minisign", self.minisign, "--poll", "0.05", "--retry-wait", "0"] + list(extra)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            code = yb.main(argv)
        return code, err.getvalue()

    def requests(self, suffix):
        return [(rng, held) for rel, rng, held in self.server.log if rel.endswith(suffix)]

    def assert_restored(self, files, netdir=None):
        netdir = netdir or self.datadir
        got = {}
        for top in yb.STATE_TOP_DIRS:
            for dirpath, _, names in os.walk(os.path.join(netdir, top)):
                for n in names:
                    full = os.path.join(dirpath, n)
                    with open(full, "rb") as f:
                        got["main/" + os.path.relpath(full, netdir).replace(os.sep, "/")] = f.read()
        self.assertEqual(sorted(got), sorted(files))
        for name in files:
            self.assertEqual(got[name], files[name], name)
        self.assertEqual(tree_hash(got), tree_hash(files))
        self.assertFalse(os.path.exists(os.path.join(self.datadir, "bootstrap-work")))
        self.assertFalse(os.path.exists(os.path.join(self.datadir, yb.STAGING)))
        self.assertFalse(os.path.exists(os.path.join(self.datadir, "main.bootstrap-incomplete")))

    def marker(self):
        return read_text(os.path.join(self.datadir, "main.bootstrap-incomplete"))

    def assert_refused(self, code, err, text):
        self.assertEqual(code, 2, err)
        self.assertIn(text, err)
        self.assertIn(text, self.marker())                                 # chunk 8's marker, with the reason
        for top in yb.STATE_TOP_DIRS + (yb.STAGING,):
            self.assertFalse(os.path.exists(os.path.join(self.datadir, top)), top)
        self.assertFalse(os.path.exists(os.path.join(self.datadir, "bootstrap-work", "import.conf")))

    def test_three_parts_from_latest_restore_the_same_state_with_one_part_of_disk(self):
        out, m = self.bundle()
        self.assertEqual(len(m["parts"]), 3)
        base = self.serve(drop={m["parts"][1]["name"]})                   # the first answer for part 1 breaks off halfway
        code, err = self.restore(base + "latest/")
        self.assertEqual(code, 0, err)
        self.assert_restored(self.files)
        record = load_json(os.path.join(self.datadir, "bootstrap.json"))
        self.assertEqual((record["format"], record["parts"], record["signed"], record["height"]), ("ycash-state/3", 3, True, MAIN_H))
        self.assertTrue(record["source"].endswith("/main/%d/" % MAIN_H))     # latest/ named the height only
        self.assertEqual([r for r, _ in self.requests("latest/manifest.json")], [None])
        part1 = self.requests(m["parts"][1]["name"])
        self.assertEqual(len(part1), 2)
        self.assertEqual(part1[1][0], "bytes=%d-" % (m["parts"][1]["bytes"] // 2))   # resumed, not fetched again
        held = [h for rel, _, h in self.server.log]
        self.assertLessEqual(max(held), m["part_bytes"])                # never more than one part on disk
        args = load_json(os.path.join(self.datadir, "fake-args.json"))
        for flag in ("-connect=0", "-listen=0", "-dnsseed=0"):
            self.assertIn(flag, args)
        self.assertFalse(any(a in ("-regtest", "-testnet") for a in args))   # mainnet: no network flag
        self.assertEqual(load_json(os.path.join(self.datadir, "fake-conf-mode.json")), 0o600)
        self.assertIn("-P", read_text(self.minisign + ".args"))

    def test_the_one_file_v2_bundle_restores_the_same_state(self):
        out, m = self.bundle(fmt="ycash-state/2")
        self.assertNotIn("parts", m)
        code, err = self.restore(out)                                      # a local directory
        self.assertEqual(code, 0, err)
        self.assert_restored(self.files)
        self.assertEqual(load_json(os.path.join(self.datadir, "bootstrap.json"))["parts"], 1)

    def test_a_local_latest_directory_is_rebased(self):
        self.bundle()
        code, err = self.restore(os.path.join(self.root, "latest"))
        self.assertEqual(code, 0, err)
        self.assert_restored(self.files)

    def test_rollback_and_the_v2_fields_are_compared(self):
        self.bundle(top=MAIN_H + 1)
        code, err = self.restore(self.serve() + "latest/")
        self.assertEqual(code, 0, err)
        state = load_json(os.path.join(self.datadir, "chainstate", "fake-state.json"))
        self.assertEqual(state["calls"], ["invalidateblock", "reconsiderblock"])
        shutil.rmtree(os.path.join(self.tmp, "bucket"))
        shutil.rmtree(self.datadir)
        self.bundle(statement=dict(self.statement, finalsaplingroot="ee" * 32))
        code, err = self.restore(self.serve() + "latest/")
        self.assert_refused(code, err, "disagrees with the statements")
        self.assertIn("finalsaplingroot", err)

    def capture_staging(self):
        """Record what the staging directory holds when a part is refused."""
        seen, real = {}, yb.fetch_part

        def fetch(*a, **kw):
            try:
                return real(*a, **kw)
            except yb.BundleError:
                staging = os.path.join(self.datadir, yb.STAGING)
                for dirpath, _, names in os.walk(staging):
                    for n in names:
                        with open(os.path.join(dirpath, n), "rb") as f:
                            seen["main/" + os.path.relpath(os.path.join(dirpath, n), staging).replace(os.sep, "/")] = f.read()
                raise
        yb.fetch_part = fetch
        self.addCleanup(setattr, yb, "fetch_part", real)
        return seen

    def test_a_corrupted_part_is_refused_before_it_is_extracted(self):
        out, m = self.bundle()
        with open(os.path.join(out, m["parts"][1]["name"]), "r+b") as f:
            f.seek(100)
            b = f.read(1)
            f.seek(100)
            f.write(bytes([b[0] ^ 1]))
        seen = self.capture_staging()
        code, err = self.restore(self.serve() + "latest/")
        self.assert_refused(code, err, "(twice)")
        self.assertEqual([r for r, _ in self.requests(m["parts"][1]["name"])], [None, None])   # fetched again from 0, once
        self.assertEqual(self.requests(m["parts"][2]["name"]), [])
        self.assertTrue(seen)                                              # part 0's entries were extracted ...
        for name, data in seen.items():                                    # ... and nothing but verified bytes
            self.assertTrue(self.files[name].startswith(data), name)
        self.assertLess(len(seen), len(self.files))

    def test_a_missing_part(self):
        out, m = self.bundle()
        os.remove(os.path.join(out, m["parts"][2]["name"]))
        code, err = self.restore(self.serve() + "latest/")
        self.assert_refused(code, err, "%s: HTTP 404" % m["parts"][2]["name"])

    def test_a_truncated_last_part(self):
        out, m = self.bundle()
        with open(os.path.join(out, m["parts"][2]["name"]), "r+b") as f:
            f.truncate(m["parts"][2]["bytes"] - 10)
        code, err = self.restore(self.serve() + "latest/")
        self.assert_refused(code, err, "shorter than the %d bytes" % m["parts"][2]["bytes"])

    def test_a_full_disk_is_refused_at_once_not_retried(self):
        import builtins, errno
        from unittest import mock
        out, m = self.bundle()
        first = m["parts"][1]["name"]

        class Full:                                                        # the disk fills while part 1 is written
            def __init__(self, f): self.f = f
            def __enter__(self): return self
            def __exit__(self, *a): self.f.close()
            def write(self, b): raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

        def full_open(path, mode="r", *a, **kw):
            f = builtins.open(path, mode, *a, **kw)
            return Full(f) if str(path).endswith(first + ".part") and mode in ("wb", "ab") else f
        with mock.patch.object(yb, "open", full_open, create=True):
            code, err = self.restore(self.serve() + "latest/")
        self.assert_refused(code, err, "no space left on the disk")
        self.assertNotIn("broke off", err)
        self.assertEqual(len(self.requests(first)), 1)                    # not retried as a broken connection

    def test_a_server_sending_more_than_a_part(self):
        out, m = self.bundle()
        with open(os.path.join(out, m["parts"][0]["name"]), "ab") as f:
            f.write(b"more")
        code, err = self.restore(self.serve() + "latest/")
        self.assert_refused(code, err, "sends more than")

    def test_keep_parts_lets_a_rerun_read_them_locally(self):
        out, m = self.bundle()
        last = os.path.join(out, m["parts"][2]["name"])
        os.rename(last, last + ".away")
        base = self.serve()
        code, err = self.restore(base + "latest/", "--keep-parts")
        self.assertEqual(code, 2, err)
        os.rename(last + ".away", last)
        code, err = self.restore(base + "latest/", "--keep-parts")
        self.assertEqual(code, 0, err)
        self.assert_restored(self.files)
        for p in m["parts"][:2]:
            self.assertEqual(len(self.requests(p["name"])), 1, p["name"])  # read from work/ on the re-run

    def test_a_signature_is_required_on_mainnet(self):
        out, m = self.bundle(signed=False)
        code, err = self.restore(self.serve() + "latest/")
        self.assert_refused(code, err, "not signed (SHA256SUMS.minisig: HTTP 404)")
        self.assertIn("a mainnet restore needs one", err)
        self.assertNotIn("--allow-unsigned accepts", err)                  # no way round it is offered
        self.assertEqual(self.requests(m["parts"][0]["name"]), [])

    def test_allow_unsigned_is_refused_on_mainnet(self):
        """The coordinator's ruling on review finding M-3: a mainnet restore is always signed."""
        out, m = self.bundle(signed=False)
        base = self.serve()
        with self.assertRaises(SystemExit) as cm:
            self.restore(base + "latest/", "--allow-unsigned")
        self.assertIn("--allow-unsigned is refused on mainnet", str(cm.exception))
        self.assertEqual(self.server.log, [])                              # refused before any request
        self.assertFalse(os.path.exists(os.path.join(self.datadir, "main.bootstrap-incomplete")))
        args = argparse.Namespace(require_signature=False, allow_unsigned=True, key=yb.DEFAULT_KEY, minisign=self.minisign)
        source = yb.Source(base + "%d/" % MAIN_H)                          # and check_signature never takes it there
        os.makedirs(self.datadir)
        sums = os.path.join(self.datadir, "SHA256SUMS")
        source.fetch("SHA256SUMS", sums)
        with self.assertRaises(yb.BundleError) as cm:
            yb.check_signature(source, sums, args, yb.main_profile(), True, False, "")
        self.assertIn("a mainnet restore needs one", str(cm.exception))

    def test_a_v2_bundle_restores_over_http(self):
        out, m = self.bundle(fmt="ycash-state/2")
        code, err = self.restore(self.serve() + "latest/")
        self.assertEqual(code, 0, err)
        self.assert_restored(self.files)
        self.assertEqual([r for r, _ in self.requests(m["tarball"])], [None])   # one part: the tarball, fetched once
        record = load_json(os.path.join(self.datadir, "bootstrap.json"))
        self.assertEqual((record["format"], record["parts"], record["signed"]), ("ycash-state/2", 1, True))
        self.assertTrue(record["source"].endswith("/main/%d/" % MAIN_H))

    def test_without_a_node_the_last_line_says_the_check_was_skipped(self):
        self.bundle()
        argv = ["--network", "main", "--datadir", self.datadir, "--source", self.serve() + "latest/", "--ycashd", "", "--cli", "",
                "--minisign", self.minisign, "--retry-wait", "0"]
        with contextlib.redirect_stderr(io.StringIO()) as err, contextlib.redirect_stdout(io.StringIO()) as out:
            code = yb.main(argv)
        self.assertEqual(code, 0, err.getvalue())
        self.assert_restored(self.files)
        last = out.getvalue().strip().splitlines()[-1]
        self.assertIn("the node check was SKIPPED (no --ycashd/--cli)", last)
        self.assertEqual(load_json(os.path.join(self.datadir, "bootstrap.json"))["check"], "skipped: no --ycashd/--cli")

    def test_the_disk_check_estimates_a_v2_datadir_at_one_and_a_half_times_the_tarball(self):
        """The published 3,100,949 bundle unpacks to 56.1 GB from 41.8 GB: the tarball's size is not an estimate."""
        os.makedirs(self.datadir)
        args = argparse.Namespace(datadir=self.datadir, keep_parts=False)
        work = os.path.join(self.datadir, "bootstrap-work")
        real = yb.shutil.disk_usage
        self.addCleanup(setattr, yb.shutil, "disk_usage", real)
        size, part = 41_800_000_000, 41_800_000_000
        v2 = {"format": "ycash-state/2", "bytes": size}
        for free, ok in ((size + part + yb.GIB, False), (size * 3 // 2 + part + yb.GIB - 1, False), (size * 3 // 2 + part + yb.GIB, True)):
            yb.shutil.disk_usage = lambda path, free=free: real(path)._replace(free=free)
            with self.subTest(free=free):
                if ok:
                    yb.check_disk(args, v2, part, work)
                else:
                    with self.assertRaises(yb.BundleError) as cm:
                        yb.check_disk(args, v2, part, work)
                    self.assertIn("the datadir 62.7 GB", str(cm.exception))
        v3 = {"format": "ycash-state/3", "bytes": size, "unpacked_bytes": 56_100_000_000}  # unpacked_bytes when it is there
        yb.shutil.disk_usage = lambda path: real(path)._replace(free=56_100_000_000 + yb.GIB + yb.GIB - 1)
        with self.assertRaises(yb.BundleError) as cm:
            yb.check_disk(args, v3, yb.GIB, work)
        self.assertIn("the datadir 56.1 GB", str(cm.exception))
        yb.shutil.disk_usage = lambda path: real(path)._replace(free=56_100_000_000 + yb.GIB + yb.GIB)
        yb.check_disk(args, v3, yb.GIB, work)

    def test_the_marker_and_its_directory_are_fsynced(self):
        os.makedirs(self.datadir)
        synced, real = [], yb.os.fsync

        def fsync(fd):
            st = os.fstat(fd)
            synced.append((st.st_dev, st.st_ino))
            return real(fd)
        yb.os.fsync = fsync
        self.addCleanup(setattr, yb.os, "fsync", real)
        args = argparse.Namespace(datadir=self.datadir, network="main")
        yb.write_marker(args, self.datadir, "started")
        marker = os.stat(os.path.join(self.datadir, "main.bootstrap-incomplete"))
        directory = os.stat(self.datadir)
        self.assertEqual(synced, [(marker.st_dev, marker.st_ino), (directory.st_dev, directory.st_ino)])
        self.assertFalse(os.path.exists(os.path.join(self.datadir, "main.bootstrap-incomplete.part")))

    def server_url(self):
        return "http://127.0.0.1:%d/main/" % self.server.server_address[1]

    def test_not_enough_disk_is_refused_before_a_part_is_fetched(self):
        out, m = self.bundle()
        real = yb.shutil.disk_usage
        yb.shutil.disk_usage = lambda path: real(path)._replace(free=m["unpacked_bytes"])
        self.addCleanup(setattr, yb.shutil, "disk_usage", real)
        code, err = self.restore(self.serve() + "latest/")
        self.assert_refused(code, err, "not enough disk")
        self.assertEqual(self.requests(".000"), [])

    def test_pins_and_formats_are_this_releases(self):
        pins = dict(MAIN_PINS, **{"570000": "ff" * 32})
        self.bundle(pins=pins)
        code, err = self.restore(self.serve() + "latest/")
        self.assert_refused(code, err, "manifest pin 570000")
        shutil.rmtree(os.path.join(self.tmp, "bucket"))
        self.bundle(format="ycash-state/4")
        code, err = self.restore(self.server_url() + "latest/")
        self.assert_refused(code, err, "expected one of ycash-state/1, ycash-state/2, ycash-state/3")

    def test_latest_must_name_the_height_it_points_to(self):
        self.bundle()
        with open(os.path.join(self.root, "latest", "manifest.json"), "w") as f:
            f.write(yb.canonical({"height": MAIN_H}))
        os.rename(os.path.join(self.root, str(MAIN_H)), os.path.join(self.root, "580000"))
        with open(os.path.join(self.root, "latest", "manifest.json"), "w") as f:
            f.write(yb.canonical({"height": 580000}))
        code, err = self.restore(self.serve() + "latest/")
        self.assert_refused(code, err, "latest/ names height 580000")

    def test_regtest_in_parts_restores_into_its_subdirectory(self):
        statement = dict(self.statement, network="regtest", height=200, blockhash="%064x" % 200)
        files = state_files("regtest", 200, statement=statement)
        out = os.path.join(self.tmp, "rt")
        write_state_bundle(out, files, "regtest", 200, "%064x" % 200, {}, statement=statement, signed=False)
        code, err = self.restore(out, network="regtest")                  # a local directory: no signature needed
        self.assertEqual(code, 0, err)
        for name, data in files.items():
            with open(os.path.join(self.datadir, *name.split("/")), "rb") as f:
                self.assertEqual(f.read(), data)
        self.assertTrue(os.path.isfile(os.path.join(self.datadir, "regtest", "bootstrap.json")))

    def test_mainnet_takes_a_state_bundle_only(self):
        for extra in (("--prefix",), ("--reset",)):
            argv = ["--network", "main", "--datadir", self.datadir, "--source", "https://example.invalid/main/latest/"] + list(extra)
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                yb.main(argv)
        self.assertFalse(os.path.exists(os.path.join(self.datadir, "main.bootstrap-incomplete")))


class MainnetPinsTest(unittest.TestCase):
    """The tool's MAINNET_PINS against this tree's src/chainparams.cpp (CMainParams): every compiled
    checkpoint, the genesis block, the Ycash fork block and, where this line compiles it, the
    chain-supply checkpoint block."""

    def test_the_pins_are_this_trees_compiled_ones(self):
        path = os.path.join(HERE, "..", "..", "src", "chainparams.cpp")
        if not os.path.isfile(path):
            self.skipTest("no src/chainparams.cpp beside contrib/")
        text = read_text(path)
        body = text[text.index("class CMainParams"):text.index("class CTestNetParams")]
        compiled = {int(h): x for h, x in re.findall(r'\(\s*(\d+),\s*uint256S\("0x([0-9a-f]{64})"\)\)', body)}
        self.assertGreaterEqual(len(compiled), 10)
        for height, value in compiled.items():
            self.assertEqual(yb.MAINNET_PINS.get(height), value, height)
        self.assertIn('hashGenesisBlock == uint256S("0x%s")' % yb.MAINNET_PINS[0], body)
        self.assertIn('uint256S("%s")' % yb.MAINNET_PINS[570000], body)          # UPGRADE_YCASH.hashActivationBlock
        supply = re.search(r'hashChainSupplyCheckpointBlock = uint256S\("([0-9a-f]{64})"\)', body)
        if supply:
            self.assertEqual(supply.group(1), yb.MAINNET_PINS[2800000])
        self.assertEqual(set(yb.MAINNET_PINS) - set(compiled), {0, 570000, 2800000})

class HardeningTest(RestoreTest):
    """The item 8 review's LOW findings."""

    def test_conf_and_datadir_in_node_arg_are_refused(self):
        for flag in ("-conf=/etc/ycash.conf", "--conf=/x", "-datadir=/tmp/elsewhere"):
            with self.subTest(flag=flag), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
                self.run_restore("--node-arg=%s" % flag)
            self.assertIn("--conf", str(cm.exception))
        self.assertFalse(os.path.exists(self.marker()))

    def test_import_conf_is_a_new_0600_file_and_is_removed(self):
        work = os.path.join(self.datadir, "bootstrap-work")
        os.makedirs(work)
        old = os.path.join(work, "import.conf")
        with open(old, "w") as f:
            f.write("left behind\n")
        os.chmod(old, 0o640)                                               # a leftover readable by more than its owner
        with open(os.path.join(self.datadir, "ycash.conf"), "w") as f:
            f.write("rpcpassword=secret\n")
        path = yb.import_conf(type("A", (), {"conf": None, "datadir": self.datadir})(), work)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertIn("rpcpassword=secret", read_text(path))
        os.environ["FAKE_REFUSE_HEIGHT"] = "5"                             # a failed import ...
        try:
            code, err = self.run_restore()
        finally:
            del os.environ["FAKE_REFUSE_HEIGHT"]
        self.assertEqual(code, 2)
        self.assertTrue(os.path.isdir(work))
        self.assertFalse(os.path.exists(old))                             # ... leaves no copy of the password
        code, err = self.run_restore("--keep")                             # nor does a kept work directory
        self.assertEqual(code, 0, err)
        self.assertFalse(os.path.exists(old))

    def test_an_unpinned_public_prefix_needs_a_signature(self):
        self.profile["node"]["private"] = False
        code, err = self.run_restore("--allow-unpinned")
        self.assertEqual(code, 2)
        self.assertIn("an unpinned prefix needs one", err)
        code, err = self.run_restore("--allow-unpinned", "--allow-unsigned")
        self.assertEqual(code, 0, err)

    def test_a_state_bundle_over_http_needs_a_signature(self):
        why = yb.signature_required(args_for(), ybprofile.load("testnet-yb-fast"), yb.Source("https://example.invalid/b/"), True, False)
        self.assertEqual(why, ["a state bundle over http(s) needs one"])
        self.assertEqual(yb.signature_required(args_for(), ybprofile.load("testnet-yb-fast"), yb.Source(self.tmp), True, False), [])

if __name__ == "__main__":
    unittest.main()
