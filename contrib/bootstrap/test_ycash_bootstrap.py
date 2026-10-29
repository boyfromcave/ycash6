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
if cmd == "getblockcount": print(tip)
elif cmd == "getblockhash": print(h(int(args[1])))
elif cmd == "getblockheader": print(json.dumps({"chainwork": "%%064x" %% (int(args[1], 16) * 3)}))
elif cmd == "gettxoutsetinfo": print(json.dumps({"hash_serialized": "utxo-%%d" %% tip}))
elif cmd == "vault_getinfo": print(json.dumps({"dbtip": {"hash": h(tip), "height": tip}, "statehash": "vault-%%d" %% tip}))
elif cmd == "yed_getstatehash": print(json.dumps({"blockhash": h(int(args[1])), "statehash": "yed-%%s" %% args[1]}))
elif cmd == "invalidateblock": st["tip"] = int(args[1], 16) - 1; st["calls"].append(cmd); json.dump(st, open(path, "w"))
elif cmd == "reconsiderblock": st["tip"] = st["top"]; st["calls"].append(cmd); json.dump(st, open(path, "w"))
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

    def test_disagreeing_node_removes_the_extracted_state(self):
        code, err = self.restore(make_state_bundle(os.path.join(self.tmp, "b"), statement_override={"utxo_hash_serialized": "other"}))
        self.assertEqual(code, 2)
        self.assertIn("disagrees with the statements", err)
        self.assertFalse(os.path.exists(os.path.join(self.datadir, "testnet-yb-fast", "chainstate")))

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


if __name__ == "__main__":
    unittest.main()
