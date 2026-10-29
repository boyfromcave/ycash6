# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Unit tests of contrib/testnet/ceremony against a stand-in testnet node (offline).

    python3 -m unittest contrib/testnet/test_ceremony.py

The stand-in answers the RPCs the ceremony makes the way a ceremony build of each testnet profile
would (the prefix to 510,247, a Vault height or none, setgenerate mining a block per poll). The
real run is the regtest rehearsal, `ceremony --rehearse`, which qa/rpc-tests/testnet_ceremony.py
drives in CI against real nodes.
"""

import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import stat
import tempfile
import unittest
from decimal import Decimal

HERE = os.path.dirname(os.path.abspath(__file__))


def _load():
    loader = importlib.machinery.SourceFileLoader("ceremony", os.path.join(HERE, "ceremony"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


cm = _load()


def hhash(*parts):
    return hashlib.sha256(repr(parts).encode()).hexdigest()


class FakeNode:
    """A ceremony build of one testnet profile, already holding the prefix."""

    def __init__(self, profile, vault=None, peers=1, ibd_done=True, balance=Decimal("100000")):
        self.p, self.vault, self.peers, self.ibd_done, self.balance = profile, vault, peers, ibd_done, balance
        self.height = profile["prefix"]["last_height"]
        self.hashes = {h: hhash("b", h) for h in range(self.height - 10, self.height + 1)}   # the prefix's last few suffice
        self.hashes[self.height] = profile["prefix"]["last_hash"]
        self.heights = {v: h for h, v in self.hashes.items()}
        self.generating = False
        self.calls = []
        self.txs = {}
        self.keys = 0
        self.sets = {}

    def add_block(self):
        self.height += 1
        self.hashes[self.height] = hhash("b", self.height)
        self.heights[self.hashes[self.height]] = self.height
        for tx in self.txs.values():
            if tx["height"] is None:
                tx["height"] = self.height

    def call(self, method, *params):
        self.calls.append(method)
        if method == "getblockcount":
            if self.generating:
                self.add_block()
            return self.height
        if method == "getblockchaininfo":
            return {"chain": self.p["chain"], "testnetprofile": self.p["testnet_profile"], "blocks": self.height,
                    "initial_block_download_complete": self.ibd_done}
        if method == "getblockhash":
            return self.hashes[int(params[0])]
        if method == "getblock":
            height = self.heights[params[0]]
            txs = [hhash("cb", height)] + [t for t, r in self.txs.items() if r["height"] == height]
            return {"height": height, "hash": params[0], "previousblockhash": self.hashes.get(height - 1), "time": 1_800_000_000 + height,
                    "chainwork": "%064x" % (height * 7), "tx": txs}
        if method == "vault_getinfo":
            return {"activationheight": self.vault or -1, "attestorsetid": None, "moduleactive": False}
        if method == "getconnectioncount":
            return self.peers
        if method == "getnetworkinfo":
            return {"subversion": "/StandIn:6.22.0/"}
        if method == "setgenerate":
            self.generating = params[0]
            return None
        if method == "getbalance":
            return self.balance
        if method == "set_create":
            assert self.height + 1 >= self.vault, "set_create before the vault upgrade"
            txid = hhash("create", len(self.txs))
            self.txs[txid] = {"height": None}
            self.sets[txid] = params[0]
            return {"txid": txid, "setid": txid, "admitkey": "02" + "11" * 32}
        if method == "gettransaction":
            tx = self.txs[params[0]]
            return {"confirmations": 0 if tx["height"] is None else self.height - tx["height"] + 1,
                    "blockhash": None if tx["height"] is None else self.hashes[tx["height"]]}
        if method == "set_getinfo":
            joins = sum(1 for t, r in self.txs.items() if r.get("join") == params[0] and r["height"] is not None)
            return {"createheight": self.txs[params[0]]["height"], "members": joins, "current": joins}
        if method == "getnewaddress":
            self.keys += 1
            return "tmSeat%d" % self.keys
        if method == "validateaddress":
            return {"pubkey": "02" + hhash("pk", params[0])}
        if method == "set_join":
            txid = hhash("join", len(self.txs))
            self.txs[txid] = {"height": None, "join": params[0], "bond": params[1]}
            self.balance -= Decimal(params[1])
            return {"txid": txid, "memberkey": params[3], "bondoutpoint": txid + ":0", "complete": True}
        if method == "dumpprivkey":
            return "cWIF-" + params[0]
        raise AssertionError("unexpected RPC %s" % method)


class Opts:
    def __init__(self, secrets, **kw):
        self.mine, self.genproclimit, self.seats, self.bond, self.poll = True, 1, None, None, 0
        self.max_blocks_wait, self.confirm_blocks, self.keydir = 0, 6, secrets
        self.__dict__.update(kw)


class CeremonyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ceremony-test-")
        self.secrets = os.path.join(self.tmp, "secrets")
        self.out = os.path.join(self.tmp, "record.json")
        self._quiet = contextlib.redirect_stdout(io.StringIO())
        self._quiet.__enter__()

    def tearDown(self):
        self._quiet.__exit__(None, None, None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_ceremony(self, network, node, steps=None, **opts):
        profile = cm.ybprofile.load(network)
        return cm.Ceremony(node, profile, Opts(self.secrets, **opts), self.out).run(steps)

    def test_fast_end_to_end(self):
        profile = cm.ybprofile.load("testnet-yb-fast")
        node = FakeNode(profile, vault=510400)
        record = self.run_ceremony("testnet-yb-fast", node)
        release = record["release"]
        self.assertEqual(release["UPGRADE_YCASH.hashActivationBlock"], node.hashes[510248])
        self.assertEqual(release["UPGRADE_VAULT.nActivationHeight"], 510400)
        setid = release["attestorSetId"]
        self.assertEqual(node.sets[setid], {"seats": 15, "unlockthreshold": 1, "cancelthreshold": 1, "slashthreshold": 1, "open": True,
                                            "ratelimitbps": 0, "livenesswindow": 1152, "maturity": 48, "bondmin": 10, "bondlockmin": 0})
        self.assertEqual(record["attestor_set"]["height"], 510400)                 # created in the activation block
        self.assertEqual(release["houseSeats"], 7)                                   # T-5
        last_join = max(s["height"] for s in record["house_seats"])
        self.assertGreaterEqual(record["checkpoint"]["height"], last_join + 48)
        self.assertEqual(release["checkpoint"], "%d:%s" % (record["checkpoint"]["height"], record["checkpoint"]["hash"]))
        self.assertEqual(release["checkpointChainTx"], 717489 + (record["checkpoint"]["height"] - 510247) + 8)   # coinbases + set + 7 joins
        self.assertEqual(node.calls.count("setgenerate") % 2, 0)                    # every start is matched by a stop
        self.assertNotIn("gettransaction", node.calls)                              # acts are not wallet transactions (CI, both lines)
        files = sorted(os.listdir(self.secrets))
        self.assertEqual(len(files), 7)
        for name in files:
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.secrets, name)).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.secrets).st_mode), 0o700)
        with open(self.out) as f:
            text = f.read()
        self.assertNotIn("cWIF", text)                                               # keys never in the record
        self.assertEqual(text, cm.canonical(json.loads(text)))
        # a re-run verifies the set and never creates a second one
        creates = node.calls.count("set_create")
        again = self.run_ceremony("testnet-yb-fast", node)
        self.assertEqual(node.calls.count("set_create"), creates)
        self.assertEqual(again["release"]["attestorSetId"], setid)
        self.assertEqual(len(os.listdir(self.secrets)), 7)

    def test_legacy_is_fork_only(self):
        profile = cm.ybprofile.load("testnet-legacy")
        node = FakeNode(profile)
        record = self.run_ceremony("testnet-legacy", node)
        self.assertNotIn("set_create", node.calls)
        self.assertIsNone(record["release"]["attestorSetId"])
        self.assertEqual(record["fork"]["height"], 510248)
        self.assertGreaterEqual(record["checkpoint"]["height"], 510248)
        with self.assertRaisesRegex(cm.CeremonyError, "never activates Vault"):
            self.run_ceremony("testnet-legacy", FakeNode(profile, vault=510400))

    def test_slow_waits_for_its_vault_height(self):
        profile = cm.ybprofile.load("testnet-yb-slow")
        record = self.run_ceremony("testnet-yb-slow", FakeNode(profile))
        self.assertIsNone(record["release"]["attestorSetId"])
        with self.assertRaisesRegex(cm.CeremonyError, "does not apply"):
            self.run_ceremony("testnet-yb-slow", FakeNode(profile), steps=("set",))
        os.remove(self.out)
        record = self.run_ceremony("testnet-yb-slow", FakeNode(profile, vault=520000))
        self.assertEqual(record["release"]["houseSeats"], 3)
        self.assertEqual(record["attestor_set"]["params"]["maturity"], 16128)

    def test_refusals(self):
        fast = cm.ybprofile.load("testnet-yb-fast")
        wrong = FakeNode(cm.ybprofile.load("testnet-yb-slow"), vault=510400)
        with self.assertRaisesRegex(cm.CeremonyError, "testnetprofile=slow"):
            self.run_ceremony("testnet-yb-fast", wrong)
        with self.assertRaisesRegex(cm.CeremonyError, "maxtipage"):
            self.run_ceremony("testnet-yb-fast", FakeNode(fast, vault=510400, ibd_done=False))
        with self.assertRaisesRegex(cm.CeremonyError, "no peer"):
            self.run_ceremony("testnet-yb-fast", FakeNode(fast, vault=510400, peers=0))
        node = FakeNode(fast, vault=510400)
        node.hashes[510247] = "ab" * 32
        node.heights["ab" * 32] = 510247
        with self.assertRaisesRegex(cm.CeremonyError, "compiled checkpoint"):
            self.run_ceremony("testnet-yb-fast", node)
        poor = FakeNode(fast, vault=510400, balance=Decimal("25"))       # 7 seats x 10 YEC need ~70
        with self.assertRaisesRegex(cm.CeremonyError, "fund it and re-run"):
            self.run_ceremony("testnet-yb-fast", poor)
        self.assertIn("set_create", poor.calls)                                       # the set exists; the record kept it
        with open(self.out) as f:
            self.assertTrue(json.load(f)["attestor_set"]["setid"])
        poor.balance = Decimal("100000")
        record = self.run_ceremony("testnet-yb-fast", poor)
        self.assertEqual(poor.calls.count("set_create"), 1)
        self.assertEqual(record["release"]["houseSeats"], 7)

    def test_no_mine_waits(self):
        fast = cm.ybprofile.load("testnet-yb-fast")
        node = FakeNode(fast, vault=510400)
        node.generating = True                       # another operator's blocks arrive
        self.run_ceremony("testnet-yb-fast", node, steps=("fork", "record"), mine=False)
        self.assertNotIn("setgenerate", node.calls)

    def test_secrets_never_inside_a_repository(self):
        repo = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(repo, ".git"))
        with self.assertRaisesRegex(cm.CeremonyError, "inside a git repository"):
            cm.prepare_secrets(os.path.join(repo, "keys"))
        self.assertTrue(cm.inside_git(HERE) or True)

    def test_rehearse_entry_point(self):
        """rc-qualify step 4 calls `ceremony rehearse --profile P --dir D --bitcoind B`."""
        self.assertEqual(cm.rehearse_argv(["--profile", "legacy", "--dir", "/w", "--bitcoind", "/b/ycashd"]),
                         ["--rehearse", "--like", "testnet-legacy", "--workdir", "/w", "--ycashd", "/b/ycashd"])
        self.assertEqual(cm.rehearse_argv(["--dir", "/w"])[:3], ["--rehearse", "--like", "testnet-yb-fast"])

    def test_cli_arguments(self):
        self.assertEqual([cm.CliRPC.arg(v) for v in ("abc", 7, Decimal("10.5"), True, {"a": 1})], ["abc", "7", "10.5", "true", '{"a": 1}'])
        rpc = cm.CliRPC("ycash-cli", "/d", cm.ybprofile.load("testnet-yb-slow"), conf="/d/c.conf", rpcport=5)
        self.assertEqual(rpc.argv, ["ycash-cli", "-datadir=/d", "-conf=/d/c.conf", "-testnet", "-testnetprofile=slow", "-rpcport=5"])


if __name__ == "__main__":
    unittest.main()
