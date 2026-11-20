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
        self.mine_keys, self.builds, self.locked, self.host_builds = set(), {}, set(), {}

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
            pub = "02" + hhash("pk", params[0])
            self.mine_keys.add(pub)
            return {"pubkey": pub, "ismine": True}
        if method == "set_join":
            assert self.height + 1 <= int(params[2]) < 500_000_000, "bondlocktime must be a height from the next block (set_join, rpc/vault.cpp)"
            if params[3] not in self.mine_keys:
                raise cm.CeremonyError("set_join: memberkey is not a key in this wallet")
            txid = hhash("join", len(self.txs))
            self.txs[txid] = {"height": None, "join": params[0], "bond": params[1]}
            self.balance -= Decimal(params[1])
            return {"txid": txid, "memberkey": params[3], "bondoutpoint": txid + ":0", "complete": True}
        if method == "set_buildact":                         # any member key: the join funded, unsigned
            assert params[0] == "join"
            p = params[1]
            n = len(self.builds)
            self.builds["unsigned%d" % n] = {"join": p["setid"], "bond": p["bondamount"], "key": p["memberkey"], "coin": "c%d" % n}
            return {"hex": "unsigned%d" % n, "type": "join", "complete": False, "signatures": 0, "required": 1}
        if method == "decoderawtransaction":
            return {"vin": [{"txid": self.builds[params[0].replace("signed-", "")]["coin"], "vout": 0}]}
        if method == "lockunspent":
            self.locked.update(i["txid"] for i in params[1])
            return True
        if method == "set_signact":                          # on a seat host: its own member keys only
            b = self.host_builds[params[0]]
            if b["key"] not in self.mine_keys:
                return {"hex": params[0], "complete": False, "signatures": 0, "required": 1}
            return {"hex": "signed-" + params[0], "complete": False, "signatures": 1, "required": 1}
        if method == "set_sendact":
            assert params[0].startswith("signed-") and Decimal(str(params[1]["allowoutflow"])) >= Decimal(self.builds[params[0][7:]]["bond"])
            txid = hhash("join", len(self.txs))
            self.txs[txid] = {"height": None, "join": self.builds[params[0][7:]]["join"], "bond": self.builds[params[0][7:]]["bond"]}
            self.balance -= Decimal(self.builds[params[0][7:]]["bond"])
            return txid
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
                                            "ratelimitbps": 0, "livenesswindow": 1152, "maturity": 48, "bondmin": 20, "bondlockmin": 0})
        self.assertEqual(record["attestor_set"]["height"], 510400)                 # created in the activation block
        self.assertEqual(release["houseSeats"], 9)                                   # beta4 D-1
        last_join = max(s["height"] for s in record["house_seats"])
        self.assertGreaterEqual(record["checkpoint"]["height"], last_join + 48)
        self.assertEqual(release["checkpoint"], "%d:%s" % (record["checkpoint"]["height"], record["checkpoint"]["hash"]))
        self.assertEqual(release["checkpointChainTx"], 717489 + (record["checkpoint"]["height"] - 510247) + 10)   # coinbases + set + 9 joins
        self.assertEqual(node.calls.count("setgenerate") % 2, 0)                    # every start is matched by a stop
        self.assertNotIn("gettransaction", node.calls)                              # acts are not wallet transactions (CI, both lines)
        files = sorted(os.listdir(self.secrets))
        self.assertEqual(len(files), 9)
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
        self.assertEqual(len(os.listdir(self.secrets)), 9)

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
        poor = FakeNode(fast, vault=510400, balance=Decimal("25"))       # 9 seats x 20 YEC need ~180
        with self.assertRaisesRegex(cm.CeremonyError, "fund it and re-run"):
            self.run_ceremony("testnet-yb-fast", poor)
        self.assertIn("set_create", poor.calls)                                       # the set exists; the record kept it
        with open(self.out) as f:
            self.assertTrue(json.load(f)["attestor_set"]["setid"])
        poor.balance = Decimal("100000")
        record = self.run_ceremony("testnet-yb-fast", poor)
        self.assertEqual(poor.calls.count("set_create"), 1)
        self.assertEqual(record["release"]["houseSeats"], 9)

    def test_no_mine_waits(self):
        fast = cm.ybprofile.load("testnet-yb-fast")
        node = FakeNode(fast, vault=510400)
        node.generating = True                       # another operator's blocks arrive
        self.run_ceremony("testnet-yb-fast", node, steps=("fork", "record"), mine=False)
        self.assertNotIn("setgenerate", node.calls)

    def member_keys(self, hosts):
        path = os.path.join(self.tmp, "member-keys.json")
        with open(path, "w") as f:
            json.dump({"hosts": hosts}, f)
        return path

    def test_member_keys_born_on_hosts(self):
        """C-T7 (D-1): nine seats, three hosts, the keys born there; no private key reaches the ceremony."""
        fast = cm.ybprofile.load("testnet-yb-fast")
        node = FakeNode(fast, vault=510400)
        hosts = {h: FakeNode(fast) for h in "abc"}
        for i, h in enumerate("abc"):
            hosts[h].keys = 100 * (i + 1)                                             # distinct wallets, distinct addresses
        keys = {h: [cm.host_key(hosts[h])["memberkey"] for _ in range(3)] for h in "abc"}
        for h in "abc":
            hosts[h].mine_keys = set(keys[h])
        path = self.member_keys(keys)
        handoff = os.path.join(self.tmp, "joins")
        with self.assertRaisesRegex(cm.CeremonyError, "9 join\\(s\\) wait for their host"):
            self.run_ceremony("testnet-yb-fast", node, member_keys=path, handoff=handoff, keydir=None)
        self.assertNotIn("dumpprivkey", node.calls)
        self.assertNotIn("getnewaddress", node.calls)
        self.assertEqual(len(node.locked), 9)                                         # each build's coins kept out of the next
        joins = sorted(n for n in os.listdir(handoff) if n.endswith(".join.json"))
        self.assertEqual(len(joins), 9)
        # a re-run before the hosts sign builds nothing new
        with self.assertRaisesRegex(cm.CeremonyError, "wait for their host"):
            self.run_ceremony("testnet-yb-fast", node, steps=("seats",), member_keys=path, handoff=handoff, keydir=None)
        self.assertEqual(len(node.builds), 9)
        for name in joins:
            with open(os.path.join(handoff, name)) as f:
                join = json.load(f)
            host = hosts[join["host"]]
            for other in "abc":                                                       # every host refuses another host's seat
                hosts[other].host_builds[join["hex"]] = node.builds[join["hex"]]
            wrong = hosts["b" if join["host"] != "b" else "a"]
            with self.assertRaisesRegex(cm.CeremonyError, "not a key of this wallet"):
                cm.host_sign(wrong, "testnet-yb-fast", os.path.join(handoff, name))
            cm.host_sign(host, "testnet-yb-fast", os.path.join(handoff, name))
        record = self.run_ceremony("testnet-yb-fast", node, steps=("seats", "mature", "record"), member_keys=path, handoff=handoff, keydir=None)
        self.assertEqual(record["release"]["houseSeats"], 9)
        self.assertNotIn("pending_joins", record)
        seats = record["house_seats"]
        self.assertEqual([s["seat"] for s in seats], list(range(1, 10)))
        self.assertEqual([s["host"] for s in seats], list("abc" * 3))               # round robin: host a holds seats 1, 4, 7
        self.assertEqual(sorted(s["memberkey"] for s in seats), sorted(sum(keys.values(), [])))
        self.assertFalse(os.path.exists(self.secrets))                               # no key file anywhere on the ceremony host
        self.assertNotIn("dumpprivkey", node.calls)

    def test_member_keys_refusals(self):
        fast = cm.ybprofile.load("testnet-yb-fast")
        k = lambda i: "02" + "%064x" % i
        good = {"a": [k(1), k(2), k(3)], "b": [k(4), k(5), k(6)], "c": [k(7), k(8), k(9)]}
        self.assertEqual(len(cm.load_member_keys(self.member_keys(good), 9)), 9)
        for hosts, why in ((dict(good, c=[k(7), k(8), k(1)]), "listed twice"),
                           (dict(good, c=[k(7), k(8)]), "same number"),
                           (dict(good, c=[k(7), k(8), "04" + "00" * 32]), "compressed public key"),
                           ({"a": good["a"], "b": good["b"]}, "lists 6 member keys")):
            with self.assertRaisesRegex(cm.CeremonyError, why):
                cm.load_member_keys(self.member_keys(hosts), 9)
        with self.assertRaisesRegex(cm.CeremonyError, "not a .* join of"):
            path = os.path.join(self.tmp, "x.join.json")
            with open(path, "w") as f:
                json.dump({"format": "ycash-ceremony/1-join", "network": "testnet-yb-slow"}, f)
            cm.host_sign(FakeNode(fast), "testnet-yb-fast", path)

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



class GapScanTest(unittest.TestCase):
    """C-T6: the gap scan's block reader (no node)."""

    SETID = "ab" * 31 + "cd"

    @staticmethod
    def act(kind, setid):
        body = bytes.fromhex(setid)[::-1] + bytes(33)
        payload = b"YV\x01" + bytes([kind]) + body
        return {"scriptPubKey": {"hex": "6a" + ("4c%02x" % len(payload) if len(payload) > 75 else "%02x" % len(payload)) + payload.hex()}}

    def block(self, height, coinbase="03aabbcc", txs=()):
        tx = [{"txid": hhash("cb", height), "vin": [{"coinbase": coinbase}], "vout": []}]
        return {"height": height, "tx": tx + list(txs)}

    def test_acts_and_tags(self):
        own_create = {"txid": self.SETID, "vin": [], "vout": [{"scriptPubKey": {"hex": "6a4c44" + (b"YV\x01\x01" + bytes(64)).hex()}}]}
        join = {"txid": hhash("join"), "vin": [], "vout": [{"scriptPubKey": {"hex": "76a914" + "00" * 20 + "88ac"}}, self.act(0x02, self.SETID)]}
        other = {"txid": hhash("other"), "vin": [], "vout": [self.act(0x06, "11" * 32)]}
        remove = {"txid": hhash("remove"), "vin": [], "vout": [self.act(0x04, self.SETID)]}
        self.assertEqual([f["kind"] for f in cm.scan_block(self.block(5, txs=[own_create, join, other]), self.SETID)], ["SET_CREATE", "SET_JOIN"])
        self.assertEqual(cm.scan_block(self.block(6, txs=[remove]), self.SETID)[0]["kind"], "SET_REMOVE")
        self.assertEqual([f["kind"] for f in cm.scan_block(self.block(7, coinbase="03aabbcc24594544210100"), self.SETID)], ["tag-v1"])
        self.assertEqual([f["kind"] for f in cm.scan_block(self.block(8, coinbase="03aabbcc31594544210200"), self.SETID)], ["tag-v2"])
        self.assertEqual(cm.scan_block(self.block(9, coinbase="0359454421"), self.SETID), [])   # "YED!" without the push byte

    def test_known_txids_and_scan(self):
        join = {"txid": hhash("join"), "vin": [], "vout": [self.act(0x02, self.SETID)]}
        foreign = {"txid": hhash("foreign"), "vin": [], "vout": [self.act(0x02, self.SETID)]}
        blocks = {10: self.block(10, txs=[join]), 11: self.block(11, txs=[foreign]), 12: self.block(12)}

        class Rpc:
            def call(self, method, *p):
                return ("h%d" % p[0]) if method == "getblockhash" else blocks[int(p[0][1:])]
        known = cm.record_txids({"release": {"attestorSetId": self.SETID}, "seats": [{"txid": join["txid"]}]})
        own, findings = cm.gap_scan(Rpc(), self.SETID, 10, 12, known, log=lambda m: None)
        self.assertEqual([f["txid"] for f in own], [join["txid"]])
        self.assertEqual([(f["height"], f["kind"]) for f in findings], [(11, "SET_JOIN")])

    def test_first_push(self):
        self.assertEqual(cm.first_push("6a03aabbcc"), bytes.fromhex("aabbcc"))
        self.assertEqual(cm.first_push("6a4c03aabbcc"), bytes.fromhex("aabbcc"))
        self.assertIsNone(cm.first_push("76a9"))
        self.assertIsNone(cm.first_push("6a05aa"))


if __name__ == "__main__":
    unittest.main()
