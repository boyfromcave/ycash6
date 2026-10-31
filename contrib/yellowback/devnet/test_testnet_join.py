# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Unit tests of yellowback-devnet's join mode (offline; a stand-in testnet node over JSON-RPC).

    python3 -m unittest contrib/yellowback/devnet/test_testnet_join.py

`up --network testnet-yb-fast` is run as a subprocess with a stand-in `ycashd` that serves the
RPCs join mode makes; then `status`, `check`, `wait-blocks`, the refusals and `down`. Regtest
behaviour is untouched by join mode: the devnet's functional tests (yellowback_devnet_roles.py,
yellowback_devnet_upgrade.py) keep covering it in CI.
"""

import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DEVNET = os.path.join(HERE, "yellowback-devnet")
sys.path.insert(0, HERE)
import testnet_join  # noqa: E402

HAS_ASYNCORE = importlib.util.find_spec("asyncore") is not None

FAKE_YCASHD = r'''#!%(python)s
# A stand-in testnet ycashd: reads its ycash.conf, serves a few RPCs, a block per getblockcount.
import json, os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
datadir = [a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("-datadir=")][0]
conf = dict(l.strip().split("=", 1) for l in open(os.path.join(datadir, "ycash.conf")) if "=" in l and not l.startswith("#"))
with open(os.path.join(datadir, "fake-argv.json"), "w") as f: json.dump(sys.argv[1:], f)
state = {"height": 510300, "stop": False}
PREFIX = "0000ec904003d5591290064b0b4d3ccddffe87ef2a3a131284438959bf68fb31"
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        m, p = req["method"], req.get("params") or []
        r = None
        if m == "getblockcount": state["height"] += 1; r = state["height"]
        elif m == "getblockchaininfo": r = {"chain": "test", "testnetprofile": conf["testnetprofile"], "blocks": state["height"], "headers": state["height"],
                                            "initial_block_download_complete": True, "bestblockhash": "00" * 32}
        elif m == "getconnectioncount": r = 2
        elif m == "getnewaddress": r = "tmFakeAddress"
        elif m == "getbalance": r = 0
        elif m == "vault_getinfo": r = {"activationheight": 510400, "attestorsetid": None, "moduleactive": False}
        elif m == "getblockhash": r = PREFIX if p[0] == 510247 else "%%064x" %% p[0]
        elif m == "getblock": h = int(p[0], 16); r = {"height": h, "previousblockhash": PREFIX if h == 510248 else "%%064x" %% (h - 1)}
        elif m == "stop": r = "stopping"; state["stop"] = True
        body = json.dumps({"result": r, "error": None, "id": req.get("id")}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
server = HTTPServer(("127.0.0.1", int(conf["rpcport"])), H)
while not state["stop"]: server.handle_request()
'''


def free_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class JoinTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="devnet-join-test-")
        self.dir = os.path.join(self.tmp, "devnet")
        self.ycashd = os.path.join(self.tmp, "bin", "ycashd")
        os.makedirs(os.path.dirname(self.ycashd))
        with open(self.ycashd, "w") as f:
            f.write(FAKE_YCASHD % {"python": sys.executable})
        os.chmod(self.ycashd, 0o700)

    def tearDown(self):
        subprocess.run([sys.executable, DEVNET, "down", "--dir", self.dir], capture_output=True)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def devnet(self, *argv):
        env = {k: v for k, v in os.environ.items() if k not in ("ZCASHD", "BITCOIND")}
        return subprocess.run([sys.executable, DEVNET] + list(argv) + ["--dir", self.dir], capture_output=True, text=True, env=env, timeout=120)

    def test_join_status_check_wait_down(self):
        peers = os.path.join(self.tmp, "peers.txt")
        with open(peers, "w") as f:
            f.write("# the launch operators\n203.0.113.7\n[2001:db8::1]:18833  # v6\n")
        port = free_port()
        up = self.devnet("up", "--network", "testnet-yb-fast", "--role", "user", "--bitcoind", self.ycashd, "--rpcport", str(port),
                         "--addnode", "198.51.100.2:18833", "--addnode-file", peers)
        self.assertEqual(up.returncode, 0, up.stdout + up.stderr)
        self.assertIn("fund tmFakeAddress", up.stdout)
        with open(os.path.join(self.dir, "devnet.json")) as f:
            state = json.load(f)
        self.assertEqual(state["network"], "testnet-yb-fast")
        self.assertEqual(state["peers"], ["198.51.100.2:18833", "203.0.113.7:18833", "[2001:db8::1]:18833"])
        with open(os.path.join(self.dir, "node0", "ycash.conf")) as f:
            conf = f.read()
        for line in ("testnet=1", "testnetprofile=fast", "rpcport=%d" % port, "listen=0", "addnode=203.0.113.7:18833", "txindex=1"):
            self.assertIn(line + "\n", conf)
        self.assertEqual(oct(os.stat(os.path.join(self.dir, "node0", "ycash.conf")).st_mode & 0o777), "0o600")
        with open(os.path.join(self.dir, "node0", "fake-argv.json")) as f:
            self.assertEqual(json.load(f)[1:], ["-testnet", "-testnetprofile=fast"])
        status = self.devnet("status")
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertIn("JOINED testnet-yb-fast", status.stdout)
        self.assertIn("Vault: at 510400", status.stdout)
        check = self.devnet("check")
        self.assertEqual(check.returncode, 0, check.stderr)
        wait = self.devnet("wait-blocks", "3")
        self.assertEqual(wait.returncode, 0, wait.stderr)
        for command, word in ((["mine", "5"], "wait-blocks"), (["price", "60"], "attestors' real feed"), (["heartbeat", "start"], "miners"),
                              (["sim", "start"], "term classes"), (["bridge", "status"], "regtest-only")):
            refused = self.devnet(*command)
            self.assertNotEqual(refused.returncode, 0, command)
            self.assertIn(word, refused.stderr, command)
        if HAS_ASYNCORE:              # upgrade-walk imports the framework's mininode (asyncore: Python <= 3.11, as on CI)
            self.walk_network_step()
        down = self.devnet("down")
        self.assertEqual(down.returncode, 0, down.stderr)
        self.assertIn("stopping node0", down.stdout)

    def walk_network_step(self):
        summary = os.path.join(self.tmp, "walk.json")
        walk = subprocess.run([sys.executable, os.path.join(HERE, "upgrade-walk"), "--dir", self.dir, "--summary", summary,
                               "--transcript", os.path.join(self.tmp, "walk.txt")], capture_output=True, text=True, timeout=120)
        self.assertEqual(walk.returncode, 0, walk.stdout + walk.stderr)
        with open(summary) as f:
            steps = json.load(f)["steps"]
        self.assertEqual(steps["network"], "PASS")
        self.assertTrue(steps["mint"].startswith("N/A on testnet-yb-fast"))
        self.assertIn("[claim] NOT ON testnet-yb-fast", walk.stdout)

    def test_refusals_at_up(self):
        legacy = self.devnet("up", "--network", "testnet-legacy", "--role", "attestor", "--bitcoind", self.ycashd)
        self.assertIn("no Yellowback", legacy.stderr)
        shaped = self.devnet("up", "--network", "testnet-yb-slow", "--agents", "--bitcoind", self.ycashd)
        self.assertIn("--agents", shaped.stderr)
        bad = self.devnet("up", "--network", "testnet-yb-slow", "--addnode", "not a host", "--bitcoind", self.ycashd)
        self.assertIn("not a HOST[:PORT]", bad.stderr)


class HelperTest(unittest.TestCase):
    def test_peers_and_credentials(self):
        self.assertEqual(testnet_join.parse_peers(["a.example", "b.example:1"], None, 18933), ["a.example:18933", "b.example:1"])
        creds = testnet_join.credentials("http://u:p%40ss@10.0.0.2:18832", None)
        self.assertEqual((creds["user"], creds["password"], creds["port"]), ("u", "p@ss", 18832))
        with self.assertRaises(SystemExit):
            testnet_join.credentials("http://10.0.0.2:18832", None)

    def test_network_of_defaults_to_regtest(self):
        self.assertEqual(testnet_join.network_of("/nonexistent"), "regtest")

    def test_devnet_loads(self):
        loader = importlib.machinery.SourceFileLoader("yellowback_devnet", DEVNET)
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        self.assertIs(module.testnet_join, testnet_join)


if __name__ == "__main__":
    unittest.main()
