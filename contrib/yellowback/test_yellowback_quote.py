#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Unit tests for the yellowback-quote daemon (plan §5, L5, M9).

No node: the RPC client is a recording fake injected through
main(node_factory=...) / QuoteAgent(node=...), and the feed is either a
stub or the real PriceFeed in --mock-price mode.

Run:  python3 -m unittest contrib/yellowback/test_yellowback_quote.py
"""

import contextlib
import importlib.machinery
import importlib.util
import io
import logging
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_loader = importlib.machinery.SourceFileLoader("yellowback_quote", os.path.join(HERE, "yellowback-quote"))
_spec = importlib.util.spec_from_loader("yellowback_quote", _loader)
yq = importlib.util.module_from_spec(_spec)
_loader.exec_module(yq)
yp = yq.yp

SAMPLE = os.path.join(HERE, "pool", "yellowback-quote.toml.sample")

MINIMAL = """
[node]
rpc_url = "http://127.0.0.1:18232"
rpc_user = "u"
rpc_password = "p"
[quote]
poll_seconds = 1
fail_polls = 2
min_sources = 1
min_venues = 1
[[sources]]
name = "nowhere"
kind = "generic"
url = "http://127.0.0.1:1/never"
path = "price"
"""


class FakeNode:
    """Records yed_setquote calls; `fail` makes the next call(s) raise; `network` is yed_getinfo's."""

    def __init__(self, network="regtest"):
        self.calls = []
        self.fail = None          # an exception instance to raise, or None
        self.network = network

    def call(self, method, *params):
        self.calls.append((method,) + params)
        if self.fail is not None:
            e, self.fail = self.fail, None
            raise e
        if method == "yed_getinfo":
            return {"network": self.network, "height": 100}
        micro, mask = params
        return {"priceMicroUsd": micro, "sourceMask": mask, "receivedAt": 1_788_673_100,
                "nextTag": {"kind": "quote" if micro else "signal", "signal": True, "payoutAddress": "s1test"}}

    def setquotes(self):
        return [c[1:] for c in self.calls if c[0] == "yed_setquote"]


class StubFeed:
    """A feed whose aggregate is scripted per poll."""

    def __init__(self, script):
        self.script = list(script)
        self.mock_file = None
        self.settings = dict(yp.FEED_DEFAULTS)
        self.sources = []

    def poll(self, force=False):
        self.current = self.script.pop(0) if self.script else None

    def aggregate(self):
        return self.current

    def report(self):
        return {"live_sources": 0 if self.current is None else 3, "live_venues": 0 if self.current is None else 2}


def write(path, text, mode=0o600):
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)            # the configs here hold rpc_password; the agent refuses 0644 (D-7)


class AgentTests(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_publishes_every_good_poll(self):
        node = FakeNode()
        agent = yq.QuoteAgent(StubFeed([(432007, 0b1011, ["a", "b", "c"]), (432100, 0b0011, ["a", "b"])]), node)
        self.assertEqual(agent.poll(), "published")
        self.assertEqual(agent.poll(), "published")
        self.assertEqual(node.setquotes(), [(432007, 0b1011), (432100, 0b0011)])
        self.assertEqual(agent.published, (432100, 0b0011))

    def test_clears_after_fail_polls(self):
        # Rule: L5 clear after two failed polls
        node = FakeNode()
        good = (432007, 0b1011, ["a", "b", "c"])
        agent = yq.QuoteAgent(StubFeed([good, None, None, None, good]), node, fail_polls=2)
        self.assertEqual(agent.poll(), "published")
        self.assertEqual(agent.poll(), "failed")                 # 1 of 2: nothing sent, the node keeps the quote
        self.assertEqual(node.setquotes(), [(432007, 0b1011)])
        self.assertEqual(agent.poll(), "cleared")                # 2 of 2: yed_setquote 0
        self.assertEqual(node.setquotes()[-1], (0, 0))
        self.assertIsNone(agent.published)
        self.assertEqual(agent.poll(), "failed")                 # 3rd failure: the clear is not repeated
        self.assertEqual(len(node.setquotes()), 2)
        self.assertEqual(agent.poll(), "published")              # resume on the next good aggregate
        self.assertEqual(node.setquotes()[-1], (432007, 0b1011))
        self.assertEqual(agent.failures, 0)

    def test_fail_polls_one_clears_immediately(self):
        node = FakeNode()
        agent = yq.QuoteAgent(StubFeed([None]), node, fail_polls=1)
        self.assertEqual(agent.poll(), "cleared")
        self.assertEqual(node.setquotes(), [(0, 0)])

    def test_rpc_failure_is_retried_not_fatal(self):
        # Rule: §5 RPC failure: logged, retried next poll, never exits
        node = FakeNode()
        good = (432007, 0b1011, ["a"])
        agent = yq.QuoteAgent(StubFeed([good, good, good]), node)
        node.fail = ConnectionRefusedError("connection refused")
        self.assertEqual(agent.poll(), "rpc-error")
        self.assertIsNone(agent.published)
        node.fail = yp.RpcError(-32603, "yellowback-unhealthy")
        self.assertEqual(agent.poll(), "rpc-error")
        self.assertEqual(agent.poll(), "published")
        self.assertEqual(len(node.setquotes()), 3)

    def test_clear_is_retried_until_acknowledged(self):
        # Rule: L5 (a lost `yed_setquote 0` is owed until the node takes it)
        node = FakeNode()
        agent = yq.QuoteAgent(StubFeed([None, None, None, (5000, 0, ["a"])]), node, fail_polls=2)
        agent.poll()
        node.fail = OSError("timed out")
        self.assertEqual(agent.poll(), "rpc-error")
        self.assertTrue(agent.pending_clear)
        self.assertEqual(agent.poll(), "cleared")
        self.assertEqual(node.setquotes(), [(0, 0), (0, 0)])
        self.assertEqual(agent.poll(), "published")
        self.assertFalse(agent.pending_clear)

    def test_dry_run_makes_no_rpc(self):
        node = FakeNode()
        agent = yq.QuoteAgent(StubFeed([(432007, 0b1011, ["a"]), None, None]), node, fail_polls=2, dry_run=True)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(agent.poll(), "dry-run")
            self.assertEqual(agent.poll(), "dry-run")
            self.assertEqual(agent.poll(), "dry-run")
        self.assertEqual(node.calls, [])
        self.assertIn('"priceMicroUsd": 432007', out.getvalue())
        self.assertIn('"aggregate": null', out.getvalue())


class MainTests(unittest.TestCase):
    """The CLI contract: exit codes, --once, --dry-run, --mock-price, configuration errors."""

    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.tmp = tempfile.TemporaryDirectory()
        self.conf = os.path.join(self.tmp.name, "quote.toml")
        self.mock = os.path.join(self.tmp.name, "price")
        write(self.conf, MINIMAL)
        write(self.mock, "0.05\n")
        self.node = FakeNode()

    def tearDown(self):
        self.tmp.cleanup()
        logging.disable(logging.NOTSET)

    def run_main(self, *argv, node=None):
        node = self.node if node is None else node
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = yq.main(list(argv), node_factory=lambda cfg: node)
        return code, out.getvalue()

    def test_once_publishes_mock_price(self):
        # Rule: §5 --once exit 0 on a published quote
        code, _ = self.run_main("--conf", self.conf, "--once", "--mock-price", self.mock)
        self.assertEqual(code, 0)
        self.assertEqual(self.node.setquotes(), [(50000, 0)])

    def test_once_exit_1_without_aggregate(self):
        # Rule: §5 --once exit 1 otherwise
        write(self.mock, "")
        code, _ = self.run_main("--conf", self.conf, "--once", "--mock-price", self.mock)
        self.assertEqual(code, 1)
        self.assertEqual(self.node.setquotes(), [])               # one failure < fail_polls: nothing sent
        self.node.fail = ConnectionRefusedError("refused")
        write(self.mock, "0.05")
        code, _ = self.run_main("--conf", self.conf, "--once", "--mock-price", self.mock)
        self.assertEqual(code, 1)                                 # RPC failure (at the network check): not published
        self.assertEqual(self.node.setquotes(), [])
        self.node.fail = ConnectionRefusedError("refused")
        code, _ = self.run_main("--conf", self.conf, "--once", "--mock-price", self.mock, "--i-know-this-is-not-regtest")
        self.assertEqual(code, 1)                                 # RPC failure at yed_setquote: not published

    def test_once_real_sources_unreachable(self):
        # the MINIMAL config's only source points at nothing: no aggregate, exit 1, no RPC
        code, _ = self.run_main("--conf", self.conf, "--once")
        self.assertEqual(code, 1)
        self.assertEqual(self.node.calls, [])

    def test_dry_run(self):
        # Rule: §5 --dry-run aggregate and print, no RPC
        code, out = self.run_main("--conf", self.conf, "--dry-run", "--mock-price", self.mock)
        self.assertEqual(code, 0)
        self.assertEqual(yq.json.loads(out), {"priceMicroUsd": 50000, "priceUsd": 0.05, "sourceMask": 0, "sources": ["mock"]})
        self.assertEqual(self.node.calls, [])
        write(self.mock, "garbage")
        code, out = self.run_main("--conf", self.conf, "--dry-run", "--mock-price", self.mock)
        self.assertEqual(code, 1)
        self.assertIsNone(yq.json.loads(out)["aggregate"])

    def test_dry_run_needs_no_rpc_url(self):
        write(self.conf, MINIMAL.replace('rpc_url = "http://127.0.0.1:18232"\n', ""))
        code, _ = self.run_main("--conf", self.conf, "--dry-run", "--mock-price", self.mock)
        self.assertEqual(code, 0)
        with contextlib.redirect_stdout(io.StringIO()):                       # the real factory needs rpc_url
            self.assertEqual(yq.main(["--conf", self.conf, "--once", "--mock-price", self.mock]), 2)

    def test_sample_config_dry_run(self):
        # the Phase 7 acceptance line, in-process
        code, out = self.run_main("--conf", SAMPLE, "--dry-run", "--mock-price", self.mock)
        self.assertEqual(code, 0)
        self.assertEqual(yq.json.loads(out)["priceMicroUsd"], 50000)

    def test_bad_configuration_exits_2(self):
        # Rule: §5 the exit code is non-zero only for a bad configuration
        cases = [
            "[node]\nrpc_url = 1\n[[sources]]\nname='a'\n",                                     # source without url/path
            MINIMAL + "\n[quote]\n",                                                            # duplicate table: TOML error
            MINIMAL.replace("fail_polls = 2", "fail_polls = 0"),
            MINIMAL.replace("min_sources = 1", "min_sources = 0"),
            MINIMAL + "\n[extra]\nx = 1\n",
            MINIMAL.replace('rpc_user = "u"', 'rpc_user = "u"\nrpc_cookie = "/x"'),             # both auth forms
            MINIMAL.replace('rpc_user = "u"\n', ""),                                            # password without user
            MINIMAL + '\n[[sources]]\nname = "dup"\nurl = "u"\npath = "p"\n[[sources]]\nname = "dup"\nurl = "u"\npath = "p"\n',
            MINIMAL + '\n[[sources]]\nname = "m"\nurl = "u"\npath = "p"\nmask_bit = 99\n',
        ]
        for text in cases:
            write(self.conf, text)
            code, _ = self.run_main("--conf", self.conf, "--once", "--mock-price", self.mock)
            self.assertEqual(code, 2, msg=text)
        code, _ = self.run_main("--conf", os.path.join(self.tmp.name, "missing.toml"), "--once")
        self.assertEqual(code, 2)

    def test_config_contract(self):
        cfg = yq.load_config(self.conf)
        self.assertEqual(cfg["node"], {"rpc_url": "http://127.0.0.1:18232", "rpc_user": "u", "rpc_password": "p"})
        self.assertEqual((cfg["quote"]["poll_seconds"], cfg["quote"]["fail_polls"], cfg["quote"]["twap_seconds"]), (1, 2, 900))
        self.assertEqual(cfg["sources"][0]["venue"], "nowhere")
        node = yq.make_node(cfg["node"])
        self.assertEqual((node.url, node.auth), ("http://127.0.0.1:18232", yp.base64.b64encode(b"u:p").decode()))
        cookie = os.path.join(self.tmp.name, ".cookie")
        write(cookie, "__cookie__:secret\n")
        node = yq.make_node({"rpc_url": "http://127.0.0.1:18232", "rpc_cookie": cookie})
        self.assertEqual(node.auth, yp.base64.b64encode(b"__cookie__:secret").decode())
        sample = yq.load_config(SAMPLE)
        self.assertEqual([yp.mask_bit_for(s) for s in sample["sources"]], [1, 0, 3])
        self.assertEqual(len(sample["btc_usd_sources"]), 3)

    def test_loop_polls_and_stops(self):
        # the daemon loop: an injected sleep raises the stop signal after two polls
        write(self.mock, "0.05")
        polls = []

        def sleep(delay):
            polls.append(delay)
            if len(polls) == 2:
                raise yq._Stop()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = yq.main(["--conf", self.conf, "--mock-price", self.mock], node_factory=lambda cfg: self.node, sleep=sleep)
        self.assertEqual(code, 0)
        self.assertEqual(self.node.setquotes(), [(50000, 0), (50000, 0)])
        self.assertTrue(all(0 < d <= 1 for d in polls))

    def test_mock_price_is_regtest_only(self):
        # Rule: audit D-11 -- the mock file is never pushed on a network other than regtest
        for network in ("main", "test"):
            node = FakeNode(network)
            code, _ = self.run_main("--conf", self.conf, "--once", "--mock-price", self.mock, node=node)
            self.assertEqual(code, 2, network)
            self.assertEqual(node.setquotes(), [])
            self.assertEqual([c[0] for c in node.calls], ["yed_getinfo"])
            code, _ = self.run_main("--conf", self.conf, "--once", "--mock-price", self.mock,
                                    "--i-know-this-is-not-regtest", node=node)
            self.assertEqual(code, 0, network)
            self.assertEqual(node.setquotes(), [(50000, 0)])
        # a node that cannot be asked: --once gives up (1); the daemon keeps asking until it answers
        node = FakeNode()
        node.fail = ConnectionRefusedError("refused")
        code, _ = self.run_main("--conf", self.conf, "--once", "--mock-price", self.mock, node=node)
        self.assertEqual((code, node.setquotes()), (1, []))
        node = FakeNode()
        node.fail = ConnectionRefusedError("refused")
        polls = []

        def sleep(delay):
            polls.append(delay)
            if len(polls) == 3:
                raise yq._Stop()
        with contextlib.redirect_stdout(io.StringIO()):
            code = yq.main(["--conf", self.conf, "--mock-price", self.mock], node_factory=lambda cfg: node, sleep=sleep)
        self.assertEqual(code, 0)
        self.assertEqual(node.setquotes(), [(50000, 0), (50000, 0)])   # one retry of yed_getinfo, then two polls
        # --dry-run never asks the node; the sources path does not involve the mock
        code, _ = self.run_main("--conf", self.conf, "--dry-run", "--mock-price", self.mock, node=FakeNode("main"))
        self.assertEqual(code, 0)

    def test_config_file_permissions(self):
        # Rule: audit D-7 -- a TOML holding rpc_password must not be group/world-readable
        write(self.conf, MINIMAL, mode=0o644)
        code, _ = self.run_main("--conf", self.conf, "--once", "--mock-price", self.mock)
        self.assertEqual(code, 2)
        with self.assertRaises(yq.ConfigError) as cm:
            yq.load_config(self.conf)
        self.assertIn("chmod 600", str(cm.exception))
        self.assertTrue(yq.load_config(self.conf, insecure_permissions=True))
        code, _ = self.run_main("--conf", self.conf, "--once", "--mock-price", self.mock, "--insecure-config-permissions")
        self.assertEqual(code, 0)
        write(self.conf, MINIMAL, mode=0o640)
        self.assertEqual(self.run_main("--conf", self.conf, "--once", "--mock-price", self.mock)[0], 2)
        # a cookie-based file carries no secret of its own: any mode
        cookie = os.path.join(self.tmp.name, ".cookie")
        write(cookie, "__cookie__:secret\n")
        write(self.conf, MINIMAL.replace('rpc_user = "u"\nrpc_password = "p"\n', 'rpc_cookie = "%s"\n' % cookie), mode=0o644)
        self.assertTrue(yq.load_config(self.conf))
        # the shipped sample is cookie-based and loads as it is checked in
        self.assertTrue(yq.load_config(SAMPLE))

    def test_insecure_rpc_needs_an_explicit_opt_in(self):
        # Rule: audit D-7 -- Basic auth over plain http:// to a host that is not loopback
        for url in ("http://10.0.0.5:8832", "http://node.example:8832"):
            text = MINIMAL.replace("http://127.0.0.1:18232", url)
            write(self.conf, text)
            with self.assertRaises(yq.ConfigError) as cm:
                yq.load_config(self.conf)
            self.assertIn("cleartext", str(cm.exception))
            write(self.conf, text.replace('rpc_password = "p"\n', 'rpc_password = "p"\nallow_insecure_rpc = true\n'))
            self.assertTrue(yq.load_config(self.conf))
            write(self.conf, text.replace("http://", "https://"))
            self.assertTrue(yq.load_config(self.conf))
        write(self.conf, MINIMAL.replace("http://127.0.0.1:18232", "http://u:p@10.0.0.5:8832").replace('rpc_user = "u"\nrpc_password = "p"\n', ""))
        self.assertRaises(yq.ConfigError, yq.load_config, self.conf)
        for ok in ("http://127.0.0.1:18232", "http://localhost:18232", "http://[::1]:18232", "http://10.0.0.5:8832"):
            text = MINIMAL.replace("http://127.0.0.1:18232", ok)
            if ok.startswith("http://10."):
                text = text.replace('rpc_user = "u"\nrpc_password = "p"\n', "")   # no credentials: nothing to leak
            write(self.conf, text)
            self.assertTrue(yq.load_config(self.conf), ok)
        write(self.conf, MINIMAL.replace("http://127.0.0.1:18232", "ftp://127.0.0.1:18232"))
        self.assertRaises(yq.ConfigError, yq.load_config, self.conf)

    def test_sources_subcommand_without_network(self):
        code, out = self.run_main("sources", "--conf", self.conf)
        self.assertEqual(code, 1)
        self.assertIn("nowhere", out)
        self.assertIn("median: none", out)


if __name__ == "__main__":
    unittest.main()
