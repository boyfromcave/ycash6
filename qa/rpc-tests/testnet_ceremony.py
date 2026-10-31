#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The launch ceremony's regtest rehearsal (testnet plan §2.2, §3.2), the same on both node lines.

`contrib/testnet/ceremony/ceremony rehearse` mines a regtest prefix, bundles it with
ycash-bootstrap, restores it into two operator nodes, runs the ceremony on them (the fork block,
the vault upgrade, the YED attestor set, seven house seats, their maturity, the record) and syncs
a fresh rc1-like node that starts with the recorded set. This test runs it for the fast profile
and for legacy (the fork alone) and checks the machine-readable record.
"""

import json
import os
import subprocess
import sys

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CEREMONY = os.path.join(REPO, "contrib", "testnet", "ceremony", "ceremony")


class TestnetCeremonyTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 0              # the rehearsal starts its own nodes
        self.setup_clean_chain = True   # v4.5.0 harness
        self.cache_behavior = 'clean'   # 6.20.0 harness (each harness ignores the other's)

    def setup_network(self, split=False):
        self.nodes = []

    def rehearse(self, profile, portseed):
        out = os.path.join(self.options.tmpdir, "rehearse-" + profile)
        binary = os.getenv("ZCASHD") or os.getenv("BITCOIND")
        run = subprocess.run([sys.executable, CEREMONY, "rehearse", "--profile", profile, "--dir", out, "--bitcoind", binary,
                              "--portseed", str(portseed)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=1800)
        print(run.stdout[-4000:])
        assert_equal(run.returncode, 0)
        with open(os.path.join(out, "ceremony-rehearsal.json")) as f:
            return json.load(f), out

    def run_test(self):
        seed = os.getpid() % 1500 + 2000
        record, out = self.rehearse("fast", seed)
        release = record["release"]
        assert_equal(record["format"], "ycash-ceremony/1")
        assert_equal(record["fork"]["height"], 51)
        assert_equal(release["UPGRADE_YCASH.hashActivationBlock"], record["fork"]["hash"])
        assert_equal(release["UPGRADE_VAULT.nActivationHeight"], 51 + 152)
        assert_equal(release["houseSeats"], 7)
        assert_equal(record["attestor_set"]["params"]["ratelimitbps"], 0)
        assert_equal(record["attestor_set"]["height"], 51 + 152)
        assert record["checkpoint"]["height"] >= max(s["height"] for s in record["house_seats"]) + record["attestor_set"]["params"]["maturity"]
        checks = record["rehearsal"]["rc1_node"]["checks"]
        assert all(checks.values()), checks
        secrets = os.listdir(os.path.join(out, "secrets"))
        assert_equal(len(secrets), 7)
        with open(os.path.join(out, "ceremony-rehearsal.json")) as f:
            assert "wif" not in f.read()

        record, _ = self.rehearse("legacy", seed + 37)
        assert_equal(record["release"]["attestorSetId"], None)
        assert_equal(record["release"]["UPGRADE_VAULT.nActivationHeight"], None)
        assert all(record["rehearsal"]["rc1_node"]["checks"].values()), record["rehearsal"]["rc1_node"]["checks"]


if __name__ == '__main__':
    TestnetCeremonyTest().main()
