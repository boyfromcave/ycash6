#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Real pool software against the node: yolo (Rust) and a stratum miner, tag on every path
(docs/plans/role-pool-regtest-plan.md section 3.5, Y5).

Every other script mines with ``generate``, the one block-building path no Ycash pool uses.  This
one puts the block through node -> ``getblocktemplate`` -> yolo -> ``mining.notify`` ->
``contrib/yellowback/devnet/stratum-miner`` (the framework's 48,5 solver) -> ``mining.submit`` ->
``submitblock``, once per cell of yolo's two flags (owner decision P-6: no modes):

  --payout unset   the stratum username is the payout address (must validate) and is paid
  --payout ADDR    every block pays ADDR; the username is a free worker name
  --text unset     the node's coinbase scriptSig is used as is (carrier 2)
  --text TEXT      the scriptSig is rebuilt as height push + ``coinbaseaux.flags`` + TEXT (carrier 3)

and asserts, per cell: two blocks accepted, both nodes at the new height, ``yed_gettag`` found
with the quote's ``priceMicroUsd`` and the pool node's payout address, coinbase vout 0 paying
the expected address (the fixed ``--payout`` or the miner's username), the scriptSig ending in
the text exactly when ``--text`` is set, and ``check-coinbase`` agreeing.  Then the negative:
``--text ... --no-flags`` (the Perl cenote's behaviour, Y-F1) yields an accepted block whose
tag is ``found: false``.

Needs a yolo binary: ``YOLO_BIN`` names it (the fork's CI builds boyfromcave/yolo and sets it);
without one the script SKIPs (exit 0 with a message) so the inherited matrix does not break.  No
``setmocktime``: yolo stamps ``max(template.curtime, now)`` and the node's ``curtime`` is already
``max(MTP + 1, now)``, so a burst-generated chain is not ``time-too-old`` (Y-F5 is the Perl's
wall-clock stamp, not the node's).
"""

import json
import os
import subprocess
import sys
import time
import urllib.request

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    PORT_MIN,
    PORT_RANGE,
    assert_equal,
    connect_nodes_bi,
    rpc_auth_pair,
    rpc_port,
    start_nodes,
    sync_blocks,
)
from test_framework.yellowback_util import (
    POOL_WIFS,
    address_of,
    pool_args,
    set_quote,
    usd_to_micro,
    yellowback_node_args,
)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, '..', '..'))
WORKSPACE = os.path.dirname(REPO)
if os.path.basename(WORKSPACE) == 'wt':                      # a worktree: wt/<name>/ -> the workspace
    WORKSPACE = os.path.dirname(WORKSPACE)
STRATUM_MINER = os.path.join(REPO, 'contrib', 'yellowback', 'devnet', 'stratum-miner')
CHECK_COINBASE = os.path.join(REPO, 'contrib', 'yellowback', 'pool', 'check-coinbase')
QUOTE_USD = '0.05'
BLOCKS_PER_CELL = 2
# Stratum port = 21000 + (rpc_port(0) - PORT_MIN - PORT_RANGE), status port = that + 5000: follows
# --portseed (offset 0..4991), sits above the framework's 11000-21000 p2p/rpc range, and stays
# BELOW 32768, where Linux's ephemeral range starts (macOS starts at 49152). An earlier 30000-based
# scheme put the third cell's ports at 33794/38794, which an outgoing client socket of an earlier
# cell had already taken on the CI runner: yolo "exited 1 at start" (run for 121621d98).
STRATUM_PORT_BASE = 21000
STRATUM_STATUS_OFFSET = 5000


def find_yolo():
    """YOLO_BIN, else the workspace build beside the fork; None means SKIP."""
    override = os.environ.get('YOLO_BIN')
    if override:
        path = os.path.expanduser(override)
        return path if os.access(path, os.X_OK) else None
    candidate = os.path.join(WORKSPACE, 'yolo', 'target', 'release', 'yolo')
    return candidate if os.access(candidate, os.X_OK) else None


# Rule: MINER-2 TAG-1
class YellowbackStratumTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.yolo = None
        self.procs = []
        self.pool_address = address_of(POOL_WIFS[0])

    def setup_network(self, split=False):
        args = [pool_args(self.pool_address), yellowback_node_args()]
        self.nodes = start_nodes(2, self.options.tmpdir, extra_args=args)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.nodes[0].importprivkey(POOL_WIFS[0], 'yellowback-payout', False)
        self.sync_all()

    # ------------------------------------------------------------------ processes

    def ports(self, index):
        base = STRATUM_PORT_BASE + (rpc_port(0) - PORT_MIN - PORT_RANGE) + index
        return base, base + STRATUM_STATUS_OFFSET

    def start_yolo(self, name, index, extra=()):
        user, password = rpc_auth_pair(0)
        port, status_port = self.ports(index)
        argv = [self.yolo, '--bind', '127.0.0.1', '--port', str(port), '--status-port', str(status_port),
                '--rpc', 'http://127.0.0.1:%d' % rpc_port(0), '--rpc-user', user, '--rpc-password', password,
                '--equihash', 'auto', '--log', 'debug'] + list(extra)
        log = open(os.path.join(self.options.tmpdir, 'yolo-%s-%d.log' % (name, index)), 'ab')
        print('starting %s' % ' '.join(argv))
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        self.procs.append(proc)
        deadline = time.time() + 30
        while time.time() < deadline:
            if proc.poll() is not None:
                log.close()
                with open(log.name, 'rb') as f: tail = f.read().decode('utf-8', 'replace').strip().splitlines()[-8:]
                raise AssertionError('yolo (%s) exited %s at start (%s):\n  %s' % (name, proc.returncode, log.name, '\n  '.join(tail)))
            doc = self.status(status_port)
            if doc and doc.get('height') is not None:
                return proc, port, status_port
            time.sleep(0.5)
        raise AssertionError('yolo (%s) served no template within 30 s; see %s' % (name, log.name))

    @staticmethod
    def status(status_port):
        try:
            with urllib.request.urlopen('http://127.0.0.1:%d/status' % status_port, timeout=3) as reply:
                return json.load(reply)
        except Exception:
            return None

    def stop_proc(self, proc):
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()

    def mine(self, port, user, blocks):
        argv = [sys.executable, STRATUM_MINER, '--pool', '127.0.0.1:%d' % port, '--user', user, '--blocks', str(blocks)]
        print('running %s' % ' '.join(argv))
        out = subprocess.run(argv, capture_output=True, text=True, timeout=600)
        print(out.stdout.strip())
        if out.returncode != 0:
            raise AssertionError('stratum-miner exited %d: %s' % (out.returncode, out.stderr.strip()))
        return out.stdout

    def check_coinbase(self, height):
        """check-coinbase's exit code: 0 a tag was found, 1 none."""
        cli = os.path.join(os.path.dirname(os.environ.get('BITCOIND', os.path.join(REPO, 'src', 'ycashd'))), 'ycash-cli')
        argv = [sys.executable, CHECK_COINBASE, '--cli', cli, str(height), '--', '-regtest',
                '-datadir=%s' % os.path.join(self.options.tmpdir, 'node0')]
        out = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        print('check-coinbase %d -> exit %d: %s' % (height, out.returncode, ' | '.join(out.stdout.split('\n')[:3])))
        assert out.returncode in (0, 1), out.stderr
        return out.returncode

    # ------------------------------------------------------------------ the checks

    def coinbase_payee(self, height):
        block = self.nodes[0].getblock(str(height), 2)
        vouts = [o for o in block['tx'][0]['vout'] if o['value'] > 0]
        return [a for o in vouts for a in o['scriptPubKey'].get('addresses', [])]

    def run_cell(self, index, miner_user, payout=None, text=None, no_flags=False, expect_tag=True):
        """One yolo start: ``payout`` is the fixed --payout address (None: the username is paid),
        ``text`` the --text (None: scriptSig untouched); ``no_flags`` adds the hidden switch."""
        name = '%s-%s%s' % ('payout' if payout else 'username', 'text' if text is not None else 'notext', '-noflags' if no_flags else '')
        extra = []
        if payout:
            extra += ['--payout', payout]
        if text is not None:
            extra += ['--text', text]
        if no_flags:
            extra += ['--no-flags']
        expected_payee = payout or miner_user
        proc, port, status_port = self.start_yolo(name, index, extra)
        before = self.nodes[0].getblockcount()
        try:
            self.mine(port, miner_user, BLOCKS_PER_CELL)
            sync_blocks(self.nodes)
            height = before + BLOCKS_PER_CELL
            assert_equal([n.getblockcount() for n in self.nodes], [height, height])
            doc = self.status(status_port)
            print('/status: %s' % json.dumps(doc, sort_keys=True))
            assert 'mode' not in doc, 'yolo still reports a mode (P-6)'
            assert_equal(doc['payout'], payout or 'username')     # the fixed address, else "username"
            assert_equal(doc['text'], text is not None)            # a bool: whether the scriptSig is rebuilt
            assert_equal(doc['accepted'], BLOCKS_PER_CELL)
            assert_equal(doc['rejected'], 0)
            assert_equal(doc['lastSubmitVerdict'], 'accepted')
            for h in range(before + 1, height + 1):
                for n in self.nodes:
                    tag = n.yed_gettag(str(h))
                    print('%s: node %d yed_gettag %d -> %s' % (name, self.nodes.index(n), h, json.dumps(tag, sort_keys=True)))
                    assert_equal(tag['found'], expect_tag)
                    if expect_tag:
                        assert_equal(tag['kind'], 'quote')
                        assert_equal(tag['priceMicroUsd'], usd_to_micro(QUOTE_USD))
                        assert_equal(tag['payoutAddress'], self.pool_address)
                sig = bytes.fromhex(self.nodes[0].getblock(str(h), 2)['tx'][0]['vin'][0]['coinbase'])
                print('%s: coinbase scriptSig at %d: %s' % (name, h, sig.hex()))
                self.check_scriptsig(sig, h, text, no_flags)
                assert_equal(self.check_coinbase(h), 0 if expect_tag else 1)
                # vout 0 is the block reward; vout 1 the founders' reward (regtest pays one too)
                payees = self.coinbase_payee(h)
                print('%s: coinbase pays %s' % (name, payees))
                assert_equal(payees[0], expected_payee)
            assert_equal(doc['tag'], 'quote' if expect_tag else 'none')
        finally:
            self.stop_proc(proc)

    def check_scriptsig(self, sig, height, text, no_flags):
        """The shape: a height push first; with --text the script ends in the text (pushed as
        data) and, unless --no-flags, carries the node's coinbaseaux.flags between the two;
        without --text the node's own script (height || OP_0 || flags, miner.cpp) is untouched."""
        if height <= 16:
            push = bytes([0x50 + height])
        else:
            raw = height.to_bytes((height.bit_length() + 8) // 8, 'little')
            push = bytes([len(raw)]) + raw
        assert sig.startswith(push), (sig.hex(), push.hex())
        flags = bytes.fromhex(self.nodes[0].getblocktemplate()['coinbaseaux']['flags'])
        if text is None:
            # the template's scriptSig (miner.cpp: height || OP_0 || flags) used untouched; the tag
            # bytes carry no time, so the flags of the next template are those of the mined block
            assert_equal(sig.hex(), (push + b'\x00' + flags).hex())
            return
        encoded = text.encode()
        assert sig.endswith(bytes([len(encoded)]) + encoded), 'no text push at the end: %s' % sig.hex()
        assert len(sig) <= 100, len(sig)
        middle = sig[len(push):-(len(encoded) + 1)]
        if no_flags:
            assert_equal(middle, b'')
        else:
            assert middle, 'coinbaseaux.flags missing between height and text: %s' % sig.hex()

    def run_test(self):
        self.yolo = find_yolo()
        if not self.yolo:
            print('SKIP: no yolo binary (set YOLO_BIN, or build <workspace>/yolo with cargo build --release)')
            return
        print('yolo: %s' % self.yolo)
        self.nodes[0].generate(101)
        self.sync_all()
        set_quote(self.nodes[0], QUOTE_USD)
        tpl = self.nodes[0].getblocktemplate()
        print('template flags (coinbaseaux): %s' % tpl.get('coinbaseaux', {}).get('flags'))
        assert tpl.get('coinbaseaux', {}).get('flags'), 'the pool node builds no tag'
        miner_user = self.nodes[1].getnewaddress()          # a foreign wallet: the username payout is visible on chain
        fixed_payout = self.nodes[1].getnewaddress()        # another: --payout wins over the username
        text = 'yellowback_stratum.py'
        try:
            self.run_cell(0, miner_user)                                        # username paid, scriptSig as is
            self.run_cell(1, miner_user, payout=fixed_payout)                   # --payout paid, scriptSig as is
            self.run_cell(2, miner_user, text=text)                             # username paid, scriptSig rebuilt
            self.run_cell(3, 'worker.1', payout=fixed_payout, text=text)        # --payout paid, username a free name
            # Y-F1 pinned: a rebuilt scriptSig that does not carry coinbaseaux.flags loses the tag
            # on a block the node accepts. --no-flags is yolo's hidden test-only switch for this.
            self.run_cell(4, miner_user, text='no-flags', no_flags=True, expect_tag=False)
        finally:
            for proc in self.procs:
                self.stop_proc(proc)
        print('yellowback_stratum: all four payout x text cells carried the tag; --text --no-flags dropped it')


if __name__ == '__main__':
    YellowbackStratumTest().main()
