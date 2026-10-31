#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Step 3 of rc-qualify (testnet plan §5.3): ycash-dd nodes on a running ycash6 devnet, compared every 100 blocks.

In plain words: the release runs on two independent node programs (ycash6 and ycash-dd). This puts
ycash-dd nodes, built at the release's pairing tag, on a devnet of the release binary, mines, and at
every 100th block checks that all of them agree on three things: the block, the vault state and the
YED state. One disagreement fails the qualification.

  yellowback-rc-crossline.py --devnet-dir DIR --dd-ycashd PATH [--dd-nodes 2] [--rounds 5] [--out FILE]

The devnet (contrib/yellowback/devnet/yellowback-devnet up --no-heartbeat) is already running in DIR.
Each ycash-dd node gets its own datadir under DIR/crossline-dd<k>, free ports, `-connect` to node 0, and
node 0's consensus arguments from DIR/devnet.json (the -nuparams, the attestor set, the Falcon height);
ports, peers, notifications and wallet roles are not carried over. The driver mines on node 0 with
`generate` to each next multiple of 100, waits until every running node (the devnet's and the
ycash-dd ones) has the same tip, and reads on each: getbestblockhash, vault_getinfo.statehash and, on
nodes with the attestor set, yed_getstatehash.statehash. --rounds such heights are compared; the
evidence is written to --out. Exit 1 on any disagreement or timeout. Python 3 standard library only.
"""
import argparse
import base64
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

# node 0's arguments that are about this one process (its ports, peers, notifications, indexes,
# wallet role), not about the chain's rules; every other argument is passed to the ycash-dd nodes.
LOCAL_ARGS = ("-port", "-rpcport", "-bind", "-rpcbind", "-rpcallowip", "-connect", "-addnode", "-seednode",
              "-datadir", "-conf", "-zmqpub", "-mineraddress", "-gen", "-genproclimit", "-insightexplorer",
              "-lightwalletd", "-txindex", "-blocknotify", "-walletnotify", "-alertnotify", "-exportdir",
              "-wallet", "-rpcuser", "-rpcpassword", "-listen", "-discover", "-dnsseed", "-debug", "-printtoconsole")


def chain_args(args):
    """The arguments of node 0 that a node of the other line needs to follow the same chain."""
    out = []
    for arg in args:
        name = arg.split("=", 1)[0]
        if any(name == local or name.startswith(local) for local in LOCAL_ARGS):
            continue
        out.append(arg)
    return out


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def read_conf(path):
    conf = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.strip().split("=", 1)
                conf[key] = value
    return conf


class Rpc:
    def __init__(self, name, port, user, password):
        self.name, self.url = name, "http://127.0.0.1:%d/" % port
        self.auth = "Basic " + base64.b64encode(("%s:%s" % (user, password)).encode()).decode()

    def __call__(self, method, *params, timeout=60):
        body = json.dumps({"jsonrpc": "1.0", "id": method, "method": method, "params": list(params)}).encode()
        request = urllib.request.Request(self.url, body, {"Authorization": self.auth, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as reply:
                doc = json.loads(reply.read())
        except urllib.error.HTTPError as error:
            doc = json.loads(error.read() or b"{}")
        if doc.get("error"):
            raise RuntimeError("%s %s: %s" % (self.name, method, doc["error"]))
        return doc["result"]


def wait(what, predicate, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return
        except (OSError, RuntimeError, ValueError):
            pass
        time.sleep(1)
    raise TimeoutError("timed out after %ds: %s" % (timeout, what))


def digests(node, has_yed):
    out = {"blockhash": node("getbestblockhash"), "vault": node("vault_getinfo")["statehash"]}
    if has_yed:
        out["yed"] = node("yed_getstatehash")["statehash"]
    return out


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--devnet-dir", required=True)
    ap.add_argument("--dd-ycashd", required=True)
    ap.add_argument("--dd-nodes", type=int, default=2)
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--timeout", type=int, default=600, help="seconds to wait for a sync (default 600)")
    ap.add_argument("--out")
    args = ap.parse_args(argv)

    with open(os.path.join(args.devnet_dir, "devnet.json"), encoding="utf-8") as fh:
        state = json.load(fh)
    num = int(state["num_nodes"])
    node_args = state["node_args"]
    nodes = []          # (name, rpc, has_yed)
    for n in range(num):
        conf_path = os.path.join(args.devnet_dir, "node%d" % n, "ycash.conf")
        if not os.path.exists(conf_path):
            continue
        conf = read_conf(conf_path)
        has_yed = any(a.startswith("-yellowbackattestorset=") for a in node_args.get(str(n), []))
        nodes.append(("y6-node%d" % n, Rpc("y6-node%d" % n, int(conf["rpcport"]), conf["rpcuser"], conf["rpcpassword"]), has_yed))
    node0_conf = read_conf(os.path.join(args.devnet_dir, "node0", "ycash.conf"))
    base_args = chain_args(node_args["0"])
    print("ycash-dd nodes take node 0's chain arguments: %s" % " ".join(base_args))

    procs = []
    try:
        for k in range(args.dd_nodes):
            datadir = os.path.join(args.devnet_dir, "crossline-dd%d" % k)
            os.makedirs(datadir, exist_ok=True)
            port, rpcport = free_port(), free_port()
            user, password = "crossline%d" % k, "crossline%d-%d" % (k, os.getpid())
            command = [args.dd_ycashd, "-regtest", "-datadir=" + datadir, "-port=%d" % port, "-rpcport=%d" % rpcport,
                       "-rpcuser=" + user, "-rpcpassword=" + password, "-listen=1", "-discover=0", "-dnsseed=0",
                       "-connect=127.0.0.1:%s" % node0_conf["port"], "-debug=yellowback", "-printtoconsole=0"] + base_args
            log = open(os.path.join(datadir, "stdout.log"), "w", encoding="utf-8")
            procs.append(subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL))
            rpc = Rpc("dd-node%d" % k, rpcport, user, password)
            wait("dd-node%d answers RPC" % k, lambda r=rpc: r("getblockcount") >= 0, 300)
            has_yed = any(a.startswith("-yellowbackattestorset=") for a in base_args)
            nodes.append(("dd-node%d" % k, rpc, has_yed))
            print("dd-node%d: %s" % (k, rpc("getnetworkinfo")["subversion"]))
        miner = nodes[0][1]
        rows, bad = [], []
        for _ in range(args.rounds):
            tip = miner("getblockcount")
            target = (tip // 100 + 1) * 100
            miner("generate", target - tip, timeout=600)
            best = miner("getbestblockhash")
            wait("every node at height %d" % target,
                 lambda: all(rpc("getbestblockhash") == best for _, rpc, _ in nodes), args.timeout)
            row = {"height": target, "nodes": {name: digests(rpc, yed) for name, rpc, yed in nodes}}
            rows.append(row)
            for field in ("blockhash", "vault", "yed"):
                seen = {d[field] for d in row["nodes"].values() if field in d}
                if len(seen) != 1:
                    bad.append("height %d: %s differs: %s" % (target, field, {n: d.get(field) for n, d in row["nodes"].items()}))
            print("height %d: %s on %d nodes" % (target, "agree" if not bad else "DISAGREE", len(nodes)))
            if bad:
                break
        result = {"rounds": rows, "problems": bad, "dd_nodes": args.dd_nodes, "chain_args": base_args}
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2, sort_keys=True)
        for problem in bad:
            print("FAIL " + problem)
        return 1 if bad else 0
    except TimeoutError as error:
        print("FAIL %s" % error)
        return 1
    finally:
        for proc in procs:
            proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
