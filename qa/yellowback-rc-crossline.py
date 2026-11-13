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
  yellowback-rc-crossline.py --devnet-dir DIR --kogany-zakurad PATH [--kogany-nodes 1] [--rounds 5] [--out FILE]

The devnet (contrib/yellowback/devnet/yellowback-devnet up --no-heartbeat) is already running in DIR.
Each ycash-dd node gets its own datadir under DIR/crossline-dd<k>, free ports, `-connect` to node 0, and
node 0's consensus arguments from DIR/devnet.json (the -nuparams, the attestor set, the Falcon height);
ports, peers, notifications and wallet roles are not carried over. The driver mines on node 0 with
`generate` to each next multiple of 100, waits until every running node (the devnet's and the
ycash-dd ones) has the same tip, and reads on each: getbestblockhash, vault_getinfo.statehash and, on
nodes with the attestor set, yed_getstatehash.statehash. --rounds such heights are compared; the
evidence is written to --out. Exit 1 on any disagreement or timeout. Python 3 standard library only.

--kogany-zakurad (kogany plan W9-b, section 4.2 rule 4): a kogany column, either beside the ycash-dd
nodes or instead of them. Each kogany node (zakurad) gets DIR/crossline-kogany<k>/zakurad.toml from
node 0's chain arguments through the mixed-line harness's map (qa/rpc-tests/test_framework/kogany.py
zakurad_config; an argument it has no row for is recorded as a note, KOGANY_LIVE / --kogany-live name
the live chunks, default W1-Y1,W2-b), free ports and node 0 as its one peer. kogany does not mine; it
follows. With a kogany column the comparison is three-way: the YED state hash of every node is also
compared with yellowback_model.py's, rebuilt from node 0's blocks at each 100th height (--model forces
that column on without kogany). The kogany column and the model import the test framework, so they
need the workspace venv's Python, as the devnet itself does.
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


def running(proc, datadir):
    """True while a started node runs; a node that has exited fails the run at once, with its output."""
    if proc.poll() is None:
        return True
    with open(os.path.join(datadir, "stdout.log"), encoding="utf-8", errors="replace") as fh:
        tail = fh.read()[-2000:]
    raise SystemExit("FAIL the node in %s exited (%s) before answering RPC:\n%s" % (datadir, proc.returncode, tail))


def digests(node, has_yed):
    out = {"blockhash": node("getbestblockhash"), "vault": node("vault_getinfo")["statehash"]}
    if has_yed:
        out["yed"] = node("yed_getstatehash")["statehash"]
    return out


HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_KOGANY_LIVE = "W1-Y1,W2-b"


def test_framework():
    """qa/rpc-tests/test_framework (kogany.py's zakurad map, yellowback_model.py)."""
    path = os.path.join(HERE, "rpc-tests")
    if path not in sys.path:
        sys.path.insert(0, path)
    from test_framework import kogany, yellowback_model
    return kogany, yellowback_model


def kogany_toml(base_args, datadir, p2p, rpcport, v2, peer_port, live):
    """The zakurad.toml of one kogany node: node 0's chain arguments through the harness's map, this
    node's own ports and directories, node 0 as its one peer."""
    kg, _ = test_framework()
    if kg.PortSeed.n is None:
        kg.PortSeed.n = 0          # the map derives default ports from it; they are replaced below
    live = frozenset(c for c in live.split(",") if c) | kg.DEFAULT_LIVE
    kept, dropped = [], []
    for arg in base_args:
        try:
            kg.zakurad_config([arg], 0, [], datadir, live=live)
            kept.append(arg)
        except kg.UnmappedArgument:
            dropped.append(arg)
    config, notes = kg.zakurad_config(kept, 0, [peer_port], datadir, live=live)
    config["network"]["listen_addr"] = "127.0.0.1:%d" % p2p
    config["network"]["zakura"]["listen_addr"] = "127.0.0.1:%d" % v2
    config["rpc"]["listen_addr"] = "127.0.0.1:%d" % rpcport
    notes = list(notes) + ["no zakurad row (not passed): %s" % a for a in dropped]
    return kg.render_toml(config, notes), notes


class Proxy:
    """node.method(*params) over an Rpc, the shape yellowback_model.build_model_from_node reads."""
    def __init__(self, rpc):
        self._rpc = rpc

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return lambda *params: self._rpc(name, *params, timeout=300)


def model_hash(rpc):
    """yellowback_model.py's YED state hash, rebuilt from the node's blocks [0, tip]."""
    _, ym = test_framework()
    model = ym.build_model_from_node(Proxy(rpc))
    return model.state_hash(), model.tip_height


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--devnet-dir", required=True)
    ap.add_argument("--dd-ycashd")
    ap.add_argument("--dd-nodes", type=int, default=2)
    ap.add_argument("--kogany-zakurad", help="zakurad (kogany): a kogany column, three-way with the model")
    ap.add_argument("--kogany-nodes", type=int, default=1)
    ap.add_argument("--kogany-live", default=os.environ.get("KOGANY_LIVE") or DEFAULT_KOGANY_LIVE,
                    help="the live kogany chunks of the zakurad.toml map (default $KOGANY_LIVE or %s)" % DEFAULT_KOGANY_LIVE)
    ap.add_argument("--model", action="store_true", help="compare the YED state hash with yellowback_model.py "
                    "(on by default with --kogany-zakurad)")
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--timeout", type=int, default=600, help="seconds to wait for a sync (default 600)")
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    if not args.dd_ycashd and not args.kogany_zakurad:
        ap.error("one of --dd-ycashd and --kogany-zakurad is required")
    dd_nodes = args.dd_nodes if args.dd_ycashd else 0
    kogany_nodes = args.kogany_nodes if args.kogany_zakurad else 0
    with_model = args.model or bool(args.kogany_zakurad)

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
    has_yed0 = any(a.startswith("-yellowbackattestorset=") for a in base_args)
    print("the other line's nodes take node 0's chain arguments: %s" % " ".join(base_args))

    procs = []
    kogany_notes = []
    try:
        for k in range(dd_nodes):
            datadir = os.path.join(args.devnet_dir, "crossline-dd%d" % k)
            os.makedirs(datadir, exist_ok=True)
            # ycash-dd (the v4.5.0 line) refuses to start without a configuration file in its datadir;
            # every setting it needs is on the command line, so the file is empty.
            open(os.path.join(datadir, "ycash.conf"), "a", encoding="utf-8").close()
            port, rpcport = free_port(), free_port()
            user, password = "crossline%d" % k, "crossline%d-%d" % (k, os.getpid())
            command = [args.dd_ycashd, "-regtest", "-datadir=" + datadir, "-port=%d" % port, "-rpcport=%d" % rpcport,
                       "-rpcuser=" + user, "-rpcpassword=" + password, "-listen=1", "-discover=0", "-dnsseed=0",
                       "-connect=127.0.0.1:%s" % node0_conf["port"], "-debug=yellowback", "-printtoconsole=0"] + base_args
            log = open(os.path.join(datadir, "stdout.log"), "w", encoding="utf-8")
            procs.append(subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL))
            rpc = Rpc("dd-node%d" % k, rpcport, user, password)
            wait("dd-node%d answers RPC" % k, lambda r=rpc, p=procs[-1], d=datadir: running(p, d) and r("getblockcount") >= 0, 300)
            nodes.append(("dd-node%d" % k, rpc, has_yed0))
            print("dd-node%d: %s" % (k, rpc("getnetworkinfo")["subversion"]))
        node0 = nodes[0][1]
        for k in range(kogany_nodes):
            datadir = os.path.join(args.devnet_dir, "crossline-kogany%d" % k)
            os.makedirs(datadir, exist_ok=True)
            p2p, rpcport, v2 = free_port(), free_port(), free_port()
            text, notes = kogany_toml(base_args, datadir, p2p, rpcport, v2, int(node0_conf["port"]), args.kogany_live)
            kogany_notes.extend(notes)
            conf = os.path.join(datadir, "zakurad.toml")
            with open(conf, "w", encoding="utf-8") as fh:
                fh.write(text)
            log = open(os.path.join(datadir, "zakurad.log"), "w", encoding="utf-8")
            procs.append(subprocess.Popen([args.kogany_zakurad, "-c", conf, "start"], stdout=log,
                                          stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL))
            rpc = Rpc("kogany%d" % k, rpcport, "", "")
            wait("kogany%d answers RPC" % k, lambda r=rpc: r("getblockcount") >= 0, 300)
            # one connection: the kogany node dials node 0; node 0 adds it only if that did not happen
            time.sleep(5)
            if not rpc("getpeerinfo"):
                node0("addnode", "127.0.0.1:%d" % p2p, "onetry")
            nodes.append(("kogany%d" % k, rpc, has_yed0))
            print("kogany%d: %s (zakurad.toml notes: %s)" % (k, rpc("getnetworkinfo")["subversion"], "; ".join(notes) or "none"))
        miner = node0
        rows, bad = [], []
        for _ in range(args.rounds):
            tip = miner("getblockcount")
            target = (tip // 100 + 1) * 100
            miner("generate", target - tip, timeout=600)
            best = miner("getbestblockhash")
            wait("every node at height %d" % target,
                 lambda: all(rpc("getbestblockhash") == best for _, rpc, _ in nodes), args.timeout)
            row = {"height": target, "nodes": {name: digests(rpc, yed) for name, rpc, yed in nodes}}
            if with_model and has_yed0:
                mhash, mtip = model_hash(miner)
                if mtip != target:
                    bad.append("height %d: the model was rebuilt at height %d" % (target, mtip))
                row["nodes"]["yellowback_model.py"] = {"yed": mhash}
            rows.append(row)
            for field in ("blockhash", "vault", "yed"):
                seen = {d[field] for d in row["nodes"].values() if field in d}
                if len(seen) != 1:
                    bad.append("height %d: %s differs: %s" % (target, field, {n: d.get(field) for n, d in row["nodes"].items()}))
            print("height %d: %s on %d nodes%s" % (target, "agree" if not bad else "DISAGREE", len(nodes),
                                                     " and yellowback_model.py" if "yellowback_model.py" in row["nodes"] else ""))
            if bad:
                break
        result = {"rounds": rows, "problems": bad, "dd_nodes": dd_nodes, "kogany_nodes": kogany_nodes,
                  "model": with_model and has_yed0, "chain_args": base_args}
        if kogany_nodes:
            result["kogany_zakurad"] = args.kogany_zakurad
            result["kogany_live"] = args.kogany_live
            result["kogany_toml_notes"] = sorted(set(kogany_notes))
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
