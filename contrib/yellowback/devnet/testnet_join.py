# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Join mode of yellowback-devnet: `up --network testnet-yb-fast|testnet-yb-slow|testnet-legacy`.

On regtest `up` builds a private chain and every role around it. On a public testnet there is no
chain to build: `up` starts (or attaches to) **one** node of that network, the seat's node, and
the roles a person can take there (testnet plan §3.2):

    user      a wallet on the testnet: an address to fund from the faucet, the GUI on its conf
    pool      yolo (`--stratum`) beside the node, serving real Equihash 192,7 miners
    attestor  the agent configuration for the seat (registration needs a bond, so it is yours to do)
    none      just the node

The node is `ycashd -testnet -testnetprofile=<p>` with the profile's ports and datadir (the
profile files in contrib/yellowback/profiles/), `-addnode` peers from `--addnode` or
`--addnode-file` (the fixed seeds arrive with rc1), optionally restored from the prefix first
(`--bootstrap`, contrib/bootstrap/ycash-bootstrap). `--rpc URL` attaches to a node you already run
instead of starting one.

Commands that only make sense on a private chain are refused with the reason: `mine` (use
`wait-blocks N`), `heartbeat`, `price` (the walk moves the attested price), `attestor N ...` (the
fault injections), `notice`, `bridge`, `vectors`, `report`, and the personas (`sim`), whose term
classes and windows are regtest's. `status`, `check`, `cli`, `wallet`, `wait-blocks`,
`scenario`, `lightwalletd` and `pool N stratum ...` work. Waits count blocks, never seconds.
"""

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(REPO, "contrib", "yellowback", "profiles"))
import ybprofile  # noqa: E402

BOOTSTRAP = os.path.join(REPO, "contrib", "bootstrap", "ycash-bootstrap")
SEATS = {"none": 0, "user": 0, "attestor": 8, "pool": 4}       # the regtest presets' seat numbers, so the helpers line up
JOIN_COMMANDS = ("status", "check", "down", "cli", "wallet", "wait-blocks", "scenario", "lightwalletd", "pool")
REFUSED = {
    "mine": "a public network's blocks come from its miners: `wait-blocks N` waits for N of them (or `pool 4 stratum start` and a miner)",
    "heartbeat": "the heartbeat mines on the devnet's own pools; a testnet's blocks come from its miners",
    "price": "the mock price walk moves the attested price; on a testnet the price is the attestors' real feed",
    "attestor": "`attestor N stop|start|price` are fault injections on the devnet's automated attestors; a testnet's attestors are their operators'",
    "notice": "run `cli -- yed_claimnotice ...` against your node instead",
    "bridge": "the bridge persona needs the devnet's nine signer wallets",
    "vectors": "the vectors are generated on a private chain (they mine)",
    "report": "the report reads the devnet's regtest logs",
    "sim": "the personas use regtest's term classes and windows; a testnet persona set comes with ycash-infra's personas image",
}


def add_up_args(command):
    command.add_argument("--network", choices=ybprofile.NETWORKS, default="regtest",
                         help="regtest (default: build the private devnet) or a public testnet to join: testnet-yb-fast, testnet-yb-slow, testnet-legacy")
    command.add_argument("--addnode", action="append", metavar="HOST[:PORT]", help="join mode: a peer to add (repeatable; default port: the profile's)")
    command.add_argument("--addnode-file", metavar="FILE", help="join mode: peers, one HOST[:PORT] per line (# comments)")
    command.add_argument("--rpc", metavar="URL", help="join mode: attach to a running node (http://user:password@host:port) instead of starting one")
    command.add_argument("--rpc-cookie", metavar="FILE", help="join mode, with --rpc: the node's .cookie for the credentials")
    command.add_argument("--rpcport", type=int, help="join mode: the started node's RPC port (default: the profile's)")
    command.add_argument("--listen", action="store_true", help="join mode: accept inbound peers on the profile's P2P port")
    command.add_argument("--bootstrap", nargs="?", const="prefix", metavar="SOURCE",
                         help="join mode: restore the prefix (or SOURCE) with ycash-bootstrap before the node's first start")


def network_of(directory):
    try:
        with open(os.path.join(directory, "devnet.json")) as f:
            return json.load(f).get("network") or "regtest"
    except (OSError, ValueError):
        return "regtest"


def parse_peers(items, path, default_port):
    """--addnode values and the file's lines as HOST:PORT strings (IPv6 in brackets)."""
    lines = list(items or [])
    if path:
        with open(path) as f:
            lines += [l.split("#", 1)[0].strip() for l in f]
    peers = []
    for line in filter(None, (l.strip() for l in lines)):
        m = re.fullmatch(r"(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::(\d{1,5}))?", line)
        if not m or (m.group(2) and not 0 < int(m.group(2)) < 65536):
            sys.exit("not a HOST[:PORT] peer: %r" % line)
        peers.append("%s:%s" % (m.group(1), m.group(2) or default_port))
    return peers


def conf_text(profile, seat, user, password, rpcport, peers, listen):
    lines = ["# written by yellowback-devnet up --network %s (join mode)" % profile["name"],
             "testnet=1", "testnetprofile=%s" % profile["testnet_profile"], "server=1", "printtoconsole=0",
             "rpcuser=%s" % user, "rpcpassword=%s" % password, "rpcbind=127.0.0.1", "rpcallowip=127.0.0.1",
             "rpcport=%d" % rpcport, "listen=%d" % int(bool(listen)), "showmetrics=0"]
    if seat == 0:   # the user seat serves lightwalletd too, which needs the address index (set before the first sync)
        lines += ["experimentalfeatures=1", "insightexplorer=1", "txindex=1"]
    lines += ["addnode=%s" % p for p in peers]
    return "\n".join(lines) + "\n"


def credentials(url, cookie):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "http" or not parsed.port:
        sys.exit("--rpc takes http://[user:password@]host:port")
    user, password = urllib.parse.unquote(parsed.username or ""), urllib.parse.unquote(parsed.password or "")
    if cookie:
        with open(cookie) as f:
            user, _, password = f.read().strip().partition(":")
    if not user:
        sys.exit("--rpc needs credentials: in the URL, or --rpc-cookie FILE")
    host = parsed.hostname
    return {"url": "http://%s:%s@%s:%d" % (urllib.parse.quote(user, safe=""), urllib.parse.quote(password, safe=""), host, parsed.port),
            "host": host, "port": parsed.port, "user": user, "password": password}


def wait_rpc(dv, state, seat, process=None, timeout=600):
    """Until the node answers getblockcount (a testnet node loads its block index first)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process is not None and process.poll() is not None:
            sys.exit("ycashd exited (status %s); see %s" % (process.returncode, os.path.join(dv.node_dir(state["dir"], seat), "ycashd.log")))
        if dv.alive(state, seat):
            return
        time.sleep(1)
    sys.exit("the node did not answer RPC within %ds" % timeout)


def up(args, dv):
    profile = ybprofile.load(args.network)
    directory = os.path.abspath(args.dir)
    role = args.role
    regtest_only = [flag for flag, on in (("--agents", args.agents), ("--no-attest", args.no_attest), ("--pqfalconheight", args.pqfalconheight is not None),
                                          ("--no-pqfalcon", args.no_pqfalcon), ("--seed", args.seed is not None)) if on]
    if regtest_only:
        sys.exit("%s shape(s) the private regtest chain; %s is joined as it is" % (", ".join(regtest_only), profile["name"]))
    if role == "attestor" and not profile["yellowback"]["enabled"]:
        sys.exit("%s has no Yellowback (Vault never activates): no attestor seat. --role user or pool" % profile["name"])
    if args.stratum and role != "pool":
        sys.exit("--stratum is the pool seat's: `up --network %s --role pool --stratum`" % profile["name"])
    if os.path.exists(os.path.join(directory, "devnet.json")):
        old = dv.load(directory) if network_of(directory) == "regtest" else _load(directory)
        if any(dv.alive(old, int(n)) for n in (old.get("rpc") or {})):
            sys.exit("a devnet is already running in %s; `down` it first" % directory)
        if not args.force:
            sys.exit("%s holds a stopped devnet; pass --force to replace it (a joined node's datadir is kept)" % directory)
    seat = SEATS[role]
    peers = parse_peers(args.addnode, args.addnode_file, profile["node"]["p2p_port"]) + parse_peers(profile["seeds"]["addnode"], None, profile["node"]["p2p_port"])
    os.makedirs(directory, exist_ok=True)
    state = {"network": profile["name"], "chain": profile["chain"], "testnet_profile": profile["testnet_profile"], "dir": directory,
             "portseed": args.portseed, "role": role, "seat": seat, "num_nodes": seat + 1, "joined": [seat], "peers": peers,
             "created": time.strftime("%Y-%m-%d %H:%M:%S"), "pools": [], "pool_addresses": [], "auto_pools": [], "attestors": [],
             "auto_attestors": [], "agents": {}, "attest_agents": {}, "population": None, "liquidator": None, "spawned": None}
    process = None
    if args.rpc:
        if args.bootstrap:
            sys.exit("--bootstrap restores a node this command starts; an attached node (--rpc) is restored by its operator")
        state["rpc"] = {str(seat): credentials(args.rpc, args.rpc_cookie)}
        state["bitcoind"] = args.bitcoind or os.environ.get("ZCASHD") or os.environ.get("BITCOIND") or os.path.join(REPO, "src", "ycashd")
    else:
        binary = args.bitcoind or os.environ.get("ZCASHD") or os.environ.get("BITCOIND") or os.path.join(REPO, "src", "ycashd")
        if not os.access(binary, os.X_OK):
            sys.exit("ycashd not found at %s" % binary)
        datadir = dv.node_dir(directory, seat)
        os.makedirs(datadir, exist_ok=True)
        rpcport = args.rpcport or profile["node"]["rpc_port"]
        user, password = "devnet", secrets.token_hex(16)
        dv.write_private(os.path.join(datadir, "ycash.conf"), conf_text(profile, seat, user, password, rpcport, peers, args.listen))
        state["bitcoind"] = binary
        state["rpc"] = {str(seat): {"url": "http://%s:%s@127.0.0.1:%d" % (user, password, rpcport), "host": "127.0.0.1", "port": rpcport,
                                    "user": user, "password": password}}
        if args.bootstrap and not os.path.isdir(os.path.join(datadir, profile["node"]["datadir"], "blocks")):
            print("restoring the prefix into %s with ycash-bootstrap (%s)" % (datadir, args.bootstrap))
            subprocess.check_call([sys.executable, "-I", BOOTSTRAP, "--network", profile["name"], "--datadir", datadir,
                                   "--conf", os.path.join(datadir, "ycash.conf"), "--source", args.bootstrap, "--ycashd", binary,
                                   "--cli", os.path.join(os.path.dirname(binary), "ycash-cli")])
        log = open(os.path.join(datadir, "ycashd.log"), "a")
        process = subprocess.Popen([binary, "-datadir=%s" % datadir] + profile["node"]["args"], stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        log.close()
        state["spawned"] = {"pid": process.pid, "datadir": datadir}
    dv.save(directory, state)
    print("[1/2] %s node%d on %s (%s): %s" % ("attached to" if args.rpc else "started", seat, profile["name"], "peers: " + (", ".join(peers) or "none yet"),
                                              state["rpc"][str(seat)]["host"] + ":%d" % state["rpc"][str(seat)]["port"]))
    wait_rpc(dv, state, seat, process)
    node = dv.rpc(state, seat)
    info = node.getblockchaininfo()
    if info.get("chain") != profile["chain"] or (info.get("testnetprofile") or "") != profile["testnet_profile"]:
        sys.exit("the node is on chain %r profile %r, not %s" % (info.get("chain"), info.get("testnetprofile"), profile["name"]))
    print("[2/2] the %s seat (%s)" % (role, dv.ROLES[role]["what"] if role in dv.ROLES else "just the node"))
    if role in ("user", "none"):
        address = node.getnewaddress()
        state["funding_address"] = address
        print("  fund %s from the %s faucet%s; `wallet` opens the GUI on this node" % (address, profile["name"], " (%s)" % profile["endpoints"]["faucet"] if profile["endpoints"]["faucet"] else ""))
    elif role == "pool":
        address = node.getnewaddress()
        state["pools"], state["pool_addresses"] = [seat], [address]
        dv.save(directory, state)
        print("  payout address %s" % address)
        if args.stratum:
            dv.stratum_start(state, seat, args.stratum_text)
            print("  (on %s blocks come from real miners at Equihash 192,7: point one at the stratum port; `mine` is regtest-only)" % profile["name"])
    elif role == "attestor":
        conf = os.path.join(directory, "attest-%d.toml" % seat)
        creds = state["rpc"][str(seat)]
        dv.write_private(conf, ATTEST_TEMPLATE % {"network": profile["name"], "port": creds["port"], "user": creds["user"], "password": creds["password"]})
        state["funding_address"] = node.getnewaddress()
        print("  agent configuration template: %s (seq and the transport are yours to fill in)" % conf)
        print("  fund %s with your bond (yed_getinfo params.attest.bondMinZat), then register: doc/yellowback-attestor.md" % state["funding_address"])
    dv.save(directory, state)
    print("height %d of %d headers; %d peer(s); %s" % (info["blocks"], info["headers"], node.getconnectioncount(),
                                                      "synced" if info.get("initial_block_download_complete") else "syncing"))
    if info["blocks"] < profile["prefix"]["last_height"] and not args.bootstrap:
        print("  the node is below the prefix (%d): `up ... --bootstrap` restores it from the published bundle instead of syncing" % profile["prefix"]["last_height"])
    return 0


ATTEST_TEMPLATE = """# written by yellowback-devnet up --network %(network)s --role attestor: your seat's agent (doc/yellowback-attestor.md)
[node]
rpc_url = "http://127.0.0.1:%(port)d"
rpc_user = "%(user)s"
rpc_password = "%(password)s"

[attest]
seq = 0   # <- REPLACE with your seq from yed_listattestors once your registration (yed_registerattestor) confirms

# [transport]  the network's attestation transport: see doc/yellowback-attestor.md (the devnet's "dir" bus is local only)
"""


def _load(directory):
    with open(os.path.join(directory, "devnet.json")) as f:
        state = json.load(f)
    return state


def dispatch(args, dv):
    """Every command but `up` on a joined devnet."""
    command = args.command
    if command not in JOIN_COMMANDS:
        reason = REFUSED.get(command, "it drives the private regtest devnet")
        sys.exit("`%s` is regtest-only: %s (this devnet joined %s)" % (command, reason, network_of(os.path.abspath(args.dir))))
    state = _load(os.path.abspath(args.dir))
    dv.PortSeed.n = state.get("portseed", 7)
    return globals()["cmd_" + command.replace("-", "_")](args, state, dv)


def cmd_status(args, state, dv):
    profile = ybprofile.load(state["network"])
    seat = state["seat"]
    print("=" * 78)
    print("  JOINED %s (-testnet -testnetprofile=%s) -- your seat: %s on node%d" % (state["network"], state["testnet_profile"], state["role"].upper(), seat))
    print("=" * 78)
    if not dv.alive(state, seat):
        print("node%d is DOWN (%s)" % (seat, "attached: start it yourself" if not state.get("spawned") else "`up --network %s --force` restarts it" % state["network"]))
        return 1
    node = dv.rpc(state, seat)
    info = node.getblockchaininfo()
    vault = node.vault_getinfo()
    print("height %d of %d headers; %d peer(s); %s; best %s" % (info["blocks"], info["headers"], node.getconnectioncount(),
          "synced" if info.get("initial_block_download_complete") else "syncing", info.get("bestblockhash")))
    print("Vault: %s; attestor set: %s; Yellowback: %s" % (
        "at %d" % vault["activationheight"] if vault["activationheight"] >= 0 else "no height in this build",
        vault.get("attestorsetid") or "none configured", "off on this network" if not profile["yellowback"]["enabled"] else
        ("live" if vault.get("moduleactive") else "inert until the release names the attestor set")))
    if state.get("funding_address"):
        print("funding address: %s (balance %s YEC)" % (state["funding_address"], node.getbalance()))
    for pool_node in state.get("pools") or []:
        print(dv.stratum_line(state, pool_node))
    return 0


def cmd_check(args, state, dv):
    seat, problems = state["seat"], []
    if not dv.alive(state, seat):
        problems.append("node%d does not answer RPC" % seat)
    else:
        node = dv.rpc(state, seat)
        info = node.getblockchaininfo()
        if info.get("chain") != state["chain"] or (info.get("testnetprofile") or "") != state["testnet_profile"]:
            problems.append("the node is on %r/%r" % (info.get("chain"), info.get("testnetprofile")))
        if node.getconnectioncount() < 1:
            problems.append("no peers (add some with --addnode)")
        for pool_node in state.get("pools") or []:
            record = dv.stratum_of(state, pool_node)
            if record and not record.get("stopped") and not dv.agent_alive(record.get("pid")):
                problems.append("yolo beside node%d died" % pool_node)
    if (state.get("lightwalletd") or {}).get("pid"):
        problem = dv.lightwalletd_check(state)
        if problem:
            problems.append(problem)
    for p in problems:
        print(p, file=sys.stderr)
    if problems:
        return 1
    print("joined devnet check passed (%s)" % state["network"])
    return 0


def cmd_wait_blocks(args, state, dv):
    return wait_blocks(dv.rpc(state, state["seat"]), args.blocks, args.timeout)


def wait_blocks(node, blocks, timeout=0):
    """Until `blocks` more blocks have arrived (counted, never slept for)."""
    start = node.getblockcount()
    target, began, last = start + blocks, time.time(), start
    while True:
        tip = node.getblockcount()
        if tip >= target:
            print("height %d (%d new block(s))" % (tip, tip - start))
            return 0
        if tip != last:
            print("  height %d, %d to go" % (tip, target - tip), flush=True)
            last = tip
        if timeout and time.time() - began > timeout:
            print("only %d of %d blocks arrived within %ds" % (tip - start, blocks, timeout), file=sys.stderr)
            return 1
        time.sleep(2)


def cmd_down(args, state, dv):
    directory = state["dir"]
    for name in ("lightwalletd",):
        dv._kill((state.get(name) or {}).get("pid"), name)
    for node, record in sorted((state.get("stratum") or {}).items()):
        dv._kill(record.get("pid"), "yolo beside node%s" % node)
    spawned = state.get("spawned")
    if spawned and dv.agent_alive(spawned.get("pid")):
        try:
            dv.rpc(state, state["seat"]).stop()
            print("stopping node%d" % state["seat"])
        except Exception as error:
            print("node%d: %s" % (state["seat"], error))
        deadline = time.time() + dv.STOP_GRACE
        while dv.agent_alive(spawned["pid"]) and time.time() < deadline:
            time.sleep(0.5)
        if dv.agent_alive(spawned["pid"]):
            dv._kill(spawned["pid"], "node%d" % state["seat"])
    elif not spawned:
        print("node%d is yours (attached with --rpc): left running" % state["seat"])
    if args.wipe:
        shutil.rmtree(directory)
        print("wiped %s" % directory)
    return 0


def cmd_cli(args, state, dv):
    seat = state["seat"]
    if args.datadir is not None:
        print(dv.node_dir(state["dir"], seat))
        return 0
    creds = state["rpc"][str(seat)]
    binary = os.path.join(os.path.dirname(state["bitcoind"]), "ycash-cli")
    profile = ybprofile.load(state["network"])
    base = [binary] + profile["node"]["args"] + ["-rpcconnect=%s" % creds["host"], "-rpcport=%d" % creds["port"],
                                                 "-rpcuser=%s" % creds["user"], "-rpcpassword=%s" % creds["password"]]
    if state.get("spawned"):
        base.insert(1, "-datadir=%s" % state["spawned"]["datadir"])
    return subprocess.call(base + args.args)


def cmd_wallet(args, state, dv):
    if not state.get("spawned"):
        sys.exit("the GUI opens on a node this devnet started; an attached node's own ycash.conf is yours to point it at")
    args.node = state["seat"]
    return dv.wallet(args)


def cmd_scenario(args, state, dv):
    return dv.scenario(args)


def cmd_lightwalletd(args, state, dv):
    if state["seat"] != 0:
        sys.exit("lightwalletd runs against the user seat's node (node0, with the address index): `up --network %s --role user`" % state["network"])
    return dv.lightwalletd(args)


def cmd_pool(args, state, dv):
    if args.action != "stratum" or args.node not in (state.get("pools") or []):
        sys.exit("on a joined testnet only `pool %d stratum start|stop|status` applies (the payout and quote are yours)" % state["seat"])
    if args.value == "start":
        dv.stratum_start(state, args.node, args.stratum_text)
    elif args.value == "stop":
        dv.stratum_stop(state, args.node)
    else:
        print(dv.stratum_line(state, args.node))
    dv.save(state["dir"], state)
    return 0
