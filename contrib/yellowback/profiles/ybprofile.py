# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Read a network profile (testnet plan §3.1): `load("testnet-yb-fast")` -> a dict.

The profiles are the `*.toml` files beside this module. Every tool that behaves differently by
network reads one instead of testing the network's name. They use a small TOML subset (README.md)
so this module can read them on Python 3.10, which has no `tomllib` (the release image and the
CI runners are Ubuntu 22.04): `key = value` lines, `[table]` headers, `#` comments, and values
that are a "string", an integer, true/false or a one-line [array] of those. Where `tomllib`
exists the tests check that both readers agree.

Standard library only.
"""

import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
NETWORKS = ("regtest", "testnet-yb-fast", "testnet-yb-slow", "testnet-legacy")
# The YCASHD_NETWORK / -testnetprofile pair each profile answers to (the Docker entrypoint's words).
ENTRYPOINT_NAMES = {("regtest", ""): "regtest", ("testnet", "fast"): "testnet-yb-fast",
                    ("testnet", "slow"): "testnet-yb-slow", ("testnet", "legacy"): "testnet-legacy"}

_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class ProfileError(Exception):
    pass


def _strip_comment(line):
    """The line without a trailing # comment (a # inside a "string" is kept)."""
    quoted = False
    for i, ch in enumerate(line):
        if ch == '"':
            quoted = not quoted
        elif ch == "#" and not quoted:
            return line[:i]
    return line


def _scalar(text, where):
    text = text.strip()
    if text.startswith('"'):
        if len(text) < 2 or not text.endswith('"') or '"' in text[1:-1] or "\\" in text:
            raise ProfileError("%s: a string is \"...\" without quotes or backslashes inside" % where)
        return text[1:-1]
    if text in ("true", "false"):
        return text == "true"
    if re.fullmatch(r"-?(0|[1-9][0-9]*)", text):
        return int(text)
    raise ProfileError("%s: %r is not a string, integer or boolean" % (where, text))


def _value(text, where):
    text = text.strip()
    if text.startswith("["):
        if not text.endswith("]"):
            raise ProfileError("%s: an array must close on the same line" % where)
        inner = text[1:-1].strip()
        if not inner:
            return []
        items, item, quoted = [], "", False
        for ch in inner:
            if ch == '"':
                quoted = not quoted
            if ch == "," and not quoted:
                items.append(item)
                item = ""
            else:
                item += ch
        items.append(item)
        return [_scalar(i, where) for i in items]
    return _scalar(text, where)


def parse(text, name="<profile>"):
    """Parse the TOML subset. Raises ProfileError on anything outside it."""
    data, table = {}, None
    for number, raw in enumerate(text.splitlines(), 1):
        where = "%s:%d" % (name, number)
        line = _strip_comment(raw).strip()
        if not line:
            continue
        if line.startswith("["):
            m = re.fullmatch(r"\[([A-Za-z_][A-Za-z0-9_]*)\]", line)
            if not m:
                raise ProfileError("%s: a table header is [name]" % where)
            if m.group(1) in data:
                raise ProfileError("%s: table [%s] twice" % (where, m.group(1)))
            table = data[m.group(1)] = {}
            continue
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not _KEY.fullmatch(key):
            raise ProfileError("%s: expected key = value" % where)
        target = data if table is None else table
        if key in target:
            raise ProfileError("%s: key %s twice" % (where, key))
        target[key] = _value(value, where)
    return data


def profiles_dir():
    """Where the profiles are: YCASH_PROFILES_DIR, else beside this module."""
    return os.environ.get("YCASH_PROFILES_DIR") or HERE


def load(network, directory=None):
    """The profile named `network` (one of NETWORKS), with a derived `vault_height` (None if unset)."""
    if network not in NETWORKS:
        raise ProfileError("unknown network %r (one of %s)" % (network, ", ".join(NETWORKS)))
    path = os.path.join(directory or profiles_dir(), network + ".toml")
    try:
        with open(path, encoding="utf-8") as f:
            data = parse(f.read(), os.path.basename(path))
    except OSError as e:
        raise ProfileError("cannot read the %s profile: %s" % (network, e))
    if data.get("name") != network:
        raise ProfileError("%s names itself %r" % (path, data.get("name")))
    data["vault_height"] = data["heights"]["vault"] or None
    return data


def network_name(ycashd_network, testnet_profile=""):
    """The profile for the Docker entrypoint's YCASHD_NETWORK (+ YCASHD_TESTNET_PROFILE), or None."""
    return ENTRYPOINT_NAMES.get((ycashd_network, testnet_profile if ycashd_network == "testnet" else ""))
