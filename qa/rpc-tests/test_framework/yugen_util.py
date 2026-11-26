# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""Where the Yugen tests find the helper processes (doc/yugen-node.md, Helper build)."""

import os

# The build (src/Makefile.yugen.include) copies yugen-leafverify, yugen-sendbuild and yewd-yugen next to ycashd.
SRC = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'src'))


def yugen_helper(env, name):
    """The helper `name`: $env if set, else the built copy in src/."""
    return os.environ.get(env) or os.path.join(SRC, name)
