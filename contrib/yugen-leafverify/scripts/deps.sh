#!/bin/sh
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
# Checks out the repositories in ../PINS at their pinned commits into ../deps/ (git-ignored),
# from their public URLs or, with YUGEN_LOCAL_ROOT set, from local repositories (../../yugen-pins.sh).
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
exec sh "$here/../yugen-pins.sh" "$here"
