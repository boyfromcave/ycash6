#!/bin/sh
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
# Checks out the repositories in ../PINS at their pinned commits into ../deps/ (git-ignored),
# from their public URLs or, with YUGEN_LOCAL_ROOT set, from local repositories (../../yugen-pins.sh).
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
# Our own link from the last run (below) would make the yew checkout look dirty: drop it first.
link=$here/deps/clones/yew/yewd/yugen/deps
[ ! -L "$link" ] || rm "$link"
sh "$here/../yugen-pins.sh" "$here"
# The wallet crate finds its own dependencies at yewd/yugen/deps: point that at ours (same pins).
ln -sfn ../../../.. "$link"
