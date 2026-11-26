#!/bin/sh
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
#
# Usage: contrib/yugen-pins.sh <helper crate dir>
# Checks out every repository in <dir>/PINS ("<path> <public git URL> <full commit>") at its
# commit into <dir>/deps/<path> (git-ignored), fetching only that commit (depth 1). The source is
# the public URL, or, when YUGEN_LOCAL_ROOT is set, the local repository $YUGEN_LOCAL_ROOT/<path>
# (local development before publication; doc/yugen-release.md). A checkout already at its pin is
# left alone and nothing is fetched, so an offline build after depends reuses it. Refuses a dirty
# checkout and a commit that is not the pin.
set -eu
here=$(cd "${1:?usage: yugen-pins.sh <helper crate dir>}" && pwd)
mkdir -p "$here/deps"
while read -r name url commit; do
	case $name in ''|'#'*) continue ;; esac
	case $commit in [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
		*) echo "yugen helpers: $here/PINS: $name: '$commit' is not a full 40-hex commit" >&2; exit 1 ;; esac
	d=$here/deps/$name
	if [ "$(git -C "$d" rev-parse -q --verify 'HEAD^{commit}' 2>/dev/null || true)" != "$commit" ]; then
		if [ -n "${YUGEN_LOCAL_ROOT:-}" ]; then src=$YUGEN_LOCAL_ROOT/$name; else src=$url; fi
		[ -d "$d/.git" ] || git init -q "$d"
		git -C "$d" cat-file -e "$commit^{commit}" 2>/dev/null || git -C "$d" fetch -q --depth 1 "$src" "$commit" || {
			echo "yugen helpers: cannot fetch $name $commit from $src (set YUGEN_LOCAL_ROOT for local repositories; doc/yugen-release.md)" >&2; exit 1; }
		git -C "$d" -c advice.detachedHead=false checkout -q "$commit"
	fi
	[ -z "$(git -C "$d" status --porcelain)" ] || { echo "yugen helpers: deps/$name is dirty" >&2; exit 1; }
	[ "$(git -C "$d" rev-parse HEAD)" = "$commit" ] || { echo "yugen helpers: deps/$name is not at $commit" >&2; exit 1; }
	echo "$name $(git -C "$d" rev-parse --short HEAD)"
done < "$here/PINS"
