#!/usr/bin/env bash
# Patch src/sync.cpp IN THE BUILD CHECKOUT ONLY (never committed; sync.cpp stays at zero delta vs
# ycash6-baseline, mapping §19 S3) so a --enable-debug (DEBUG_LOCKORDER) ycashd can run the
# functional suite. Two stock-6.20.0 behaviours otherwise stop it before any Yellowback code runs:
#
#  1. Fatal detector. potential_deadlock_detected() aborts (g_debug_lockorder_abort defaults to
#     true, sync.cpp:203) or, with the global false, throws std::logic_error out of LOCK (sync.cpp:112),
#     which TraceThread rethrows. ycashd has no option to set the global (only sync_tests does), and
#     stock 6.20.0 trips it on the first block relay between two peers (the cs_vNodes /
#     pnode->cs_vRecvMsg TRY_LOCK pair, net.cpp:1191/1218 vs net.cpp:1713 + main.cpp:4886). The patch
#     makes it log-only, as v4.5.0's DEBUG_LOCKORDER_LOGONLY did; qa/yellowback-lockorder-check.py
#     then judges every report in debug.log.
#  2. Exit-time use-after-free. The lock bookkeeping is a function-local static (GetLockData) and
#     a thread_local lock stack (g_lockstack), both destroyed at exit() before the static
#     CNetCleanup, whose destructor still takes LOCK(pnode->cs_hSocket) (net.cpp:2009). The writes
#     into the freed map/vector corrupt the heap and the process dies in ~CNode (macOS:
#     _os_unfair_lock_corruption_abort in pthread_mutex_destroy, net.cpp:2020 -> :2276), so every
#     node with a peer fails its own shutdown. Leaking both objects (as upstream Bitcoin Core's
#     GetLockData does) removes it. v4.5.0 did not have this: its lock stack was a
#     boost::thread_specific_ptr with NULL guards.
#
# Usage: qa/yellowback-lockorder-logonly.sh [repo-root]   (idempotent check: fails if a pattern is gone)
set -euo pipefail
f="${1:-.}/src/sync.cpp"
perl -0pi -e '
  $n = 0;
  $n += s/^bool g_debug_lockorder_abort = true;$/bool g_debug_lockorder_abort = false;   \/\/ yellowback-lockorder-logonly/m;
  $n += s/^    throw std::logic_error\("potential deadlock detected"\);$/    \/\/ yellowback-lockorder-logonly: report only, keep running/m;
  $n += s/^    static LockData lockdata;$/    static LockData& lockdata = *new LockData();   \/\/ yellowback-lockorder-logonly: never destroyed/m;
  $n += s/^static thread_local LockStack g_lockstack;$/static thread_local LockStack& g_lockstack = *new LockStack();   \/\/ yellowback-lockorder-logonly: never destroyed/m;
  die "yellowback-lockorder-logonly: expected 4 substitutions in sync.cpp, made $n\n" unless $n == 4;
' "$f"
echo "patched $f (log-only DEBUG_LOCKORDER, bookkeeping never destroyed)"
