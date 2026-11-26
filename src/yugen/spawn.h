// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_YUGEN_SPAWN_H
#define YCASH_YUGEN_SPAWN_H

// The Yugen helper processes' fork discipline (doc/yugen-node.md N-A5). Only Yugen code uses it;
// the stock runCommand (notify commands) keeps upstream's system(), and the Yugen pipes are
// close-on-exec so that its children do not inherit them.

#include <mutex>

#ifndef WIN32
extern "C" char** environ;
#endif

//! Held around every fork() of a Yugen helper (and while a pipe that carries a secret is made
//! close-on-exec where pipe2 is missing), so that no Yugen child inherits another one's pipe.
std::mutex& SpawnMutex();
//! The descriptor limit for CloseFdsFrom, read before fork (sysconf is not async-signal-safe).
long OpenFdLimit();
//! In a forked child: closes every descriptor from `first` up (close_range/closefrom where available).
void CloseFdsFrom(int first, long maxfd);
//! pipe2(O_CLOEXEC) where the platform has it; otherwise pipe + FD_CLOEXEC (call it with SpawnMutex held).
bool PipeCloexec(int p[2]);

#endif // YCASH_YUGEN_SPAWN_H
