// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yugen/spawn.h"

#include <fcntl.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif

std::mutex& SpawnMutex()
{
    static std::mutex m;
    return m;
}

long OpenFdLimit()
{
    const long maxfd = sysconf(_SC_OPEN_MAX);
    return maxfd > 0 ? maxfd : 1024;
}

// Called in a forked child: async-signal-safe only (close_range/closefrom where the platform has them, else
// close() up to `maxfd`, which the parent computed before fork).
void CloseFdsFrom(int first, long maxfd)
{
#if defined(__linux__) && defined(SYS_close_range)
    if (syscall(SYS_close_range, (unsigned)first, ~0U, 0) == 0) return;
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
    closefrom(first);
    return;
#endif
    for (long i = first; i < maxfd; i++) close((int)i);
}

bool PipeCloexec(int p[2])
{
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    return pipe2(p, O_CLOEXEC) == 0;
#else
    if (pipe(p) != 0) return false;
    fcntl(p[0], F_SETFD, FD_CLOEXEC);
    fcntl(p[1], F_SETFD, FD_CLOEXEC);
    return true;
#endif
}
