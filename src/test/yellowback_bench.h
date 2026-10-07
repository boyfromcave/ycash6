// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_TEST_YELLOWBACK_BENCH_H
#define YCASH_TEST_YELLOWBACK_BENCH_H

#include <cstdlib>
#include <cstdint>

#if defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer) || __has_feature(memory_sanitizer)
#define YELLOWBACK_BENCH_INSTRUMENTED 1
#endif
#endif
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__) || defined(DEBUG_LOCKORDER)
#define YELLOWBACK_BENCH_INSTRUMENTED 1
#endif

/** The factor the throughput benches (N6: a 2 MB block through EvaluateBlock in < 200 ms, 10,000
 *  plain transactions through MempoolCheck in < 1 s) apply to their time budgets. The budgets are
 *  performance smoke on an optimised build, not correctness; an instrumented build (ASan/UBSan,
 *  TSan, MSan, DEBUG_LOCKORDER's --enable-debug -O0) is many times slower for reasons unrelated to
 *  the code under test, so there the budget is scaled by 10 (and still checked, so a real
 *  regression of an order of magnitude is caught). YELLOWBACK_BENCH_SCALE=<n> overrides the factor
 *  for a build the macros cannot see (lcov --coverage, valgrind); 0 or garbage means 1. */
inline int64_t BenchBudgetScale()
{
    if (const char* env = std::getenv("YELLOWBACK_BENCH_SCALE")) {
        const long n = std::strtol(env, nullptr, 10);
        if (n > 0) return (int64_t)n;
    }
#ifdef YELLOWBACK_BENCH_INSTRUMENTED
    return 10;
#else
    return 1;
#endif
}

#endif // YCASH_TEST_YELLOWBACK_BENCH_H
