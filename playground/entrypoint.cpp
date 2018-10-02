#include "config.h"
#if defined(CONFIG_USE_CPP)
// ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――

// External headers
#include <atomic>
#include <iostream>
#include <mutex>

// Internal headers
#include "entrypoint.hpp"
extern "C" {
#include "runner.h"
}

// ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――

/** Lock default constructor.
**/
Lock::Lock() {
    // Code here
}

/** Lock destructor.
**/
Lock::~Lock() {
    // Code here
}

/** [thread-safe] Acquire the given lock, wait if it has already been acquired.
**/
void Lock::acquire() {
    // Code here
}

/** [thread-safe] Release the given lock.
 * @param lock Initialized lock structure
**/
void Lock::release() {
    // Code here
}

// ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――

/** Thread entry point.
 * @param nb Total number of threads
 * @param id This thread ID (from 0 to nb-1 included)
**/
void entry_point(size_t nb, size_t id, Lock& lock) {
    ::printf("Hello from C++ version in thread %lu/%lu\n", id, nb); // Feel free to remove me
    for (int i = 0; i < 10000; ++i) {
        ::std::lock_guard<Lock> guard{lock};
        ::shared_access();
    }
}

// ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
#endif
