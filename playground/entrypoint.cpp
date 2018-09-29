// External headers
#include <atomic>
#include <iostream>

// Internal headers
extern "C" {
#include <runner.h>
}

#if defined(CONFIG_USE_CPP)
// ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――

/** Thread entry point.
 * @param nb Total number of threads
 * @param id This thread ID (from 0 to nb-1)
**/
extern "C" void entry_point(size_t nb, size_t id) {
    ::printf("Hello from C++ version in thread %lu/%lu\n", id, nb);
}

// ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
#endif
