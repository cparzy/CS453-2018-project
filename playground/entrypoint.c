// External headers
#include <stdatomic.h>
#include <stdio.h>

// Internal headers
#include <runner.h>

#if !defined(CONFIG_USE_CPP)
// ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――

/** Thread entry point.
 * @param nb Total number of threads
 * @param id This thread ID (from 0 to nb-1)
**/
void entry_point(size_t nb, size_t id) {
    printf("Hello from C version in thread %lu/%lu\n", id, nb);
}

// ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
#endif
