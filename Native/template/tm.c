/**
 * @file   tm.c
 * @author [...]
 *
 * @section LICENSE
 *
 * [...]
 *
 * @section DESCRIPTION
 *
 * Implementation of your own transaction manager.
 * You can completely rewrite this file (and create more files) as you wish.
**/

// Requested features
#define _GNU_SOURCE
#define _POSIX_C_SOURCE   200809L
#ifdef __STDC_NO_ATOMICS__
    #error Current C11 compiler does not support atomic operations
#endif

// External headers


// Internal headers
#include <tm.h>

// ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――

/** Define a proposition as likely true.
 * @param prop Proposition
**/
#undef likely
#ifdef __GNUC__
    #define likely(prop) \
        __builtin_expect((prop) ? 1 : 0, 1)
#else
    #define likely(prop) \
        (prop)
#endif

/** Define a proposition as likely false.
 * @param prop Proposition
**/
#undef unlikely
#ifdef __GNUC__
    #define unlikely(prop) \
        __builtin_expect((prop) ? 1 : 0, 0)
#else
    #define unlikely(prop) \
        (prop)
#endif

/** Define one or several attributes.
 * @param type... Attribute names
**/
#undef as
#ifdef __GNUC__
    #define as(type...) \
        __attribute__((type))
#else
    #define as(type...)
    #warning This compiler has no support for GCC attributes
#endif

// ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――

/** Initial allocation of a shared memory region.
 * @param size  Size of the shared memory region to allocate (in bytes)
 * @param align Power of 2 alignment of the allocated, shared memory region
 * @return Opaque shared memory region handle, NULL on failure
**/
shared_t tm_create(size_t size as(unused), size_t align as(unused)) {
    // TODO: tm_create(size_t, size_t)
    return NULL;
}

/** Clean-up the given shared memory region.
 * @param shared Shared memory region to clean-up, with no running transaction
**/
void tm_destroy(shared_t shared as(unused)) {
    // TODO: tm_destroy(shared_t)
}

/** [thread-safe] Return the start address of the given shared memory region.
 * @param shared Shared memory region to query
 * @return Start address (this function never fails if 'shared' has not been destroyed)
**/
void* tm_start(shared_t shared as(unused)) {
    // TODO: tm_start(shared_t)
    return NULL;
}

/** [thread-safe] Return the size/alignment (in bytes) of the given shared memory region.
 * @param shared Shared memory region to query
 * @return Region size/alignment (this function never fails if 'shared' has not been destroyed)
**/
size_t tm_size(shared_t shared as(unused)) {
    // TODO: tm_start(shared_t)
    return 0;
}
size_t tm_align(shared_t shared as(unused)) {
    // TODO: tm_start(shared_t)
    return 0;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t shared as(unused)) {
    // TODO: tm_begin(shared_t)
    return 0;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region to start a transaction on
 * @param tx     Transaction to end
 * @return Whether the whole transaction is a success
**/
bool tm_end(shared_t shared as(unused), tx_t tx as(unused)) {
    // TODO: tm_end(shared_t, tx_t)
    return false;
}

/** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
 * @param shared Shared memory region to start a transaction on
 * @param tx     Transaction to use
 * @param source Source start address
 * @param size   Source/target range
 * @param target Target start address
 * @return Whether the whole transaction can continue
**/
bool tm_read(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t size as(unused), void* target as(unused)) {
    // TODO: tm_read(shared_t, tx_t, void const*, size_t, void*)
    return false;
}

/** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
 * @param shared Shared memory region to start a transaction on
 * @param tx     Transaction to use
 * @param source Source start address
 * @param size   Source/target range
 * @param target Target start address
 * @return Whether the whole transaction can continue
**/
bool tm_write(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t size as(unused), void* target as(unused)) {
    // TODO: tm_write(shared_t, tx_t, void const*, size_t, void*)
    return false;
}
