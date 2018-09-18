/**
 * @file   tm.c
 * @author Sébastien Rouault <sebastien.rouault@epfl.ch>
 *
 * @section LICENSE
 *
 * Copyright © 2018 Sébastien Rouault.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * any later version. Please see https://gnu.org/licenses/gpl.html
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * @section DESCRIPTION
 *
 * Lock-based transaction manager implementation used as the reference.
**/

// Compile-time configuration
// #define use_mm_pause

// Requested features
#define _GNU_SOURCE
#define _POSIX_C_SOURCE   200809L
#ifdef __STDC_NO_ATOMICS__
    #error Current C11 compiler does not support atomic operations
#endif

// External headers
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#if (defined(__i386__) || defined(__x86_64__)) && defined(use_mm_pause)
    #include <xmmintrin.h>
#else
    #include <sched.h>
#endif

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

struct lock_t {
    atomic_bool locked; // Whether the lock is taken
};

struct region {
    struct lock_t lock; // Global lock
    void* start;        // Start of the shared memory region
    size_t size;        // Size of the shared memory region (in bytes)
    size_t align;       // Alignment of the shared memory region (in bytes)
};

// ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――

/** Pause for a very short amount of time.
**/
static void pause() {
#if (defined(__i386__) || defined(__x86_64__)) && defined(use_mm_pause)
    _mm_pause();
#else
    sched_yield();
#endif
}

/** Initialize the given lock.
 * @param lock Lock to initialize
 * @return Whether the operation is a success
**/
static bool lock_init(struct lock_t* lock) {
    atomic_init(&(lock->locked), false);
    return true;
}

/** Clean the given lock up.
 * @param lock Lock to clean up
**/
static void lock_cleanup(struct lock_t* lock as(unused)) {
    return;
}

/** Wait and acquire the given lock.
 * @param lock Lock to acquire
 * @return Whether the operation is a success
**/
static bool lock_acquire(struct lock_t* lock) {
    bool expected = false;
    while (unlikely(!atomic_compare_exchange_weak_explicit(&(lock->locked), &expected, true, memory_order_acquire, memory_order_relaxed))) {
        expected = false;
        while (unlikely(atomic_load_explicit(&(lock->locked), memory_order_relaxed)))
            pause();
    }
    return true;
}

/** Release the given lock.
 * @param lock Lock to acquire
 * @return Whether the operation is a success
**/
static void lock_release(struct lock_t* lock) {
    atomic_store_explicit(&(lock->locked), false, memory_order_release);
}

// ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――

/** Initial allocation of a shared memory region.
 * @param size  Size of the shared memory region to allocate (in bytes)
 * @param align Power of 2 alignment of the allocated, shared memory region
 * @return Opaque shared memory region handle, NULL on failure
**/
shared_t tm_create(size_t size, size_t align) {
    struct region* region = (struct region*) malloc(sizeof(struct region));
    if (unlikely(!region))
        return NULL;
    if (unlikely(posix_memalign(&(region->start), align, size) != 0)) {
        free(region);
        return NULL;
    }
    if (unlikely(!lock_init(&(region->lock)))) {
        free(region->start);
        free(region);
        return NULL;
    }
    region->size  = size;
    region->align = align;
    return region;
}

/** Clean-up the given shared memory region.
 * @param shared Shared memory region to clean-up, with no running transaction
**/
void tm_destroy(shared_t shared) {
    struct region* region = (struct region*) shared;
    lock_cleanup(&(region->lock));
    free(region->start);
    free(region);
}

/** [thread-safe] Return the start address of the given shared memory region.
 * @param shared Shared memory region to query
 * @return Start address (this function never fails if 'shared' has not been destroyed)
**/
void* tm_start(shared_t shared) {
    return ((struct region*) shared)->start;
}

/** [thread-safe] Return the size/alignment (in bytes) of the given shared memory region.
 * @param shared Shared memory region to query
 * @return Region size/alignment (this function never fails if 'shared' has not been destroyed)
**/
size_t tm_size(shared_t shared) {
    return ((struct region*) shared)->size;
}
size_t tm_align(shared_t shared) {
    return ((struct region*) shared)->align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t shared) {
    if (unlikely(!lock_acquire(&(((struct region*) shared)->lock))))
        return invalid_tx;
    return 1; // There can be only one transaction running => ID is useless
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region to start a transaction on
 * @param tx     Transaction to end
 * @return Whether the whole transaction is a success
**/
bool tm_end(shared_t shared, tx_t tx as(unused)) {
    lock_release(&(((struct region*) shared)->lock));
    return true;
}

/** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
 * @param shared Shared memory region to start a transaction on
 * @param tx     Transaction to use
 * @param source Source start address
 * @param size   Source/target range
 * @param target Target start address
 * @return Whether the whole transaction can continue
**/
bool tm_read(shared_t shared as(unused), tx_t tx as(unused), void const* source, size_t size, void* target) {
    memcpy(target, source, size);
    return true;
}

/** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
 * @param shared Shared memory region to start a transaction on
 * @param tx     Transaction to use
 * @param source Source start address
 * @param size   Source/target range
 * @param target Target start address
 * @return Whether the whole transaction can continue
**/
bool tm_write(shared_t shared as(unused), tx_t tx as(unused), void const* source, size_t size, void* target) {
    memcpy(target, source, size);
    return true;
}
