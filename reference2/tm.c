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
// #define USE_MM_PAUSE
// #define USE_TICKET_LOCK

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
#if (defined(__i386__) || defined(__x86_64__)) && defined(USE_MM_PAUSE)
    #include <xmmintrin.h>
#else
    #include <sched.h>
#endif

#include "lock_if.h"

// Internal headers
#include <tm.h>

// -------------------------------------------------------------------------- //

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

// -------------------------------------------------------------------------- //



struct region {
    ptlock_t lock; // Global lock
    void* start;        // Start of the shared memory region
    size_t size;        // Size of the shared memory region (in bytes)
    size_t align;       // Claimed alignment of the shared memory region (in bytes)
    size_t align_alloc; // Actual alignment of the memory allocations (in bytes)
};



// -------------------------------------------------------------------------- //

shared_t tm_create(size_t size, size_t align) {
    struct region* region = (struct region*) malloc(sizeof(struct region));
    if (unlikely(!region)) {
        return invalid_shared;
    }
    size_t align_alloc = align < sizeof(void*) ? sizeof(void*) : align;
    if (unlikely(posix_memalign(&(region->start), align_alloc, size) != 0)) {
        free(region);
        return invalid_shared;
    }

    INIT_LOCK(&region->lock);
    memset(region->start, 0, size);
    region->size        = size;
    region->align       = align;
    region->align_alloc = align_alloc;
    return region;
}

void tm_destroy(shared_t shared) {
    struct region* region = (struct region*) shared;
    DESTROY_LOCK(&(region->lock));
    free(region->start);
    free(region);
}

void* tm_start(shared_t shared) {
    return ((struct region*) shared)->start;
}

size_t tm_size(shared_t shared) {
    return ((struct region*) shared)->size;
}

size_t tm_align(shared_t shared) {
    return ((struct region*) shared)->align;
}

tx_t tm_begin(shared_t shared, bool is_ro as(unused)) {
    LOCK(&(((struct region*) shared)->lock));
    return invalid_tx + 1; // There can be only one transaction running => ID is useless
}

bool tm_end(shared_t shared, tx_t tx as(unused)) {
    UNLOCK(&(((struct region*) shared)->lock));
    return true;
}

bool tm_read(shared_t shared as(unused), tx_t tx as(unused), void const* source, size_t size, void* target) {
    memcpy(target, source, size);
    return true;
}

bool tm_write(shared_t shared as(unused), tx_t tx as(unused), void const* source, size_t size, void* target) {
    memcpy(target, source, size);
    return true;
}

alloc_t tm_alloc(shared_t shared, tx_t tx as(unused), size_t size, void** target) {
    if (unlikely(posix_memalign(target, ((struct region*) shared)->align_alloc, size) != 0)) // Allocation failed
        return nomem_alloc;
    memset(*target, 0, size);
    return success_alloc;
}

bool tm_free(shared_t shared as(unused), tx_t tx as(unused), void* target) {
    free(target);
    return true;
}
