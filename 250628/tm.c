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
 * Only the interface (i.e. exported symbols and semantic) must be preserved.
**/

// Requested features
#define _GNU_SOURCE
#define _POSIX_C_SOURCE   200809L
#ifdef __STDC_NO_ATOMICS__
#error Current C11 compiler does not support atomic operations
#endif

// External headers
#include <assert.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

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

#define BYTE_SIZE 8

typedef struct segment_version segment_version;

struct segment_version {
    atomic_uint v_lock;
    void* content;
    segment_version* next;
};

typedef struct {
    void* start;
    atomic_uint* v_locks;
    segment_version** versions;
    atomic_uint VClock;
    atomic_size_t size;
    atomic_size_t align;
    atomic_size_t align_alloc;
} region;

typedef struct {
    bool read;
    void* new_val;
} shared_memory_state; // Kind of a read-write set

typedef struct {
    bool is_ro;
    unsigned int rv;
    unsigned int vw;
    shared_memory_state* mem_states;
} transaction;

// === Headers

bool tm_free(shared_t shared as(unused), tx_t tx as(unused), void* target as(unused));

alloc_t tm_alloc(shared_t shared as(unused), tx_t tx as(unused), size_t size as(unused), void** target as(unused));

void free_ptr(void* ptr);

bool tm_write(shared_t shared, tx_t tx, void const* source, size_t size, void* target);

bool validate_after_read(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t start_index, size_t nb_items, unsigned int* locks_before_reading);

bool tm_read(shared_t shared, tx_t tx, void const* source, size_t size, void* target);

bool tm_read_only(shared_t shared, tx_t tx, void const* source, size_t size, void* target);

unsigned int get_unlocked_vlock(unsigned int vlock);

unsigned int get_locked_vlock(unsigned int vlock);

unsigned int extract_version(unsigned int vlock);

bool is_locked(unsigned int vlock);

size_t get_nb_items(size_t size, size_t alignment);

size_t get_start_index(shared_t shared, void const* mem_ptr);

void free_transaction(tx_t tx, shared_t shared);

void propagate_writes(shared_t shared, tx_t tx);

void release_write_locks(shared_t shared, tx_t tx, size_t until);

bool validate_read_set(shared_t shared as(unused), tx_t tx as(unused), size_t number_of_items);

bool lock_write_set(tx_t tx, shared_t shared);

bool tm_end(shared_t shared as(unused), tx_t tx as(unused));

tx_t tm_begin(shared_t shared as(unused), bool is_ro as(unused));

size_t tm_align(shared_t shared as(unused));

size_t tm_size(shared_t shared as(unused));

void* tm_start(shared_t shared as(unused));

void tm_destroy(shared_t shared as(unused));

void free_versions_linked_list(segment_version** versions, size_t nb_items);

shared_t tm_create(size_t size as(unused), size_t align as(unused));

// ===


/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size as(unused), size_t align as(unused))
{
    // Allocate the region
    region* reg = (region*) malloc(sizeof(region));
    if (unlikely(!reg)) { // means that the proposition: !region is likely false
        return invalid_shared;
    }

    // Check that the given alignment is correct
    // Also satisfy alignment requirement of 'struct link'
    size_t align_alloc = align < sizeof(void*) ? sizeof(void*) : align;

    // Allocate the first segment of the region
    if (unlikely(posix_memalign(&(reg->start), align_alloc, size) != 0)) {
        free_ptr(reg);
        return invalid_shared;
    }

    // Fill the first segment of the region with 0s
    memset(reg->start, 0, size);

    atomic_init(&(reg->size), size);
    atomic_init(&(reg->align), align);
    atomic_init(&(reg->align_alloc), align_alloc);
    atomic_init(&(reg->VClock), 0u);

    size_t number_of_items = size / align;

    // Init the array of versioned-locks
    atomic_uint* v_locks = (atomic_uint*) calloc(number_of_items, sizeof(atomic_uint));
    if (unlikely(!v_locks)) {
        free_ptr(reg->start);
        free_ptr(reg);
        return invalid_shared;
    }
    for (size_t i = 0; i < number_of_items; i++) {
        atomic_init(&(v_locks[i]), 0u);
    }
    reg->v_locks = v_locks;

    // Init the segment versions
    segment_version** versions = (segment_version**) calloc(number_of_items, sizeof(segment_version*));
    if (unlikely(!versions)) {
        free_ptr(reg->start);
        free_ptr(reg->v_locks);
        free_ptr(reg);
        return invalid_shared;
    }
    void* src = reg->start;
    for (size_t i = 0; i < number_of_items; i++) {
        void* ith_segment = malloc(align);
        memcpy(ith_segment, src, align);
        unsigned int ith_version_lock = atomic_load(&(reg->v_locks[i]));
        segment_version* first_version = (segment_version*) malloc(sizeof(segment_version));
        assert(first_version != NULL);
        first_version->content = ith_segment;
        first_version->next = NULL;
        atomic_init(&(first_version->v_lock), ith_version_lock);
        versions[i] = first_version;
        src = align + (char*)src;
    }
    reg->versions = versions;

    return reg;
}

void free_versions_linked_list(segment_version** versions, size_t nb_items)
{
    for (size_t i = 0; i < nb_items; i++) {
        segment_version* curr = versions[i];
        assert(curr != NULL);
        while (curr != NULL) {
            segment_version* next_tmp = curr->next;
            free_ptr(curr->content);
            free_ptr((void*)curr);
            curr = next_tmp;
        }
        assert(curr == NULL);
    }
    free_ptr(versions);
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared as(unused))
{
    region* reg = (region*)shared;
    size_t size = tm_size(shared);
    size_t align = tm_align(shared);
    size_t nb_items = get_nb_items(size, align);
    free_ptr(reg->start);
    free_ptr((void*)(reg->v_locks));
    free_versions_linked_list(reg->versions, nb_items);
    free_ptr(shared);
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t shared as(unused))
{
    return ((region*)shared)->start;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared as(unused))
{
    size_t size = atomic_load(&(((region*)shared)->size));
    return size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared as(unused))
{
    size_t align = atomic_load(&(((region*)shared)->align));
    return align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t shared as(unused), bool is_ro as(unused))
{
    transaction* tx = (transaction*) malloc(sizeof(transaction));
    if (unlikely(!tx)) {
        return invalid_tx;
    }

    tx->is_ro = is_ro;
    tx->rv = atomic_load(&(((region*)shared)->VClock));

    if (!tx->is_ro) {
        size_t size = tm_size(shared);
        size_t align = tm_align(shared);
        size_t nb_items = get_nb_items(size, align);
        shared_memory_state* mem_states = (shared_memory_state*) calloc(nb_items, sizeof(shared_memory_state));
        if (unlikely(!mem_states)) {
            free_ptr(tx);
            return invalid_tx;
        }
        for (size_t i = 0; i < nb_items; i++) {
            mem_states[i].read = false;
            mem_states[i].new_val = NULL;
        }
        tx->mem_states = mem_states;
    }
    return (tx_t)tx;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared as(unused), tx_t tx as(unused))
{
    if (((transaction*)tx)->is_ro) {
        free_transaction(tx, shared);
        return true;
    }

    if (!lock_write_set(tx, shared)) {
        free_transaction(tx, shared);
        return false;
    }

    size_t size = tm_size(shared);
    size_t alignment = tm_align(shared);
    size_t nb_items = get_nb_items(size, alignment);

    if (!validate_read_set(shared, tx, nb_items)) {
        release_write_locks(shared, tx, nb_items);
        free_transaction(tx, shared);
        return false;
    }

    propagate_writes(shared, tx);
    free_transaction(tx, shared);
    return true;
}

bool lock_write_set(tx_t tx, shared_t shared)
{
    region* reg = (region*)shared;
    transaction* tsct = (transaction*)tx;
    size_t size = tm_size(shared);
    size_t alignment = tm_align(shared);
    assert(size % alignment == 0);
    size_t nb_items = get_nb_items(size, alignment);
    shared_memory_state* mem_states = tsct->mem_states;
    atomic_uint* v_locks = reg->v_locks;
    for (size_t i = 0; i < nb_items; i++) {
        shared_memory_state* mem_state = &(mem_states[i]);
        // if in write-set
        if (mem_state->new_val != NULL) {
            // try to acquire the lock on this segment
            atomic_uint* ith_v_lock = &(v_locks[i]);
            unsigned int old_value = atomic_load(ith_v_lock);
            // compute the expected value
            unsigned int expected_value = get_unlocked_vlock(old_value);
            // compute the new value
            unsigned int new_value = get_locked_vlock(old_value);

            bool got_the_lock = atomic_compare_exchange_strong(ith_v_lock, &expected_value, new_value);
            if (!got_the_lock) {
                // release all the locks acquired until now
                release_write_locks(shared, tx, i);
                return false;
            }
        }
    }
    return true;
}

bool validate_read_set(shared_t shared as(unused), tx_t tx as(unused), size_t number_of_items)
{
    if (shared == NULL || (void*)tx == NULL) {
        return false;
    }
    region* reg = (region*)shared;
    transaction* tsct = (transaction*)tx;
    for (size_t i = 0; i < number_of_items; i++) {
        // If is read-set
        shared_memory_state* ith_memory = &(tsct->mem_states[i]);
        if (ith_memory->read) {
            // version_lock* curr_version_lock = &(((struct region*)shared)->version_locks[i]);
            unsigned int v_l = atomic_load(&(reg->v_locks[i]));
            bool locked = is_locked(v_l);
            unsigned int version = extract_version(v_l);
            // if it is not in the write-set but it is locked
            if (ith_memory->new_val == NULL && locked) {
                return false;
            }
            if (version > tsct->rv) {
                return false;
            }
        }
    }
    return true;
}

// When this function is called, we have all the write locks until index 'until' of the segments in the write set
// It will release the nb_items first locks
// If you want to release all locks, nb_items should be equals to the total number of items (size / alignment)
void release_write_locks(shared_t shared, tx_t tx, size_t until)
{
    size_t size = tm_size(shared);
    assert(until <= size);

    atomic_uint* v_locks = ((region*)shared)->v_locks;
    shared_memory_state* mem_states = ((transaction*)tx)->mem_states;
    for (size_t i = 0; i < until; i++) {
        shared_memory_state* mem_state = &(mem_states[i]);
        if (mem_state->new_val != NULL) {
            atomic_uint* ith_v_lock = &(v_locks[i]);
            unsigned int old_value = atomic_load(ith_v_lock);
            assert(is_locked(old_value));
            unsigned int new_value = get_unlocked_vlock(old_value);
            atomic_store(ith_v_lock, new_value);
        }
    }
}

void propagate_writes(shared_t shared, tx_t tx)
{
    unsigned int former_vclock = atomic_fetch_add(&(((region*)shared)->VClock), 1);
    unsigned int vw = former_vclock + 1;
    region* reg = (region*)shared;
    transaction* tsct = (transaction*)tx;
    tsct->vw = vw;

    size_t size = tm_size(shared);
    size_t alignment = tm_align(shared);
    size_t nb_items = get_nb_items(size, alignment);

    atomic_uint* v_locks = reg->v_locks;
    void* start = tm_start(shared);
    segment_version** versions = reg->versions;

    shared_memory_state* mem_states = tsct->mem_states;

    for (size_t i = 0; i < nb_items; i++) {
        shared_memory_state* mem_state = &(mem_states[i]);
        if (mem_state->new_val != NULL) {
            atomic_uint* ith_v_lock = &(v_locks[i]);
            unsigned long version = atomic_load(ith_v_lock);
            assert(is_locked(version));

            // point to the correct segment of shared memory
            void* target_segment = (i * alignment) + (char*)start;

            segment_version* s_version = (segment_version*) malloc(sizeof(segment_version));
            atomic_init(&(s_version->v_lock), tsct->vw);
            s_version->content = malloc(alignment);
            memcpy(s_version->content, mem_state->new_val, alignment);

            assert(versions[i] != NULL);
            assert(extract_version(atomic_load(&(versions[i]->v_lock))) < tsct->vw);
            s_version->next = versions[i];
            versions[i] = s_version;

            // write to the shared memory and update the version
            unsigned int new_version = get_unlocked_vlock(tsct->vw);
            memcpy(target_segment, mem_state->new_val, alignment);
            atomic_store(ith_v_lock, new_version);
        }
    }
}

void free_transaction(tx_t tx, shared_t shared)
{
    if ((void*)tx == NULL) {
        return;
    }
    if (!((transaction*)tx)->is_ro) {
        size_t size = tm_size(shared);
        size_t alignment = tm_align(shared);
        size_t nb_items = get_nb_items(size, alignment);
        for (size_t i = 0; i < nb_items; i++) {
            shared_memory_state* mem_state = &(((transaction*)tx)->mem_states[i]);
            if (mem_state->new_val != NULL) {
                free_ptr(mem_state->new_val);
            }
        }
        free_ptr((void*)(((transaction*)tx)->mem_states));
    }
    free_ptr((void*)tx);
}

size_t get_start_index(shared_t shared, void const* mem_ptr)
{
    size_t alignment = tm_align(shared);
    void* start = tm_start(shared);
    size_t start_index = (mem_ptr - start) / alignment;
    return start_index;
}

size_t get_nb_items(size_t size, size_t alignment)
{
    size_t nb_items = size / alignment;
    return nb_items;
}

bool is_locked(unsigned int vlock)
{
    size_t shift_amount = (sizeof(unsigned int) * BYTE_SIZE - 1);
    unsigned int mask = 1u << shift_amount;
    return (vlock & mask) >> shift_amount;
}

unsigned int extract_version(unsigned int vlock)
{
    unsigned int mask = ~(0u) >> 1;
    return vlock & mask;
}

unsigned int get_locked_vlock(unsigned int vlock)
{
    unsigned int mask = 1u << (sizeof(unsigned int) * BYTE_SIZE - 1);
    unsigned int locked_vlock = vlock | mask;
    assert(is_locked(locked_vlock));
    return locked_vlock;
}

unsigned int get_unlocked_vlock(unsigned int vlock)
{
    unsigned int mask = ~(0u) >> 1;
    unsigned int unlocked_vlock = vlock & mask;
    assert(!is_locked(unlocked_vlock));
    return unlocked_vlock;
}


bool tm_read_only(shared_t shared, tx_t tx, void const* source, size_t size, void* target)
{
    region* reg = (region*)shared;
    transaction* tsct = (transaction*)tx;
    size_t alignment = tm_align(shared);
    assert(size % alignment == 0);
    size_t nb_items = get_nb_items(size, alignment);
    size_t start_index = get_start_index(shared, source);
    void* current_target = target;
    for (size_t i = 0; i < nb_items; i++) {
        size_t segment_index = start_index + i;
        segment_version* s_version = reg->versions[segment_index];
        assert(s_version != NULL);
        while (s_version != NULL && extract_version(atomic_load(&(s_version->v_lock))) > tsct->rv) {
            s_version = s_version->next;
        }
        assert(s_version != NULL);
        assert(extract_version(atomic_load(&(s_version->v_lock))) <= tsct->rv);
        memcpy(current_target, s_version->content, alignment);
        current_target = alignment + (char*)current_target;
    }
    return true;
}

/** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in the shared region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in a private region)
 * @return Whether the whole transaction can continue
**/
bool tm_read(shared_t shared, tx_t tx, void const* source, size_t size, void* target)
{
    transaction* tsct = (transaction*)tx;
    if (tsct->is_ro) {
        return tm_read_only(shared, tx, source, size, target);
    }

    region* reg = (region*)shared;
    size_t alignment = tm_align(shared);
    assert(size % alignment == 0);
    size_t nb_items = get_nb_items(size, alignment);
    size_t start_index = get_start_index(shared, source);
    void* current_target = target;
    void const* current_source = source;

    unsigned int* locks_before_reading = (unsigned int*) calloc(nb_items, sizeof(unsigned int));
    assert(locks_before_reading != NULL);
    for (size_t i = 0; i < nb_items; i++) {
        size_t lock_index = start_index + i;
        atomic_uint* ith_version_lock = &(reg->v_locks[lock_index]);
        unsigned int ith_lock = atomic_load(ith_version_lock);
        locks_before_reading[i] = ith_lock;
        if (is_locked(ith_lock) || extract_version(ith_lock) > tsct->rv) {
            free(locks_before_reading);
            free_transaction(tx, shared);
            return false;
        }
    }

    for (size_t i = 0; i < nb_items; i++) {
        size_t segment_index = start_index + i;
        shared_memory_state* mem_state = &(tsct->mem_states[segment_index]);
        if (mem_state->new_val != NULL) {
            memcpy(current_target, mem_state->new_val, alignment);
        } else {
            memcpy(current_target, current_source, alignment);
        }
        mem_state->read = true;
        current_source = alignment + (char*)current_source;
        current_target = alignment + (char*)current_target;
    }

    bool validated = validate_after_read(shared, tx, source, start_index, nb_items, locks_before_reading);
    free_ptr((void*)locks_before_reading);
    if (!validated) {
        free_transaction(tx, shared);
        return false;
    }
    return true;
}

bool validate_after_read(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t start_index, size_t nb_items, unsigned int* locks_before_reading)
{
    if (shared == NULL || (void*)tx == NULL || source == NULL || locks_before_reading == NULL) {
        // printf ("validate_after_read fail\n");
        return false;
    }
    region* reg = (region*)shared;
    transaction* tsct = (transaction*)tx;
    for (size_t i = 0; i < nb_items; i++) {
        unsigned int before_read_lock = locks_before_reading[i];
        assert(!is_locked(before_read_lock));
        unsigned int before_read_version = extract_version(before_read_lock);
        assert(before_read_version <= tsct->rv);
        size_t lock_index = i + start_index;
        unsigned int v_l = atomic_load(&(reg->v_locks[lock_index]));
        bool locked = is_locked(v_l);
        if (locked) {
            return false;
        }
        unsigned int version = extract_version(v_l);
        if (before_read_version != version || version > tsct->rv) {
            return false;
        }
    }
    // printf ("validate_after_read success\n");
    return true;
}

/** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in a private region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in the shared region)
 * @return Whether the whole transaction can continue
**/
bool tm_write(shared_t shared, tx_t tx, void const* source, size_t size, void* target)
{
    transaction* tsct = (transaction*)tx;
    assert(!tsct->is_ro);
    size_t alignment = tm_align(shared);
    assert(size % alignment == 0);
    size_t start_index = get_start_index(shared, target);
    size_t number_of_items = get_nb_items(size, alignment);
    const void* current_src_slot = source;
    for (size_t i = start_index; i < start_index + number_of_items; i++) {
        shared_memory_state* memory_state = &(tsct->mem_states[i]);
        if (memory_state->new_val != NULL) {
            memcpy(memory_state->new_val, current_src_slot, alignment);
        } else {
            memory_state->new_val = malloc(alignment);
            assert(memory_state->new_val != NULL);
            memcpy(memory_state->new_val, current_src_slot, alignment);
        }
        current_src_slot = alignment + (const char*)current_src_slot;
    }
    return true;
}

void free_ptr(void* ptr)
{
    assert(ptr != NULL);
    free(ptr);
    ptr = NULL;
}

/** [thread-safe] Memory allocation in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param size   Allocation requested size (in bytes), must be a positive multiple of the alignment
 * @param target Pointer in private memory receiving the address of the first byte of the newly allocated, aligned segment
 * @return Whether the whole transaction can continue (success/nomem), or not (abort_alloc)
**/
alloc_t tm_alloc(shared_t shared as(unused), tx_t tx as(unused), size_t size as(unused), void** target as(unused))
{
    // TODO: tm_alloc(shared_t, tx_t, size_t, void**)
    return abort_alloc;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t shared as(unused), tx_t tx as(unused), void* target as(unused))
{
    // TODO: tm_free(shared_t, tx_t, void*)
    return false;
}
