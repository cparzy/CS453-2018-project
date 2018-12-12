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

shared_t tm_create(size_t size as(unused), size_t align as(unused));
void tm_destroy(shared_t shared as(unused));
void* tm_start(shared_t shared as(unused));
size_t tm_size(shared_t shared as(unused));
size_t tm_align(shared_t shared as(unused));
tx_t tm_begin(shared_t shared as(unused), bool is_ro as(unused));
bool tm_end(shared_t shared as(unused), tx_t tx as(unused));
void free_transaction(tx_t tx, shared_t shared);
size_t get_start_index(shared_segment_node* shared_segment, size_t alignment, void const* mem_ptr);
size_t get_nb_items(size_t size, size_t alignment);
bool is_locked(unsigned int versioned_lock);
unsigned int extract_version(unsigned int versioned_lock);
bool validate_after_read(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t start_index, size_t nb_items, unsigned int* locks_before_reading, shared_segment_node* shared_segment);
local_segment_node* create_local_from_shared_segment(shared_segment_node* segment, size_t alignment);
shared_segment_node* get_shared_segment(void const* source, shared_t shared);
local_segment_node* get_local_segment(void const* source, txt_t tx, shared_segment_node* shared_segment, size_t alignment);
bool tm_read(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t size as(unused), void* target as(unused));
bool tm_write(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t size as(unused), void* target as(unused));
bool tm_validate(shared_t shared as(unused), tx_t tx as(unused));
void release_write_lock(shared_t shared as(unused), tx_t tx as(unused), local_segment_node* last_segment_locked, size_t nb_items_in_last_segment, bool release_all);
void propagate_writes(shared_t shared as(unused), tx_t tx as(unused));
bool validate_read_set(shared_t shared as(unused), tx_t tx as(unused), size_t alignment);
bool lock_write_set(shared_t shared, tx_t tx);
void free_ptr(void* ptr);

typedef struct {
    uintptr_t from;
    uintptr_t to;
    size_t size;
    void* start;
    shared_segment_node* next;
    atomic_uint* version_locks; // The last bit is the lock bit
    atomic_bool free;
} shared_segment_node;

typedef struct {
    uintptr_t from;
    uintptr_t to;
    size_t size;
    shared_memory_state* mem_state;
    local_segment_node* next;
    shared_segment_node* shared_segment;
} local_segment_node;

struct region {
    atomic_size_t size;        // Size of the shared memory region (in bytes)
    atomic_size_t align;       // Claimed alignment of the shared memory region (in bytes)
    atomic_size_t align_alloc; // Actual alignment of the memory allocations (in bytes)
    atomic_uint VClock;
    shared_segment_node* first_shared_segment;
};

typedef struct {
    bool read;
    void* new_val;
} shared_memory_state;

struct transaction {
    bool is_ro; // whether the transaction is read-only
    unsigned int rv; // read-version number
    unsigned int vw; // write-version number
    local_segment_node* first_segment;
};

/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size as(unused), size_t align as(unused))
{

    // Allocate the region
    struct region* region = (struct region*) malloc(sizeof(struct region));
    if (unlikely(!region)) { // means that the proposition: !region is likely false
        return invalid_shared;
    }

    // Check that the given alignment is correct
    // Also satisfy alignment requirement of 'struct link'
    size_t align_alloc = align < sizeof(void*) ? sizeof(void*) : align;

    shared_segment_node* first_segment = (shared_segment_node*) malloc(sizeof(shared_segment_node));
    assert(first_segment != NULL);
    // Allocate the first segment of the region
    if (unlikely(posix_memalign(&(first_segment->start), align_alloc, size) != 0)) {
        free_ptr(region);
        return invalid_shared;
    }
    // Fill the first segment of the region with 0s
    memset(first_segment->start, 0, size);

    first_segment->from = (uintptr_t) first_segment->start;
    first_segment->size = size;
    first_segment->to = (uintptr_t) first_segment->start + size;
    first_segment->next = NULL;
    atomic_init(&(first_segment->free), false);

    atomic_init(&(region->size), size);
    atomic_init(&(region->align), align);
    atomic_init(&(region->align_alloc), align_alloc);
    atomic_init(&(region->VClock), 0u);

    size_t number_of_items = get_nb_items(size, align);

    // Init the array of versioned-locks
    atomic_uint* version_locks = (atomic_uint*) calloc(number_of_items, sizeof(atomic_uint));
    assert(version_locks != NULL);
    for (size_t i = 0; i < number_of_items; i++) {
        atomic_init(&(version_locks[i]), 0u);
    }
    first_segment->version_locks = version_locks;

    region->first_shared_segment = first_segment;

    // printf ("Region %p created\n", (void*)region);
    return region;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared as(unused))
{
    struct region* reg = (struct region*)shared;
    shared_segment_node* curr_segment = reg->first_shared_segment;
    while (curr_segment != NULL) {
        shared_segment_node* next = curr_segment->next;
        free_ptr(curr_segment->start);
        free_ptr((void*)(curr_segment->version_locks));
        free_ptr((void*)curr_segment);
        curr_segment = next;
    }
    free_ptr(shared);
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t shared as(unused))
{
    struct region* reg = (struct region*)shared;
    return reg->first_shared_segment->start;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared as(unused))
{
    size_t size = atomic_load(&(((struct region*)shared)->size));
    return size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared as(unused))
{
    size_t align = atomic_load(&(((struct region*)shared)->align));
    return align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t shared, bool is_ro)
{
    struct region* reg = (struct region*)shared;
    unsigned int global_clock = atomic_load(&((reg->VClock)));
    struct transaction* trans = (struct transaction*) malloc(sizeof(struct transaction));
    if (unlikely(!trans)) {
        // printf ("tm_begin failed\n");
        return invalid_tx;
    }

    trans->rv = global_clock;
    trans->is_ro = is_ro;
    trans->first_segment = NULL;
    return (tx_t)trans;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared as(unused), tx_t tx as(unused))
{
    if (((struct transaction*)tx)->is_ro) {
        free_transaction(tx, shared);
        return true;
    }
    bool validated = tm_validate(shared, tx);
    if (!validated) {
        free_transaction(tx, shared);
        // printf ("tm_end fail, tx: %p, shared: %p\n", (void*)tx, (void*)shared);
        return false;
    }
    // Propage writes to shared memory and release write locks
    propagate_writes(shared, tx);
    free_transaction(tx, shared);
    // printf ("tm_end succeeded?: %d, tx: %p, shared: %p\n", validated, (void*)tx, (void*)shared);
    return validated;
}

void free_transaction(tx_t tx, shared_t shared)
{
    size_t alignment = tm_align(shared);
    struct transaction* trans = (struct transaction*)tx;
    if (!trans->is_ro) {
        local_segment_node* curr_local_segment = trans->first-segment;
        while (curr_local_segment != NULL) {
            size_t size = curr_local_segment->size;
            size_t nb_items = get_nb_items(size, alignment);
            if ((void*)tx == NULL) {
                return;
            }
            for (size_t i = 0; i < nb_items; i++) {
                shared_memory_state* mem_state = &(curr_local_segment->mem_state[i]);
                if (mem_state->new_val != NULL) {
                    free_ptr(mem_state->new_val);
                }
            }
            free_ptr((void*)curr_local_segment->mem_state);
            curr_local_segment = curr_local_segment->next;
        }
    }
    free_ptr((void*)tx);
}

size_t get_start_index(shared_segment_node* shared_segment, size_t alignment, void const* mem_ptr)
{
    size_t alignment = tm_align(shared);
    void* start = shared_segment->start;
    size_t start_index = (mem_ptr - start) / alignment;
    return start_index;
}

size_t get_nb_items(size_t size, size_t alignment)
{
    size_t nb_items = size / alignment;
    return nb_items;
}

bool is_locked(unsigned int versioned_lock)
{
    unsigned int is_locked_mask = 1 << (sizeof(unsigned int) * BYTE_SIZE - 1);
    return (versioned_lock & is_locked_mask) >> (sizeof(unsigned int) * BYTE_SIZE - 1);
}

unsigned int extract_version(unsigned int versioned_lock)
{
    unsigned int extract_version_mask = ~(0u) >> 1;
    return versioned_lock & extract_version_mask;
}

bool validate_after_read(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t start_index, size_t nb_items, unsigned int* locks_before_reading, shared_segment_node* shared_segment)
{
    if (shared == NULL || (void*)tx == NULL || source == NULL || locks_before_reading == NULL) {
        // printf ("validate_after_read fail\n");
        return false;
    }
    for (size_t i = 0; i < nb_items; i++) {
        unsigned int before_read_lock = locks_before_reading[i];
        assert(!is_locked(before_read_lock));
        size_t lock_index = i + start_index;
        unsigned int v_l = atomic_load(&(shared_segment->version_locks[lock_index]));
        bool locked = is_locked(v_l);
        if (locked) {
            // printf ("validate_after_read fail\n");
            return false;
        }
        unsigned int before_read_version = extract_version(before_read_lock);
        unsigned int version = extract_version(v_l);
        if (before_read_version != version || version > ((struct transaction*)tx)->rv) {
            // printf ("validate_after_read fail\n");
            return false;
        }
    }
    // printf ("validate_after_read success\n");
    return true;
}

local_segment_node* create_local_from_shared_segment(shared_segment_node* segment, size_t alignment)
{
    local_segment_node* local_segment = (local_segment_node*) malloc(sizeof(local_segment_node));
    local_segment->from = segment->from;
    local_segment->to = segment->to;
    local_segment->size = segment->size;
    size_t nb_items = get_nb_items(local_segment->size, alignment);
    local_segment->mem_state = (shared_memory_state*) calloc(nb_items, sizeof(shared_memory_state));
    local_segment->shared_segment = shared_segment;
    assert(local_segment->mem_state != NULL);
    for (size_t i = 0; i < nb_items; i++) {
        local_segment->mem_state[i].read = false;
        local_segment->mem_state[i].new_val = NULL;
    }
    return local_segment;
}

shared_segment_node* get_shared_segment(void const* source, shared_t shared)
{
    struct region* reg = (struct region*) shared;
    uintptr_t src = (uintptr_t) source;
    shared_segment_node* curr_shared_segment = reg->first_shared_segment;
    assert(curr_shared_segment != NULL);
    while (curr_shared_segment != NULL) {
        if (curr_shared_segment->from <= src && src < curr_shared_segment->to) {
            return curr_shared_segment;
        }
        curr_shared_segment = curr_shared_segment->next;
    }

    return NULL;
}

local_segment_node* get_local_segment(void const* source, txt_t tx, shared_segment_node* shared_segment, size_t alignment)
{
    struct transaction* trans = (struct transaction*)tx;
    struct region* reg = (struct region*)shared;
    uintptr_t src = (uintptr_t)source;
    local_segment_node* curr_local_segment = trans->first_segment;
    local_segment_node* prev = NULL;
    while (curr_local_segment != NULL) {
        if (curr_local_segment->from <= src && src < curr_local_segment->to) {
            return curr_local_segment;
        }
        prev = curr_local_segment;
        curr_local_segment = curr_local_segment->next;
    }

    assert(curr_local_segment == NULL);
    local_segment_node* local_segment = create_local_from_shared_segment(shared_segment, alignment);
    if (prev == NULL) {
        trans->first_segment = local_segment;
    } else {
        prev->next = local_segment;
    }
    return local_segment;
}

/** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in the shared region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in a private region)
 * @return Whether the whole transaction can continue
**/
bool tm_read(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t size as(unused), void* target as(unused))
{
    size_t alignment = tm_align(shared);
    bool transaction_is_ro = ((struct transaction*)tx)->is_ro;
    if (size % alignment != 0) {
        free_transaction(tx, shared);
        // printf ("tm_read fail, tx: %p, source: %p\n", (void*)tx, (void*)source);
        return false;
    }
    shared_segment_node* shared_segment = get_shared_segment(source, shared);
    assert(shared_segment != NULL);
    local_segment_node* local_segment = get_local_segment(source, tx, shared_segment, alignment);
    assert(local_segment != NULL);

    assert((uintptr_t)source + size <= local_segment->to);

    size_t start_index = get_start_index(local, source);
    // number of items we want to read
    size_t number_of_items = get_nb_items(size, alignment);

    const void* current_src_slot = source;
    void* current_trgt_slot = target;

    unsigned int* locks_before_reading = (unsigned int*) calloc(number_of_items, sizeof(unsigned int));
    if (unlikely(!locks_before_reading)) {
        free_transaction(tx, shared);
        return false;
    }
    for (size_t i = 0; i < number_of_items; i++) {
        size_t lock_index = start_index + i;
        atomic_uint* ith_version_lock = &(shared_segment->version_locks[lock_index]);
        unsigned int ith_lock = atomic_load(ith_version_lock);
        locks_before_reading[i] = ith_lock;
        if (is_locked(ith_lock) || extract_version(ith_lock) > ((struct transaction*)tx)->rv) {
            free(locks_before_reading);
            free_transaction(tx, shared);
            return false;
        }
    }

    for (size_t i = start_index; i < start_index + number_of_items; i++) {
        shared_memory_state* memory_state = NULL;
        if (!transaction_is_ro) {
            memory_state = &(local_segment->mem_state[i]);
        }
        if (!transaction_is_ro && memory_state->new_val != NULL) {
            memcpy(current_trgt_slot, memory_state->new_val, alignment);
        } else {
            memcpy(current_trgt_slot, current_src_slot, alignment);
        }
        if (!transaction_is_ro) {
            // Add this location into the read-set
            memory_state->read = true;
        }
        // You may want to replace char* by uintptr_t
        current_src_slot = alignment + (char*)current_src_slot;
        current_trgt_slot = alignment + (char*)current_trgt_slot;
    }

    // validate the read => has to appear atomic
    bool validated = validate_after_read(shared, tx, source, start_index, number_of_items, locks_before_reading, shared_segment);
    free_ptr((void*)locks_before_reading);
    if (!validated) {
        free_transaction(tx, shared);
        // printf ("tm_read fail, tx: %p, source: %p\n", (void*)tx, (void*)source);
        return false;
    }
    // printf ("tm_read success, tx: %p, source: %p\n", (void*)tx, (void*)source);
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
bool tm_write(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t size as(unused), void* target as(unused))
{
    assert(!((struct transaction*)tx)->is_ro);
    size_t alignment = tm_align(shared);
    if (size % alignment != 0) {
        free_transaction(tx, shared);
        // printf ("tm_write fail, tx: %p, target: %p\n", (void*)tx, (void*)target);
        return false;
    }

    shared_segment_node* shared_segment = get_shared_segment(target, shared);
    assert(shared_segment != NULL);
    local_segment_node* local_segment = get_local_segment(target, tx, shared_segment, alignment);
    assert(local_segment != NULL);

    assert((uintptr_t)target + size <= local_segment->to);

    size_t start_index = get_start_index(local_segment, target);
    size_t number_of_items = get_nb_items(size, alignment);
    const void* current_src_slot = source;
    for (size_t i = start_index; i < start_index + number_of_items; i++) {
        shared_memory_state* memory_state = &(local_segment->memory_state[i]);
        if (memory_state->new_val != NULL) {
            memcpy(memory_state->new_val, current_src_slot, alignment);
        } else {
            memory_state->new_val = malloc(alignment);
            if (unlikely(!(memory_state->new_val))) {
                free_transaction(tx, shared);
                // printf ("tm_write fail, tx: %p, target: %p\n", (void*)tx, (void*)target);
                return false;
            }
            memcpy(memory_state->new_val, current_src_slot, alignment);
        }
        current_src_slot = alignment + (const char*)current_src_slot;
    }
    // printf ("tm_write success, tx: %p, target: %p\n", (void*)tx, (void*)target);
    return true;
}

bool tm_validate(shared_t shared as(unused), tx_t tx as(unused))
{
    // lock the write-set
    if (!lock_write_set(shared, tx)) {
        return false;
    }

    unsigned int former_vclock = atomic_fetch_add(&(((struct region*)shared)->VClock), 1);
    unsigned int vw = former_vclock + 1;

    ((struct transaction*)tx)->vw = vw;

    size_t alignment = tm_align(shared);

    if (((struct transaction*)tx)->rv + 1 != vw) {
        // Validate read-set
        if (!validate_read_set(shared, tx, alignment)) {
            release_write_lock(shared, tx, NULL, -1, true);
            return false;
        }
    }

    return true;
}

// When this function is called, we have all the write locks
// It will release the nb_items first locks
// If you want to release all locks, nb_items should be equals to the total number of items (size / alignment)
void release_write_lock(shared_t shared as(unused), tx_t tx as(unused), local_segment_node* last_segment_locked, size_t nb_items_in_last_segment, bool release_all)
{
    if (shared == NULL || (void*)tx == NULL) {
        return;
    }

    size_t alignment = tm_align(shared);
    struct transaction* trans = (struct transaction*) tx;
    local_segment_node* curr_local_segment = trans->first_segment;
    while (curr_local_segment != NULL) {
        size_t size = curr_local_segment->size;
        size_t nb_items = get_nb_items(size, alignment);
        if (!release_all && curr_local_segment == last_segment_locked) {
            nb_items = nb_items_in_last_segment;
        }
        shared_segment_node* shared_segment = curr_local_segment->shared_segment;
        for (size_t i = 0; i < nb_items; i++) {
            void* val_written = trans->mem_state[i].new_val;
            bool in_write_set = val_written != NULL;
            if (in_write_set) {
                atomic_uint* lock = &(shared_segment->version_locks[i]);
                unsigned int current_value = atomic_load(lock);
                assert(is_locked(current_value));
                unsigned int unlock_mask = ~(0u) >> 1;
                unsigned int new_value = current_value & unlock_mask;
                atomic_store(lock, new_value);
            }
        }
        if (!release_all && curr_local_segment == last_segment_locked) {
            return;
        }
        curr_local_segment = curr_local_segment->next;
    }
}

void propagate_writes(shared_t shared as(unused), tx_t tx as(unused))
{
    size_t alignment = tm_align(shared);
    struct transaction* = (struct transaction*) tx;
    local_segment_node* local_segment = trans->first_segment;

    while (local_segment != NULL) {
        size_t size = local_segment->size;
        size_t nb_items = get_nb_items(size, alignment);
        shared_segment_node* shared_segment = local_segment->shared_segment;
        void* start = shared_segment->start;
        for (size_t i = 0; i < nb_items; i++) {
            shared_memory_state* ith_memory_state = &(trans->mem_state[i]);
            // If in write-set
            if (ith_memory_state->new_val != NULL) {
                // point to the correct location in shared memory
                void* target_pointer = (i * alignment) + (char*)start;
                // copy the content written by the transaction in shared memory
                memcpy(target_pointer, ith_memory_state->new_val, alignment);
                // get the versioned-lock
                atomic_uint* ith_version_lock = &(shared_segment->version_locks[i]);
                assert(is_locked(atomic_locad(ith_version_lock)));
                // set version value to the write-version and release the lock
                unsigned int unlock_mask = ~(0u) >> 1;
                unsigned int new_value = trans->vw && unlock_mask;
                // set new version & unlock
                atomic_store(ith_version_lock, new_value);
            }
        }
        local_segment = local_segment->next;
    }
}

bool validate_read_set(shared_t shared as(unused), tx_t tx as(unused), size_t alignment)
{
    if (shared == NULL || (void*)tx == NULL) {
        return false;
    }

    struct transaction* trans = (struct transaction*)tx;
    local_segment_node* local_segment;
    while (local_segment_node != NULL) {
        size_t size = local_segment_node->size;
        size_t nb_items = get_nb_items(size, alignment);
        shared_segment_node* shared_segment = local_segment_node->shared_segment;
        for (size_t i = 0; i < nb_items; i++) {
            shared_memory_state* ith_memory = &(local_segment_node->mem_state[i]);
            if (ith_memory->read) {
                unsigned int v_l = atomic_load(&(shared_segment->version_locks[i]));
                bool locked = is_locked(v_l);
                unsigned int version = extract_version(v_l);
                // if it is not in the write-set but it is locked
                if (ith_memory->new_val == NULL && locked) {
                    return false;
                }
                if (version > trans->rv) {
                    return false;
                }
            }
        }
        local_segment_node = local_segment_node->next;
    }
    return true;
}

bool lock_write_set(shared_t shared, tx_t tx)
{
    size_t alignment = tm_align(shared);
    struct transaction* trans = (struct transaction*) tx;
    local_segment_node* curr_local_segment = trans->first_segment;
    while (curr_local_segment != NULL) {
        size_t size = curr_local_segment->size;
        size_t nb_items = get_nb_items(size, alignment);
        shared_segment_node* shared_segment = curr_local_segment->shared_segment;
        for (size_t i = 0; i < nb_items; i++) {
            void* val_written = trans->mem_state[i].new_val;
            bool in_write_set = val_written != NULL;
            if (in_write_set) {
                atomic_uint* lock = &(shared_segment->version_locks[i]);
                unsigned int lock_mask = 1 << (sizeof(unsigned int) * BYTE_SIZE - 1);
                unsigned int old_value = atomic_load(lock);
                unsigned int unlock_mask = ~(0u) >> 1;
                unsigned int expected_value = old_value & unlock_mask;
                unsigned int new_value = old_value | lock_mask;
                bool got_the_lock = atomic_compare_exchange_strong(lock, &expected_value, new_value);
                if (!got_the_lock) {
                    // release locks got until now
                    release_write_lock(shared, tx, curr_local_segment, i, false);
                    return false;
                }
            }
        }
        curr_local_segment = curr_local_segment->next;
    }
    return true;
}

void free_ptr(void* ptr)
{
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
