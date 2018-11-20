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

void free_ptr(void* ptr);

bool lock_write_set(shared_t shared, tx_t tx);

bool validate_read_set(shared_t shared as(unused), tx_t tx as(unused), size_t number_of_items);
void propagate_writes(shared_t shared as(unused), tx_t tx as(unused));
void release_write_lock(shared_t shared as(unused), tx_t tx as(unused), size_t nb_items);

bool tm_validate(shared_t shared as(unused), tx_t tx as(unused));

bool validate_after_read(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t start_index, size_t nb_items, unsigned int* locks_before_reading);
size_t get_nb_items(size_t size, size_t alignment);

size_t get_start_index(shared_t shared as(unused), void const* mem_ptr as(unused));

void free_transaction(tx_t tx, shared_t shared);

struct region {
    void* start;
    atomic_size_t size;        // Size of the shared memory region (in bytes)
    atomic_size_t align;       // Claimed alignment of the shared memory region (in bytes)
    atomic_size_t align_alloc; // Actual alignment of the memory allocations (in bytes)
    atomic_uint VClock;
    atomic_uint* version_locks; // The last bit is the lock bit
};

typedef struct {
    bool read;
    void* new_val;
} shared_memory_state;

struct transaction {
    bool is_ro; // whether the transaction is read-only
    unsigned int rv; // read-version number
    unsigned int vw; // write-version number
    shared_memory_state* memory_state;
};

/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size as(unused), size_t align as(unused)) {
 
    // Allocate the region
    struct region* region = (struct region*) malloc(sizeof(struct region));
    if (unlikely(!region)) { // means that the proposition: !region is likely false
        return invalid_shared;
    }

    // Check that the given alignment is correct
    // Also satisfy alignment requirement of 'struct link'
    size_t align_alloc = align < sizeof(void*) ? sizeof(void*) : align;

    // Allocate the first segment of the region
    if (unlikely(posix_memalign(&(region->start), align_alloc, size) != 0)) {
        free_ptr(region);
        return invalid_shared;
    }

    // Fill the first segment of the region with 0s
    memset(region->start, 0, size);

    atomic_init(&(region->size), size);
    atomic_init(&(region->align), align);
    atomic_init(&(region->align_alloc), align_alloc);
    atomic_init(&(region->VClock), 0u);

    size_t number_of_items = size / align;
 
    // Init the array of versioned-locks
    atomic_uint* version_locks = (atomic_uint*) calloc(number_of_items, sizeof(atomic_uint));
    if (unlikely(!version_locks)) {
        free_ptr(region->start);
        free_ptr(region);
        return invalid_shared;
    }
    for (size_t i = 0; i < number_of_items; i++) {
        atomic_init(&(version_locks[i]), 0u);
    }
    region->version_locks = version_locks;
    
    // printf ("Region %p created\n", (void*)region);
    return region;    
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared as(unused)) {
    struct region* reg = (struct region*)shared;
    free_ptr(reg->start);
    free_ptr((void*)(reg->version_locks));
    free_ptr(shared);
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t shared as(unused)) {
    return ((struct region*)shared)->start;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared as(unused)) {
    size_t size = atomic_load(&(((struct region*)shared)->size));
    return size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared as(unused)) {
    size_t align = atomic_load(&(((struct region*)shared)->align));
    return align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t shared as(unused), bool is_ro as(unused)) {
    unsigned int global_clock = atomic_load(&(((struct region*)shared)->VClock));
 
    struct transaction* trans = (struct transaction*) malloc(sizeof(struct transaction));
    if (unlikely(!trans)) {
        // printf ("tm_begin failed\n");
        return invalid_tx;
    }

    trans->rv = global_clock;
    trans->is_ro = is_ro;
    size_t size = tm_size(shared);
    size_t alignment = tm_align(shared);
    size_t number_of_items = get_nb_items(size, alignment);
 
    shared_memory_state* memory_state = (shared_memory_state*) calloc(number_of_items, sizeof(shared_memory_state));
    if (unlikely(!memory_state)) {
        free_ptr(trans);
        // printf ("tm_begin failed\n");
        return invalid_tx;
    }

    for (size_t i = 0; i < number_of_items; i++) {
        memory_state[i].read = false;
        memory_state[i].new_val = NULL;
    }
    trans->memory_state = memory_state;

    // printf ("transaction %p begins\n", (void*)trans);
    return (tx_t)trans;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared as(unused), tx_t tx as(unused)) {
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

void free_transaction(tx_t tx, shared_t shared) {
    size_t size = tm_size(shared);
    size_t alignment = tm_align(shared);
    size_t nb_items = get_nb_items(size, alignment);
    if ((void*)tx == NULL) {
        return;
    }
    for (size_t i = 0; i < nb_items; i++) {
        shared_memory_state* mem_state = &(((struct transaction*)tx)->memory_state[i]);
        if (mem_state->new_val != NULL) {
            free_ptr(mem_state->new_val);
        }
    }
    free_ptr((void*)(((struct transaction*)tx)->memory_state));
    free_ptr((void*)tx);
}

size_t get_start_index(shared_t shared as(unused), void const* mem_ptr as(unused)) {
    size_t alignment = tm_align(shared);
    void* start = tm_start(shared);
    size_t start_index = (mem_ptr - start) / alignment;
    return start_index;
}

size_t get_nb_items(size_t size, size_t alignment) {
    size_t nb_items = size / alignment;
    return nb_items;
}

bool is_locked(unsigned int versioned_lock) {
    unsigned int is_locked_mask = 1 << (sizeof(unsigned int) * BYTE_SIZE - 1);
    return (versioned_lock & is_locked_mask) >> (sizeof(unsigned int) * BYTE_SIZE - 1);
}

unsigned int extract_version(unsigned int versioned_lock) {
    unsigned int extract_version_mask = ~(0u) >> 1;
    return versioned_lock & extract_version_mask;
}

bool validate_after_read(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t start_index, size_t nb_items, unsigned int* locks_before_reading) {
    if (shared == NULL || (void*)tx == NULL || source == NULL || locks_before_reading == NULL) {
        // printf ("validate_after_read fail\n");
        return false;
    }
    assert(sizeof(locks_before_reading)/sizeof(unsigned int*) == nb_items);
    for (size_t i = 0; i < nb_items; i++) {
        unsigned int before_read_lock = locks_before_reading[i];
        assert(!is_locked(before_read_lock));
        size_t lock_index = i + start_index;
        unsigned int v_l = atomic_load(&(((struct region*)shared)->version_locks[lock_index]));
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

/** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in the shared region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in a private region)
 * @return Whether the whole transaction can continue
**/
bool tm_read(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t size as(unused), void* target as(unused)) {
    size_t alignment = tm_align(shared);
    if (size % alignment != 0) {
        free_transaction(tx, shared);
        // printf ("tm_read fail, tx: %p, source: %p\n", (void*)tx, (void*)source);
        return false;
    }
    size_t start_index = get_start_index(shared, source);
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
        atomic_uint* ith_version_lock = &(((struct region*)shared)->version_locks[lock_index]);
        locks_before_reading[i] = atomic_load(ith_version_lock);
        if (is_locked(locks_before_reading[i])) {
            free(locks_before_reading);
            free_transaction(tx, shared);
            return false;
        }
    } 
 
    for (size_t i = start_index; i < start_index + number_of_items; i++) {
        shared_memory_state* memory_state = &(((struct transaction*)tx)->memory_state[i]);
        if (memory_state->new_val != NULL) {
            memcpy(current_trgt_slot, memory_state->new_val, alignment);
        } else {
            // Check lock and timestamp
            memcpy(current_trgt_slot, current_src_slot, alignment);
            // Check lock and timestamp
        }
        // Add this location into the read-set
        memory_state->read = true;
        // You may want to replace char* by uintptr_t
        current_src_slot = alignment + (char*)current_src_slot;
        current_trgt_slot = alignment + (char*)current_trgt_slot;
    }

    // validate the read => has to appear atomic
    bool validated = validate_after_read(shared, tx, source, start_index, number_of_items, locks_before_reading);
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
bool tm_write(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t size as(unused), void* target as(unused)) {
    size_t alignment = tm_align(shared);
    if (size % alignment != 0) {
        free_transaction(tx, shared);
        // printf ("tm_write fail, tx: %p, target: %p\n", (void*)tx, (void*)target);
        return false;
    }

    size_t start_index = get_start_index(shared, target);
    size_t number_of_items = get_nb_items(size, alignment);
    const void* current_src_slot = source;
    for (size_t i = start_index; i < start_index + number_of_items; i++) {
        shared_memory_state* memory_state = &(((struct transaction*)tx)->memory_state[i]);
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

bool tm_validate(shared_t shared as(unused), tx_t tx as(unused)) {
    // lock the write-set
    if (!lock_write_set(shared, tx)) {
        return false;
    }

    unsigned int former_vclock = atomic_fetch_add(&(((struct region*)shared)->VClock), 1);
    unsigned int vw = former_vclock + 1;

    ((struct transaction*)tx)->vw = vw;

    size_t size = tm_size(shared);
    size_t alignment = tm_align(shared);
    size_t nb_items = get_nb_items(size, alignment);

    if (((struct transaction*)tx)->rv + 1 != vw) {
        // Validate read-set
        if (!validate_read_set(shared, tx, nb_items)) {
            release_write_lock(shared, tx, nb_items);
            return false;
        }
    } 

    return true;
}

// When this function is called, we have all the write locks
// It will release the nb_items first locks
// If you want to release all locks, nb_items should be equals to the total number of items (size / alignment)
void release_write_lock(shared_t shared as(unused), tx_t tx as(unused), size_t nb_items) {
    if (shared == NULL || (void*)tx == NULL) {
        return;
    }
    for (size_t i = 0; i < nb_items; i++) {
        shared_memory_state* ith_memory_state = &(((struct transaction*)tx)->memory_state[i]);
        if (ith_memory_state->new_val != NULL) {
            unsigned int current_value = atomic_load(&(((struct region*)shared)->version_locks[i]));
            assert(is_locked(current_value));
            unsigned int unlock_mask = ~(0u) >> 1;
            unsigned int new_value = current_value & unlock_mask;
            atomic_store(&(((struct region*)shared)->version_locks[i]), new_value);
        }
    }
}

void propagate_writes(shared_t shared as(unused), tx_t tx as(unused)) {
    size_t size = tm_size(shared);
    size_t alignment = tm_align(shared);
    size_t nb_items = get_nb_items(size, alignment);
    void* start = tm_start(shared);
    for (size_t i = 0; i < nb_items; i++) {
        // shared_memory_state ith_memory_state = ((struct transaction*)tx)->memory_state[i];
        shared_memory_state* ith_memory_state = &(((struct transaction*)tx)->memory_state[i]);
        // If in write-set
        if (ith_memory_state->new_val != NULL) {
            // point to the correct location in shared memory
            void* target_pointer = (i * alignment) + (char*)start;
            // copy the content written by the transaction in shared memory
            memcpy(target_pointer, ith_memory_state->new_val, alignment);
            // get the versioned-lock
            atomic_uint* ith_version_lock = &(((struct region*)shared)->version_locks[i]);
            assert(is_locked(atomic_load(ith_version_lock)));
            // set version value to the write-version and release the lock
            unsigned int unlock_mask = ~(0u) >> 1;
            unsigned int new_value = ((struct transaction*)tx)->vw & unlock_mask;
            atomic_store(ith_version_lock, new_value);
        }
    } 
}

bool validate_read_set(shared_t shared as(unused), tx_t tx as(unused), size_t number_of_items) {
    if (shared == NULL || (void*)tx == NULL) {
        return false;
    }
    for (size_t i = 0; i < number_of_items; i++) {
        // If is read-set
        shared_memory_state* ith_memory = &(((struct transaction*)tx)->memory_state[i]);
        if (ith_memory->read) {
            // version_lock* curr_version_lock = &(((struct region*)shared)->version_locks[i]);
            unsigned int v_l = atomic_load(&(((struct region*)shared)->version_locks[i]));
            bool locked = is_locked(v_l);
            unsigned int version = extract_version(v_l);
            // if it is not in the write-set but it is locked
            if (ith_memory->new_val == NULL && locked) {
                return false;
            }
            if (version > ((struct transaction*)tx)->rv) {
                return false;
            }
        }
    }
    return true;
}

bool lock_write_set(shared_t shared, tx_t tx) {
    size_t size = tm_size(shared);
    size_t alignment = tm_align(shared);
    size_t number_of_items = get_nb_items(size, alignment);
    for (size_t i = 0; i < number_of_items; i++) {
        void* val_written = ((struct transaction*)tx)->memory_state[i].new_val;
        bool in_write_set = val_written != NULL;
        if (in_write_set) {
            atomic_uint* lock = &(((struct region*)shared)->version_locks[i]);
            unsigned int lock_mask = 1 << (sizeof(unsigned int) * BYTE_SIZE - 1);
            unsigned int old_value = atomic_load(lock);
            unsigned int unlock_mask = ~(0u) >> 1;
	        unsigned int expected_value = old_value & unlock_mask;
            unsigned int new_value = old_value | lock_mask;
            bool got_the_lock = atomic_compare_exchange_strong(lock, &expected_value, new_value);
            if (!got_the_lock) {
                // release locks got until now
                release_write_lock(shared, tx, i);
                return false;
            }
        }
    }
    return true;
}

void free_ptr(void* ptr) {
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
alloc_t tm_alloc(shared_t shared as(unused), tx_t tx as(unused), size_t size as(unused), void** target as(unused)) {
    // TODO: tm_alloc(shared_t, tx_t, size_t, void**)
    return abort_alloc;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t shared as(unused), tx_t tx as(unused), void* target as(unused)) {
    // TODO: tm_free(shared_t, tx_t, void*)
    return false;
}
