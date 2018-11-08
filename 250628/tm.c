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



void free_ptr(void* ptr);

bool lock_write_set(shared_t shared, tx_t tx);

bool valide_read_set(shared_t shared as(unused), tx_t tx as(unused));

void propagate_writes(shared_t shared as(unused), tx_t tx as(unused));

void release_write_lock(shared_t shared as(unused), tx_t tx as(unused), size_t nb_items);

bool tm_validate(shared_t shared as(unused), tx_t tx as(unused));

bool validate_after_read(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t start_index, size_t nb_items);
size_t get_nb_items(size_t size, size_t alignment);

size_t get_start_index(shared_t shared as(unused), void const* mem_ptr as(unused));

void free_transaction(tx_t tx as(unused));



typedef struct {
    atomic_bool lock;
    atomic_int version;
} version_lock;

struct region {
    void* start;
    atomic_size_t size;        // Size of the shared memory region (in bytes)
    atomic_size_t align;       // Claimed alignment of the shared memory region (in bytes)
    atomic_size_t align_alloc; // Actual alignment of the memory allocations (in bytes)
    atomic_int VClock;
    version_lock* version_locks;
};

typedef struct {
    bool written;
    bool read;
    void* new_val;
} shared_memory_state;

struct transaction {
    bool is_ro; // whether the transaction is read-only
    int rv; // read-version number
    int vw; // write-version number
    shared_memory_state* memory_state;
};

/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size as(unused), size_t align as(unused)) {
    printf("Create new region, size: %zu, align: %zu\n", size, align);
    // Allocate the region
    struct region* region = (struct region*) malloc(sizeof(struct region));
    if (unlikely(!region)) { // means that the proposition: !region is likely false
        printf("unlikely(!region) returned true...\n");
        return invalid_shared;
    }

    // Check that the given alignment is correct
    // Also satisfy alignment requirement of 'struct link'
    size_t align_alloc = align < sizeof(void*) ? sizeof(void*) : align;

    printf("align_alloc: %zu\n", align_alloc);

    // Allocate the first segment of the region
    if (unlikely(posix_memalign(&(region->start), align_alloc, size) != 0)) {
        printf("unlikely(posix_memalign(&(region->start), align_alloc, size) != 0) returned true\n");
        free_ptr(region);
        // free(region);
        // region = NULL;
        return invalid_shared;
    }

    // Fill the first segment of the region with 0s
    printf("Fill the first segment of the region with 0s\n");
    memset(region->start, 0, size);
    printf("tm_create, start: %p\n", region->start);

    atomic_init(&(region->size), size);
    atomic_init(&(region->align), align);
    atomic_init(&(region->align_alloc), align_alloc);
    atomic_init(&(region->VClock), 0);

    size_t number_of_items = size / align;
    printf("Number of items: %zu\n", number_of_items);

    version_lock* version_locks = (version_lock*) calloc(number_of_items, sizeof(version_lock));
    if (unlikely(!version_locks)) {
        printf("unlikely(!version_locks) returned true\n");
        free_ptr(region->start);
        free_ptr(region);
        return invalid_shared;
    }

    for (size_t i = 0; i < number_of_items; i++) {
        printf("initiating version_locks[%zu]\n", i);
        atomic_init(&(version_locks[i].version), 0);
        atomic_init(&(version_locks[i].lock), false);
    }
    printf("After initiating version locks\n");
    region->version_locks = version_locks;
    printf("Before returning region\n");
    return region;    
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared as(unused)) {
    printf("In tm_destroy\n");
    struct region* reg = (struct region*)shared;
    free_ptr(reg->start);
    free_ptr((void*)(reg->version_locks));
    free_ptr(shared);
    printf("Finish tm_destroy\n");
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t shared as(unused)) {
    // TODO: tm_start(shared_t)
    printf("in tm_start\n");
    // TODO: start may have to be an atomic pointer!
    return ((struct region*)shared)->start;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared as(unused)) {
    // TODO: may have to cast to size_t
    printf("In tm_size\n");
    size_t size = atomic_load(&(((struct region*)shared)->size));
    printf("return from tm_size: %zu\n", size);
    return size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared as(unused)) {
    printf("in tm_align\n");
    size_t align = atomic_load(&(((struct region*)shared)->align));
    printf("return from tm_align: %zu\n", align);
    return align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t shared as(unused), bool is_ro as(unused)) {
    printf("in tm_begin\n");
    // TODO: tm_begin(shared_t)
    int rv = atomic_load(&(((struct region*)shared)->VClock));
    printf("After loading rv: %d\n", rv);
    struct transaction* trans = (struct transaction*) malloc(sizeof(struct transaction));
    if (unlikely(!trans)) { // means that the proposition: !region is likely false
        printf("unlikely(!trans) returned true\n");
        return invalid_tx;
    }

    trans->rv = rv;
    trans->is_ro = is_ro;
    size_t size = tm_size(shared);
    size_t alignment = tm_align(shared);
    size_t number_of_items = get_nb_items(size, alignment);
    printf("number_of_items: %zu\n", number_of_items);
    shared_memory_state* memory_state = (shared_memory_state*) calloc(number_of_items, sizeof(shared_memory_state));
    if (unlikely(!memory_state)) {
        printf("unlikely(!memory_state) returned true\n");
        free_ptr(trans);
        return invalid_tx;
    }
    for (size_t i = 0; i < number_of_items; i++) {
        memory_state[i].read = false;
        memory_state[i].written = false;
        memory_state[i].new_val = NULL;
    }
    trans->memory_state = memory_state;
    printf("return from tm_begin: %p\n", (void*)trans);
    return (tx_t)trans;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared as(unused), tx_t tx as(unused)) {
    printf("In tm_end\n");
    if (((struct transaction*)tx)->is_ro) {
        printf("tm_end read-only\n");
        return true;
    }
    return tm_validate(shared, tx);
}

void free_transaction(tx_t tx as(unused)) {
    printf("in free_transaction\n");
    if ((void*)tx == NULL) {
        printf("free_transaction: tx == NULL\n");
        return;
    }
    free_ptr((void*)(((struct transaction*)tx)->memory_state));
    free_ptr((void*)tx);
}

size_t get_start_index(shared_t shared as(unused), void const* mem_ptr as(unused)) {
    printf("in get_start_index\n");
    if (shared == NULL || mem_ptr == NULL) {
        printf("shared == NULL || mem_ptr == NULL\n");
    }
    size_t alignment = tm_align(shared);
    void* start = tm_start(shared);
    printf("get_start_index, start: %p, mem_ptr: %p, alignment: %zu\n", start, mem_ptr, alignment);
    size_t start_index = (mem_ptr - start) / alignment;
    printf("return from get_start_index: %zu\n", start_index);
    return start_index;
}

size_t get_nb_items(size_t size, size_t alignment) {
    printf("in get_nb_items, size: %zu, alignment: %zu\n", size, alignment);
    if (alignment == 0) {
        printf("get_nb_items, alignment == 0\n");
    }
    size_t nb_items = size / alignment;
    printf("returns from get_nb_items: %zu\n", nb_items);
    return nb_items;
}

bool validate_after_read(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t start_index, size_t nb_items) {
    printf("In validate_after_read\n");
    if (shared == NULL || (void*)tx == NULL || source == NULL) {
        printf("shared == NULL || tx == NULL || source == NULL\n");
        return false;
    }
    printf("validate_after_read, going from %zu, to %zu\n", start_index, (start_index + nb_items));
    for (size_t i = start_index; i < start_index + nb_items; i++) {
        version_lock v_l = ((struct region*)shared)->version_locks[i];
        bool locked = atomic_load(&(v_l.lock));
        if (locked) {
            printf("validate_after_read, locked!, return false\n");
            return false;
        }
        int version = atomic_load(&(v_l.version));
        if (version > ((struct transaction*)tx)->rv) {
            printf("validate_after_read, version bad!, return false\n");
            return false;
        }
    }
    printf("validate_after_read return true\n");
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
    printf("in tm_read: %p, size: %zu\n", (void*)tx, size);
    size_t alignment = tm_align(shared);
    if (size % alignment != 0) {
        printf("tm_read, size modulo alignment != 0\n");
        return false;
    }
    size_t start_index = get_start_index(shared, source);
    printf("tm_read, start_index: %zu\n", start_index);
    // number of items we want to read
    size_t number_of_items = get_nb_items(size, alignment);
    printf("tm_read, number_of_items: %zu\n", number_of_items);
    const void* current_src_slot = source;
    void* current_trgt_slot = target;
    printf("tm_read, going from %zu, to %zu\n", start_index, start_index + number_of_items);
    for (size_t i = start_index; i < start_index + number_of_items; i++) {
        printf("current_src_slot: %p\n", current_src_slot);
        printf("current_trgt_slot: %p\n", current_trgt_slot);
        shared_memory_state memory_state = ((struct transaction*)tx)->memory_state[i];
        if (memory_state.written) {
            printf("tm_read, copying from local write-set\n");
            memcpy(current_trgt_slot, memory_state.new_val, alignment);
        } else {
            printf("tm_read, copying from shared memory\n");
            // Check lock and timestamp
            memcpy(current_trgt_slot, current_src_slot, alignment);
            // Check lock and timestamp
        }
        // You may want to replace char* by uintptr_t
        current_src_slot = alignment + (char*)current_src_slot;
        current_trgt_slot = alignment + (char*)current_trgt_slot;
    }

    // validate the read => has to appear atomic
    if (!validate_after_read(shared, tx, source, start_index, number_of_items)) {
        printf("tm_read, validate_after_read failed\n");
        free_transaction(tx);
        return false;
    }

    printf("tm_read successed\n");
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
    printf("in tm_write, %p, size: %zu\n", (void*)tx, size);
    size_t alignment = tm_align(shared);
    if (size % alignment != 0) {
        printf("tm_write: size modulo alignment != 0\n");
        return false;
    }

    size_t start_index = get_start_index(shared, target);
    printf("tm_write, start_index: %zu\n", start_index);
    size_t number_of_items = get_nb_items(size, alignment);
    printf("tm_write, number_of_items: %zu\n", number_of_items);
    void* current_trgt_slot = target;
    printf("tm_write, going from %zu, to %zu\n", start_index, start_index + number_of_items);
    for (size_t i = start_index; i < start_index + number_of_items; i++) {
        printf("tm_write, current_trgt_slot: %p\n", current_trgt_slot);
        printf("tm_write, tx->memory_state: %p\n", (void*)((struct transaction*)tx)->memory_state);
        shared_memory_state memory_state = ((struct transaction*)tx)->memory_state[i];
        if (memory_state.written) {
            printf("tm_written, written == true\n");
            memcpy(memory_state.new_val, current_trgt_slot, alignment);
        } else {
            void* local_content = (void*) malloc(alignment);
            if (unlikely(!local_content)) {
                printf("tm_write, unlikely(!local_content)\n");
                free_transaction(tx);
                return false;
            }
            memcpy(local_content, current_trgt_slot, alignment);
            // may be replaced by memory_state->new_val = local_content;
            ((struct transaction*)tx)->memory_state[i].new_val = local_content;
        }
        current_trgt_slot = alignment + (char*)current_trgt_slot;
    }

    printf("tm_write succeded\n");
    return true;
}

bool tm_validate(shared_t shared as(unused), tx_t tx as(unused)) {
    printf("in tm_validate: %p\n", (void*)tx);
    // lock the write-set
    if (!lock_write_set(shared, tx)) {
        printf("tm_validate, was not able to lock write set\n");
        free_transaction(tx);
        return false;
    }

    // increment global version-clock: TODO not sure about this part
    // int expected = tx->rv;
    // bool global_clock_incremented = atomic_compare_exchange_strong(&(shared->VCLock), &expected, tx->rv + 1)
    // if (!global_clock_incremented) {
    //     // abort
    //     return false;
    // }
    int former_vclock = atomic_fetch_add(&(((struct region*)shared)->VClock), 1);
    int vw = former_vclock + 1;
    printf("tm_validate, vw: %d\n", vw);

    ((struct transaction*)tx)->vw = vw;

    if (((struct transaction*)tx)->rv + 1 != vw) {
        // Validate read-set
        if (!valide_read_set(shared, tx)) {
            printf("tm_validate: valide_read_set returned false\n");
            size_t nb_items = get_nb_items(tm_size(shared), tm_align(shared));
            printf("propagate_writes: nb_items: %zu\n", nb_items);
            release_write_lock(shared, tx, nb_items);
            free_transaction(tx);
            return false;
        }
    } 

    // Propage writes to shared memory and release write locks
    propagate_writes(shared, tx);

    printf("tm_validate returns true\n");
    return true;
}

// When this function is called, we have all the write locks
// It will release the nb_items first locks
// If you want to release all locks, nb_items should be equals to the total number of items (size / alignment)
void release_write_lock(shared_t shared as(unused), tx_t tx as(unused), size_t nb_items) {
    printf("in release_write_lock\n");
    printf("nb_items: %zu\n", nb_items);
    if (shared == NULL || (void*)tx == NULL) {
        printf("release_write_lock: shared == NULL || tx == NULL\n");
        return;
    }
    for (size_t i = 0; i < nb_items; i++) {
        bool in_write_set = ((struct transaction*)tx)->memory_state[i].written;
        if (in_write_set) {
            bool expected = true;
            atomic_compare_exchange_strong(&(((struct region*)shared)->version_locks[i].lock), &expected, false);
        }
    }

    printf("finish release_write_lock\n");
}

void propagate_writes(shared_t shared as(unused), tx_t tx as(unused)) {
    printf("In propagate_writes\n");
    size_t size = tm_size(shared);
    size_t alignment = tm_align(shared);
    size_t number_of_items = get_nb_items(size, alignment);
    printf("propagate_writes: number_of_items: %zu\n", number_of_items);
    void* start = tm_start(shared);
    for (size_t i = 0; i < number_of_items; i++) {
        shared_memory_state ith_memory_state = ((struct transaction*)tx)->memory_state[i];
        // If is read-set
        if (ith_memory_state.written) {
            if (ith_memory_state.new_val == NULL) {
                printf("Error: ith_memory_state.new_val == NULL\n");
                continue;
            }
            // point to the correct location in shared memory
            void* target_pointer = (i * alignment) + (char*)start;
            // copy the content written by the transaction in shared memory
            memcpy(target_pointer, ith_memory_state.new_val, alignment);
            // get the versioned-lock
            version_lock ith_version_lock = ((struct region*)shared)->version_locks[i];
            // set version value to the write-version
            atomic_store(&(ith_version_lock.version), ((struct transaction*)tx)->vw);
            // release the lock
            atomic_store(&(ith_version_lock.lock), false);
        }
    }

    printf("Finish propagate writes\n");
}

bool valide_read_set(shared_t shared as(unused), tx_t tx as(unused)) {
    printf("in validate_read_set\n");
    if (shared == NULL || (void*)tx == NULL) {
        printf("valide_read_set: shared == NULL || tx == NULL\n");
        return false;
    }
    size_t size = tm_size(shared);
    size_t alignment = tm_align(shared);
    size_t number_of_items = get_nb_items(size, alignment);
    printf("valide_read_set: number_of_items: %zu\n", number_of_items);
    for (size_t i = 0; i < number_of_items; i++) {
        // If is read-set
        if (((struct transaction*)tx)->memory_state[i].read) {
            version_lock curr_version_lock = ((struct region*)shared)->version_locks[i];
            if (atomic_load(&(curr_version_lock.lock)) && atomic_load(&(curr_version_lock.version)) > ((struct transaction*)tx)->rv) {
                printf("validate_read_set, returns false, locked or bad version\n");
                return false;
            }
        }
    }

    printf("validate_read_set returns true\n");
    return true;
}

bool lock_write_set(shared_t shared, tx_t tx) {
    printf("in lock_write_set\n");
    size_t size = tm_size(shared);
    size_t alignment = tm_align(shared);
    size_t number_of_items = get_nb_items(size, alignment);
    printf("lock_write_set: number_of_items: %zu\n", number_of_items);
    for (size_t i = 0; i < number_of_items; i++) {
        bool in_write_set = ((struct transaction*)tx)->memory_state[i].written;
        if (in_write_set) {
            bool expected = false;
            bool got_the_lock = atomic_compare_exchange_strong(&(((struct region*)shared)->version_locks[i].lock), &expected, true);
            if (!got_the_lock) {
                printf("lock_write_set, did not got the lock, releasing the lock acquired until now and returning false\n");
                // release locks got until now
                release_write_lock(shared, tx, i);
                return false;
            }
        }
    }
    printf("lock_write_set returns true\n");
    return true;
}

void free_ptr(void* ptr) {
    printf("In free pointer\n");
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
