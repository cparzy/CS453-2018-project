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

// TODO: fill headers

typedef struct {
    atomic_ulong version_lock;
    void* segment;
    segment_version* next;
} segment_version;

typedef struct {
    void* start;
    atomic_ulong* v_locks;
    segment_version* versions;
    atomic_uint VClock;
    atomic_size_t size;
    atomic_size_t align;
    atomic_size_t align_alloc;
} region;

typedef struct {
    void* new_val;
} write_set;

typedef struct {
    bool is_ro;
    unsigned int timestamp;
    write_set* writes;
} transaction;

/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size as(unused), size_t align as(unused)) {
 
    // Allocate the region
    region* region = (region*) malloc(sizeof(region));
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
    atomic_ulong* v_locks = (atomic_ulong*) calloc(number_of_items, sizeof(atomic_ulong));
    if (unlikely(!v_locks)) {
        free_ptr(region->start);
        free_ptr(region);
        return invalid_shared;
    }
    for (size_t i = 0; i < number_of_items; i++) {
        atomic_init(&(v_locks[i]), 0ul);
    }
    region->v_locks = v_locks;
    
    // Init the segment versions
    segment_version* versions = (segment_version*) calloc(number_of_items, sizeof(segment_version));
    if (unlikely(!versions)) {
        free_ptr(region->start);
        free_ptr(region->v_locks);
        free_ptr(region);
        return invalid_shared;
    }
    void src = region->start;
    for (size_t i = 0; i < number_of_items; i++) {
        void* ith_segment = malloc(align);
        memcpy(ith_segment, src, align);
        unsigned long ith_version_lock = atomic_load(&(region->v_locks[i]));
        versions[i] = { .segment = ith_segment, .version_lock = 0, .next = NULL };
        atomic_store(&(versions[i].version_lock), ith_version_lock);
        src = align + (char*)src;
    }
    region->versions = versions;

    // printf ("Region %p created\n", (void*)region);
    return region;    
}

void free_versions_linked_list(segment_version* versions, size_t nb_items) {
    assert(nb_items == sizeof(versions) / sizeof(segment_version));
    for (size_t i = 0; i < nb_items; i++) {
        segment_version first_version = version[0];
        // segment_version next = versions[0];
        assert(first_version != NULL);
        if (first_version->next != NULL) {
            segment_version* curr = first_version->next
            while (curr != NULL) {
                segment_version* next_tmp = curr->next;
                free_ptr((void*)curr);
                curr = next_tmp;
            }
            assert(curr->next == NULL);
        }
    }
    free_ptr(versions);
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared as(unused)) {
    struct region* reg = (struct region*)shared;
    size_t size = tm_size(shared);
    size_t align = tm_align(shared);
    size_t nb_items = get_nb_items(size, align);
    free_ptr(reg->start);
    free_ptr((void*)(reg->v_locks));
    free_versions_linked_list(reg->versions);
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
    transaction* tx = (transaction*) malloc(sizeof(transaction));
    if (unlikely(!tx)) {
        return invalid_tx;
    }

    tx->is_ro = is_ro;

    unsigned int former_timestamp = atomic_fetch_add(&(((struct region*)shared)->VClock), 1);
    unsigned int timestamp = former_timestamp + 1;
    tx->timestamp = timestamp;

    if (!tx->is_ro) {
        size_t size = tm_size(shared);
        size_t align = tm_align(shared);
        size_t nb_items = get_nb_items(size, align);
        write_set* writes = (write_set*) calloc(nb_items, sizeof(write_set));
        if (unlikely(!writes)) {
            free_ptr(tx);
            return invalid_tx;
        }
        for (size_t i = 0; i < nb_items; i++) {
            writes[i].new_val = NULL;
        }
        tx->writes = writes;
    }

    return (tx_t)tx;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared as(unused), tx_t tx as(unused)) {
    return false;
}

// /** [thread-safe] End the given transaction.
//  * @param shared Shared memory region associated with the transaction
//  * @param tx     Transaction to end
//  * @return Whether the whole transaction committed
// **/
// bool tm_end(shared_t shared as(unused), tx_t tx as(unused)) {
//     if (((struct transaction*)tx)->is_ro) {
//         free_transaction(tx, shared);
//         return true;
//     }
//     bool validated = tm_validate(shared, tx);
//     if (!validated) {
//         free_transaction(tx, shared);
//         // printf ("tm_end fail, tx: %p, shared: %p\n", (void*)tx, (void*)shared);
//         return false;
//     }
//     // Propage writes to shared memory and release write locks
//     propagate_writes(shared, tx);
//     free_transaction(tx, shared);
//     // printf ("tm_end succeeded?: %d, tx: %p, shared: %p\n", validated, (void*)tx, (void*)shared);
//     return validated;
// }

void free_transaction(tx_t tx, shared_t shared) {
    if ((void*)tx == NULL) {
        return;
    }
    if (!((struct transaction*)tx)->is_ro) {
        size_t size = tm_size(shared);
        size_t alignment = tm_align(shared);
        size_t nb_items = get_nb_items(size, alignment);
        for (size_t i = 0; i < nb_items; i++) {
            write_set* ith_write = &(((struct transaction*)tx)->writes[i]);
            if (ith_write->new_val != NULL) {
                free_ptr(mem_state->new_val);
            }
        }
        free_ptr((void*)(((struct transaction*)tx)->writes));
    }
    free_ptr((void*)tx);
}

size_t get_start_index(shared_t shared, void const* mem_ptr) {
    size_t alignment = tm_align(shared);
    void* start = tm_start(shared);
    size_t start_index = (mem_ptr - start) / alignment;
    return start_index;
}

size_t get_nb_items(size_t size, size_t alignment) {
    size_t nb_items = size / alignment;
    return nb_items;
}

bool is_locked(unsigned long versioned_lock) {
    unsigned int is_locked_mask = 1 << (sizeof(unsigned long) * BYTE_SIZE - 1);
    return (versioned_lock & is_locked_mask) >> (sizeof(unsigned long) * BYTE_SIZE - 1);
}

unsigned int extract_read_version(unsigned long versioned_lock) {
    // first half is the read-version
    unsigned long mask = ~(0ul) >> ((sizeof(unsigned long) * BYTE_SIZE) / 2); // 00001111
    unsigned long read_version = versioned_lock & mask;
    return (unsigned int)read_version;
}

unsigned int extract_write_version(unsigned long versioned_lock) {
    unsigned long mask = ~(0ul) << (((sizeof(unsigned long) * BYTE_SIZE) / 2) + 1); // 11100000
    mask = mask >> 1; // 01110000
    unsigned long write_version = (versioned_lock & mask) >> (((sizeof(unsigned long) * BYTE_SIZE) / 2);
    return (unsigned int)write_version;
}

unsigned long set_read_version(unsigned long versioned_lock, unsigned int new_read_version) {
    unsigned long mask = ~(0u) << ((sizeof(unsigned long) * BYTE_SIZE) / 2); // 11110000
    unsigned long cancelled_read_version = versioned_lock & mask; // xxxx0000
    unsigned long new_r_v = (unsigned long)new_read_version; // 0000yyyy
    unsigned long new_lock = cancelled_read_version | new_r_v; // xxxxyyyy
    assert(is_locked(versioned_lock) == is_locked(new_lock));
    assert(extract_write_version(versioned_lock) == extract_write_version(new_lock));
    return new_lock;
}

unsigned long create_new_versioned_lock(unsigned int read_version, unsigned int write_version, bool locked) {
    unsigned long lock_bit_mask = 0ul;
    if (locked) {
        lock_bit_mask = 1ul << ((sizeof(unsigned long) * BYTE_SIZE - 1)// 10000000;
    } else {
        lock_bit_mask = ~(1ul) >> 1;//01111111
    }

    unsigned long new_lock = (unsigned long)read_version; // 0000rrrr
    unsigned long write_version_to_be_added = (unsigned long)write_version; // 0000wwww
    write_version_to_be_added = write_version_to_be_added << ((sizeof(unsigned long) * BYTE_SIZE) / 2); // wwww0000
    new_lock = new_lock | write_version; // wwwwrrrr

    if (locked) {
        unsigned long lock_bit_mask = lock_bit_mask = 1ul << ((sizeof(unsigned long) * BYTE_SIZE - 1); // 10000000
        new_lock = new_lock | lock_bit_mask; // 1wwwrrrr
    } else {
        unsigned long lock_bit_mask = lock_bit_mask = ~(1ul) >> 1; //01111111
        new_lock = new_lock & lock_bit_mask; // 0wwwrrrr
    }

    assert(extract_read_version(new_lock) == read_version);
    assert(extract_write_version(new_lock) == write_version);
    assert(is_locked(new_lock) == locked);
    return new_lock;
}

/** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in the shared region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in a private region)
 * @return Whether the whole transaction can continue
**/
bool tm_read(shared_t shared, tx_t tx, void const* source, size_t size, void* target) {
    size_t alignment = tm_align(shared);
    assert(size >= 0 && size % alignment == 0);

    unsigned int tx_timestamp = ((transaction*)tx)->timestamp;
    bool tx_is_ro = ((transaction*)tx)->is_ro;
    write_set* tx_writes = ((transaction*)tx)->writes;

    size_t nb_items = get_nb_items(size, alignment);
    size_t start_index = get_start_index(shared, source);
    void* current_target = target;
    for (size_t i = 0; i < nb_items; i++) {
        size_t segment_index = start_index + i;
        write_set* written_val = &(tx_writes[segment_index]);
        if (!tx_is_ro && written_val->new_val != NULL) {
            memcpy(current_target, written_val->new_val, alignment);
        } else {
            segment_version* ith_version = &(shared->versions[segment_index]);
            assert(ith_version != NULL);
            segment_version* curr = ith_version;
            // Find the correct version to read
            while (curr->next != NULL && tx_timestamp < extract_write_version(atomic_load(&(curr->version_lock)))) {
                curr = curr->next;
            }
            assert(curr != NULL);
            assert(curr >= extract_write_version(version_lock));
            // curr contains the more recent version that can be read by our transaction
            memcpy(current_target, curr->segment, alignment);
            unsigned long version_lock = atomic_load(&(curr->version_lock));
            // update the read-version of the segment if segment read-version < tx read-version
            if (extract_read_version(version_lock) < tx_timestamp) {
                unsigned long new_version_lock = set_read_version(version_lock, tx_timestamp);
                atomic_store(&(curr->version_lock), new_version_lock);
            }
        }
        current_target = alignment + (char*)current_target;
    }

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
bool tm_write(shared_t shared, tx_t tx, void const* source, size_t size, void* target) {
    assert(!((transaction*)tx)->is_ro);
    size_t alignment = tm_align(shared);
    assert(size % alignment == 0);
    size_t start_index = get_start_index(shared, target);
    size_t nb_items = get_nb_items(size, alignment);
    
    write_set* tx_writes = ((transaction*)tx)->writes;
    unsigned int tx_timestamp = ((transaction*)tx)->timestamp;
    segment_version* versions = ((region*)shared)->versions;

    const void* current_src_slot = source;
    for (size_t i = 0; i < nb_items; i++) {
        size_t segment_index = start_index + i;
        segment_version* segment_version = &(versions[segment_index]);
        unsigned long segment_version_lock = atomic_load(&(segment_version->version_lock));
        if (is_locked(segment_version_lock) 
            || extract_read_version(segment_version_lock) > tx_timestamp 
            || extract_write_version(segment_version_lock) > tx_timestamp) { // not sure about the write timestamp
            free_transaction(tx, shared);
            return false;
        }
        write_set* written_val = &(tx_writes[segment_index]);
        if (written_val->new_val != NULL) {
            memcpy(written_val->new_val, current_src_slot, alignment);
        } else {
            void* new_val = malloc(alignment);
            if (unlikely(!new_val)) {
                free_transaction(tx, shared);
                return false;
            }
            memcpy(new_val, current_src_slot, alignment);
            written_val->new_val = new_val;
        }
        current_src_slot = alignment + (char*)current_src_slot;
    }

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
