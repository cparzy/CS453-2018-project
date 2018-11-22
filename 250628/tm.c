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
    atomic_ulong version_lock;
    void* segment;
    segment_version* next;
};

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

shared_t tm_create(size_t size as(unused), size_t align as(unused));

void free_versions_linked_list(segment_version* versions, size_t nb_items);

void tm_destroy(shared_t shared as(unused));

void* tm_start(shared_t shared as(unused));

size_t tm_size(shared_t shared as(unused));

size_t tm_align(shared_t shared as(unused));

tx_t tm_begin(shared_t shared as(unused), bool is_ro as(unused));

bool tm_end(shared_t shared as(unused), tx_t tx as(unused));

bool lock_write_set(tx_t tx, shared_t shared);

void release_write_locks(shared_t shared, tx_t tx, size_t until);

bool tm_validate(shared_t shared, tx_t tx);

void propagate_writes(shared_t shared, tx_t tx);

void free_transaction(tx_t tx, shared_t shared);

size_t get_start_index(shared_t shared, void const* mem_ptr);

size_t get_nb_items(size_t size, size_t alignment);

bool is_locked(unsigned long versioned_lock);

unsigned int extract_read_version(unsigned long versioned_lock);

unsigned int extract_write_version(unsigned long versioned_lock);

unsigned long set_read_version(unsigned long versioned_lock, unsigned int new_read_version);

unsigned long create_new_versioned_lock(unsigned int read_version, unsigned int write_version, bool locked);

bool tm_read(shared_t shared, tx_t tx, void const* source, size_t size, void* target);

bool tm_write(shared_t shared, tx_t tx, void const* source, size_t size, void* target);

void free_ptr(void* ptr);

alloc_t tm_alloc(shared_t shared as(unused), tx_t tx as(unused), size_t size as(unused), void** target as(unused));

bool tm_free(shared_t shared as(unused), tx_t tx as(unused), void* target as(unused));

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
    atomic_ulong* v_locks = (atomic_ulong*) calloc(number_of_items, sizeof(atomic_ulong));
    if (unlikely(!v_locks)) {
        free_ptr(reg->start);
        free_ptr(reg);
        return invalid_shared;
    }
    for (size_t i = 0; i < number_of_items; i++) {
        atomic_init(&(v_locks[i]), 0ul);
    }
    reg->v_locks = v_locks;

    // Init the segment versions
    segment_version* versions = (segment_version*) calloc(number_of_items, sizeof(segment_version));
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
        unsigned long ith_version_lock = atomic_load(&(reg->v_locks[i]));
        versions[i] = (segment_version) {
            .segment = ith_segment, .version_lock = 0, .next = NULL
        };
        atomic_store(&(versions[i].version_lock), ith_version_lock);
        src = align + (char*)src;
    }
    reg->versions = versions;

    // printf ("Region %p created\n", (void*)region);
    return reg;
}

void free_versions_linked_list(segment_version* versions, size_t nb_items)
{
    printf("nb_items: %zu\n", nb_items);
    printf("sizeof(versions): %zu\n", sizeof(versions));
    printf("sizeof(versions[0])): %zu\n", sizeof(versions[0]));
    printf("division: %zu\n", (sizeof(versions) / sizeof(versions[0])));
    // TODO: put back the assert !
    // assert(nb_items == sizeof(versions) / sizeof(versions[0]));
    for (size_t i = 0; i < nb_items; i++) {
        segment_version* first_version = &(versions[0]);
        // segment_version next = versions[0];
        assert(first_version != NULL);
        if (first_version->next != NULL) {
            segment_version* curr = first_version->next;
            while (curr != NULL) {
                segment_version* next_tmp = curr->next;
                free_ptr(curr->segment);
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

    unsigned int former_timestamp = atomic_fetch_add(&(((region*)shared)->VClock), 1);
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

    if (!tm_validate(shared, tx)) {
        release_write_locks(shared, tx, nb_items);
        free_transaction(tx, shared);
        return false;
    }

    propagate_writes(shared, tx);
    release_write_locks(shared, tx, nb_items);
    free_transaction(tx, shared);
    return true;
}

bool lock_write_set(tx_t tx, shared_t shared)
{
    size_t size = tm_size(shared);
    size_t alignment = tm_align(shared);
    assert(size % alignment == 0);
    size_t nb_items = get_nb_items(size, alignment);
    write_set* writes = ((transaction*)tx)->writes;
    atomic_ulong* v_locks = ((region*)shared)->v_locks;
    for (size_t i = 0; i < nb_items; i++) {
        write_set* ith_write = &(writes[i]);
        // if in write-set
        if (ith_write->new_val != NULL) {
            // try to acquire the lock on this segment
            atomic_ulong* ith_v_lock = &(v_locks[i]);
            unsigned long old_value = atomic_load(ith_v_lock);

            // compute the expected value
            unsigned long unlock_mask = ~(0ul) >> 1;
            unsigned long expected_value = old_value & unlock_mask;

            // compute the new value
            unsigned long lock_mask = 1ul << (sizeof(unsigned long) * BYTE_SIZE - 1);
            unsigned long new_value = old_value | lock_mask;
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

// When this function is called, we have all the write locks until index 'until' of the segments in the write set
// It will release the nb_items first locks
// If you want to release all locks, nb_items should be equals to the total number of items (size / alignment)
void release_write_locks(shared_t shared, tx_t tx, size_t until)
{
    size_t size = tm_size(shared);
    assert(until <= size);

    atomic_ulong* v_locks = ((region*)shared)->v_locks;
    write_set* writes = ((transaction*)tx)->writes;
    for (size_t i = 0; i < until; i++) {
        write_set* ith_write = &(writes[i]);
        if (ith_write->new_val != NULL) {
            atomic_ulong* ith_v_lock = &(v_locks[i]);
            unsigned long old_value = atomic_load(ith_v_lock);
            assert(is_locked(old_value));
            unsigned long unlock_mask = ~(0ul) >> 1;
            unsigned long new_value = old_value & unlock_mask;
            atomic_store(ith_v_lock, new_value);
        }
    }
}

bool tm_validate(shared_t shared, tx_t tx)
{
    size_t size = tm_size(shared);
    size_t alignment = tm_align(shared);
    size_t nb_items = get_nb_items(size, alignment);
    atomic_ulong* v_locks = ((region*)shared)->v_locks;
    write_set* writes = ((transaction*)tx)->writes;
    unsigned int tx_timestamp = ((transaction*)tx)->timestamp;
    for (size_t i = 0; i < nb_items; i++) {
        write_set* ith_write = &(writes[i]);
        // if in write-set
        if (ith_write->new_val != NULL) {
            atomic_ulong* ith_v_lock = &(v_locks[i]);
            unsigned long lock_value = atomic_load(ith_v_lock);
            assert(is_locked(lock_value));
            if (extract_read_version(lock_value) > tx_timestamp || extract_write_version(lock_value) > tx_timestamp) {
                return false;
            }
        }
    }
    return true;
}

void propagate_writes(shared_t shared, tx_t tx)
{
    size_t size = tm_size(shared);
    size_t alignment = tm_align(shared);
    size_t nb_items = get_nb_items(size, alignment);

    atomic_ulong* v_locks = ((region*)shared)->v_locks;
    void* start = tm_start(shared);
    segment_version* versions = ((region*)shared)->versions;

    write_set* writes = ((transaction*)tx)->writes;
    unsigned int tx_timestamp = ((transaction*)tx)->timestamp;

    for (size_t i = 0; i < nb_items; i++) {
        write_set* ith_write = &(writes[i]);
        if (ith_write->new_val != NULL) {
            // point to the correct location in shared memory
            atomic_ulong* ith_v_lock = &(v_locks[i]);
            unsigned long version = atomic_load(ith_v_lock);
            assert(is_locked(version));

            // point to the correct segment of shared memory
            void* target_segment = (i * alignment) + (char*)start;

            // create a new segment_version storing the old version of the segment
            // (to make it available for reads)
            segment_version* s_version = (segment_version*) malloc(sizeof(segment_version));
            void* segment = malloc(alignment);
            memcpy(segment, target_segment, alignment);
            s_version->segment = segment;
            unsigned long unlock_mask = ~(0ul) >> 1;
            atomic_init(&(s_version->version_lock), version & unlock_mask);

            // insert this newly created segment_version into the appropriate linked-list, at the correct position
            segment_version* ith_version = &(versions[i]);
            segment_version* prev = NULL;
            segment_version* next = ith_version;
            while (next != NULL && atomic_load(&(next->version_lock)) > version) {
                prev = next;
                next = next->next;
            }
            if (prev == NULL) {
                assert(next != NULL && atomic_load(&(next->version_lock)) <= version);
                s_version->next = next;
                versions[i] = *s_version;
                free_ptr((void*)s_version);
            } else {
                assert(atomic_load(&(prev->version_lock)) > version);
                assert(next == NULL || atomic_load(&(next->version_lock)) <= version);
                prev->next = s_version;
                s_version->next = NULL;
            }

            // write to the shared memory and update the version
            memcpy(target_segment, ith_write->new_val, alignment);
            atomic_store(ith_v_lock, create_new_versioned_lock(tx_timestamp, tx_timestamp, true));
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
            write_set* ith_write = &(((transaction*)tx)->writes[i]);
            if (ith_write->new_val != NULL) {
                free_ptr(ith_write->new_val);
            }
        }
        free_ptr((void*)(((transaction*)tx)->writes));
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

bool is_locked(unsigned long versioned_lock)
{
    unsigned long is_locked_mask = 1ul << (sizeof(unsigned long) * BYTE_SIZE - 1);
    return (versioned_lock & is_locked_mask) >> (sizeof(unsigned long) * BYTE_SIZE - 1);
}

unsigned int extract_read_version(unsigned long versioned_lock)
{
    // first half is the read-version
    unsigned long mask = ~(0ul) >> ((sizeof(unsigned long) * BYTE_SIZE) / 2); // 00001111
    unsigned long read_version = versioned_lock & mask;
    return (unsigned int)read_version;
}

unsigned int extract_write_version(unsigned long versioned_lock)
{
    unsigned long mask = ~(0ul) << (((sizeof(unsigned long) * BYTE_SIZE) / 2) + 1); // 11100000
    mask = mask >> 1; // 01110000
    unsigned long write_version = (versioned_lock & mask) >> ((sizeof(unsigned long) * BYTE_SIZE) / 2);
    return (unsigned int)write_version;
}

unsigned long set_read_version(unsigned long versioned_lock, unsigned int new_read_version)
{
    unsigned long mask = ~(0ul) << ((sizeof(unsigned long) * BYTE_SIZE) / 2); // 11110000
    unsigned long cancelled_read_version = versioned_lock & mask; // xxxx0000
    unsigned long new_r_v = (unsigned long)new_read_version; // 0000yyyy
    unsigned long new_lock = cancelled_read_version | new_r_v; // xxxxyyyy
    assert(is_locked(versioned_lock) == is_locked(new_lock));
    assert(extract_write_version(versioned_lock) == extract_write_version(new_lock));
    return new_lock;
}

unsigned long create_new_versioned_lock(unsigned int read_version, unsigned int write_version, bool locked)
{
    unsigned long new_lock = (unsigned long)read_version; // 0000rrrr
    unsigned long write_version_to_be_added = (unsigned long)write_version; // 0000wwww
    write_version_to_be_added = write_version_to_be_added << ((sizeof(unsigned long) * BYTE_SIZE) / 2); // wwww0000
    new_lock = new_lock | write_version_to_be_added; // wwwwrrrr

    if (locked) {
        unsigned long lock_bit_mask = 1ul << (sizeof(unsigned long) * BYTE_SIZE - 1); // 10000000
        new_lock = new_lock | lock_bit_mask; // 1wwwrrrr
    } else {
        unsigned long lock_bit_mask = ~(1ul) >> 1; //01111111
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
bool tm_read(shared_t shared, tx_t tx, void const* source, size_t size, void* target)
{
    size_t alignment = tm_align(shared);
    assert(size % alignment == 0);

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
            segment_version* ith_version = &(((region*)shared)->versions[segment_index]);
            assert(ith_version != NULL);
            segment_version* curr = ith_version;
            // Find the correct version to read
            while (curr->next != NULL && tx_timestamp < extract_write_version(atomic_load(&(curr->version_lock)))) {
                curr = curr->next;
            }
            assert(curr != NULL);
            assert(tx_timestamp >= extract_write_version(atomic_load(&(curr->version_lock))));
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
bool tm_write(shared_t shared, tx_t tx, void const* source, size_t size, void* target)
{
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
