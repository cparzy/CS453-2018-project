/**
 * @file   grading.cpp
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
 * Grading of the implementations.
**/

// Compile-time configuration
// #define USE_MM_PAUSE

#include <assert.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sched.h>
#include <inttypes.h>
#include <sys/time.h>
#include <unistd.h>
#include <malloc.h>
#include "getticks.h"
#include "barrier.h"

// External headers
#include <algorithm>
#include <atomic>
#include <condition_variable>
using namespace std::chrono_literals;
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <random>
#include <thread>
extern "C" {
#include <dlfcn.h>
#include <limits.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#if (defined(__i386__) || defined(__x86_64__)) && defined(USE_MM_PAUSE)
    #include <xmmintrin.h>
#endif
}

// Internal headers
namespace STM {
#include <tm.hpp>
}

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

// -------------------------------------------------------------------------- //

// Whether to enable more safety checks
constexpr static auto assert_mode = false;

// -------------------------------------------------------------------------- //

namespace Exception {

/** Defines a simple exception.
 * @param name   Exception name
 * @param parent Parent exception (use ::std::exception as the root)
 * @param text   Explanatory string
**/
#define EXCEPTION(name, parent, text) \
    class name: public parent { \
    public: \
        /** Return the explanatory string. \
         * @return Explanatory string \
        **/ \
        virtual char const* what() const noexcept { \
            return "grading: " text; \
        } \
    }

/** Exceptions tree.
**/
EXCEPTION(Any, ::std::exception, "exception");
    EXCEPTION(Path, Any, "path exception");
        EXCEPTION(PathResolve, Path, "unable to resolve the given path");
    EXCEPTION(Module, Any, "transaction library exception");
        EXCEPTION(ModuleLoading, Module, "unable to load a transaction library");
        EXCEPTION(ModuleSymbol, Module, "symbol not found in loaded libraries");
    EXCEPTION(Transaction, Any, "transaction manager exception");
        EXCEPTION(TransactionAlign, Transaction, "incorrect alignment detected before transactional operation");
        EXCEPTION(TransactionReadOnly, Transaction, "tried to write/alloc/free using a read-only transaction");
        EXCEPTION(TransactionCreate, Transaction, "shared memory region creation failed");
        EXCEPTION(TransactionBegin, Transaction, "transaction begin failed");
        EXCEPTION(TransactionAlloc, Transaction, "memory allocation failed (insufficient memory)");
        EXCEPTION(TransactionRetry, Transaction, "transaction aborted and can be retried");
        EXCEPTION(TransactionNotLastSegment, Transaction, "trying to deallocate the first segment");
    EXCEPTION(Shared, Any, "operation in shared memory exception");
        EXCEPTION(SharedAlign, Shared, "address in shared memory is not properly aligned for the specified type");
        EXCEPTION(SharedOverflow, Shared, "index is past array length");
        EXCEPTION(SharedDoubleAlloc, Shared, "(probable) double allocation detected before transactional operation");
        EXCEPTION(SharedDoubleFree, Shared, "double free detected before transactional operation");
    EXCEPTION(TooSlow, Any, "non-reference module takes too long to process the transactions");

#undef EXCEPTION

}

// -------------------------------------------------------------------------- //

/** Non-copyable helper base class.
**/
class NonCopyable {
public:
    /** Deleted copy constructor/assignment.
    **/
    NonCopyable(NonCopyable const&) = delete;
    NonCopyable& operator=(NonCopyable const&) = delete;
protected:
    /** Protected default constructor, to make sure class is not directly instantiated.
    **/
    NonCopyable() = default;
};

// -------------------------------------------------------------------------- //

/** Transactional library management class.
**/
class TransactionalLibrary final: private NonCopyable {
    friend class TransactionalMemory;
private:
    /** Function types.
    **/
    using FnCreate  = decltype(&STM::tm_create);
    using FnDestroy = decltype(&STM::tm_destroy);
    using FnStart   = decltype(&STM::tm_start);
    using FnSize    = decltype(&STM::tm_size);
    using FnAlign   = decltype(&STM::tm_align);
    using FnBegin   = decltype(&STM::tm_begin);
    using FnEnd     = decltype(&STM::tm_end);
    using FnRead    = decltype(&STM::tm_read);
    using FnWrite   = decltype(&STM::tm_write);
    using FnAlloc   = decltype(&STM::tm_alloc);
    using FnFree    = decltype(&STM::tm_free);
private:
    void*     module;     // Module opaque handler
    FnCreate  tm_create;  // Module's initialization function
    FnDestroy tm_destroy; // Module's cleanup function
    FnStart   tm_start;   // Module's start address query function
    FnSize    tm_size;    // Module's size query function
    FnAlign   tm_align;   // Module's alignment query function
    FnBegin   tm_begin;   // Module's transaction begin function
    FnEnd     tm_end;     // Module's transaction end function
    FnRead    tm_read;    // Module's shared memory read function
    FnWrite   tm_write;   // Module's shared memory write function
    FnAlloc   tm_alloc;   // Module's shared memory allocation function
    FnFree    tm_free;    // Module's shared memory freeing function
private:
    /** Solve a symbol from its name, and bind it to the given function.
     * @param name Name of the symbol to resolve
     * @param func Target function to bind (optional, to use template parameter deduction)
    **/
    template<class Signature> auto solve(char const* name) const {
        auto res = ::dlsym(module, name);
        if (unlikely(!res))
            throw Exception::ModuleSymbol{};
        return *reinterpret_cast<Signature*>(&res);
    }
    template<class Signature> void solve(char const* name, Signature& func) const {
        func = solve<Signature>(name);
    }
public:
    /** Loader constructor.
     * @param path  Path to the library to load
    **/
    TransactionalLibrary(char const* path) {
        { // Resolve path and load module
            char resolved[PATH_MAX];
            if (unlikely(!realpath(path, resolved)))
                throw Exception::PathResolve{};
            module = ::dlopen(resolved, RTLD_NOW | RTLD_LOCAL);
            if (unlikely(!module))
                throw Exception::ModuleLoading{};
        }
        { // Bind module's 'tm_*' symbols
            solve("tm_create", tm_create);
            solve("tm_destroy", tm_destroy);
            solve("tm_start", tm_start);
            solve("tm_size", tm_size);
            solve("tm_align", tm_align);
            solve("tm_begin", tm_begin);
            solve("tm_end", tm_end);
            solve("tm_read", tm_read);
            solve("tm_write", tm_write);
            solve("tm_alloc", tm_alloc);
            solve("tm_free", tm_free);
        }
    }
    /** Unloader destructor.
    **/
    ~TransactionalLibrary() noexcept {
        ::dlclose(module); // Close loaded module
    }
};

/** One shared memory region management class.
**/
class TransactionalMemory final: private NonCopyable {
private:
    /** Check whether the given alignment is a power of 2
    **/
    constexpr static bool is_power_of_two(size_t align) noexcept {
        return align != 0 && (align & (align - 1)) == 0;
    }
public:
    /** Opaque shared memory region handle class.
    **/
    using Shared = STM::shared_t;
    /** Transaction class alias.
    **/
    using TX = STM::tx_t;
private:
    TransactionalLibrary const& tl; // Bound transactional library
    Shared shared;     // Handle of the shared memory region used
    void*  start_addr; // Shared memory region first segment's start address
    size_t start_size; // Shared memory region first segment's size (in bytes)
    size_t alignment;  // Shared memory region alignment (in bytes)
public:
    /** Bind constructor.
     * @param library Transactional library to use
     * @param align   Shared memory region required alignment
     * @param size    Size of the shared memory region to allocate
    **/
    TransactionalMemory(TransactionalLibrary const& library, size_t align, size_t size): tl{library}, start_size{size}, alignment{align} {
        if (unlikely(assert_mode && (!is_power_of_two(align) || size % align != 0)))
            throw Exception::TransactionAlign{};
        { // Initialize shared memory region
            shared = tl.tm_create(size, align);
            if (unlikely(shared == STM::invalid_shared))
                throw Exception::TransactionCreate{};
            start_addr = tl.tm_start(shared);
        }
    }
    /** Unbind destructor.
    **/
    ~TransactionalMemory() noexcept {
        tl.tm_destroy(shared);
    }
public:
    /** [thread-safe] Return the start address of the first shared segment.
     * @return Address of the first allocated shared region
    **/
    auto get_start() const noexcept {
        return start_addr;
    }
    /** [thread-safe] Return the size of the first shared segment.
     * @return Size in the first allocated shared region (in bytes)
    **/
    auto get_size() const noexcept {
        return start_size;
    }
    /** [thread-safe] Get the shared memory region global alignment.
     * @return Global alignment (in bytes)
    **/
    auto get_align() const noexcept {
        return alignment;
    }
public:
    /** [thread-safe] Begin a new transaction on the shared memory region.
     * @param ro Whether the transaction is read-only
     * @return Opaque transaction ID, 'STM::invalid_tx' on failure
    **/
    auto begin(bool ro) const noexcept {
        return tl.tm_begin(shared, ro);
    }
    /** [thread-safe] End the given transaction.
     * @param tx Opaque transaction ID
     * @return Whether the whole transaction is a success
    **/
    auto end(TX tx) const noexcept {
        return tl.tm_end(shared, tx);
    }
    /** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
     * @param tx     Transaction to use
     * @param source Source start address
     * @param size   Source/target range
     * @param target Target start address
     * @return Whether the whole transaction can continue
    **/
    auto read(TX tx, void const* source, size_t size, void* target) const noexcept {
        return tl.tm_read(shared, tx, source, size, target);
    }
    /** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
     * @param tx     Transaction to use
     * @param source Source start address
     * @param size   Source/target range
     * @param target Target start address
     * @return Whether the whole transaction can continue
    **/
    auto write(TX tx, void const* source, size_t size, void* target) const noexcept {
        return tl.tm_write(shared, tx, source, size, target);
    }
    /** [thread-safe] Memory allocation operation in the given transaction, throw if no memory available.
     * @param tx     Transaction to use
     * @param size   Size to allocate
     * @param target Target start address
     * @return Allocation status
    **/
    auto alloc(TX tx, size_t size, void** target) const noexcept {
        return tl.tm_alloc(shared, tx, size, target);
    }
    /** [thread-safe] Memory freeing operation in the given transaction.
     * @param tx     Transaction to use
     * @param target Target start address
     * @return Whether the whole transaction can continue
    **/
    auto free(TX tx, void* target) const noexcept {
        return tl.tm_free(shared, tx, target);
    }
};

/** One transaction over a shared memory region management class.
**/
class Transaction final: private NonCopyable {
public:
    // Just to make explicit the meaning of the associated boolean
    constexpr static auto read_write = false;
    constexpr static auto read_only  = true;
private:
    TransactionalMemory const& tm; // Bound transactional memory
    STM::tx_t tx; // Opaque transaction handle
    bool aborted; // Transaction was aborted
    bool is_ro;   // Whether the transaction is read-only (solely for assertion)
public:
    /** Deleted copy constructor/assignment.
    **/
    Transaction(Transaction const&) = delete;
    Transaction& operator=(Transaction const&) = delete;
    /** Begin constructor.
     * @param tm Transactional memory to bind
     * @param ro Whether the transaction is read-only
    **/
    Transaction(TransactionalMemory const& tm, bool ro): tm{tm}, tx{tm.begin(ro)}, aborted{false}, is_ro{ro} {
        if (unlikely(tx == STM::invalid_tx))
            throw Exception::TransactionBegin{};
    }
    /** End destructor.
    **/
    ~Transaction() {
        if (likely(!aborted))
            tm.end(tx);
    }
public:
    /** [thread-safe] Return the bound transactional memory instance.
     * @return Bound transactional memory instance
    **/
    auto const& get_tm() const noexcept {
        return tm;
    }
public:
    /** [thread-safe] Read operation in the bound transaction, source in the shared region and target in a private region.
     * @param source Source start address
     * @param size   Source/target range
     * @param target Target start address
    **/
    void read(void const* source, size_t size, void* target) {
        if (unlikely(!tm.read(tx, source, size, target))) {
            aborted = true;
            throw Exception::TransactionRetry{};
        }
    }
    /** [thread-safe] Write operation in the bound transaction, source in a private region and target in the shared region.
     * @param source Source start address
     * @param size   Source/target range
     * @param target Target start address
    **/
    void write(void const* source, size_t size, void* target) {
        if (unlikely(assert_mode && is_ro))
            throw Exception::TransactionReadOnly{};
        if (unlikely(!tm.write(tx, source, size, target))) {
            aborted = true;
            throw Exception::TransactionRetry{};
        }
    }
    /** [thread-safe] Memory allocation operation in the bound transaction, throw if no memory available.
     * @param size Size to allocate
     * @return Target start address
    **/
    void* alloc(size_t size) {
        if (unlikely(assert_mode && is_ro))
            throw Exception::TransactionReadOnly{};
        void* target;
        switch (tm.alloc(tx, size, &target)) {
        case STM::Alloc::success:
            return target;
        case STM::Alloc::nomem:
            throw Exception::TransactionAlloc{};
        default: // STM::Alloc::abort
            aborted = true;
            throw Exception::TransactionRetry{};
        }
    }
    /** [thread-safe] Memory freeing operation in the bound transaction.
     * @param target Target start address
    **/
    void free(void* target) {
        if (unlikely(assert_mode && is_ro))
            throw Exception::TransactionReadOnly{};
        if (unlikely(!tm.free(tx, target))) {
            aborted = true;
            throw Exception::TransactionRetry{};
        }
    }
};

/** Shared read/write helper class.
 * @param Type Specified type (array)
**/
template<class Type> class Shared {
protected:
    Transaction& tx; // Bound transaction
    Type* address; // Address in shared memory
public:
    /** Binding constructor.
     * @param tx      Bound transaction
     * @param address Address to bind to
    **/
    Shared(Transaction& tx, void* address): tx{tx}, address{reinterpret_cast<Type*>(address)} {
        if (unlikely(assert_mode && reinterpret_cast<uintptr_t>(address) % tx.get_tm().get_align() != 0))
            throw Exception::SharedAlign{};
        if (unlikely(assert_mode && reinterpret_cast<uintptr_t>(address) % alignof(Type) != 0))
            throw Exception::SharedAlign{};
    }
public:
    /** Get the address in shared memory.
     * @return Address in shared memory
    **/
    auto get() const noexcept {
        return address;
    }
public:
    /** Read operation.
     * @return Private copy of the content at the shared address
    **/
    Type read() const {
        Type res;
        tx.read(address, sizeof(Type), &res);
        return res;
    }
    operator Type() const {
        return read();
    }
    /** Write operation.
     * @param source Private content to write at the shared address
    **/
    void write(Type const& source) const {
        tx.write(&source, sizeof(Type), address);
    }
    void operator=(Type const& source) const {
        return write(source);
    }
public:
    /** Address of the first byte after the entry.
     * @return First byte after the entry
    **/
    void* after() const noexcept {
        return address + 1;
    }
};
template<class Type> class Shared<Type*> {
protected:
    Transaction& tx; // Bound transaction
    Type** address; // Address in shared memory
public:
    /** Binding constructor.
     * @param tx      Bound transaction
     * @param address Address to bind to
    **/
    Shared(Transaction& tx, void* address): tx{tx}, address{reinterpret_cast<Type**>(address)} {
        if (unlikely(assert_mode && reinterpret_cast<uintptr_t>(address) % tx.get_tm().get_align() != 0))
            throw Exception::SharedAlign{};
        if (unlikely(assert_mode && reinterpret_cast<uintptr_t>(address) % alignof(Type*) != 0))
            throw Exception::SharedAlign{};
    }
public:
    /** Get the address in shared memory.
     * @return Address in shared memory
    **/
    auto get() const noexcept {
        return address;
    }
public:
    /** Read operation.
     * @return Private copy of the content at the shared address
    **/
    Type* read() const {
        Type* res;
        tx.read(address, sizeof(Type*), &res);
        return res;
    }
    operator Type*() const {
        return read();
    }
    /** Write operation.
     * @param source Private content to write at the shared address
    **/
    void write(Type* source) const {
        tx.write(&source, sizeof(Type*), address);
    }
    void operator=(Type* source) const {
        return write(source);
    }
    /** Allocate and write operation.
     * @param size Size to allocate (defaults to size of the underlying class)
     * @return Private copy of the just-written content at the shared address
    **/
    Type* alloc(size_t size = 0) const {
        if (unlikely(assert_mode && read() != nullptr))
            throw Exception::SharedDoubleAlloc{};
        auto addr = tx.alloc(size > 0 ? size: sizeof(Type));
        write(reinterpret_cast<Type*>(addr));
        return reinterpret_cast<Type*>(addr);
    }
    /** Free and write operation.
    **/
    void free() const {
        if (unlikely(assert_mode && read() == nullptr))
            throw Exception::SharedDoubleFree{};
        tx.free(read());
        write(nullptr);
    }
public:
    /** Address of the first byte after the entry.
     * @return First byte after the entry
    **/
    void* after() const noexcept {
        return address + 1;
    }
};
template<class Type> class Shared<Type[]> {
protected:
    Transaction& tx; // Bound transaction
    Type* address; // Address of the first element in shared memory
public:
    /** Binding constructor.
     * @param tx      Bound transaction
     * @param address Address to bind to
    **/
    Shared(Transaction& tx, void* address): tx{tx}, address{reinterpret_cast<Type*>(address)} {
        if (unlikely(assert_mode && reinterpret_cast<uintptr_t>(address) % tx.get_tm().get_align() != 0))
            throw Exception::SharedAlign{};
        if (unlikely(assert_mode && reinterpret_cast<uintptr_t>(address) % alignof(Type) != 0))
            throw Exception::SharedAlign{};
    }
public:
    /** Get the address in shared memory.
     * @return Address in shared memory
    **/
    auto get() const noexcept {
        return address;
    }
public:
    /** Read operation.
     * @param index Index to read
     * @return Private copy of the content at the shared address
    **/
    Type read(size_t index) const {
        Type res;
        tx.read(address + index, sizeof(Type), &res);
        return res;
    }
    /** Write operation.
     * @param index  Index to write
     * @param source Private content to write at the shared address
    **/
    void write(size_t index, Type const& source) const {
        tx.write(tx, &source, sizeof(Type), address + index);
    }
public:
    /** Reference a cell.
     * @param index Cell to reference
     * @return Shared on that cell
    **/
    Shared<Type> operator[](size_t index) const {
        return Shared<Type>{tx, address + index};
    }
    /** Address of the first byte after the entry.
     * @param length Length of the array
     * @return First byte after the entry
    **/
    void* after(size_t length) const noexcept {
        return address + length;
    }
};
template<class Type, size_t n> class Shared<Type[n]> {
protected:
    Transaction& tx; // Bound transaction
    Type* address; // Address of the first element in shared memory
public:
    /** Binding constructor.
     * @param tx      Bound transaction
     * @param address Address to bind to
    **/
    Shared(Transaction& tx, void* address): tx{tx}, address{reinterpret_cast<Type*>(address)} {
        if (unlikely(assert_mode && reinterpret_cast<uintptr_t>(address) % tx.get_tm().get_align() != 0))
            throw Exception::SharedAlign{};
        if (unlikely(assert_mode && reinterpret_cast<uintptr_t>(address) % alignof(Type) != 0))
            throw Exception::SharedAlign{};
    }
public:
    /** Get the address in shared memory.
     * @return Address in shared memory
    **/
    auto get() const noexcept {
        return address;
    }
public:
    /** Read operation.
     * @param index Index to read
     * @return Private copy of the content at the shared address
    **/
    Type read(size_t index) const {
        if (unlikely(assert_mode && index >= n))
            throw Exception::SharedOverflow{};
        Type res;
        tx.read(address + index, sizeof(Type), &res);
        return res;
    }
    /** Write operation.
     * @param index  Index to write
     * @param source Private content to write at the shared address
    **/
    void write(size_t index, Type const& source) const {
        if (unlikely(assert_mode && index >= n))
            throw Exception::SharedOverflow{};
        tx.write(tx, &source, sizeof(Type), address + index);
    }
public:
    /** Reference a cell.
     * @param index Cell to reference
     * @return Shared on that cell
    **/
    Shared<Type> operator[](size_t index) const {
        if (unlikely(assert_mode && index >= n))
            throw Exception::SharedOverflow{};
        return Shared<Type>{tx, address + index};
    }
    /** Address of the first byte after the array.
     * @return First byte after the array
    **/
    void* after() const noexcept {
        return address + n;
    }
};

// -------------------------------------------------------------------------- //

/** Seed type.
**/
using Seed = ::std::uint_fast32_t;

/** Workload base class.
**/
class Workload {
protected:
    /** Worker context base class.
    **/
    class ContextBase: private NonCopyable {};
public:
    /** Context class.
    **/
    using Context = ::std::unique_ptr<ContextBase>;
protected:
    TransactionalLibrary const& tl;  // Associated transactional library
    TransactionalMemory         tm;  // Built transactional memory to use
public:
    /** Deleted copy constructor/assignment.
    **/
    Workload(Workload const&) = delete;
    Workload& operator=(Workload const&) = delete;
    /** Transactional memory constructor.
     * @param library Transactional library to use
     * @param align   Shared memory region required alignment
     * @param size    Size of the shared memory region to allocate
    **/
    Workload(TransactionalLibrary const& library, size_t align, size_t size): tl{library}, tm{tl, align, size} {}
    /** Virtual destructor.
    **/
    virtual ~Workload() {};
public:
    /** [thread-safe] Prepare one worker thread's context.
     * @param Seed to use
     * @return Context pointer
    **/
    virtual Context prepare(Seed) = 0;
    /** [thread-safe] One transaction in one worker thread.
     * @param Associated worker context
     * @return Whether no inconsistency has been (passively) detected
    **/
    virtual bool run(Seed, size_t) = 0;
    /** [thread-safe] Worker full run.
     * @return Whether no inconsistency has been detected
    **/
    virtual bool check() const = 0;
};

/** Bank workload class.
**/
class Bank final: public Workload {
protected:
    /** Bank worker context class.
    **/
    class BankContext: public ContextBase {
    public:
        ::std::minstd_rand engine;
        ::std::bernoulli_distribution long_dist;
        ::std::bernoulli_distribution alloc_dist;
        ::std::uniform_int_distribution<size_t> account;
        ::std::gamma_distribution<float> alloc_trigger;
    public:
        /** Defaulted move constructor/assignment.
        **/
        BankContext(BankContext&&) = default;
        BankContext& operator=(BankContext&&) = default;
        /** Parameter constructor.
         * @param ... <to complete>
        **/
        BankContext(Seed seed, float prob_long, float prob_alloc, size_t nbaccounts, size_t  expnbaccounts): engine{seed}, long_dist{prob_long}, alloc_dist{prob_alloc}, account{0, nbaccounts - 1}, alloc_trigger{expnbaccounts, 1} {}
    };
public:
    /** Account balance class alias.
    **/
    using Balance = intptr_t;
    static_assert(sizeof(Balance) >= sizeof(void*), "Balance class is too small");
private:
    /** Shared segment of accounts class.
    **/
    class AccountSegment final {
    private:
        /** Dummy structure for size and alignment retrieval.
        **/
        struct Dummy {
            size_t  dummy0;
            void*   dummy1;
            Balance dummy2;
            Balance dummy3[];
        };
    public:
        /** Get the segment size for a given number of accounts.
         * @param nbaccounts Number of accounts per segment
         * @return Segment size (in bytes)
        **/
        constexpr static auto size(size_t nbaccounts) noexcept {
            return sizeof(Dummy) + nbaccounts * sizeof(Balance);
        }
        /** Get the segment alignment for a given number of accounts.
         * @return Segment size (in bytes)
        **/
        constexpr static auto align() noexcept {
            return alignof(Dummy);
        }
    public:
        Shared<size_t>         count; // Number of allocated accounts in this segment
        Shared<AccountSegment*> next; // Next allocated segment
        Shared<Balance>       parity; // Segment balance correction for when deleting an account
        Shared<Balance[]>   accounts; // Amount of money on the accounts (undefined if not allocated)
    public:
        /** Deleted copy constructor/assignment.
        **/
        AccountSegment(AccountSegment const&) = delete;
        AccountSegment& operator=(AccountSegment const&) = delete;
        /** Binding constructor.
         * @param tx      Associated pending transaction
         * @param address Block base address
        **/
        AccountSegment(Transaction& tx, void* address): count{tx, address}, next{tx, count.after()}, parity{tx, next.after()}, accounts{tx, parity.after()} {}
    };
private:
    size_t  nbaccounts;    // Initial number of accounts and number of accounts per segment
    size_t  expnbaccounts; // Expected total number of accounts
    Balance init_balance;  // Initial account balance
    float   prob_long;     // Probability of running a long, read-only control transaction
    float   prob_alloc;    // Probability of running an allocation/deallocation transaction, knowing a long transaction won't run
public:
    /** Bank workload constructor.
     * @param library       Transactional library to use
     * @param nbtxperwrk    Number of transactions per worker
     * @param nbaccounts    Initial number of accounts and number of accounts per segment
     * @param expnbaccounts Initial number of accounts and number of accounts per segment
     * @param init_balance  Initial account balance
     * @param prob_long     Probability of running a long, read-only control transaction
     * @param prob_alloc    Probability of running an allocation/deallocation transaction, knowing a long transaction won't run
    **/
    Bank(TransactionalLibrary const& library, size_t nbaccounts, size_t expnbaccounts, Balance init_balance, float prob_long, float prob_alloc): Workload{library, AccountSegment::align(), AccountSegment::size(nbaccounts)}, nbaccounts{nbaccounts}, expnbaccounts{expnbaccounts}, init_balance{init_balance}, prob_long{prob_long}, prob_alloc{prob_alloc} {
        do {
            try {
                Transaction tx{tm, Transaction::read_write};
                AccountSegment segment{tx, tm.get_start()};
                segment.count = nbaccounts;
                for (size_t i = 0; i < nbaccounts; ++i)
                    segment.accounts[i] = init_balance;
                break;
            } catch (Exception::TransactionRetry const&) {
                continue;
            }
        } while (true);
    }
private:
    /** Long read-only transaction, summing the balance of each account.
     * @param count Loosely-updated number of accounts
     * @return Whether no inconsistency has been found
    **/
    bool long_tx(size_t& nbaccounts) const {
        do {
            try {
                auto count = 0ul;
                auto sum   = Balance{0};
                auto start = tm.get_start();
                Transaction tx{tm, Transaction::read_only};
                while (start) {
                    AccountSegment segment{tx, start};
                    decltype(count) segment_count = segment.count;
                    count += segment_count;
                    sum += segment.parity;
                    for (decltype(count) i = 0; i < segment_count; ++i) {
                        Balance local = segment.accounts[i];
                        if (unlikely(local < 0))
                            return false;
                        sum += local;
                    }
                    start = segment.next;
                }
                nbaccounts = count;
                return sum == static_cast<Balance>(init_balance * count);
            } catch (Exception::TransactionRetry const&) {
                continue;
            }
        } while (true);
    }
    /** Account (de)allocation transaction, adding accounts with initial balance or removing them.
     * @param trigger Trigger level that will decide whether to allocate or deallocate
     * @return Whether no inconsistency has been found
    **/
    bool alloc_tx(size_t trigger) const {
        do {
            try {
                auto count = 0ul;
                auto start = tm.get_start();
                void* prev = nullptr;
                Transaction tx{tm, Transaction::read_write};
                while (true) {
                    AccountSegment segment{tx, start};
                    decltype(count) segment_count = segment.count;
                    count += segment_count;
                    decltype(start) segment_next = segment.next;
                    if (!segment_next) {
                        if (count > trigger && likely(count > 2)) { // Deallocate
                            --segment_count;
                            auto new_parity = segment.parity.read() + segment.accounts[segment_count] - init_balance;
                            if (segment_count > 0) { // Just "deallocate" account
                                segment.count = segment_count;
                                segment.parity = new_parity;
                            } else { // Deallocate segment
                                if (unlikely(assert_mode && prev == nullptr))
                                    throw Exception::TransactionNotLastSegment{};
                                AccountSegment prev_segment{tx, prev};
                                prev_segment.next.free();
                                prev_segment.parity = prev_segment.parity.read() + new_parity;
                            }
                        } else { // Allocate
                            if (segment_count < nbaccounts) { // Just "allocate" account
                                segment.accounts[segment_count] = init_balance;
                                segment.count = segment_count + 1;
                            } else {
                                AccountSegment next_segment{tx, segment.next.alloc(AccountSegment::size(nbaccounts))};
                                next_segment.count = 1;
                                next_segment.accounts[0] = init_balance;
                            }
                        }
                        return true;
                    }
                    prev  = start;
                    start = segment_next;
                }
            } catch (Exception::TransactionRetry const&) {
                continue;
            }
        } while (true);
    }
    /** Short read-write transaction, transferring one unit from an account to an account (potentially the same).
     * @param send_id Index of the sender account
     * @param recv_id Index of the receiver account (potentially same as source)
     * @return Whether no inconsistency has been found
    **/
    bool short_tx(size_t send_id, size_t recv_id) const {
        do {
            try {
                auto start = tm.get_start();
                Transaction tx{tm, Transaction::read_write};
                void* send_ptr = nullptr;
                void* recv_ptr = nullptr;
                // Get the account pointers in shared memory
                while (true) {
                    AccountSegment segment{tx, start};
                    size_t segment_count = segment.count;
                    if (!send_ptr) {
                        if (send_id < segment_count) {
                            send_ptr = segment.accounts[send_id].get();
                            if (recv_ptr)
                                break;
                        } else {
                            send_id -= segment_count;
                        }
                    }
                    if (!recv_ptr) {
                        if (recv_id < segment_count) {
                            recv_ptr = segment.accounts[recv_id].get();
                            if (send_ptr)
                                break;
                        } else {
                            recv_id -= segment_count;
                        }
                    }
                    start = segment.next;
                    if (!start) // Current segment is the last segment
                        return true; // At least one account does not exist => do nothing
                }
                // Transfer the money if enough fund
                Shared<Balance> sender{tx, send_ptr};
                Shared<Balance> recver{tx, recv_ptr};
                auto send_val = sender.read();
                if (send_val > 0) {
                    sender = send_val - 1;
                    recver = recver.read() + 1;
                }
                return true;
            } catch (Exception::TransactionRetry const&) {
                continue;
            }
        } while (true);
    }
public:
    virtual Context prepare(Seed seed) {
        return ::std::make_unique<BankContext>(seed, prob_long, prob_alloc, nbaccounts, expnbaccounts);
    }
    virtual bool run(Seed seed, size_t nbtxperwrk) {
        ::std::minstd_rand engine{seed};
        ::std::bernoulli_distribution long_dist{prob_long};
        ::std::bernoulli_distribution alloc_dist{prob_alloc};
        ::std::gamma_distribution<float> alloc_trigger(expnbaccounts, 1);
        size_t count = nbaccounts;
        for (size_t cntr = 0; cntr < nbtxperwrk; ++cntr) {
            if (long_dist(engine)) { // Do a long transaction
                if (unlikely(!long_tx(count)))
                    return false;
            } else if (alloc_dist(engine)) { // Do an allocation transaction
                if (unlikely(!alloc_tx(alloc_trigger(engine))))
                    return false;
            } else { // Do a short transaction
                ::std::uniform_int_distribution<size_t> account{0, count - 1};
                if (unlikely(!short_tx(account(engine), account(engine))))
                    return false;
            }
        }
        return true;
    }
    virtual bool check() const {
        size_t dummy;
        return long_tx(dummy);
    }
};

// -------------------------------------------------------------------------- //

/** Time accounting class.
**/
class Chrono final {
public:
    /** Tick class.
    **/
    using Tick = uint_fast64_t;
    constexpr static auto invalid_tick = Tick{0xbadc0de}; // Invalid tick value
private:
    Tick total; // Total tick counter
    Tick local; // Segment tick counter
public:
    /** Tick constructor.
     * @param tick Initial number of ticks (optional)
    **/
    Chrono(Tick tick = 0) noexcept: total{tick} {}
private:
    /** Call a "clock" function, convert the result to the Tick type.
     * @param func "Clock" function to call
     * @return Resulting time
    **/
    static Tick convert(int (*func)(::clockid_t, struct ::timespec*)) noexcept {
        struct ::timespec buf;
        if (unlikely(func(CLOCK_MONOTONIC, &buf) < 0))
            return invalid_tick;
        auto res = static_cast<Tick>(buf.tv_nsec) + static_cast<Tick>(buf.tv_sec) * static_cast<Tick>(1000000000ul);
        if (unlikely(res == invalid_tick)) // Bad luck...
            return invalid_tick + 1;
        return res;
    }
public:
    /** Get the resolution of the clock used.
     * @return Resolution (in ns), 'invalid_tick' for unknown
    **/
    static auto get_resolution() noexcept {
        return convert(::clock_getres);
    }
public:
    /** Start measuring a time segment.
    **/
    void start() noexcept {
        local = convert(::clock_gettime);
    }
    /** Measure a time segment.
    **/
    auto delta() noexcept {
        return convert(::clock_gettime) - local;
    }
    /** Stop measuring a time segment, and add it to the total.
    **/
    void stop() noexcept {
        total += delta();
    }
    /** Reset the total tick counter.
    **/
    void reset() noexcept {
        total = 0;
    }
    /** Get the total tick counter.
     * @return Total tick counter
    **/
    auto get_tick() const noexcept {
        return total;
    }
};

/** Pause execution for a longer time.
**/
static void long_pause() {
    ::std::this_thread::sleep_for(::std::chrono::milliseconds(200));
}

/** Tailored thread synchronization class.
**/
class Sync final {
private:
    /** Synchronization status.
    **/
    enum class Status {
        Wait,  // Workers waiting each others, run as soon as all ready
        Run,   // Workers running (still full success)
        Abort, // Workers running (>0 failure)
        Done,  // Workers done (all success)
        Fail,  // Workers done (>0 failures)
        Quit   // Workers must terminate
    };
private:
    unsigned int const        nbworkers; // Number of workers to support
    ::std::atomic<unsigned int> nbready; // Number of thread having reached that state
    ::std::atomic<Status>       status;  // Current synchronization status
public:
    /** Deleted copy constructor/assignment.
    **/
    Sync(Sync const&) = delete;
    Sync& operator=(Sync const&) = delete;
    /** Worker count constructor.
     * @param nbworkers Number of workers to support
    **/
    Sync(unsigned int nbworkers): nbworkers{nbworkers}, nbready{0}, status{Status::Done} {}
public:
    /** Master trigger "synchronized" execution in all threads.
    **/
    void master_notify() noexcept {
        status.store(Status::Wait, ::std::memory_order_release);
    }
    /** Master trigger termination in all threads.
    **/
    void master_join() noexcept {
        status.store(Status::Quit, ::std::memory_order_release);
    }
    /** Master wait for all workers to finish.
     * @param maxtick Maximum number of ticks to wait before exiting the process on an error
     * @return Whether all workers finished on success
    **/
    bool master_wait(Chrono::Tick maxtick) {
        Chrono chrono;
        chrono.start();
        while (true) {
            switch (status.load(::std::memory_order_relaxed)) {
            case Status::Done:
                return true;
            case Status::Fail:
                return false;
            default:
                long_pause();
                if (maxtick != Chrono::invalid_tick && chrono.delta() > maxtick)
                    throw Exception::TooSlow{};
            }
        }
    }
    /** Worker wait until next run.
     * @return Whether the worker can proceed, or quit otherwise
    **/
    bool worker_wait() noexcept {
        while (true) {
            auto res = status.load(::std::memory_order_relaxed);
            if (res == Status::Wait)
                break;
            if (res == Status::Quit)
                return false;
            pause();
        }
        auto res = nbready.fetch_add(1, ::std::memory_order_relaxed);
        if (res + 1 == nbworkers) { // Latest worker, switch to run status
            nbready.store(0, ::std::memory_order_relaxed);
            status.store(Status::Run, ::std::memory_order_release);
        } else do { // Not latest worker, wait for run status
            pause();
            auto res = status.load(::std::memory_order_relaxed);
            if (res == Status::Run || res == Status::Abort)
                break;
        } while (true);
        return true;
    }
    /** Worker notify termination of its run.
     * @param success Whether its run was a success
    **/
    void worker_notify(bool success) noexcept {
        if (!success)
            status.store(Status::Abort, ::std::memory_order_relaxed);
        auto&& res = nbready.fetch_add(1, ::std::memory_order_acq_rel);
        if (res + 1 == nbworkers) { // Latest worker, switch to done/fail status
            nbready.store(0, ::std::memory_order_relaxed);
            status.store(status.load(::std::memory_order_relaxed) == Status::Abort ? Status::Fail : Status::Done, ::std::memory_order_release);
        }
    }
};

// NOTE: ASCYLIB-STYLE CODE BELOW

// -------------------------------------------------------------------------- //

#define DEFAULT_DURATION                1000
#define DEFAULT_INITIAL                 1024
#define DEFAULT_NB_THREADS              1
#define DEFAULT_RANGE                   (2 * DEFAULT_INITIAL)
#define DEFAULT_UPDATE                  20
#define DEFAULT_WATCHDOG_TIMEOUT        60000 // in milliseconds

#if !defined(UNUSED)
#  define UNUSED __attribute__ ((unused))
#endif

static volatile int stop;
static volatile int stop_watchdog;

auto num_threads = []() {
    auto res = ::std::thread::hardware_concurrency();
    if (unlikely(res == 0))
        res = 16;
    return static_cast<size_t>(res);
}();
auto num_accounts  = 4   * num_threads;
auto expnbaccounts = 1024 * num_threads;
auto init_balance  = 100;
auto prob_long     = 0.5f;
auto prob_alloc    = 0.3f;
auto nbrepeats     = 11;
auto seed          = static_cast<Seed>(42);
size_t duration    = DEFAULT_DURATION;


volatile ticks *tx_count;

std::mutex cv_m;
std::condition_variable cv;
barrier_t barrier, barrier_global;

typedef struct thread_data
{
  uint32_t id;
  Workload* workload;
  Seed seed;
} thread_data_t;


void*
test(void* thread) 
{
  thread_data_t* td = (thread_data_t*) thread;
  uint32_t ID = td->id;
  Workload* workload = td->workload;
  Seed seed = td->seed;

  uint64_t my_tx_count = 0;

  // barrier before initialization
  barrier_cross(&barrier);

  // auto context = workload->prepare(seed);

  // barrier after initialization
  // barrier_cross(&barrier);

  // barrier before actual measured run
  barrier_cross(&barrier_global);

  bool res;
  // while (stop == 0) {
  //   res = workload->run(context);
  //   if (likely(res)) {
  //     my_tx_count++;
  //   } else {
  //     my_tx_count = UINT64_MAX;
  //     break;
  //   }
  // }

  workload->run(seed, 1000);

  barrier_cross(&barrier_global);

  tx_count[ID] = my_tx_count;

  pthread_exit(NULL);
}

void*
watchdog(void* thread) {

    auto timeout = DEFAULT_WATCHDOG_TIMEOUT * 1ms;
    std::unique_lock<std::mutex> lk(cv_m);
    cv.wait_for(lk, timeout, []{return stop_watchdog == 1;});

    if (!stop_watchdog) {
        printf("Timing out!\n");
        exit(-1);
    }

    pthread_exit(NULL);
} 

double
measure(Workload& workload) {
  struct timeval start, end;
  struct timespec timeout;
  timeout.tv_sec = duration / 1000;
  timeout.tv_nsec = (duration % 1000) * 1000000;

  stop = 0;
  pthread_t threads[num_threads];
  pthread_t watchdog_thread;
  pthread_attr_t attr;
  int rc;
  void *status;

  barrier_init(&barrier_global, num_threads + 1);
  barrier_init(&barrier, num_threads);

  /* Initialize and set thread detached attribute */
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
  thread_data_t* tds = (thread_data_t*) malloc(num_threads * sizeof(thread_data_t));

  // start watchdog thread
  stop_watchdog = 0;
  rc = pthread_create(&watchdog_thread, &attr, watchdog, NULL);
  if (rc) {
      printf("ERROR; return code from pthread_create() is %d\n", rc);
      exit(-1);
  }
  size_t t;
  for(t = 0; t < num_threads; t++)
  {
    tds[t].id = t;
    tds[t].workload = &workload;
    tds[t].seed = seed;
    rc = pthread_create(&threads[t], &attr, test, tds + t);
    if (rc)
    {
      printf("ERROR; return code from pthread_create() is %d\n", rc);
      exit(-1);
    }

  }

  /* Free attribute and wait for the other threads */
  pthread_attr_destroy(&attr);

  barrier_cross(&barrier_global);
  gettimeofday(&start, NULL);
  // nanosleep(&timeout, NULL);
  // stop = 1;
  barrier_cross(&barrier_global);
  gettimeofday(&end, NULL);

  duration = (end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec);

  for(t = 0; t < num_threads; t++) {
    rc = pthread_join(threads[t], &status);
    if (rc) {
      printf("ERROR; return code from pthread_join() is %d\n", rc);
      exit(-1);
    }
  }

    // stop watchdog thread
    stop_watchdog = 1;
    cv.notify_all();
    rc = pthread_join(watchdog_thread, &status);
    if (rc) {
        printf("ERROR; return code from pthread_join() is %d\n", rc);
        exit(-1);  
    }

  free(tds);
  volatile uint64_t tx_count_total = 0;

  for(t=0; t < num_threads; t++) 
  {
    if (tx_count[t] != UINT64_MAX) {
      tx_count_total += tx_count[t];
    } else {
      printf("INCONCISTENCY DETECTED!\n");
      exit(-1);
    }

  }

#define LLU long long unsigned int

  // int UNUSED pr = (int) (putting_count_total_succ - removing_count_total_succ);

  // printf("    : %-10s | %-10s | %-11s | %-11s | %s\n", "total", "success", "succ %", "total %", "effective %");
  // uint64_t total = putting_count_total + getting_count_total + removing_count_total;
  // double putting_perc = 100.0 * (1 - ((double)(total - putting_count_total) / total));
  // double putting_perc_succ = (1 - (double) (putting_count_total - putting_count_total_succ) / putting_count_total) * 100;
  // double getting_perc = 100.0 * (1 - ((double)(total - getting_count_total) / total));
  // double getting_perc_succ = (1 - (double) (getting_count_total - getting_count_total_succ) / getting_count_total) * 100;
  // double removing_perc = 100.0 * (1 - ((double)(total - removing_count_total) / total));
  // double removing_perc_succ = (1 - (double) (removing_count_total - removing_count_total_succ) / removing_count_total) * 100;
  // printf("srch: %-10llu | %-10llu | %10.1f%% | %10.1f%% | \n", (LLU) getting_count_total, 
  //  (LLU) getting_count_total_succ,  getting_perc_succ, getting_perc);
  // printf("insr: %-10llu | %-10llu | %10.1f%% | %10.1f%% | %10.1f%%\n", (LLU) putting_count_total, 
  //  (LLU) putting_count_total_succ, putting_perc_succ, putting_perc, (putting_perc * putting_perc_succ) / 100);
  // printf("rems: %-10llu | %-10llu | %10.1f%% | %10.1f%% | %10.1f%%\n", (LLU) removing_count_total, 
  //  (LLU) removing_count_total_succ, removing_perc_succ, removing_perc, (removing_perc * removing_perc_succ) / 100);

  double throughput = (tx_count_total) * 1000.0 / duration;
  printf("#txs %zu\t(%zu us\n", num_threads, duration);
  // printf("#Mops %.3f\n", throughput / 1e6);  

  return throughput;

}

// returns median throughput
void
eval(char const* path) {
  TransactionalLibrary tl{path};
  Bank bank{tl, num_accounts, expnbaccounts, init_balance, prob_long, prob_alloc};

  measure(bank);
}

int
main(int argc, char **argv) {

  struct option long_options[] = {
    // These options don't set a flag
    {"help",                      no_argument,       NULL, 'h'},
    {"verbose",                   no_argument,       NULL, 'e'},
    {"duration",                  required_argument, NULL, 'd'},
    {"initial-size",              required_argument, NULL, 'i'},
    {"num-threads",               required_argument, NULL, 'n'},
    {"range",                     required_argument, NULL, 'r'},
    {"update-rate",               required_argument, NULL, 'u'},
    {"num-buckets",               required_argument, NULL, 'b'},
    {"print-vals",                required_argument, NULL, 'v'},
    {"vals-pf",                   required_argument, NULL, 'f'},
    {NULL, 0, NULL, 0}
  };

  int i, c;
  char *tl_path, *ref_path;
  while(1) 
  {
    i = 0;
    c = getopt_long(argc, argv, "hAf:d:i:n:r:s:t:m:l:p:v:f:x:", long_options, &i);

    if(c == -1)
      break;

    if(c == 0 && long_options[i].flag == 0)
      c = long_options[i].val;

    switch(c) 
    {
      case 0:
      /* Flag is automatically set */
      break;
      case 'h':
      printf("ASCYLIB -- stress test "
       "\n"
       "\n"
       "Usage:\n"
       "  %s [options...]\n"
       "\n"
       "Options:\n"
       "  -h, --help\n"
       "        Print this message\n"
       "  -e, --verbose\n"
       "        Be verbose\n"
       "  -d, --duration <int>\n"
       "        Test duration in milliseconds\n"
       "  -i, --initial-size <int>\n"
       "        Number of elements to insert before test\n"
       "  -n, --num-threads <int>\n"
       "        Number of threads\n"
       "  -r, --range <int>\n"
       "        Range of integer values inserted in set\n"
       "  -u, --update-rate <int>\n"
       "        Percentage of update transactions\n"
       "  -p, --put-rate <int>\n"
       "        Percentage of put update transactions (should be less than percentage of updates)\n"
       , argv[0]);
      exit(0);
      case 'd':
        duration = atoi(optarg);
        break;
      case 's':
        seed = static_cast<Seed>(::std::stoul(optarg));
        break;
      case 'n':
        num_threads = atoi(optarg);
        break;
      case 'r':
        nbrepeats = atol(optarg);
        break;
      case 't':
        tl_path = optarg;
        break;
      case '?':
      default:
      printf("Use -h or --help for help\n");
      exit(1);
    }
  }

  num_accounts = 4 * num_threads;



  /* Initializes the local data */
  tx_count = (ticks *) calloc(num_threads , sizeof(ticks));

  eval(tl_path);

  return 0;
}

