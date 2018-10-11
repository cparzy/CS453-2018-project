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

#include <algorithm>
#include <atomic>
#include <chrono>
#include <iostream>
#include <random>
#include <thread>
extern "C" {
#include <dlfcn.h>
#include <limits.h>
#include <time.h>
#if (defined(__i386__) || defined(__x86_64__)) && defined(USE_MM_PAUSE)
    #include <xmmintrin.h>
#endif
}

// Internal headers
namespace TM {
extern "C" {
#include <tm.h>
}
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

/** Seed type.
**/
using Seed = ::std::uint_fast32_t;

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
        EXCEPTION(TransactionCreate, Module, "shared memory region creation failed");
        EXCEPTION(TransactionBegin, Module, "transaction begin failed");
        EXCEPTION(TransactionAlloc, Module, "memory allocation failed (insufficient memory)");
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

/** Transactional library class.
**/
class TransactionalLibrary final {
    friend class TransactionalMemory;
private:
    /** Function types.
    **/
    using FnCreate  = decltype(&TM::tm_create);
    using FnDestroy = decltype(&TM::tm_destroy);
    using FnStart   = decltype(&TM::tm_start);
    using FnSize    = decltype(&TM::tm_size);
    using FnAlign   = decltype(&TM::tm_align);
    using FnBegin   = decltype(&TM::tm_begin);
    using FnEnd     = decltype(&TM::tm_end);
    using FnRead    = decltype(&TM::tm_read);
    using FnWrite   = decltype(&TM::tm_write);
    using FnAlloc   = decltype(&TM::tm_alloc);
    using FnFree    = decltype(&TM::tm_free);
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
    /** Deleted copy constructor/assignment.
    **/
    TransactionalLibrary(TransactionalLibrary const&) = delete;
    TransactionalLibrary& operator=(TransactionalLibrary const&) = delete;
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

/** Transactional memory class.
**/
class TransactionalMemory final {
public:
    /** Opaque shared memory region handle class.
    **/
    using Shared = TM::shared_t;
    /** Transaction class.
    **/
    using TX = TM::tx_t;
private:
    TransactionalLibrary const& tl; // Bound transactional library
    Shared    shared;     // Handle of the shared memory region used
    uintptr_t start_addr; // Shared memory region start address
public:
    /** Deleted copy constructor/assignment.
    **/
    TransactionalMemory(TransactionalMemory const&) = delete;
    TransactionalMemory& operator=(TransactionalMemory const&) = delete;
    /** Bind constructor.
     * @param library Transactional library to use
     * @param align   Shared memory region required alignment
     * @param size    Size of the shared memory region to allocate
    **/
    TransactionalMemory(TransactionalLibrary const& library, size_t align, size_t size): tl{library} {
        { // Initialize shared memory region
            shared = tl.tm_create(size, align);
            if (unlikely(shared == TM::invalid_shared))
                throw Exception::TransactionCreate{};
            start_addr = reinterpret_cast<uintptr_t>(tl.tm_start(shared));
        }
    }
    /** Unbind destructor.
    **/
    ~TransactionalMemory() noexcept {
        tl.tm_destroy(shared);
    }
public:
    /** Build an address in the shared region from an offset.
     * @param ptr Offset (in bytes)
     * @return Address in the shared region
    **/
    void* address(uintptr_t ptr) const noexcept {
        return reinterpret_cast<void*>(ptr + start_addr);
    }
public:
    /** [thread-safe] Begin a new transaction on the shared memory region.
     * @return Opaque transaction ID
    **/
    auto begin() {
        auto&& res = tl.tm_begin(shared);
        if (unlikely(res == TM::invalid_tx))
            throw Exception::TransactionBegin{};
        return res;
    }
    /** [thread-safe] End the given transaction.
     * @param tx Opaque transaction ID
     * @return Whether the whole transaction is a success
    **/
    auto end(TX tx) noexcept {
        return tl.tm_end(shared, tx);
    }
    /** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
     * @param tx     Transaction to use
     * @param source Source start address
     * @param size   Source/target range
     * @param target Target start address
     * @return Whether the whole transaction can continue
    **/
    auto read(TX tx, void const* source, size_t size, void* target) noexcept {
        return tl.tm_read(shared, tx, source, size, target);
    }
    /** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
     * @param tx     Transaction to use
     * @param source Source start address
     * @param size   Source/target range
     * @param target Target start address
     * @return Whether the whole transaction can continue
    **/
    auto write(TX tx, void const* source, size_t size, void* target) noexcept {
        return tl.tm_write(shared, tx, source, size, target);
    }
    /** [thread-safe] Memory allocation operation in the given transaction, throw if no memory available.
     * @param tx     Transaction to use
     * @param size   Size to allocate
     * @param target Target start address
     * @return Whether the whole transaction can continue
    **/
    auto alloc(TX tx, size_t size, void** target) {
        auto status = tl.tm_alloc(shared, tx, size, target);
        if (unlikely(status == TM::nomem_alloc))
            throw Exception::TransactionAlloc{};
        return status == TM::success_alloc;
    }
    /** [thread-safe] Memory freeing operation in the given transaction.
     * @param tx     Transaction to use
     * @param target Target start address
     * @return Whether the whole transaction can continue
    **/
    auto free(TX tx, void* target) noexcept {
        return tl.tm_free(shared, tx, target);
    }
};

// -------------------------------------------------------------------------- //

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
    /** Transaction library constructor.
     * @param library Transactional library to use
     * @param align   Shared memory region required alignment
     * @param size    Size of the shared memory region to allocate
    **/
    Workload(TransactionalLibrary const& library, size_t align, size_t size): tl{library}, tm{tl, align, size} {
    }
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
    virtual bool run(Context&) = 0;
    /** [thread-safe] Worker full run.
     * @return Whether no inconsistency has been detected
    **/
    virtual bool check() = 0;
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
        ::std::uniform_int_distribution<size_t> account;
    public:
        /** Defaulted move constructor/assignment.
        **/
        BankContext(BankContext&&) = default;
        BankContext& operator=(BankContext&&) = default;
        /** Parameter constructor.
         * @param ... <to complete>
        **/
        BankContext(Seed seed, float prob_long, size_t nbaccounts): engine{seed}, long_dist{prob_long}, account{0, nbaccounts - 1} {}
    };
private:
    size_t nbaccounts; // Number of accounts
    int  init_balance; // Initial account balance
    float   prob_long; // Probability of running a long, read-only control transaction
public:
    /** Bank workload constructor.
     * @param library      Transactional library to use
     * @param nbaccounts   Number of accounts
     * @param init_balance Initial account balance
     * @param prob_long    Probability of running a long, read-only control transaction
    **/
    Bank(TransactionalLibrary const& library, size_t nbaccounts, int init_balance, float prob_long): Workload{library, sizeof(int), sizeof(int) * nbaccounts}, nbaccounts{nbaccounts}, init_balance{init_balance}, prob_long{prob_long} {
        do {
            auto tx = tm.begin();
            auto&& init_fn = [&]() {
                for (size_t i = 0; i < nbaccounts; ++i) {
                    if (unlikely(!tm.write(tx, &init_balance, sizeof(int), tm.address(i * sizeof(int)))))
                        return false;
                }
                return true;
            };
            if (unlikely(!init_fn()))
                continue;
            if (unlikely(!tm.end(tx)))
                continue;
            break;
        } while (false);
    }
private:
    /** Long transaction, summing the balance of each account.
     * @return Whether no inconsistency has been found
    **/
    bool long_check_tx() {
        do {
            auto valid = true;
            auto tx = tm.begin();
            int sum = 0;
            auto&& read_fn = [&]() {
                for (size_t i = 0; i < nbaccounts; ++i) {
                    int local;
                    if (unlikely(!tm.read(tx, tm.address(i * sizeof(int)), sizeof(int), &local)))
                        return false;
                    if (unlikely(local < 0))
                        valid = false;
                    sum += local;
                }
                return true;
            };
            if (unlikely(!read_fn()))
                continue;
            if (unlikely(!tm.end(tx)))
                continue;
            return valid && sum == init_balance * static_cast<int>(nbaccounts);
        } while (true);
    }
public:
    virtual Context prepare(Seed seed) {
        return ::std::make_unique<BankContext>(seed, prob_long, nbaccounts);
    }
    virtual bool run(Context& context) {
        auto&& ctx = static_cast<BankContext&>(*context);
        
        if (ctx.long_dist(ctx.engine)) { // Do a long transaction
            if (unlikely(!long_check_tx()))
                return false;
        } else { // Do a short transaction
            auto tx = tm.begin();
            auto acc_a = ctx.account(ctx.engine);
            auto acc_b = ctx.account(ctx.engine); // Of course, might be same as 'acc_a'
            int solde_a, solde_b;
            tm.read(tx, tm.address(acc_a * sizeof(int)), sizeof(int), &solde_a);
            tm.read(tx, tm.address(acc_b * sizeof(int)), sizeof(int), &solde_b);
            if (unlikely(solde_a < 0 || solde_b < 0)) { // Inconsistency!
                tm.end(tx);
                return false;
            }
            if (likely(solde_a > 0)) {
                if (acc_a != acc_b) {
                    --solde_a;
                    ++solde_b;
                }
                tm.write(tx, &solde_a, sizeof(int), tm.address(acc_a * sizeof(int)));
                tm.write(tx, &solde_b, sizeof(int), tm.address(acc_b * sizeof(int)));
            }
            tm.end(tx);
        }

        return true;
    }
    virtual bool check() {
        return long_check_tx();
    }
};

// NOTE: Code has not been modified below

// -------------------------------------------------------------------------- //

#define DEFAULT_DURATION                1000
#define DEFAULT_INITIAL                 1024
#define DEFAULT_NB_THREADS              1
#define DEFAULT_RANGE                   (2 * DEFAULT_INITIAL)
#define DEFAULT_UPDATE                  20

#if !defined(UNUSED)
#  define UNUSED __attribute__ ((unused))
#endif

static volatile int stop;

auto num_threads = []() {
    auto res = ::std::thread::hardware_concurrency();
    if (unlikely(res == 0))
        res = 16;
    return static_cast<size_t>(res);
}();
auto num_accounts = 4 * num_threads;
auto init_balance = 100;
auto prob_long    = 0.5f;
auto nbrepeats    = 11;
auto seed         = static_cast<Seed>(42);
size_t duration = DEFAULT_DURATION;


volatile ticks *tx_count;


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

  auto context = workload->prepare(seed);

  // barrier after initialization
  barrier_cross(&barrier);

  // barrier before actual measured run
  barrier_cross(&barrier_global);

  bool res;
  while (stop == 0) {
    res = workload->run(context);
    if (likely(res)) {
      my_tx_count++;
    } else {
      my_tx_count = UINT64_MAX;
      break;
    }
  }

  barrier_cross(&barrier);

  barrier_cross(&barrier);

  tx_count[ID] = my_tx_count;

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
  pthread_attr_t attr;
  int rc;
  void *status;

  barrier_init(&barrier_global, num_threads + 1);
  barrier_init(&barrier, num_threads);

  /* Initialize and set thread detached attribute */
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
  thread_data_t* tds = (thread_data_t*) malloc(num_threads * sizeof(thread_data_t));

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
  nanosleep(&timeout, NULL);
  stop = 1;

  gettimeofday(&end, NULL);
  duration = (end.tv_sec * 1000 + end.tv_usec / 1000) - (start.tv_sec * 1000 + start.tv_usec / 1000);

  for(t = 0; t < num_threads; t++) 
  {
    rc = pthread_join(threads[t], &status);
    if (rc) 
    {
      printf("ERROR; return code from pthread_join() is %d\n", rc);
      exit(-1);
    }
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
  printf("#txs %zu\t(%-10.0f\n", num_threads, throughput);
  printf("#Mops %.3f\n", throughput / 1e6);  

  return throughput;

}

void
eval(char const* path) {
  TransactionalLibrary tl{path};
  Bank bank{tl, num_accounts, init_balance, prob_long};

  double tputs[nbrepeats];
  for (int i = 0; i < nbrepeats; i++) {
    tputs[i] = measure(bank);
  }
  ::std::nth_element(tputs, tputs + (nbrepeats >> 1), tputs + nbrepeats); // Partial-sort times around the median
  printf("Performance of %s: %.2f tx/s (median of %u runs)\n", path,tputs[nbrepeats >> 1], nbrepeats);
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
  while(1) 
  {
    i = 0;
    c = getopt_long(argc, argv, "hAf:d:i:n:r:s:u:m:l:b:v:f:x:", long_options, &i);

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
      case '?':
      default:
      printf("Use -h or --help for help\n");
      exit(1);
    }
  }

  num_accounts = 4 * num_threads;



  /* Initializes the local data */
  tx_count = (ticks *) calloc(num_threads , sizeof(ticks));


  eval("../reference.so");



  return 0;
}