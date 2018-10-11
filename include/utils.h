#ifndef _UTILS_H_INCLUDED_
#define _UTILS_H_INCLUDED_
//some utility functions
//#define USE_MUTEX_LOCKS
//#define ADD_PADDING
/* #define OPTERON */
/* #define OPTERON_OPTIMIZE */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sched.h>
#include <inttypes.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef __sparc__
#  include <sys/types.h>
#  include <sys/processor.h>
#  include <sys/procset.h>
#elif defined(__tile__)
#  include <arch/atomic.h>
#  include <arch/cycle.h>
#  include <tmc/cpus.h>
#  include <tmc/task.h>
#  include <tmc/spin.h>
#  include <sched.h>
#else
#  if defined(PLATFORM_MCORE)
#    include <numa.h>
#  endif
#  if defined(__SSE__)
#    include <xmmintrin.h>
#  else
#    define _mm_pause() __asm__ volatile ("nop")
#  endif
#  if defined(__SSE2__)
#    include <emmintrin.h>
#  endif
#endif
#include <pthread.h>
#include "getticks.h"
#include "random.h"
#include "measurements.h"
#include "ssalloc.h"
#include "atomic_ops_if.h"

#ifdef __cplusplus
extern "C" {
#endif


#define DO_ALIGN
  /* #define DO_PAD */


#if !defined(false)
#  define false 0
#endif

#if !defined(true)
#  define true 1
#endif

#define likely(x)       __builtin_expect((x), 1)
#define unlikely(x)     __builtin_expect((x), 0)


#if !defined(UNUSED)
#  define UNUSED __attribute__ ((unused))
#endif

#if defined(DO_ALIGN)
#  define ALIGNED(N) __attribute__ ((aligned (N)))
#else
#  define ALIGNED(N)
#endif

#if !defined(COMPILER_BARRIER)
#  define COMPILER_BARRIER() __asm__ volatile ("" ::: "memory")
#endif

#if !defined(COMPILER_NO_REORDER)
#  define COMPILER_NO_REORDER(exec)		\
  COMPILER_BARRIER();				\
  exec;						\
  COMPILER_BARRIER()
#endif

  static inline int
  is_power_of_two (unsigned int x) 
  {
    return ((x != 0) && !(x & (x - 1)));
  }





#  define PAUSE _mm_pause()

  static inline void
  pause_rep(uint32_t num_reps)
  {
    volatile uint32_t i;
    for (i = 0; i < num_reps; i++)
      {
	PAUSE;
	/* PAUSE; */
	/* __asm__ volatile ("NOP"); */
      }
  }

  static inline void
  nop_rep(uint32_t num_reps)
  {
    uint32_t i;
    for (i = 0; i < num_reps; i++)
      {
	__asm__ volatile ("");
      }
  }

  /* PLATFORM specific -------------------------------------------------------------------- */
#if !defined(PREFETCHW)
#  if defined(__x86_64__)
#    define PREFETCHW(x)		     __asm__ volatile("prefetchw %0" :: "m" (*(unsigned long *)x))
#  elif defined(__sparc__)
#    define PREFETCHW(x)		
#  elif defined(XEON)
#    define PREFETCHW(x)		
#  else
#    define PREFETCHW(x)		
#  endif
#endif 

#if !defined(PREFETCH)
#  if defined(__x86_64__)
#    define PREFETCH(x)		     __asm__ volatile("prefetch %0" :: "m" (*(unsigned long *)x))
#  elif defined(__sparc__)
#    define PREFETCH(x)		
#  elif defined(XEON)
#    define PREFETCH(x)		
#  else
#    define PREFETCH(x)		
#  endif
#endif 


  //debugging functions
#ifdef DEBUG
#  define DPRINT(args...) fprintf(stderr,args);
#  define DDPRINT(fmt, args...) printf("%s:%s:%d: "fmt, __FILE__, __FUNCTION__, __LINE__, args)
#else
#  define DPRINT(...)
#  define DDPRINT(fmt, ...)
#endif



  static inline double wtime(void)
  {
    struct timeval t;
    gettimeofday(&t,NULL);
    return (double)t.tv_sec + ((double)t.tv_usec)/1000000.0;
  }




  static inline void cdelay(ticks cycles){
    if (unlikely(cycles == 0))
      {
	return;
      }
    ticks __ts_end = getticks() + (ticks) cycles;
    while (getticks() < __ts_end);
  }

  static inline void cpause(ticks cycles){
#if defined(XEON)
    cycles >>= 3;
    ticks i;
    for (i=0;i<cycles;i++) {
      _mm_pause();
    }
#else
    ticks i;
    for (i=0;i<cycles;i++) {
      __asm__ __volatile__("nop");
    }
#endif
  }

  static inline void udelay(unsigned int micros)
  {
    double __ts_end = wtime() + ((double) micros / 1000000);
    while (wtime() < __ts_end);
  }

  //getticks needs to have a correction because the call itself takes a
  //significant number of cycles and skewes the measurement
  extern ticks getticks_correction_calc();

  static inline ticks get_noop_duration() {
#define NOOP_CALC_REPS 1000000
    ticks noop_dur = 0;
    uint32_t i;
    ticks corr = getticks_correction_calc();
    ticks start;
    ticks end;
    start = getticks();
    for (i=0;i<NOOP_CALC_REPS;i++) {
      __asm__ __volatile__("nop");
    }
    end = getticks();
    noop_dur = (ticks)((end-start-corr)/(double)NOOP_CALC_REPS);
    return noop_dur;
  }

  /// Round up to next higher power of 2 (return x if it's already a power
  /// of 2) for 32-bit numbers
  static inline uint32_t pow2roundup (uint32_t x){
    if (x==0) return 1;
    --x;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    return x+1;
  }

  static const size_t pause_fixed = 16384;

  static inline void
  do_pause()
  {
    cpause((mrand(seeds) % pause_fixed));
  }


  static const size_t pause_max   = 16384;
  static const size_t pause_base  = 512;
  static const size_t pause_min   = 512;

  static inline void
  do_pause_exp(size_t nf)
  {
    if (unlikely(nf > 32))
      {
	nf = 32;
      }
    const size_t p = (pause_base << nf);
    const size_t pm = (p > pause_max) ? pause_max : p;
    const size_t tp = pause_min + (mrand(seeds) % pm);
    cdelay(tp);
  }

#define DO_PAUSE_TYPE         1       // 0: fixed max pause
                                      // 1: exponentially increasing pause


#if DO_PAUSE_TYPE == 0
#define DO_PAUSE()            do_pause()
#define NUM_RETRIES()        
#elif DO_PAUSE_TYPE == 1
#define DO_PAUSE()            do_pause_exp(__nr++);
#define NUM_RETRIES()         UNUSED size_t __nr;
#else

#endif


#ifdef __cplusplus
}

#endif


#endif
