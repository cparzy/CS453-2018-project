# Project of the course CS-453

Your goal is to implement a Software Transactional Memory (STM).

The *real* goal is of course to get you a hands-on experience with actual concurrent programming.


## What prior knowledge do I need?

Only basic C or C++ knowledge.

How to use the atomic libraries and the memory models of C11 and C++11 will be taught in the weekly project sessions.

### Useful resources

* [C/C++ reference](https://en.cppreference.com/w/)

  * [C11 atomic](https://en.cppreference.com/w/c/atomic)

  * [C++11 atomic](https://en.cppreference.com/w/cpp/atomic)

* [Preshing on Programming](http://preshing.com/archives/) - Stellar resources and facts about concurrent programming


## What is a STM?

* [This course](http://lpd.epfl.ch/site/education/ca_2018).

* The Art of Multiprocessor Programming - Chapter 18.

### Some implementations out there

* [TinySTM](http://www.tmware.org/tinystm.html)

* [LibLTX](https://sourceforge.net/projects/libltx)

* [stmmap](https://github.com/skaphan/stmmap)

You may read and inspire from existing STM libraries, but it must be **your own code** that carries out transactions.


## Grading

* *Correctness* is a must.

   Each transaction must *appear atomic*. No correctness = no passing grade (for the project only).

* *Throughput* is to go from a passing grade to the maximum grade.

   Comparison of your implementation to the reference one. Metric: #transaction *commits* per second.

### Evaluation machine

*Precise specification to come.*


## How to write my own STM?

1. Clone/download this repository.

2. Make a local copy of/rename the `template` directory with your SCIPER number (e.g. `$cp -r template 123456`).

3. Complete or completely rewrite (your copy of) the template with **your own code**.

   1. Complete/rewrite your code; only the interface should be kept identical.

   2. Compile and test locally with: `path/to/directory/grading$ make build-libs run`.

   3. Possibly send your code to the TA for testing on the *evaluation machine*.

   4. Repeat any of the previous steps until you are satisfied with correctness and performance.

### List of functions to implement

First iteration:

* `shared_t tm_create(size_t, size_t)`

* `void tm_destroy(shared_t)`

* `void* tm_start(shared_t)`

* `size_t tm_size(shared_t)`

* `size_t tm_align(shared_t)`

* `tx_t tm_begin(shared_t)`

* `bool tm_end(shared_t, tx_t)`

* `bool tm_read(shared_t, tx_t, void const*, size_t, void*)`

* `bool tm_write(shared_t, tx_t, void const*, size_t, void*)`

Second iteration (which adds memory (de)allocation):

* `bool tm_alloc(shared_t, tx_t, size_t, void**)`

* `bool tm_free(shared_t, tx_t, void*)`
