/**
 * @file   runner.cpp
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
 * Trivial program that call a function in several threads.
**/

// External headers
#include <iostream>
#include <thread>

// Internal headers
extern "C" {
#include <runner.h>
}

// ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――

/** Program entry point.
 * @param argc Arguments count
 * @param argv Arguments values
 * @return Program return code
**/
int main(int argc [[gnu::unused]], char** argv [[gnu::unused]]) {
    auto const nbworkers = []() {
        auto res = ::std::thread::hardware_concurrency();
        if (res == 0)
            res = 4;
        return static_cast<size_t>(res);
    }();
    ::std::thread threads[nbworkers];
    for (size_t i = 0; i < nbworkers; ++i) {
        threads[i] = ::std::thread{[=]() {
            entry_point(nbworkers, i);
        }};
    }
    for (auto&& thread: threads)
        thread.join();
    return 0;
}
