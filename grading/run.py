# coding: utf-8

import sys
import subprocess
import numpy
import re
import multiprocessing





args = sys.argv

# usage: run.py grading_binary reference target numrepetitions

binary = sys.argv[1]
reference = sys.argv[2]
target = sys.argv[3]
numrepetitions = int(sys.argv[4])

nbworkers = multiprocessing.cpu_count()
nbtxperwrk = int(100000 / nbworkers)
nbaccounts = 1024 * nbworkers
expnbaccounts = 1024 * nbworkers 
init_balance = 100
prob_long = 0.5
prob_alloc = 0.3


print(" #worker threads:     " , nbworkers);
print(" #TX per worker:      " , nbtxperwrk);
print(" Initial #accounts:   " , nbaccounts);
print(" Expected #accounts:  " , expnbaccounts)
print(" Initial balance:     " , init_balance);
print(" Long TX probability: " , prob_long);
print(" Allocation TX prob.: " , prob_alloc);
print(" Number of reps       " , numrepetitions);

args  = " -n" + str(nbworkers) 
args += " -x" + str(nbtxperwrk) 
args += " -a" + str(nbaccounts) 
args += " -b" + str(init_balance)
args += " -l" + str(prob_long)
args += " -p" + str(prob_alloc)

# reference
times = []
for rep in range(numrepetitions):
    output = subprocess.check_output(binary + args + " -t " + reference, shell=True).decode("utf-8")
    print(output)
    m = re.search("\((\d+)", output)
    times.append(int(m.group(1)))

ref_time = numpy.median(times)
print("Reference time: ", ref_time, "us")

# target
times = []
for rep in range(numrepetitions):
    output = subprocess.check_output(binary + args + " -t " + target, shell=True).decode("utf-8")
    print(output)
    m = re.search("\((\d+)", output)
    times.append(int(m.group(1)))

tar_time = numpy.median(times)
print("Target time: ", tar_time, "us")

perf_ratio = ref_time/tar_time
print ("Performance ratio: ", perf_ratio)