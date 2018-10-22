import sys
import subprocess
import numpy
import re

args = sys.argv

# usage: run.py reference target numrepetitions

reference = sys.argv[1]
target = sys.argv[2]
numrepetitions = int(sys.argv[3])

# reference
times = []
for rep in range(numrepetitions):
    output = subprocess.check_output("./grading -t " + reference, shell=True).decode("utf-8")
    print(output)
    m = re.search("\((\d+)", output)
    times.append(int(m.group(1)))

ref_time = numpy.median(times)
print("Reference time: ", ref_time)

# target
times = []
for rep in range(numrepetitions):
    output = subprocess.check_output("./grading -t " + target, shell=True).decode("utf-8")
    print(output)
    m = re.search("\((\d+)", output)
    times.append(int(m.group(1)))

tar_time = numpy.median(times)
print("Target time: ", tar_time)

perf_ratio = ref_time/tar_time
print ("Performance ratio: ", perf_ratio)