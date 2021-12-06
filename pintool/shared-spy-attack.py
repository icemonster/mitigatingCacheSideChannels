import subprocess
import os
import re

results = {}

def parse_out(out):
    lines = out.split(b'\n')
    d = None
    leakedKey = None
    for line in lines:
        if line.startswith(b'd = '):
            d = line.split(b'd = ')[1]
        elif line.startswith(b'Key: '):
            leakedKey = line.split(b'Key: ')[1]
    assert d is not None, out
    assert leakedKey is not None, out
    size = len(d)
    return d, leakedKey[-size:].zfill(size)

def save_results(d, leaked, noise):
    #d = real key
    #leaked = leaked key
    results[noise] = (d, leaked)
    #Experiments take some time. We save intermediate results in case something happens
    with open('results.txt', 'w') as f:
        f.write(str(results))

#Compile
os.system('make obj-intel64/pin_sharp_cache.so')

#Waittime = 0.  Cache noise is personalized
RUN_CMD = ['pin', '-t', 'obj-intel64/pin_sharp_cache.so', 'ifeellucky', '0x4014e3', '0x4016dc', '0', 'CACHENOISE', '--',  './rsa']

for noise in range(1,100, 2):
    print("Running for noise =", noise)
    RUN_CMD[7] = str(noise) #Change cache noise argument to specified value

    out = subprocess.check_output(RUN_CMD)
    d, leaked = parse_out(out)
    save_results(d, leaked, noise)
