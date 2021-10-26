import sys
import getopt
import functools
import operator
import random

def usage(name):
    sys.stderr.write("Usage: %s [-h] [-v] [-d <int>] [-k <int>] [-i {0|1}*] [-a {1|2}] \n" % name)
    sys.stderr.write("  -h                Print this message\n")
    sys.stderr.write("  -v                Verbose output for each clock cycle\n")
    sys.stderr.write("  -s                Cache set size (spawn same number of spies)\n")
    sys.stderr.write("  -k                RSA key exponents, e.g. 011000110\n")
    sys.stderr.write("  -i                Iterations of RSA key detection\n")
    sys.stderr.write("  -a                Which attack to run. eg. 2\n")

class thread():
  
  def __init__(self, victim, id, total, cache):
    self.victim   = victim
    self.id       = id
    self.total    = total
    self.ready    = 0
    self.cnt      = 0
    self.spyHits  = []
    self.cache = cache
    
  def update_victim(self, useExp, waitTime, hit=False):
    self.ready += waitTime # time between reads, impacted by cache hit/miss?
    self.cnt += 1
    
  def update_spy(self, waitTime, hit):
    self.spyHits.append(hit)
    self.cnt += 1
    offset = 0
    if self.cnt == 1:
      offset = waitTime - self.id
    elif self.cnt % 2 == 1:
      offset = (waitTime + (self.total-self.id-1)) - (self.id)
    else:
      offset = (waitTime + self.id) - (self.total-self.id-1)
    self.ready +=  offset # spy update ? (reverse order) (account for misses)...

  def load(self, loc):
    return self.cache.load(loc)

class Cache:
  def __init__(self, associativity, tcount, upper_level):
    self.ass = associativity
    self.data = [-1]* associativity # set associativity of Cache (only care about a single set)
    self.full = False
    self.missCnt = [0]*tcount
    self.upper_level_cache = upper_level

  # If loc in Cache -> hit (True)
  # If loc not in Cache and Cache full -> miss (False) and use replacement policy
  def load(self, loc):
    hit_LLC = True
    if loc not in self.data: # Miss
      if self.upper_level_cache is not None:
        hit_LLC = self.upper_level_cache.load(loc)
      else:
        hit_LLC = False
      if not self.full: # Miss -> Not Full
        idx = self.data.index(-1)
        self.data[idx] = loc
        self.full = (idx+1) == len(self.data)
      else: # Miss -> Replacement Policy
        newLoc = self.evict(loc)
        self.data[newLoc] = loc
    return hit_LLC

  # Current setup assumes each thread only accesses one location in the set
  # so no need to check for other used locations within the set or inclusivity
  def evict(self, loc):
    # Select at random
    self.missCnt[loc] += 1 # Counter triggered by SHARP on random evict
    return random.randint(0,len(self.data)-1)
    
  def reset(self):
    self.data = [-1] * len(self.data)
    self.full = False
    
class Attack1():

  def __init__(self, tcount, setAssoc, origKey, verbose):
    self.tcount = tcount
    self.spies = []
    self.cache = Cache(setAssoc, tcount, None)
    for i in range(tcount-1): self.spies.append(thread(False,i,tcount-1, self.cache))
    self.victim = thread(True,tcount-1,1, self.cache)
    self.spyKeys = []
    self.origKey = origKey
    self.verbose = verbose
    self.victimT = tcount+1
    
  # Each spy has a list of hits and misses
  # Reconstruct partial key from those
  def combineSpies(self):
    combinedKey = []
    prevAll = True
    for i in range(1,len(self.origKey)+1):
      hits = [t.spyHits[i] for t in self.spies]
      out = -1
      cnt = 0
      for h in hits:
        if not h: cnt += 1
      if all(hits): out = 0
      elif prevAll and cnt > 0: out = 1
      elif i%2 == 0 and hits[0] == False: out = 1 # Last loaded spy now misses in next iteration (must have been displaced by victim (only access in between)
      elif i%2 == 1 and hits[-1] == False: out = 1
      prevAll = all(hits)
      combinedKey.append(out)
    
    self.spyKeys.append(combinedKey)
   
  # Each iteration spies produce a combined partial key
  # Reconstruct full key from those
  def combineKeys(self):
    fullKey = []
    kL = len(self.spyKeys)
    for i in range(len(self.origKey)):
      added = False
      for k in range(kL):
        if self.spyKeys[k][i] > -1 and not added:
          fullKey.append(self.spyKeys[k][i])
          added = True
        elif self.spyKeys[k][i] > -1:
          if self.spyKeys[k][i] != fullKey[-1]: print("e conflict in keys")
      if not added: fullKey.append(-1)
    
    return fullKey
   
  def resetThreads(self):
    self.victim.cnt = 0
    self.victim.ready = 0
    for s in self.spies:
      s.cnt = 0
      s.spyHits = []
      s.ready = 0
  
  def runSimulation(self, rsaIter):
    for i in range(rsaIter): # Each iteration victim uses full RSA key
      c = 0 # clock counter
      while True: # run until full RSA key used
        if self.verbose: print("Clock "+str(c))
        for t in self.spies: # Spies first to fill up the cache
          if t.ready == c:
            hit = t.load(t.id) # Spy loads its own data
            if self.verbose: print("SPY "+str(t.id)+" Hit: "+str(hit))
            t.update_spy(self.victimT,hit)
        if self.victim.ready == c:
          if self.victim.cnt == len(self.origKey): break
          if (self.origKey[self.victim.cnt] == 1): # Victim loads exponent code
            hit = self.victim.load(self.victim.id)
            self.victim.update_victim(True, self.victimT, hit)
            if self.verbose: print("Victim exp "+" Hit: "+str(hit))
          else:
            self.victim.update_victim(False, self.victimT)
            if self.verbose: print("Victim Noexp")
        c += 1 # next clock
      self.combineSpies() # Combine the information from the spies
      print("Key at iteration "+str(i) + " " + str(self.spyKeys[-1]))
      self.resetThreads()
      self.cache.reset()

    leaked_key = self.combineKeys() # Combine partial keys found in each iteration
    cnt = 0
    for i in range(len(leaked_key)):
      if leaked_key[i] == -1: cnt += 1
      elif leaked_key[i] != self.origKey[i]: print("e mismatched key")

    print("Spied Key " + str(leaked_key))
    print("Origi Key " + str(self.origKey))
    print("Number missed: "+str(cnt))


class Attack2:
  def __init__(self, tcount, setAssoc, origKey, verbose):
    L3Cache = Cache(setAssoc, tcount, None)
    L2Cache_1 = Cache(4, tcount, L3Cache)
    L2Cache_2 = Cache(4, tcount, L3Cache)
    self.origKey = origKey
    self.verbose = verbose
    self.tcount = tcount
    self.victim = thread(True, 0, tcount-1, L2Cache_1)
    self.spy1 = thread(False, 1, tcount-1, L2Cache_1)
    self.spy2 = thread(False, 2, tcount-1, L2Cache_2)

  def runSimulation(self, iters):
    raise NotImplementedError("TODO")

def run(name, args):
    
    rsa = [0,1,0,1,0,1]
    iters = 5
    Csize = 4
    verbose = False
    atk = 1
    
    optlist, args = getopt.getopt(args, "vhs:i:k:a:")
    for (opt, val) in optlist:
        if opt == '-h':
          usage(name)
          return
        elif opt == '-s':
          Csize = int(val)
        elif opt == '-k':
          rsa = [int(e) for e in val]
        elif opt == '-i':
          iters = int(val)
        elif opt == '-v':
          verbose = True
        elif opt == '-a':
          atk = int(val)
    
    random.seed(0)
    if atk == 1:
      sim = Attack1(Csize+1, Csize, rsa, verbose)
    else:
      sim = Attack2(Csize+1, Csize, rsa, verbose)
    sim.runSimulation(iters)
    
if __name__ == "__main__":
    run(sys.argv[0], sys.argv[1:])
