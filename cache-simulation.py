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
  
  def __init__(self, victim, id, total, cache, core_id):
    self.victim   = victim
    self.id       = id
    self.total    = total
    self.ready    = 0
    self.cnt      = 0
    self.spyHits  = []
    self.cache = cache
    self.core_id = core_id #Core in which this thread is running
    
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
    hit, evicted = self.cache.load(loc, self.core_id)
    return hit

class Cache:
  def __init__(self, associativity, tcount, upper_level):
    self.ass = associativity
    self.data = [-1] * associativity # set associativity of Cache (only care about a single set)
    self.owners = [-1] * associativity
    self.full = False
    self.alarm_count = [0]*tcount
    self.upper_level_cache = upper_level
    self.evict = self.evict_default

  def evict_selected(self, loc):
    '''
      Evict location <loc> and update the bit set of L3
    '''
    for idx in range(len(self.data)):
      if self.data[idx] == loc:
        self.data[idx] = -1
        self.owners[idx] = -1
        if self.upper_level_cache is not None:
          self.upper_level_cache.evict_selected(loc)
        self.full = False

  # If loc in Cache -> hit (True)
  # If loc not in Cache and Cache full -> miss (False) and use replacement policy
  def load(self, loc, core_id):
    hit_LLC = True
    evicted = None

    if loc not in self.data: # Miss
      if self.upper_level_cache is not None:
        hit_LLC, evicted = self.upper_level_cache.load(loc, core_id)
        if evicted is not None:
          for idx in range(len(self.data)):
            if self.data[idx] == evicted:
              self.data[idx] = -1
              self.owners[idx] = -1
      else:
        hit_LLC = False
      if not self.full: # Miss -> Not Full
        idx = self.data.index(-1)
        self.data[idx] = loc
        self.owners[idx] = core_id
        self.full = all(map(lambda x: x != -1, self.data))
      else: # Miss -> Replacement Policy
        newLoc = self.evict(loc, core_id)

        #Enforce inclusivity
        evicted = self.data[newLoc]

        self.data[newLoc] = loc
        self.owners[newLoc] = core_id
    return hit_LLC, evicted

  def evict_default(self, loc, core_id):
    '''
    For setups where we assume each thread only accesses one location in the set
    # so no need to check for other used locations within the set
    '''
    to_evict = random.randint(0,len(self.data)-1)
    return to_evict
    
  def evict_sharp(self, loc, core_id):
    # Select at random
    for idx in range(len(self.data)):
      if self.owners[idx] == core_id:
        return idx
    
    self.alarm_count[core_id] += 1 # Counter triggered by SHARP on random evict
    return random.randint(0,len(self.data)-1)
    
  def reset(self):
    self.data = [-1] * len(self.data)
    self.full = False
    
class Attack1():

  def __init__(self, tcount, setAssoc, origKey, verbose):
    self.tcount = tcount
    self.spies = []
    self.cache = Cache(setAssoc, tcount, None)
    self.cache.evict = self.cache.evict_sharp

    for i in range(tcount-1): self.spies.append(thread(False,i,tcount-1, self.cache, i))
    self.victim = thread(True,tcount-1,1, self.cache, tcount-1)
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
    self.L3Cache = Cache(setAssoc, tcount, None)
    self.L3Cache.evict = self.L3Cache.evict_sharp
    self.L2Cache_1 = Cache(4, tcount, self.L3Cache)
    self.L2Cache_2 = Cache(4, tcount, self.L3Cache)
    self.origKey = origKey
    self.verbose = verbose
    self.tcount = tcount
    self.ass = setAssoc
    self.victim = thread(True, 0, tcount-1, self.L2Cache_1, 0)
    self.spy1 = thread(False, 1, tcount-1, self.L2Cache_1, 0)
    self.spy2 = thread(False, 2, tcount-1, self.L2Cache_2, 1)
    self.spy2_leaked = [] #Leaked key

    self.spy2.ready = 0 #First to go, take ownership of all lines
    self.victim.ready = 1 #Then, victim takes control of 1 line
    self.spy1.ready = 2 #Then, spi1 evicts that block
    self.victimT = 3

  def process_leak(self):
    ''' Use spy2 measurements to compute the key '''
    return self.spy2_leaked

  def resetThreads(self):
    self.victim.cnt = 0
    self.victim.ready = 0
    for s in (self.spy1, self.spy2):
      s.cnt = 0
      s.spyHits = []
      s.ready = 0

  def runSimulation(self, iters):
    iters = 1 #Always need a single iteration only
    victim_addr = 0x4001337 #Just a random address
    for i in range(iters):
      self.spy2_leaked = []
      c = -1
      while 1:
        c = c + 1
        if self.verbose: 
          print("Clock "+str(c))
          print(self.L3Cache.data)
          print(self.L3Cache.owners)

        if self.spy1.ready == c:
          #Evict the same block as the victim
          self.L2Cache_1.evict_selected(victim_addr)
          self.spy1.ready += 3
        if self.spy2.ready == c:
          misses = 0
          miss = []

          #Reset so we always miss our L2 cache. 
            #This can be done IRL by accessing another group of lines that map to the same set in the L3
          self.L2Cache_2.reset() 

          #Take ownership of all lines in the set
          for line in range(self.ass):
            hit = self.spy2.load(line)
            if not hit:
              misses += 1
              miss.append(line)
          if misses == 1:
            if self.verbose: print("Spy2: I think exp is 1", miss, len(self.spy2_leaked))
            self.spy2_leaked.append(1)
          elif misses == 0:
            if self.verbose: print("Spy2: I think exp is 0", miss, len(self.spy2_leaked))
            self.spy2_leaked.append(0)
          else:
            if self.verbose: print("Spy2: #Misses:", misses, miss, len(self.spy2_leaked))
          self.spy2.ready += 3

        if self.victim.ready == c:
          # Same behaviour as the previous attack
          if self.victim.cnt == len(self.origKey): break
          if (self.origKey[self.victim.cnt] == 1): # Victim loads exponent code
            hit = self.victim.load(victim_addr)
            #self.victim.update_victim(True, self.victimT, hit)
            if self.verbose: print("Victim exp "+" Hit: "+str(hit))
          else:
            #self.victim.update_victim(False, self.victimT)
            if self.verbose: print("Victim Noexp")
          self.victim.ready += 3
          self.victim.cnt +=  1

      self.L2Cache_1.reset()
      self.L2Cache_2.reset()
      self.L3Cache.reset()
      self.resetThreads()

    leaked_key = self.process_leak() # Combine partial keys found in each iteration
    cnt = 0
    for i in range(len(leaked_key)):
      if i >= len(self.origKey):
        if self.verbose: print("Too many leaked bits")
        break
      if leaked_key[i] == -1: cnt += 1
      else: assert leaked_key[i] == self.origKey[i], f"e mismatched key at bit: {i}"

    print("Spied Key " + str(leaked_key))
    print("Origi Key " + str(self.origKey))
    print("Number missed: "+str(cnt))


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
