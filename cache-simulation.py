import sys
import getopt
import functools
import operator
import random

def usage(name):
    sys.stderr.write("Usage: %s [-h] " % name)
    sys.stderr.write("  -h                Print this message\n")


class thread():
  
  def __init__(self, victim, id, total):
    self.victim   = victim
    self.id       = id
    self.total    = total
    self.ready    = 0
    self.cnt      = 0
    self.spyHits  = []
    
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
      offset = 2*waitTime - 2*(self.id+1)
    else:
      offset = 2*waitTime - 2*(self.total-self.id)
    self.ready +=  offset # spy update ? (reverse order) (account for misses)...

class Simulator():
  
  L3       = None
  L3Full   = None
  missCnt  = None
  spies    = None
  victim   = None
  tcount   = None
  spyKeys  = None
  fullKey  = None
  origKey  = None
  victimT  = 5
  
  def __init__(self, tcount, setAssoc, origKey):
    self.tcount = tcount
    self.spies = []
    for i in range(tcount-1): self.spies.append(thread(False,i,tcount-1))
    self.victim = thread(True,tcount-1,1)
    self.L3 = [-1] * setAssoc # set associaty of L3 (only care about a single set)
    self.L3Full = False
    self.missCnt = [0] * tcount
    self.spyKeys = []
    self.origKey = origKey
    
  # Each spy has a list of hits and misses
  # Reconstruct partial key from those
  def combineSpies(self):
    combinedKey = []
    prevAll = True
    for i in range(1,len(self.origKey)+1):
      hits = [t.spyHits[i] for t in self.spies]
      out = -1
      if all(hits): out = 0
      elif prevAll and i%2 == 0 and hits[0] == True: out = 1
      elif prevAll and i%2 == 1 and hits[-1] == True: out = 1
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
    
    self.fullKey = fullKey
   
  # Current setup assumes each thread only accesses one location in the set
  # so no need to check for other used locations within the set or inclusivity
  def evict(self):
    # Select at random
    return random.randint(0,len(self.L3)-1)
   
  # If loc in L3 -> hit (True)
  # If loc not in L3 and L3 full -> miss (False) and use replacement policy
  def load(self, loc):
    if loc in self.L3: # Hit
      return True
    elif not self.L3Full: # Miss -> Not Full
      cnt = 0
      while self.L3[cnt] > -1: cnt += 1
      self.L3[cnt] = loc
      if (cnt+1) == len(self.L3): self.L3Full = True
      return False
    else: # Miss -> Replacement Policy
      newLoc = self.evict()
      self.L3[newLoc] = loc
      self.missCnt[loc] += 1 # Counter triggered by SHARP on random evict
      return False
    
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
        print("Clock "+str(c))
        for t in self.spies: # Spies first to fill up the cache
          if t.ready == c:
            hit = self.load(t.id) # Spy loads its own data
            print("SPY "+str(t.id)+" Hit: "+str(hit))
            t.update_spy(self.victimT,hit)
        if self.victim.ready == c:
          if self.victim.cnt == len(self.origKey): break
          if (self.origKey[self.victim.cnt] == 1): # Victim loads exponent code
            hit = self.load(self.victim.id)
            self.victim.update_victim(True, self.victimT, hit)
            print("Victim exp "+" Hit: "+str(hit))
          else:
            self.victim.update_victim(False, self.victimT)
            print("Victim Noexp")
        c += 1 # next clock
      self.combineSpies() # Combine the information from the spies
      print("Key at iteration "+str(i) + " " + str(self.spyKeys[-1]))
      self.resetThreads()
      self.L3Full = False
      self.L3 = [-1] * len(self.L3)
    self.combineKeys() # Combine partial keys found in each iteration
    print("Spied Key " + str(self.fullKey))
    print("Origi Key " + str(self.origKey))
    


def run(name, args):
    
    optlist, args = getopt.getopt(args, "h")
    for (opt, val) in optlist:
        if opt == '-h':
          usage(name)
          return
    sim = Simulator(5,4,[0,1,0,1,0,1])
    sim.runSimulation(5)
    
if __name__ == "__main__":
    run(sys.argv[0], sys.argv[1:])
