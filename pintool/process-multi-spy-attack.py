import sys
import getopt

def trim(s):
    while len(s) > 0 and s[-1] in '\r\n':
        s = s[:-1]
    return s
    
def process(fname, count):

  original_key = "10001010010001000001110010000011001000110010110010000100101110001100010101100101011111100010001100011100001111111110010110110011011000110010100111011011101011101001100010010110101011010011000000010000000011101000001011000101011111101011111110100010100111011000011011110001010100100000111100110100010101010011110101000100111001010101111111100111000100011100110000101110011100001010010001000000011101001001010010100011011101111010110101001001111111100001010100001110000000101110100110111000110001100100101000011100011011111110000100010010111000000111011000110001010110000111011101100110100111010011000011001000011011110000101001010110010001010110011110000111101101011101011101000110000100000011011100010101111101010010001010001001001010001001111111110100101100111001000010101100011010111001111110001110000110100100101000111011011100101010000010011100100010101110011010110000111001011111110111100101000100000000010111111000010101110001100100100010000010111100111100001111111010100001111100110010100010111111011011111100001"
  original_key.split()
  file = open(fname, 'r')
  full_key = []
  unks=0
  first = True
  for line in file:
    line = trim(line)
    if len(line) == 0: continue
    tokens = line.split()
    if tokens[0] == "Combined":
      # Read next partial key
      i = 0
      for b in tokens[2]:
        if not first and i >= len (full_key): continue
        if b == '?':
          if first:
            unks+=1
            full_key += ['?']
        elif b == '0':
          if first:
            full_key += ['0']
          else:
            if full_key[i] == '?':
              full_key[i] = '0'
              unks -= 1
            elif full_key[i] == '1':
              
              print("Conflict at position "+str(i))
        elif b == '1':
          if first:
            full_key += ['1']
          else:
            if full_key[i] == '?':
              full_key[i] = '1'
              unks -= 1
            elif full_key[i] == '0':
              
              print("Conflict at position "+str(i))
        i+=1
      first = False
  dups = 0
  pos = 0
  i = 0
  es = 0
  hits = 0
  qs = 0
  while i < len(full_key):
    if full_key[i] == original_key[pos]:
      i += 1
      pos += 1
      hits += 1
    elif full_key[i] == '?':
      i += 1
      pos += 1
      qs += 1
    else:
      if pos > 0 and original_key[pos-1] == full_key[i]:
        dups += 1
        i += 1
      else:
        es += 1
        i += 1
        pos += 1
    if pos >= len(original_key):
      print("LONG "+str(len(full_key)-i))
      break
  print("Iteration "+str(count))
  #print(len(original_key))
  print("Hits: "+str(hits))
  print("Duplicats: "+str(dups))
  print("Errors: "+str(es))
  str1 =""
  print("Unknowns in combined full key: "+str(unks))
  print("Combined Full Key: "+str1.join(full_key))
  str2=""
  
  print("Original Key: "+str2.join(original_key))
      
def run(name, args):
  fname = None
  count = None
  optlist, args = getopt.getopt(args, "f:i:")
  for (opt, val) in optlist:
      if opt == '-f':
        fname = val
      elif opt == '-i':
        count = int(val)
        
  process(fname,count)

if __name__ == "__main__":
    run(sys.argv[0], sys.argv[1:])
