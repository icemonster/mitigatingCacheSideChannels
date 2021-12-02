#include <iostream>
#include <iterator>
#include <algorithm>
#include <vector>
#include <sstream>
#include <math.h>
#include <stdlib.h>
#include "pin.H"

#define LINE_SIZE 64

using namespace std;

typedef struct Way_Struct {
    bool valid;
    unsigned int lru;
    unsigned long tag;
} Way;

/* Adjust these values at will */
bool multi_spy; // attack 1
bool shared_l2; // attack 2
int spy_count;
int spy_probability;

class Cache {
    public:
        unsigned long accesses;
        unsigned long misses;
        unsigned int size;
        unsigned int line_size;
        unsigned int miss_penalty;
        unsigned int associativity;

        unsigned long tag_mask;
        unsigned long set_mask;
        unsigned long block_off_mask;

        unsigned long set_bits;
        unsigned long blk_bits;

        Way **sets;
    
        // J
        // SHARP data
        bool sharp;
        unsigned long * alarm_counter;
        int  ** owner;
        

        
        Cache(unsigned int s, unsigned int ls, unsigned int mp, unsigned int a, bool sp) {
            size = s;
            line_size = ls;
            miss_penalty = mp;
            associativity = a;
            accesses = 0;
            misses = 0;

            unsigned long set_number = size * 1024 / line_size / associativity;

            set_bits = ceil(log2(set_number));
            blk_bits = ceil(log2(line_size));
            // All powers of two, so its fine
            block_off_mask = exp2(blk_bits) - 1;
            set_mask = exp2(blk_bits + set_bits) - 1 - block_off_mask;
            tag_mask = 0xffffffffffffffff - block_off_mask - set_mask;

            sets = (Way **) malloc(sizeof(Way*)*set_number);

            for (unsigned long i = 0; i < set_number; i++){
                sets[i] = (Way*)malloc(sizeof(Way)*associativity);
                for (unsigned long j = 0; j < associativity; j++){
                    sets[i][j].valid = false;
                    sets[i][j].lru = 0;
                }
            }
            
            sharp = sp;
            alarm_counter = 0;
            
            owner = (int **) malloc (sizeof(int *) * set_number);
            
            for (unsigned long i = 0; i < set_number; i++){
                owner[i] = (int *) malloc(sizeof(int) * associativity);
                for (unsigned long j = 0; j < associativity; j++){
                    owner[i][j] = -1 ;
                }
            }
        }

        bool tags_equal(unsigned long addr, unsigned long tag){
            return (addr & tag_mask) == tag;
        }

        unsigned long get_set_index(unsigned long addr){
            return (addr & set_mask) >> blk_bits;
        }

        bool find_tag_in_set(unsigned long set, unsigned long addr){
            Way *ways = sets[set];

            unsigned int maximum = 0;
            for (unsigned long way = 0; way < associativity; way++){
                if (ways[way].lru > maximum){
                    maximum = ways[way].lru;
                }
            }

            for (unsigned long i = 0; i < associativity; i++){
                if (ways[i].valid && tags_equal(addr, ways[i].tag)){
                    ways[i].lru = maximum+1; /* Most recently used address, so lru is max LRU + 1 */
                    return false;
                }
            }

            return true;
        }

        void swap(unsigned long *lrus, unsigned long *ways, int index1, int index2){
            unsigned long temp1 = lrus[index1];
            unsigned long temp2 = ways[index1];
            lrus[index1] = lrus[index2];
            ways[index1] = ways[index2];
            lrus[index2] = temp1;
            ways[index2] = temp2;
        }

        void sort_lru_list(unsigned long *ways, unsigned long set){
            /* Sort ways in a set so that we can iterate them by LRU order */
            unsigned long lrus[associativity];

            for (unsigned long way = 0; way < associativity; way++){
                ways[way] = way;
                lrus[way] = sets[set][way].lru;
            }

            /* I mean, max associativity is not that high, we can do bubble sort */
            for(unsigned int i = 0; i < associativity-1; i++){
                for (unsigned j = 0; j < associativity - i - 1; j++){
                    if (lrus[j] > lrus[j+1]){
                        swap(lrus, ways, j, j+1);
                    }
                }
            }

        }

        void evict_lru_block(unsigned long set, unsigned long addr){
            Way *ways = sets[set];

            unsigned long ways_list[associativity];
            sort_lru_list(ways_list, set);

            unsigned int way = ways_list[0];
            ways[way].valid = true;
            ways[way].tag = addr & tag_mask;

            ways[way].lru = ways[ways_list[associativity-1]].lru + 1;
        }
    
        // J
        void evict_sharp_block (unsigned long set, unsigned long addr, int core) {
            Way *ways = sets[set];

            unsigned long ways_list[associativity];
            sort_lru_list(ways_list, set);
            unsigned long way;

            int candidate = -1;
            
            // STEP 1: check if a way is unused
            for (unsigned int i = 0; i < associativity; i++) {
                way = ways_list[i]; /* Access way in LRU order */
                if (owner[set][way] == -1) {
                    candidate = way;
                    break;
                }
            }

            if (candidate > -1) {
                ways[candidate].valid = true;
                ways[candidate].tag = addr & tag_mask;
                owner[set][candidate] = core;
                return;
            }
            
            // STEP 2: check if a way is owned by calling processor
            for (unsigned int i = 0; i < associativity; i++) {
                way = ways_list[i];
                if (owner[set][i] == core) {
                    candidate = i;
                    break;
                }
            }
            if (candidate > -1) {
                ways[candidate].valid = true;
                ways[candidate].tag = addr & tag_mask;
                owner[set][candidate] = core;
                return;
            }
            
            // STEP 3: evict something randomly
            candidate = rand() % associativity;
            ways[candidate].valid = true;
            ways[candidate].tag = addr & tag_mask;
            owner[set][candidate] = core;
            alarm_counter[core]++; // update alarm counter
            return;
  
        }

        bool access(unsigned long addr, bool is_load, int core){
            accesses++;
            
            unsigned long set = get_set_index(addr);


            bool is_miss = find_tag_in_set(set, addr);

            if (is_miss){
                misses++;
                
                if (sharp) evict_sharp_block (set, addr, core);
                else evict_lru_block(set, addr);
            }

            return is_miss;
        }

        bool store(unsigned long addr, int core){
            return access(addr, false, core);
        }
        bool load(unsigned long addr, int core){
            return access(addr, true, core);
        }

        void print_contents(){
            unsigned long set_number = size * 1024 / line_size / associativity;
            for (unsigned long set = 0; set < set_number; set++){
                for (unsigned int way = 0; way < associativity; way++){
                    if (sets[set][way].valid){
                        cout << "Set: " << set << " Way: " << way << " Tag: " << sets[set][way].tag << " (" << sets[set][way].lru << ")" << endl;
                    }
                }
            }
        }
};

BOOL data_cache_load(unsigned long addr, int core);

// J
class Spy {
public:
    
    int spy_id;
    int ready;
    int cnt;
    int wait_time;
    bool shared;
    vector<bool> hits;
    
    Spy (int id) {
        cnt = 0;
        ready = 0;
        wait_time = 30; //?
        spy_id = id;
        if (spy_id == 0 and shared_l2) shared = true;
        else shared = false;
    }
    
    void operate () {
        cnt += 1;
        if (cnt == 1) { // initial configuration
            if (shared) {} // attack 2
            else { // attack 1
                int offset = wait_time - spy_id;
                ready += offset;
            }
            return;
        }
        if (cnt == ready) { // wait time over
            if (shared) {} // attack 2
            else { // attack 1
                // call load and check if hit
                /*
                    TODO: Choose good address and core
                    TODO: How to check if it is a hit
                */
                bool hit = data_cache_load(0x0, 0);
                hits.push_back(hit);
                
                // update wait time
                //   currently fine-grained, i.e., 1 unit difference between spies
                int offset = 0;
                if (cnt%2==1) offset = (wait_time + (spy_count - spy_id - 1)) - spy_id;
                else offset = (wait_time + spy_id) - (spy_count - spy_id - 1);
                ready += offset;
            }
        }
    }
};

Cache *l2_cache;
Cache *l3_cache;
Spy ** spies;

VOID instr_cache_load(unsigned long ip) {
    /*
        TODO:   Pass the core argument correctly
    */
    bool miss;
    miss = l2_cache->load (ip, 0);
    if (miss) l3_cache->load (ip, 0);
}

BOOL data_cache_load(unsigned long addr, int core){
    bool miss;
    miss = l2_cache->load (addr, core);
    if (miss) l3_cache->load (addr, core);
    return miss;
}

VOID data_cache_store(unsigned long addr, int core){
    bool miss;
    miss = l2_cache->load (addr, core);
    if (miss) l3_cache->load (addr, core);
}

VOID spy_instruction(int spy){
    spies[spy]->operate();
}

VOID Instruction(INS ins, VOID *v)
{
    ADDRINT ip = INS_Address(ins);
    UINT32 memOperands = INS_MemoryOperandCount(ins);

    // All instructions cause a load in Icache
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)instr_cache_load, IARG_UINT64, ip, IARG_END);

    /* Service the first and second read first */
    for (UINT32 memOp = 0; memOp < memOperands; memOp++){
        if (INS_MemoryOperandIsRead(ins, memOp)){
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE,  (AFUNPTR) data_cache_load,
                IARG_MEMORYOP_EA, memOp,
                IARG_UINT64, 0,
                IARG_END);
        }
    }

    /* And then the write */
    for (UINT32 memOp = 0; memOp < memOperands; memOp++){
        if (INS_MemoryOperandIsWritten(ins, memOp)){
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE,  (AFUNPTR) data_cache_store,
                IARG_MEMORYOP_EA, memOp,
                IARG_UINT64, 0,
                IARG_END);
        }
    }
    
    
    // J - random values computed statically here
    for (int i = 0; i < spy_count; i++) {
        if (rand() % 100 <= spy_probability) { // chance of spy instruction
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE,  (AFUNPTR) spy_instruction,
                IARG_UINT64, i,
                IARG_END);
        }
    }
    
    
}

// J
void print_combined_key () {
    if (multi_spy) {
        // combine hits from spies
        vector<int> combined_key;
        bool prev_all = true;
        for (unsigned int i = 0; i < spies[0]->hits.size(); i++) {
            int cnt = 0;
            int out = -1;
            for (int s = 0; s < spy_count; s++) {
                if (spies[s]->hits[i]) cnt++;
            }
            // all hits means no exponent
            if (cnt == spy_count) out = 0;
            // previous all hits and now miss means exponent used
            else if (prev_all && cnt < spy_count) out = 1;
            // miss on last spy means exponent used
            else if (i%2==0 && !spies[0]->hits[i]) out = 1;
            else if (i%2==1 && !spies[spy_count-1]->hits[i]) out = 1;
            prev_all = (cnt == spy_count);
            combined_key.push_back (out);
        }
        cout << "Combined Key: ";
        for (unsigned int i = 0; i < combined_key.size(); i++) cout << combined_key[i] << " ";
        cout << endl;
    }
}

VOID Fini(INT32 code, VOID *v)
{
    print_combined_key();
}

INT32 Usage(){
    cerr << "Our cache simulator tool." << endl;
    cerr << "Usage: pin -t obj-intel64/pin_sharp_cache.so -- cache_test/MMM.out " << endl;
    return -1;
}


int main_test_caches(int argc, char **argv){
    /* Test new changes to Caches,
         considering associativity could be larger than 2, 
         and we now load from multiple caches
    */

    unsigned int assoc_l2 = 4;
    unsigned int assoc_l3 = 16;
    unsigned long set_number_l2 = 256 * 1024 / LINE_SIZE / assoc_l2;

    l2_cache = new Cache(256, LINE_SIZE, 100, assoc_l2, false);
    l3_cache = new Cache(12288, LINE_SIZE, 100, assoc_l3, true); // l3 uses SHARP
    
    //BOOL data_cache_load(unsigned long addr, int core);

    data_cache_load(0, 0);
    data_cache_load(LINE_SIZE*set_number_l2, 0);
    data_cache_load(LINE_SIZE*set_number_l2*2, 0);
    data_cache_load(LINE_SIZE*set_number_l2*3, 0);
    data_cache_load(LINE_SIZE*set_number_l2*4, 0);
    data_cache_load(LINE_SIZE*set_number_l2*5, 0);
    data_cache_load(LINE_SIZE*set_number_l2*6, 0);
    data_cache_load(LINE_SIZE*set_number_l2*7, 0);

    cout << "Loaded 4 colliding addresses" << endl;
    cout << "L2 cache" << endl; l2_cache->print_contents();
    cout << "L3 cache" << endl; l3_cache->print_contents();

    return 0;
}

int main(int argc, char **argv)
{
    spy_probability = 90; // chances a spy will insert an instruction
    
    // select attack
    multi_spy = true;
    shared_l2 = false;
    spy_count = 4;

    srand(0);
    
    /*if (argc < 11){
        return Usage();
    }*/

    PIN_Init(argc, argv);
    
    /* Parameters taken from a real i7 processor */
    l2_cache = new Cache(256, LINE_SIZE, 100, 4, false);
    l3_cache = new Cache(12288, LINE_SIZE, 100, 16, true); // l3 uses SHARP
    
    
    if (shared_l2) spy_count = 2;
    spies = (Spy**) malloc (sizeof (Spy *) * spy_count);
    if (shared_l2) {
        spies[0] = new Spy (0); // shares L2
        spies[1] = new Spy (1); // different core
    }
    else {
        for (int i = 0; i < spy_count; i++) {
            spies[i] = new Spy (i+1); // do not share core 0
        }
    }
    

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    return 0;
}

/* 
    Compile with:
        make obj-intel64/pin_sharp_cache.so
    Test with:
        pin -t obj-intel64/pin_sharp_cache.so -- ./rsa
*/
