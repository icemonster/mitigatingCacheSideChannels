#include <iostream>
#include <iterator>
#include <algorithm>
#include <vector>
#include <sstream>
#include <math.h>
#include <stdlib.h>
#include "pin.H"

#define LINE_SIZE 64
#define L2_ASSOC 4
#define L3_ASSOC 16

/* Assuming 1 cycle per instruction */
#define CPI 1

/*  SHARP, end of section 7.3, "Hence, we recommend to use SHARP4 and use a threshold of 2,000 alarm events in 1 billion cycles" */
#define SHARP_ALARM_TIME_THRESHOLD 1000000000
#define SHARP_ALARM_THRESHOLD 2000

using namespace std;

typedef struct Way_Struct {
    bool valid;
    unsigned int lru;
    unsigned long tag;
} Way;

typedef struct Cache_Answer {
    bool miss; /* Whether it was a miss */
    bool evicted; /* Whether a valid address was evicted */
    unsigned long evicted_addr; /* Which addr was evicted if so */
    unsigned int evicted_core; /* Core that the evicted addr belongs to. Only used for L3 evictions */
    unsigned long penalty; /* Time penalty. If it was a hit, hit time. Otherwise, Miss time */
} CacheAnswer;

/* Adjust these values at will */
bool multi_spy; // attack 1
bool shared_l2; // attack 2
int spy_count;
int spy_probability;

unsigned long number_cores = 0;
unsigned long timestamp = 0;

/* Pass these as argument. Spies will use them to evict the correct address */
long unsigned int square_addr;
long unsigned int multiply_addr;

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
            alarm_counter = (unsigned long*) malloc(sizeof(unsigned long)*number_cores);
            
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
            unsigned long lru_temp = lrus[index1];
            unsigned long way_temp = ways[index1];
            lrus[index1] = lrus[index2];
            lrus[index2] = lru_temp;
            ways[index1] = ways[index2];
            ways[index2] = way_temp;
        }

        void sort_lru_list(unsigned long *ways, unsigned long set){
            /* Sort ways in a set so that we can iterate them by LRU order */
            unsigned long lrus[associativity];

            for (unsigned long way = 0; way < associativity; way++){
                ways[way] = way;
                lrus[way] = sets[set][way].lru;
            }

            /* I mean, max associativity is not usually high, we can do bubble sort */
            for(unsigned int i = 0; i < associativity-1; i++){
                for (unsigned j = 0; j < associativity - i - 1; j++){
                    if (lrus[j] > lrus[j+1]){
                        swap(lrus, ways, j, j+1);
                    }
                }
            }

        }

        unsigned long reconstruct_addr(unsigned long tag, unsigned long set){
            return (set << blk_bits) + tag;
        }

        void evict_lru_block(CacheAnswer *result, unsigned long set, unsigned long addr){
            /* Usual eviction policy */
            Way *ways = sets[set];

            unsigned long ways_list[associativity];
            sort_lru_list(ways_list, set);

            /* Just get the way with the minimum LRU value */
            unsigned int way = ways_list[0];
            if (ways[way].valid == true){
                result->evicted = true;
                result->evicted_addr = reconstruct_addr(ways[way].tag, set);
                result->evicted_core = 0; // Not used
            }

            ways[way].valid = true;
            ways[way].tag = addr & tag_mask;

            /* Update LRU to be maximum LRU +1 */
            ways[way].lru = ways[ways_list[associativity-1]].lru + 1;
        }
    
        void evict_sharp_block (CacheAnswer *result, unsigned long set, unsigned long addr, int core) {
            /* Sharp's eviction policy */
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
                result->evicted = false;
                result->evicted_addr = 0;
                result->evicted_core = 0;
                ways[candidate].valid = true;
                ways[candidate].tag = addr & tag_mask;
                ways[candidate].lru = ways[ways_list[associativity-1]].lru + 1;
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
                if (ways[candidate].valid == true){
                    result->evicted = true;
                    result->evicted_addr = reconstruct_addr(ways[candidate].tag, set);
                    result->evicted_core = core;
                }
                ways[candidate].valid = true;
                ways[candidate].tag = addr & tag_mask;
                ways[candidate].lru = ways[ways_list[associativity-1]].lru + 1;
                owner[set][candidate] = core;
                return;
            }
            
            // STEP 3: evict something randomly
            candidate = rand() % associativity;
            if (ways[candidate].valid == true){
                result->evicted = true;
                result->evicted_addr = reconstruct_addr(ways[candidate].tag, set);
                result->evicted_core = owner[set][candidate];
            }
            ways[candidate].valid = true;
            ways[candidate].tag = addr & tag_mask;
            ways[candidate].lru = ways[ways_list[associativity-1]].lru + 1;
            owner[set][candidate] = core;
            alarm_counter[core]++; // Update alarm counter
            return;
  
        }

        void load(CacheAnswer *result, unsigned long addr, int core){
            /* Returns addr of entry evicted, or 0 if it was a hit */
            accesses++;
            
            unsigned long set = get_set_index(addr);

            bool is_miss = find_tag_in_set(set, addr);

            result->miss = is_miss;
            result->penalty = 1;
            result->evicted = false;
            result->evicted_addr = 0;
            result->evicted_core = 0;

            if (is_miss){
                result->penalty = miss_penalty;
                misses++;
                
                if (sharp) evict_sharp_block (result, set, addr, core);
                else evict_lru_block(result, set, addr);
            }
        }

        void print_contents(){
            /* Just a debug function. Dont mind me */
            unsigned long set_number = size * 1024 / line_size / associativity;
            for (unsigned long set = 0; set < set_number; set++){
                for (unsigned int way = 0; way < associativity; way++){
                    if (sets[set][way].valid){
                        if (sharp)
                            cout << "Set: " << set << " Way: " << way << " Tag: " << sets[set][way].tag << " (" << sets[set][way].lru << ")"  << "[" << owner[set][way] << "]" << endl;
                        else
                            cout << "Set: " << set << " Way: " << way << " Tag: " << sets[set][way].tag << " (" << sets[set][way].lru << ")" << endl;
                    }
                }
            }
        }
};

Cache *l2_cache;
Cache *l3_cache;

bool aligned_addr(unsigned long addr){
    return (addr & (LINE_SIZE-1)) != 0;
}
unsigned long load(unsigned long addr, int core){
    /* Function responsible for loading a block from a cache hierarchy
         and implementing snoopy protocol / invalidate */

    CacheAnswer l2_answer;
    CacheAnswer l3_answer;

    /* Addresses must be aligned to 16 bits */
    if (aligned_addr(addr)){
        addr = addr - (addr & (LINE_SIZE-1));
    }

    if (core == 0){
        /* Victim and Attacker0 have a different cache hierarchy for simplicity */
        l2_cache->load (&l2_answer, addr, core);
        if (l2_answer.miss){
            if (l2_answer.evicted){
                /* Update ownership in L3 */
                unsigned long addr = l2_answer.evicted_addr;
                unsigned long set = l3_cache->get_set_index(addr);
                Way *ways = l3_cache->sets[set];
                for (unsigned long way = 0; way < l3_cache->associativity; way++){
                    if (ways[way].valid && l3_cache->tags_equal(addr, ways[way].tag)){
                        l3_cache->owner[set][way] = -1;
                        break;
                    }
                }
            }
                
            l3_cache->load (&l3_answer, addr, core);
            if (l3_answer.evicted){
                if (l3_answer.evicted_core == 0){
                    /* Evict from L2 cache from the proper core
                            TODO: As soon as attackers start having an L2 as well, I also have to consider them
                    */

                    unsigned long addr = l3_answer.evicted_addr;
                    unsigned long set = l2_cache->get_set_index(addr);
                    Way *ways = l2_cache->sets[set];
                    for (unsigned long way = 0; way < l2_cache->associativity; way++){
                        if (ways[way].valid && l2_cache->tags_equal(addr, ways[way].tag)){
                            ways[way].valid = false;
                            break;
                        }
                    }
                }
            }
        }
    }
    else {
        /* TODO: Attackers access L3 cache directly for now */
        l3_cache->load(&l3_answer, addr, core);
        if (l3_answer.evicted){
            if (l3_answer.evicted_core == 0){
                /* Evict from L2 cache from the proper core
                        TODO: As soon as attackers start having an L2 as well, I also have to consider them
                */

                unsigned long addr = l3_answer.evicted_addr;
                unsigned long set = l2_cache->get_set_index(addr);
                Way *ways = l2_cache->sets[set];
                for (unsigned long way = 0; way < l2_cache->associativity; way++){
                    if (ways[way].valid && l2_cache->tags_equal(addr, ways[way].tag)){
                        ways[way].valid = false;
                        break;
                    }
                }
            }
        }
    }

    if (core == 0){
        if (l2_answer.miss){
            return l3_answer.penalty;
        }
        else{
            return l2_answer.penalty;
        }
    }
    else{
        return l3_answer.penalty;
    }
    
}

class Spy {
public:
    
    int spy_id;
    int ready;
    int cnt;
    int wait_time;
    vector<bool> hits;
    unsigned long set_number_l3;
    unsigned long set_number_l2;
    bool iteration_started;

    Spy (int id) {
        cnt = 0;
        ready = 0;
        wait_time = 30; //?
        spy_id = id; /* Also represents the core it is located in */
        set_number_l3 = l3_cache->size * 1024 / LINE_SIZE / l3_cache->associativity;
        set_number_l2 = l2_cache->size * 1024 / LINE_SIZE / l2_cache->associativity;
        iteration_started = false;
    }
    
    void operate () {
        
        /* Described as a state machine depending on the value of cnt */
        cnt += 1;
        if (cnt == 1) { // initial configuration
            if (shared_l2) {
                // attack 2
                if (spy_id == 0) /* First spy just waits */
                    ready += 1;
                else { /* Second spy can start filling an L3 cache */
                    /* Fill up square set */
                    for (unsigned int i = 1; i < L3_ASSOC+1; i++){
                        load(square_addr + LINE_SIZE*set_number_l3*i, spy_id);
                    }

                    /* Fill up multiply set. Waiting does not really matter, we can do this at startup  */
                    for (unsigned int i = 1; i < L3_ASSOC+1; i++){
                        load(multiply_addr + LINE_SIZE*set_number_l3*i, spy_id);
                    }
                    ready += 1000;

                }
            } 
            else { // attack 1
                int offset = wait_time - spy_id;
                ready += offset;
            }
            return;
        }
        if (cnt >= ready) { // wait time over
            if (shared_l2) {
                // attack 2
                if (spy_id == 0){
                    // Constantly evict square_addr and multiply_addr from L2 cache, but not from L3
                    for (unsigned int i = 1; i < L2_ASSOC+1; i++){
                        load(square_addr + LINE_SIZE*set_number_l2*i, spy_id);
                        load(multiply_addr + LINE_SIZE*set_number_l2*i, spy_id);
                    }
                    ready += 1;
                }
                else{
                    /* Check iteration start (square_addr), 
                        and when it finally starts, check if previous iteration has miss for multiply_addr */
                    unsigned long time_to_wait = 0;
                    if (iteration_started == false){
                        for (unsigned int i = 1; i < L3_ASSOC+1; i++){
                            time_to_wait = load(square_addr + LINE_SIZE*set_number_l3*i, spy_id);
                            if (time_to_wait >= 36){ // Cheating for now
                                iteration_started = true;
                                cout << "Leaked that iteration started " << endl;
                            }
                        }
                        ready += 1;
                    }
                    else{
                        bool exponent_is_1 = false;
                        for (unsigned int i = 1; i < L3_ASSOC+1; i++){
                            time_to_wait = load(multiply_addr + LINE_SIZE*set_number_l3*i, spy_id);
                            if (time_to_wait >= 36){ // Cheating for now
                                exponent_is_1 = true;
                            }
                        }
                        cout << "Leaked that exponent is " << exponent_is_1 << endl;
                        hits.push_back(exponent_is_1);
                        iteration_started = false;
                        ready += 100;
                    }
                }
            } 
            else { // attack 1
                // call load and check if hit
                /*
                    TODO: Choose good address
                    TODO: How to check if it is a hit
                */
                unsigned time_to_wait = load(LINE_SIZE*set_number_l3*spy_id, spy_id);
                ready += time_to_wait;
                hits.push_back(true); /* TODO - Update algorithm accordingly. We no longer have a <hit> or <miss> indicator */
                
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

Spy ** spies;

VOID instr_cache_load(unsigned long ip) {
    /*
        Only the victim causes instruction loads for simplicity
            And it is assumed to be always located on core 0
    */

    /* TESTING function addresses    */
    if (ip == square_addr){
        cout << "square" << endl;
    }
    else if(ip == multiply_addr){
        cout << "multiply" << endl;
    }
    /* ------------------------------ */

    timestamp += CPI; /* Time increases as victim executes instructions */
    if (timestamp == SHARP_ALARM_TIME_THRESHOLD){
        /* Check if any of the alarms surpasses the defined threshold. Otherwise, reset them all */
        for (unsigned int i = 0; i < number_cores; i++){
            if (l3_cache->alarm_counter[i] > SHARP_ALARM_THRESHOLD){
                cout << "!!!!!!! WARNING !!!!!!! You have triggered the alarm for core " << i << endl;
            }
            l3_cache->alarm_counter[i] = 0;
        }
        
    }

    load(ip, 0);
}

VOID data_cache_load(unsigned long addr, int core){
    load(addr, core);
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
                ins, IPOINT_BEFORE,  (AFUNPTR) data_cache_load,
                IARG_MEMORYOP_EA, memOp,
                IARG_UINT64, 0,
                IARG_END);
        }
    }
    
    
    /* 
        Random values computed statically here. 
            Faster than dynamically call rand every victim instruction
            Still introduces a significant amount of noise
    */
    for (int i = 0; i < spy_count; i++) {
        if (rand() % 100 <= spy_probability) { // chance of spy instruction
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE,  (AFUNPTR) spy_instruction,
                IARG_UINT64, i,
                IARG_END);
        }
    }
    
    
}

void print_combined_key () {
    /* Computing the private key using information gathered 
        by all the spies AFTER the victim finishes executing.
            We do not need communication between spies during execution */

    cout << "Computing combined key..." << endl;
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
        for (unsigned int i = 0; i < combined_key.size(); i++) cout << combined_key[i];
        cout << endl;
    }
    else{
        cout << "Key: ";
        for (unsigned int i = 4; i < spies[1]->hits.size(); i+= 2){
            if (spies[1]->hits[i] && !spies[1]->hits[i+1])
                cout << "1";
            else
                cout << "0";
        }
        cout << "1" << endl;
    }
}

VOID Fini(INT32 code, VOID *v)
{
    cout << "Overall stats: " << endl;
    cout << "Timestamp:" << timestamp << endl;
    for (unsigned int i = 0; i < number_cores; i++){
        printf("Alarm for core %d: %ld\n", i, l3_cache->alarm_counter[i]);
    }

    cout << "L3 overall misses: " << l3_cache->misses << " and accesses: " << l3_cache->accesses << endl;

    print_combined_key();
}

INT32 Usage(){
    cerr << "Our cache simulator tool." << endl;
    cerr << "Usage: pin -t obj-intel64/pin_sharp_cache.so <square_addr> <multiply_addr> -- ./rsa " << endl;
    return -1;
}

void test_second_atk_simplified(){
    /* Test technique used in our second attack. */
    unsigned long set_number_l2 = 256 * 1024 / LINE_SIZE / L2_ASSOC;
    unsigned long set_number_l3 = 16384 * 1024 / LINE_SIZE / L3_ASSOC;

    number_cores = 2;
    square_addr = 0x401697;
    multiply_addr = 0x4016dc;

    l2_cache = new Cache(256, LINE_SIZE, 12, L2_ASSOC, false);
    l3_cache = new Cache(16384, LINE_SIZE, 36, L3_ASSOC, true); // l3 uses SHARP
    
    for (unsigned int i = 1; i < L3_ASSOC+1; i++){
        load(square_addr + LINE_SIZE*set_number_l3*i, 1);
        load(multiply_addr + LINE_SIZE*set_number_l3*i, 1);
    }

    cout << endl << endl << "Spy1 fills up sets corresponding to square and multiply calls" << endl;
    cout << "L3 cache" << endl; l3_cache->print_contents();

    for (unsigned int i = 1; i < L3_ASSOC+1; i++){
        unsigned long time_to_wait = load(square_addr + LINE_SIZE*set_number_l3*i, 1);
        if (time_to_wait >= 36){
            cout << "This should not be printed" << endl;
            break;
        }
    }

    load(square_addr, 0);
    cout << endl << endl << "Victim calls square" << endl;
    cout << "L2 cache" << endl; l2_cache->print_contents();
    cout << "L3 cache" << endl; l3_cache->print_contents();

    cout << "Square address is located at " << square_addr << endl;
    for (unsigned int i = 1; i < L2_ASSOC+1; i++){
        load(square_addr + LINE_SIZE*set_number_l2*i, 0);
        load(multiply_addr + LINE_SIZE*set_number_l2*i, 0);
    }
    cout << endl << endl << "Spy0 should have evicted square" << endl;
    cout << "L2 cache" << endl; l2_cache->print_contents();
    cout << "L3 cache" << endl; l3_cache->print_contents();

    for (unsigned int i = 1; i < L3_ASSOC+1; i++){
        unsigned long time_to_wait = load(square_addr + LINE_SIZE*set_number_l3*i, 1);
        if (time_to_wait >= 36){
            cout << "This should be printed" << endl;
        }
    }

    for (unsigned int i = 1; i < L3_ASSOC+1; i++){
        unsigned long time_to_wait = load(square_addr + LINE_SIZE*set_number_l3*i, 1);
        if (time_to_wait >= 36){
            cout << "This should not be printed" << endl;
        }
    }

    for (unsigned int i = 1; i < L2_ASSOC+1; i++){
        load(square_addr + LINE_SIZE*set_number_l2*i, 0);
        load(multiply_addr + LINE_SIZE*set_number_l2*i, 0);
    }

    for (unsigned int i = 1; i < L3_ASSOC+1; i++){
        unsigned long time_to_wait = load(square_addr + LINE_SIZE*set_number_l3*i, 1);
        if (time_to_wait >= 36){
            cout << "This should not be printed" << endl;
        }
    }

    load(multiply_addr, 0);
    cout << endl << endl << "Victim calls multiply" << endl;
    cout << "L2 cache" << endl; l2_cache->print_contents();
    cout << "L3 cache" << endl; l3_cache->print_contents();

    for (unsigned int i = 1; i < L2_ASSOC+1; i++){
        load(square_addr + LINE_SIZE*set_number_l2*i, 0);
        load(multiply_addr + LINE_SIZE*set_number_l2*i, 0);
    }

    for (unsigned int i = 1; i < L3_ASSOC+1; i++){
        unsigned long time_to_wait = load(square_addr + LINE_SIZE*set_number_l3*i, 1);
        if (time_to_wait >= 36){
            cout << "This should not be printed" << endl;
        }
    }

    load(square_addr, 0);
    cout << endl << endl << "Victim calls square" << endl;
    cout << "L2 cache" << endl; l2_cache->print_contents();
    cout << "L3 cache" << endl; l3_cache->print_contents();

    for (unsigned int i = 1; i < L2_ASSOC+1; i++){
        load(square_addr + LINE_SIZE*set_number_l2*i, 0);
        load(multiply_addr + LINE_SIZE*set_number_l2*i, 0);
    }
    cout << endl << endl << "Spy1 evicts everything" << endl;
    cout << "L2 cache" << endl; l2_cache->print_contents();
    cout << "L3 cache" << endl; l3_cache->print_contents();


    for (unsigned int i = 1; i < L3_ASSOC+1; i++){
        unsigned long time_to_wait = load(square_addr + LINE_SIZE*set_number_l3*i, 1);
        if (time_to_wait >= 36){
            cout << "This should be printed" << endl;
        }
    }

}

void test_evict_and_ownership(){
    /* Test ownership invalidation protocol when a cache line is evicted from the L2 */
    unsigned long set_number_l2 = 256 * 1024 / LINE_SIZE / L2_ASSOC;
    unsigned long set_number_l3 = 16384 * 1024 / LINE_SIZE / L3_ASSOC;

    number_cores = 17;

    l2_cache = new Cache(256, LINE_SIZE, 12, L2_ASSOC, false);
    l3_cache = new Cache(16384, LINE_SIZE, 36, L3_ASSOC, true); // l3 uses SHARP

    /* Initially load <L2_ASSOC> blocks from core 0 */
    for (unsigned int i = 0; i < L2_ASSOC; i++){
        load(LINE_SIZE*set_number_l2*i, 0);
    }

    cout << "L2 cache" << endl; l2_cache->print_contents();
    cout << "L3 cache" << endl; l3_cache->print_contents();

    /* Now, there is a set where all the ways are filled. Load one more address */
    load(LINE_SIZE*set_number_l2*L2_ASSOC, 0);

    /* The entry of the block that was evicted from the L3 cache should be owned by no one now */
    cout << "L2 cache" << endl; l2_cache->print_contents();
    cout << "L3 cache" << endl; l3_cache->print_contents();
    cout << "Ownership test finished. Testing eviction from inclusivity ... " << endl;
    srand(12); /* Made on purpose so the core 16th evicts the address at set 4096 and way 0 */
    /* Now, using 16 attackers, evict the added block from the L3 cache */
    unsigned long address_to_invalidate = LINE_SIZE*set_number_l2*L2_ASSOC;
    for (int core = 1; core < 17; core++){
        load(address_to_invalidate + LINE_SIZE*set_number_l3*L3_ASSOC*core, core);
        cout << "L3 cache" << endl; l3_cache->print_contents();
    }

    /* L2 cache should now have that block invalidated */
    cout << "L2 cache" << endl; l2_cache->print_contents();




}
void test_sharp(){
    /* Test our SHARK implementation */
    unsigned long set_number_l3 = 16384 * 1024 / LINE_SIZE / L3_ASSOC;
    number_cores = 3;

    l2_cache = new Cache(256, LINE_SIZE, 12, L2_ASSOC, false);
    l3_cache = new Cache(16384, LINE_SIZE, 36, L3_ASSOC, true); // l3 uses SHARP

    /* Initially load <L3_ASSOC> blocks from core 0 */
    for (unsigned int i = 0; i < L3_ASSOC; i++){
        load(LINE_SIZE*set_number_l3*i, 0);
    }

    cout << "About to load from core 1" << endl;
    /* Load 1 block from core 1 */
    load(LINE_SIZE*set_number_l3*L3_ASSOC, 1);
    cout << "Loaded" << endl;

    /* L3 cache should have <L3_ASSOC>-1 blocks from core0 and 1 block from core1 */
    cout << "L3 cache" << endl; l3_cache->print_contents();

    /* After loading one more block from core 1, the L3 cache should have the same format as before */
    load(LINE_SIZE*set_number_l3*(L3_ASSOC+1), 1);
    cout << "L3 cache" << endl; l3_cache->print_contents();

    /* After loading one block from core 2, the L3 cache should now evict randomly one block */
    load(LINE_SIZE*set_number_l3*(L3_ASSOC+2), 2);
    cout << "L3 cache" << endl; l3_cache->print_contents();
}

void test_caches(){
    /* Test new changes to Caches,
         considering associativity could be larger than 2, 
         and we now load from multiple caches
    */
    unsigned long set_number_l2 = 256 * 1024 / LINE_SIZE / L2_ASSOC;
    number_cores = 4;

    l2_cache = new Cache(256, LINE_SIZE, 12, L2_ASSOC, false);
    l3_cache = new Cache(16384, LINE_SIZE, 36, L3_ASSOC, true); // l3 uses SHARP

    load(0, 0);
    load(LINE_SIZE*set_number_l2, 0);
    load(LINE_SIZE*set_number_l2*2, 0);
    load(LINE_SIZE*set_number_l2*3, 0);
    load(LINE_SIZE*set_number_l2*4, 0);
    load(LINE_SIZE*set_number_l2*5, 0);
    load(LINE_SIZE*set_number_l2*6, 0);
    load(LINE_SIZE*set_number_l2*7, 0);

    cout << "Loaded 4 colliding addresses" << endl;
    cout << "L2 cache" << endl; l2_cache->print_contents();
    cout << "L3 cache" << endl; l3_cache->print_contents();
}

int main(int argc, char **argv)
{
    /* Finish comment in this line for testing
    test_second_atk_simplified();
    return 0;
    
    test_evict_and_ownership();
    test_sharp();
    test_caches();
    return 0;
    // */

    spy_probability = 100; // chances a spy will insert an instruction
    
    // select attack
    multi_spy = false;
    shared_l2 = true;

    if (shared_l2){
        spy_count = 2;
        number_cores = 2;
    }
    else{
        spy_count = L3_ASSOC;
        number_cores = L3_ASSOC + 1;
    }

    srand(0); /* Make stuff deterministic for easier debugging */
    
    if (argc < 7+2){
        return Usage();
    }

    square_addr = strtol(argv[5], NULL, 16);
    multiply_addr = strtol(argv[6], NULL, 16);

    PIN_Init(argc, argv);
    
    /* Parameters taken from a real i7 processor (3.4 GHz i7-4770). L3 cache size is made to be a power of 2 */
    l2_cache = new Cache(256, LINE_SIZE, 12, L2_ASSOC, false);
    l3_cache = new Cache(16384, LINE_SIZE, 36, L3_ASSOC, true); // l3 uses SHARP
    
    

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
        pin -t obj-intel64/pin_sharp_cache.so 0x4014e3 0x4016dc -- ./rsa
*/
