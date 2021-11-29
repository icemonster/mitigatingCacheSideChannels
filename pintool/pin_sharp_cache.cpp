#include <iostream>
#include <iterator>
#include <algorithm>
#include <vector>
#include <sstream>
#include <math.h>
#include <stdlib.h>
#include "pin.H"

#define MILLION 1000000
#define THOUSAND 1000
#define NUM_ORDERED_ACCESS_MISSES 20

using namespace std;

typedef struct Reference {
    unsigned long count;
    unsigned long misses;
    unsigned long PC;
} Ref;

typedef struct Way_Struct {
    bool valid;
    bool lru;
    unsigned long tag;
} Way;

class Access {
    public:
        unsigned long address;
        unsigned long count;
        unsigned long misses;
        bool type;
        Access(unsigned long a, bool t, unsigned long c, unsigned long m){
            address = a;
            type = t;
            count = c;
            misses = m;
        } 
};

bool better_access (Access *i,Access *j) { return (i->misses>j->misses); }


class Cache {
    public:
        unsigned long accesses;
        unsigned long misses;
        unsigned int size;
        unsigned int line_size;
        unsigned int miss_penalty;
        unsigned int associativity;
        vector<Access*> ordered_accesses;

        unsigned long tag_mask;
        unsigned long set_mask;
        unsigned long block_off_mask;

        unsigned long set_bits;
        unsigned long blk_bits;

        map<pair<unsigned long, bool>, Reference*> all_accesses; 

        Way **sets;
    
        // SHARP data
        bool sharp;
        unsigned long * alarm_counter;
        int  ** owner;
        

        
        Cache(unsigned int s, unsigned int ls, unsigned int mp, unsigned int a, bool sp) : ordered_accesses(NUM_ORDERED_ACCESS_MISSES) {
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
                    sets[i][j].lru = true;
                }
            }
            
            sharp = sp;
            alarm_counter = 0;
            
            owner = malloc (sizeof (int *) * set_number);
            
            for (unsigned long i = 0; i < set_number; i++){
                owner[i] = malloc (sizeof (int) * associativity);
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

        void compute_ordered_misses(int number){
            unsigned long acc = 0;

            vector<Access*> all_accesses_vec;

            for (auto const& it : all_accesses){
                acc++;
                all_accesses_vec.push_back(new Access(it.first.first, it.first.second, it.second->count, it.second->misses));
            }

            partial_sort_copy(
                all_accesses_vec.begin(), all_accesses_vec.end(), //.begin/.end in C++98/C++03
                ordered_accesses.begin(), ordered_accesses.end(), 
                better_access //remove "int" in C++14
            );
        }

        int increment_access(pair<unsigned long, bool> key, bool type, bool is_miss){
            if (all_accesses.count(key) == 0)
                return 0;
            
            all_accesses[key]->count++;
            if (is_miss){
                all_accesses[key]->misses++;
            }

            return 1;
        }

        bool find_tag_in_set(unsigned long set, unsigned long addr){
            Way *ways = sets[set];
            // TODO: updated for set size greater than 2

            for (unsigned long i = 0; i < associativity; i++){
                if (ways[i].valid && tags_equal(addr, ways[i].tag)){
                    ways[i].lru = false;
                    
                    if (associativity > 1)
                        ways[1-i].lru = true;
                        
                    return false;
                }
            }

            return true;
        }

        void evict_lru_block(unsigned long set, unsigned long addr){
            Way *ways = sets[set];
            // TODO: updated for set size greater than 2
            if (associativity == 1){
                ways[0].valid = true;
                ways[0].tag = addr & tag_mask;
            }
            else{
                int i = 0;
                if (ways[1].lru){
                    i = 1;
                }
                ways[i].valid = true;
                ways[i].tag = addr & tag_mask;
                ways[i].lru = false;
                ways[1-i].lru = true;
            }
        }
    
        void evict_sharp_block (unsigned long set, unsigned long addr, int core) {
            Way *ways = sets[set];
            int candidate = -1;
            
            // STEP 1: check if a way is unused
            for (int i = 0; i < associativity; i++) {
                if (owner[set][i] == -1) {
                    candidate = i;
                    break;
                }
            }
            if (candidate > -1) {
                ways[candidate].valid = true;
                ways[candidate].tag = addr & tag_mask;
                owner[set][i] = core;
                return;
            }
            
            // STEP 2: check if a way is owned by calling processor
            for (int i = 0; i < associativity; i++) {
                if (owner[set][i] == core) {
                    candidate = i;
                    break;
                }
            }
            if (candidate > -1) {
                ways[candidate].valid = true;
                ways[candidate].tag = addr & tag_mask;
                owner[set][i] = core;
                return;
            }
            
            // STEP 3: evict something randomly
            candidate = rand() % associativity;
            ways[candidate].valid = true;
            ways[candidate].tag = addr & tag_mask;
            owner[set][i] = core;
            alarm_counter[core]++; // update alarm counter
            return;
  
        }

        void access(unsigned long addr, bool is_load, unsigned long pc, int core){
            accesses++;
            
            pair<unsigned long, bool> key(pc, is_load);

            unsigned long set = get_set_index(addr);


            bool is_miss = find_tag_in_set(set, addr);

            if (is_miss){
                misses++;
                
                if (sharp) evict_sharp_block (set, addr, core);
                else evict_lru_block(set, addr);
            }


            /* Update the global access_count/miss_count for this specific address */
            int already_accessed = increment_access(key, is_load, is_miss);
            if (!already_accessed){
                Ref *access = (Ref *)malloc(sizeof(Ref)); /* TODO - Free this in Fini */
                access->count = 1;
                access->misses = 1;
                all_accesses[key] = access;
            }
        }

        void store(unsigned long addr, unsigned long pc, int core){
            access(addr, false, pc, core);
        }
        void load(unsigned long addr, unsigned long pc, int core){
            access(addr, true, pc, core);
        }
};

class Spy {
public:
    
    int spy_id;
    int ready;
    int cnt;
    bool shared;
    vector<bool> hits;
    
    
    Spy (int id) {
        cnt = -1;
        ready = 0;
        
        spy_id = id;
        if (spy_id == 0 and shared_l2) shared = true;
        else shared = false;
    }
    
    void operate () {
        if (cnt == -1) { // initial configuration
            if (shared) {}
            else {}
            
            return;
        }
        if (++cnt == ready) { // wait time over
            if (shared) {}
            else {
                // call load and check if hit
                data_cache_load() // arguments? (how to check if hit?)
                
                // update wait time
                ready += 30;
            }
        }
    }
    
}

//Cache *data_cache;
Cache *instr_cache;

Cache *l1_cache;
Cache *l2_cache;
Cache *l3_cache;

int spy_count;
bool multi_spy; // attack 1
bool shared_l2; // attack 2
int spy_probability;
Spy * spies;

VOID instr_cache_load(unsigned long ip) {
//    instr_cache->accesses++;
//    instr_cache->load(ip, ip);
    
    bool miss;
    miss = instr_cache->load (ip, ip, core);
    if (miss) miss = l2_cache->load (ip, ip, core);
    if (miss) l3_cache->load (ip, ip, core);
}

VOID data_cache_load(unsigned long addr, unsigned long pc, int core){
    bool miss;
    miss = l1_cache->load (addr, pc, core);
    if (miss) miss = l2_cache->load (add, pc, core);
    if (miss) l3_cache->load (add, pc, core);
    
}

VOID data_cache_store(unsigned long addr, unsigned long pc, int core){
    bool miss;
    miss = l1_cache->load (addr, pc, core);
    if (miss) miss = l2_cache->load (add, pc, core);
    if (miss) l3_cache->load (add, pc, core);
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
                IARG_UINT64, ip,
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
                IARG_UINT64, ip,
                IARG_UINT64, 0,
                IARG_END);
        }
    }
    
    

    for (int i = 0; i < spy_count; i++) {
        if (rand() % 100 <= spy_probability) { // chance of spy instruction
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE,  (AFUNPTR) spy_instruction,
                IARG_UINT64, i,
                IARG_END);
        }
    }
    
    
}

VOID Fini(INT32 code, VOID *v)
{
    cout.precision(4);

    // Print the actual results
    unsigned long instr_exec = instr_cache->accesses;
    unsigned long data_stalls = data_cache->misses*data_cache->miss_penalty;;
    unsigned long instr_stalls = instr_cache->misses*instr_cache->miss_penalty;
    unsigned long total = instr_exec + data_stalls + instr_stalls;
    long double instr_exec_rate = (long double)(instr_exec * 100) / (long double)total;
    long double data_stall_rate = (long double)(data_stalls * 100) / (long double)total;
    long double instr_stall_rate = (long double)(instr_stalls * 100) / (long double)total;

    cout << endl << endl << "Overall Performance Breakdown: " << endl;
    cout << "==============================" << endl;
    cout << "Instruction Execution: " << instr_exec/MILLION << "M cycles ( " << instr_exec_rate << "%)" << endl;
    cout << "Data Cache Stalls: " << data_stalls/MILLION << "M cycles ( " << data_stall_rate << "%)" << endl;
    cout << "Instruction Cache Stalls: " << instr_stalls/MILLION << "M cycles ( " << instr_stall_rate << "%)" << endl;
    cout << "------------------------------------------------" << endl;
    cout << "Total Execution Time: " << total/MILLION << "M cycles ( " << "100" << "%)" << endl << endl;

    cout << "Data Cache:" << endl;
    cout << "===========" << endl;

    if (data_cache->associativity == 1)
        cout << "Configuration: size = " << data_cache->size << "KB, line size = " << data_cache->line_size << "B, associativity = " << "DirectMapped" << ", miss latency = " << data_cache->miss_penalty << " cycles" << endl;
    else
        cout << "Configuration: size = " << data_cache->size << "KB, line size = " << data_cache->line_size << "B, associativity = " << "2-way" << ", miss latency = " << data_cache->miss_penalty << " cycles" << endl;

    long double data_miss_rate = (long double)(data_cache->misses) * 100 / (long double) data_cache->accesses;
    cout << "Overall Performance: " << data_cache->accesses/MILLION << "M References, " << data_cache->misses/MILLION << "M Misses, Miss Rate = " << data_miss_rate << "%, Data Cache Stalls = " << data_cache->misses*data_cache->miss_penalty/MILLION << "M cycles" << endl << endl;
    cout << "Rank ordering of data references by absolute miss cycles:" << endl << endl;

    cout << "\tPC\t\t| Type\t| References\t|Misses\t| Miss Rate\t| Total Miss Cycles\t| Contribution to Total Data Miss Cycles" << endl;
    cout << "\t--------------------------------------------------------------------------------------------------------" << endl;

    data_cache->compute_ordered_misses(NUM_ORDERED_ACCESS_MISSES);
    int i = 0;
    for (Access *acc : data_cache->ordered_accesses){
        i++;
        stringstream stream;
        stream << "0x" << hex << acc->address;
        string address_hex( stream.str() );
        cout << i << ". \t"  
        << address_hex << "\t| " 
        << (acc->type? "Load" : "Store") << "\t| " 
        << acc->count/(long double)THOUSAND << "K\t\t| " 
        << acc->misses/(long double)THOUSAND << "K\t| " 
        << (long double)acc->misses / (long double)acc->count << "\t\t| " 
        << acc->misses*data_cache->miss_penalty/MILLION << "M\t\t| " 
        << (long double)(acc->misses*data_cache->miss_penalty)*100 / (long double)data_stalls  << "%" << endl;
    }

    cout << endl;
    
    cout << "Instruction Cache:" << endl;
    cout << "==================" << endl;
    if (instr_cache->associativity == 1)
        cout << "Configuration: size = " << instr_cache->size << "KB, line size = " << instr_cache->line_size << "B, associativity = " << "DirectMapped" << ", miss latency = " << instr_cache->miss_penalty << " cycles" << endl;
    else
        cout << "Configuration: size = " << instr_cache->size << "KB, line size = " << instr_cache->line_size << "B, associativity = " << "2-way" << ", miss latency = " << instr_cache->miss_penalty << " cycles" << endl;
    
    long double instr_miss_rate = (long double)(instr_cache->misses) * 100 / (long double) instr_cache->accesses;
    cout << "Overall Performance: " << instr_cache->accesses/THOUSAND << "K References, " << instr_cache->misses/THOUSAND << "K Misses, Miss Rate = " << instr_miss_rate << "%, Inst Cache Stalls = " << instr_cache->misses*instr_cache->miss_penalty/MILLION << "M cycles" << endl << endl;
    cout << "Rank ordering of instruction references by absolute miss cycles:" << endl;

    cout << "\tPC\t\t| References\t|Misses\t| Miss Rate\t| Total Miss Cycles\t| Contribution to Total Inst Miss Cycles" << endl;
    cout << "\t--------------------------------------------------------------------------------------------------------" << endl;

    instr_cache->compute_ordered_misses(NUM_ORDERED_ACCESS_MISSES);
    i = 0;
    for (Access *acc : instr_cache->ordered_accesses){
        i++;
        stringstream stream;
        stream << "0x" << hex << acc->address;
        string address_hex( stream.str() );
        cout << i << ". \t"  
            << address_hex << "\t| " 
            << acc->count/(long double)THOUSAND << "K\t\t| " 
            << acc->misses/(long double)THOUSAND << "K\t| " 
            << (long double)acc->misses / (long double)acc->count << "\t\t| " 
            << acc->misses*instr_cache->miss_penalty/THOUSAND << "K\t\t| " 
            << (long double)(acc->misses*instr_cache->miss_penalty)*100 / (long double)instr_stalls << "%"  << endl;
    }
}

INT32 Usage(){
    cerr << "Our cache simulator tool." << endl;
    cerr << "Usage: pin -t obj-intel64/pin_cache.so <cacheSize> <lineSize> <missPenalty> <associativity> -- cache_test/MMM.out " << endl;
    return -1;
}

int main(int argc, char **argv)
{

    srand(0);
    
    if (argc < 11){
        return Usage();
    }

    PIN_Init(argc, argv);
    
//    data_cache = new Cache(atoi(argv[5]), atoi(argv[6]), atoi(argv[7]), atoi(argv[8]));
    instr_cache = new Cache(atoi(argv[5]), atoi(argv[6]), atoi(argv[7]), atoi(argv[8]), false);

    l1_cache = new Cache(8, 64, 100, 1, false);
    l2_cache = new Cache(8, 64, 100, 2, false);
    l3_cache = new Cache(8, 64, 100, 4, true); // l3 uses SHARP
    
    // select attack
    multi_spy = true;
    spy_count = 4;
    
    shared_l2 = false;
    if (shared_l2) spy_count = 2;
    spies = malloc (sizeof (Spy *) * spy_count);
    if (shared_l2) {
        spies[0] = new Spy (0); // shares L2
        spies[1] = new Spy (1); // different core
    }
    else {
        for (int i = 0; i < spy_count; i++) {
            spies[i] = new Spy (i+1); // do not share core 0
        }
    }
    
    spy_probability = 90; // chances a spy will insert an instruction
    
    INS_AddInstrumentFunction(Instruction, 0);

    /* Implement your cache simulator here */

    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    return 0;
}

/* 
    Test with:
        pin -t obj-intel64/pin_cache.so 8 64 100 1 -- cache_test/MMM.out 
        pin -t obj-intel64/pin_cache.so 8 64 100 2 -- cache_test/MMM.out  
        pin -t obj-intel64/pin_cache.so 8 128 100 2 -- cache_test/MMM.out  
        pin -t obj-intel64/pin_cache.so 32 128 100 2 -- cache_test/MMM.out  

        And the other sample targets too
*/
