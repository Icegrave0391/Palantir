#ifndef _TAINT_TAINTSUMMARY_H_
#define _TAINT_TAINTSUMMARY_H_

#include <map>
#include <set>
#include<sstream>
#include <stack>
#include <tuple>
#include <vector>
#include <cassert>
#include <algorithm>
#include <chrono>

#include "../redis/redis.h"
#include "../pt/pt_block.h"
#include "isa.h"
#include "common.h"

#define ADJMAP_BACKWARD 0
#define ADJMAP_FORWARD 1
#define ADJMAP 2

// taint_summary.rel.at(type)
#define STACK 0
#define HEAP 1
#define GLOBAL 2
#define REGISTER 3
#define SYMBOL 4
#define EMPTY 5
#define SYSCALL 6

// taint_summary.syscall_direction
#define SYSCALL_NONE 0
#define SYSCALL_IN 1
#define SYSCALL_OUT 2

static inline std::string uint64_to_str(uint64_t input) {
    std::stringstream addr_stream;
    addr_stream << std::hex << input;
    return addr_stream.str();
}

static inline uint64_t str_to_uint64(std::string input) {
    return stoull(input, nullptr, 16);
}

typedef uint64_t ts_rel_t;
typedef uint64_t ts_unit_t;

typedef struct _taint_summary {
    // the number of taint relations
    ts_rel_t rnum;

    // the number of taint units
    ts_unit_t unum;

    // whether with the scope of taint analysis
    bool scope; 

    // stack base
    int64_t stack_base;

    // redirect to sibing (https://github.com/Icegrave0391/palantiri/issues/28)
    mem_addr_t redirect;

    // vector <int> -> <des, src, src,...>
    std::vector<std::vector<int>> rel_index;

    // vector <int> -> <des_size, des_offset, des_type, src_size,...>
    std::vector<std::vector<int>> rel;

    // <int, int, int> -> <size, offset, type>
    std::vector<std::array<int, 3>> unit;

    int syscall_direction;
    int syscall_id;
} taint_summary;

typedef struct adjnode {
    mem_addr_t addr;
    taint_summary *ts;
    std::map<std::string, std::list<adjnode *>>::iterator next;
    std::map<std::string, std::list<adjnode *>>::iterator previous;

    // used in traverseAdjmap
    bool traverse_ret;

    // empty
    bool empty;

    // overwrite "<"
    bool operator<(const adjnode& a) const {
        return addr < a.addr;
    }
} adjnode;

typedef std::list<adjnode *> adjlist;

typedef std::map<std::string, adjlist> adjmap;

typedef std::array<mem_addr_t, 2> pltaddr;

class TaintSummary: public Redis {
    std::map<std::string, taint_summary *> all_ts;

    // temporary backward and forward adjacency matrix information
    adjmap adj_map_forward;
    adjmap adj_map_backward;
    std::set<std::string> start_point;
    // used in build adj_map
    std::set<std::string> seen_start_point;

    // final adjacency matrix information
    adjmap adj_map;

    // used as addr update in updateAdjmap
    // record context for every adj_node in adj_map
    std::map<std::string, std::set<std::string>> prefix_map;

    // plt address range (e.g., 0x400560 -> 0x4005f0)
    pltaddr plt_addr;
    std::vector<mem_addr_t> hook_addr;

    // iterator used to traverse adj_map
    std::string start_str; // e.g., nginx-0-
    std::map<pid_t, adjmap::iterator> taint_head;
    adjmap::iterator last_clone_it;

    bool curr_in_scope;
    // used to traverse adj_map after encountering basic blocks beyond the scope
    // of taint analysis
    int ret_from_outscope;
    adjmap::iterator head_after_outscope;

public:
    // start function addresses (defines when to start taint summary retrivals)
    std::vector<mem_addr_t> start_addr;

    std::chrono::steady_clock sc;
    double time;

    double time1;
    double time2;
    double time3;
    double time4;
    double time5;

    bool last_is_clone;

    TaintSummary(const char *ip, int port, std::string prog_name);
    ~TaintSummary();

    // parse keys in redis db
    std::list<mem_addr_t> parseCallsite(std::string context, int order);

    // basic operations
    adjlist &addAdjmap(std::string addr, int order);
    adjnode *addAdjlist(adjlist &exist_adjlist, mem_addr_t addr);
    
    // used for taintstat
    symbol_id_t symbol_num;
    void initSymbolNum();

    // generate adj_map according to callsite information
    void initPlt();
    void initStartTaint();
    void initAdjmap(int order);
    void updateAdjmap();
    void createTraverseIndex();

    std::set<std::string> backwardUpdate(std::string target, std::string noise);  
    void forwardUpdate(std::string target);

    void identifyStartPoint();
    void initPrefixMap();
    void initAdjMap();
    void updateAdjmap(std::set<std::string> prefix, std::string child);

    // init taint summary for adj_node in adj_map
    void getAllTS();
    void initAdjTS();
    
    void initURSIR(std::string category, std::string value_str, taint_summary *ts);
    void initRelIndex(std::vector<std::string> value_list, taint_summary *ts);
    void initUnit(int index, std::vector<std::string> value_list, taint_summary *ts);
    void InitRel();

    // traverse adjmap
    adjnode *traverseAdjmap(mem_addr_t addr, enum pt_block_type type, pid_t pid);
    adjnode *locateAdjnode(std::list<mem_addr_t> addrs);

    // print
    void printAdjmap(adjmap _adj_map);
    void printPrefixmap();
    void printPlt();
    void printStartTaint();
    void printTS(taint_summary *ts);
    void printMaxNumContext(adjmap _adj_map);

    // free
    void freeAdjmap();
};

#endif