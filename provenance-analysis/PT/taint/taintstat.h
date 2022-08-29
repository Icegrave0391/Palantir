#ifndef _TAINT_TAINTSTAT_H_
#define _TAINT_TAINTSTAT_H_

#include <map>
#include <cassert>
#include <vector>
#include <iomanip>
#include <set>

#include "isa.h"

#define invalid_reg(msg, reg) do { \
    std::cerr << msg << reg << std::endl; \
} while(0)

#define invalid_symbol(msg, reg) do { \
    std::cerr << msg << reg << std::endl; \
} while(0)

#define invalid_mem_addr(msg, addr) do { \
    std::cerr << msg \
    << std::setw(16) << std::setfill('0') << std::hex \
    << addr << std::dec << std::endl; \
} while(0)

#define invalid_addr(msg, addr) do { \
    std::cerr << msg \
    << std::dec << addr << std::endl; \
} while(0)

#define print_reg_name(reg_id) do { \
    std::string reg_name; \
    assert(getRegName(reg_id, reg_name) == 0); \
    std::cout << reg_name; \
} while(0)

#define print_mem_addr(addr) do { \
    std::cout << std::setw(16) << std::setfill('0') << std::hex \
    << addr << std::dec; \
} while(0)

#define print_addr(addr) do { \
    std::cout << std::dec << addr; \
} while(0)

#define print_taint(taint) do { \
    std::cout << " "; \
    for (auto i: taint) { \
        std::cout << i << " "; \
    } \
    std::cout << std::endl; \
} while(0)

typedef uint32_t syscall_id_t;
typedef uint32_t syscall_seq_t;
typedef std::set<syscall_seq_t> taint_tag_t;

class TaintStat {
    private:
        reg_id_t reg_taintstate_len;
        symbol_id_t symbol_num;

        // taint stat for symbol
        std::vector<taint_tag_t> symbolTaintStat;

        /* Todo: update map to virtual memory */
        // taint state for stack
        std::map<mem_addr_t, taint_tag_t> stackTaintState;
        // taint state for stack
        std::map<mem_addr_t, taint_tag_t> heapTaintState;
        // taint state for stack
        std::map<mem_addr_t, taint_tag_t> globalTaintState;

    public:
        // taint state for register
        std::vector<taint_tag_t> regTaintState;

        TaintStat(symbol_id_t _symbol_num);
        ~TaintStat();

        // register taint operations
        void getRegTaint(reg_id_t reg_id, taint_tag_t &taint);
        void setRegTaint(reg_id_t reg_id, taint_tag_t taint);
        void emptyRegTaint(reg_id_t reg_id);
        void printRegTaint(reg_id_t reg_id);

        // symbol taint operations;
        void getSymbolTaint(symbol_id_t symbol_id, taint_tag_t &taint);
        void setSymbolTaint(symbol_id_t symbol_id, taint_tag_t taint);
        void emptySymbolTaint(symbol_id_t symbol_id);
        void printSymbolTaint(symbol_id_t symbol_id);

        // stack taint operations
        void getStackTaint(int offset, int size, taint_tag_t &taint);
        void setStackTaint(int offset, int size, taint_tag_t taint);
        void emptyStackTaint(int offset, int size);
        void printStackTaint(int offset, int size);

        // heap taint operations
        void getHeapTaint(int offset, int size, taint_tag_t &taint);
        void setHeapTaint(int offset, int size, taint_tag_t taint);
        void emptyHeapTaint(int offset, int size);
        void printHeapTaint(int offset, int size);

        // global taint operations
        void getGlobalTaint(int offset, int size, taint_tag_t &taint);
        void setGlobalTaint(int offset, int size, taint_tag_t taint);
        void emptyGlobalTaint(int offset, int size);
        void printGlobalTaint(int offset, int size);

};

#endif
