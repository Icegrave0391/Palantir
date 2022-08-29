#ifndef _TAINT_TAINTENGINE_H_
#define _TAINT_TAINTENGINE_H_

#include <iostream>
#include <cstring>

#include "taintstat.h"
#include "taintsummary.h"
#include "common.h"

#define PT_RING_BUFFER_SIZE 2048

#define ABORT(expr, fmt, ...) \
do { \
	if (expr) { \
		fprintf(stderr, fmt "\n", ## __VA_ARGS__); \
		exit(0); \
	} \
} while (0)

typedef std::vector<std::pair<syscall_id_t, taint_tag_t>> taint_syscall_t;
typedef std::map<pid_t, taint_syscall_t> taint_audit_t;

class TaintEngine {
    public:
        // start function addresses (defines when to start taint summary retrivals)
        std::vector<mem_addr_t> start_addr;

        // flag for start taint analysis
        std::vector<pid_t> pids_taint_start;

        // syscall sequence for plt functions/basic blocks
        std::map<pid_t, syscall_seq_t> pids_syscall_seq;
        syscall_seq_t global_syscall_seq;

        // syscall id and taint tag for different syscalls
        std::vector<taint_tag_t> taint_syscall;
        // used to match write before close
        taint_tag_t write_syscall_taint;

        // audit sequence and taint tag for audit logs
        taint_audit_t taint_audit;
        bool text_section;
        bool analyzed_block;

        pt_blocks *blocks;

        TaintStat *taint_stat;
        TaintSummary *taint_summary;

        // analysis performance
        std::chrono::steady_clock sc;
        double time;

        TaintEngine(const char *ip, int port, std::string proc_name);
        ~TaintEngine();

        void traverseBlocks();
        void updateTaintStat(adjnode *adj_node, pid_t pid);
        void emptyTaintStat(int type, int offset, int size, int64_t stack_base);

        void printBlocks();
        void printSyscalls();
        void PrintTaintAudit();
};

#endif