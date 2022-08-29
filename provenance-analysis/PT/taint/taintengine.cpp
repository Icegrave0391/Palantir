#include "taintengine.h"

TaintEngine::TaintEngine(const char *ip, int port, std::string prog_name) {        
    // buffer to receive block addresses from pt
    blocks = new pt_blocks {
		.ptr = (pt_block_addr *) malloc(PT_RING_BUFFER_SIZE * sizeof(pt_block_addr)),
		.size = PT_RING_BUFFER_SIZE,
		.pos = 0,
	};
    ABORT(!blocks->ptr, "malloc for blocks failed");

    taint_summary = new TaintSummary(ip, port, prog_name);
    start_addr = taint_summary->start_addr;

    taint_stat = new TaintStat(taint_summary->symbol_num);

    global_syscall_seq = 0;

    for (uint32_t i = 0; i < TOTAL_SYSCALL_NUM; i++) {
        taint_syscall.push_back(taint_tag_t());
    }

    text_section = true;

    time = 0;
}

TaintEngine::~TaintEngine() {
    taint_tag_t().swap(write_syscall_taint);
    std::vector<taint_tag_t>().swap(taint_syscall);
    for (auto it: taint_audit) {
        taint_syscall_t().swap(it.second);
    }
    free(blocks->ptr);
    delete(blocks);
    delete(taint_stat);
    delete(taint_summary);
}

void TaintEngine::traverseBlocks() {
    for (uint64_t i = 0; i < blocks->pos; i++) {
        mem_addr_t addr = blocks->ptr[i].addr;
        enum pt_block_type type =  blocks->ptr[i].type;
        pid_t pid = blocks->ptr[i].pid;

        if (likely(addr > 0x70000000000)) {
            text_section = false;
            if (likely(type != PT_TYPE_SYSCALL)) {
                continue;
            }
        }
        else {
            text_section = true;
        }

        // Todo: improve the efficiency of identifying taint start label
        bool start_taint = false;
        if (std::find(pids_taint_start.begin(), pids_taint_start.end(), pid) != pids_taint_start.end()) {
            start_taint = true;
        }
        else if (unlikely(std::find(start_addr.begin(), start_addr.end(), addr) != start_addr.end())) {
            pids_taint_start.push_back(pid);
            start_taint = true;
        }

        // traverse basic blocks in the adjmap and update taint status
        if (unlikely(text_section) and start_taint) {
            adjnode *adj_node = taint_summary->traverseAdjmap(addr, type, pid);

            // update taint_stat using taint summary
            if (adj_node != NULL) {
                auto t1 = sc.now();
                updateTaintStat(adj_node, pid);
                analyzed_block = true;
                auto t2 = sc.now();
                time += static_cast<std::chrono::duration<double>>(t2 - t1).count();
            }
            else {
                analyzed_block = false;
            }
        }

        // collect fine-grained provenance for syscalls
        if (unlikely(type == PT_TYPE_SYSCALL)) {
            int sid = blocks->ptr[i].sid;
            pid_t pid = blocks->ptr[i].pid;
            
            if (pids_syscall_seq.find(pid) == pids_syscall_seq.end()) {
                pids_syscall_seq[pid] = 0;
            }

            // continue if pt parser fail to infer the syscall id
            if (sid == -1) {
                continue;
            }

            taint_syscall_t &pid_taint = taint_audit[pid];
            switch (sid) {
                // Todo: add system calls related to network
                case 1:
                    if (write_syscall_taint != taint_tag_t()) {
                        pid_taint.push_back(std::make_pair(sid, write_syscall_taint));
                        write_syscall_taint = taint_tag_t();
                        break;
                    }
                    // write
                case 18:
                    // pwrite
                case 20:
                    // writev
                case 296:
                    // pwritev
                case 311:
                    // process_vm_writev
                case 328:
                    // pwritev2
                case 40:
                    // sendfile
                case 44:
                    // sendto
                case 46:
                    // sendmsg
                case 242:
                    // mq_timedsend
                case 307:
                    // sendmmsg
                    if (analyzed_block) {
                        pid_taint.push_back(std::make_pair(sid, taint_syscall.at(sid)));
                    }
                    else {
                        pid_taint.push_back(std::make_pair(sid, taint_tag_t()));
                    }
                    break;
                case 56:
                    // clone
                    taint_summary->last_is_clone = true;
                    pid_taint.push_back(std::make_pair(sid, taint_tag_t()));     
                    break;
                default:
                    // we hardcode taint propagation for write (1) just before close (3)
                    // if (sid == 3) {
                    //     auto it_pid_taint = pid_taint.rbegin();
                    //     while (it_pid_taint != pid_taint.rend()) {
                    //         if ((*it_pid_taint).first == 1) {
                    //             (*it_pid_taint).second = write_syscall_taint;
                    //         }
                    //         else {
                    //             write_syscall_taint = taint_tag_t();
                    //             break;
                    //         }
                    //         it_pid_taint++;
                    //     }
                    // }
                    pid_taint.push_back(std::make_pair(sid, taint_tag_t()));         
                    break;
            }

            pids_syscall_seq[pid] += 1;
        }
    }
}

void TaintEngine::emptyTaintStat(int type, int offset, int size, int64_t stack_base) {
    switch (type) {
        case STACK:
            offset = offset + stack_base;
            taint_stat->emptyStackTaint(offset, size);
            break;
        case HEAP:
            taint_stat->emptyHeapTaint(offset, size);
            break;
        case GLOBAL:
            taint_stat->emptyGlobalTaint(offset, size);
            break;
        case REGISTER:
            // offset represents reg_id
            taint_stat->emptyRegTaint(offset);
            break;
        case SYMBOL:
            // offset represents symbol_id
            taint_stat->emptySymbolTaint(offset);
            break;
        case EMPTY:
            std::cerr << "cannot empty EMPTY event" << std::endl;
            exit(-1);
        case SYSCALL:
            std::cerr << "cannot empty SYSCALL event" << std::endl;
            exit(-1);
        default:
            std::cerr << "unkown taint state type " << type << std::endl;
            exit(-1);
    }
}

void TaintEngine::updateTaintStat(adjnode *adj_node, pid_t pid) {
    // address of current block
    // mem_addr_t addr = adj_node->addr;

    // obtain data dependency in taint summary
    auto ts = adj_node->ts;
    std::vector<std::vector<int>> rel_vec = ts->rel;

    // syscall id
    int sid = -1;

    for (auto r: rel_vec) {
        // set taint states of sink
        int d_size = r.at(0);
        int d_offset = r.at(1);
        int d_type = r.at(2);

        // get taint states of sources
        taint_tag_t taint_tag;
        int r_size = r.size();
        bool exist_in_syscall = false;

        for (int i = 3; i < r_size; i = i + 3) {
            int s_size = r.at(i);
            int s_offset = r.at(i + 1);
            int s_type = r.at(i + 2);

            switch (s_type) {
                case STACK:
                    s_offset = s_offset + adj_node->ts->stack_base;
                    taint_stat->getStackTaint(s_offset, s_size, taint_tag);
                    break;
                case HEAP:
                    taint_stat->getHeapTaint(s_offset, s_size, taint_tag);
                    break;
                case GLOBAL:
                    taint_stat->getGlobalTaint(s_offset, s_size, taint_tag);
                    break;
                case REGISTER:
                    // s_offset represents reg_id
                    taint_stat->getRegTaint(s_offset, taint_tag);
                    break;
                case SYMBOL:
                    // s_offset represents reg_id
                    taint_stat->getSymbolTaint(s_offset, taint_tag);
                    break;
                case EMPTY:
                    emptyTaintStat(d_type, d_offset, d_size, adj_node->ts->stack_base);
                    break;
                case SYSCALL:
                    // we only count multiple syscalls once in a taint summary
                    if (exist_in_syscall == false) {
                        if (pids_syscall_seq.find(pid) == pids_syscall_seq.end()) {
                            pids_syscall_seq[pid] = 0;
                        }
                        taint_tag.insert(pids_syscall_seq[pid]);
                        exist_in_syscall = true;
                        sid = adj_node->ts->syscall_id;
                        // printf("%d SYSCALL_IN: %lx %d %s\n", pids_syscall_seq[pid], addr, sid,  syscallid2name(sid));
                        assert(ts->syscall_direction == SYSCALL_IN);
                    }
                    break;
                default:
                    std::cerr << "Unkown taint state type " << s_type << std::endl;
                    exit(-1);
            }
        }

        switch (d_type) {
            case STACK:
                d_offset = d_offset + adj_node->ts->stack_base;
                taint_stat->setStackTaint(d_offset, d_size, taint_tag);
                break;
            case HEAP:
                taint_stat->setHeapTaint(d_offset, d_size, taint_tag);
                break;
            case GLOBAL:
                taint_stat->setGlobalTaint(d_offset, d_size, taint_tag);
                break;
            case REGISTER:
                // d_offset represents reg_id
                taint_stat->setRegTaint(d_offset, taint_tag);
                break;
            case SYMBOL:
                // d_offset represents reg_id
                taint_stat->setSymbolTaint(d_offset, taint_tag);
                break;
            case EMPTY:
                std::cerr << "EMPTY cannot be destination" << std::endl;
                exit(-1);
            case SYSCALL:
                assert(ts->syscall_direction == SYSCALL_OUT);
                sid = adj_node->ts->syscall_id;
                taint_syscall.at(sid) = taint_tag;
                if (sid == 1) {
                    write_syscall_taint = taint_syscall.at(sid);
                }
                if (pids_syscall_seq.find(pid) == pids_syscall_seq.end()) {
                    pids_syscall_seq[pid] = 0;
                }
                // printf("%d SYSCALL_OUT: %lx %d %s\n", pids_syscall_seq[pid], addr, sid,  syscallid2name(sid));
                // print_taint(taint_tag);
                break;
            default:
                std::cerr << "Unkown taint state type " << d_type << std::endl;
                exit(-1);
        }
    }
}

void TaintEngine::PrintTaintAudit() {
    syscall_seq_t seq = 0;
    for (auto it_audit: taint_audit) {
        pid_t pid = it_audit.first;
        std::cout << std::dec << "pid: " << pid << std::endl;
        taint_syscall_t taint_pid = it_audit.second;
        for (auto it_syscall: taint_pid) {
            syscall_id_t sid = it_syscall.first;
            taint_tag_t taint = it_syscall.second;
            std::cout << seq << " " <<  syscallid2name(sid);
            print_taint(taint);
            seq += 1;
        }
        seq = 0;
        std::cout << std::endl;
    }
}

void TaintEngine::printBlocks() {
    for (uint64_t i = 0; i < blocks->pos; i++) {
        mem_addr_t addr = blocks->ptr[i].addr;
        int sid;

        int type = blocks->ptr[i].type;
        switch (type) {
            case PT_TYPE_CALL:
                if (addr > 0x70000000000)
                    break;
                // printf("  call: %lx\n", addr);
                printf("  block: %lx\n", addr);
                break;
            case PT_TYPE_RET:
                if (addr > 0x70000000000)
                    break;
                // printf("  ret: %lx\n", addr);
                printf("  block: %lx\n", addr);
                break;
            case PT_TYPE_SYSCALL:
                sid = blocks->ptr[i].sid;
                // printf("%d syscall: %lx %d %s\n", global_syscall_seq, addr, sid,  syscallid2name(sid));
                global_syscall_seq += 1;
                break;
            default:
                if (addr > 0x70000000000)
                    break;
                printf("  block: %lx\n", addr);
                break;
        }
    }
}

void TaintEngine::printSyscalls() {
    for (uint64_t i = 0; i < blocks->pos; i++) {
        mem_addr_t addr = blocks->ptr[i].addr;
        
        int type = blocks->ptr[i].type;
        if (type == PT_TYPE_SYSCALL) {
            int sid = blocks->ptr[i].sid;
            printf("%d syscall: %lx %d %s\n", global_syscall_seq, addr, sid,  syscallid2name(sid));
            global_syscall_seq += 1;
        }
    }
}