#include "taintstat.h"

/* 
Registers used in PT: number = 70
    'rax', 'eax', 'ax', 'al', 'ah',
    'rcx', 'ecx', 'cx', 'cl', 'ch',
    'rdx', 'edx', 'dx', 'dl', 'dh',
    'rbx', 'ebx', 'bx', 'bl', 'bh',
    'rsp', 'sp', 'esp',
    'rbp', 'bp', 'ebp', 'bpl', 'bph',
    'rsi', 'esi', 'si', 'sil', 'sih',
    'rdi', 'edi', 'di', 'dil', 'dih',
    'r8', 'r8d', 'r8w', 'r8b',
    'r9', 'r9d', 'r9w', 'r9b',
    'r10', 'r10d', 'r10w', 'r10b',
    'r11', 'r11d', 'r11w', 'r11b',
    'r12', 'r12d', 'r12w', 'r12b',
    'r13', 'r13d', 'r13w', 'r13b',
    'r14', 'r14d', 'r14w', 'r14b',
    'r15', 'r15d', 'r15w', 'r15b',
*/

TaintStat::TaintStat(symbol_id_t _symbol_num) {
    reg_taintstate_len = 70;
    for (reg_id_t i = 0; i < reg_taintstate_len; i++)
        regTaintState.push_back(taint_tag_t());

    // the total number of symbols is defined in redis
    symbol_num = _symbol_num;
    for (symbol_id_t i = 0; i < symbol_num; i++)
        symbolTaintStat.push_back(taint_tag_t());
}

TaintStat::~TaintStat() {
    std::vector<taint_tag_t>().swap(regTaintState);
}

void TaintStat::getRegTaint(reg_id_t reg_id, taint_tag_t &taint) {
    std::list<reg_id_t> reg_dep;
    assert(getRegDep(reg_id, reg_dep) == 0);

    for (auto id: reg_dep) {
        taint_tag_t taint_reg = regTaintState.at(id);
        taint.insert(taint_reg.begin(), taint_reg.end());
    }
}

void TaintStat::setRegTaint(reg_id_t reg_id, taint_tag_t taint) {
    std::list<reg_id_t> reg_dep;
    assert(getRegDep(reg_id, reg_dep) == 0);

    for (auto id: reg_dep)
        regTaintState.at(id) = taint;
}

void TaintStat::emptyRegTaint(reg_id_t reg_id) {
    std::list<reg_id_t> reg_dep;
    assert(getRegDep(reg_id, reg_dep) == 0);

    for (auto id: reg_dep)
        regTaintState.at(id).clear();
}

void TaintStat::printRegTaint(reg_id_t reg_id) {
    if (reg_id < reg_taintstate_len) {
        print_reg_name(reg_id);
        print_taint(regTaintState[reg_id]);
    }
    else {
        invalid_reg("invalid reg: ", reg_id);
    }
}

void TaintStat::getSymbolTaint(symbol_id_t symbol_id, taint_tag_t &taint) {
    assert(symbol_id < symbol_num);
    taint_tag_t taint_symbol = symbolTaintStat.at(symbol_id);
    taint.insert(taint_symbol.begin(), taint_symbol.end());
}

void TaintStat::setSymbolTaint(symbol_id_t symbol_id, taint_tag_t taint) {
    assert(symbol_id < symbol_num);
    symbolTaintStat.at(symbol_id) = taint;
}

void TaintStat::emptySymbolTaint(symbol_id_t symbol_id) {
    assert(symbol_id < symbol_num);
    symbolTaintStat.at(symbol_id).clear();
}

void TaintStat::printSymbolTaint(symbol_id_t symbol_id) {
    assert(symbol_id < symbol_num);
    print_taint(symbolTaintStat.at(symbol_id));
}

void TaintStat::getStackTaint(int offset, int size, taint_tag_t &taint) {
    for (int i = 0; i < size; i++) {
        int stack_addr = offset + i;
        auto it = stackTaintState.find(stack_addr);
        if (it != stackTaintState.end()) {
            taint_tag_t taint_tmp = it->second;
            taint.insert(taint_tmp.begin(), taint_tmp.end());
        }
    }
}

void TaintStat::setStackTaint(int offset, int size, taint_tag_t taint) {
    for (int i = 0; i < size; i++) {
        int stack_addr = offset + i;
        stackTaintState[stack_addr] = taint;
    }
}

void TaintStat::emptyStackTaint(int offset, int size) {
    for (int i = 0; i < size; i++) {
        int stack_addr = offset + i;
        stackTaintState[stack_addr].clear();
    }
}

void TaintStat::printStackTaint(int offset, int size) {
    for (int i = 0; i < size; i++) {
        int stack_addr = offset + i;
        auto it = stackTaintState.find(stack_addr);
        if (it != stackTaintState.end()) {
            print_addr(stack_addr);
            print_taint(it->second);
        }
    }
}

void TaintStat::getHeapTaint(int offset, int size, taint_tag_t &taint) {
    for (int i = 0; i < size; i++) {
        int heap_addr = offset + i;
        auto it = heapTaintState.find(heap_addr);
        if (it != heapTaintState.end()) {
            taint_tag_t taint_tmp = it->second;
            taint.insert(taint_tmp.begin(), taint_tmp.end());
        }
    }
}

void TaintStat::setHeapTaint(int offset, int size, taint_tag_t taint) {
    for (int i = 0; i < size; i++) {
        int heap_addr = offset + i;
        heapTaintState[heap_addr] = taint;
    }
}

void TaintStat::emptyHeapTaint(int offset, int size) {
    for (int i = 0; i < size; i++) {
        int heap_addr = offset + i;
        heapTaintState[heap_addr].clear();
    }
}

void TaintStat::printHeapTaint(int offset, int size) {
    for (int i = 0; i < size; i++) {
        int heap_addr = offset + i;
        auto it = heapTaintState.find(heap_addr);
        if (it != heapTaintState.end()) {
            print_addr(heap_addr);
            print_taint(it->second);
        }
    }
}

void TaintStat::getGlobalTaint(int offset, int size, taint_tag_t &taint) {
    for (int i = 0; i < size; i++) {
        int global_addr = offset + i;
        auto it = globalTaintState.find(global_addr);
        if (it != globalTaintState.end()) {
            taint_tag_t taint_tmp = it->second;
            taint.insert(taint_tmp.begin(), taint_tmp.end());
        }
    }
}

void TaintStat::setGlobalTaint(int offset, int size, taint_tag_t taint) {
    for (int i = 0; i < size; i++) {
        int global_addr = offset + i;
        globalTaintState[global_addr] = taint;
    }
}

void TaintStat::emptyGlobalTaint(int offset, int size) {
    for (int i = 0; i < size; i++) {
        int global_addr = offset + i;
        globalTaintState[global_addr].clear();
    }
}

void TaintStat::printGlobalTaint(int offset, int size) {
    for (int i = 0; i < size; i++) {
        int global_addr = offset + i;
        auto it = globalTaintState.find(global_addr);
        if (it != globalTaintState.end()) {
            print_addr(global_addr);
            print_taint(it->second);
        }
    }
}
