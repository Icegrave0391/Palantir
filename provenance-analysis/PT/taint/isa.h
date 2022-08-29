#ifndef _TAINT_ISA_H_
#define _TAINT_ISA_H_

#include <string>
#include <list>
#include <iostream>

typedef uint32_t symbol_id_t;
typedef uint32_t reg_id_t;
typedef uint64_t mem_addr_t;

// We use X86 Instruction Set Architecture (ISA) from Angr
// get reg dependency. e.g., rax -> (eax, ah, al)
int getRegDep(const reg_id_t reg_id, std::list<reg_id_t> &reg_dep);
int getRegName(const reg_id_t reg_id, std::string &reg_name);

#endif