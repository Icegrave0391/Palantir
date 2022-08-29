#ifndef _TAINT_COMMON_H_
#define _TAINT_COMMON_H_

#include <iostream>

#include "taintsummary.h"

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define TOTAL_SYSCALL_NUM 335

typedef int pid_t;

std::string taintInt2Str(int type);
int syscallDirection(int syscall_id);
const char* syscallid2name(int syscall_id);

#endif