#ifndef _PT_COMMON_H_
#define _PT_COMMON_H_

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#define CIRCULAR_SIZE 10

#define TOTAL_SYSCALL_NUM 335

const char* syscallid2name(int syscall_id);

typedef struct circular_addr_t {
    unsigned long *previous_addr;
    int head;
    int max;
} circular_addr_t;

circular_addr_t *circular_addr_init();
void circular_addr_free(circular_addr_t * addr_c);
void circular_addr_put(circular_addr_t * addr_c, unsigned long addr);
unsigned long circular_addr_get(circular_addr_t * addr_c, int back);

const char* syscallid2name(int syscall_id);

#endif
