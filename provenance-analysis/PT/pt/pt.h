#ifndef _PT_PT_H
#define _PT_PT_H

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <sys/time.h>
#include <stdbool.h>
#include <mnemonics.h>
#include <distorm.h>

#include "pt_block.h"
#include "pt_packet.h"
#include "common.h"

#define ABORT(expr, fmt, ...) \
do { \
	if (expr) { \
		fprintf(stderr, fmt "\n", ## __VA_ARGS__); \
		exit(0); \
	} \
} while (0)

// MAGIC number from Griffin
#define MAGIC 0x51C0FFEE
#define VERSION 1

#define PAGE_SIZE 4096

#define PID_SPACE 0xffff
struct {
	void *base;
	void *top;
	// sp (stack pointer) monitors stack behaviors
	struct pt_event *sp; 
	struct pt_event *xbegin;
} stacks[PID_SPACE];

// The user-level address space layout in GRIFFIN
#define MIRROR_DISTANCE 0x010000000000
#define MIRROR(addr, level) (((addr) + (level) * MIRROR_DISTANCE) & 0x7fffffffffff)
#define PT_IP_TO_CODE(addr) MIRROR(addr, 1)
#define PT_IP_TO_BLOCK(addr) MIRROR((addr) & ~0x7, ((addr) & 0x7) + 2)

typedef unsigned short pt_recover_arg;

unsigned long previous_addr;

circular_addr_t *previous_addr_circular;

// cache traced blocks in TSX
struct _tsx_block {
	unsigned long addr;
	int sid;
	enum pt_block_type type;
};
#define MAX_TSX_BLOCK 10000
unsigned long tsx_block_index;
struct _tsx_block tsx_block[MAX_TSX_BLOCK];

// check pt trace integrity
void trace_integrity_check(FILE *);

// parse pt traces
long pt_parse(enum pt_logitem_kind, void *, pt_blocks *, unsigned int*, unsigned int*);

#endif
