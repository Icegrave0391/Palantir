#ifndef _PT_PT_BLOCK_H
#define _PT_PT_BLOCK_H

#define pt_in_block(a, b) (pt_get_block(a)->fallthrough_addr == (b)->fallthrough_addr)
#define pt_get_fallthrough_addr(b) (b)->fallthrough_addr
#define pt_get_target_addr(b) (b)->target_addr
#define pt_get_current_kind(b) (b)->kind
#define pt_block_is_call(b) ((b)->kind == PT_BLOCK_DIRECT_CALL || (b)->kind == PT_BLOCK_INDIRECT_CALL)
#define pt_block_is_ret(b) ((b)->kind == PT_BLOCK_RET)
#define pt_block_is_direct(b) ((b)->kind == PT_BLOCK_DIRECT_CALL || (b)->kind == PT_BLOCK_DIRECT_JMP)
#define pt_block_is_cond(b) ((b)->kind == PT_BLOCK_COND_JMP)
#define pt_block_is_syscall(b) ((b)->kind == PT_BLOCK_SYSCALL)

enum pt_block_kind {
	PT_BLOCK_DIRECT_CALL,
	PT_BLOCK_INDIRECT_CALL,
	PT_BLOCK_DIRECT_JMP,
	PT_BLOCK_INDIRECT_JMP,
	PT_BLOCK_COND_JMP,
	PT_BLOCK_RET,
	PT_BLOCK_SYSCALL,
	PT_BLOCK_TRAP,
};

/* assume that one code block does not contain more than 10 syscalls */
#define MAX_SYSCALL_NUM 10

typedef struct _pt_block {
	// fallthrough_addr shows the address of the "fall through" block
	unsigned long fallthrough_addr; 
	struct _pt_block *fallthrough_block;
	// target_addr shows the block address of the direct jump (call, jump...)
	// if the address cannot be determined (e.g., the next block is a system call)
	// , we keep target_block as null
	unsigned long target_addr;
	struct _pt_block *target_block;

	enum pt_block_kind kind;
	
    int syscall_num;
	unsigned long syscall_addr[MAX_SYSCALL_NUM];
	int syscall_id[MAX_SYSCALL_NUM];

	unsigned int n_inst;
} pt_block;

enum pt_block_type {
	PT_TYPE_BLOCK,
	PT_TYPE_CALL,
	PT_TYPE_RET,
	PT_TYPE_SYSCALL
};

typedef struct _pt_block_addr {
	unsigned long addr;
	enum pt_block_type type;
	int sid;
	int pid;
	unsigned int n_inst;
}pt_block_addr;

typedef struct _pt_blocks {
	pt_block_addr *ptr;
	unsigned long size; 
	unsigned long pos;
}pt_blocks;

#endif