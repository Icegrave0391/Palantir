#include "pt.h"

void trace_integrity_check(FILE* trace) {
	struct pt_logfile_header lhdr;
	size_t len = fread(&lhdr, 1, sizeof(lhdr), trace);

	// printf("len: %ld\n", len);
	// printf("lhdr: %ld\n", sizeof(lhdr));

	ABORT(len < sizeof(lhdr), "corrupted trace");
	ABORT(lhdr.magic != MAGIC, "unmatched magic");
	ABORT(lhdr.version != VERSION, "unmatched version");
}

int disasm_syscall_id_block(unsigned long addr, int *reg_r, int  *reg_e) {
	int syscall_id = -1;

	_CodeInfo codeInfo = {
		.codeOffset = addr,
		.nextOffset = 0,
		.code = (const unsigned char *) PT_IP_TO_CODE(addr),
		// .code = my_code_stream,
		.codeLen = 0x7fffffff,
		.dt = Decode64Bits,
		.features = DF_STOP_ON_FLOW_CONTROL,
	};

	unsigned int inst_count;
	// we hardcode the size of basic blocks with syscalls to be smaller than 50
	unsigned inst_num = 50;
	_DInst inst[inst_num];
	distorm_decompose(&codeInfo, inst, inst_num, &inst_count);

	for (int i = inst_count - 2; i > -1; i--) {
		_DInst curr_inst = inst[i];

		if (curr_inst.opcode == I_MOV) {
			if (curr_inst.ops[0].index == *reg_r || curr_inst.ops[0].index == *reg_e) {
				if (curr_inst.ops[1].type == O_REG) {
					*reg_r = curr_inst.ops[1].index;
					*reg_e = curr_inst.ops[1].index;
				}
				else if (curr_inst.ops[1].type == O_IMM) {
					syscall_id = curr_inst.imm.ex.i1;
					break;
				}
			}
		}
		else if (curr_inst.opcode == I_XOR) {
			if ((curr_inst.ops[0].index == *reg_r && curr_inst.ops[1].index == *reg_r)
				|| (curr_inst.ops[0].index == *reg_e && curr_inst.ops[1].index == *reg_e)) {
					syscall_id = 0;
					break;	
				}
		}
	}

	ABORT(META_GET_FC(inst[inst_count -1].meta) == FC_NONE, "addr: %lx, block size > %d", codeInfo.codeOffset, inst_num);

	return syscall_id;
}

int disasm_syscall_id(unsigned long addr) {
	int reg_r = R_RAX;
	int reg_e = R_EAX;

	int syscall_id = -1;
	syscall_id = disasm_syscall_id_block(addr, &reg_r, &reg_e);
	
	// if we cannot find syscall_id in the currect block, we will search for it
	// in the previous blocks
	for (int i = 0; i < CIRCULAR_SIZE && syscall_id == -1; i++) {
		unsigned long previous_addr = circular_addr_get(previous_addr_circular, i);
		if (previous_addr == 0) {
			break;
		}
		syscall_id = disasm_syscall_id_block(previous_addr, &reg_r, &reg_e);
	}

	// we do not cover complicated syscall id setting
	if (syscall_id == -1){
		fprintf(stderr, "cannot infer syscall id from addr: %lx\n", addr);
	}

	return syscall_id;
}

unsigned int *total_n_inst;
pt_block *disasm_block_distorm(unsigned long addr)
{	
	// Record the number of executed instructions
	_DInst _inst[200];
	_CodeInfo _codeInfo = {
		.codeOffset = addr,
		.nextOffset = 0,
		.code = (const unsigned char *) PT_IP_TO_CODE(addr),
		.codeLen = 0x7fffffff,
		.dt = Decode64Bits,
		.features = DF_STOP_ON_FLOW_CONTROL,
	};

	unsigned int n_inst;
	pt_block *block;
	_DInst inst;
	_CodeInfo codeInfo = {
		.codeOffset = addr,
		.nextOffset = 0,
		.code = (const unsigned char *) PT_IP_TO_CODE(addr),
		.codeLen = 0x7fffffff,
		.dt = Decode64Bits,
		.features = DF_STOP_ON_FLOW_CONTROL | DF_RETURN_FC_ONLY,
	};

	block = (pt_block *) malloc(sizeof(pt_block));
	memset((void *) block, 0, sizeof(pt_block));

	while (1) {
		distorm_decompose(&codeInfo, &inst, 1, &n_inst);

		// Record the number of executed instructions
		distorm_decompose(&_codeInfo, _inst, 200, &n_inst);
		block->n_inst += n_inst;

		// parse code blocks with multiple system calls
		if (block->kind == PT_BLOCK_SYSCALL) {
			if (META_GET_FC(inst.meta) == FC_SYS) {
				if (block->syscall_num == MAX_SYSCALL_NUM) {
					fprintf(stderr, "Set a larger value for MAX_SYSCALL_NUM\n");
					exit(EXIT_FAILURE);
				}
				block->syscall_addr[block->syscall_num] = inst.addr;
				block->syscall_id[block->syscall_num] = disasm_syscall_id(codeInfo.codeOffset);
				block->syscall_num += 1;
				circular_addr_put(previous_addr_circular, codeInfo.codeOffset);
				codeInfo.code = (const unsigned char*) PT_IP_TO_CODE(codeInfo.nextOffset);
				codeInfo.codeOffset = codeInfo.nextOffset;
				continue;
			}

			return block;
		}

		switch (META_GET_FC(inst.meta)) {
		case FC_CALL:
			block->kind = inst.ops[0].type == O_PC? PT_BLOCK_DIRECT_CALL: PT_BLOCK_INDIRECT_CALL;
			block->fallthrough_addr = inst.addr + inst.size;
			if (block->kind == PT_BLOCK_DIRECT_CALL)
				block->target_addr = block->fallthrough_addr + inst.imm.sdword;
			return block;
		case FC_RET:
			block->kind = PT_BLOCK_RET;
			block->fallthrough_addr = inst.addr + inst.size;
			return block;
		case FC_SYS:
			block->kind = PT_BLOCK_SYSCALL;
			block->fallthrough_addr = inst.addr + inst.size;
			block->syscall_addr[block->syscall_num] = inst.addr;
			block->syscall_id[block->syscall_num] = disasm_syscall_id(codeInfo.codeOffset);
			block->syscall_num += 1;
			circular_addr_put(previous_addr_circular, codeInfo.codeOffset);
			codeInfo.code = (const unsigned char*) PT_IP_TO_CODE(codeInfo.nextOffset);
			codeInfo.codeOffset = codeInfo.nextOffset;
			continue;
			// block->kind = PT_BLOCK_SYSCALL;
			// block->fallthrough_addr = inst.addr + inst.size;
			// return block;
		case FC_UNC_BRANCH:
			block->kind = inst.ops[0].type == O_PC? PT_BLOCK_DIRECT_JMP: PT_BLOCK_INDIRECT_JMP;
			block->fallthrough_addr = inst.addr + inst.size;
			if (block->kind == PT_BLOCK_DIRECT_JMP || inst.ops[0].index == R_RIP)
				block->target_addr = block->fallthrough_addr +
					(inst.ops[0].size == 32? inst.imm.sdword: inst.imm.sbyte);
			return block;
		case FC_CND_BRANCH:
			block->kind = PT_BLOCK_COND_JMP;
			block->fallthrough_addr = inst.addr + inst.size;
			block->target_addr = block->fallthrough_addr +
				(inst.ops[0].size == 32? inst.imm.sdword: inst.imm.sbyte);
			return block;
		case FC_INT:
			block->kind = PT_BLOCK_TRAP;
			block->fallthrough_addr = inst.addr + inst.size;
			return block;
		case FC_CMOV:
			circular_addr_put(previous_addr_circular, codeInfo.codeOffset);
			codeInfo.code = (const unsigned char*) PT_IP_TO_CODE(codeInfo.nextOffset);
			codeInfo.codeOffset = codeInfo.nextOffset;
			continue;
		default:
			printf("fail to parse %ld", addr);
			return NULL;
		}
	}
}

pt_blocks* blocks = NULL;
#define write_to_block_buffer(addr, pt_block_type, sid, pid) do { \
	blocks->ptr[blocks->pos].addr = addr; \
	blocks->ptr[blocks->pos].type = pt_block_type; \
	blocks->ptr[blocks->pos].sid = sid; \
	blocks->ptr[blocks->pos].pid = pid; \
	blocks->pos += 1; \
	if (blocks->pos == (blocks->size - 1)) { \
		blocks->size = blocks->size * 2; \
		blocks->ptr = (pt_block_addr *) realloc(blocks->ptr, blocks->size * sizeof(pt_block_addr)); \
	} \
} while(0)

static inline void pt_on_block(unsigned long addr, pt_recover_arg pid, enum pt_block_kind kind){
	int type;
	switch (kind) {
		case PT_BLOCK_RET:
			type = PT_TYPE_RET;
			break;
		case PT_BLOCK_DIRECT_CALL:
			type = PT_TYPE_CALL;
			break;
		case PT_BLOCK_INDIRECT_CALL:
			type = PT_TYPE_CALL;
			break;
		case PT_BLOCK_SYSCALL:
			type = PT_TYPE_SYSCALL;
			return;
		default:
			type = PT_TYPE_BLOCK;
			break;
       }

	// becasue we do not know whether traced blocks are valid in TSX's transactions,
	// they are cached in the memory until xcommit
	int sid = -1;
	if (stacks[pid].xbegin == NULL) {
		// printf("  block: %lx\n", addr);
		write_to_block_buffer(addr, type, sid, pid);
	}
	else {
		tsx_block[tsx_block_index].addr = addr;
		tsx_block[tsx_block_index].type = type;
		tsx_block_index += 1;
		ABORT(tsx_block_index == MAX_TSX_BLOCK, "MAX_TSX_BLOCK is set too small");
	}
}

static inline void pt_on_syscall(int syscall_num, unsigned long *syscall_addr, int *syscall_id, pt_recover_arg pid)
{
	// because we do not know whether traced syscalls are valid in TSX's transactions,
	// they are cached in the memory until xcommit
	for (int i = 0; i < syscall_num; i++) {
		unsigned long addr = (syscall_addr)[i];
		int sid = (syscall_id)[i];
		if (stacks[pid].xbegin == NULL) {
			write_to_block_buffer(addr, PT_TYPE_SYSCALL, sid, pid);
		}
		else {
			tsx_block[tsx_block_index].addr = addr;
			tsx_block[tsx_block_index].type = PT_TYPE_SYSCALL;
			tsx_block[tsx_block_index].sid = sid;
			tsx_block_index += 1;
			ABORT(tsx_block_index == MAX_TSX_BLOCK, "MAX_TSX_BLOCK is set too small");
		}
	}
}

#define pt_on_call(addr, pid) do {} while (0)

// #define pt_on_call(addr, pid) do {
// 	*(stacks[pid].sp--) = (struct pt_event) {addr, PT_EVENT_CALL};
// } while (0)

#define pt_on_ret(addr, pid) do {} while (0)

// static inline void pt_on_ret(unsigned long addr, pt_recover_arg pid)
// {
	// struct pt_event *sp;

	/* ignore sigreturn */
	// if (*(unsigned long *)(PT_IP_TO_CODE(addr)) == 0x0f0000000fc0c748 &&
	// 		*(unsigned char *)(PT_IP_TO_CODE(addr) + 8) == 0x05)
	// 	return;

	// for (sp = stacks[pid].sp + 1; ; sp++) {
	// 	if (sp->kind != PT_EVENT_CALL) {
	// 		*(sp - 1) = (struct pt_event) {addr, PT_EVENT_RET};
	// 		stacks[pid].sp = sp - 2;
	// 		return;
	// 	}

	// 	if (sp->addr == addr) {
	// 		stacks[pid].sp = sp;
	// 		return;
	// 	}
	// }
// }

static inline pt_block *pt_get_block(unsigned long addr)
{
	// printf("%lx\n", addr);
	// fflush(stdout);

	pt_block *block = *(pt_block **) PT_IP_TO_BLOCK(addr);

	if (!block) {
		block = disasm_block_distorm(addr);
		*(pt_block **) PT_IP_TO_BLOCK(addr) = block;
	}

	// record the number of executed instructions
	*total_n_inst += block->n_inst;
	// printf("addr %lx instruction %u\n", addr, block->n_inst);

	circular_addr_put(previous_addr_circular, addr);

	return block;
}

static inline pt_block *
pt_get_fallthrough_block(pt_block *block)
{
	if (!block->fallthrough_block)
		block->fallthrough_block = pt_get_block(pt_get_fallthrough_addr(block));
	else
		*total_n_inst += block->n_inst;
	return block->fallthrough_block;
}

static inline pt_block *
pt_get_target_block(pt_block *block)
{	
	if (!block->target_block)
		block->target_block = pt_get_block(pt_get_target_addr(block));
	else
		*total_n_inst += block->n_inst;
	return block->target_block;
}

static inline void pt_on_xbegin(pt_recover_arg pid)
{
	if (!stacks[pid].xbegin) {
		*(stacks[pid].sp--) = (struct pt_event) {0, PT_EVENT_XBEGIN};
		stacks[pid].xbegin = stacks[pid].sp + 1;
		tsx_block_index = 0;
	}
}

static inline void pt_on_xcommit(pt_recover_arg pid)
{
	struct pt_event *old_sp, *sp;

	ABORT(!stacks[pid].xbegin, "commit outside a transaction");

	old_sp = stacks[pid].sp;
	stacks[pid].sp = stacks[pid].xbegin;

	for (sp = stacks[pid].xbegin - 1; sp > old_sp; sp--) {
		if (sp->kind == PT_EVENT_CALL)
			pt_on_call(sp->addr, pid);
		else if (sp->kind == PT_EVENT_RET)
			pt_on_ret(sp->addr, pid);
		else
			ABORT(1, "unexpected event type (%d) while commit", sp->kind);
	}

	stacks[pid].xbegin = NULL;
	tsx_block_index = 0;

	for (unsigned long i = 0; i < tsx_block_index; i++) {
		unsigned long addr = tsx_block[i].addr;
		int type = tsx_block[i].type;
		int sid = tsx_block[i].sid;
		write_to_block_buffer(addr, type, sid, pid);
	}
}

static inline void pt_on_xabort(pt_recover_arg pid)
{
	ABORT(!stacks[pid].xbegin, "abort outside a transaction");

	stacks[pid].sp = stacks[pid].xbegin;
	stacks[pid].xbegin = NULL;
	tsx_block_index = 0;
}

unsigned int *total_n_packet;
void pt_recover(char *buffer, unsigned int size, pt_recover_arg arg)
{
	unsigned long bytes_remained;
	enum pt_packet_kind kind;
	unsigned char *packet;
	unsigned long packet_len = 0;
	unsigned long last_ip = 0;
	unsigned long curr_addr = 0;
	unsigned char mask;
	unsigned char bit_selector;
	pt_block *curr_block = NULL;
#define RETC_STACK_SIZE 64
	pt_block *retc[RETC_STACK_SIZE] = {0};
	unsigned int retc_index = 0;
	unsigned char mode_payload;

#define NEXT_PACKET() \
do { \
	bytes_remained -= packet_len; \
	packet += packet_len; \
	kind = pt_get_packet(packet, bytes_remained, &packet_len); \
} while (0)

#define FOLLOW_DIRECT_UNTIL(cond) \
do { \
	while (pt_block_is_direct(curr_block) && (!(cond))) { \
		if (pt_block_is_call(curr_block)) { \
			pt_on_call(pt_get_fallthrough_addr(curr_block), arg); \
			retc[retc_index] = curr_block; \
			retc_index = (retc_index + 1) % RETC_STACK_SIZE; \
		} \
		unsigned long target_addr = pt_get_target_addr(curr_block);\
		curr_block = pt_get_target_block(curr_block); \
		pt_on_block(target_addr, arg, pt_get_current_kind(curr_block)); \
		if pt_block_is_syscall(curr_block) \
			pt_on_syscall(curr_block->syscall_num, curr_block->syscall_addr, curr_block->syscall_id, arg); \
	} \
} while(0)

#define FOLLOW_DIRECT() FOLLOW_DIRECT_UNTIL(0)

	packet = (unsigned char*) buffer;
	bytes_remained = size;

	while (bytes_remained > 0) {
		*total_n_packet += 1;
		kind = pt_get_packet(packet, bytes_remained, &packet_len);
		switch (kind) {
		case PT_PACKET_TNTSHORT:
			// TNT packet contains the instruction flow information for conditional
			// direct jumps (Jcc and LOOP) and RETs whose target matches the last
			// NLIP.
			// printf("TNT\n");
			// fflush(stdout);

			mask = (unsigned char)*packet;

			bit_selector = 1 << ((32 - __builtin_clz(mask)) - 1);
			do {
				FOLLOW_DIRECT();
				if (mask & (bit_selector >>= 1)) {
					// jump token
					if (pt_block_is_ret(curr_block)) {
						retc_index = (retc_index + RETC_STACK_SIZE - 1) % RETC_STACK_SIZE;
						pt_on_ret(pt_get_fallthrough_addr(retc[retc_index]), arg);
						curr_block = pt_get_fallthrough_block(retc[retc_index]);
						pt_on_block(pt_get_fallthrough_addr(retc[retc_index]), arg, pt_get_current_kind(curr_block));
						
						if pt_block_is_syscall(curr_block)
							pt_on_syscall(curr_block->syscall_num, curr_block->syscall_addr, curr_block->syscall_id, arg);
					} else {
						unsigned long target_addr = pt_get_target_addr(curr_block);
						curr_block = pt_get_target_block(curr_block);
						pt_on_block(target_addr, arg, pt_get_current_kind(curr_block));
						if pt_block_is_syscall(curr_block)
							pt_on_syscall(curr_block->syscall_num, curr_block->syscall_addr, curr_block->syscall_id, arg);						
					}
				} else {
					// jump not token: the next block starts at the fallthrough_addr
					unsigned long fallthrough_addr = pt_get_fallthrough_addr(curr_block);
					curr_block = pt_get_fallthrough_block(curr_block);
					pt_on_block(fallthrough_addr, arg, pt_get_current_kind(curr_block));
					if pt_block_is_syscall(curr_block)
						pt_on_syscall(curr_block->syscall_num, curr_block->syscall_addr, curr_block->syscall_id, arg);
				}
			} while (bit_selector != 2);
			break;

		case PT_PACKET_TIP:
			// For every indirect jump and procedure call, exception/interrupt, and
			// interrupt return, a Target IP Packet containing destination address
			// is generated.
			// printf("TIP\n");
			// fflush(stdout);
			curr_addr = pt_get_and_update_ip(packet, packet_len, &last_ip);

			if (curr_block) {
				FOLLOW_DIRECT();
				if (pt_block_is_call(curr_block)) {
					pt_on_call(pt_get_fallthrough_addr(curr_block), arg);
					retc[retc_index] = curr_block;
					retc_index = (retc_index + 1) % RETC_STACK_SIZE;
				} else if (pt_block_is_ret(curr_block)) {
					pt_on_ret(curr_addr, arg);
				}
			}

			curr_block = pt_get_block(curr_addr);
			pt_on_block(curr_addr, arg, pt_get_current_kind(curr_block));

			if pt_block_is_syscall(curr_block) {
				pt_on_syscall(curr_block->syscall_num, curr_block->syscall_addr, curr_block->syscall_id, arg);
			}
			break;

		case PT_PACKET_TIPPGE:
			// PGE packets are generated when RTIT (real time instruction trace)
			// is enabled
			// printf("PGE\n");
			// fflush(stdout);
			curr_addr = pt_get_and_update_ip(packet, packet_len, &last_ip);
			curr_block = pt_get_block(curr_addr);
			break;

		case PT_PACKET_TIPPGD:
			// PGD packets are generated when RTIT transitions from a packet
			// generating mode into a disabled mode due to filtering criteria not
			// being met, or disabling RTIT.
			// printf("PGD\n");
			// fflush(stdout);
			if (curr_block)
				FOLLOW_DIRECT();
			pt_get_and_update_ip(packet, packet_len, &last_ip);
			break;

		case PT_PACKET_FUP:
			// printf("FUP\n");
			// fflush(stdout);
			curr_addr = pt_get_and_update_ip(packet, packet_len, &last_ip);
			FOLLOW_DIRECT_UNTIL(pt_in_block(curr_addr, curr_block));
			curr_block = NULL;
			break;

		case PT_PACKET_PSB:
			// A PSB packet is for trace simulation software to identify a trace
			// stream boundary
			// printf("PSB\n");
			// fflush(stdout);
			last_ip = 0;
			do {
				NEXT_PACKET();
				if (kind == PT_PACKET_FUP)
					pt_get_and_update_ip(packet, packet_len, &last_ip);
			} while (kind != PT_PACKET_PSBEND && kind != PT_PACKET_OVF);
			break;

		case PT_PACKET_MODE:
			// printf("MODE\n");
			// fflush(stdout);
			mode_payload = *(packet+1);
			switch ((mode_payload >> 5)) {
			case 0: /* MODE.Exec */
				break;
			case 1: /* MODE.TSX */
				do {
					NEXT_PACKET();
				} while (kind != PT_PACKET_FUP);

				curr_addr = pt_get_and_update_ip(packet, packet_len, &last_ip);
				FOLLOW_DIRECT_UNTIL(pt_in_block(curr_addr, curr_block));
				
				switch ((mode_payload & (unsigned char)0x3)) {
				case 0:
					// tsx commit
					// printf("tsx commit\n");
					pt_on_xcommit(arg);
					break;
				case 1:
					// tsx begin
					// printf("tsx begin\n");
					pt_on_xbegin(arg);
					break;
				case 2:
					// tsx xabort
					// printf("tsx abort\n");
					pt_on_xabort(arg);
					curr_block = NULL;
					break;
				default:
					break;
				}
				break;
			default:
				break;
			}
			break;

		case PT_PACKET_OVF:
			// indicate that the RTIT internal buffer is full and that packets are
			// no longer being generated
			// printf("OVF\n");
			// fflush(stdout);
			do {
				NEXT_PACKET();
			} while (kind != PT_PACKET_FUP);
			curr_addr = pt_get_and_update_ip(packet, packet_len, &last_ip);
			curr_block = pt_get_block(curr_addr);
			break;

		default:
			break;
		}

		bytes_remained -= packet_len;
		packet += packet_len;
	}
}

// return: whether start a new thread
long pt_parse(enum pt_logitem_kind kind, void *item, pt_blocks* _blocks, unsigned int *_total_n_inst, unsigned int *_total_n_packet) {
	struct pt_logitem_buffer *buffer;
	struct pt_logitem_process *process;
	struct pt_logitem_thread *thread;
	// struct pt_logitem_image *image;
	struct pt_logitem_xpage *xpage;
	void *addr;
	struct pt_logitem_fork *fork;
	// struct pt_logitem_audit *audit;
	struct pt_event *sp;
	// char time_str[100];
	// struct timeval time;
	blocks = _blocks;
	// change pos to init blocks
	blocks->pos = 0;
	// record the number of instructions/packets
	total_n_inst = _total_n_inst;
	total_n_packet = _total_n_packet;
	
	switch (kind) {
		case PT_LOGITEM_BUFFER:
			buffer = (struct pt_logitem_buffer *) item;
			// printf("buffer: pid=%lu, size=%lu\n", buffer->pid, buffer->size);
			previous_addr_circular = circular_addr_init();
			pt_recover((char *)(buffer + 1), buffer->size, buffer->pid);
			circular_addr_free(previous_addr_circular);
			break;
		case PT_LOGITEM_PROCESS:
			process = (struct pt_logitem_process *) item;
			printf("process: tgid=%lu, cmd=%s\n", process->tgid, (char *) (process + 1));
			break;
		case PT_LOGITEM_THREAD:
			thread = (struct pt_logitem_thread *) item;
			printf("thread: tgid=%lu, pid=%lu, name=%s\n", thread->tgid,
			thread->pid, thread->name);
			if (stacks[thread->pid].base)
				break;
			stacks[thread->pid].top = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			ABORT(!stacks[thread->pid].top, "stack allocation failed");
			stacks[thread->pid].top += PAGE_SIZE;
			stacks[thread->pid].sp = ((struct pt_event *) stacks[thread->pid].top) - 1;
			stacks[thread->pid].xbegin = NULL;
			return thread->pid;
		case PT_LOGITEM_IMAGE:
			// image = (struct pt_logitem_image *) item;
			// printf("image: tgid=%lu, base=%lx, size=%x, name=%s\n", image->tgid, 
			// image->base, image->size, (char *) (image + 1));
			break;
		case PT_LOGITEM_XPAGE:			
			xpage = (struct pt_logitem_xpage *) item;
			// printf("xpage: tgid=%lu, base=%lx, size=%lx\n", xpage->tgid, xpage->base, xpage->size);
			// 1 code block page and 8 basic block pointer pages
			// details in Figure 3 in Griffin ASPLOS ’17
			for (int i = 1; i < 10; i++) {
				addr = mmap((void *) MIRROR(xpage->base, i), xpage->size,
						PROT_READ | PROT_WRITE, MAP_ANONYMOUS
						| MAP_PRIVATE | MAP_FIXED, -1, 0);
				ABORT((unsigned long) addr != MIRROR(xpage->base, i), "mirror failed");
			}
			// load images from pt trace
			memcpy((void *) PT_IP_TO_CODE(xpage->base), xpage + 1, xpage->size);
			break;
		case PT_LOGITEM_UNMAP:
			ABORT(1, "UNMAP unsupported");
			break;
		case PT_LOGITEM_FORK:
			fork = (struct pt_logitem_fork *) item;
			// printf("fork: parent=%lu, child=%lu\n", fork->parent_pid, fork->child_pid);
			stacks[fork->child_pid].top = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			ABORT(!stacks[fork->child_pid].top, "stack allocation failed");
			stacks[fork->child_pid].top += PAGE_SIZE;
			stacks[fork->child_pid].sp = ((struct pt_event *) stacks[fork->child_pid].top) - 1;
			stacks[fork->child_pid].xbegin = stacks[fork->parent_pid].xbegin;
			ABORT(stacks[fork->child_pid].xbegin, "fork in transaction?");
			/* duplicate call stack from parent thread */
			for (sp = (struct pt_event *)stacks[fork->parent_pid].top - 1; sp > stacks[fork->parent_pid].sp; sp--)
				*(stacks[fork->child_pid].sp--) = *sp;
			break;
		case PT_LOGITEM_SECTION:
			ABORT(1, "PT_LOGITEM_SECTION unsupported");
			break;
		case PT_LOGITEM_THREAD_END:
			ABORT(1, "PT_LOGITEM_THREAD_END unsupported");
			break;
		case PT_LOGITEM_AUDIT:
			// audit = (struct pt_logitem_audit *) item;
			// time.tv_sec =  audit->timestamp;
			// strftime(time_str, 100, "%Y-%m-%dT%T", localtime(&time.tv_sec));
			// printf("audit: sid=%lu, timestamp=%s\n", audit->sid, time_str);
			break;
		default:
			ABORT(1, "unrecognized item type: %d", kind);
	}
	return -1;
}
