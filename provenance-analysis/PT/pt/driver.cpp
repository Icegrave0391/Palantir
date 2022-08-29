#include "driver.h"

int main(int argc, char *argv[]) 
{
	// read pt trace file
	ABORT(argc < 2, "./driver log-file block");
	FILE* trace = fopen(argv[1], "r");
	ABORT(!trace, "open %s failed", argv[1]);

	// whether to print basic blocks
	bool print_block_flag = false;
	if (argc > 2) {
		print_block_flag = true;
	}

	std::chrono::steady_clock sc;
	double t_disa = 0;

	// pt trace integrity check
	trace_integrity_check(trace);

	// read pt traces
	struct pt_logitem_header header;

	pt_blocks *blocks = new pt_blocks {
		.ptr = (pt_block_addr *) malloc(PT_RING_BUFFER_SIZE * sizeof(pt_block_addr)),
		.size = PT_RING_BUFFER_SIZE,
		.pos = 0,
	};

	uint32_t total_n_inst = 0;
	uint32_t total_n_block = 0;
	uint32_t total_n_packet = 0;

	int syscall_index = 0;
	while (fread(&header, 1, sizeof(header), trace)) {
		// deal with xpage
		if (header.size == 0) {
			continue;
		}
		else {
			// undo the seek due to header read
			fseek(trace, -sizeof(header), SEEK_CUR);
		}

		// allocate memory to store the whole item
		void *item = malloc(header.size);
		ABORT(!item, "malloc for item failed");

		// read in
		size_t len = fread(item, 1, header.size, trace);
		ABORT(len != header.size, "unexpected trace ending");

		// parse pt trace
		auto ts_disa = sc.now();
		pt_parse(header.kind, item, blocks, &total_n_inst, &total_n_packet);
		auto te_disa = sc.now();
		t_disa += static_cast<std::chrono::duration<double>>(te_disa - ts_disa).count();

		for (uint64_t i = 0; i < blocks->pos; i++) {
        	uint64_t addr = blocks->ptr[i].addr;
        	enum pt_block_type type =  blocks->ptr[i].type;
			uint16_t pid = blocks->ptr[i].pid;

			total_n_block += 1;

			if (addr > 0x70000000000) {
				if (type != PT_TYPE_SYSCALL) {
					continue;
				}
			}

			if (print_block_flag) {
				std::cout << std::dec << "pid: " << pid << std::hex << " block: \t" << addr << std::endl;
			}

			if (type == PT_TYPE_SYSCALL) {
				int sid = blocks->ptr[i].sid;
				
				// continue if pt parser fail to infer the syscall id
				if (sid == -1) {
					// printf("%d syscall: %lx\n", syscall_index, addr);;
				}
				else {
					// printf("%d syscall: %lx %d %s\n", syscall_index, addr, sid, syscallid2name(sid));
				}
				syscall_index += 1;
			}
		}
		
		free(item);	
	}
	
	std::cout << "#Block " << total_n_block << std::endl;
	std::cout << "#Instruction " << total_n_inst << std::endl;
	std::cout << "#Packet " << total_n_packet << std::endl;

	std::cout << "Disassembly Runtime " << std::fixed << std::setprecision(3)
    << t_disa << " seconds" << std::endl;

	free(blocks->ptr);
    delete(blocks);
	fclose(trace);

	return 0;
}
