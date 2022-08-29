#include "driver.h"

int main(int argc, char *argv[]) 
{
	ABORT(argc < 4, "./driver program_in_redis pt_log_file audit_log_file");

	// define program (e.g., nginx) to analysis
	std::string prog_name = argv[1];
	std::cout << "PT analysis on " << prog_name << std::endl;

	// read pt trace file
	FILE* trace = fopen(argv[2], "r");
	ABORT(!trace, "open %s failed", argv[1]);

	// read audit log file
	std::string beat_dir = argv[3];
	Audit audit = Audit(beat_dir);

	std::chrono::steady_clock sc;
	double t_tree = 0;
	double t_taint = 0;
	double t_disa = 0;
	double t_tag = 0;

	// pt trace integrity check
	trace_integrity_check(trace);

	// init taint engine to track information flows
	auto ts_tree = sc.now();
	TaintEngine *taint_engine = new TaintEngine("127.0.0.1", 6379, prog_name);
	auto te_tree = sc.now();
	t_tree = static_cast<std::chrono::duration<double>>(te_tree - ts_tree).count();

	// read pt traces
	struct pt_logitem_header header;

	// created processes in pt traces
	std::vector<pid_t> procs;
	
	// the number of instructions
	uint32_t total_n_inst = 0;
	uint32_t total_n_packet = 0;

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
		long new_pid = pt_parse(header.kind, item, taint_engine->blocks, &total_n_inst, &total_n_packet);
		auto te_disa = sc.now();
		t_disa += static_cast<std::chrono::duration<double>>(te_disa - ts_disa).count();

		// traverse pt blocks and update taint states
		auto ts_taint = sc.now();
		taint_engine->traverseBlocks();
		auto te_taint = sc.now();
		t_taint += static_cast<std::chrono::duration<double>>(te_taint - ts_taint).count();
		// taint_engine->printBlocks();
		// taint_engine->printSyscalls();
		free(item);

		// there is a new process
		if (new_pid != -1) {
			procs.push_back(new_pid);
		}
	}

	std::cout << "#Instruction " << std::dec << total_n_inst << std::endl;
	std::cout << "#Packet " << total_n_packet << std::endl;

	std::cout << "Tree Construction Overhead " << std::fixed << std::setprecision(3)
    << t_tree << " seconds" << std::endl;

	std::cout << "PT Disassembly Overhead " << std::fixed << std::setprecision(3)
    << t_disa << " seconds" << std::endl;

	std::cout << "PT Taint/Traverse Overhead " << std::fixed << std::setprecision(3)
    << t_taint << " seconds" << std::endl;

	std::cout << "PT Taint Overhead " << std::fixed << std::setprecision(3)
    << taint_engine->time << " seconds" << std::endl;

	// taint_engine->PrintTaintAudit();
	
	std::cout << "Feedback taint to audit logs" << std::endl;
	audit.CollectEvent(prog_name, procs);

	auto ts_tag = sc.now();
	audit.MatchPT(taint_engine->taint_audit);
	auto te_tag = sc.now();
	t_tag = static_cast<std::chrono::duration<double>>(te_tag - ts_tag).count();

	std::cout << "PG Tag Overhead " << std::fixed << std::setprecision(3)
    << t_tag << " seconds" << std::endl;

	delete(taint_engine);
	fclose(trace);

	return 0;
}
