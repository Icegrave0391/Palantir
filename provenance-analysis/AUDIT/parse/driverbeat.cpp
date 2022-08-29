#include "driverbeat.h"

int main(int argc, char **argv)
{
	// parse command line arguments
	Config cfg(argc, argv);
	cfg.ConfigBeat();
	
	// Knowledge graph for auditbeat
	KG *infotbl = new KG(auditbeat);

	// define Local File to store KG (no computation)
	LocalStore ls(cfg.embed_data_path, infotbl);

	// visualize in neo4j
	Neo4jdb neo4jdb(cfg.neo4j_config, infotbl);

	if (cfg.loadentity) {
		// load system entities from local files
		EntityLoadFromFile(cfg.embed_data_path, infotbl);
		// print KG information
		infotbl->PrintKG();
	}

	auto beat_dirs = TraverseBeatDir(cfg.auditbeat_data_dir);
	for (auto beat_dir : beat_dirs) {
		std::cout << "Processing Dir: " << beat_dir << std::endl;
		
		// load system info before audting starts
		Loadmetainfo(beat_dir, infotbl);
		
		auto beat_files = CollectBeatFile(beat_dir);
		for (auto beat_file: beat_files) {
			KGBeatParse(beat_file, infotbl);

			// print KG information
			infotbl->PrintKG();

			if (cfg.storeentity) {
				ls.EntityStoreToFile();
			}
		}
	}
	
	// lookup edges related to a process
	if (cfg.lookupproc) {
		std::vector<KGEdge *> edges_of_interest = infotbl->PrintEdges(cfg.lookup_proc_exe, cfg.lookup_proc_pid);
		neo4jdb.Neo4jVizEdge(edges_of_interest);
	}

	// Graph Visualization (does not support large-scale graphs)
	if (cfg.graph)
		neo4jdb.Neo4jVisKG();

	// store system entities locally
	if (cfg.storeentity)
		ls.DumpProcFileSocketEdge2FactSize();

	Tracker tracker = Tracker(infotbl);
	tracker.AdjacencyTable();
	
	do {
		std::cout << "input hash for tracking (0 for quit)" << std::endl;
		std::string target_str;
		std::cin >> target_str;
		hash_t target = std::stol(target_str);
		if (target == 0) {
			break;
		}
		std::vector<KGEdge*> edges_of_interest = tracker.BackwardTrackPT(target);
		std::cout << "With PT: #edges: " << edges_of_interest.size() << std::endl;
		neo4jdb.Neo4jVizEdge(edges_of_interest);
		std::string enter;
		std::cin >> enter;
		edges_of_interest = tracker.BackwardTrack(target);
		std::cout << "Without PT: #edges: " << edges_of_interest.size() << std::endl;
		neo4jdb.Neo4jVizEdge(edges_of_interest);
	} while (true);

	infotbl->FreeInteraction();
	infotbl->FreeNode();
	delete (infotbl);
	return 0;
}
