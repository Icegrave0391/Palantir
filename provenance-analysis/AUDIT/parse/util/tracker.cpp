#include "tracker.h"

Tracker::Tracker(KG *_infotbl) {
	infotbl = _infotbl;
}

Tracker::~Tracker() {
	for (auto &node: outnode) {
		node.second.clear();
	}
	for (auto &node: innode) {
		node.second.clear();
	}
}

struct less_than_seq {
    inline bool operator() (KGEdge* &a, KGEdge* &b) {
        return (a->seq < b->seq);
    }
};

void Tracker::AdjacencyTable() {
	edge_map em = infotbl->KGEdgeTable;
	for (auto it: em) {
		KGEdge *edge = it.second;
		hash_t n1_hash = edge->n1_hash;
		outnode[n1_hash].push_back(edge);
		hash_t n2_hash = edge->n2_hash;
		innode[n2_hash].push_back(edge);
	}

	for (auto it = outnode.begin(); it != outnode.end(); it++) {
		auto &edges = it->second;
		sort(edges.begin(), edges.end(), less_than_seq());
	}

	for (auto it = innode.begin(); it != innode.end(); it++) {
		auto &edges = it->second;
		sort(edges.begin(), edges.end(), less_than_seq());
	}
}

/*  Forward tracking on a node in KG
	forward tracking: 5677179269860443547 is /home/yinfang/a.c
	hash_t poi_forward = 5677179269860443547;
	std::vector<KGEdge *> forward_edges = tracker.ForwardTrack(poi_forward);
*/
std::vector<KGEdge*> Tracker::ForwardTrack(hash_t n_hash) {
	std::vector<KGEdge*> connected_edges;
	std::stack<hash_t> node_stack;
	std::stack<seq_t> time_stack;
	std::unordered_map <hash_t, bool> visited;
	node_map &nm = infotbl->NoiseTable;

	// we record system activities (write, create, read) that work on this node
	// even though they are out of reach during forward tracking
	// This is bec forward tracking is to abstract behaviors while
	// backward tracking is to analyze forensics
	auto in_edges = innode.find(n_hash);
	auto out_edges_excp = outnode.find(n_hash);
	if (in_edges == innode.end() && out_edges_excp == outnode.end()) {
		std::cout << "Cannot find this node in both innode and outnode map => cannot do forward tracking" 
				<< std::endl; 
	}

	if (in_edges != innode.end()) {
		for (auto in_edge: in_edges->second) {
			connected_edges.push_back(in_edge);
		}
	}

	// adapted DFS on node of interest
	node_stack.push(n_hash);
	time_stack.push(0);
	visited[n_hash] = true;
	while (!node_stack.empty()) {
		hash_t n_next = node_stack.top();
		node_stack.pop();
		seq_t t_next = time_stack.top();
		time_stack.pop();

		auto out_edges = outnode.find(n_next);
		if (out_edges == outnode.end()) {
			continue;
		}

		for (auto out_edge: out_edges->second) {
			// the timestamp of each following edge
			// has to be monotonically increasing from all previous edges.
			seq_t out_edge_seq = out_edge->seq;
			if (t_next > out_edge_seq) {
				continue;
			}
			connected_edges.push_back(out_edge);

			hash_t out_node = out_edge->n2_hash;

			// don't track previously seen nodes
			if (visited[out_node]) {
				continue;
			}

			// stop at externel socket which cause dependency explosion problem
			NodeType_t out_node_type = infotbl->SearchNodeType(out_node);
			if (out_node_type == NodeType_t::Socket) {
				continue;
			}

			// stop at noisy nodes (filefox) which cause dependency explosion problem
			auto it_obj = nm.find(out_node);
			if (it_obj != nm.end()) {
				continue;
			}

			node_stack.push(out_node);
			time_stack.push(out_edge_seq);
			visited[out_node] = true;
			// we record system activities (write, create) that work on this node
			// even though they are out of reach during forward tracking
			auto in_edges = innode.find(out_node);
			if (in_edges == innode.end()) {
				continue;
			}
			for (auto in_edge: in_edges->second) {
				hash_t in_node = in_edge->n1_hash;
				if (in_node == n_next) {
					continue;
				}
				connected_edges.push_back(in_edge);
			}
		}
	}
	return connected_edges;
}

// Different from ForwardTrack, ForwardTrackKG is used to summarize behaviors
// merge_file is used to extract behaviors which is the subset of another behavior
std::vector<KGEdge*> Tracker::ForwardTrackKG(hash_t n_hash, std::set<hash_t> &merge_file) {
	std::vector<KGEdge*> connected_edges;
	std::stack<hash_t> node_stack;
	std::stack<seq_t> time_stack;
	std::unordered_map <hash_t, bool> visited;
	std::set<hash_t> out_accessed_file;
	node_map &nm = infotbl->NoiseTable;

	// we record system activities (write, create, read) that work on this node
	// even though they are out of reach during forward tracking
	// This is bec forward tracking is to abstract behaviors while
	// backward tracking is to analyze forensics
	auto in_edges = innode.find(n_hash);
	if (in_edges != innode.end()) {
		for (auto in_edge: in_edges->second) {
			connected_edges.push_back(in_edge);
		}
	}

	// // skip a file if it's in noisy file set
	auto found = nm.find(n_hash);
	if (found != nm.end()) {
		return connected_edges;
	}

	// adapted DFS on node of interest
	node_stack.push(n_hash);
	time_stack.push(0);
	visited[n_hash] = true;
	while (!node_stack.empty()) {
		hash_t n_next = node_stack.top();
		node_stack.pop();
		seq_t t_next = time_stack.top();
		time_stack.pop();

		auto out_edges = outnode.find(n_next);
		if (out_edges == outnode.end()) {
			continue;
		}

		for (auto out_edge: out_edges->second) {
			// the timestamp of each following edge
			// has to be monotonically increasing from all previous edges.
			seq_t out_edge_seq = out_edge->seq;
			if (t_next > out_edge_seq) {
				continue;
			}
			connected_edges.push_back(out_edge);

			hash_t out_node = out_edge->n2_hash;
			// don't track previously seen nodes
			if (visited[out_node]) {
				continue;
			}

			// stop at externel socket which cause dependency explosion problem
			NodeType_t out_node_type = infotbl->SearchNodeType(out_node);
			if (out_node_type == NodeType_t::Socket) {
				continue;
			}

			// stop at noisy nodes (e.g., filefox) which cause dependency explosion problem
			found = nm.find(out_node);
			if (found != nm.end()) {
				continue;
			}

			node_stack.push(out_node);
			time_stack.push(out_edge_seq);
			visited[out_node] = true;
			out_accessed_file.insert(out_node);

			// merge two behaviors if one is a subset of the other
			if (out_node_type == NodeType_t::File) {
				merge_file.insert(out_node);
			}

			// we record system activities (write, create) that work on this node
			// even though they are out of reach during forward tracking
			auto in_edges = innode.find(out_node);
			if (in_edges == innode.end()) {
				continue;
			}
			for (auto in_edge: in_edges->second) {
				hash_t in_node = in_edge->n1_hash;
				if (in_node == n_next) {
					continue;
				}
				connected_edges.push_back(in_edge);

				// whether in_node (file) behavior is a subset of the current behavior
				NodeType_t in_node_type = infotbl->SearchNodeType(in_node);
				if (in_node_type != NodeType_t::File) {
					continue;
				}

				auto in_edges_ = innode.find(in_node);
				if (in_edges_ != innode.end()) {
					continue;
				}

				auto out_edges_ = outnode.find(in_node);
				int merge_file_flag = 1;
				for (auto out_edge: out_edges_->second) {
					hash_t out_node_ = out_edge->n2_hash;
					auto it = out_accessed_file.find(out_node_);
					if (it == out_accessed_file.end()) {
						merge_file_flag = 0;
						continue;
					}
				}
				if (merge_file_flag) {
					merge_file.insert(in_node);
				}
			}
		}
	}
	return connected_edges;
}

/*  Backward tracking on a node in KG
	backward tracking: 7600404975456846803 is /home/yinfang/a.out
	hash_t poi_backward = 7600404975456846803;
	std::vector<KGEdge *> backward_edges = tracker.BackwardTrack(poi_backward);
	Todo: not tested. cannot guarantee it is correct
*/
std::vector<KGEdge*> Tracker::BackwardTrack(hash_t n_hash) {
	std::vector<KGEdge*> connected_edges;
	std::stack<hash_t> node_stack;
	std::stack<seq_t> time_stack;
	std::unordered_map <hash_t, bool> visited;

	// adapted DFS on node of interest
	node_stack.push(n_hash);
	time_stack.push(INT64_MAX);
	visited[n_hash] = true;
	while (!node_stack.empty()) {
		hash_t n_next = node_stack.top();
		node_stack.pop();
		seq_t t_next = time_stack.top();
		time_stack.pop();
		visited[n_next] = true;
		
		auto in_edges = innode.find(n_next);
		if (in_edges == innode.end()) {
			continue;
		}

		// std::cout << "\n" << uint128tostring(t_next) << ":";
		for (auto in_edge: in_edges->second) {
			// the timestamp of each following edge
			// has to be monotonically increasing from all previous edges
			seq_t in_edge_seq = in_edge->seq;
			if (t_next < in_edge_seq) {
				continue;
			}
			connected_edges.push_back(in_edge);
			hash_t in_node = in_edge->n1_hash;
			if (visited[in_node]) {
				continue;
			}

			node_stack.push(in_node);
			time_stack.push(in_edge_seq);
			visited[in_node] = true;
		}
	}
	return connected_edges;
}

/*  Backward tracking on a node in KG with PT information
	backward tracking: 7600404975456846803 is /home/yinfang/a.out
	hash_t poi_backward = 7600404975456846803;
	std::vector<KGEdge *> backward_edges = tracker.BackwardTrackPT(poi_backward);
	Todo: not tested. cannot guarantee it is correct
*/
std::vector<KGEdge*> Tracker::BackwardTrackPT(hash_t n_hash) {
	std::vector<KGEdge*> connected_edges;
	
	// stack of node, timestamp, pt_vec
	std::stack<std::tuple<hash_t, seq_t, std::vector<seq_t>>> node_stack;

	// visited nodes during graph traversal
	std::unordered_map <hash_t, bool> visited;

	// adapted DFS on node of interest
	node_stack.push(std::make_tuple(n_hash, INT64_MAX, std::vector<seq_t>()));
	visited[n_hash] = true;
	while (!node_stack.empty()) {
		hash_t n_next = std::get<0>(node_stack.top());
		seq_t t_next = std::get<1>(node_stack.top());
		std::vector<seq_t> pt_next = std::get<2>(node_stack.top());
		node_stack.pop();
		visited[n_next] = true;
		
		// continue if there is no in_edge for n_next
		auto in_edges = innode.find(n_next);
		if (in_edges == innode.end()) {
			continue;
		}	

		// traverse all in_edges
		for (auto in_edge: in_edges->second) {
			// the timestamp of each following edge
			// has to be monotonically increasing from all previous edges
			seq_t in_edge_seq = in_edge->seq;
			if (t_next < in_edge_seq) {
				continue;
			}

			// refine information flow with PT information
			if (!pt_next.empty()) {
				if (std::find(pt_next.begin(), pt_next.end(), in_edge_seq) == pt_next.end()) {
					continue;
				}
			}
			
			connected_edges.push_back(in_edge);

			// no need to add the node to the stack if visited before
			hash_t in_node = in_edge->n1_hash;
			if (visited[in_node]) {
				continue;
			}

			// use PT to refine information flow
			std::vector<seq_t> pt_vec = in_edge->pt_vec;
			node_stack.push(std::make_tuple(in_node, in_edge_seq, pt_vec));

			if (pt_vec.empty()) {
				visited[in_node] = true;
			}
		}
	}

	return connected_edges;
}

void Tracker::PrintTracker() {
	// print outnode map
	for (auto node: outnode) {
		std::cout << "outnode: " << node.first << std::endl;
		std::vector<KGEdge*> edges = node.second;
		for (auto edge: edges) {
			std::cout << uint128tostring(edge->seq) << " ";
		}
		std::cout << std::endl;
	}
	// print innode map
	for (auto node: innode) {
		std::cout << "innode: " << node.first << std::endl;
		std::vector<KGEdge*> edges = node.second;
		for (auto edge: edges) {
			std::cout << uint128tostring(edge->seq) << " ";
		}
		std::cout << std::endl;
	}
}
