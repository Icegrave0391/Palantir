#ifndef SHERLOCK_UTIL_TRACKER_H_
#define SHERLOCK_UTIL_TRACKER_H_

#include "parser/kg.h"
#include <stack>
#include <set>
#include <algorithm>

// Connection node map records edges connected to nodes
// hash_t represents node id.
typedef std::unordered_map <hash_t, std::vector<KGEdge*>, HashFunction> cnnnode_map;

class Tracker
{
public:
	KG *infotbl;
	// outnode represents outgoing edges
	cnnnode_map outnode;
	// innode represents ingoing edges
	cnnnode_map innode;

	Tracker(KG *);
	~Tracker();
	
	void AdjacencyTable();
	void PrintTracker();
	std::vector<KGEdge*> ForwardTrack(hash_t);
	std::vector<KGEdge*> BackwardTrack(hash_t);
	// forward tracking while record accessed files
	std::vector<KGEdge*> ForwardTrackKG(hash_t, std::set<hash_t> &);

	// graph traversal with PT information
	std::vector<KGEdge*> BackwardTrackPT(hash_t n_hash);
};

#endif
