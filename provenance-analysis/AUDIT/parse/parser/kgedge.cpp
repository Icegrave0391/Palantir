#include "kgedge.h"

// for auditbeat
KGEdge::KGEdge(hash_t *n1, hash_t *n2, EdgeType_t r, seq_t seq_, sess_t sess_, std::string timestamp_) {
	e_id = 0;
	n1_id = n1;
	n2_id = n2;
	relation = r;
	seq = seq_;
	sess = sess_;
	timestamp = timestamp_;
}

// for auditbeat with pt trace
KGEdge::KGEdge(hash_t *n1, hash_t *n2, EdgeType_t r, seq_t seq_, sess_t sess_, std::string timestamp_, std::string pt_) {
	e_id = 0;
	n1_id = n1;
	n2_id = n2;
	relation = r;
	seq = seq_;
	sess = sess_;
	timestamp = timestamp_;

	// parse pt_ into pt_vec for backward tracking
	pt_str = pt_;
	if (pt_str == "null") {
		return;
	}
	std::string pt_token;
	size_t pos = 0;
	while((pos = pt_.find(" ")) != std::string::npos) {
		pt_token = pt_.substr(0, pos);
		pt_vec.push_back((biguint_t)stoint128_t(pt_token));
		pt_ = pt_.substr(pos);
	}
	pt_vec.push_back((biguint_t)stoint128_t(pt_));
}

// for darpa / loading auditbeat data
KGEdge::KGEdge(hash_t n1, hash_t n2, EdgeType_t r, seq_t seq_, sess_t sess_, hash_t uuid, std::string timestamp_) {
	e_id = uuid;
	n1_hash = n1;
	n2_hash = n2;
	relation = r;
	seq = seq_;
	sess = sess_;
	timestamp = timestamp_;
} 
