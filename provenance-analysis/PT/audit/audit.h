#ifndef _AUDIT_AUDIT_H_
#define _AUDIT_AUDIT_H_

#include <set>
#include <vector>
#include <string>
#include <dirent.h>
#include <iostream>
#include <algorithm>
#include <memory>
#include <fstream>
#include <sstream>

#include "common.h"

std::ostringstream& operator<<(std::ostringstream&, __uint128_t);

#define uint128tostring(bigint)	({					\
	std::ostringstream _stream;						\
	_stream << bigint;								\
	std::string _str = _stream.str();				\
	_str;											\
})

typedef std::tuple<seq_t, offset_t, std::fstream *> seq_offset_t;

typedef uint32_t syscall_id_t;
typedef uint32_t syscall_seq_t;
typedef std::set<syscall_seq_t> taint_tag_t;
typedef std::vector<std::pair<syscall_id_t, taint_tag_t>> taint_syscall_t;
typedef std::map<pid_t, taint_syscall_t> taint_audit_t;

class Audit: public Common {   
public:
    // audit file
    std::string beat_dir;
    std::vector<std::string> beat_files;
    
    // file offset to processes with pid as XX
    std::map<int, std::vector<seq_offset_t>> offset;
    std::vector<std::fstream *> open_file;

    // new audit file
    std::fstream *auditbeat_new;

    Audit(std::string data_dir);
    ~Audit();

    std::vector<std::string> CollectBeatFile();
    
    void CollectEvent(std::string prog_name, std::vector<pid_t> procs);
    void MatchPT(taint_audit_t taint_audit);

    void PrintBeatFile();
};

#endif