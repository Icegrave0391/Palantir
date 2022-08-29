#include "audit.h"

Audit::Audit(std::string data_dir): Common() {
    beat_dir = data_dir;
    beat_files = CollectBeatFile();
    auditbeat_new = new std::fstream(beat_dir + "auditbeat.-1", std::ios::out | std::ios::trunc);
    if (auditbeat_new == NULL) {
        std::cout << "fail to open " << beat_dir + "auditbeat.-1" << std::endl;
    }
    else {
        std::cout << "succeed to open " << beat_dir + "auditbeat.-1" << std::endl;
    }
}

Audit::~Audit() {
    for (auto f_input: open_file) {
        f_input->close();
        delete(f_input);
    }
    auditbeat_new->close();
    delete(auditbeat_new);
}

bool compare_seq(seq_offset_t s1, seq_offset_t s2) {
    return (std::get<0>(s1) > std::get<0>(s2));
}

void Audit::CollectEvent(std::string prog_name, std::vector<pid_t> procs) {
    uint32_t n_log = 0;
    auto prog_file = std::fstream(prog_name, std::ios::out | std::ios::trunc);

    for (auto beat_file: beat_files) {
        // extract events related to process with pid
        std::fstream *f_input = new std::fstream(beat_file, std::ios::in);
        open_file.push_back(f_input);
        std::string line;
        offset_t offset_ = 0;

        // traverse audit log file
        while(std::getline(*f_input, line)) {
            // search for pid in audit logs
            pid_t audit_pid = -1;
            for (pid_t pid: procs) {
                std::string search = "\"pid\":\"" + std::to_string(pid) + "\"";
                auto found_pid = line.find(search);
                if (unlikely(found_pid != std::string::npos)) {
                    audit_pid = pid;
                }
            }
            if (likely(audit_pid == -1)) {
                offset_ = f_input->tellg();
                *auditbeat_new << line << std::endl;
                continue;
            }
            else {
                prog_file << line << std::endl;
                n_log += 1;
            }

            // extract sequence
            auto found_seq = line.find("\"sequence\"");
            if (unlikely(found_seq == std::string::npos)) {
                // seq does not matter for non syscall events
                std::cerr << "Cannot find sequence in " << line << std::endl;
                exit(-1);
            }
            auto seq_start = found_seq + 11;
            auto seq_end = line.find(",", seq_start + 1);
            if (seq_end == std::string::npos) {
                seq_end = line.find("}", seq_start) + 1;
            }
            seq_t seq = std::stol(line.substr(seq_start, seq_end - seq_start));
            
            offset[audit_pid].push_back(std::make_tuple(seq, offset_, f_input));
            offset_ = f_input->tellg();
        }

        f_input->clear();
    }

    for (auto &it_offset: offset) {
        std::sort(it_offset.second.begin(), it_offset.second.end());
    }

    std::cout << "#Logs" << std::dec << n_log << std::endl;
}

// match audit logs with syscalls from pt traces
void Audit::MatchPT(taint_audit_t taint_audit) {
    for (auto it_offset: offset) {
        pid_t pid = it_offset.first;
        std::vector<seq_offset_t> offset_pid = it_offset.second;

        // locate taint for process with pid
        auto taint_pid = taint_audit[pid];
        auto taint_pid_size = taint_pid.size();
        if (taint_pid_size == 0) {
            std::cerr << "taint_pid is empty for " << pid << std::endl;
            continue;
        }
        else {
            std::cout << "process: "  << std::dec << pid << std::endl;
            std::cout << "#audit logs is " << offset_pid.size() << std::endl;
            std::cout << "#pt syscalls is " << taint_pid_size << std::endl;
        }

        unsigned long index = 0;
        std::vector<seq_t> seq_vec;

        for (auto event_offset: offset_pid) {
            seq_t seq = std::get<0>(event_offset);
            offset_t offset_ = std::get<1>(event_offset);
            std::fstream *f_input = std::get<2>(event_offset);
            
            // read line based on offset
            std::string line;
            f_input->seekg(offset_, std::ios::beg);
            std::getline(*f_input, line);

            // parse json object
            Json::Value event;
            Json::CharReaderBuilder builder {};
            auto reader = std::unique_ptr<Json::CharReader>(builder.newCharReader());
            JSONCPP_STRING errs;
            const auto parseSuccessful = reader->parse(line.c_str(),
                                                    line.c_str() + line.length(),
                                                    &event,
                                                    &errs);
            if (unlikely(!parseSuccessful)) {
                std::cerr << "Fail to parse file" << __FILE__ << std::endl;
                return;
            }

            // syscall from audit logs
            std::string audit_syscall_name = Jval2str(event["auditd"]["data"]["syscall"]);
            int audit_syscall_id = syscallname2id(audit_syscall_name);
            
            // std::cout << audit_syscall_name << " " << audit_syscall_id << " " << uint128tostring(seq) << std::endl;
            // continue;

            // syscall from pt traces
            int pt_syscall_id = taint_pid.at(index).first;

            // match syscalls in audit logs and pt traces
            if (audit_syscall_id == pt_syscall_id) {
                seq_vec.push_back(seq);
                taint_tag_t taint_source = taint_pid.at(index).second;

                // add taint_source to event json object
                std::string source_str;
                for (auto source: taint_source) {
                    source_str += uint128tostring(seq_vec.at(source));
                    source_str += " ";
                }
                // delete the last " "
                source_str = source_str.substr(0, source_str.size()-1);
                if (source_str == "") {
                    source_str = "-1";
                }
                event["auditd"]["pt"] = source_str;

                // print audit log info
                // std::cout << std::dec << index << "\t" << uint128tostring(seq);
                // std::cout << "\t" << audit_syscall_name;
                // for (auto source: taint_source) {
                //     std::cout << "\t" << source << "\t" << uint128tostring(seq_vec.at(source)); 
                // }
                // std::cout << std::endl;

                // modify original audit logs to 
                if (taint_source.empty() == false or pt_syscall_id == 1 or pt_syscall_id == 20) {
                    Json::FastWriter fast_writer;
                    line = fast_writer.write(event);
                }

                // end of pt trace
                if (++index == taint_pid_size) {
                    break;
                }
            }
            
            *auditbeat_new << line << '\n';
        }
        std::cout << std::endl;
    }
}

std::vector<std::string> Audit::CollectBeatFile() {
	// collect and sort log file names in auditbeat_data_dir
	// must process events Chronologically due to event dependency
	struct dirent *entry;
	DIR *dp = opendir(beat_dir.c_str());
	if (dp == NULL) {
		std::cerr << beat_dir << " does not exist or could not be read " << __FILE__ << " " <<  __LINE__ << std::endl;
		exit(EXIT_FAILURE);
	}
	std::vector<int> data_file_idx;
	while ((entry = readdir(dp))) {
		std::string log_path(entry->d_name);
		auto pos = log_path.find("auditbeat.");
		if (pos != std::string::npos) {
			std::string file_idx_str = log_path.substr(pos + 10);
            int file_idx_int = std::stoi(file_idx_str);
            if (file_idx_int != -1) {
                data_file_idx.push_back(file_idx_int);
            }
		} 
	}
	std::sort(data_file_idx.rbegin(), data_file_idx.rend());

	// collect log file paths in chronological order
	std::vector<std::string> auditbeat_files_path;
	for (auto idx: data_file_idx) {
		auditbeat_files_path.push_back(beat_dir + "auditbeat." + std::to_string(idx));
	}
	auditbeat_files_path.push_back(beat_dir + "auditbeat");

	closedir (dp);
	return auditbeat_files_path;
}

void Audit::PrintBeatFile() {
    for (auto beat_file: beat_files) {
        std::cout << beat_file << std::endl;
    }
}
