#include "taintsummary.h"

TaintSummary::TaintSummary(const char *ip, int port, std::string prog_name): Redis(ip, port, prog_name) {    
    /* init plt address range */
    initPlt();
    printPlt();

    /* init tainting scope address range */
    initStartTaint();
    printStartTaint();

    /* obtain all keys from redis db */
    std::cout << "Geting all taint summaries" << std::endl;
    getAllTS();

    /* obtain the number of symbol */
    initSymbolNum();

    /* init adj_map_forward and adj_map_backward */
    std::cout << "Initing adj_map_forward" << std::endl;
    initAdjmap(ADJMAP_FORWARD);
    // initAdjmap(ADJMAP_BACKWARD);
    // std::cout << "\nadj_map_forward" << std::endl;
    // printAdjmap(adj_map_forward);
    // std::cout << "\nadj_map_backward" << std::endl;
    // printAdjmap(adj_map_backward);

    /* init adj_map with context information */
    std::cout << "Initing adj_map" << std::endl;
    updateAdjmap();
    // std::cout << "\nadj_map: after update" << std::endl;
    // printAdjmap(adj_map);
    // std::cout << "\nprefix_map: after update" << std::endl;
    // printPrefixmap();

    /* init iterator used to traverse adj_map */
    curr_in_scope = true;
    ret_from_outscope = 0;
    last_is_clone = false;
    last_clone_it = adj_map.end();

    /* init taint summary for every adj_node in adj_map */
    std::cout << "Initing taint summary in adj_map" << std::endl;
    initAdjTS();

    /* test */
    // traverseAdjmap(0x400835, PT_TYPE_CALL);
    // traverseAdjmap(0x4005d0, PT_TYPE_BLOCK);
    // traverseAdjmap(0x400856, PT_TYPE_CALL);
    // traverseAdjmap(0x4006d2, PT_TYPE_CALL);
    // traverseAdjmap(0x4005e0, PT_TYPE_BLOCK);
    // traverseAdjmap(0x4006f3, PT_TYPE_BLOCK);

    printMaxNumContext(adj_map);
}

void TaintSummary::printMaxNumContext(adjmap _adj_map) {
    int max_num = 0;
    for (auto map_itr: _adj_map) {
        auto adj_list = map_itr.second;
        int size = adj_list.size();
        if (size > max_num) {
            max_num = size;
        }
    }
    std::cout << std::dec << "Max #taint summuries in the same context: " << max_num << std::endl;
    std::cout << std::dec << "#context: " << _adj_map.size() << std::endl;
}

TaintSummary::~TaintSummary() {
    for (auto ctx_ts: all_ts) {
        taint_summary *ts = ctx_ts.second;
        std::vector<std::array<int, 3>>().swap(ts->unit);
        std::vector<std::vector<int>>().swap(ts->rel_index);
        std::vector<std::vector<int>>().swap(ts->rel);

        free(ts);
    }

    freeAdjmap();
}

void TaintSummary::initPlt() {
    std::string plt_str = prog_name + ":.plt";
    std::vector<std::string> plt_value = getListValue(plt_str.c_str());
    if (plt_value.size() == 0) {
        std::cerr << "Cannot find plt address range in redis" << std::endl;
        exit(-1);
    }
    plt_addr.at(0) = std::stoi(plt_value.at(1));
    int plt_size = std::stoi(plt_value.at(0));
    plt_addr.at(1) = plt_addr.at(0) + plt_size;

    freeReplyObject(value_reply);

    std::string hook_str = prog_name + ":.hook";
    std::vector<std::string> hook_value = getListValue(hook_str.c_str());
    if (hook_value.size() == 0 ) {
        std::cerr << "Cannot find hook addresses in redis" << std::endl;
        // exit(-1);
    }
    for (auto value: hook_value) {
        hook_addr.push_back(std::stoi(value));
    }

    freeReplyObject(value_reply);
}

void TaintSummary::initStartTaint() {
    std::string start_str = prog_name + ":.start";
    std::vector<std::string> start_value = getListValue(start_str.c_str());
    if (start_value.size() == 0) {
        std::cerr << "Cannot find start address range in redis" << std::endl;
        // exit(-1);
    }
    for (auto value: start_value) {
        std::cout << value << std::endl;
        start_addr.push_back(std::stoul(value.substr(2), nullptr, 16));
    }

    freeReplyObject(value_reply);
}

void TaintSummary::initSymbolNum() {
    std::string symbol_str = prog_name + ":.symbol_num";
    std::string value = getStringValue(symbol_str.c_str());
    symbol_num = std::stoi(value);
    freeReplyObject(value_reply);
}

std::list<mem_addr_t> TaintSummary::parseCallsite(std::string context, int order) {
    size_t last = 0;
    size_t next = 0;
    std::list<mem_addr_t> addrs;
    bool last_addr = false;
    
    do {
        if ((next = context.find(":", last)) == std::string::npos) {
            last_addr = true;
        }

        std::string token = context.substr(last, next - last);
        mem_addr_t addr = std::stol(token, 0, 16);
        if (order == ADJMAP_BACKWARD)
            addrs.push_front(addr);
        else
            addrs.push_back(addr);

        last = next + 1;
    } while (last_addr == false);

    return addrs;
}

adjlist &TaintSummary::addAdjmap(std::string addr, int order) {
    if (order == ADJMAP_BACKWARD) {
        auto ret = adj_map_backward.insert(std::pair<std::string, adjlist>(addr, adjlist()));
        return ret.first->second;
    }
    else if (order == ADJMAP_FORWARD) {
        auto ret = adj_map_forward.insert(std::pair<std::string, adjlist>(addr, adjlist()));
        return ret.first->second;
    }
    else {
        auto ret = adj_map.insert(std::pair<std::string, adjlist>(addr, adjlist()));
        return ret.first->second;
    }
}

adjnode *TaintSummary::addAdjlist(adjlist &exist_adjlist, mem_addr_t addr) {
    // whether addr_next exist in adj_list
    for (auto old_adj_node: exist_adjlist) {
        if (old_adj_node->addr == addr) {
            return old_adj_node;
        }
    }
    
    // addr_next does not exist in adjlist
    adjnode *new_adj_node = NULL;
    new_adj_node = (struct adjnode*) malloc(sizeof(struct adjnode));
    memset((void *) new_adj_node, 0, sizeof(adjnode));
    
    new_adj_node->addr = addr;
    new_adj_node->next = adj_map.end();
    new_adj_node->previous = adj_map.end();
    new_adj_node->traverse_ret = false;

    exist_adjlist.push_back(new_adj_node);

    return new_adj_node;
}

void TaintSummary::initPrefixMap() {
    for (auto addr: start_point) {
        std::set<std::string> prefix;
        prefix.insert("");
        prefix_map[addr] = prefix;
    }
}

void TaintSummary::initAdjMap() {
    for (auto addr: start_point) {
        std::string addr_str = addr + "-";
        adjlist &exist_adjlist = addAdjmap(addr_str, ADJMAP);
        adjnode* adj_node = addAdjlist(exist_adjlist, str_to_uint64(addr));
        adj_node->next = adj_map.find(addr_str);
    }
}

void TaintSummary::updateAdjmap(std::set<std::string> prefix, std::string child) {
    for (std::string addr_str: prefix) {
        adjlist &exist_adjlist = addAdjmap(addr_str, ADJMAP);
        addAdjlist(exist_adjlist, str_to_uint64(child));
    }
}

std::set<std::string> TaintSummary::backwardUpdate(std::string target, std::string noise) {
    // obtain backward children
    auto it_adj = adj_map_backward.find(target);
    if (it_adj == adj_map_backward.end()) {
        std::cerr << "Cannot find " << target << " in adj_map_forward" << std::endl;
        exit(-1);
    }
    adjlist children = it_adj->second;

    // reach a start point
    if (children.empty()) {
        seen_start_point.insert(target);
    }

    std::set<std::string> prefix;
    for (auto child: children) {
        std::string child_addr = uint64_to_str(child->addr);

        if (child_addr == noise)
            continue;
        
        // determine if child_addr in prefix_map
        std::set<std::string> child_prefix_tmp;
        auto it = prefix_map.find(child_addr);
        if (it != prefix_map.end()) {
            child_prefix_tmp = it->second;
        }
        else {
            std::string empty;
            child_prefix_tmp = backwardUpdate(child_addr, empty);      
        }

        std::set<std::string> child_prefix;
        for (std::string s: child_prefix_tmp)
            child_prefix.insert(s + child_addr + "-");

        prefix.insert(child_prefix.begin(), child_prefix.end());
    }

    prefix_map[target] = prefix;

    updateAdjmap(prefix, target);

    return prefix;
}

void TaintSummary::forwardUpdate(std::string target) {
    // obtain forward children
    auto it_adj = adj_map_forward.find(target);
    if (it_adj == adj_map_forward.end()) {
        std::cerr << "Cannot find target in adj_map_forward" << std::endl;
        exit(-1);
    }
    adjlist children = it_adj->second;

    // obtain target prefix
    auto it_prefix = prefix_map.find(target);
    if (it_prefix == prefix_map.end()) {
        std::cerr << "Cannot find target in prefix_map" << std::endl;
        exit(-1);
    }
    std::set<std::string> target_prefix = it_prefix->second;

    // prefix from forward propagation
    std::set<std::string> target2child_prefix;
    for (auto p: target_prefix) {
        target2child_prefix.insert(p + target +  "-");
    }

    for (auto child: children) {
        std::string child_addr = uint64_to_str(child->addr);

        // handle function recursion
        bool child_in_prefix = false;
        for (auto p: target_prefix) {
            if (p.find(child_addr) != std::string::npos) {
                child_in_prefix = true;
            }
        }

        // Todo: might trigger bug
        prefix_map[child_addr] = target2child_prefix;
        updateAdjmap(target2child_prefix, child_addr);

        if (child_in_prefix) {
            continue;
        }

        // prefix from backward propagation (not necessary as we perform
        // forwardUpdate on all start points)
        // std::set<std::string> prefix = backwardUpdate(child_addr, target);

        // unify prefix from forward and backward propagation
        // std::set<std::string> child_prefix;
        // child_prefix.insert(target2child_prefix.begin(), target2child_prefix.end());
        // child_prefix.insert(prefix.begin(), prefix.end());
        // prefix_map[child_addr] = child_prefix;
        // updateAdjmap(child_prefix, child_addr);

        forwardUpdate(child_addr);
    }
}

void TaintSummary::updateAdjmap() {
    // init prefix_map and adj_map for start points
    initPrefixMap();
    initAdjMap();

    // start forward propagation with all start_point
    for (auto addr: start_point) {
        if (seen_start_point.find(addr) == seen_start_point.end())  {
            forwardUpdate(addr);
        }
    }

    // update previous/next/traverse_ret in every adj_node
    createTraverseIndex();
}

void TaintSummary::initAdjmap(int order) {
    for (auto ctx_ts: all_ts) {
        std::string context = ctx_ts.first;

        // obtain call-site information
        std::list<mem_addr_t> addrs = parseCallsite(context, order);

        mem_addr_t addr = addrs.front();
        std::string addr_str = uint64_to_str(addr);
        auto it_addr = addrs.begin();
        do {
            // add adjmap for every addr in addrs
            adjlist &exist_adjlist = addAdjmap(addr_str, order);

            it_addr++;
            if (it_addr == addrs.end()) {
                break;
            }

            // add adjlist for the addr_next in addrs           
            addr = *it_addr;
            addAdjlist(exist_adjlist, addr);
            addr_str = uint64_to_str(addr);
        } while(1);

        // start points in the forward adjmap
        if (order == ADJMAP_FORWARD && addrs.size() == 1) {
            start_point.insert(addr_str);
        }
    }

    start_point.insert("0");
}

void TaintSummary::createTraverseIndex() {
    for (auto adj: adj_map) {
        auto addr_head = adj.first;
        auto adj_list = adj.second;

        for (auto adj_node: adj_list) {
            // identify blocks where traverse_ret (plt/hook) should be labeled true
            mem_addr_t addr = adj_node->addr;
            if (addr >= plt_addr.at(0) and addr <= plt_addr.at(1)) {
                adj_node->traverse_ret = true;
            }

            if (std::find(hook_addr.begin(), hook_addr.end(), addr) != hook_addr.end()) {
                adj_node->traverse_ret = true;
            }

            if (adj_list.size() == 1 and
                addr_head.find(uint64_to_str(addr)) != std::string::npos) {
                adj_node->traverse_ret = true;
            }

            // update next iterator in adj_node
            auto addr_next = addr_head + uint64_to_str(addr) + "-";
            auto it_next = adj_map.find(addr_next);
            if (it_next != adj_map.end()) {
                adj_node->next = it_next;
            }
            // adj_node would be assigned NULL if adj_node does not have any
            // child, i.e., it_next == adj_map.end()

            // update previous iterator in adj_node
            int found_first = addr_head.find_last_of("-");
            int found_second = addr_head.substr(0, found_first).find_last_of("-");
            if (found_second != -1) {
                std::string addr_previous = addr_head.substr(0, found_second + 1);
                auto it_previous = adj_map.find(addr_previous);
                if (it_previous != adj_map.end()) {
                    adj_node->previous = it_previous;
                }
                else {
                    std::cerr << "Cannot find " << addr_previous << " in update previous iterator in adj_node" << std::endl;
                    exit(-1);
                }
            }
        }
    }
}

adjnode *TaintSummary::traverseAdjmap(mem_addr_t addr, enum pt_block_type type, pid_t pid) {
    // auto t1 = sc.now();

    // (designed for multi-thread adjmap traversal) 
    // search for taint_head with pid to traverse adjmap
    auto search_head = taint_head.find(pid);
    if (search_head == taint_head.end()) {
        // pid is not created in taint_head
        if (last_clone_it == adj_map.end()) {
            // the first parent process
            taint_head[pid] = adj_map.find("0-");
        }
        else {
            taint_head[pid] = last_clone_it;
        }
    }
    else {
        if (last_is_clone) {
            last_clone_it = search_head->second;
            last_is_clone = false;
        }
    }
    adjmap::iterator &head = taint_head[pid];

    if (head == adj_map.end()) {
        head = adj_map.find("0-");
        // std::cout << "addr " << std::hex << addr << " after taint analysis" << std::endl;
        // auto t2 = sc.now();
        // time1 += static_cast<std::chrono::duration<double>>(t2 - t1).count();
        return NULL;
    }

    // return NULL if current block is beyond the scope of taint analysis
    if (curr_in_scope == false) {
        if (type == PT_TYPE_CALL) {
            ret_from_outscope += 1;  

            // Todo: handle function call to .bss in WGET (invalidate_persistent)
            // if (unlikely(addr == 0x436284 or addr == 0x43628d)) {
            //     ret_from_outscope -= 1;   
            // } 

            // Todo: handle function call in CURL to external lib
            // if (unlikely(addr == 0x415cc0 or addr == 0x41646e
            // or addr == 0x416991 or addr == 0x416d32)) {
            //    ret_from_outscope -= 1;   
            // } 
        }
        else if (type == PT_TYPE_RET) {
            ret_from_outscope -= 1;
        }
        else if (type == PT_TYPE_BLOCK) {
            // plt functions will skip ret instruction
            if (addr >= plt_addr.at(0) and addr <= plt_addr.at(1)) {
                ret_from_outscope -= 1;
            }
        }

        if (ret_from_outscope == -1) {
            head = head_after_outscope;
            curr_in_scope = true;
            ret_from_outscope = 0;
        }
        // else {
        //     std::cout << "ret_from_outscope " << ret_from_outscope << std::endl;
        // }

        // auto t2 = sc.now();
        // time2 += static_cast<std::chrono::duration<double>>(t2 - t1).count();

        // std::cout << "current out of scope" << std::endl;

        return NULL;
    }

    // find the adj_node
    adjnode *adj_node = NULL;
    auto adj_list = head->second;

    for (auto adj_node_tmp: adj_list) {
        // Todo: change adj_list from list to set -> reduce time complexity
        if (unlikely(adj_node_tmp->addr == addr)) {
            adj_node = adj_node_tmp;
            break;
        }
    }

    if (adj_node == NULL) {
        // cannot find adj_node if addr is a nop instruction
        if (std::find(hook_addr.begin(), hook_addr.end(), addr) == hook_addr.end()) {
            // std::cout << "context " << head->first << std::endl;
            // std::cout << "addr " << std::hex << addr << " lost" << std::endl;
        }
        // auto t2 = sc.now();
        // time3 += static_cast<std::chrono::duration<double>>(t2 - t1).count();
        return NULL;
    }
    else {
        // std::cout << "context " << head->first << std::endl;
        // std::cout << "addr " << std::hex << addr << " found" << std::endl;
    }

    // redirect to its sibling
    if (adj_node->ts->redirect != 0) {
        addr = adj_node->ts->redirect;

        for (auto adj_node_tmp: adj_list) {
        if (adj_node_tmp->addr == addr)
            adj_node = adj_node_tmp;
        }
        if (adj_node == NULL) {
            std::cerr << "Cannot find redirected addr" << std::endl;
            exit(-1);
        }
    }

    // whether the current block is within the scope of taint analysis
    if (adj_node->ts->scope == false) {
        // std::cout << "start out of scope" << std::endl;

        curr_in_scope = false;
        head_after_outscope = adj_node->previous;

        if (type == PT_TYPE_CALL) {
            ret_from_outscope += 1;
        }
        else if (type == PT_TYPE_RET) {
            ret_from_outscope -= 1;
        }   
        else if (type == PT_TYPE_BLOCK) {
            if (adj_node->traverse_ret == true) {
                ret_from_outscope -= 1;
            }
        }
        // auto t2 = sc.now();
        // time4 += static_cast<std::chrono::duration<double>>(t2 - t1).count();
        return NULL;
    }

    /* update head when traversing adj_map */
    if (type == PT_TYPE_CALL) {
        // hook address
        if (adj_node->traverse_ret == false) {
            head = adj_node->next;
        }
    }
    else if (type == PT_TYPE_RET) {
        head = adj_node->previous;
        if (head == adj_map.end()) {
            // the following pt trace still need the taint analysis
            head = adj_map.find("0-");
        }
    }
    else if (type == PT_TYPE_BLOCK) {
        // e.g., plt -> head = adj_node->previous; 
        if (adj_node->traverse_ret == true) {
            head = adj_node->previous;
        }
    }
    else {
        std::cerr << "Cannot handle PT_TYPE_SYSCALL in traverseAdjmap" << std::endl;
        exit(-1);
    }

    // auto t2 = sc.now();
    // time5 += static_cast<std::chrono::duration<double>>(t2 - t1).count();
    return adj_node;
}

void TaintSummary::freeAdjmap() {
    for (auto adj: adj_map_forward) {
        auto adj_list = adj.second;
        for (auto adj_node: adj_list) {
            free(adj_node);
        }
    }

    // for (auto adj: adj_map_backward) {
    //     auto adj_list = adj.second;
    //     for (auto adj_node: adj_list) {
    //         free(adj_node);
    //     }
    // }

    for (auto adj: adj_map) {
        auto adj_list = adj.second;
        for (auto adj_node: adj_list) {
            free(adj_node);
        }
    }
}

adjnode *TaintSummary::locateAdjnode(std::list<mem_addr_t> addrs) {
    adjnode *adj_node = NULL;
    auto head = adj_map.end();

    for (auto addr: addrs) {
        if (head == adj_map.end()) {            
            head = adj_map.find(uint64_to_str(addr) + "-");
            if (head == adj_map.end()) {
                std::cerr << "Cannot find " << std::hex << addr << " in locateAdjnode(1)" << std::endl;
                exit(-1);
            }
        }

        auto adj_list = head->second;
        auto it_adj_list = adj_list.begin();
        for (; it_adj_list != adj_list.end(); it_adj_list++) {
            adj_node = *it_adj_list;
            if (adj_node->addr == addr) {
                head = adj_node->next;
                break;
            }
        }
        if (it_adj_list == adj_list.end()) {
            std::cerr << "Cannot find " << std::hex <<  addr << " in locateAdjnode(2)" << std::endl;
            exit(-1);
        }
    }

    return adj_node;
}

// init unum/rnum/stack_base/in_scope/redirect
void TaintSummary::initURSIR(std::string category, std::string value_str, taint_summary *ts) {
    ts_rel_t value = std::stoul(value_str);

    if (category == "rnum") {
        ts->rnum = value;
    }
    else if (category == "unum") {
        ts->unum = value;
    }
    else if (category == "stack") {
        ts->stack_base = value;
    }
    else if (category == "redirect") {
        ts->redirect = value;
    }
    else if (category == "scope") {
        // we only identify basic blocks beyond the scope of taint analysis
        assert(value == 0);
        ts->scope = false;
    }
    else {
        std::cerr << "unkown type: " << category << " in redis" <<  std::endl;
        exit(-1);
    }
}

void TaintSummary::initRelIndex(std::vector<std::string> value_list, taint_summary *ts) {
    std::vector<int> rel;

    auto it = value_list.rbegin();
    int index_src = std::stoi(*it);
    rel.push_back(index_src);

    do {
        it++;
        int index_des = std::stoi(*it);
        rel.push_back(index_des);
    } while(std::next(it, 1) != value_list.rend());

    auto &rel_vec = ts->rel_index;
    rel_vec.push_back(rel);
}

void TaintSummary::initUnit(int index, std::vector<std::string> value_list, taint_summary *ts) {
    int value_0 = std::stoi(value_list.at(0));
    int value_1 = std::stoi(value_list.at(1));
    std::string value_2 = value_list.at(2);

    int type;
    if (value_2 == "stack") {
        type = STACK;
    }
    else if (value_2 == "heap") {
        type = HEAP;
    }
    else if (value_2 == "global") {
        type = GLOBAL;
    }
    else if (value_2 == "register") {
        type = REGISTER;
    }
    else if (value_2 == "symbol") {
        type = SYMBOL;
    }
    else if (value_2 == "empty") {
        type = EMPTY;
    }
    else if (value_2 == "syscall") {
        type = SYSCALL;
        ts->syscall_direction = syscallDirection(value_1);
        ts->syscall_id = value_1;
    }
    else {
        std::cerr << "unkown unit type: " << value_2 << std::endl;
        exit(-1);
    }
    
    auto &unit_vec = ts->unit;
    int gap = index + 1 - unit_vec.size();
    for (int i = 0; i < gap; i++) {
        std::array<int, 3> empty_unit = {0, 0, 0};
        unit_vec.push_back(empty_unit);
    }

    std::array<int, 3> new_unit = {value_0, value_1, type};
    unit_vec.at(index) = new_unit;
}

void TaintSummary::getAllTS(){
    // get all keys from redis
    getAllKey();

    for (size_t i = 0; i < key_reply->elements; i++) {
        auto key = key_reply->element[i]->str;
        std::string key_str = std::string(key);
        auto first_separator = key_str.find(":");
        std::string prog_name_key = key_str.substr(0, first_separator);
        key_str = key_str.substr(first_separator + 1);

        if (prog_name_key != prog_name) {
            continue;
        }

        if (unlikely(key_str == ".plt" or key_str == ".hook" or key_str == ".symbol_num" or key_str == ".start")){
            continue;
        }

        // context from key_str
        std::string context = key_str.substr(0, key_str.find_last_of(":"));
        size_t last_in_context = context.find_last_of(":") ;
        std::string token = context.substr(last_in_context + 1);
        try {
            std::stol(token, 0, 16);
        }
        catch(...) {
            context = context.substr(0, last_in_context);;
        }

        // taint summary from key_str
        taint_summary *ts = NULL;
        auto ts_itr = all_ts.find(context);
        if (ts_itr == all_ts.end()) {
            ts = (taint_summary *) malloc(sizeof(taint_summary));
            memset((void *) ts, 0, sizeof(taint_summary));
            ts->rnum = 0;
            ts->unum = 0;
            ts->stack_base = 0;
            ts->redirect = 0;
            ts->scope = true;
            ts->syscall_direction = SYSCALL_NONE;

            all_ts[context] = ts;
        }
        else {
            ts = (*ts_itr).second;
        }

        // key type from redis
        auto type = getType(key);

        // last element of key_str
        std::string category = key_str.substr(key_str.find_last_of(":") + 1);

        if (strcmp(type, "string") == 0) {
            std::string value = getStringValue(key);
            initURSIR(category, value, ts);
        }
        else if (strcmp(type, "list") == 0) {
            // parse value list
            std::vector<std::string> value = getListValue(key);

            char type = key_str[key_str.find_last_of(":") - 1];
            if (type == 'r') {
                initRelIndex(value, ts);
            }
            else if (type == 'u') {
                int index = std::stoi(category);
                initUnit(index, value, ts);
            }
            else {
                std::cerr << "unkown list in redis" << std::endl;
                exit(-1);
            }
        }
        else {
            std::cerr << "Unkown Redis Data Type: " << type << std::endl;
            exit(-1);
        }

        freeReplyObject(type_reply);
        freeReplyObject(value_reply);
    }

    // tradeoff space overhead to performance overhead: transfer rel_index to rel
    InitRel();
}

void TaintSummary::InitRel() {
    for (auto ctx_ts: all_ts) {
        taint_summary *ts = ctx_ts.second;
        std::vector<std::vector<int>> &rel = ts->rel;
        std::vector<std::vector<int>> rel_index = ts->rel_index;
        std::vector<std::array<int, 3>> units = ts->unit;

        for (auto r_idx_vec: rel_index) {
            std::vector<int> r;
            for (auto r_idx: r_idx_vec) {
                std::array<int, 3> u = units.at(r_idx);
                int size = u.at(0);
                int offset = u.at(1);
                int type = u.at(2);
                r.push_back(size);
                r.push_back(offset);
                r.push_back(type);
            }
            rel.push_back(r);
        }
    }
}

void TaintSummary::initAdjTS() {
    for (auto ctx_ts: all_ts) {
        std::string context = ctx_ts.first;
        taint_summary *ts = ctx_ts.second;

        std::list<mem_addr_t> addrs = parseCallsite(context, ADJMAP_FORWARD);

        adjnode *adj_node = locateAdjnode(addrs);

        adj_node->ts = ts;   
    }
}

void TaintSummary::printPrefixmap() {
    for (auto prefix: prefix_map) {
        auto addr = prefix.first;
        auto prefix_addr_set = prefix.second;
        std::cout << std::hex << addr << ":";

        for (auto prefix_addr: prefix_addr_set) {
            std::cout << " " << prefix_addr;
        }
        std::cout << std::endl;
    }
}

void TaintSummary::printPlt() {
    std::cout << "plt address range: ";
    std::cout << std::hex << plt_addr.at(0) << " -> " << plt_addr.at(1) << std::endl;
    std::cout << "hook address: ";
    for (auto value: hook_addr)
        std::cout << value << " ";
    std::cout << std::endl;
}

void TaintSummary::printStartTaint() {
    std::cout << "tainting scope address: ";
    for (auto value: start_addr)
        std::cout << value << " ";
    std::cout << std::endl;
}

void TaintSummary::printAdjmap(adjmap _adj_map) {
    for (auto adj: _adj_map) {
        auto addr_head = adj.first;
        auto adj_list = adj.second;
        std::cout << std::hex << addr_head  << ":";

        for (auto adj_node: adj_list) {
            auto addr_tail = adj_node->addr;
            std::cout << " " << addr_tail << "(rnum:" << adj_node->ts->rnum <<
            " unum:" << adj_node->ts->unum << ")";
            std::cout << " " << addr_tail;
        }
        std::cout << std::endl;
    }
}

void TaintSummary::printTS(taint_summary *ts) {
    // rnum and unum
    std::cout << "rnum: " << ts->rnum << std::endl;
    std::cout << "unum: " << ts->unum << std::endl;
    
    // stack_base
    std::cout << "stack_base: " << ts->stack_base << std::endl;

    // scope
    std::cout << "scope: " << ts->scope << std::endl;

    // unit
    std::cout << "\nunits:" << std::dec << std::endl;
    auto unit_vec = ts->unit;
    for (auto u: unit_vec) {
        std::cout << "size: " << u.at(0) << " ";
        std::cout << "offset: " << u.at(1) << " ";
        std::cout << "type: " << taintInt2Str(u.at(2)) << std::endl;
    }

    // rel_index
    std::cout << "\nrelation index:" << std::endl;
    auto rel_idx_vec = ts->rel_index;
    for (auto r: rel_idx_vec) {
        auto it = r.begin();
        std::cout << "des: " << *it << " src: ";
        do {
            it++;
            std::cout << *it << " ";
        } while (std::next(it, 1) != r.end());
        std::cout << std::endl;
    }

    // relation
    std::cout << "\nrelation:" << std::endl;
    auto rel_vec = ts->rel;
    for (auto r: rel_vec) {
        int r_size = r.size();
        std::cout << "des: " << r.at(0) << " " << r.at(1) << " " << taintInt2Str(r.at(2)) << " src: ";
        for (int i = 3; i < r_size; i = i + 3) {
             std::cout << r.at(i) << " " << r.at(i + 1) << " " << taintInt2Str(r.at(i + 2)) << " ";
        }
        std::cout << std::endl;
    }
}
