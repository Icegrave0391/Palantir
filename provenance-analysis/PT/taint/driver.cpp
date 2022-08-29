#include "taintengine.h"

int main() {
    TaintEngine taint_engine("127.0.0.1", 6379);

    taint_tag_t list1 = {1,2,3};
    taint_tag_t list2 = {4,5};

    /* symbol */
    {
        taint_tag_t list3;
        symbol_id_t symbol_id = 9;

        // test setSymbolTaint
        taint_engine.taint_stat->setSymbolTaint(symbol_id, list1);
        taint_engine.taint_stat->printSymbolTaint(symbol_id);

        // test getSymbolTaint
        taint_engine.taint_stat->getSymbolTaint(symbol_id, list3);
        print_taint(list3);

        // test emptyRegTaint
        taint_engine.taint_stat->emptySymbolTaint(symbol_id);
        taint_engine.taint_stat->printSymbolTaint(symbol_id);
        return 0;
    }

    /* register */
    {
        taint_tag_t list3;
        reg_id_t red_id = 0;

        // test setRegTaint
        taint_engine.taint_stat->setRegTaint(red_id, list1);
        taint_engine.taint_stat->printRegTaint(red_id);
        
        // test getRegTaint
        taint_engine.taint_stat->getRegTaint(red_id, list3);
        print_reg_name(red_id);
        print_taint(list3);

        // test emptyRegTaint
        taint_engine.taint_stat->emptyRegTaint(red_id);
        taint_engine.taint_stat->printRegTaint(red_id);
    }
    
    /* stack memory */
    {
        taint_tag_t list3;
        int offset = -16;
        int size = 8;

        taint_engine.taint_stat->setStackTaint(offset, size, list1);
        taint_engine.taint_stat->printStackTaint(offset, size);

        taint_engine.taint_stat->setStackTaint(offset, size, list2);
        taint_engine.taint_stat->printStackTaint(offset, size);

        taint_engine.taint_stat->getStackTaint(offset, size, list3);
        std::cout << "taint summary " << offset << "->" << offset + size;
        print_taint(list3);
    }

    /* heap memory */
    {
        taint_tag_t list3;
        int offset = -16;
        int size = 8;

        taint_engine.taint_stat->setHeapTaint(offset, size, list2);
        taint_engine.taint_stat->printHeapTaint(offset, size);

        taint_engine.taint_stat->setHeapTaint(offset, size, list1);
        taint_engine.taint_stat->printHeapTaint(offset, size);

        taint_engine.taint_stat->getHeapTaint(offset, size, list3);
        std::cout << "taint summary " << offset << "->" << offset + size;
        print_taint(list3);
    }

    /* global memory */
    {
        taint_tag_t list3;
        int offset = -16;
        int size = 8;

        taint_engine.taint_stat->setGlobalTaint(offset, size, list2);
        taint_engine.taint_stat->printGlobalTaint(offset, size);

        taint_engine.taint_stat->emptyGlobalTaint(offset, size);
        taint_engine.taint_stat->printGlobalTaint(offset, size);

        taint_engine.taint_stat->getGlobalTaint(offset, size, list3);
        std::cout << "taint summary " << offset << "->" << offset + size;
        print_taint(list3);
    }

    return 0;
}
