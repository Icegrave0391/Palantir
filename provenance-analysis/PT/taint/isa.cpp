#include "isa.h"

int getRegDep(const reg_id_t reg_id, std::list<reg_id_t> &reg_dep) {
    switch(reg_id) {
        case 0:
            reg_dep = {0,1,2,3,4};
            return 0;
        case 1:
            reg_dep = {1,2,3,4};
            return 0;
        case 2:
            reg_dep = {2,3,4};
            return 0;
        case 3:
            reg_dep = {3};
            return 0;
        case 4:
            reg_dep = {4};
            return 0;
        case 5:
            reg_dep = {5,6,7,8,9};
            return 0;
        case 6:
            reg_dep = {6,7,8,9};
            return 0;
        case 7:
            reg_dep = {7,8,9};
            return 0;
        case 8:
            reg_dep = {8};
            return 0;
        case 9:
            reg_dep = {9};
            return 0;
        case 10:
            reg_dep = {10,11,12,13,14};
            return 0;
        case 11:
            reg_dep = {11,12,13,14};
            return 0;
        case 12:
            reg_dep = {12,13,14};
            return 0;
        case 13:
            reg_dep = {13};
            return 0;
        case 14:
            reg_dep = {14};
            return 0;
        case 15:
            reg_dep = {15,16,17,18,19};
            return 0;
        case 16:
            reg_dep = {16,17,18,19};
            return 0;
        case 17:
            reg_dep = {17,18,19};
            return 0;
        case 18:
            reg_dep = {18};
            return 0;
        case 19:
            reg_dep = {19};
            return 0;
        case 20:
            reg_dep = {20,21};
            return 0;
        case 21:
            reg_dep = {21};
            return 0;
        case 22:
            reg_dep = {22,23,24,25};
            return 0;
        case 23:
            reg_dep = {23,24,25};
            return 0;
        case 24:
            reg_dep = {24};
            return 0;
        case 25:
            reg_dep = {25};
            return 0;
        case 26:
            reg_dep = {26,27,28,29,30};
            return 0;
        case 27:
            reg_dep = {27,28,29,30};
            return 0;
        case 28:
            reg_dep = {28,29,30};
            return 0;
        case 29:
            reg_dep = {29};
            return 0;
        case 30:
            reg_dep = {30};
            return 0;
        case 31:
            reg_dep = {31,32,33,34,35};
            return 0;
        case 32:
            reg_dep = {32,33,34,35};
            return 0;
        case 33:
            reg_dep = {33,34,35};
            return 0;
        case 34:
            reg_dep = {34};
            return 0;
        case 35:
            reg_dep = {35};
            return 0;
        case 36:
            reg_dep = {36,37,38,39};
            return 0;
        case 37:
            reg_dep = {37,38,39};
            return 0;
        case 38:
            reg_dep = {38,39};
            return 0;
        case 39:
            reg_dep = {39};
            return 0;
        case 40:
            reg_dep = {40,41,42,43};
            return 0;
        case 41:
            reg_dep = {41,42,43};
            return 0;
        case 42:
            reg_dep = {42,43};
            return 0;
        case 43:
            reg_dep = {43};
            return 0;
        case 44:
            reg_dep = {44,45,46,47};
            return 0;
        case 45:
            reg_dep = {45,46,47};
            return 0;
        case 46:
            reg_dep = {46,47};
            return 0;
        case 47:
            reg_dep = {47};
            return 0;
        case 48:
            reg_dep = {48,49,50,51};
            return 0;
        case 49:
            reg_dep = {49,50,51};
            return 0;
        case 50:
            reg_dep = {50,51};
            return 0;
        case 51:
            reg_dep = {51};
            return 0;
        case 52:
            reg_dep = {52,53,54,55};
            return 0;
        case 53:
            reg_dep = {53,54,55};
            return 0;
        case 54:
            reg_dep = {54,55};
            return 0;
        case 55:
            reg_dep = {55};
            return 0;
        case 56:
            reg_dep = {56,57,58,59};
            return 0;
        case 57:
            reg_dep = {57,58,59};
            return 0;
        case 58:
            reg_dep = {58,59};
            return 0;
        case 59:
            reg_dep = {59};
            return 0;
        case 60:
            reg_dep = {60,61,62,63};
            return 0;
        case 61:
            reg_dep = {61,62,63};
            return 0;
        case 62:
            reg_dep = {62,63};
            return 0;
        case 63:
            reg_dep = {63};
            return 0;
        case 64:
            reg_dep = {64,65,66,67};
            return 0;
        case 65:
            reg_dep = {65,66,67};
            return 0;
        case 66:
            reg_dep = {66,67};
            return 0;
        case 67:
            reg_dep = {67};
            return 0;
        default:
            return -1;
    }
    return -1;
}

int getRegName(const reg_id_t reg_id, std::string &reg_name) {
    switch(reg_id) {
        case 0:
            reg_name = "rax";
            return 0;
        case 1:
            reg_name = "eax";
            return 0;
        case 2:
            reg_name = "ax";
            return 0;
        case 3:
            reg_name = "al";
            return 0;
        case 4:
            reg_name = "ah";
            return 0;
        case 5:
            reg_name = "rcx";
            return 0;
        case 6:
            reg_name = "ecx";
            return 0;
        case 7:
            reg_name = "cx";
            return 0;
        case 8:
            reg_name = "cl";
            return 0;
        case 9:
            reg_name = "ch";
            return 0;
        case 10:
            reg_name = "rdx";
            return 0;
        case 11:
            reg_name = "edx";
            return 0;
        case 12:
            reg_name = "dx";
            return 0;
        case 13:
            reg_name = "dl";
            return 0;
        case 14:
            reg_name = "dh";
            return 0;
        case 15:
            reg_name = "rbx";
            return 0;
        case 16:
            reg_name = "ebx";
            return 0;
        case 17:
            reg_name = "bx";
            return 0;
        case 18:
            reg_name = "bl";
            return 0;
        case 19:
            reg_name = "bh";
            return 0;
        case 20:
            reg_name = "rsp";
            return 0;
        case 21:
            reg_name = "esp";
            return 0;
        case 22:
            reg_name = "rbp";
            return 0;
        case 23:
            reg_name = "ebp";
            return 0;
        case 24:
            reg_name = "bpl";
            return 0;
        case 25:
            reg_name = "bph";
            return 0;
        case 26:
            reg_name = "rsi";
            return 0;
        case 27:
            reg_name = "esi";
            return 0;
        case 28:
            reg_name = "si";
            return 0;
        case 29:
            reg_name = "sil";
            return 0;
        case 30:
            reg_name = "sih";
            return 0;
        case 31:
            reg_name = "rdi";
            return 0;
        case 32:
            reg_name = "edi";
            return 0;
        case 33:
            reg_name = "di";
            return 0;
        case 34:
            reg_name = "dil";
            return 0;
        case 35:
            reg_name = "dih";
            return 0;
        case 36:
            reg_name = "r8";
            return 0;
        case 37:
            reg_name = "r8d";
            return 0;
        case 38:
            reg_name = "r8w";
            return 0;
        case 39:
            reg_name = "r8b";
            return 0;
        case 40:
            reg_name = "r9";
            return 0;
        case 41:
            reg_name = "r9d";
            return 0;
        case 42:
            reg_name = "r9w";
            return 0;
        case 43:
            reg_name = "r9b";
            return 0;
        case 44:
            reg_name = "r10";
            return 0;
        case 45:
            reg_name = "r10d";
            return 0;
        case 46:
            reg_name = "r10w";
            return 0;
        case 47:
            reg_name = "r10b";
            return 0;
        case 48:
            reg_name = "r11";
            return 0;
        case 49:
            reg_name = "r11d";
            return 0;
        case 50:
            reg_name = "r11w";
            return 0;
        case 51:
            reg_name = "r11b";
            return 0;
        case 52:
            reg_name = "r12";
            return 0;
        case 53:
            reg_name = "r12d";
            return 0;
        case 54:
            reg_name = "r12w";
            return 0;
        case 55:
            reg_name = "r12b";
            return 0;
        case 56:
            reg_name = "r13";
            return 0;
        case 57:
            reg_name = "r13d";
            return 0;
        case 58:
            reg_name = "r13w";
            return 0;
        case 59:
            reg_name = "r13b";
            return 0;
        case 60:
            reg_name = "r14";
            return 0;
        case 61:
            reg_name = "r14d";
            return 0;
        case 62:
            reg_name = "r14w";
            return 0;
        case 63:
            reg_name = "r14b";
            return 0;
        case 64:
            reg_name = "r15";
            return 0;
        case 65:
            reg_name = "r15d";
            return 0;
        case 66:
            reg_name = "r15w";
            return 0;
        case 67:
            reg_name = "r15b";
            return 0;
        default:
            return -1;
    }
    return -1;
}