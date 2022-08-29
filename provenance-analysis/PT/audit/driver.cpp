#include "audit.h"

int main(int argc, char **argv) {
    if (argc < 3) {
        std::cerr << "./driver audit-dir pid\n";
        return 0;
    }

    std::string beat_dir = argv[1];

    Audit audit = Audit(beat_dir);

    audit.PrintBeatFile();

    return 0;
}