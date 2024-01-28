#include <iostream>
#include "Flow.hpp"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>" << std::endl;
        return 1;
    }

    FlowAnalyzer flowAnalyzer;
    flowAnalyzer.analyzePcapFile(argv[1]);

    return 0;
}
