// flow_analyzer.hpp
#ifndef FLOW_ANALYZER_HPP
#define FLOW_ANALYZER_HPP

#include <pcap.h>
#include <iostream>
#include <map>
#include <string>
#include <fstream>
#include "flow.hpp"

class FlowAnalyzer {
private:
    std::map<std::string, Flow> flow_map;

    std::string getFlowKey(const struct ip* ip_header, uint16_t src_port, uint16_t dst_port);

    void handlePacket(const struct pcap_pkthdr* pkthdr, const unsigned char* packet);

    void saveResultsToFile(const std::string& filePath);

public:
    void analyzePcapFile(const std::string& pcapFilePath);
};

#endif // FLOW_ANALYZER_HPP
