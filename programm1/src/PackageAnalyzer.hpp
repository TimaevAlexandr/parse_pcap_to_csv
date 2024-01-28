#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <fstream>

class Flow {
public:
    uint64_t packet_count;
    uint64_t byte_count;

    Flow() : packet_count(0), byte_count(0) {}
};

class FlowAnalyzer {
private:
    std::map<std::string, Flow> flow_map;

    std::string getFlowKey(const struct ip* ip_header, uint16_t src_port, uint16_t dst_port);

    void handlePacket(const struct pcap_pkthdr* pkthdr, const unsigned char* packet);

    void saveResultsToFile(const std::string& filePath);

public:
    void analyzePcapFile(const std::string& pcapFilePath);
};
