#include "PackageAnalyzer.hpp"
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <iostream>

std::string FlowAnalyzer::getFlowKey(const struct ip* ip_header, uint16_t src_port, uint16_t dst_port) {
    std::string src_ip = inet_ntoa(ip_header->ip_src);
    std::string dst_ip = inet_ntoa(ip_header->ip_dst);

    return src_ip + "," + dst_ip + "," + std::to_string(src_port) + "," + std::to_string(dst_port);
}

void FlowAnalyzer::handlePacket(const struct pcap_pkthdr* pkthdr, const unsigned char* packet) {
    struct ip* ip_header = (struct ip*)(packet + 14);
    struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14 + ip_header->ip_hl * 4);

    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);

    std::string flow_key = getFlowKey(ip_header, src_port, dst_port);

    Flow& flow = flow_map[flow_key];
    flow.packet_count++;
    flow.byte_count += pkthdr->len;
}

void FlowAnalyzer::saveResultsToFile(const std::string& filePath) {
    std::ofstream output_file(filePath, std::ofstream::trunc); // очиащем файл перед записью

    if (!output_file.is_open()) {
        std::cerr << "Error opening output file." << std::endl;
        return;
    }

    output_file << "Source IP,Destination IP,Source Port,Destination Port,Packet Count,Byte Count" << std::endl;

    for (const auto& entry : flow_map) {
        std::string flow_key = entry.first;
        size_t pos1 = flow_key.find(",");
        size_t pos2 = flow_key.find(",", pos1 + 1);
        size_t pos3 = flow_key.find(",", pos2 + 1);

        std::string src_ip = flow_key.substr(0, pos1);
        std::string dst_ip = flow_key.substr(pos1 + 1, pos2 - pos1 - 1);
        uint16_t src_port = std::stoi(flow_key.substr(pos2 + 1, pos3 - pos2 - 1));
        uint16_t dst_port = std::stoi(flow_key.substr(pos3 + 1));

        const Flow& flow = entry.second;

        output_file << src_ip << "," << dst_ip << "," << src_port << "," << dst_port << "," << flow.packet_count << ","
                    << flow.byte_count << std::endl;
    }

    output_file.close();
}

void FlowAnalyzer::analyzePcapFile(const std::string& pcapFilePath) {
        pcap_t* pcap_handle;
        char errbuf[PCAP_ERRBUF_SIZE];

        pcap_handle = pcap_open_offline(pcapFilePath.c_str(), errbuf);
        if (pcap_handle == nullptr) {
            std::cerr << "Error opening pcap file: " << errbuf << std::endl;
            return;
        }

        pcap_loop(pcap_handle, 0, [](unsigned char* user, const struct pcap_pkthdr* pkthdr, const unsigned char* packet) {
            reinterpret_cast<FlowAnalyzer*>(user)->handlePacket(pkthdr, packet);
        }, reinterpret_cast<unsigned char*>(this));

        pcap_close(pcap_handle);

        saveResultsToFile("../output.csv");

        std::cout << "\nClassification completed. Results saved in 'output.csv'." << std::endl;
    }