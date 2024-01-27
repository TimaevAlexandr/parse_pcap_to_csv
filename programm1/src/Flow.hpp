#ifndef FLOW_HPP
#define FLOW_HPP

#include <cstdint>

class Flow {
public:
    uint64_t packet_count;
    uint64_t byte_count;

    Flow() : packet_count(0), byte_count(0) {}
};

#endif // FLOW_HPP
