cmake_minimum_required(VERSION 3.14)
project(PacketClassifier)

set(CMAKE_CXX_STANDARD 11)

set(PCAP_LIBRARY_PATH "${CMAKE_CURRENT_SOURCE_DIR}/libpcap/libpcap.so.1.11.0-PRE-GIT")

if(NOT EXISTS ${PCAP_LIBRARY_PATH})
    message(FATAL_ERROR "libpcap not found in the specified path: ${PCAP_LIBRARY_PATH}")
endif()

set(SOURCE_FILES
    main.cpp
)

#no warn
if (CMAKE_VERSION VERSION_GREATER_EQUAL 3.13)
    cmake_policy(SET CMP0076 NEW)
endif()


add_executable(packet_classifier ${SOURCE_FILES})

target_link_libraries(packet_classifier PRIVATE ${PCAP_LIBRARY_PATH})
