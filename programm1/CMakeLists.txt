cmake_minimum_required(VERSION 3.14)
project(PacketClassifier)

set(CMAKE_CXX_STANDARD 11)

# Устанавливаем путь к библиотеке pcap
set(PCAP_LIBRARY_PATH "${CMAKE_CURRENT_SOURCE_DIR}/libpcap/libpcap.so.1.11.0-PRE-GIT")

# Проверяем, найдена ли библиотека pcap
if(NOT EXISTS ${PCAP_LIBRARY_PATH})
    message(FATAL_ERROR "libpcap not found in the specified path: ${PCAP_LIBRARY_PATH}")
endif()

# Устанавливаем пути и исходные файлы
set(SOURCE_FILES
    main.cpp
)

# Создаем исполняемый файл
add_executable(packet_classifier ${SOURCE_FILES})

# Линкуем с локальной библиотекой pcap
target_link_libraries(packet_classifier PRIVATE ${PCAP_LIBRARY_PATH})
