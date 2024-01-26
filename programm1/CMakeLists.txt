cmake_minimum_required(VERSION 3.14)
project(PacketClassifier)

set(CMAKE_CXX_STANDARD 11)

# Находим библиотеку pcap
find_library(PCAP_LIBRARY NAMES pcap)

# Проверяем, найдена ли библиотека pcap
if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found.")
endif()

# Устанавливаем пути и исходные файлы
set(SOURCE_FILES
    main.cpp
)

# Создаем исполняемый файл
add_executable(packet_classifier ${SOURCE_FILES})

# Линкуем с библиотекой pcap
target_link_libraries(packet_classifier PRIVATE ${PCAP_LIBRARY})
