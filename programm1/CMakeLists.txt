cmake_minimum_required(VERSION 3.14)
project(PacketClassifier)

set(CMAKE_CXX_STANDARD 11)

# Указываем путь к папке с libpcap
set(PCAP_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libpcap")
set(PCAP_LIBRARY_PATH "${CMAKE_CURRENT_SOURCE_DIR}/libpcap/libpcap.a")

# Проверяем, найдены ли библиотека и заголовочные файлы
if(NOT EXISTS ${PCAP_INCLUDE_DIR} OR NOT EXISTS ${PCAP_LIBRARY_PATH})
    message(FATAL_ERROR "libpcap not found in the specified path: ${CMAKE_CURRENT_SOURCE_DIR}/libpcap")
endif()

# Устанавливаем пути и исходные файлы
set(SOURCE_FILES
    main.cpp
)

# Создаем исполняемый файл
add_executable(packet_classifier ${SOURCE_FILES})

# Указываем путь к заголовочным файлам libpcap
target_include_directories(packet_classifier PRIVATE ${PCAP_INCLUDE_DIR})

# Линкуем с локальной библиотекой pcap
target_link_libraries(packet_classifier PRIVATE ${PCAP_LIBRARY_PATH})
