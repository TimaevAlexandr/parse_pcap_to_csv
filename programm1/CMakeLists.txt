cmake_minimum_required(VERSION 3.14)
project(PacketClassifier)

set(CMAKE_CXX_STANDARD 11)

# Находим библиотеки pcap
find_library(PCAP_LIBRARY_STATIC NAMES pcap PATHS ${CMAKE_CURRENT_SOURCE_DIR})
find_library(PCAP_LIBRARY_SHARED NAMES pcap PATHS ${CMAKE_CURRENT_SOURCE_DIR})

# Проверяем, найдены ли библиотеки pcap
if(NOT PCAP_LIBRARY_STATIC OR NOT PCAP_LIBRARY_SHARED)
    message(FATAL_ERROR "libpcap not found.")
endif()

# Устанавливаем пути и исходные файлы
set(SOURCE_FILES
    main.cpp
)

# Создаем исполняемый файл
add_executable(packet_classifier ${SOURCE_FILES})

# Линкуем с статической библиотекой pcap
target_link_libraries(packet_classifier PRIVATE ${PCAP_LIBRARY_STATIC})

# Линкуем с динамической библиотекой pcap
# Если вы хотите использовать динамическую библиотеку, раскомментируйте следующую строку
# target_link_libraries(packet_classifier PRIVATE ${PCAP_LIBRARY_SHARED})
