CXX=g++
CXXFLAGS=-Wall
LDFLAGS=-ldl
SOURCES=main.cpp
EXECUTABLE=programm
MESSAGE="Now you can run the programm with 'make run pcap_file=example.pcap ' "

build:
	g++ main.cpp -ldl -o prog libs/libpcap.so.1.11.0-PRE-GIT
	@echo $(MESSAGE)
run:
	chmod +x $(EXECUTABLE)
	./$(EXECUTABLE) $(pcap_file)
