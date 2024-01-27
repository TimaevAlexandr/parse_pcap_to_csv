CXX=g++
CXXFLAGS=-w
LDFLAGS=-ldl
SOURCES=main.cpp
EXECUTABLE=programm
MESSAGE="\n Now you can run the programm with 'make run pcap_file=example.pcap ' "
LIBRARY_PATH=libs/libpcap.so.1.11.0-PRE-GIT

build:
	g++ $(SOURCES) $(CXXFLAGS) $(LDFLAGS) -o $(EXECUTABLE) $(LIBRARY_PATH)
	@echo $(MESSAGE)
run:
	export LD_LIBRARY_PATH=./libs
	./$(EXECUTABLE) $(pcap_file)
clean:
	rm $(EXECUTABLE)