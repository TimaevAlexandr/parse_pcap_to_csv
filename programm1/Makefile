CXX=g++
CXXFLAGS=-w
LDFLAGS=-ldl
SOURCES=main.cpp
EXECUTABLE=programm
MESSAGE="\n Now you can run the programm with 'make run pcap_file=example.pcap ' "
LIBRARY=libpcap.so.1.11.0-PRE-GIT
export LD_LIBRARY_PATH=./libs

build:
	g++ $(SOURCES) $(CXXFLAGS) $(LDFLAGS) -o $(EXECUTABLE) $(LIBRARY)
	@echo $(MESSAGE)
run:
	@./$(EXECUTABLE) $(pcap_file)
clean:
	rm $(EXECUTABLE)