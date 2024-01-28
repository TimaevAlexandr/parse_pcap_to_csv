CXX=g++
CXXFLAGS=-w
LDFLAGS=-ldl
SOURCES=main.cpp
EXECUTABLE=programm
MESSAGE="\n Now you can run the programm with 'make run pcap_file=example.pcap ' "
LIBRARY=libpcap.so.1
export LD_LIBRARY_PATH=./libs

build:
	$(CXX) $(SOURCES) $(CXXFLAGS) $(LDFLAGS) -o $(EXECUTABLE) $(LD_LIBRARY_PATH)/$(LIBRARY)
	@echo $(MESSAGE)
run:
	@./$(EXECUTABLE) $(pcap_file)
clean:
	rm $(EXECUTABLE)