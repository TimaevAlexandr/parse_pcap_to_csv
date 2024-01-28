CXX=g++
CXXFLAGS=-w
LDFLAGS=-ldl
SOURCES=src/main.cpp src/Flow.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=programm
MESSAGE="\n Now you can run the programm with 'make run pcap_file=example.pcap ' "
LIBRARY=libpcap.so.1
export LD_LIBRARY_PATH=./libs

build: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LD_LIBRARY_PATH)/$(LIBRARY)
	@echo $(MESSAGE)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

run: $(EXECUTABLE)
	@./$(EXECUTABLE) $(pcap_file)

clean:
	rm -f $(OBJECTS) $(EXECUTABLE)
