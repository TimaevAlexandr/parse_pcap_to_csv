CXX=g++
CXXFLAGS=-w
LDFLAGS=-ldl
SOURCES=$(wildcard src/*.cpp)
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=programm

export LD_LIBRARY_PATH=./libs
LIBRARY=libpcap.so.1

MESSAGE="\nNow you can run the programm with 'make run pcap_file=example.pcap'"


build: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LD_LIBRARY_PATH)/$(LIBRARY)
	@echo $(MESSAGE)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

run: $(EXECUTABLE)
	@./$(EXECUTABLE) $(pcap_file)

clean:
	rm -f $(OBJECTS)
