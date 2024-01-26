CC = g++
CFLAGS = -std=c++11 -Wall
LIBS = -lpcap

SRC = programm1.cpp
OBJ = $(SRC:.cpp=.o)
EXEC = programm1

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(EXEC)
