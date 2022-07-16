TRACERT=tracert.cpp
CXXFLAGS=-g -ggdb -Wall -Wextra -std=c++17
CXXC=g++

TRACERT_BIN=tracert

run: clear $(TRACERT_BIN)
	sudo ./$(TRACERT_BIN)

$(TRACERT_BIN): $(TRACERT)
	$(CXXC) $(CXXFLAGS) $(TRACERT) -o $(TRACERT_BIN)

clear:
	reset
