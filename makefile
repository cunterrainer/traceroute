TRACERT=tracert.cpp
TRACERT_BIN=tracert

ifeq ($(conf),d)
	OPTFLAGS=-g -ggdb
else
	ifeq ($(conf),of)
		OPTFLAGS=-Ofast
	else
		OPTFLAGS=-O2
	endif
endif

CXXFLAGS=$(OPTFLAGS) -Wall -Wextra -std=c++17
CXXC=g++


run: clear $(TRACERT_BIN)
	sudo ./$(TRACERT_BIN) google.com

$(TRACERT_BIN): $(TRACERT)
	$(CXXC) $(CXXFLAGS) $(TRACERT) -o $(TRACERT_BIN)

clear:
	reset
