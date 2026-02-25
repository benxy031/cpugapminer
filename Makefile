CC=gcc
CXX=g++
CFLAGS=-O3 -std=c11 -Wall -Wextra -march=native -flto
CXXFLAGS=-O3 -std=c++17 -Wall -Wextra -march=native -flto
LDFLAGS=-flto
SRCDIR=src
BINDIR=bin
TARGET=$(BINDIR)/gap_miner

# Optional: GMP_PREFIX=/path/to/gmp  to use a custom (e.g. --enable-fat) build.
# Static linking avoids runtime dependency on non-system libgmp.
ifdef GMP_PREFIX
	GMP_CFLAGS=-I$(GMP_PREFIX)/include
	GMP_LIB=$(GMP_PREFIX)/lib/libgmp.a
else
	GMP_CFLAGS=
	GMP_LIB=-lgmp
endif

# enable WITH_RPC=1 to include RPC wrapper sources and link curl
ifdef WITH_RPC
	LIBS=-lcurl -ljansson -lssl -lcrypto $(GMP_LIB) -lm -pthread -lstdc++
	CFLAGS+=-DWITH_RPC $(GMP_CFLAGS)
	# build rpc C++ objects
	RPC_SRCS=$(SRCDIR)/rpc_cwrap.cpp $(SRCDIR)/rpc_globals.cpp $(SRCDIR)/rpc_stubs.cpp $(SRCDIR)/Rpc.cpp
	RPC_OBJS=$(RPC_SRCS:.cpp=.o)
	LINKER=$(CXX)
else
	LIBS=-lssl -lcrypto $(GMP_LIB) -lm -pthread
	LINKER=$(CC)
	RPC_OBJS=
endif

all: $(TARGET)

test: tests/test_rpc_json

tests/test_rpc_json: $(SRCDIR)/rpc_json.c tests/test_rpc_json.c
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $(SRCDIR)/rpc_json.c tests/test_rpc_json.c -ljansson

$(BINDIR):
	mkdir -p $(BINDIR)

$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(SRCDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TARGET): $(BINDIR) $(SRCDIR)/main.o $(RPC_OBJS)
	$(LINKER) -o $@ $(SRCDIR)/main.o $(RPC_OBJS) $(LDFLAGS) $(LIBS)

clean:
	rm -rf $(BINDIR) $(SRCDIR)/*.o

.PHONY: all clean
