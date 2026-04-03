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
	STRATUM_OBJ=$(SRCDIR)/stratum.o
	LINKER=$(CXX)
else
	LIBS=-lssl -lcrypto $(GMP_LIB) -lm -pthread
	LINKER=$(CC)
	RPC_OBJS=
	STRATUM_OBJ=
endif

# enable WITH_CUDA=1 to include GPU Fermat testing via CUDA
# enable WITH_OPENCL=1 to build OpenCL host scaffolding backend
# optional: GPU_BITS=768 (default, shift ≤ 512), 1024 (shift ≤ 768), etc.
ifdef WITH_CUDA
ifdef WITH_OPENCL
$(error WITH_CUDA and WITH_OPENCL cannot be enabled together)
endif
endif

GPU_BITS ?= 1024
GPU_NLIMBS := $(shell echo '$(GPU_BITS) / 64' | bc)

ifdef WITH_CUDA
	NVCC ?= nvcc
	CUDA_ARCH ?= -arch=sm_86
	CUDA_PATH ?= /usr/local/cuda
	GPU_OBJ=$(SRCDIR)/gpu_fermat.o
	CFLAGS+=-DWITH_CUDA -DGPU_NLIMBS=$(GPU_NLIMBS) -I$(CUDA_PATH)/include
	NVCC_FLAGS=-DGPU_NLIMBS=$(GPU_NLIMBS)
	LIBS+=-lcudart -L$(CUDA_PATH)/lib64
endif

ifdef WITH_OPENCL
	GPU_OBJ=$(SRCDIR)/gpu_fermat_opencl.o
	CFLAGS+=-DWITH_OPENCL -DGPU_NLIMBS=$(GPU_NLIMBS)
	LIBS+=-lOpenCL
endif

ifndef GPU_OBJ
	GPU_OBJ=
endif

all: $(TARGET)

test: tests/test_rpc_json tests/test_wheel_sieve tests/test_wheel_compare

tests/test_rpc_json: $(SRCDIR)/rpc_json.c tests/test_rpc_json.c
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $(SRCDIR)/rpc_json.c tests/test_rpc_json.c -ljansson

tests/test_wheel_sieve: $(SRCDIR)/wheel_sieve.c tests/test_wheel_sieve.c
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $(SRCDIR)/wheel_sieve.c tests/test_wheel_sieve.c

tests/test_wheel_compare: $(SRCDIR)/wheel_sieve.c tests/test_wheel_compare.c
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $(SRCDIR)/wheel_sieve.c tests/test_wheel_compare.c

$(BINDIR):
	mkdir -p $(BINDIR)

$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(SRCDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(SRCDIR)/gpu_fermat.o: $(SRCDIR)/gpu_fermat.cu $(SRCDIR)/gpu_fermat.h
	$(NVCC) -O3 $(CUDA_ARCH) $(NVCC_FLAGS) -c $< -o $@

$(TARGET): $(BINDIR) $(SRCDIR)/main.o $(SRCDIR)/stats.o $(SRCDIR)/sieve_cache.o $(SRCDIR)/gap_scan.o $(SRCDIR)/crt_heap.o $(SRCDIR)/crt_solver.o $(SRCDIR)/presieve_utils.o $(SRCDIR)/wheel_sieve.o $(SRCDIR)/uint256_utils.o $(SRCDIR)/block_utils.o $(SRCDIR)/primality_utils.o $(RPC_OBJS) $(STRATUM_OBJ) $(GPU_OBJ)
	$(LINKER) -o $@ $(SRCDIR)/main.o $(SRCDIR)/stats.o $(SRCDIR)/sieve_cache.o $(SRCDIR)/gap_scan.o $(SRCDIR)/crt_heap.o $(SRCDIR)/crt_solver.o $(SRCDIR)/presieve_utils.o $(SRCDIR)/wheel_sieve.o $(SRCDIR)/uint256_utils.o $(SRCDIR)/block_utils.o $(SRCDIR)/primality_utils.o $(RPC_OBJS) $(STRATUM_OBJ) $(GPU_OBJ) $(LDFLAGS) $(LIBS)

clean:
	rm -rf $(BINDIR) $(SRCDIR)/*.o

gen_crt: $(BINDIR) tools/gen_crt.c
	$(CC) -O2 -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -o $(BINDIR)/gen_crt tools/gen_crt.c -lm -lpthread

.PHONY: all clean gen_crt
