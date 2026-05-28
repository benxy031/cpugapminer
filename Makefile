CC=gcc
CXX=g++
CFLAGS=-O3 -std=c11 -Wall -Wextra -march=native -flto
CXXFLAGS=-O3 -std=c++17 -Wall -Wextra -march=native -flto
LDFLAGS=-flto
SRCDIR=src
BINDIR=bin
TARGET=$(BINDIR)/gap_miner
BUILD_CFG_FILE=$(SRCDIR)/.build_config

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
	# build active RPC wrapper (legacy Rpc.cpp path is excluded)
	RPC_SRCS=$(SRCDIR)/rpc_cwrap.cpp
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
	GPU_OBJ=$(SRCDIR)/gpu_fermat.o $(SRCDIR)/gpu_sieve.o
	CFLAGS+=-DWITH_CUDA -DGPU_NLIMBS=$(GPU_NLIMBS) -I$(CUDA_PATH)/include
	NVCC_FLAGS=-DGPU_NLIMBS=$(GPU_NLIMBS) -std=c++17
	LIBS+=-lcudart -L$(CUDA_PATH)/lib64

	# Optional CGBN-based Fermat kernel (~1.9× faster for full-width candidates).
	# Enable with: make WITH_CGBN_FERMAT=1 ...
	# Requires internet on first build (auto-clones NVlabs/CGBN header-only library).
	CGBN_DIR  := tools/bench_cgbn/cgbn
	CGBN_HDR  := $(CGBN_DIR)/include/cgbn/cgbn.h
	ifdef WITH_CGBN_FERMAT
		NVCC_FLAGS += -DWITH_CGBN_FERMAT -I$(CGBN_DIR)/include
		CFLAGS     += -DWITH_CGBN_FERMAT
	endif
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

TEST_CFLAGS=$(filter-out -DWITH_CUDA -DWITH_OPENCL,$(CFLAGS))

test: tests/test_rpc_json tests/test_wheel_sieve tests/test_wheel_compare tests/test_crt_runtime_policy tests/test_sievegap

tests/test_rpc_json: $(SRCDIR)/rpc_json.c tests/test_rpc_json.c
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $(SRCDIR)/rpc_json.c tests/test_rpc_json.c -ljansson

tests/test_wheel_sieve: $(SRCDIR)/wheel_sieve.c tests/test_wheel_sieve.c
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $(SRCDIR)/wheel_sieve.c tests/test_wheel_sieve.c

tests/test_wheel_compare: $(SRCDIR)/wheel_sieve.c tests/test_wheel_compare.c
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $(SRCDIR)/wheel_sieve.c tests/test_wheel_compare.c

tests/test_crt_runtime_policy: $(SRCDIR)/crt_runtime.c tests/test_crt_runtime_policy.c
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $(SRCDIR)/crt_runtime.c tests/test_crt_runtime_policy.c

tests/test_sievegap: $(SRCDIR)/sievegap.c $(SRCDIR)/uint256_utils.c tests/test_sievegap.c
	$(CC) $(TEST_CFLAGS) -I$(SRCDIR) -o $@ $(SRCDIR)/sievegap.c $(SRCDIR)/uint256_utils.c tests/test_sievegap.c -lcrypto -lm

tests/bench_sievegap: $(SRCDIR)/sievegap.c $(SRCDIR)/uint256_utils.c tests/bench_sievegap.c
	$(CC) -O3 $(TEST_CFLAGS) -I$(SRCDIR) -o $@ $(SRCDIR)/sievegap.c $(SRCDIR)/uint256_utils.c tests/bench_sievegap.c -lcrypto -lm

$(BINDIR):
	mkdir -p $(BINDIR)

$(BUILD_CFG_FILE): | $(BINDIR)
	@tmp_file="$$(mktemp)"; \
	printf "WITH_RPC=%s\nWITH_CUDA=%s\nWITH_OPENCL=%s\nGPU_BITS=%s\nCUDA_ARCH=%s\n" \
		"$(WITH_RPC)" "$(WITH_CUDA)" "$(WITH_OPENCL)" "$(GPU_BITS)" "$(CUDA_ARCH)" > "$$tmp_file"; \
	if [ ! -f "$@" ] || ! cmp -s "$$tmp_file" "$@"; then \
		mv "$$tmp_file" "$@"; \
	else \
		rm -f "$$tmp_file"; \
	fi

# Explicit header deps for runtime SIMD dispatch helper.
$(SRCDIR)/main.o: $(SRCDIR)/cpu_features.h
$(SRCDIR)/wheel_sieve.o: $(SRCDIR)/cpu_features.h

$(SRCDIR)/%.o: $(SRCDIR)/%.c $(BUILD_CFG_FILE)
	$(CC) $(CFLAGS) -c $< -o $@

$(SRCDIR)/%.o: $(SRCDIR)/%.cpp $(BUILD_CFG_FILE)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(SRCDIR)/gpu_fermat.o: $(SRCDIR)/gpu_fermat.cu $(SRCDIR)/gpu_fermat.h
ifdef WITH_CGBN_FERMAT
	@if [ ! -f "$(CGBN_HDR)" ]; then \
		echo "[cgbn] Cloning NVlabs/CGBN (header-only)..."; \
		git clone --depth=1 https://github.com/NVlabs/CGBN.git $(CGBN_DIR); \
	fi
endif
	$(NVCC) -O3 $(CUDA_ARCH) $(NVCC_FLAGS) -c $< -o $@

$(SRCDIR)/gpu_sieve.o: $(SRCDIR)/gpu_sieve.cu $(SRCDIR)/gpu_sieve.h
	$(NVCC) -O3 $(CUDA_ARCH) $(NVCC_FLAGS) -c $< -o $@

$(TARGET): $(BINDIR) $(SRCDIR)/main.o $(SRCDIR)/stats.o $(SRCDIR)/sieve_cache.o $(SRCDIR)/gap_scan.o $(SRCDIR)/crt_heap.o $(SRCDIR)/crt_solver.o $(SRCDIR)/crt_gap_scan.o $(SRCDIR)/crt_runtime.o $(SRCDIR)/crt_runtime_worker.o $(SRCDIR)/crt_runtime_cpu.o $(SRCDIR)/crt_runtime_gpu.o $(SRCDIR)/presieve_utils.o $(SRCDIR)/wheel_sieve.o $(SRCDIR)/sievegap.o $(SRCDIR)/uint256_utils.o $(SRCDIR)/block_utils.o $(SRCDIR)/primality_utils.o $(SRCDIR)/rgm_check.o $(SRCDIR)/gap_dist.o $(RPC_OBJS) $(STRATUM_OBJ) $(GPU_OBJ)
	$(LINKER) -o $@ $(SRCDIR)/main.o $(SRCDIR)/stats.o $(SRCDIR)/sieve_cache.o $(SRCDIR)/gap_scan.o $(SRCDIR)/crt_heap.o $(SRCDIR)/crt_solver.o $(SRCDIR)/crt_gap_scan.o $(SRCDIR)/crt_runtime.o $(SRCDIR)/crt_runtime_worker.o $(SRCDIR)/crt_runtime_cpu.o $(SRCDIR)/crt_runtime_gpu.o $(SRCDIR)/presieve_utils.o $(SRCDIR)/wheel_sieve.o $(SRCDIR)/sievegap.o $(SRCDIR)/uint256_utils.o $(SRCDIR)/block_utils.o $(SRCDIR)/primality_utils.o $(SRCDIR)/rgm_check.o $(SRCDIR)/gap_dist.o $(RPC_OBJS) $(STRATUM_OBJ) $(GPU_OBJ) $(LDFLAGS) $(LIBS)

clean:
	rm -rf $(BINDIR) $(SRCDIR)/*.o $(BUILD_CFG_FILE)

gen_crt: $(BINDIR) tools/gen_crt.c
	$(CC) -O2 -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -o $(BINDIR)/gen_crt tools/gen_crt.c -lm -lpthread

gen_crt_exhaust: $(BINDIR) tools/gen_crt_exhaust.c
	$(CC) -O3 -std=c11 -Wall -Wextra -march=native -o $(BINDIR)/gen_crt_exhaust tools/gen_crt_exhaust.c -lgmp -lm

.PHONY: all clean gen_crt gen_crt_exhaust
