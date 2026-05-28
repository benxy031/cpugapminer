# Makefile for tools/bench_cgbn/
#
# Auto-clones NVIDIA CGBN (header-only) from GitHub if not present.
# Build: make              → bench_fermat (sm_86, RTX 3060 default)
#        make CUDA_ARCH="-arch=sm_75"   → for Turing
#        make CUDA_ARCH="-arch=sm_89"   → for Ada Lovelace

CUDA_ARCH ?= -arch=sm_86

NVCC      := nvcc
CGBN_DIR  := cgbn
CGBN_HDR  := $(CGBN_DIR)/include/cgbn/cgbn.h
TARGET    := bench_fermat

NVCC_FLAGS := $(CUDA_ARCH) -O3 -std=c++14 -I$(CGBN_DIR)/include \
              -lineinfo --ptxas-options=-v -lgmp

.PHONY: all clean run

all: $(TARGET)

# Auto-clone CGBN if the header is missing
$(CGBN_HDR):
	@echo "[bench_cgbn] Cloning NVIDIA CGBN (header-only, NVlabs)..."
	git clone --depth=1 https://github.com/NVlabs/CGBN.git $(CGBN_DIR)
	@echo "[bench_cgbn] CGBN cloned → $(CGBN_DIR)/include/cgbn/cgbn.h"

$(TARGET): bench_fermat.cu $(CGBN_HDR)
	$(NVCC) $(NVCC_FLAGS) -o $@ bench_fermat.cu
	@echo "[bench_cgbn] Built: $(TARGET)"

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET) *.o
	@echo "[bench_cgbn] clean done (CGBN source kept in $(CGBN_DIR)/)"

# Optional: remove the cloned CGBN source too
distclean: clean
	rm -rf $(CGBN_DIR)
