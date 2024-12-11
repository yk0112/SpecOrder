SRC := md2_dgst

CFLAGS += $(if $(OPT),$(OPT),-O0) -ggdb
LDFLAGS += $(if $(OPT),$(OPT),-O0) -ggdb

.SUFFIXES:  # disable built-in rules
.PHONY: all

all: $(SRC)

# Native builds
CC = /usr/bin/clang
CXX = /usr/bin/clang++
NATIVE_FLAGS :=
NATIVE_LDFLAGS :=

native: $(addsuffix .o, $(SRC))
	$(CC) $(LDFLAGS) $(NATIVE_LDFLAGS) $? -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(NATIVE_FLAGS) $< -c -o $@


# Native with coverage
CCSF = /usr/bin/clang-sf
CXXSF = /usr/bin/clang-sf++
NATIVECOV_FLAGS := --coverage-only hongg
NATIVECOV_LDFLAGS := --coverage-only hongg

nativecov: $(addsuffix .nativecov.o, $(SRC))
	$(CCSF) $(LDFLAGS) $(NATIVECOV_LDFLAGS) $? -o $@

%.nativecov.o: %.c
	$(CCSF) $(CFLAGS) $(NATIVECOV_FLAGS) $< -c -o $@


# SpecFuzz build
HONGGFUZZ_FLAGS := -L${HONGG_SRC}/libhfuzz/ -L${HONGG_SRC}/libhfcommon -lhfuzz -lhfcommon
SF_COMMON := --enable-coverage --debug-pass -DNDEBUG
ifdef SF_COLLECT
	SF_COMMON := --collect $(CURDIR)/function_list.txt
endif
SF_FLAGS := $(SF_COMMON)
SF_LDFLAGS := $(SF_COMMON) $(HONGGFUZZ_FLAGS)

$(SRC): $(addsuffix .sf.o, $(SRC))
	$(CCSF) $(LDFLAGS) $(SF_LDFLAGS) $? -o $@

%.sf.o: %.c
	$(CCSF) $(CFLAGS) $(SF_FLAGS) $< -c -o $@

clean:
	rm -f *.o $(ALL_TYPES)
