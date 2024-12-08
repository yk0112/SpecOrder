CC = clang
CXX = clang++
CFLAGS := -fsanitize=address -O0 -ggdb

CCSF = clang-sf
CXXSF = clang-sf++
SF_CFLAGS := -fsanitize=address -O0 -ggdb --enable-coverage
HONGGFUZZ_LDFLAGS := -L${HONGG_SRC}/libhfuzz/ -L${HONGG_SRC}/libhfcommon -lhfuzz -lhfcommon

all: sf

native: $(addsuffix .o, $(SRC))
	$(CC) $(CFLAGS) $? -o $(NAME)-native

%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@

sf: $(addsuffix .sf.o, $(SRC))
	$(CCSF) $(SF_CFLAGS) $? -o $(NAME)-sf

%.sf.o: %.c
	$(CCSF) $(SF_CFLAGS) $< -c -o $@

mytest: md2_dgst.sf.o
	$(CCSF) $(HONGGFUZZ_LDFLAGS) $(SF_CFLAGS) $? -o md2_dgst

clean:
	rm -f *.o $(NAME)-native $(NAME)-sf fuzz
