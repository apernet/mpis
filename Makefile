LLC ?= llc
CLANG ?= clang
CC ?= gcc
FLEX = flex
BISON = bison

LIBBPF_DIR = libbpf/src
LIBBPF = $(LIBBPF_DIR)/libbpf.a

CFLAGS +=  -I$(LIBBPF_DIR)/build/usr/include/ -Wall -Wextra -march=native
LDFLAGS += -L$(LIBBPF_DIR)
LIBS = -l:libbpf.a -lelf -lz
BPF_CFLAGS += -I$(LIBBPF_DIR)/build/usr/include/ -Wall -Wextra

all: CFLAGS+=-O3 -g
all: BPF_CFLAGS+=-O3 -g
all: mpis-routectl mpis-ebpf.o

debug: CFLAGS+=-O0 -g
debug: BPF_CFLAGS+=-O0 -g
debug: mpis-routectl mpis-ebpf.o

MPIS_ROUTECTL_OBJS=mpis-routectl.o mpis-table.o mpis-table.tab.o mpis-table.yy.o

.PHONY: all debug clean

mpis-routectl: $(MPIS_ROUTECTL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

%.c: %.y
	# pass

%.tab.c: %.y
	$(BISON) -d $<

%.yy.c: %.l
	$(FLEX) -o $@ $<

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "libbpf not found, try \`git submodule update --init'"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all; \
		mkdir -p build; DESTDIR=build $(MAKE) install_headers; \
	fi

mpis-ebpf.o: mpis-ebpf.c $(LIBBPF)
	$(CLANG) -S -target bpf $(BPF_CFLAGS) -emit-llvm -c -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

mpis-routectl.c: $(LIBBPF)

clean:
	rm -fr *.o *.tab.c *.yy.c mpis-routectl $(LIBBPF_DIR)/build
	$(MAKE) -C $(LIBBPF_DIR) clean