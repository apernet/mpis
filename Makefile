CFLAGS+=-Wall -Wextra -march=native
FLEX=flex
BISON=bison

all: CFLAGS+=-O3
all: mpis-routectl

debug: CFLAGS+=-O0 -g
debug: mpis-routectl

MPIS_ROUTECTL_OBJS=mpis-routectl.o mpis-table.o mpis-table.tab.o mpis-table.yy.o

.PHONY: all debug clean

mpis-routectl: $(MPIS_ROUTECTL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.tab.c: %.y
	$(BISON) -d $<

%.yy.c: %.l
	$(FLEX) -o $@ $<

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

%.c: %.y

clean:
	rm -f *.o *.tab.c *.yy.c mpis-routectl