CC = gcc --std=gnu99
CFLAGS = -O3 -ggdb -Wall -Wno-strict-aliasing -pthread -D_REENTRANT
LDFLAGS = -lpthread -lpcap -lnmsg

BINS = nmsg-pkt-inject

all: $(BINS)

NMSG_PKT_INJECT_OBJS = \
	argv.o \
	nmsg-pkt-inject.o

nmsg-pkt-inject: $(NMSG_PKT_INJECT_OBJS)

clean:
	rm -f $(BINS) $(NMSG_PKT_INJECT)

.PHONY: all clean
