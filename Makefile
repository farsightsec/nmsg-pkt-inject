CC = gcc --std=gnu99
CFLAGS = -fstack-protector --param=ssp-buffer-size=4 -Wformat -Werror=format-security -O3 -ggdb -Wall -Wno-strict-aliasing -pthread -D_REENTRANT
LDFLAGS = -Wl,-z,relro -lpthread -lpcap -lnmsg

BINS = nmsg-pkt-inject

all: $(BINS)

NMSG_PKT_INJECT_OBJS = \
	argv.o \
	nmsg-pkt-inject.o

nmsg-pkt-inject: $(NMSG_PKT_INJECT_OBJS)

clean:
	rm -f $(BINS) $(NMSG_PKT_INJECT) *.o

.PHONY: all clean
