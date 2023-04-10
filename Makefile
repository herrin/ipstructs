CC := gcc
CFLAGS := -Wall -g -O3 -I /usr/include/dpdk
LDFLAGS :=

targets = headers checksum icmp

all: $(targets)

headers: compare.o
	$(CC) -o $@ $(LDFLAGS) compare.o

checksum: test_helpers.o checksum.o
	$(CC) -o $@ $(LDFLAGS) test_helpers.o checksum.o

icmp: test_helpers.o icmp.o
	$(CC) -o $@ $(LDFLAGS) test_helpers.o icmp.o

connect: connect.o
	$(CC) -o $@ $(LDFLAGS) connect.o

clean:
	rm -f *.o
	rm -f $(targets)

.c.o:
	$(CC) -c $(CFLAGS) $<

