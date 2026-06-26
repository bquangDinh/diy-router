CC=gcc
CFLAGS=-Wall -Wextra -O0 -g
LDFLAGS= -lpcap

raspi_router: main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

.PHONY: clean

clean:
	rm -f raspi_router