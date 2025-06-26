CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinclude
LDFLAGS = -ldl

all: injector

injector: src/injector.c include/libinjector.h
	$(CC) $(CFLAGS) src/injector.c -o injector $(LDFLAGS)

clean:
	rm -f injector