CC=gcc

ENABLE_DEBUGGING ?= 0

CFLAGS=-Wall -Wextra -O3 -Iinclude -DENABLE_DEBUGGING=$(ENABLE_DEBUGGING)

SRC=$(wildcard src/*.c)
OBJ=$(SRC:src/%.c=build/%.o)

$(info ENABLE_DEBUGGING=$(ENABLE_DEBUGGING))

TARGET=router

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $@

build/%.o: src/%.c
	mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf build $(TARGET)

run:
	sudo ./router

.PHONY: all clean run