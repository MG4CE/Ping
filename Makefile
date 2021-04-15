CC := gcc

BIN_NAME := ping

BIN_DIR := bin

BIN_TARGET := $(BIN_DIR)/$(BIN_NAME)

CPPFLAGS := -O2
CFLAGS := -Wall

.PHONY: all clean

all:
	mkdir -p $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c main.c -o $(BIN_DIR)/$(BIN_NAME)

clean:
	@$(RM) -rv $(BIN_DIR)

