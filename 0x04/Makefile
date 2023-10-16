CC := gcc
CFLAGS := -Wall -Wno-unused-result -O1
SRC := src/crackme.c
TARGET := bin/crackme


all: $(SRC)
	$(CC) $^ $(CFLAGS) -o $(TARGET)
.PHONY: all

clean:
	rm -rf bin/*
.PHONY: clean
