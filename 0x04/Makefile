CC := gcc
CFLAGS := -Wall -Wno-unused-result -O0
SRC := src/crackme.c
TARGET := bin/crackme

all: $(SRC)
	@$(MAKE) ensure_bin_dir
	$(CC) $^ $(CFLAGS) -o $(TARGET)
.PHONY: all

clean:
	rm -rf bin/*
.PHONY: clean

ensure_bin_dir:
	@if [ ! -d bin ]; then \
		mkdir -p bin; \
	fi
.PHONY: ensure_bin_dir