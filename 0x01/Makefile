CC = gcc
CFLAGS = -m32 -fno-stack-protector -no-pie -z execstack
DEBUG_FLAGS = -g
TARGET = release
SRC = src/soft-release.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

debug: $(SRC)
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) -o $(TARGET) $(SRC)

clean:
	rm -rf $(TARGET)