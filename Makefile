EXECUTABLE := ext4backup
CC = gcc
BUILD_DIR := build
SRC_DIR := src
CFLAGS := -O2 $(shell pkg-config glib-2.0 ext2fs --cflags)
LIBS := $(shell pkg-config glib-2.0 libacl libcap ext2fs libudev --libs)
SRCS := $(shell find $(SRC_DIR)/ -name '*.c' -printf '%f\n')
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)

$(BUILD_DIR)/$(EXECUTABLE): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LIBS)
	rm $(BUILD_DIR)/*.o

$(BUILD_DIR)/%.c.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -r $(BUILD_DIR)/*
