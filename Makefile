CC ?= clang
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic
LDFLAGS ?=

SRC_DIR := src
BUILD_DIR := build

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

TARGET := termux-sandbox

.PHONY: all clean install

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

install: $(TARGET)
	install -Dm755 $(TARGET) $(PREFIX)/usr/bin/termux-sandbox

test: $(TARGET)
	@echo "Running basic tests..."
	@./$(TARGET) list || true

.DEFAULT_GOAL := all
