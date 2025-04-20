
# HARDN build Makefile

CC       ?= gcc
CFLAGS   ?= -Wall -Wextra -O2
SRC_DIR   = src
BUILD_DIR = build
BIN_DIR   = bin
TARGET    = $(BIN_DIR)/hardn

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

prefix   ?= /usr/local
bindir    = $(prefix)/bin

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET)
	@mkdir -p $(DESTDIR)$(bindir)
	install -m 755 $(TARGET) $(DESTDIR)$(bindir)/hardn

uninstall:
	rm -f $(DESTDIR)$(bindir)/hardn

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

.PHONY: all clean install uninstall