CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2
BIN_DIR = bin
C_SRC_DIR = c_src

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	SHARED_LIB = $(BIN_DIR)/libipc_ops.dylib
	SHARED_FLAG = -dynamiclib
else
	SHARED_LIB = $(BIN_DIR)/libipc_ops.so
	SHARED_FLAG = -shared
endif

.PHONY: all build test clean demo repl base-shell

all: build test

build: $(BIN_DIR) $(BIN_DIR)/leak_generator $(SHARED_LIB)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/leak_generator: $(C_SRC_DIR)/test_leak_generator.c | $(BIN_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(SHARED_LIB): $(C_SRC_DIR)/ipc_ops.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -fPIC $(SHARED_FLAG) $< -o $@

test: build
	python3 -m pytest tests/ -v

demo: build
	python3 demo.py

base-shell: build
	python3 demo_base_shell.py

repl: build
	python3 ipc_agent.py

clean:
	rm -rf $(BIN_DIR) .pytest_cache **/__pycache__

