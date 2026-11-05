# ==========================================================================
# Makefile — build the C tools from src/ into bin/.
#   make            build everything and run the unit tests
#   make test       run the unit tests only
#   make clean      remove the built binaries
# Note: variable values are kept comment-free so no trailing spaces leak in.
# ==========================================================================
CC      = gcc
# warnings on, optimised, headers found in src/
CFLAGS  = -Wall -Wextra -O2 -Isrc
# math library, used by the flood-rate calculation
LIBS    = -lm
# the detector engine, linked into every tool
ENGINE  = src/tracer_ids.c
# headers that trigger a rebuild when changed
HDR     = src/tracer_ids.h src/sha256.h
# output directory for the compiled binaries
BIN     = bin

TOOLS   = $(BIN)/ids_daemon $(BIN)/signed_sender $(BIN)/ids_runner \
          $(BIN)/bench_hmac $(BIN)/test_v3

.PHONY: all test clean

# default target: build all tools, then run the unit tests
all: $(TOOLS) test
	@echo "build complete -> $(BIN)/"

# create the output directory if it does not exist (order-only prerequisite)
$(BIN):
	@mkdir -p $(BIN)

$(BIN)/ids_daemon:    src/ids_daemon.c    $(ENGINE) $(HDR) | $(BIN)
	$(CC) $(CFLAGS) src/ids_daemon.c    $(ENGINE) $(LIBS) -o $@
$(BIN)/signed_sender: src/signed_sender.c $(ENGINE) $(HDR) | $(BIN)
	$(CC) $(CFLAGS) src/signed_sender.c $(ENGINE) $(LIBS) -o $@
$(BIN)/ids_runner:    src/ids_runner.c    $(ENGINE) $(HDR) | $(BIN)
	$(CC) $(CFLAGS) src/ids_runner.c    $(ENGINE) $(LIBS) -o $@
$(BIN)/bench_hmac:    src/bench_hmac.c    $(ENGINE) $(HDR) | $(BIN)
	$(CC) $(CFLAGS) src/bench_hmac.c    $(ENGINE) $(LIBS) -o $@
$(BIN)/test_v3:       src/test_v3.c       $(ENGINE) $(HDR) | $(BIN)
	$(CC) $(CFLAGS) src/test_v3.c       $(ENGINE) $(LIBS) -o $@

# run the 8 regression tests
test: $(BIN)/test_v3
	./$(BIN)/test_v3

clean:
	rm -f $(TOOLS)
