CC       := gcc
CFLAGS   := -w -I/opt/netronome/include/
LDFLAGS  := -L/opt/netronome/lib/
LDLIBS   := -lnfp -lz -pthread

SRC      := host_reader.c event_ring_worker.c spooler.c
OBJ      := $(SRC:.c=.o)
TARGET   := host_reader

PIDFILE  := /tmp/$(TARGET).pid
LOGFILE  := /tmp/$(TARGET).log
SUDO     ?= sudo

.PHONY: all clean run run-debug start stop restart status

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	$(SUDO) ./$(TARGET)

run-debug: $(TARGET)
	$(SUDO) ./$(TARGET) -D

start: $(TARGET)
	@# Clean up stale PID if needed
	@if [ -f "$(PIDFILE)" ]; then \
	  PID=$$(cat "$(PIDFILE)"); \
	  if $(SUDO) kill -0 $$PID 2>/dev/null; then \
	    echo "$(TARGET) already running with PID $$PID"; \
	    exit 0; \
	  else \
	    echo "Removing stale PID file"; \
	    rm -f "$(PIDFILE)"; \
	  fi; \
	fi
	@echo "Starting $(TARGET)..."
	@# Fully detach: setsid + nohup; keep stdout/err in LOGFILE; write PID atomically
	@$(SUDO) sh -c 'cd "$$(pwd)"; \
	  : >"$(LOGFILE)"; \
	  (setsid nohup "./$(TARGET)" >>"$(LOGFILE)" 2>&1 & echo $$! >"$(PIDFILE)") >/dev/null 2>&1'
	@PID=$$(cat "$(PIDFILE)"); echo "Started with PID $$PID (logs: $(LOGFILE))"

stop:
	@if [ ! -f "$(PIDFILE)" ]; then \
	  echo "$(TARGET) is not running."; exit 0; \
	fi
	@PID=$$(cat "$(PIDFILE)"); \
	if ! $(SUDO) kill -0 $$PID 2>/dev/null; then \
	  echo "Process not running; removing stale PID file."; rm -f "$(PIDFILE)"; exit 0; \
	fi; \
	echo "Stopping $(TARGET) with PID $$PID..."; \
	$(SUDO) kill $$PID; \
	for i in $$(seq 1 20); do \
	  if $(SUDO) kill -0 $$PID 2>/dev/null; then sleep 0.1; else break; fi; \
	done; \
	if $(SUDO) kill -0 $$PID 2>/dev/null; then \
	  echo "Process still alive, sending SIGKILL"; \
	  $(SUDO) kill -9 $$PID; \
	fi; \
	rm -f "$(PIDFILE)"; \
	echo "Stopped."

status:
	@if [ -f "$(PIDFILE)" ]; then \
	  PID=$$(cat "$(PIDFILE)"); \
	  if $(SUDO) kill -0 $$PID 2>/dev/null; then \
	    # Extra guard: ensure the PID matches our binary name
	    COMM=$$($(SUDO) ps -o comm= -p $$PID 2>/dev/null | tr -d " \t"); \
	    if [ "$$COMM" = "$(TARGET)" ]; then \
	      echo "$(TARGET) is running with PID $$PID"; \
	    else \
	      echo "PID $$PID is not $(TARGET) (got $$COMM); removing stale PID file."; \
	      rm -f "$(PIDFILE)"; \
	    fi; \
	  else \
	    echo "$(TARGET) is not running (stale PID $$PID)"; \
	    rm -f "$(PIDFILE)"; \
	  fi; \
	else \
	  echo "$(TARGET) is not running"; \
	fi

logs:
	@echo "Tailing $(LOGFILE) (Ctrl-C to stop)"; \
	if [ -f "$(LOGFILE)" ]; then tail -n 200 -f "$(LOGFILE)"; else echo "No log file yet."; fi

clean:
	rm -f $(OBJ) $(TARGET) $(PIDFILE) $(LOGFILE)
