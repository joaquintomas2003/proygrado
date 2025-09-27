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
	@# If PIDFILE exists but process is gone, clean it up
	@if [ -f "$(PIDFILE)" ]; then \
	  PID=$$(cat "$(PIDFILE)"); \
	  if $(SUDO) kill -0 $$PID 2>/dev/null; then \
	    echo "$(TARGET) already running with PID $$PID"; \
	    exit 0; \
	  else \
	    echo "Removing stale PID file"; \
	    rm -f "$(PIDFILE)"; \
	  fi \
	fi
	@echo "Starting $(TARGET)..."
	@# Start under root AND write the child's PID from that same root shell
	@$(SUDO) env PIDFILE="$(PIDFILE)" LOGFILE="$(LOGFILE)" sh -c 'nohup "./$(TARGET)" >>"$$LOGFILE" 2>&1 & echo $$! >"$$PIDFILE"'
	@echo "Started with PID $$(cat "$(PIDFILE)") (logs: $(LOGFILE))"

stop:
	@if [ -f "$(PIDFILE)" ]; then \
	  PID=$$(cat "$(PIDFILE)"); \
	  if $(SUDO) kill -0 $$PID 2>/dev/null; then \
	    echo "Stopping $(TARGET) with PID $$PID..."; \
	    $(SUDO) kill $$PID; \
	    rm -f "$(PIDFILE)"; \
	    echo "Stopped."; \
	  else \
	    echo "Process not running; removing stale PID file."; \
	    rm -f "$(PIDFILE)"; \
	  fi \
	else \
	  echo "$(TARGET) is not running."; \
	fi

restart: stop start

status:
	@if [ -f "$(PIDFILE)" ]; then \
	  PID=$$(cat "$(PIDFILE)"); \
	  if $(SUDO) kill -0 $$PID 2>/dev/null; then \
	    echo "$(TARGET) is running with PID $$PID"; \
	  else \
	    echo "$(TARGET) is not running (stale PID $$PID)"; \
	  fi \
	else \
	  echo "$(TARGET) is not running"; \
	fi

clean:
	rm -f $(OBJ) $(TARGET) $(PIDFILE) $(LOGFILE)
