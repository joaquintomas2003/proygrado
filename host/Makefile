CC       := gcc
CFLAGS   := -w -I/opt/netronome/include/
LDFLAGS  := -L/opt/netronome/lib/
LDLIBS   := -lnfp -lz -pthread

SRC      := host_reader.c event_ring_worker.c
OBJ      := $(SRC:.c=.o)
TARGET   := host_reader

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	sudo ./$(TARGET)

clean:
	rm -f $(OBJ) $(TARGET)
